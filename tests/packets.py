"""Builds test frames and pcap files without third-party packet libraries."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

ETHERNET = 1
RAW = 101

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _ip(addr: str) -> bytes:
    return ipaddress.ip_address(addr).packed


def tcp(
    sport: int, dport: int, seq: int, ack: int = 0, flags: int = ACK, payload: bytes = b""
) -> bytes:
    return (
        struct.pack(
            "!HHIIBBHHH",
            sport,
            dport,
            seq & 0xFFFFFFFF,
            ack & 0xFFFFFFFF,
            5 << 4,
            flags,
            65535,
            0,
            0,
        )
        + payload
    )


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ipv4(
    src: str,
    dst: str,
    proto: int,
    body: bytes,
    ident: int = 1,
    frag_off: int = 0,
    more: bool = False,
) -> bytes:
    flags = (0x2000 if more else 0) | (frag_off // 8)
    return (
        struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, flags, 64, proto, 0, _ip(src), _ip(dst)
        )
        + body
    )


def ipv6(src: str, dst: str, proto: int, body: bytes) -> bytes:
    return struct.pack("!IHBB16s16s", 6 << 28, len(body), proto, 64, _ip(src), _ip(dst)) + body


def ether(ip_packet: bytes, vlan: int | None = None) -> bytes:
    ethertype = 0x86DD if ip_packet[0] >> 4 == 6 else 0x0800
    head = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
    if vlan is not None:
        head += struct.pack("!HH", 0x8100, vlan)
    return head + struct.pack("!H", ethertype) + ip_packet


class Conn:
    """A TCP connection between a client and a server, producing frames."""

    def __init__(
        self,
        client: str = "10.0.0.1",
        cport: int = 51000,
        server: str = "203.0.113.7",
        sport: int = 8443,
        cseq: int = 1000,
        sseq: int = 5000,
    ) -> None:
        self.c = (client, cport)
        self.s = (server, sport)
        self.cseq = cseq
        self.sseq = sseq
        self.ts = 1_700_000_000.0

    def _frame(self, src, dst, seq, ack, flags, payload) -> tuple[float, int, bytes]:
        self.ts += 0.001
        segment = tcp(src[1], dst[1], seq, ack, flags, payload)
        proto_ip = ipv6 if ":" in src[0] else ipv4
        return (self.ts, ETHERNET, ether(proto_ip(src[0], dst[0], 6, segment)))

    def handshake(self) -> list[tuple[float, int, bytes]]:
        frames = [
            self._frame(self.c, self.s, self.cseq, 0, SYN, b""),
            self._frame(self.s, self.c, self.sseq, self.cseq + 1, SYN | ACK, b""),
            self._frame(self.c, self.s, self.cseq + 1, self.sseq + 1, ACK, b""),
        ]
        self.cseq += 1
        self.sseq += 1
        return frames

    def send(
        self,
        payload: bytes,
        *,
        seq: int | None = None,
        advance: bool = True,
        flags: int = ACK | PSH,
    ):
        """Client -> server. ``seq`` overrides the sequence number."""
        s = self.cseq if seq is None else seq
        f = self._frame(self.c, self.s, s, self.sseq, flags, payload)
        if advance and seq is None:
            self.cseq += len(payload)
        return f

    def reply(
        self,
        payload: bytes,
        *,
        seq: int | None = None,
        advance: bool = True,
        flags: int = ACK | PSH,
    ):
        """Server -> client."""
        s = self.sseq if seq is None else seq
        f = self._frame(self.s, self.c, s, self.cseq, flags, payload)
        if advance and seq is None:
            self.sseq += len(payload)
        return f

    def ack_from_server(self, ack: int):
        return self._frame(self.s, self.c, self.sseq, ack, ACK, b"")

    def close(self) -> list[tuple[float, int, bytes]]:
        frames = [
            self._frame(self.c, self.s, self.cseq, self.sseq, FIN | ACK, b""),
            self._frame(self.s, self.c, self.sseq, self.cseq + 1, FIN | ACK, b""),
            self._frame(self.c, self.s, self.cseq + 1, self.sseq + 1, ACK, b""),
        ]
        self.cseq += 1
        self.sseq += 1
        return frames

    def rst(self):
        return self._frame(self.c, self.s, self.cseq, 0, RST, b"")


def write_pcap(path: Path, frames: list[tuple[float, int, bytes]], *, nano: bool = False) -> Path:
    linktype = frames[0][1] if frames else ETHERNET
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    scale = 1_000_000_000 if nano else 1_000_000
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 262144, linktype))
        for ts, _, frame in frames:
            sec = int(ts)
            frac = round((ts - sec) * scale)
            f.write(struct.pack("<IIII", sec, frac, len(frame), len(frame)) + frame)
    return path


def ipv6_fragment(ident: int, offset: int, more: bool, next_header: int, payload: bytes) -> bytes:
    return struct.pack("!BBHI", next_header, 0, (offset // 8) << 3 | int(more), ident) + payload


def nested_ipv6_fragments(levels: int, inner: bytes) -> list[tuple[float, int, bytes]]:
    """Fragment sets nested ``levels`` deep: each reassembled datagram is a
    fragment of the next set. ``inner`` is the TCP segment at the bottom."""
    src, dst = "2001:db8::1", "2001:db8::2"
    payload, nxt, frames = inner, 6, []
    for i in range(levels):
        tail = ipv6_fragment(1000 + i, 8, False, nxt, payload[8:])
        frames.append((1.0 + i * 1e-4, ETHERNET, ether(ipv6(src, dst, 44, tail))))
        payload, nxt = ipv6_fragment(1000 + i, 0, True, nxt, payload[:8]), 44
    frames.append((2.0, ETHERNET, ether(ipv6(src, dst, nxt, payload))))
    return frames
