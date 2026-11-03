"""The event iterator: ``reassemble()`` and the events it yields."""

from __future__ import annotations

import enum
import ipaddress
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from . import _native, htp, pcap

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Endpoint = tuple[IPAddress, int]
Frame = tuple[float, int, bytes]
Source = pcap.Handle | Iterable[Frame]
ServerHint = str | IPAddress | tuple[str | IPAddress, int] | None


class Direction(enum.Enum):
    """Where the data goes."""

    TO_SERVER = "to_server"
    TO_CLIENT = "to_client"


class CloseReason(enum.Enum):
    FIN = "FIN"
    RST = "RST"
    TIMEOUT = "TIMEOUT"
    EOF = "EOF"


_DIRECTIONS = (Direction.TO_SERVER, Direction.TO_CLIENT)


@dataclass(eq=False)
class Flow:
    """One connection (TCP) or one exchange between two endpoints (UDP).

    ``state`` is yours: store per-connection decoder state there.
    """

    id: int
    transport: str
    client: Endpoint
    server: Endpoint
    start: float
    state: Any = field(default=None, repr=False)

    def __repr__(self) -> str:
        return f"<Flow {self.transport} {_fmt(self.client)} -> {_fmt(self.server)}>"


def _fmt(ep: Endpoint) -> str:
    ip, port = ep
    return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"


@dataclass(frozen=True, eq=False)
class Opened:
    flow: Flow
    ts: float


@dataclass(frozen=True, eq=False)
class Data:
    """New bytes. For UDP, exactly one datagram."""

    flow: Flow
    direction: Direction
    data: bytes
    ts: float

    def __repr__(self) -> str:
        preview = self.data[:32]
        more = "..." if len(self.data) > 32 else ""
        return f"Data({self.flow!r}, {self.direction}, {preview!r}{more} [{len(self.data)} bytes])"


@dataclass(frozen=True, eq=False)
class Gap:
    """``length`` bytes of this direction were never captured."""

    flow: Flow
    direction: Direction
    length: int
    ts: float


@dataclass(frozen=True, eq=False)
class Closed:
    flow: Flow
    reason: CloseReason
    ts: float


Event = Opened | Data | Gap | Closed | htp.Tx


def _server_hint(server: ServerHint) -> tuple[str, int | None] | None:
    if server is None:
        return None
    if isinstance(server, tuple):
        ip, port = server
        return str(ipaddress.ip_address(ip)), int(port)
    return str(ipaddress.ip_address(server)), None


def _raw_events(
    source: Source, server: ServerHint, idle_timeout: float | None, http: htp.Config | None
) -> Iterator[tuple]:
    settings = None if http is None else http._native()
    core = _native.Reassembler(_server_hint(server), idle_timeout, settings)
    try:
        if isinstance(source, pcap.Handle):
            while (batch := core.run(source)) is not None:
                yield from batch
            return
        for ts, linktype, frame in source:
            yield from core.push(ts, linktype, frame)
        yield from core.finish()
    finally:
        # Early exit (break, exception, Ctrl-C): free the handle now rather
        # than whenever the iterator is garbage collected.
        core.release()


def _events(
    source: Source,
    server: ServerHint,
    idle_timeout: float | None,
    http: htp.Config | None,
    overlaps: bool,
) -> Iterator[Event | tuple[str, Flow, float, Direction]]:
    flows: dict[int, Flow] = {}
    for ev in _raw_events(source, server, idle_timeout, http):
        kind = ev[0]
        if kind == "data":
            _, fid, ts, d, data = ev
            yield Data(flows[fid], _DIRECTIONS[d], data, ts)
        elif kind == "opened":
            _, fid, ts, transport, (cip, cport), (sip, sport) = ev
            client = (ipaddress.ip_address(cip), cport)
            flow = Flow(fid, transport, client, (ipaddress.ip_address(sip), sport), ts)
            flows[fid] = flow
            yield Opened(flow, ts)
        elif kind == "gap":
            _, fid, ts, d, length = ev
            yield Gap(flows[fid], _DIRECTIONS[d], length, ts)
        elif kind == "closed":
            _, fid, ts, reason = ev
            yield Closed(flows.pop(fid), CloseReason(reason), ts)
        elif kind == "tx":
            _, fid, ts, fields = ev
            yield htp._tx(flows[fid], ts, fields)
        elif kind == "overlap" and overlaps:
            _, fid, ts, d = ev
            yield ("overlap", flows[fid], ts, _DIRECTIONS[d])


def reassemble(
    source: Source,
    *,
    server: ServerHint = None,
    idle_timeout: float | None = 3600.0,
    http: htp.Config | None = None,
) -> Iterator[Event]:
    """Reassembles flows from a pcap handle or from ``(ts, linktype, frame)`` tuples.

    ``server`` names the server (an address, or an ``(address, port)`` pair) when
    direction can't be told from the TCP handshake. ``idle_timeout`` is in
    seconds; ``None`` means flows end only on FIN, RST, or end of input.
    ``http`` parses every TCP connection with libhtp: transactions are yielded
    as ``htp.Tx`` instead of ``Data`` events (see ``flowreassemble.htp``).
    """
    yield from _events(source, server, idle_timeout, http, overlaps=False)  # type: ignore[misc]
