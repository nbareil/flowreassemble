//! Frame decoding: link layers, VLAN/MPLS/PPPoE, tunnels, IPv4/IPv6 with
//! defragmentation, down to TCP and UDP.
//!
//! Checksums are never verified: captures taken with NIC offload carry bogus
//! checksums on every locally sent packet.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::segments::Segments;

const MAX_DEPTH: u8 = 8;
const MAX_DATAGRAM: u64 = 65_535 + 8;
const FRAG_TIMEOUT: f64 = 30.0;
const VXLAN_PORT: u16 = 4789;

pub enum Transport {
    Tcp {
        seq: u32,
        ack: u32,
        flags: u8,
        payload: Vec<u8>,
    },
    Udp {
        payload: Vec<u8>,
    },
}

pub struct Packet {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub transport: Transport,
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FragKey {
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    id: u32,
}

struct FragBuf {
    first_ts: f64,
    total: Option<u64>,
    proto: u8,
    segments: Segments,
}

#[derive(Default)]
pub struct Decoder {
    frags: HashMap<FragKey, FragBuf>,
    last_sweep: f64,
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(at..at + 2)?.try_into().ok()?))
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

impl Decoder {
    pub fn decode(&mut self, ts: f64, linktype: i32, frame: &[u8]) -> Option<Packet> {
        if !self.frags.is_empty() && ts - self.last_sweep > 1.0 {
            self.frags.retain(|_, f| ts - f.first_ts <= FRAG_TIMEOUT);
            self.last_sweep = ts;
        }
        match linktype {
            1 => self.ether(ts, frame, 0),
            // NULL / LOOP: 4-byte address family, then IP.
            0 | 108 => self.ip(ts, frame.get(4..)?, 0),
            // RAW variants.
            12 | 14 | 101 | 228 | 229 => self.ip(ts, frame, 0),
            // LINUX_SLL
            113 => self.ethertype(ts, be16(frame, 14)?, frame.get(16..)?, 0),
            // LINUX_SLL2
            276 => self.ethertype(ts, be16(frame, 0)?, frame.get(20..)?, 0),
            _ => None,
        }
    }

    fn ether(&mut self, ts: f64, d: &[u8], depth: u8) -> Option<Packet> {
        self.ethertype(ts, be16(d, 12)?, d.get(14..)?, depth)
    }

    fn ethertype(&mut self, ts: f64, et: u16, d: &[u8], depth: u8) -> Option<Packet> {
        if depth > MAX_DEPTH {
            return None;
        }
        match et {
            0x0800 | 0x86dd => self.ip(ts, d, depth),
            0x8100 | 0x88a8 | 0x9100 => self.ethertype(ts, be16(d, 2)?, d.get(4..)?, depth + 1),
            0x8847 | 0x8848 => {
                let mut at = 0;
                loop {
                    let bottom = d.get(at + 2)? & 1 == 1;
                    at += 4;
                    if bottom {
                        break;
                    }
                }
                self.ip(ts, d.get(at..)?, depth + 1)
            }
            0x8864 => match be16(d, 6)? {
                0x0021 | 0x0057 => self.ip(ts, d.get(8..)?, depth + 1),
                _ => None,
            },
            0x6558 => self.ether(ts, d, depth + 1),
            _ => None,
        }
    }

    fn ip(&mut self, ts: f64, d: &[u8], depth: u8) -> Option<Packet> {
        match d.first()? >> 4 {
            4 => self.ipv4(ts, d, depth),
            6 => self.ipv6(ts, d, depth),
            _ => None,
        }
    }

    fn ipv4(&mut self, ts: f64, d: &[u8], depth: u8) -> Option<Packet> {
        let ihl = ((d.first()? & 0x0f) as usize) * 4;
        let total = (be16(d, 2)? as usize).min(d.len());
        if ihl < 20 || total < ihl {
            return None;
        }
        let proto = *d.get(9)?;
        let src = IpAddr::V4(Ipv4Addr::from(be32(d, 12)?));
        let dst = IpAddr::V4(Ipv4Addr::from(be32(d, 16)?));
        let frag = be16(d, 6)?;
        let more = frag & 0x2000 != 0;
        let offset = ((frag & 0x1fff) as u64) * 8;
        let payload = &d[ihl..total];
        if !more && offset == 0 {
            return self.l4(ts, src, dst, proto, payload, depth);
        }
        let key = FragKey {
            src,
            dst,
            proto,
            id: be16(d, 4)? as u32,
        };
        let whole = self.reassemble(ts, key, proto, offset, more, payload)?;
        self.l4(ts, src, dst, whole.0, &whole.1, depth)
    }

    fn ipv6(&mut self, ts: f64, d: &[u8], depth: u8) -> Option<Packet> {
        let plen = be16(d, 4)? as usize;
        let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(d.get(8..24)?).ok()?));
        let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(d.get(24..40)?).ok()?));
        let body = d.get(40..)?;
        let body = &body[..plen.min(body.len())];
        self.ipv6_chain(ts, src, dst, *d.get(6)?, body, depth)
    }

    fn ipv6_chain(
        &mut self,
        ts: f64,
        src: IpAddr,
        dst: IpAddr,
        mut next: u8,
        mut d: &[u8],
        depth: u8,
    ) -> Option<Packet> {
        if depth > MAX_DEPTH {
            return None;
        }
        loop {
            match next {
                0 | 43 | 60 => {
                    let len = (*d.get(1)? as usize + 1) * 8;
                    next = *d.first()?;
                    d = d.get(len..)?;
                }
                51 => {
                    let len = (*d.get(1)? as usize + 2) * 4;
                    next = *d.first()?;
                    d = d.get(len..)?;
                }
                44 => {
                    let inner = *d.first()?;
                    let fo = be16(d, 2)?;
                    let offset = ((fo >> 3) as u64) * 8;
                    let more = fo & 1 == 1;
                    let key = FragKey {
                        src,
                        dst,
                        proto: 0,
                        id: be32(d, 4)?,
                    };
                    let payload = d.get(8..)?;
                    if !more && offset == 0 {
                        next = inner;
                        d = payload;
                        continue;
                    }
                    let (proto, whole) = self.reassemble(ts, key, inner, offset, more, payload)?;
                    // A reassembled datagram can hold another fragment:
                    // count it as a layer so nesting stays bounded.
                    return self.ipv6_chain(ts, src, dst, proto, &whole, depth + 1);
                }
                _ => return self.l4(ts, src, dst, next, d, depth),
            }
        }
    }

    fn reassemble(
        &mut self,
        ts: f64,
        key: FragKey,
        proto: u8,
        offset: u64,
        more: bool,
        payload: &[u8],
    ) -> Option<(u8, Vec<u8>)> {
        if offset + payload.len() as u64 > MAX_DATAGRAM {
            return None;
        }
        let buf = self.frags.entry(key).or_insert_with(|| FragBuf {
            first_ts: ts,
            total: None,
            proto,
            segments: Segments::default(),
        });
        if offset == 0 {
            buf.proto = proto;
        }
        buf.segments.insert(offset, payload);
        if !more {
            buf.total = Some(offset + payload.len() as u64);
        }
        let total = buf.total?;
        if !buf.segments.covers(total) {
            return None;
        }
        let buf = self.frags.remove(&key)?;
        let mut whole = buf.segments.into_vec();
        whole.truncate(total as usize);
        Some((buf.proto, whole))
    }

    fn l4(
        &mut self,
        ts: f64,
        src: IpAddr,
        dst: IpAddr,
        proto: u8,
        d: &[u8],
        depth: u8,
    ) -> Option<Packet> {
        match proto {
            4 | 41 if depth < MAX_DEPTH => self.ip(ts, d, depth + 1),
            47 if depth < MAX_DEPTH => {
                let flags = be16(d, 0)?;
                if flags & 0x0007 != 0 {
                    return None; // only GRE version 0
                }
                let mut len = 4;
                for bit in [0x8000, 0x2000, 0x1000] {
                    if flags & bit != 0 {
                        len += 4;
                    }
                }
                self.ethertype(ts, be16(d, 2)?, d.get(len..)?, depth + 1)
            }
            6 => {
                let hlen = ((d.get(12)? >> 4) as usize) * 4;
                if hlen < 20 {
                    return None;
                }
                Some(Packet {
                    src,
                    dst,
                    sport: be16(d, 0)?,
                    dport: be16(d, 2)?,
                    transport: Transport::Tcp {
                        seq: be32(d, 4)?,
                        ack: be32(d, 8)?,
                        flags: *d.get(13)?,
                        payload: d.get(hlen..)?.to_vec(),
                    },
                })
            }
            17 => {
                let sport = be16(d, 0)?;
                let dport = be16(d, 2)?;
                let ulen = (be16(d, 4)? as usize).clamp(8, d.len().max(8));
                let payload = d.get(8..ulen.min(d.len()))?;
                if dport == VXLAN_PORT && depth < MAX_DEPTH && payload.first()? & 0x08 != 0 {
                    return self.ether(ts, payload.get(8..)?, depth + 1);
                }
                Some(Packet {
                    src,
                    dst,
                    sport,
                    dport,
                    transport: Transport::Udp {
                        payload: payload.to_vec(),
                    },
                })
            }
            _ => None,
        }
    }
}
