//! Flow tracking and TCP/UDP reassembly. Turns decoded packets into events.
//!
//! Rules (see CLAUDE.md):
//! - Overlapping bytes: the first copy wins; a different later copy is
//!   reported as an anomaly.
//! - Connections without a handshake in the capture are picked up mid-stream.
//! - Holes are skipped (as gaps) when the receiver acknowledged data past
//!   them, when too much data is buffered behind them, or when the flow ends.
//! - Flows end on FIN from both sides, RST, idle timeout, or end of input.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::decode::{Packet, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Transport};
use crate::segments::Segments;

const TAIL_KEEP: usize = 64 * 1024;
const MAX_BUFFERED: usize = 16 * 1024 * 1024;
const MAX_ACK_JUMP: u64 = 1 << 30;
const CLOSED_LINGER: f64 = 120.0;
/// How far from a closed connection's last sequence number a late segment
/// is still taken as part of it. A new connection's random initial sequence
/// number falls this close only rarely.
const LINGER_WINDOW: u32 = 1 << 24;
const SWEEP_EVERY: f64 = 1.0;

pub const TO_SERVER: u8 = 0;
pub const TO_CLIENT: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CloseReason {
    Fin,
    Rst,
    Timeout,
    Eof,
}

#[derive(Debug)]
pub enum Event {
    Opened {
        flow: u64,
        ts: f64,
        proto: Proto,
        client: (IpAddr, u16),
        server: (IpAddr, u16),
    },
    Data {
        flow: u64,
        ts: f64,
        dir: u8,
        data: Vec<u8>,
    },
    Gap {
        flow: u64,
        ts: f64,
        dir: u8,
        len: u64,
    },
    Overlap {
        flow: u64,
        ts: f64,
        dir: u8,
    },
    Closed {
        flow: u64,
        ts: f64,
        reason: CloseReason,
    },
    /// An HTTP transaction (HTTP mode only, produced by `http.rs`).
    Tx {
        flow: u64,
        ts: f64,
        tx: Box<crate::http::TxCopy>,
    },
}

/// The server, as given by the user: an address, optionally with a port.
pub type ServerHint = (IpAddr, Option<u16>);

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct Key {
    a: (IpAddr, u16),
    b: (IpAddr, u16),
    proto: Proto,
}

impl Key {
    fn new(p: &Packet, proto: Proto) -> Key {
        let x = (p.src, p.sport);
        let y = (p.dst, p.dport);
        let (a, b) = if x <= y { (x, y) } else { (y, x) };
        Key { a, b, proto }
    }
}

/// Where an event happens: which flow, when, and in which direction.
#[derive(Clone, Copy)]
struct At {
    flow: u64,
    ts: f64,
    dir: u8,
}

#[derive(Default)]
struct Half {
    /// Sequence number of the SYN, when seen.
    isn: Option<u32>,
    next_seq: Option<u32>,
    next_off: u64,
    pending: Segments,
    fin_off: Option<u64>,
    fin_done: bool,
    max_ack_off: u64,
    tail: Vec<u8>,
}

impl Half {
    fn offset(&self, seq: u32) -> Option<i64> {
        let base = self.next_seq?;
        Some(self.next_off as i64 + seq.wrapping_sub(base) as i32 as i64)
    }

    fn deliver(&mut self, at: At, data: Vec<u8>, out: &mut Vec<Event>) {
        self.next_off += data.len() as u64;
        self.next_seq = self.next_seq.map(|s| s.wrapping_add(data.len() as u32));
        self.tail.extend_from_slice(&data);
        if self.tail.len() > TAIL_KEEP {
            self.tail.drain(..self.tail.len() - TAIL_KEEP);
        }
        out.push(Event::Data {
            flow: at.flow,
            ts: at.ts,
            dir: at.dir,
            data,
        });
    }

    fn drain(&mut self, at: At, out: &mut Vec<Event>) {
        while let Some(seg) = self.pending.pop_at(self.next_off) {
            self.deliver(at, seg, out);
        }
        if self.fin_off == Some(self.next_off) {
            self.fin_done = true;
        }
    }

    /// Delivers everything up to `target`, reporting holes as gaps.
    fn skip_to(&mut self, target: u64, at: At, out: &mut Vec<Event>) {
        while self.next_off < target {
            if let Some(seg) = self.pending.pop_at(self.next_off) {
                self.deliver(at, seg, out);
                continue;
            }
            let next = self
                .pending
                .first_start()
                .filter(|s| *s < target)
                .unwrap_or(target);
            let len = next - self.next_off;
            self.next_off = next;
            self.next_seq = self.next_seq.map(|s| s.wrapping_add(len as u32));
            self.tail.clear();
            out.push(Event::Gap {
                flow: at.flow,
                ts: at.ts,
                dir: at.dir,
                len,
            });
        }
        self.drain(at, out);
    }

    /// True if `data` at `off` (entirely before `next_off`) differs from what
    /// was already delivered.
    fn conflicts_with_delivered(&self, off: u64, data: &[u8]) -> bool {
        let tail_start = self.next_off - self.tail.len() as u64;
        let start = off.max(tail_start);
        let end = (off + data.len() as u64).min(self.next_off);
        if start >= end {
            return false;
        }
        let old = &self.tail[(start - tail_start) as usize..(end - tail_start) as usize];
        let new = &data[(start - off) as usize..(end - off) as usize];
        old != new
    }

    fn segment(&mut self, seq: u32, fin: bool, payload: &[u8], at: At, out: &mut Vec<Event>) {
        if self.next_seq.is_none() {
            self.next_seq = Some(seq);
        }
        let Some(off) = self.offset(seq) else { return };
        let end = off + payload.len() as i64;
        if end < 0 {
            return;
        }
        let (off, payload) = if off < 0 {
            (0u64, &payload[(-off) as usize..])
        } else {
            (off as u64, payload)
        };
        if fin && self.fin_off.is_none() {
            let fin_off = off + payload.len() as u64;
            self.fin_off = Some(fin_off);
            // An ACK seen earlier may cover the FIN's own sequence number,
            // which is not stream data.
            self.max_ack_off = self.max_ack_off.min(fin_off);
            // Nothing follows a FIN: drop bytes buffered beyond it.
            self.pending.truncate(fin_off);
        }
        // ...nor bytes arriving later beyond it.
        let payload = match self.fin_off {
            Some(fin) if off >= fin => &payload[..0],
            Some(fin) => &payload[..payload.len().min((fin - off) as usize)],
            None => payload,
        };
        if !payload.is_empty() {
            let end = off + payload.len() as u64;
            let mut conflict = false;
            let fresh = if off < self.next_off {
                conflict = self.conflicts_with_delivered(off, payload);
                if end <= self.next_off {
                    &payload[..0]
                } else {
                    &payload[(self.next_off - off) as usize..]
                }
            } else {
                payload
            };
            if !fresh.is_empty() {
                let at = end - fresh.len() as u64;
                conflict |= self.pending.insert(at, fresh);
            }
            if conflict {
                out.push(Event::Overlap {
                    flow: at.flow,
                    ts: at.ts,
                    dir: at.dir,
                });
            }
        }
        self.drain(at, out);
        if self.pending.bytes() > MAX_BUFFERED {
            let target = self.pending.first_start().unwrap_or(self.next_off);
            self.skip_to(target, at, out);
        }
    }

    /// The other side acknowledged everything before `ack`.
    fn acked(&mut self, ack: u32, at: At, out: &mut Vec<Event>) {
        let Some(ack_off) = self.offset(ack) else {
            return;
        };
        if ack_off <= self.next_off as i64 || ack_off as u64 - self.next_off > MAX_ACK_JUMP {
            return;
        }
        let mut ack_off = ack_off as u64;
        if let Some(fin) = self.fin_off {
            ack_off = ack_off.min(fin);
        }
        self.max_ack_off = self.max_ack_off.max(ack_off);
        // Only skip a hole when the stream provably went on past it: buffered
        // data after it, or an acknowledged FIN (the FIN marks the stream end).
        let past_hole = self.pending.first_start().is_some_and(|s| s < ack_off)
            || self.fin_off.is_some_and(|fin| ack_off >= fin);
        if past_hole {
            self.skip_to(ack_off, at, out);
        }
    }

    fn finish(&mut self, at: At, out: &mut Vec<Event>) {
        let target = self
            .pending
            .end()
            .unwrap_or(0)
            .max(self.max_ack_off)
            .max(self.fin_off.unwrap_or(0))
            .max(self.next_off);
        self.skip_to(target, at, out);
    }
}

/// What is kept of a TCP connection closed by FIN or RST, to tell its late
/// packets (dropped) from a new connection on the same 4-tuple.
struct Linger {
    ts: f64,
    client: (IpAddr, u16),
    /// Per direction (`TO_SERVER`, `TO_CLIENT`): the SYN's sequence number,
    /// and the sequence number following the last byte.
    isn: [Option<u32>; 2],
    end: [Option<u32>; 2],
}

impl Linger {
    fn new(flow: &Flow, ts: f64) -> Self {
        Linger {
            ts,
            client: flow.client,
            isn: [flow.halves[0].isn, flow.halves[1].isn],
            end: [flow.halves[0].next_seq, flow.halves[1].next_seq],
        }
    }

    /// True if the packet is a late part of the closed connection.
    fn owns(&self, p: &Packet, flags: u8, seq: u32) -> bool {
        let dir = if (p.src, p.sport) == self.client {
            TO_SERVER
        } else {
            TO_CLIENT
        } as usize;
        if flags & TCP_SYN != 0 {
            return self.isn[dir] == Some(seq);
        }
        match self.end[dir] {
            Some(end) => (seq.wrapping_sub(end) as i32).unsigned_abs() < LINGER_WINDOW,
            None => true,
        }
    }
}

struct Flow {
    id: u64,
    proto: Proto,
    client: (IpAddr, u16),
    last_ts: f64,
    halves: [Half; 2],
}

impl Flow {
    /// A SYN from `p` starts a new connection on this 4-tuple (port reuse),
    /// rather than repeating this connection's SYN.
    fn reused_by(&self, p: &Packet, seq: u32) -> bool {
        let carried_data = self
            .halves
            .iter()
            .any(|h| h.next_off > 0 || h.fin_off.is_some() || !h.pending.is_empty());
        let isn = self.halves[self.dir(p) as usize].isn;
        carried_data && isn != Some(seq)
    }

    fn dir(&self, p: &Packet) -> u8 {
        if (p.src, p.sport) == self.client {
            TO_SERVER
        } else {
            TO_CLIENT
        }
    }

    fn close(&mut self, ts: f64, reason: CloseReason, out: &mut Vec<Event>) {
        if self.proto == Proto::Tcp {
            for dir in [TO_SERVER, TO_CLIENT] {
                let at = At {
                    flow: self.id,
                    ts,
                    dir,
                };
                self.halves[dir as usize].finish(at, out);
            }
        }
        out.push(Event::Closed {
            flow: self.id,
            ts,
            reason,
        });
    }
}

pub struct Reassembler {
    server: Option<ServerHint>,
    idle_timeout: Option<f64>,
    flows: HashMap<Key, Flow>,
    closed: HashMap<Key, Linger>,
    next_id: u64,
    now: f64,
    last_sweep: f64,
}

fn is_server(hint: &ServerHint, ep: (IpAddr, u16)) -> bool {
    hint.0 == ep.0 && hint.1.is_none_or(|port| port == ep.1)
}

impl Reassembler {
    pub fn new(server: Option<ServerHint>, idle_timeout: Option<f64>) -> Self {
        Reassembler {
            server,
            idle_timeout,
            flows: HashMap::new(),
            closed: HashMap::new(),
            next_id: 1,
            now: f64::NEG_INFINITY,
            last_sweep: f64::NEG_INFINITY,
        }
    }

    fn pick_client(&self, p: &Packet, flags: u8) -> (IpAddr, u16) {
        let src = (p.src, p.sport);
        let dst = (p.dst, p.dport);
        if let Some(hint) = &self.server {
            if is_server(hint, dst) {
                return src;
            }
            if is_server(hint, src) {
                return dst;
            }
        }
        if flags & TCP_SYN != 0 {
            return if flags & TCP_ACK != 0 { dst } else { src };
        }
        if p.sport < p.dport { dst } else { src }
    }

    pub fn push(&mut self, ts: f64, p: Packet, out: &mut Vec<Event>) {
        self.advance(ts, out);
        let (proto, flags) = match &p.transport {
            Transport::Tcp { flags, .. } => (Proto::Tcp, *flags),
            Transport::Udp { .. } => (Proto::Udp, 0),
        };
        let key = Key::new(&p, proto);
        let starts = match &p.transport {
            Transport::Tcp { payload, .. } => flags & TCP_SYN != 0 || !payload.is_empty(),
            Transport::Udp { .. } => true,
        };

        let pure_syn = flags & (TCP_SYN | TCP_ACK) == TCP_SYN;
        let tcp_seq = match &p.transport {
            Transport::Tcp { seq, .. } => *seq,
            Transport::Udp { .. } => 0,
        };
        if pure_syn
            && self
                .flows
                .get(&key)
                .is_some_and(|f| f.reused_by(&p, tcp_seq))
        {
            // Port reuse: a new connection on the same 4-tuple.
            let mut old = self.flows.remove(&key).expect("flow exists");
            old.close(ts, CloseReason::Timeout, out);
        }
        if !self.flows.contains_key(&key) {
            let late = self
                .closed
                .get(&key)
                .is_some_and(|l| l.owns(&p, flags, tcp_seq));
            if !starts || late {
                return;
            }
            self.closed.remove(&key);
            let client = self.pick_client(&p, flags);
            let server = if client == (p.src, p.sport) {
                (p.dst, p.dport)
            } else {
                (p.src, p.sport)
            };
            let id = self.next_id;
            self.next_id += 1;
            out.push(Event::Opened {
                flow: id,
                ts,
                proto,
                client,
                server,
            });
            self.flows.insert(
                key,
                Flow {
                    id,
                    proto,
                    client,
                    last_ts: ts,
                    halves: Default::default(),
                },
            );
        }

        let flow = self.flows.get_mut(&key).expect("flow exists");
        flow.last_ts = ts;
        let dir = flow.dir(&p);
        let id = flow.id;
        match p.transport {
            Transport::Udp { payload } => out.push(Event::Data {
                flow: id,
                ts,
                dir,
                data: payload,
            }),
            Transport::Tcp {
                seq,
                ack,
                flags,
                payload,
            } => {
                // The ACK covers data sent before this packet: apply it first,
                // so data it releases comes out before this packet's payload.
                if flags & TCP_ACK != 0 {
                    let other = 1 - dir;
                    let at = At {
                        flow: id,
                        ts,
                        dir: other,
                    };
                    flow.halves[other as usize].acked(ack, at, out);
                }
                let half = &mut flow.halves[dir as usize];
                if flags & TCP_SYN != 0 {
                    if half.next_seq.is_none() {
                        half.isn = Some(seq);
                        half.next_seq = Some(seq.wrapping_add(1));
                    }
                    if payload.is_empty() && flags & TCP_FIN == 0 {
                        return;
                    }
                }
                let seq = if flags & TCP_SYN != 0 {
                    seq.wrapping_add(1)
                } else {
                    seq
                };
                let at = At { flow: id, ts, dir };
                half.segment(seq, flags & TCP_FIN != 0, &payload, at, out);
                let done =
                    flags & TCP_RST != 0 || (flow.halves[0].fin_done && flow.halves[1].fin_done);
                if done {
                    let reason = if flags & TCP_RST != 0 {
                        CloseReason::Rst
                    } else {
                        CloseReason::Fin
                    };
                    let mut flow = self.flows.remove(&key).expect("flow exists");
                    flow.close(ts, reason, out);
                    self.closed.insert(key, Linger::new(&flow, ts));
                }
            }
        }
    }

    /// Moves time forward to `ts`, closing idle flows.
    pub fn advance(&mut self, ts: f64, out: &mut Vec<Event>) {
        if ts > self.now {
            self.now = ts;
        }
        if self.now - self.last_sweep < SWEEP_EVERY {
            return;
        }
        self.last_sweep = self.now;
        let now = self.now;
        self.closed.retain(|_, l| now - l.ts < CLOSED_LINGER);
        let Some(timeout) = self.idle_timeout else {
            return;
        };
        let mut idle: Vec<Key> = self
            .flows
            .iter()
            .filter(|(_, f)| now - f.last_ts >= timeout)
            .map(|(k, _)| *k)
            .collect();
        idle.sort_by_key(|k| self.flows[k].id);
        for key in idle {
            let mut flow = self.flows.remove(&key).expect("flow exists");
            flow.close(now, CloseReason::Timeout, out);
        }
    }

    /// End of input: closes every open flow.
    pub fn finish(&mut self, out: &mut Vec<Event>) {
        let mut flows: Vec<Flow> = self.flows.drain().map(|(_, f)| f).collect();
        flows.sort_by_key(|f| f.id);
        let ts = self.now.max(0.0);
        for mut flow in flows {
            flow.close(ts, CloseReason::Eof, out);
        }
    }
}
