//! HTTP through the vendored libhtp: one connection parser per TCP flow.
//!
//! This sits after the flow reassembler. In HTTP mode, the `Data` and `Gap`
//! events of TCP flows are fed to libhtp, and every transaction becomes a
//! `Tx` event holding a copy of libhtp's `htp_tx_t` fields, taken when libhtp
//! completes the transaction (or when the connection closes, for transactions
//! left incomplete). `Gap` events still pass through.
//!
//! If libhtp stops parsing a connection (a CONNECT tunnel, an error, or a gap
//! it can't skip), the rest of that connection is delivered as plain `Data`
//! events, starting with the bytes libhtp had read but not parsed.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CString, c_char, c_int, c_void};
use std::net::IpAddr;

use crate::flows::{Event, Proto};

#[repr(C)]
struct HtpCfg {
    _private: [u8; 0],
}
#[repr(C)]
struct HtpConnp {
    _private: [u8; 0],
}
#[repr(C)]
struct HtpTx {
    _private: [u8; 0],
}
#[repr(C)]
struct HtpTxData {
    _private: [u8; 0],
}
#[repr(C)]
struct Bstr {
    _private: [u8; 0],
}
#[repr(C)]
struct HtpTable {
    _private: [u8; 0],
}
#[repr(C)]
struct HtpUri {
    _private: [u8; 0],
}

type TxHook = extern "C" fn(*mut HtpTx) -> c_int;
type DataHook = extern "C" fn(*mut HtpTxData) -> c_int;

const HTP_OK: c_int = 1;
const HTP_STREAM_DATA_OTHER: c_int = 5;
const HTP_STREAM_DATA: c_int = 9;

unsafe extern "C" {
    fn htp_config_create() -> *mut HtpCfg;
    fn htp_config_destroy(cfg: *mut HtpCfg);
    fn htp_config_set_server_personality(cfg: *mut HtpCfg, personality: c_int) -> c_int;
    fn htp_config_set_response_decompression(cfg: *mut HtpCfg, enabled: c_int);
    fn htp_config_set_request_decompression(cfg: *mut HtpCfg, enabled: c_int);
    fn htp_config_set_parse_request_cookies(cfg: *mut HtpCfg, enabled: c_int);
    fn htp_config_set_tx_auto_destroy(cfg: *mut HtpCfg, enabled: c_int);
    fn htp_config_register_transaction_complete(cfg: *mut HtpCfg, cb: TxHook);
    fn htp_config_register_request_body_data(cfg: *mut HtpCfg, cb: DataHook);
    fn htp_config_register_response_body_data(cfg: *mut HtpCfg, cb: DataHook);

    fn htp_connp_create(cfg: *mut HtpCfg) -> *mut HtpConnp;
    fn htp_connp_open(
        connp: *mut HtpConnp,
        client_addr: *const c_char,
        client_port: c_int,
        server_addr: *const c_char,
        server_port: c_int,
        ts: *const libc::timeval,
    );
    fn htp_connp_set_user_data(connp: *mut HtpConnp, user_data: *const c_void);
    fn htp_connp_req_data(
        connp: *mut HtpConnp,
        ts: *const libc::timeval,
        data: *const c_void,
        len: usize,
    ) -> c_int;
    fn htp_connp_res_data(
        connp: *mut HtpConnp,
        ts: *const libc::timeval,
        data: *const c_void,
        len: usize,
    ) -> c_int;
    fn htp_connp_req_data_consumed(connp: *mut HtpConnp) -> usize;
    fn htp_connp_res_data_consumed(connp: *mut HtpConnp) -> usize;
    fn htp_connp_close(connp: *mut HtpConnp, ts: *const libc::timeval);
    fn htp_connp_destroy_all(connp: *mut HtpConnp);
    fn htp_tx_get_user_data(tx: *const HtpTx) -> *mut c_void;
    fn htp_tx_set_user_data(tx: *mut HtpTx, user_data: *mut c_void);

    // src/htp_shim.c
    fn fr_bstr_ptr(b: *const Bstr) -> *const u8;
    fn fr_bstr_len(b: *const Bstr) -> usize;
    fn fr_tx_bstr(tx: *const HtpTx, field: c_int) -> *const Bstr;
    fn fr_tx_int(tx: *const HtpTx, field: c_int) -> i64;
    fn fr_tx_uri(tx: *const HtpTx, raw: c_int) -> *const HtpUri;
    fn fr_uri_bstr(u: *const HtpUri, field: c_int) -> *const Bstr;
    fn fr_uri_port_number(u: *const HtpUri) -> c_int;
    fn fr_tx_table(tx: *const HtpTx, which: c_int) -> *const HtpTable;
    fn fr_table_size(t: *const HtpTable) -> usize;
    fn fr_table_entry(
        t: *const HtpTable,
        i: usize,
        headers: c_int,
        name: *mut *const Bstr,
        value: *mut *const Bstr,
    );
    fn fr_tx_data_tx(d: *const HtpTxData) -> *mut HtpTx;
    fn fr_tx_data_ptr(d: *const HtpTxData) -> *const u8;
    fn fr_tx_data_len(d: *const HtpTxData) -> usize;
    fn fr_tx_flow(tx: *const HtpTx) -> *mut c_void;
    fn fr_connp_tx_count(connp: *const HtpConnp) -> usize;
    fn fr_connp_tx(connp: *const HtpConnp, i: usize) -> *mut HtpTx;
    fn fr_connp_buffered(connp: *const HtpConnp, response: c_int, data: *mut *const u8) -> usize;
    fn fr_connp_current_unparsed(
        connp: *const HtpConnp,
        response: c_int,
        data: *mut *const u8,
    ) -> usize;
}

/// `htp_tx_t` byte-string fields, in the order of `fr_tx_bstr`.
pub const TX_BYTES: [&str; 13] = [
    "request_line",
    "request_method",
    "request_uri",
    "request_protocol",
    "request_content_type",
    "request_auth_username",
    "request_auth_password",
    "request_hostname",
    "response_line",
    "response_protocol",
    "response_status",
    "response_message",
    "response_content_type",
];

/// `htp_tx_t` integer fields, in the order of `fr_tx_int`.
pub const TX_INTS: [&str; 25] = [
    "request_ignored_lines",
    "request_method_number",
    "request_protocol_number",
    "is_protocol_0_9",
    "request_message_len",
    "request_entity_len",
    "request_transfer_coding",
    "request_content_encoding",
    "request_content_length",
    "request_auth_type",
    "request_port_number",
    "response_ignored_lines",
    "response_protocol_number",
    "response_status_number",
    "response_status_expected_number",
    "seen_100continue",
    "response_message_len",
    "response_entity_len",
    "response_content_length",
    "response_transfer_coding",
    "response_content_encoding",
    "flags",
    "request_progress",
    "response_progress",
    "index",
];

/// `htp_uri_t` byte-string fields, in the order of `fr_uri_bstr`.
pub const URI_BYTES: [&str; 8] = [
    "scheme", "username", "password", "hostname", "port", "path", "query", "fragment",
];

pub type Pairs = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Debug)]
pub struct UriCopy {
    pub bytes: Vec<Option<Vec<u8>>>,
    pub port_number: i32,
}

/// A copy of one libhtp transaction.
#[derive(Debug)]
pub struct TxCopy {
    pub bytes: Vec<Option<Vec<u8>>>,
    pub ints: Vec<i64>,
    pub parsed_uri: Option<UriCopy>,
    pub parsed_uri_raw: Option<UriCopy>,
    pub request_headers: Pairs,
    pub response_headers: Pairs,
    pub request_cookies: Pairs,
    pub request_body: Option<Vec<u8>>,
    pub response_body: Option<Vec<u8>>,
}

/// libhtp settings, as given by `htp.Config` (Python).
pub struct Settings {
    pub server_personality: i32,
    pub request_decompression: bool,
    pub response_decompression: bool,
    pub parse_request_cookies: bool,
    pub keep_bodies: Option<usize>,
}

unsafe fn bytes(b: *const Bstr) -> Option<Vec<u8>> {
    if b.is_null() {
        return None;
    }
    let (ptr, len) = unsafe { (fr_bstr_ptr(b), fr_bstr_len(b)) };
    if len == 0 {
        return Some(Vec::new());
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

unsafe fn uri(u: *const HtpUri) -> Option<UriCopy> {
    if u.is_null() {
        return None;
    }
    Some(UriCopy {
        bytes: (0..URI_BYTES.len())
            .map(|i| unsafe { bytes(fr_uri_bstr(u, i as c_int)) })
            .collect(),
        port_number: unsafe { fr_uri_port_number(u) },
    })
}

unsafe fn table(tx: *const HtpTx, which: c_int) -> Pairs {
    let t = unsafe { fr_tx_table(tx, which) };
    let headers = (which != 2) as c_int;
    (0..unsafe { fr_table_size(t) })
        .filter_map(|i| {
            let mut name = std::ptr::null();
            let mut value = std::ptr::null();
            unsafe { fr_table_entry(t, i, headers, &mut name, &mut value) };
            Some((
                unsafe { bytes(name) }?,
                unsafe { bytes(value) }.unwrap_or_default(),
            ))
        })
        .collect()
}

/// Bodies collected for one transaction (libhtp tx user data).
#[derive(Default)]
struct Bodies {
    request: Option<Vec<u8>>,
    response: Option<Vec<u8>>,
}

unsafe fn take_bodies(tx: *mut HtpTx) -> Bodies {
    let p = unsafe { htp_tx_get_user_data(tx) } as *mut Bodies;
    if p.is_null() {
        return Bodies::default();
    }
    unsafe { htp_tx_set_user_data(tx, std::ptr::null_mut()) };
    *unsafe { Box::from_raw(p) }
}

unsafe fn copy_tx(tx: *mut HtpTx, keep_bodies: bool) -> TxCopy {
    let bodies = unsafe { take_bodies(tx) };
    let empty = || keep_bodies.then(Vec::new);
    TxCopy {
        bytes: (0..TX_BYTES.len())
            .map(|i| unsafe { bytes(fr_tx_bstr(tx, i as c_int)) })
            .collect(),
        ints: (0..TX_INTS.len())
            .map(|i| unsafe { fr_tx_int(tx, i as c_int) })
            .collect(),
        parsed_uri: unsafe { uri(fr_tx_uri(tx, 0)) },
        parsed_uri_raw: unsafe { uri(fr_tx_uri(tx, 1)) },
        request_headers: unsafe { table(tx, 0) },
        response_headers: unsafe { table(tx, 1) },
        request_cookies: unsafe { table(tx, 2) },
        request_body: bodies.request.or_else(empty),
        response_body: bodies.response.or_else(empty),
    }
}

/// State reached from libhtp callbacks (the connection parser's user data).
struct Shared {
    keep_bodies: Option<usize>,
    done: Vec<TxCopy>,
}

extern "C" fn on_tx_complete(tx: *mut HtpTx) -> c_int {
    unsafe {
        let shared = fr_tx_flow(tx) as *mut Shared;
        let copy = copy_tx(tx, (*shared).keep_bodies.is_some());
        (*shared).done.push(copy);
    }
    HTP_OK
}

fn on_body(d: *mut HtpTxData, response: bool) -> c_int {
    unsafe {
        let tx = fr_tx_data_tx(d);
        let shared = fr_tx_flow(tx) as *const Shared;
        let Some(limit) = (*shared).keep_bodies else {
            return HTP_OK;
        };
        let mut p = htp_tx_get_user_data(tx) as *mut Bodies;
        if p.is_null() {
            p = Box::into_raw(Box::default());
            htp_tx_set_user_data(tx, p as *mut c_void);
        }
        let body = if response {
            &mut (*p).response
        } else {
            &mut (*p).request
        };
        let body = body.get_or_insert_with(Vec::new);
        let (ptr, len) = (fr_tx_data_ptr(d), fr_tx_data_len(d));
        let room = limit.saturating_sub(body.len()).min(len);
        if !ptr.is_null() && room > 0 {
            body.extend_from_slice(std::slice::from_raw_parts(ptr, room));
        }
    }
    HTP_OK
}

extern "C" fn on_request_body(d: *mut HtpTxData) -> c_int {
    on_body(d, false)
}

extern "C" fn on_response_body(d: *mut HtpTxData) -> c_int {
    on_body(d, true)
}

enum Chunk {
    Data(Vec<u8>),
    Gap(u64),
}

struct HttpFlow {
    connp: *mut HtpConnp,
    shared: *mut Shared,
    queue: [VecDeque<Chunk>; 2],
    blocked: [bool; 2],
    /// libhtp stopped: the rest of the connection is plain data.
    raw: bool,
}

fn timeval(ts: f64) -> libc::timeval {
    let sec = ts.floor();
    libc::timeval {
        tv_sec: sec as libc::time_t,
        tv_usec: ((ts - sec) * 1e6) as libc::suseconds_t,
    }
}

impl HttpFlow {
    fn new(
        cfg: *mut HtpCfg,
        keep_bodies: Option<usize>,
        ts: f64,
        client: (IpAddr, u16),
        server: (IpAddr, u16),
    ) -> Self {
        let shared = Box::into_raw(Box::new(Shared {
            keep_bodies,
            done: Vec::new(),
        }));
        let caddr = CString::new(client.0.to_string()).expect("no NUL in address");
        let saddr = CString::new(server.0.to_string()).expect("no NUL in address");
        let tv = timeval(ts);
        let connp = unsafe {
            let connp = htp_connp_create(cfg);
            htp_connp_set_user_data(connp, shared as *const c_void);
            htp_connp_open(
                connp,
                caddr.as_ptr(),
                client.1 as c_int,
                saddr.as_ptr(),
                server.1 as c_int,
                &tv,
            );
            connp
        };
        HttpFlow {
            connp,
            shared,
            queue: Default::default(),
            blocked: [false; 2],
            raw: false,
        }
    }

    /// Feeds queued chunks to libhtp. Bytes libhtp won't parse are returned
    /// as `(direction, data)`.
    fn pump(&mut self, ts: f64, raw_out: &mut Vec<(u8, Vec<u8>)>) {
        let tv = timeval(ts);
        let mut progressed = true;
        while progressed && !self.raw {
            progressed = false;
            for dir in [0usize, 1] {
                while !self.blocked[dir] && !self.raw {
                    let Some(chunk) = self.queue[dir].pop_front() else {
                        break;
                    };
                    let (ptr, len) = match &chunk {
                        Chunk::Data(d) => (d.as_ptr() as *const c_void, d.len()),
                        Chunk::Gap(n) => (std::ptr::null(), *n as usize),
                    };
                    let (rc, consumed) = unsafe {
                        if dir == 0 {
                            let rc = htp_connp_req_data(self.connp, &tv, ptr, len);
                            (rc, htp_connp_req_data_consumed(self.connp))
                        } else {
                            let rc = htp_connp_res_data(self.connp, &tv, ptr, len);
                            (rc, htp_connp_res_data_consumed(self.connp))
                        }
                    };
                    // Anything but DATA / DATA_OTHER means libhtp stopped
                    // (tunnel, error, stop, or CLOSED after refusing a gap).
                    let stopped = rc != HTP_STREAM_DATA && rc != HTP_STREAM_DATA_OTHER;
                    // Must be read while `chunk` (libhtp's current data) is alive.
                    let mut unparsed = Vec::new();
                    if stopped {
                        unparsed = unsafe { self.unparsed(dir, true) };
                    }
                    progressed = true;
                    self.blocked[1 - dir] = false;
                    let rest = match chunk {
                        Chunk::Data(d) if consumed < d.len() => Some(d[consumed..].to_vec()),
                        _ => None,
                    };
                    if stopped {
                        self.raw = true;
                        unparsed.extend(rest.unwrap_or_default());
                        if !unparsed.is_empty() {
                            raw_out.push((dir as u8, unparsed));
                        }
                        // The other direction may hold bytes libhtp never parsed.
                        let other = unsafe { self.unparsed(1 - dir, false) };
                        if !other.is_empty() {
                            raw_out.push((1 - dir as u8, other));
                        }
                    } else if rc == HTP_STREAM_DATA_OTHER {
                        if let Some(rest) = rest {
                            self.queue[dir].push_front(Chunk::Data(rest));
                        }
                        self.blocked[dir] = true;
                    }
                }
            }
        }
        if self.raw {
            for dir in 0..2 {
                for chunk in self.queue[dir].drain(..) {
                    if let Chunk::Data(d) = chunk {
                        raw_out.push((dir as u8, d));
                    }
                }
            }
        }
    }

    /// Bytes libhtp read in direction `dir` but did not parse. With
    /// `current`, also the unparsed part of the chunk just fed, which is only
    /// valid right after the call that received it.
    unsafe fn unparsed(&self, dir: usize, current: bool) -> Vec<u8> {
        let response = dir as c_int;
        let mut out = Vec::new();
        let mut ptr = std::ptr::null();
        let len = unsafe { fr_connp_buffered(self.connp, response, &mut ptr) };
        if !ptr.is_null() && len > 0 {
            out.extend_from_slice(unsafe { std::slice::from_raw_parts(ptr, len) });
        }
        if current {
            let len = unsafe { fr_connp_current_unparsed(self.connp, response, &mut ptr) };
            if !ptr.is_null() && len > 0 {
                out.extend_from_slice(unsafe { std::slice::from_raw_parts(ptr, len) });
            }
        }
        out
    }

    fn take_done(&mut self) -> Vec<TxCopy> {
        std::mem::take(unsafe { &mut (*self.shared).done })
    }

    /// Closes the connection parser; returns every transaction left.
    fn close(mut self, ts: f64) -> Vec<TxCopy> {
        let tv = timeval(ts);
        let keep = unsafe { (*self.shared).keep_bodies.is_some() };
        if !self.raw {
            // Once libhtp has stopped, don't let it finalize what it holds.
            unsafe { htp_connp_close(self.connp, &tv) };
        }
        let mut txs = self.take_done();
        unsafe {
            for i in 0..fr_connp_tx_count(self.connp) {
                let tx = fr_connp_tx(self.connp, i);
                if !tx.is_null() {
                    txs.push(copy_tx(tx, keep));
                }
            }
        }
        txs
    }
}

impl Drop for HttpFlow {
    fn drop(&mut self) {
        unsafe {
            for i in 0..fr_connp_tx_count(self.connp) {
                let tx = fr_connp_tx(self.connp, i);
                if !tx.is_null() {
                    drop(take_bodies(tx));
                }
            }
            htp_connp_destroy_all(self.connp);
            drop(Box::from_raw(self.shared));
        }
    }
}

pub struct Http {
    cfg: *mut HtpCfg,
    keep_bodies: Option<usize>,
    flows: HashMap<u64, HttpFlow>,
}

// The libhtp structures are only reached through `&mut Http`: the owning
// Python object hands out one mutable borrow at a time, from one thread at a
// time, and the parser is never touched while the Python lock is released.
unsafe impl Send for Http {}
unsafe impl Sync for Http {}

impl Http {
    pub fn new(s: &Settings) -> Self {
        let cfg = unsafe {
            let cfg = htp_config_create();
            // The personality resets other settings, so it goes first.
            htp_config_set_server_personality(cfg, s.server_personality as c_int);
            htp_config_set_request_decompression(cfg, s.request_decompression as c_int);
            htp_config_set_response_decompression(cfg, s.response_decompression as c_int);
            htp_config_set_parse_request_cookies(cfg, s.parse_request_cookies as c_int);
            htp_config_set_tx_auto_destroy(cfg, 1);
            htp_config_register_transaction_complete(cfg, on_tx_complete);
            htp_config_register_request_body_data(cfg, on_request_body);
            htp_config_register_response_body_data(cfg, on_response_body);
            cfg
        };
        Http {
            cfg,
            keep_bodies: s.keep_bodies,
            flows: HashMap::new(),
        }
    }

    pub fn process(&mut self, events: Vec<Event>) -> Vec<Event> {
        let mut out = Vec::with_capacity(events.len());
        for ev in events {
            match ev {
                Event::Opened {
                    flow,
                    ts,
                    proto: Proto::Tcp,
                    client,
                    server,
                } => {
                    let hf = HttpFlow::new(self.cfg, self.keep_bodies, ts, client, server);
                    self.flows.insert(flow, hf);
                    out.push(ev);
                }
                Event::Data {
                    flow,
                    ts,
                    dir,
                    data,
                } => match self.flows.get_mut(&flow) {
                    Some(hf) if !hf.raw => {
                        hf.queue[dir as usize].push_back(Chunk::Data(data));
                        Self::pump(hf, flow, ts, &mut out);
                    }
                    _ => out.push(Event::Data {
                        flow,
                        ts,
                        dir,
                        data,
                    }),
                },
                Event::Gap { flow, ts, dir, len } => {
                    if let Some(hf) = self.flows.get_mut(&flow).filter(|hf| !hf.raw) {
                        hf.queue[dir as usize].push_back(Chunk::Gap(len));
                        Self::pump(hf, flow, ts, &mut out);
                    }
                    out.push(ev);
                }
                Event::Closed { flow, ts, .. } => {
                    if let Some(hf) = self.flows.remove(&flow) {
                        for tx in hf.close(ts) {
                            out.push(Event::Tx {
                                flow,
                                ts,
                                tx: Box::new(tx),
                            });
                        }
                    }
                    out.push(ev);
                }
                other => out.push(other),
            }
        }
        out
    }

    fn pump(hf: &mut HttpFlow, flow: u64, ts: f64, out: &mut Vec<Event>) {
        let mut raw = Vec::new();
        hf.pump(ts, &mut raw);
        for tx in hf.take_done() {
            out.push(Event::Tx {
                flow,
                ts,
                tx: Box::new(tx),
            });
        }
        for (dir, data) in raw {
            out.push(Event::Data {
                flow,
                ts,
                dir,
                data,
            });
        }
    }
}

impl Drop for Http {
    fn drop(&mut self) {
        self.flows.clear();
        unsafe { htp_config_destroy(self.cfg) };
    }
}
