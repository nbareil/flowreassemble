//! Native engine for the `flowreassemble` Python package.
//!
//! The Python layer (`python/flowreassemble/`) is the public API. This module
//! turns frames into compact event tuples that the Python layer wraps:
//!
//! - `("opened", flow_id, ts, "tcp" | "udp", (client_ip, port), (server_ip, port))`
//! - `("data", flow_id, ts, direction, bytes)`
//! - `("gap", flow_id, ts, direction, length)`
//! - `("overlap", flow_id, ts, direction)`
//! - `("closed", flow_id, ts, "FIN" | "RST" | "TIMEOUT" | "EOF")`
//! - `("tx", flow_id, ts, fields)`: HTTP mode only. `fields` is a dict named
//!   after libhtp's `htp_tx_t` fields (see `http.rs`).
//!
//! `direction` is 0 (to the server) or 1 (to the client).

mod decode;
mod flows;
mod http;
mod pcap_handle;
mod segments;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use decode::Decoder;
use flows::{CloseReason, Event, Proto};
use pcap_handle::{Handle, Next};

const BATCH: usize = 4096;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[pyclass(module = "flowreassemble._native")]
struct Reassembler {
    id: u64,
    decoder: Decoder,
    flows: flows::Reassembler,
    finished: bool,
    handle: Option<Py<Handle>>,
    http: Option<http::Http>,
}

fn endpoint(ep: (IpAddr, u16)) -> (String, u16) {
    (ep.0.to_string(), ep.1)
}

fn to_py(py: Python<'_>, events: Vec<Event>) -> PyResult<Vec<Py<PyAny>>> {
    events
        .into_iter()
        .map(|e| {
            let obj = match e {
                Event::Opened {
                    flow,
                    ts,
                    proto,
                    client,
                    server,
                } => {
                    let proto = match proto {
                        Proto::Tcp => "tcp",
                        Proto::Udp => "udp",
                    };
                    (
                        "opened",
                        flow,
                        ts,
                        proto,
                        endpoint(client),
                        endpoint(server),
                    )
                        .into_pyobject(py)?
                        .into_any()
                }
                Event::Data {
                    flow,
                    ts,
                    dir,
                    data,
                } => ("data", flow, ts, dir, PyBytes::new(py, &data))
                    .into_pyobject(py)?
                    .into_any(),
                Event::Gap { flow, ts, dir, len } => {
                    ("gap", flow, ts, dir, len).into_pyobject(py)?.into_any()
                }
                Event::Overlap { flow, ts, dir } => {
                    ("overlap", flow, ts, dir).into_pyobject(py)?.into_any()
                }
                Event::Closed { flow, ts, reason } => {
                    let reason = match reason {
                        CloseReason::Fin => "FIN",
                        CloseReason::Rst => "RST",
                        CloseReason::Timeout => "TIMEOUT",
                        CloseReason::Eof => "EOF",
                    };
                    ("closed", flow, ts, reason).into_pyobject(py)?.into_any()
                }
                Event::Tx { flow, ts, tx } => ("tx", flow, ts, tx_dict(py, &tx)?)
                    .into_pyobject(py)?
                    .into_any(),
            };
            Ok(obj.unbind())
        })
        .collect()
}

fn opt_bytes<'py>(py: Python<'py>, b: &Option<Vec<u8>>) -> Option<Bound<'py, PyBytes>> {
    b.as_ref().map(|b| PyBytes::new(py, b))
}

fn pairs<'py>(py: Python<'py>, p: &http::Pairs) -> Vec<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    p.iter()
        .map(|(k, v)| (PyBytes::new(py, k), PyBytes::new(py, v)))
        .collect()
}

fn uri_dict<'py>(
    py: Python<'py>,
    u: &Option<http::UriCopy>,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let Some(u) = u else { return Ok(None) };
    let d = PyDict::new(py);
    for (name, value) in http::URI_BYTES.iter().zip(&u.bytes) {
        d.set_item(name, opt_bytes(py, value))?;
    }
    d.set_item("port_number", u.port_number)?;
    Ok(Some(d))
}

fn tx_dict<'py>(py: Python<'py>, tx: &http::TxCopy) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    for (name, value) in http::TX_BYTES.iter().zip(&tx.bytes) {
        d.set_item(name, opt_bytes(py, value))?;
    }
    for (name, value) in http::TX_INTS.iter().zip(&tx.ints) {
        d.set_item(name, value)?;
    }
    d.set_item("parsed_uri", uri_dict(py, &tx.parsed_uri)?)?;
    d.set_item("parsed_uri_raw", uri_dict(py, &tx.parsed_uri_raw)?)?;
    d.set_item("request_headers", pairs(py, &tx.request_headers))?;
    d.set_item("response_headers", pairs(py, &tx.response_headers))?;
    d.set_item("request_cookies", pairs(py, &tx.request_cookies))?;
    d.set_item("request_body", opt_bytes(py, &tx.request_body))?;
    d.set_item("response_body", opt_bytes(py, &tx.response_body))?;
    Ok(d)
}

fn http_settings(d: &Bound<'_, PyDict>) -> PyResult<http::Settings> {
    let get = |k: &str| -> PyResult<Bound<'_, PyAny>> {
        d.get_item(k)?
            .ok_or_else(|| PyValueError::new_err(format!("missing http setting: {k}")))
    };
    Ok(http::Settings {
        server_personality: get("server_personality")?.extract()?,
        request_decompression: get("request_decompression")?.extract()?,
        response_decompression: get("response_decompression")?.extract()?,
        parse_request_cookies: get("parse_request_cookies")?.extract()?,
        keep_bodies: get("keep_bodies")?.extract()?,
    })
}

fn wall_clock() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[pymethods]
impl Reassembler {
    #[new]
    #[pyo3(signature = (server, idle_timeout, http = None))]
    fn new(
        server: Option<(String, Option<u16>)>,
        idle_timeout: Option<f64>,
        http: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let server = server
            .map(|(ip, port)| {
                ip.parse::<IpAddr>()
                    .map(|ip| (ip, port))
                    .map_err(|_| PyValueError::new_err(format!("invalid server address: {ip}")))
            })
            .transpose()?;
        Ok(Reassembler {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            decoder: Decoder::default(),
            flows: flows::Reassembler::new(server, idle_timeout),
            finished: false,
            handle: None,
            http: http
                .map(http_settings)
                .transpose()?
                .map(|s| http::Http::new(&s)),
        })
    }

    /// Feeds one frame. Returns the events it produced.
    fn push(
        &mut self,
        py: Python<'_>,
        ts: f64,
        linktype: i32,
        frame: &[u8],
    ) -> PyResult<Vec<Py<PyAny>>> {
        let mut out = Vec::new();
        if let Some(p) = self.decoder.decode(ts, linktype, frame) {
            self.flows.push(ts, p, &mut out);
        } else {
            self.flows.advance(ts, &mut out);
        }
        self.emit(py, out)
    }

    /// End of input: closes every open flow.
    fn finish(&mut self, py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
        let mut out = Vec::new();
        if !self.finished {
            self.finished = true;
            self.flows.finish(&mut out);
        }
        self.emit(py, out)
    }

    /// Reads packets from a pcap handle until some events are ready.
    /// Returns None once the input has ended and every flow was closed.
    fn run(
        &mut self,
        py: Python<'_>,
        handle: &Bound<'_, Handle>,
    ) -> PyResult<Option<Vec<Py<PyAny>>>> {
        if self.finished {
            return Ok(None);
        }
        let h = handle.get();
        if self.handle.is_none() {
            h.owner
                .compare_exchange(0, self.id, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| {
                    pcap_handle::Error::new_err("handle is already read by another reassembly")
                })?;
            self.handle = Some(handle.clone().unbind());
        }
        let nano = h.nano.load(Ordering::Relaxed);
        let mut guard = h
            .state
            .try_lock()
            .map_err(|_| pcap_handle::Error::new_err("handle is busy"))?;
        let linktype = match &*guard {
            pcap_handle::State::Active(c) => c.get_datalink().0,
            pcap_handle::State::Offline(c) => c.get_datalink().0,
            _ => return Err(PyValueError::new_err("handle is not activated")),
        };
        let mut out = Vec::new();
        let mut ended = false;
        for _ in 0..BATCH {
            if h.stop.load(Ordering::SeqCst) {
                ended = true;
                break;
            }
            let state: &mut pcap_handle::State = &mut guard;
            match py.detach(|| state.next(nano)) {
                Next::Packet(ts, frame) => match self.decoder.decode(ts, linktype, &frame) {
                    Some(p) => self.flows.push(ts, p, &mut out),
                    None => self.flows.advance(ts, &mut out),
                },
                Next::Timeout => {
                    if h.live {
                        self.flows.advance(wall_clock(), &mut out);
                    }
                    py.check_signals()?;
                }
                Next::End => {
                    ended = true;
                    break;
                }
                Next::Failed(msg) => {
                    if h.stop.load(Ordering::SeqCst) {
                        ended = true;
                        break;
                    }
                    return Err(pcap_handle::Error::new_err(msg));
                }
            }
            if !out.is_empty() {
                break;
            }
        }
        drop(guard);
        if ended {
            self.finished = true;
            self.release();
            self.flows.finish(&mut out);
        } else {
            py.check_signals()?;
        }
        self.emit(py, out).map(Some)
    }
}

impl Reassembler {
    fn emit(&mut self, py: Python<'_>, out: Vec<Event>) -> PyResult<Vec<Py<PyAny>>> {
        let out = match &mut self.http {
            Some(h) => h.process(out),
            None => out,
        };
        to_py(py, out)
    }

    fn release(&mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h
                .get()
                .owner
                .compare_exchange(self.id, 0, Ordering::SeqCst, Ordering::SeqCst);
        }
    }
}

impl Drop for Reassembler {
    fn drop(&mut self) {
        self.release();
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Reassembler>()?;
    m.add_class::<Handle>()?;
    m.add("PcapError", m.py().get_type::<pcap_handle::Error>())?;
    m.add_function(wrap_pyfunction!(pcap_handle::open_offline, m)?)?;
    m.add_function(wrap_pyfunction!(pcap_handle::open_live, m)?)?;
    m.add_function(wrap_pyfunction!(pcap_handle::create, m)?)?;
    m.add_function(wrap_pyfunction!(pcap_handle::findalldevs, m)?)?;
    Ok(())
}
