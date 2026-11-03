//! `flowreassemble.pcap`: libpcap's own model, without the `pcap_` prefix.
//!
//! A `Handle` is libpcap's `pcap_t`. It is created inactive by `create()`
//! (configure it with `set_*`, then `activate()`), or ready to use by
//! `open_live()` and `open_offline()`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use pcap::{Active, BreakLoop, Capture, Inactive, Offline, Precision};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(pcap, Error, PyException, "Error reported by libpcap.");

fn err(e: pcap::Error) -> PyErr {
    Error::new_err(e.to_string())
}

pub enum State {
    Inactive(Capture<Inactive>),
    Active(Capture<Active>),
    Offline(Capture<Offline>),
    Closed,
}

pub enum Next {
    Packet(f64, Vec<u8>),
    Timeout,
    End,
    Failed(String),
}

impl State {
    /// Reads one packet. Called with the Python lock released.
    pub fn next(&mut self, nano: bool) -> Next {
        let res = match self {
            State::Active(c) => c.next_packet(),
            State::Offline(c) => c.next_packet(),
            _ => return Next::Failed("handle is not activated".into()),
        };
        match res {
            Ok(p) => {
                let frac = if nano { 1e-9 } else { 1e-6 };
                let ts = p.header.ts.tv_sec as f64 + p.header.ts.tv_usec as f64 * frac;
                Next::Packet(ts, p.data.to_vec())
            }
            Err(pcap::Error::TimeoutExpired) => Next::Timeout,
            Err(pcap::Error::NoMorePackets) => Next::End,
            Err(e) => Next::Failed(e.to_string()),
        }
    }
}

/// A libpcap capture handle (`pcap_t`).
#[pyclass(module = "flowreassemble.pcap", frozen)]
pub struct Handle {
    pub state: Mutex<State>,
    pub stop: AtomicBool,
    pub live: bool,
    pub nano: AtomicBool,
    /// The reassembly reading this handle (0: none). A handle feeds one
    /// reassembly at a time, otherwise packets would be split between them.
    pub owner: AtomicU64,
    breaker: Mutex<Option<BreakLoop>>,
}

impl Handle {
    fn new(state: State, live: bool, nano: bool) -> Self {
        let h = Handle {
            state: Mutex::new(state),
            stop: AtomicBool::new(false),
            live,
            nano: AtomicBool::new(nano),
            owner: AtomicU64::new(0),
            breaker: Mutex::new(None),
        };
        h.arm_breaker();
        h
    }

    fn arm_breaker(&self) {
        let mut st = self.state.lock().expect("pcap state lock");
        let b = match &mut *st {
            State::Active(c) => Some(c.breakloop_handle()),
            State::Offline(c) => Some(c.breakloop_handle()),
            _ => None,
        };
        *self.breaker.lock().expect("breaker lock") = b;
    }

    fn with_state<R>(&self, f: impl FnOnce(&mut State) -> PyResult<R>) -> PyResult<R> {
        let mut st = self
            .state
            .try_lock()
            .map_err(|_| Error::new_err("handle is in use by a running reassembly"))?;
        f(&mut st)
    }

    fn configure(&self, f: impl FnOnce(Capture<Inactive>) -> Capture<Inactive>) -> PyResult<()> {
        self.with_state(|st| match std::mem::replace(st, State::Closed) {
            State::Inactive(c) => {
                *st = State::Inactive(f(c));
                Ok(())
            }
            other => {
                *st = other;
                Err(Error::new_err("handle is already activated"))
            }
        })
    }
}

#[pymethods]
impl Handle {
    /// pcap_set_snaplen
    fn set_snaplen(&self, snaplen: i32) -> PyResult<()> {
        self.configure(|c| c.snaplen(snaplen))
    }

    /// pcap_set_promisc
    fn set_promisc(&self, promisc: bool) -> PyResult<()> {
        self.configure(|c| c.promisc(promisc))
    }

    /// pcap_set_timeout, in milliseconds
    fn set_timeout(&self, timeout_ms: i32) -> PyResult<()> {
        self.configure(|c| c.timeout(timeout_ms))
    }

    /// pcap_set_immediate_mode
    fn set_immediate_mode(&self, immediate: bool) -> PyResult<()> {
        self.configure(|c| c.immediate_mode(immediate))
    }

    /// pcap_set_buffer_size, in bytes
    fn set_buffer_size(&self, size: i32) -> PyResult<()> {
        self.configure(|c| c.buffer_size(size))
    }

    /// pcap_set_rfmon
    fn set_rfmon(&self, rfmon: bool) -> PyResult<()> {
        self.configure(|c| c.rfmon(rfmon))
    }

    /// pcap_set_tstamp_precision: "micro" or "nano"
    fn set_tstamp_precision(&self, precision: &str) -> PyResult<()> {
        let p = match precision {
            "micro" => Precision::Micro,
            "nano" => Precision::Nano,
            _ => return Err(Error::new_err("precision must be 'micro' or 'nano'")),
        };
        self.configure(|c| c.precision(p))?;
        self.nano.store(p == Precision::Nano, Ordering::Relaxed);
        Ok(())
    }

    /// pcap_activate
    fn activate(&self) -> PyResult<()> {
        self.with_state(|st| match std::mem::replace(st, State::Closed) {
            State::Inactive(c) => {
                *st = State::Active(c.open().map_err(err)?);
                Ok(())
            }
            other => {
                *st = other;
                Err(Error::new_err("handle is already activated"))
            }
        })?;
        self.arm_breaker();
        Ok(())
    }

    /// pcap_setfilter (compiled with pcap_compile)
    #[pyo3(signature = (expression, optimize = true))]
    fn setfilter(&self, expression: &str, optimize: bool) -> PyResult<()> {
        self.with_state(|st| match st {
            State::Active(c) => c.filter(expression, optimize).map_err(err),
            State::Offline(c) => c.filter(expression, optimize).map_err(err),
            _ => Err(Error::new_err("handle is not activated")),
        })
    }

    /// pcap_datalink: the link-layer header type (DLT_*)
    fn datalink(&self) -> PyResult<i32> {
        self.with_state(|st| match st {
            State::Active(c) => Ok(c.get_datalink().0),
            State::Offline(c) => Ok(c.get_datalink().0),
            _ => Err(Error::new_err("handle is not activated")),
        })
    }

    /// pcap_breakloop: makes a running `reassemble()` or `conversations()`
    /// on this handle close its open flows and end. Safe from a signal
    /// handler.
    fn breakloop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(b) = &*self.breaker.lock().expect("breaker lock") {
            b.breakloop();
        }
    }

    /// pcap_close
    fn close(&self) -> PyResult<()> {
        *self.breaker.lock().expect("breaker lock") = None;
        self.with_state(|st| {
            *st = State::Closed;
            Ok(())
        })
    }

    fn __repr__(&self) -> String {
        let kind = match self.state.try_lock().as_deref() {
            Ok(State::Inactive(_)) => "inactive",
            Ok(State::Active(_)) => "live",
            Ok(State::Offline(_)) => "offline",
            Ok(State::Closed) => "closed",
            Err(_) => "busy",
        };
        format!("<pcap.Handle {kind}>")
    }
}

/// pcap_open_offline. Timestamps are read at nanosecond precision.
#[pyfunction]
pub fn open_offline(path: std::path::PathBuf) -> PyResult<Handle> {
    let c = Capture::from_file_with_precision(&path, Precision::Nano).map_err(err)?;
    Ok(Handle::new(State::Offline(c), false, true))
}

/// pcap_create: an inactive handle, to configure with `set_*` then `activate()`.
#[pyfunction]
pub fn create(device: &str) -> PyResult<Handle> {
    let c = Capture::from_device(device).map_err(err)?;
    Ok(Handle::new(State::Inactive(c), true, false))
}

/// pcap_open_live
#[pyfunction]
pub fn open_live(device: &str, snaplen: i32, promisc: bool, timeout_ms: i32) -> PyResult<Handle> {
    let c = Capture::from_device(device)
        .map_err(err)?
        .snaplen(snaplen)
        .promisc(promisc)
        .timeout(timeout_ms)
        .open()
        .map_err(err)?;
    Ok(Handle::new(State::Active(c), true, false))
}

/// pcap_findalldevs: names of the devices that can be opened.
#[pyfunction]
pub fn findalldevs() -> PyResult<Vec<String>> {
    Ok(pcap::Device::list()
        .map_err(err)?
        .into_iter()
        .map(|d| d.name)
        .collect())
}
