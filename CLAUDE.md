# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

Early development. TCP/UDP reassembly, `reassemble()`, `conversations()`, the
`pcap` submodule, and HTTP through libhtp (`htp` submodule, `http=` option)
work. Not done yet: bundling libpcap into Linux wheels, CI (including fuzzing
the HTTP path), and tests of live capture (they need capture privileges).

## Commands

Everything runs inside the Nix dev shell, which provides Rust, maturin, uv,
Python 3.12, libpcap, zlib and pkg-config: `nix develop` (or prefix any command
with `nix develop -c`).

- `make dev`: create `.venv` (uv) and install the package in editable mode.
- `make test`: Rust unit tests, then rebuild and run pytest.
- `make lint` / `make format`: rustfmt, clippy (`-D warnings`), ruff.
- `make build`: release wheel (abi3, one wheel for Python 3.10+).
- Single Python test: `uv run --no-sync pytest tests/test_tcp.py::test_rst_closes_the_flow`
  (run `maturin develop --uv` first if Rust code changed).
- Single Rust test: `cargo test segments::tests::covers_detects_holes`.

## Architecture

Two layers: a Rust engine (`src/`, compiled as `flowreassemble._native`) and
the public Python API (`python/flowreassemble/`).

- `src/decode.rs`: frame → TCP/UDP packet. Link layers (Ethernet, SLL, SLL2,
  raw, null/loop), VLAN/QinQ, MPLS, PPPoE, GRE, VXLAN, IP-in-IP, IPv6
  extension headers, IPv4/IPv6 defragmentation. Checksums are never checked.
- `src/segments.rs`: out-of-order byte ranges with first-copy-wins overlaps,
  shared by defragmentation and TCP.
- `src/flows.rs`: flow table and TCP/UDP reassembly; emits `Event`s. It holds
  the rules: picking the client (handshake, then `server=` hint, then lower
  port), a packet's ACK applied before its payload (so released data keeps
  its order), port reuse (a SYN whose sequence number differs from the
  connection's ISN), gaps (skipped when the receiver ACKs past buffered data, when more
  than 16 MiB is buffered, or at close), overlaps, idle timeout,
  and closing everything at end of input. A FIN marks the end of its
  direction's stream: an ACK reaching it proves the bytes before it, and
  nothing past it is delivered. After a FIN/RST close, the connection's
  sequence numbers are kept for 120 s (`Linger`), to drop its late packets
  while still seeing a new connection on the same 4-tuple.
  Encapsulation depth (`MAX_DEPTH` in `decode.rs`) also counts nested IP
  fragment reassemblies; keep every recursive decode path bounded by it.
- `src/pcap_handle.rs`: the `pcap` submodule. One `Handle` (`pcap_t`) moves
  through libpcap's states (inactive → active, or offline). A handle feeds one
  reassembly at a time (`owner`); `breakloop()` only sets a flag, which works
  without the capture lock. Live handles are made non-blocking when activated
  and each read waits at most 100 ms, so Ctrl-C and `breakloop()` always get
  control back: a blocked libpcap read can't be interrupted.
- `src/lib.rs`: `_native.Reassembler`. `push()` takes one frame, `run(handle)`
  reads packets with the Python lock released and returns batches of event
  tuples, `finish()` closes everything. The tuple format is documented at the
  top of the file.
- `src/http.rs` + `src/htp_shim.c`: HTTP mode. A post-processor over the
  reassembler's events: TCP `Data`/`Gap` go into one libhtp connection parser
  per flow, and libhtp hooks copy each completed `htp_tx_t` into a `Tx` event
  (incomplete ones are copied at close). Rust never touches libhtp structs
  directly: the C shim exposes fields by number (the name lists in `http.rs`
  must match the shim's `switch` order). libhtp's suspended parsing
  (`HTP_STREAM_DATA_OTHER`) is handled with per-direction queues; on
  `TUNNEL`/`ERROR`/`STOP` the rest of the connection becomes plain `Data`
  (libhtp's read-but-unparsed bytes are recovered by `fr_connp_buffered` and
  `fr_connp_current_unparsed`). Copy anything from libhtp's current data
  before the chunk it points into is dropped.
- `vendor/libhtp/`: libhtp 0.5.53, built by `build.rs` with the `cc` crate
  (no autotools). `vendor/libhtp/README.md` lists every local change; keep it
  up to date.
- `python/flowreassemble/_reassemble.py`: wraps event tuples into `Opened`,
  `Data`, `Gap` and `Closed` dataclasses and `Flow` objects. Overlap events are
  dropped here, except for `conversations()`.
- `python/flowreassemble/_conversations.py`: builds `Conversation` objects
  (turns, gaps with stream offsets, anomalies, `max_bytes`) from the same
  event stream.

Tests: most behavior is tested with pytest (`tests/`). `tests/packets.py`
builds frames and pcap files in pure Python (`Conn` drives a TCP connection),
so tests need no fixture files or third-party packet libraries. Rust unit tests
cover small internals.

## Goal

A modern reimplementation of libnids (IP defragmentation + TCP stream
reassembly, delivering application-layer byte streams) written in Rust, with
first-class Python bindings. The main use case is incident response: writing
quick, throwaway decoders for custom C2 protocols from pcap files.

Keep what libnids taught; drop what it did only because of its era. There is
no compatibility requirement with libnids or pynids: don't reproduce their
API, names, or quirks.

**Target workflow:** the pcap is already filtered down to one protocol between
one client and one server. It can still contain many sequential connections
(for example, one per beacon), but never a mix of protocols. Don't build
multi-protocol dispatch.

## Decisions

- **Name:** `flowreassemble` for the PyPI package, the Python import, and the
  Rust crate.
- **Python first.** About 90% of usage will be from Python. Design the Python
  API first; the Rust crate is the engine, not a stable public API.
- **Layout:** plain maturin layout (PyO3). Don't use the author's cookiecutter
  template. The project will be published on github.com.
- **Python API shape:** two layers over one core.
  - *Event iterator:* `for ev in reassemble(handle, ...): match ev: ...` with `Opened`,
    `Data(flow, direction, data)`, `Gap`, and `Closed(reason)`. UDP uses
    `Data` too: one event per datagram, with boundaries preserved. In HTTP
    mode, libhtp's transaction object (`htp.Tx`, for `htp_tx_t`) is yielded
    directly as the event, with no wrapper event type. Per-flow user state
    lives on `flow.state`, not in user dicts. Directions are a `Direction`
    enum (a bare name in a `case` pattern would capture, not compare). There
    is no anomaly event in this layer.
  - *Conversations:* `conversations(...)` yields one object per connection,
    once the connection closes. It has `client`, `server`, `start`, `end`,
    `close_reason`, direction-merged `turns`, `to_server` / `to_client`
    (concatenated bytes), `gaps`, `anomalies` (such as retransmissions with
    different content), and in HTTP mode `transactions` (a list of `htp.Tx`).
    Memory per connection is capped by `max_bytes=`. Past the cap, bytes are
    dropped, the truncation is recorded in `anomalies`, and the conversation
    is still yielded.
  - The event iterator never holds back bytes for the user: each `Data`
    carries only new bytes, and buffering partial messages is the user's job.
    There is no equivalent of libnids's `discard`.
  - Both layers take a libpcap handle (`reassemble(handle, ...)`,
    `conversations(handle, ...)`) with the same options (`server=`, `http=`,
    `max_bytes=`, ...). Opening and filtering are done on the handle, not
    through options of ours.
- **No user callbacks.** Everything goes through the iterator. libhtp hooks
  are used internally by the glue and are not exposed for registration.
- **Directions** are named by where the data goes: `to_server` and
  `to_client`.
- **Packet source: libpcap, exposed, not hidden.** It's bundled into the
  wheels. As with `htp`, a `flowreassemble.pcap` submodule mirrors libpcap's
  own model and names, without the `pcap_` prefix: `pcap.open_offline(path)`,
  both live-capture APIs (`pcap.open_live(device, snaplen, promisc,
  timeout_ms)`, and `pcap.create(device)` → `set_*` (snaplen, promisc,
  timeout, immediate_mode, buffer_size, tstamp_precision, ...) →
  `activate()`), `handle.setfilter(bpf)`, `handle.datalink()`. The user opens
  and filters the handle, then passes it to `reassemble()` or
  `conversations()`. Don't add `read_pcap()` / `capture()`-style shortcuts or
  `bpf=` options that hide it. The reassembly core takes packets as input and
  doesn't depend on libpcap.
- **Any frame source works too:** `reassemble()` and `conversations()` also
  accept any iterable of `(timestamp, linktype, frame)` (scapy, dpkt, test
  fixtures). It's slower than a `pcap` handle because every frame crosses from
  Python.
- **End of input closes everything:** when the input ends, every open flow is
  closed (reason `EOF`), so nothing is lost.
- **Idle timeout:** `idle_timeout=` in seconds, default 1 hour, with `None`
  meaning never. Sparse C2 beacons on one long-lived connection must stay one
  conversation, which is why the default is large. Time comes from packet
  timestamps; during live capture it also advances on the wall clock.
- **Stopping live capture:** `handle.breakloop()` (libpcap's own mechanism,
  safe to call from a signal handler) makes `reassemble()` and
  `conversations()` close and yield the open flows, then end normally. A plain
  Ctrl-C raises `KeyboardInterrupt` right away, and the flows still open are
  not yielded.
- **Why `pcap` is a submodule and not a separate package:** the Rust core
  reads packets from the handle directly. That keeps per-packet work out of
  Python, releases the Python lock while blocking, and allows Ctrl-C. It's
  only safe when the handle and the core share one libpcap copy, meaning one
  compiled extension; each wheel bundles its own private libpcap. The
  top-level `pcap` import name is also taken on PyPI.
- **Platforms:** Linux and macOS first. Windows is best effort: libpcap there
  means Npcap, which users install themselves and which we can't bundle.
- **Python:** 3.10+ (the API relies on `match`).
- **Live capture is required in v1.** It needs capture privileges (root or
  `CAP_NET_RAW` on Linux, BPF device access on macOS). Idle timeouts close
  flows, so conversations are yielded even when a connection never ends.
  Ctrl-C must stop a blocking capture cleanly.
- **HTTP is first-class, via the C libhtp (0.5.x, last release 0.5.53).** Its
  full public API is needed: every hook, and the public `htp_tx_t` with
  cookies, parsed URI, and auth. libhtp reached end-of-life in July 2026, so
  security fixes are now this project's responsibility. Build it from vendored
  source through `build.rs` (it needs zlib and iconv; it bundles its own LZMA
  decoder), and fuzz the HTTP path
  in CI. The Rust port (`suricata-htp`) was rejected because almost all of its
  API is `pub(crate)`.
- **HTTP details (implemented):** `htp.Config()` defaults are those of
  `htp_config_create()` (personality `MINIMAL`, response decompression on,
  request decompression off, cookie parsing on). `htp.Tx` fields carry
  libhtp's names; only `flow` and `ts` are ours, plus the opt-in
  `request_body`/`response_body` (`keep_bodies`). Every TCP connection is
  parsed as HTTP in HTTP mode; `Gap` events still pass through. Bytes libhtp
  does not parse come as `Data`: after it stops (CONNECT or 101 tunnel, parse
  error, or a gap it refuses, such as one inside a request line), the bytes it
  had buffered and the rest of the connection; at close, bytes it still holds.
  A stopped parser is never asked to finalize (no `htp_connp_close`).
  `conversations(max_bytes=)` counts kept HTTP bodies too.
- **Expose libhtp, don't hide it.** Python sees libhtp's own model and names
  (`htp.Config`, `htp.Tx`, its field names, raw `bytes` values). This library
  adds only the glue (one connection parser per HTTP flow, feeding both
  directions, gaps, timestamps, close) and conveniences that are opt-in and
  explicitly named, such as keeping bodies in memory up to a cap. Don't add a
  parallel HTTP abstraction.
- **Overlapping retransmissions:** keep the first copy of each byte. When a
  later copy has different content, report it.
- **Mid-stream pickup:** connections whose handshake isn't in the capture are
  still reassembled. Direction is guessed from ports unless the user names the
  server.

## Reference: how the author uses pynids today

Workflow from
<https://justanothergeek.chdir.org/2020/11/Decoding-C2-Traffic-in-Python-or-HOWTO-eat-during-an-IR-engagement/>
(template:
<https://gist.github.com/nbareil/07307dee653ef3400cd3ece0c7a35799>):
pynids feeds reassembled TCP data into htpy (libhtp) to parse HTTP C2 traffic.

Pain points in that template, which the new design should eliminate:

- Per-connection state kept in global dicts keyed by `tcp.addr`, cleaned up by
  hand (or leaked).
- Manual dispatch on `nids_state` (`JUST_EST` / `DATA` / `CLOSE` / `TIMEOUT` /
  `RESET`) and `collect = 1` boilerplate.
- Confusing direction naming: `tcp.client.count_new` means data sent *by the
  server*.
- Slicing `data[:count_new]` by hand.
- Callback exceptions swallowed by the C layer, so every callback is wrapped
  in try/except.
- Global, string-keyed config (`nids.param(...)`, `nids.chksum_ctl(...)`), a
  single global instance, and `nids.run()` owning the loop.
- Checksum verification has to be disabled explicitly for captures with NIC
  offload.
- VLAN traffic needs an explicit `vlan and ...` BPF filter.
- Painful to build (the post resorts to Docker with pinned versions).
