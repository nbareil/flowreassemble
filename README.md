# flowreassemble

flowreassemble turns packet captures into application byte streams, so you
can write a decoder for a custom protocol (such as C2 traffic) in a few lines
of Python. It defragments IP, reassembles TCP and UDP flows, and parses HTTP
with libhtp. The engine is written in Rust and reads from libpcap directly,
either a pcap file or a live interface.

```python
from flowreassemble import conversations, pcap

h = pcap.open_offline("c2.pcap")
h.setfilter("host 203.0.113.7")

for conv in conversations(h, server=("203.0.113.7", 8443)):
    print(conv.client, "->", conv.server, conv.close_reason)
    for turn in conv.turns:
        print(f"  {turn.direction.value}: {turn.data[:64]!r}")
```

It is a modern take on libnids. It keeps libnids's model (IP
defragmentation, TCP reassembly, delivery of new bytes per direction) but
not its API: there are no callbacks and no global state, and every
connection's state lives on the flow.

Status: early development. The API can still change.

## Install

```sh
pip install flowreassemble
```

Wheels exist for Python 3.10 and later on Linux (x86_64 and aarch64, glibc
2.28 or later) and macOS (11 or later, Apple silicon and Intel). Linux wheels
contain their own libpcap, so you don't need to install one. macOS wheels use
the libpcap that ships with macOS. There are no Windows wheels.

## Two ways to read traffic

Both functions take the same source and options. Pick the one that matches
how much data you expect.

- `conversations()` yields one `Conversation` per connection after the
  connection closes, with all of its bytes. Use it for most investigations.
- `reassemble()` yields events as packets arrive and never holds bytes back.
  Use it for live capture, for long-lived connections, or when a capture is
  too large to keep each connection in memory.

### Conversations

```python
from flowreassemble import Direction, conversations, pcap

for conv in conversations(pcap.open_offline("c2.pcap")):
    beacon = conv.to_server  # every byte sent to the server
    tasking = conv.to_client
    for turn in conv.turns:  # direction changes, in order
        if turn.direction is Direction.TO_SERVER:
            ...
```

A `Conversation` has these fields:

| Field | Content |
| --- | --- |
| `client`, `server` | `(ipaddress, port)` pairs |
| `transport` | `"tcp"` or `"udp"` |
| `start`, `end` | Timestamps (seconds since the epoch, as `float`) |
| `close_reason` | `CloseReason.FIN`, `RST`, `TIMEOUT`, or `EOF` |
| `turns` | `Turn(direction, ts, data)` list. A TCP turn is all the bytes sent in one direction before the other side spoke; a UDP turn is one datagram. |
| `to_server`, `to_client` | All captured bytes of one direction, concatenated |
| `gaps` | `(direction, offset, length)` for bytes missing from the capture. `offset` counts every byte of that direction, missing ones included. |
| `anomalies` | `Anomaly(kind, direction, ts)`: `"overlap"` when a retransmission carried different bytes (the first copy is kept), `"truncated"` when `max_bytes` was reached |
| `transactions` | HTTP mode only: the `htp.Tx` objects, in order |
| `flow` | The `Flow`, the same object that `reassemble()` uses |

`max_bytes` caps the bytes kept per conversation, both directions together
(64 MiB by default; `None` removes the cap). Past the cap, the bytes are
dropped, a `"truncated"` anomaly is recorded, and the conversation is still
yielded.

### Events

```python
from flowreassemble import Closed, Data, Direction, Gap, Opened, pcap, reassemble

for ev in reassemble(pcap.open_offline("c2.pcap")):
    match ev:
        case Opened(flow):
            flow.state = MyDecoder()
        case Data(flow, Direction.TO_SERVER, data):
            flow.state.feed_request(data)
        case Data(flow, Direction.TO_CLIENT, data):
            flow.state.feed_response(data)
        case Gap(flow, direction, length):
            flow.state.resync(direction)
        case Closed(flow, reason):
            flow.state.done(reason)
```

| Event | Fields | Meaning |
| --- | --- | --- |
| `Opened` | `flow`, `ts` | A new connection (TCP) or exchange between two endpoints (UDP) |
| `Data` | `flow`, `direction`, `data`, `ts` | Bytes not delivered before. For UDP, exactly one datagram. |
| `Gap` | `flow`, `direction`, `length`, `ts` | `length` bytes of that direction were never captured |
| `Closed` | `flow`, `reason`, `ts` | The flow ended: `CloseReason.FIN`, `RST`, `TIMEOUT`, or `EOF` |

`flow.state` is yours: store your decoder's state there. It disappears with
the flow, so you don't need to clean anything up. `Data` only carries new
bytes; if a message spans several `Data` events, buffer it yourself.

Use `Direction.TO_SERVER` and `Direction.TO_CLIENT` in `case` patterns. A bare
name in a pattern captures the value instead of comparing it.

### Options

| Option | Default | Effect |
| --- | --- | --- |
| `server=` | `None` | The server, as an address or an `(address, port)` pair. Without it, the TCP handshake tells which side is the server; when the handshake isn't in the capture, the side with the lower port is. |
| `idle_timeout=` | `3600.0` | Seconds without packets before a flow closes with `TIMEOUT`. `None` means never. The default is large so that sparse beacons on one connection stay one conversation. |
| `http=` | `None` | An `htp.Config`: parse every TCP connection as HTTP (see [HTTP](#http)) |
| `max_bytes=` | 64 MiB | `conversations()` only: bytes kept per conversation |

When the input ends, every open flow closes with reason `EOF`, so no data is
lost.

## Packet sources

### Capture files and filters

`flowreassemble.pcap` exposes libpcap with its own names, without the `pcap_`
prefix. Open and filter the handle, then pass it to `reassemble()` or
`conversations()`:

```python
h = pcap.open_offline("c2.pcap")   # pcap or pcapng
h.setfilter("tcp and host 203.0.113.7")
h.datalink()                       # the link-layer type (DLT_*)
```

### Live capture

Live capture needs capture privileges: root or `CAP_NET_RAW` on Linux, access
to the BPF devices on macOS.

```python
h = pcap.open_live("eth0", 65535, True, 100)  # device, snaplen, promisc, timeout_ms
```

To reach every setting, use libpcap's create and activate sequence instead:

```python
h = pcap.create("eth0")
h.set_snaplen(65535)
h.set_immediate_mode(True)
h.set_buffer_size(16 << 20)
h.set_tstamp_precision("nano")
h.activate()
```

`pcap.findalldevs()` lists the devices you can open.

To stop a capture and still get the open flows, call `h.breakloop()`. It's
safe to call from a signal handler. `reassemble()` and `conversations()` then
close every open flow (reason `EOF`), yield what's left, and end normally:

```python
import signal

signal.signal(signal.SIGTERM, lambda *_: h.breakloop())
for conv in conversations(h):
    ...
```

Ctrl-C raises `KeyboardInterrupt` right away instead, and the flows still
open are not yielded.

### Any other frame source

Both functions also accept any iterable of `(timestamp, linktype, frame)`
tuples, such as frames read by dpkt or scapy. This is slower than a `pcap`
handle, because every frame crosses from Python into the engine.

```python
import dpkt

with open("c2.pcap", "rb") as f:
    reader = dpkt.pcap.Reader(f)
    frames = ((ts, reader.datalink(), buf) for ts, buf in reader)
    for conv in conversations(frames):
        ...
```

## HTTP

With `http=htp.Config(...)`, libhtp (0.5.53, vendored) parses every TCP
connection. In `reassemble()`, each HTTP transaction comes as an `htp.Tx`
event instead of `Data`. In `conversations()`, transactions go to
`conv.transactions`, and `turns` keeps only the bytes libhtp didn't parse.

```python
from flowreassemble import htp, pcap, reassemble

config = htp.Config(keep_bodies=10_000_000)
for ev in reassemble(pcap.open_offline("c2.pcap"), http=config):
    match ev:
        case htp.Tx() as tx if tx.parsed_uri.path == b"/my/c2/dispatcher/":
            if b"magic" in tx.request_cookies:
                print(tx.request_body, tx.response_status_number, tx.response_body)
```

`htp.Tx` is a copy of libhtp's `htp_tx_t`, with libhtp's field names:
`request_method`, `request_uri`, `parsed_uri`, `request_headers`,
`request_cookies`, `request_auth_username`, `response_status_number`,
`response_headers`, and so on. Byte strings are `bytes`, and a field is
`None` when libhtp has no value. Headers and cookies are `htp.Table` objects,
where lookups by name ignore case. Two fields are added: `flow` and `ts`.

`htp.Config` holds libhtp's settings, with libhtp's defaults:

| Setting | Default |
| --- | --- |
| `server_personality` | `htp.ServerPersonality.MINIMAL` |
| `request_decompression` | `False` |
| `response_decompression` | `True` |
| `parse_request_cookies` | `True` |
| `keep_bodies` | `None` |

`keep_bodies` isn't a libhtp setting. It keeps up to that many bytes of each
request and response body in `request_body` and `response_body`, de-chunked
and decompressed if decompression is on. Compare a body with
`request_entity_len` or `response_entity_len` to tell whether it was cut.

A transaction is yielded when libhtp completes it, or when its connection
closes; check `request_progress` and `response_progress` to tell. If libhtp
stops parsing a connection (after a CONNECT or a `101` tunnel, on a parse
error, or on a gap it refuses, such as one inside a request line), the rest of that connection comes as plain
`Data` events.

## What the reassembler handles

- **Link layers and encapsulation:** Ethernet, Linux cooked capture (SLL and
  SLL2), raw IP, null/loopback, VLAN and QinQ, MPLS, PPPoE, GRE, VXLAN, and
  IP-in-IP. VLAN traffic needs no special filter.
- **IP:** IPv4 and IPv6, IPv6 extension headers, and defragmentation of both.
- **Checksums are never verified**, so captures taken on a host with NIC
  offload work as they are.
- **Retransmissions and overlaps:** the first copy of each byte wins. A later
  copy with different content is reported as an `"overlap"` anomaly.
- **Missing data:** a hole is skipped and reported as a `Gap` when the
  receiver acknowledges data past it, when more than 16 MiB is buffered
  behind it, or when the connection closes.
- **Mid-stream pickup:** connections whose handshake isn't in the capture are
  still reassembled. Use `server=` when port numbers don't tell which side is
  the server.
- **Port reuse:** a new connection on the same address and port pair is a new
  flow, and late packets of a closed connection are dropped.

## Development

Everything runs in the Nix dev shell (`nix develop`), which provides Rust,
maturin, uv, Python, and libpcap.

```sh
nix develop
make dev      # create .venv and install the package in editable mode
make test     # Rust unit tests, then pytest
make lint     # rustfmt, clippy, ruff
make build    # release wheel
```

CI runs `make lint` and `make test` on Linux and macOS. To publish a release,
set the same version in `pyproject.toml` and `Cargo.toml`, then push a tag
named `vX.Y.Z`. The release workflow builds and tests the wheels and the
sdist, attaches them to a GitHub release, and uploads them to PyPI.

## License

BSD 3-Clause. The vendored libhtp (`vendor/libhtp/`) keeps its own license.
