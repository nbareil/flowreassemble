# Packet sources

`reassemble()` and `conversations()` read from a libpcap handle, or from any
iterable of frames.

## Capture files and filters

`flowreassemble.pcap` exposes libpcap with its own names, without the `pcap_`
prefix. Open and filter the handle, then pass it to `reassemble()` or
`conversations()`:

```python
from flowreassemble import pcap

h = pcap.open_offline("c2.pcap")  # pcap or pcapng
h.setfilter("tcp and host 203.0.113.7")
h.datalink()  # the link-layer type (DLT_*)
```

`setfilter()` takes libpcap's filter syntax (see `pcap-filter(7)`).
flowreassemble decodes VLAN-tagged frames without help, but libpcap filters
see the tag: in a capture file, `host 203.0.113.7` doesn't match tagged
frames. To match both, write `host 203.0.113.7 or (vlan and host
203.0.113.7)`.

A handle feeds one `reassemble()` or `conversations()` at a time, and a file
handle is read once: to read the file again, open it again.

## Live capture

Live capture needs capture privileges: root or `CAP_NET_RAW` on Linux, and
read access to the BPF devices on macOS.

`open_live()` opens and activates a handle in one call:

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

During live capture, idle timeouts advance on the wall clock as well as on
packet timestamps, so flows still close when the network goes quiet. A
connection that never ends is still yielded by `conversations()` once it has
been idle for `idle_timeout` seconds.

### Stopping a capture

`h.breakloop()` stops a capture and keeps the data. `reassemble()` and
`conversations()` then close every open flow (reason `EOF`), yield what's
left, and end normally. `breakloop()` is safe to call from a signal handler
or from another thread:

```python
import signal

signal.signal(signal.SIGTERM, lambda *_: h.breakloop())
for conv in conversations(h):
    ...
```

Ctrl-C raises `KeyboardInterrupt` right away instead, and the flows still
open are not yielded. To keep them on Ctrl-C, call `breakloop()` from a
`SIGINT` handler.

The capture reads with the Python lock released, so other Python threads keep
running during a capture.

## Any other frame source

Both functions also accept any iterable of `(timestamp, linktype, frame)`
tuples: `timestamp` in seconds since the epoch, `linktype` a `DLT_*` value
(1 for Ethernet), and `frame` the raw bytes. Use it for frames read by dpkt or
scapy, or built by a test. It's slower than a `pcap` handle, because every
frame crosses from Python into the engine.

```python
import dpkt

from flowreassemble import conversations

with open("c2.pcap", "rb") as f:
    reader = dpkt.pcap.Reader(f)
    frames = ((ts, reader.datalink(), buf) for ts, buf in reader)
    for conv in conversations(frames):
        ...
```

## Link-layer types

The reassembler decodes these link-layer types:

| `linktype` | Name |
| --- | --- |
| 1 | Ethernet (`DLT_EN10MB`) |
| 0, 108 | Null and loopback (`DLT_NULL`, `DLT_LOOP`) |
| 12, 14, 101, 228, 229 | Raw IPv4 or IPv6 (`DLT_RAW`, `LINKTYPE_RAW`, `LINKTYPE_IPV4`, `LINKTYPE_IPV6`) |
| 113 | Linux cooked capture (`DLT_LINUX_SLL`) |
| 276 | Linux cooked capture v2 (`DLT_LINUX_SLL2`) |

Frames of other types are ignored.
