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

It's a modern take on libnids. It keeps libnids's model (IP defragmentation,
TCP reassembly, delivery of new bytes per direction) but not its API: there
are no callbacks and no global state, and each connection's state lives on
its flow.

flowreassemble is in early development, and its API can still change.

```{toctree}
:maxdepth: 2
:caption: Guide

install
tutorial
conversations
events
sources
http
reassembly
```

```{toctree}
:maxdepth: 2
:caption: Reference

api
development
```
