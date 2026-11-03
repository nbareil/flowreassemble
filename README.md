# flowreassemble

IP defragmentation and TCP/UDP flow reassembly for Python, written in Rust.
A modern take on libnids, built for writing quick decoders of application
protocols (such as C2 traffic) from packet captures or live interfaces.

```python
from flowreassemble import reassemble, conversations, Data, Direction, pcap

h = pcap.open_offline("c2.pcap")
h.setfilter("host 203.0.113.7")

for ev in reassemble(h, server=("203.0.113.7", 8443)):
    match ev:
        case Data(flow, Direction.TO_SERVER, data):
            ...

for conv in conversations(pcap.open_offline("c2.pcap")):
    for turn in conv.turns:
        print(turn.direction, turn.data[:64])
```

HTTP is parsed by libhtp, exposed with its own model and names:

```python
from flowreassemble import reassemble, htp, pcap

for ev in reassemble(pcap.open_offline("c2.pcap"), http=htp.Config(keep_bodies=10_000_000)):
    match ev:
        case htp.Tx() as tx if tx.parsed_uri.path == b"/my/c2/dispatcher/":
            if b"magic" in tx.request_cookies:
                print(tx.request_body, tx.response_status_number, tx.response_body)
```

Status: early development.
