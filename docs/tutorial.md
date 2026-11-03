# Tutorial: decode a C2 protocol

This tutorial writes a decoder for a small, made-up C2 protocol, first with
`conversations()`, then with `reassemble()`. The protocol runs over TCP to
`203.0.113.7:8443`. Each message is a 4-byte big-endian length, then a payload
XORed with the byte `0x5A`. The implant sends a beacon, and the server answers
with a task.

## Split a stream into messages

flowreassemble delivers byte streams, not messages: TCP doesn't keep message
boundaries, so one segment can carry half a message, or three. The decoder's
first job is framing. This function takes the bytes received so far and
returns the complete messages, plus the bytes left over:

```python
import struct

KEY = 0x5A


def messages(stream: bytes) -> tuple[list[bytes], bytes]:
    out = []
    while len(stream) >= 4:
        (length,) = struct.unpack_from(">I", stream)
        if len(stream) < 4 + length:
            break  # the rest of this message hasn't arrived yet
        out.append(bytes(b ^ KEY for b in stream[4 : 4 + length]))
        stream = stream[4 + length :]
    return out, stream
```

## Decode whole conversations

`conversations()` yields each connection once it closes, with each direction's
bytes already concatenated, so framing happens once per direction:

```python
from flowreassemble import conversations, pcap

h = pcap.open_offline("beacons.pcap")
h.setfilter("tcp and host 203.0.113.7")

for conv in conversations(h, server=("203.0.113.7", 8443)):
    beacons, _ = messages(conv.to_server)
    tasks, _ = messages(conv.to_client)
    print(conv.client[0], conv.close_reason.name, beacons, tasks)
    if conv.gaps:
        print("  bytes missing from the capture:", conv.gaps)
```

The filter keeps only the C2 traffic, and `server=` names the server, so
direction is right even for a connection whose handshake the capture missed.
Opening and filtering are done on the `pcap` handle, with libpcap's own
functions.

When the order of messages across directions matters (which task answered
which beacon), walk `conv.turns` instead. Each turn holds the bytes one side
sent before the other side spoke:

```python
for turn in conv.turns:
    msgs, _ = messages(turn.data)
    print(turn.direction.value, msgs)
```

This works when each message fits in one turn, which is the case for most
request-response protocols. Otherwise, frame each direction's stream as above.

## Decode as packets arrive

`conversations()` keeps every connection in memory until it closes. For a
live capture, or for one connection that lasts for days, use `reassemble()`:
it yields events as packets are reassembled and keeps nothing for you. The
decoder then has to buffer partial messages itself, and the place to keep that
buffer is `flow.state`:

```python
from flowreassemble import Closed, Data, Direction, Gap, Opened, pcap, reassemble


class Decoder:
    def __init__(self) -> None:
        self.pending = {Direction.TO_SERVER: b"", Direction.TO_CLIENT: b""}
        self.broken = False

    def feed(self, direction: Direction, data: bytes) -> list[bytes]:
        msgs, self.pending[direction] = messages(self.pending[direction] + data)
        return msgs


h = pcap.open_offline("beacons.pcap")
h.setfilter("tcp and host 203.0.113.7")

for ev in reassemble(h, server=("203.0.113.7", 8443)):
    match ev:
        case Opened(flow):
            flow.state = Decoder()
        case Data(flow, direction, data) if not flow.state.broken:
            for msg in flow.state.feed(direction, data):
                print(flow.client[0], direction.value, msg)
        case Gap(flow):
            # The framing is lost: this protocol has no way to resynchronize.
            flow.state.broken = True
        case Closed(flow, reason):
            print(flow.client[0], "closed:", reason.name)
```

`flow.state` belongs to the flow, and it's dropped with the flow when the
connection closes: there's no table of connections to clean up.

Each `Data` event carries only bytes never delivered before, in stream order.
Retransmissions are already removed. A `Gap` says how many bytes of that
direction are missing; the bytes after it come in the next `Data` event.

## Next steps

- [Conversations](conversations.md) and [Events](events.md) describe both
  layers in full.
- [Packet sources](sources.md) covers live capture and frames read by other
  libraries.
- If the C2 protocol runs over HTTP, let libhtp parse it: see [HTTP](http.md).
