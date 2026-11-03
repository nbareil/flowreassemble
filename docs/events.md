# Events

`reassemble()` yields events as packets are reassembled, and never holds
bytes back for you. Use it for live capture, for long-lived connections, or
for captures too large to keep each connection in memory. For whole
connections at once, use [conversations](conversations.md).

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

## Event types

| Event | Fields | Meaning |
| --- | --- | --- |
| `Opened` | `flow`, `ts` | A new connection (TCP) or exchange between two endpoints (UDP) |
| `Data` | `flow`, `direction`, `data`, `ts` | Bytes not delivered before. For UDP, exactly one datagram. |
| `Gap` | `flow`, `direction`, `length`, `ts` | `length` bytes of that direction were never captured |
| `Closed` | `flow`, `reason`, `ts` | The flow ended: `CloseReason.FIN`, `RST`, `TIMEOUT`, or `EOF` |
| `htp.Tx` | see [HTTP](http.md) | HTTP mode only: one HTTP transaction |

Every flow starts with `Opened` and ends with `Closed`. Events of different
flows interleave in packet order.

## Matching on directions

Use `Direction.TO_SERVER` and `Direction.TO_CLIENT` in `case` patterns, not
bare names. A bare name in a pattern captures the value instead of comparing
it: `case Data(flow, TO_SERVER, data)` matches every `Data` event.

Directions are named by where the data goes. `TO_SERVER` is what the client
sent.

## Per-flow state

`flow.state` is yours: it starts as `None`, and you can store anything in it,
such as a decoder object. It disappears with the flow, so there's no table of
connections to clean up, and two connections between the same hosts never
share state.

## New bytes only

Each `Data` event carries only bytes never delivered before, in stream order:
retransmissions and overlaps are already removed. A message can span several
`Data` events, and one event can hold several messages, so buffer partial
messages in `flow.state`. The [tutorial](tutorial.md#decode-as-packets-arrive)
shows a decoder that does this.

There is no anomaly event in this layer. To see overlapping retransmissions
with different bytes, use `conversations()` and its `anomalies`.

## Options

`reassemble()` takes `server=`, `idle_timeout=`, and `http=`, with the same
meaning as for [`conversations()`](conversations.md#options).
