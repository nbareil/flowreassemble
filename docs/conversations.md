# Conversations

`conversations()` yields one {class}`~flowreassemble.Conversation` per
connection, after the connection closes, with all of its bytes. Use it for
most investigations of a capture file. To process data as it arrives instead,
use [events](events.md).

```python
from flowreassemble import Direction, conversations, pcap

for conv in conversations(pcap.open_offline("c2.pcap")):
    beacon = conv.to_server  # every byte sent to the server
    tasking = conv.to_client
    for turn in conv.turns:  # direction changes, in order
        if turn.direction is Direction.TO_SERVER:
            ...
```

## Fields

| Field | Content |
| --- | --- |
| `client`, `server` | `(ipaddress, port)` pairs |
| `transport` | `"tcp"` or `"udp"` |
| `start`, `end` | Timestamps, in seconds since the epoch (`float`) |
| `close_reason` | `CloseReason.FIN`, `RST`, `TIMEOUT`, or `EOF` |
| `turns` | List of `Turn(direction, ts, data)` |
| `to_server`, `to_client` | All captured bytes of one direction, concatenated |
| `gaps` | List of `(direction, offset, length)` for bytes missing from the capture |
| `anomalies` | List of `Anomaly(kind, direction, ts)` |
| `transactions` | HTTP mode only: the `htp.Tx` objects, in order |
| `flow` | The `Flow`, the same object as in the event layer |

## Turns

A TCP turn holds the bytes one side sent before the other side spoke. A
request and its response are usually two consecutive turns. A UDP turn is one
datagram, so datagram boundaries are kept, even between datagrams sent in the
same direction.

`to_server` and `to_client` join the turns of one direction. Use them when
the protocol's framing is independent of who speaks when.

## Gaps

`gaps` lists the bytes that were never captured, as
`(direction, offset, length)`. `offset` counts every byte of that direction,
missing ones included, so the first missing byte of a stream that lost its
first 6 bytes is at offset 0. The bytes in `turns` don't include the missing
ones: compare offsets with your decoder's position to tell where a message
was cut.

## Anomalies

`anomalies` records what's worth knowing about how this conversation was
captured:

- `"overlap"`: a retransmission carried bytes different from the first copy.
  The first copy is kept. Different retransmissions are rare in a normal
  capture, and they can mean an attempt to evade inspection.
- `"truncated"`: the conversation reached `max_bytes`, and the later bytes
  were dropped.

## Memory cap

`max_bytes` caps the bytes kept per conversation, both directions together
(64 MiB by default, `None` for no cap). In HTTP mode, kept bodies count too.
Past the cap, the bytes are dropped, a `"truncated"` anomaly is recorded, and
the conversation is still yielded when it closes.

## Options

`conversations()` takes the same options as `reassemble()`, plus `max_bytes`.

| Option | Default | Effect |
| --- | --- | --- |
| `server=` | `None` | The server, as an address or an `(address, port)` pair. See [Which side is the server](reassembly.md#which-side-is-the-server). |
| `idle_timeout=` | `3600.0` | Seconds without packets before a flow closes with `TIMEOUT`. `None` means never. |
| `http=` | `None` | An `htp.Config`: parse every TCP connection as HTTP. See [HTTP](http.md). |
| `max_bytes=` | 64 MiB | Bytes kept per conversation |

The default `idle_timeout` is large so that sparse beacons on one long-lived
connection stay one conversation.

When the input ends, every open flow closes with reason `EOF` and is
yielded, so no data is lost.
