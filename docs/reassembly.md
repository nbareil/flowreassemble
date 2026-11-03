# How reassembly works

This page describes the rules the reassembler follows, for when its output
needs explaining.

## Decoding

- **Link layers:** Ethernet, Linux cooked capture (SLL and SLL2), raw IP, and
  null/loopback. See [Link-layer types](sources.md#link-layer-types).
- **Encapsulation:** VLAN and QinQ, MPLS, PPPoE, GRE, VXLAN, and IP-in-IP are
  decoded down to the inner TCP or UDP packet. Nesting is limited to 8
  levels of encapsulation, nested fragment reassemblies included.
- **IP:** IPv4 and IPv6, with IPv6 extension headers. Fragments of both are
  reassembled; a datagram whose fragments don't all arrive within 30 seconds
  is dropped.
- **Checksums are never verified.** Captures taken on the sending host often
  carry wrong checksums, because the network card computes them after
  capture.

## Which side is the server

Each flow has a client and a server, and directions are named from them. The
reassembler picks them from the first packet of the flow:

1. If `server=` matches one side, that side is the server. `server=` takes an
   address, or an `(address, port)` pair to match the port too.
2. Otherwise, for TCP, the handshake decides: the sender of a SYN is the
   client, and the sender of a SYN-ACK is the server.
3. Otherwise, the side with the lower port is the server.

The third rule covers connections picked up mid-stream (whose handshake isn't
in the capture) and UDP. Name the server when it uses a high port.

## TCP streams

- **Retransmissions and overlaps:** the first copy of each byte wins. When a
  later copy has different bytes, `conversations()` records an `"overlap"`
  anomaly.
- **Out-of-order segments** are buffered until the bytes before them arrive.
- **Missing data:** a hole is given up on, and reported as a `Gap`, when the
  receiver acknowledges data past it (so the bytes were sent but not
  captured), when more than 16 MiB is buffered behind it, or when the
  connection closes.
- **End of a direction:** a FIN marks the end of its direction's stream.
  Nothing past it is delivered.

## Flows and their end

A flow closes, with a `Closed` event, for one of four reasons:

| Reason | When |
| --- | --- |
| `FIN` | Both sides sent a FIN |
| `RST` | A TCP reset |
| `TIMEOUT` | No packet for `idle_timeout` seconds (1 hour by default) |
| `EOF` | The input ended, or `breakloop()` stopped a capture |

Time comes from packet timestamps. During live capture, it also advances on
the wall clock, so idle flows close when the network is quiet.

UDP flows have no handshake and no FIN: a UDP flow is the exchange between two
endpoints, and it ends on idle timeout or at the end of the input.

## Port reuse

A client can reuse the same address and port for a new connection to the
same server. When a SYN's sequence number differs from the open connection's,
and that connection has already carried data, the open flow closes (reason
`TIMEOUT`) and the SYN starts a new one.

After a connection closes with FIN or RST, the reassembler remembers its
sequence numbers for 120 seconds. Late packets of that connection, such as a
retransmitted FIN, are dropped instead of opening a new flow, while a new
connection on the same addresses and ports is still recognized.
