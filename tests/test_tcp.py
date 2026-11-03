import ipaddress

from flowreassemble import Closed, CloseReason, Data, Direction, Gap, Opened, reassemble
from packets import ACK, ETHERNET, FIN, SYN, Conn, ether, ipv4, nested_ipv6_fragments, tcp


def stream(events, direction):
    return b"".join(e.data for e in events if isinstance(e, Data) and e.direction is direction)


def test_handshake_data_and_fin():
    c = Conn()
    frames = c.handshake() + [c.send(b"hello"), c.reply(b"world"), c.send(b"!")] + c.close()
    events = list(reassemble(frames))

    assert isinstance(events[0], Opened)
    flow = events[0].flow
    assert flow.transport == "tcp"
    assert flow.client == (ipaddress.ip_address("10.0.0.1"), 51000)
    assert flow.server == (ipaddress.ip_address("203.0.113.7"), 8443)
    assert stream(events, Direction.TO_SERVER) == b"hello!"
    assert stream(events, Direction.TO_CLIENT) == b"world"
    assert isinstance(events[-1], Closed)
    assert events[-1].reason is CloseReason.FIN
    assert all(e.flow is flow for e in events)


def test_out_of_order_segments_are_put_back_in_order():
    c = Conn()
    hs = c.handshake()
    first = c.send(b"AAAA")
    second = c.send(b"BBBB")
    third = c.send(b"CCCC")
    events = list(reassemble(hs + [third, first, second] + c.close()))
    assert stream(events, Direction.TO_SERVER) == b"AAAABBBBCCCC"
    assert not any(isinstance(e, Gap) for e in events)


def test_identical_retransmission_is_delivered_once():
    c = Conn()
    hs = c.handshake()
    seg = c.send(b"once")
    events = list(reassemble(hs + [seg, seg] + c.close()))
    assert stream(events, Direction.TO_SERVER) == b"once"


def test_overlapping_bytes_keep_the_first_copy():
    c = Conn()
    frames = c.handshake()
    start = c.cseq + 3
    frames.append(c.send(b"ab", seq=start + 2))  # arrives first, out of order
    frames.append(c.send(b"XYZW", seq=start))  # overlaps "ab" with different bytes
    events = list(reassemble(frames + [c.send(b"012", seq=start - 3)]))
    assert stream(events, Direction.TO_SERVER) == b"012XYab"


def test_sequence_numbers_wrap_around():
    c = Conn(cseq=0xFFFFFFFF - 2)
    frames = c.handshake() + [c.send(b"wrap"), c.send(b"around")] + c.close()
    assert stream(list(reassemble(frames)), Direction.TO_SERVER) == b"wraparound"


def test_mid_stream_connection_uses_the_lower_port_as_server():
    c = Conn(cport=51000, sport=8443)
    events = list(reassemble([c.send(b"cmd"), c.reply(b"out")]))
    flow = events[0].flow
    assert flow.server[1] == 8443
    assert stream(events, Direction.TO_SERVER) == b"cmd"
    assert stream(events, Direction.TO_CLIENT) == b"out"
    assert events[-1].reason is CloseReason.EOF


def test_server_option_overrides_the_port_guess():
    c = Conn(cport=80, sport=40000, server="198.51.100.9")
    events = list(reassemble([c.send(b"x"), c.reply(b"y")], server=("198.51.100.9", 40000)))
    assert events[0].flow.server == (ipaddress.ip_address("198.51.100.9"), 40000)
    events = list(reassemble([c.send(b"x")], server="198.51.100.9"))
    assert events[0].flow.server[1] == 40000


def test_hole_acknowledged_by_receiver_is_reported_as_gap():
    c = Conn()
    frames = c.handshake()
    lost = c.send(b"LOST")
    after = c.send(b"after")
    frames += [after, c.ack_from_server(c.cseq)]
    events = list(reassemble(frames, idle_timeout=None))
    gaps = [e for e in events if isinstance(e, Gap)]
    assert [(g.direction, g.length) for g in gaps] == [(Direction.TO_SERVER, 4)]
    assert stream(events, Direction.TO_SERVER) == b"after"
    assert lost  # never fed


def test_hole_never_filled_is_reported_at_close():
    c = Conn()
    frames = c.handshake()
    c.send(b"LOST")
    frames.append(c.send(b"tail"))
    events = list(reassemble(frames))
    kinds = [type(e).__name__ for e in events]
    assert kinds == ["Opened", "Gap", "Data", "Closed"]
    assert events[1].length == 4


def test_rst_closes_the_flow():
    c = Conn()
    events = list(reassemble(c.handshake() + [c.send(b"x"), c.rst()]))
    assert events[-1].reason is CloseReason.RST


def test_idle_timeout_closes_flows_on_packet_time():
    c = Conn()
    first = c.handshake() + [c.send(b"one")]
    c.ts += 7200
    later = [c.send(b"two")]
    events = list(reassemble(first + later))
    closed = [e for e in events if isinstance(e, Closed)]
    assert [e.reason for e in closed] == [CloseReason.TIMEOUT, CloseReason.EOF]

    events = list(reassemble(first + later, idle_timeout=None))
    closed = [e for e in events if isinstance(e, Closed)]
    assert [e.reason for e in closed] == [CloseReason.EOF]
    assert stream(events, Direction.TO_SERVER) == b"onetwo"


def test_port_reuse_starts_a_new_flow():
    a = Conn(cseq=100)
    b = Conn(cseq=900_000)
    b.ts = a.ts + 1
    frames = a.handshake() + [a.send(b"first")] + b.handshake() + [b.send(b"second")]
    flows = [e.flow for e in reassemble(frames) if isinstance(e, Opened)]
    assert len(flows) == 2


def test_flow_state_is_kept_across_events():
    c = Conn()
    frames = c.handshake() + [c.send(b"a"), c.send(b"b")] + c.close()
    for ev in reassemble(frames):
        match ev:
            case Opened(flow):
                flow.state = []
            case Data(flow, Direction.TO_SERVER, data):
                flow.state.append(data)
            case Closed(flow):
                assert flow.state == [b"a", b"b"]


def test_vlan_ipv6_and_ip_fragments_are_decoded():
    c = Conn(client="2001:db8::1", server="2001:db8::2")
    frames = c.handshake() + [c.send(b"over v6")]
    assert stream(list(reassemble(frames)), Direction.TO_SERVER) == b"over v6"

    seg = tcp(51000, 8443, 1, 0, SYN, b"")
    syn = (1.0, ETHERNET, ether(ipv4("10.0.0.1", "203.0.113.7", 6, seg), vlan=42))
    body = tcp(51000, 8443, 2, 0, ACK, b"fragmented payload!")
    frag1 = ipv4("10.0.0.1", "203.0.113.7", 6, body[:16], ident=7, frag_off=0, more=True)
    frag2 = ipv4("10.0.0.1", "203.0.113.7", 6, body[16:], ident=7, frag_off=16)
    frames = [syn, (1.1, ETHERNET, ether(frag2, vlan=42)), (1.2, ETHERNET, ether(frag1, vlan=42))]
    assert stream(list(reassemble(frames)), Direction.TO_SERVER) == b"fragmented payload!"


def test_duplicate_syn_after_data_does_not_split_the_connection():
    c = Conn()
    hs = c.handshake()
    frames = hs + [c.send(b"one"), hs[0], c.send(b"two")] + c.close()
    events = list(reassemble(frames))
    assert sum(isinstance(e, Opened) for e in events) == 1
    assert stream(events, Direction.TO_SERVER) == b"onetwo"


def test_data_released_by_an_ack_comes_before_the_acking_packet_data():
    c = Conn()
    frames = c.handshake()
    c.send(b"LOST")
    frames.append(c.send(b"REQ"))
    frames.append(c.reply(b"RESP"))  # its ACK covers the hole
    order = [(e.direction, e.data) for e in reassemble(frames) if isinstance(e, Data)]
    assert order == [(Direction.TO_SERVER, b"REQ"), (Direction.TO_CLIENT, b"RESP")]


def test_ip_fragment_nesting_is_limited():
    syn = tcp(51000, 8443, 1, 0, SYN, b"")
    assert any(isinstance(e, Opened) for e in reassemble(nested_ipv6_fragments(1, syn)))
    assert not any(isinstance(e, Opened) for e in reassemble(nested_ipv6_fragments(20, syn)))
    # Deep nesting used to recurse without bound and overflow the stack.
    assert not any(isinstance(e, Opened) for e in reassemble(nested_ipv6_fragments(30_000, syn)))


def test_acked_fin_after_lost_data_reports_the_gap_and_closes_with_fin():
    c = Conn()
    frames = c.handshake()
    base = c.cseq
    frames.append(c.client_frame(base + 10, FIN | ACK))  # the 10 bytes before it were lost
    frames.append(c.server_frame(c.sseq, FIN | ACK, ack=base + 11))
    events = list(reassemble(frames))
    assert [(type(e).__name__, getattr(e, "length", None)) for e in events[1:]] == [
        ("Gap", 10),
        ("Closed", None),
    ]
    assert events[-1].reason is CloseReason.FIN


def test_gap_before_a_fin_is_reported_at_end_of_input():
    c = Conn()
    frames = c.handshake() + [c.client_frame(c.cseq + 10, FIN | ACK)]
    gaps = [e.length for e in reassemble(frames) if isinstance(e, Gap)]
    assert gaps == [10]


def test_ack_covering_the_fin_seen_before_the_fin_adds_no_gap():
    c = Conn()
    frames = c.handshake()
    base = c.cseq
    frames += [
        c.send(b"0123456789"),
        c.ack_from_server(base + 11),  # acknowledges the FIN, not yet captured
        c.client_frame(base + 10, FIN | ACK),
        c.server_frame(c.sseq, FIN | ACK, ack=base + 11),
    ]
    events = list(reassemble(frames))
    assert not any(isinstance(e, Gap) for e in events)
    assert events[-1].reason is CloseReason.FIN
