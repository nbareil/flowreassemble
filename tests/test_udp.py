from flowreassemble import Closed, CloseReason, Data, Direction, Opened, conversations, reassemble
from packets import ETHERNET, ether, ipv4, udp


def dgram(ts, src, sport, dst, dport, payload):
    return (ts, ETHERNET, ether(ipv4(src, dst, 17, udp(sport, dport, payload))))


FRAMES = [
    dgram(1.0, "10.0.0.1", 53000, "198.51.100.53", 53, b"query-1"),
    dgram(1.1, "198.51.100.53", 53, "10.0.0.1", 53000, b"answer-1"),
    dgram(1.2, "10.0.0.1", 53000, "198.51.100.53", 53, b"query-2"),
    dgram(1.3, "10.0.0.1", 53000, "198.51.100.53", 53, b"query-3"),
]


def test_each_datagram_is_one_data_event():
    events = list(reassemble(FRAMES))
    assert isinstance(events[0], Opened)
    assert events[0].flow.transport == "udp"
    assert events[0].flow.server[1] == 53
    data = [(e.direction, e.data) for e in events if isinstance(e, Data)]
    assert data == [
        (Direction.TO_SERVER, b"query-1"),
        (Direction.TO_CLIENT, b"answer-1"),
        (Direction.TO_SERVER, b"query-2"),
        (Direction.TO_SERVER, b"query-3"),
    ]
    assert isinstance(events[-1], Closed) and events[-1].reason is CloseReason.EOF


def test_datagrams_stay_separate_turns_in_conversations():
    (conv,) = conversations(FRAMES)
    assert [t.data for t in conv.turns] == [b"query-1", b"answer-1", b"query-2", b"query-3"]
