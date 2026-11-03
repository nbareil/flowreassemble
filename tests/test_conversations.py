from flowreassemble import CloseReason, Direction, conversations
from packets import Conn


def test_turns_merge_consecutive_bytes_per_direction():
    c = Conn()
    frames = (
        c.handshake()
        + [c.send(b"GET "), c.send(b"/x"), c.reply(b"200"), c.send(b"bye")]
        + c.close()
    )
    (conv,) = conversations(frames)
    assert [(t.direction, t.data) for t in conv.turns] == [
        (Direction.TO_SERVER, b"GET /x"),
        (Direction.TO_CLIENT, b"200"),
        (Direction.TO_SERVER, b"bye"),
    ]
    assert conv.to_server == b"GET /xbye"
    assert conv.to_client == b"200"
    assert conv.close_reason is CloseReason.FIN
    assert conv.client == conv.flow.client
    assert conv.start <= conv.end


def test_one_conversation_per_connection():
    a, b = Conn(cport=50001), Conn(cport=50002)
    frames = a.handshake() + b.handshake() + [a.send(b"a"), b.send(b"b")] + a.close() + b.close()
    convs = list(conversations(frames))
    assert sorted(c.to_server for c in convs) == [b"a", b"b"]


def test_gaps_record_their_offset_in_the_stream():
    c = Conn()
    frames = c.handshake() + [c.send(b"head")]
    c.send(b"LOST")
    frames.append(c.send(b"tail"))
    (conv,) = conversations(frames)
    assert conv.gaps == [(Direction.TO_SERVER, 4, 4)]
    assert conv.to_server == b"headtail"


def test_overlap_with_different_bytes_is_an_anomaly():
    c = Conn()
    frames = c.handshake()
    base = c.cseq
    frames += [c.send(b"orig", seq=base + 4), c.send(b"0123EVIL", seq=base)]
    (conv,) = conversations(frames)
    assert conv.to_server == b"0123orig"
    assert [a.kind for a in conv.anomalies] == ["overlap"]


def test_max_bytes_truncates_and_still_yields():
    c = Conn()
    frames = c.handshake() + [c.send(b"0123456789"), c.reply(b"abcdef")] + c.close()
    (conv,) = conversations(frames, max_bytes=12)
    assert conv.to_server == b"0123456789"
    assert conv.to_client == b"ab"
    assert [(a.kind, a.direction) for a in conv.anomalies] == [("truncated", Direction.TO_CLIENT)]
    assert conv.close_reason is CloseReason.FIN
