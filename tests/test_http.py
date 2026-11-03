import gzip
import urllib.parse

from flowreassemble import Closed, Data, Direction, conversations, htp, reassemble
from packets import Conn

GET = b"GET /my/c2/dispatcher/?id=42 HTTP/1.1\r\nHost: c2.example\r\nCookie: magic=yes; s=1\r\n\r\n"
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nServer: x\r\n\r\nhello"


def http_conn(*exchanges, close=True):
    c = Conn(sport=80)
    frames = c.handshake()
    for req, resp in exchanges:
        frames.append(c.send(req))
        if resp is not None:
            frames.append(c.reply(resp))
    return frames + (c.close() if close else [])


def txs(frames, **config):
    return [e for e in reassemble(frames, http=htp.Config(**config)) if isinstance(e, htp.Tx)]


def test_transaction_fields_follow_libhtp():
    (tx,) = txs(http_conn((GET, OK)))
    assert tx.request_method == b"GET"
    assert tx.request_uri == b"/my/c2/dispatcher/?id=42"
    assert tx.parsed_uri.path == b"/my/c2/dispatcher/"
    assert tx.parsed_uri.query == b"id=42"
    assert tx.request_protocol == b"HTTP/1.1"
    assert tx.request_headers[b"host"] == b"c2.example"
    assert tx.request_hostname == b"c2.example"
    assert tx.response_status_number == 200
    assert tx.response_headers.get(b"Server") == b"x"
    assert tx.request_progress is htp.RequestProgress.COMPLETE
    assert tx.response_progress is htp.ResponseProgress.COMPLETE
    assert tx.response_entity_len == 5
    assert tx.request_body is None and tx.response_body is None
    assert tx.flow.server[1] == 80


def test_http_mode_replaces_data_events_with_transactions():
    events = list(reassemble(http_conn((GET, OK)), http=htp.Config()))
    assert [type(e).__name__ for e in events] == ["Opened", "Tx", "Closed"]


def test_keep_alive_yields_each_transaction_in_order():
    second = GET.replace(b"id=42", b"id=43")
    a, b = txs(http_conn((GET, OK), (second, OK)))
    assert (a.index, a.parsed_uri.query) == (0, b"id=42")
    assert (b.index, b.parsed_uri.query) == (1, b"id=43")


def test_cookies_and_bodies_like_the_pynids_template():
    post = (
        b"POST /my/c2/dispatcher/ HTTP/1.1\r\nHost: c2\r\nCookie: magic=yes\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\ncmd=whoami&"
    )
    reply = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nroot\nok\n"
    for tx in txs(http_conn((post, reply)), keep_bodies=1_000_000):
        assert tx.parsed_uri.path == b"/my/c2/dispatcher/"
        assert b"magic" in tx.request_cookies
        assert urllib.parse.parse_qs(tx.request_body) == {b"cmd": [b"whoami"]}
        assert tx.response_body == b"root\nok\n"


def test_chunked_gzip_response_is_decoded():
    body = gzip.compress(b"secret payload")
    chunked = hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n0\r\n\r\n"
    resp = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" + chunked
    )
    (tx,) = txs(http_conn((GET, resp)), keep_bodies=1000)
    assert tx.response_body == b"secret payload"


def test_keep_bodies_cuts_each_body():
    (tx,) = txs(http_conn((GET, OK)), keep_bodies=2)
    assert tx.response_body == b"he"
    assert tx.response_entity_len == 5


def test_incomplete_transaction_is_yielded_before_close():
    events = list(reassemble(http_conn((GET, None)), http=htp.Config()))
    tx, closed = events[-2:]
    assert isinstance(tx, htp.Tx) and isinstance(closed, Closed)
    assert tx.request_progress is htp.RequestProgress.COMPLETE
    assert tx.response_progress is htp.ResponseProgress.NOT_STARTED


def test_connect_tunnel_continues_as_plain_data():
    connect = b"CONNECT c2.example:443 HTTP/1.1\r\nHost: c2.example:443\r\n\r\n"
    est = b"HTTP/1.1 200 Connection established\r\n\r\n"
    # libhtp probes the tunnel up to a NUL or LF; TLS records have NULs early.
    hello = b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03"
    server_hello = b"\x16\x03\x03\x00\x5a\x02\x00\x00\x56\x03\x03"
    c = Conn(sport=8080)
    frames = c.handshake() + [c.send(connect), c.reply(est), c.send(hello), c.reply(server_hello)]
    events = list(reassemble(frames + c.close(), http=htp.Config()))
    (tx,) = [e for e in events if isinstance(e, htp.Tx)]
    assert tx.request_method == b"CONNECT"
    assert tx.response_status_number == 200
    data = [(e.direction, e.data) for e in events if isinstance(e, Data)]
    assert data == [(Direction.TO_SERVER, hello), (Direction.TO_CLIENT, server_hello)]


def test_basic_auth_is_decoded():
    req = b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
    (tx,) = txs(http_conn((req, OK)))
    assert tx.request_auth_type is htp.AuthType.BASIC
    assert (tx.request_auth_username, tx.request_auth_password) == (b"user", b"pass")


def test_conversations_collect_transactions():
    (conv,) = conversations(http_conn((GET, OK), (GET, OK)), http=htp.Config())
    assert [tx.index for tx in conv.transactions] == [0, 1]
    assert conv.turns == []


def test_random_and_mutated_traffic_does_not_crash():
    import random

    rng = random.Random(1234)
    seeds = [GET + OK, b"CONNECT a:443 HTTP/1.1\r\n\r\n", b"HTTP/1.1 101 Switching\r\n\r\n", b""]
    for _ in range(300):
        base = bytearray(rng.choice(seeds) + rng.randbytes(rng.randrange(0, 64)))
        for _ in range(rng.randrange(0, 8)):
            if base:
                base[rng.randrange(len(base))] = rng.randrange(256)
        cut = rng.randrange(len(base) + 1)
        c = Conn(sport=80)
        frames = c.handshake()
        for i, part in enumerate((bytes(base[:cut]), bytes(base[cut:]), rng.randbytes(16))):
            if part:
                frames.append(c.send(part) if i % 2 == 0 else c.reply(part))
        if rng.random() < 0.5:
            frames += c.close()
        events = list(reassemble(frames, http=htp.Config(keep_bodies=64)))
        assert isinstance(events[-1], Closed)


def test_gap_inside_request_line_stops_http_parsing():
    c = Conn(sport=80)
    frames = c.handshake() + [c.send(b"GET /my/c")]
    c.send(b"2/dispatcher/ ")  # never captured
    frames.append(c.send(b"HTTP/1.1\r\nHost: x\r\n\r\n"))
    events = list(reassemble(frames + c.close(), http=htp.Config()))
    assert all(e.request_uri is None for e in events if isinstance(e, htp.Tx))
    data = [e.data for e in events if isinstance(e, Data)]
    assert data == [b"GET /my/c", b"HTTP/1.1\r\nHost: x\r\n\r\n"]


def test_short_tunnel_payload_is_delivered_at_close():
    c = Conn(sport=8080)
    frames = c.handshake() + [
        c.send(b"CONNECT a:443 HTTP/1.1\r\n\r\n"),
        c.reply(b"HTTP/1.1 200 OK\r\n\r\n"),
        c.send(b"\x16\x03\x01"),
    ]
    events = list(reassemble(frames, http=htp.Config()))
    assert [e.data for e in events if isinstance(e, Data)] == [b"\x16\x03\x01"]
    assert isinstance(events[-1], Closed)
