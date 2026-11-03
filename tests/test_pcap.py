import pytest
from flowreassemble import (
    Closed,
    CloseReason,
    Data,
    Opened,
    conversations,
    pcap,
    reassemble,
)
from packets import Conn, write_pcap


def two_connections():
    a = Conn(server="203.0.113.7")
    b = Conn(server="198.51.100.1", cport=50002)
    return (
        a.handshake()
        + [a.send(b"to-a")]
        + a.close()
        + b.handshake()
        + [b.send(b"to-b")]
        + b.close()
    )


def test_offline_handle_feeds_reassembly(tmp_path):
    h = pcap.open_offline(write_pcap(tmp_path / "c.pcap", two_connections()))
    assert h.datalink() == 1
    data = [e.data for e in reassemble(h) if isinstance(e, Data)]
    assert data == [b"to-a", b"to-b"]


def test_setfilter_applies_bpf(tmp_path):
    h = pcap.open_offline(write_pcap(tmp_path / "c.pcap", two_connections()))
    h.setfilter("host 198.51.100.1")
    (conv,) = conversations(h)
    assert conv.to_server == b"to-b"


def test_nanosecond_timestamps(tmp_path):
    c = Conn()
    c.ts = 1_700_000_000.123456789 - 0.001
    path = write_pcap(tmp_path / "n.pcap", [c.send(b"x")], nano=True)
    (opened, *_) = reassemble(pcap.open_offline(path))
    assert opened.ts == pytest.approx(1_700_000_000.123456789, abs=1e-8)


def test_breakloop_closes_open_flows_and_ends(tmp_path):
    c = Conn()
    frames = c.handshake() + [c.send(b"first")] + [c.send(b"more") for _ in range(10)]
    h = pcap.open_offline(write_pcap(tmp_path / "c.pcap", frames))
    events = []
    for ev in reassemble(h):
        events.append(ev)
        if isinstance(ev, Data):
            h.breakloop()
    assert [type(e) for e in events] == [Opened, Data, Closed]
    assert events[-1].reason is CloseReason.EOF


def test_a_handle_feeds_one_reassembly_at_a_time(tmp_path):
    h = pcap.open_offline(write_pcap(tmp_path / "c.pcap", two_connections()))
    first = reassemble(h)
    next(first)
    with pytest.raises(pcap.Error):
        next(reassemble(h))
    h.setfilter("tcp")  # changing the filter between events is fine
    assert [e for e in first if isinstance(e, Data)]


def test_missing_file_raises_pcap_error(tmp_path):
    with pytest.raises(pcap.Error):
        pcap.open_offline(tmp_path / "nope.pcap")


def test_create_returns_an_inactive_handle():
    dev = pcap.findalldevs()[0]
    h = pcap.create(dev)
    h.set_snaplen(65535)
    h.set_immediate_mode(True)
    with pytest.raises(pcap.Error):
        h.datalink()


def test_breakloop_only_stops_the_running_reassembly(tmp_path):
    c = Conn()
    frames = c.handshake() + [c.send(b"first"), c.send(b"second")] + c.close()
    h = pcap.open_offline(write_pcap(tmp_path / "c.pcap", frames))
    for ev in reassemble(h):
        if isinstance(ev, Data):
            h.breakloop()
    rest = [e.data for e in reassemble(h) if isinstance(e, Data)]
    assert rest == [b"second"]


def test_native_reassembler_keeps_reading_the_handle_it_claimed(tmp_path):
    from flowreassemble import _native

    path = write_pcap(tmp_path / "c.pcap", two_connections())
    a, b = pcap.open_offline(path), pcap.open_offline(path)
    r1, r2 = _native.Reassembler(None, 3600.0), _native.Reassembler(None, 3600.0)
    r1.run(a)
    r2.run(b)
    with pytest.raises(pcap.Error):
        r1.run(b)
