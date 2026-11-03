"""Whole conversations: ``conversations()`` yields one per connection, once it closes."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from . import htp
from ._reassemble import (
    Closed,
    CloseReason,
    Data,
    Direction,
    Endpoint,
    Flow,
    Gap,
    Opened,
    ServerHint,
    Source,
    _events,
)


@dataclass(eq=False)
class Turn:
    """Consecutive bytes sent in one direction before the other side spoke."""

    direction: Direction
    ts: float
    data: bytes

    def __repr__(self) -> str:
        more = "..." if len(self.data) > 32 else ""
        return f"Turn({self.direction}, {self.data[:32]!r}{more} [{len(self.data)} bytes])"


@dataclass(frozen=True)
class Anomaly:
    """Something worth knowing about the capture of this conversation.

    ``kind`` is ``"overlap"`` (a retransmission carried different bytes; the
    first copy was kept) or ``"truncated"`` (``max_bytes`` was reached; later
    bytes were dropped).
    """

    kind: str
    direction: Direction
    ts: float


@dataclass(eq=False)
class Conversation:
    flow: Flow
    transport: str
    client: Endpoint
    server: Endpoint
    start: float
    end: float
    close_reason: CloseReason
    turns: list[Turn] = field(default_factory=list, repr=False)
    gaps: list[tuple[Direction, int, int]] = field(default_factory=list, repr=False)
    """``(direction, offset, length)``: ``offset`` counts every byte of that
    direction's stream, including missing ones."""
    anomalies: list[Anomaly] = field(default_factory=list, repr=False)
    transactions: list[htp.Tx] = field(default_factory=list, repr=False)
    """HTTP mode only: libhtp transactions, in order."""

    @property
    def to_server(self) -> bytes:
        """Every captured byte sent to the server, concatenated."""
        return b"".join(t.data for t in self.turns if t.direction is Direction.TO_SERVER)

    @property
    def to_client(self) -> bytes:
        """Every captured byte sent to the client, concatenated."""
        return b"".join(t.data for t in self.turns if t.direction is Direction.TO_CLIENT)


class _Builder:
    def __init__(self, flow: Flow, max_bytes: int | None) -> None:
        self.flow = flow
        self.max_bytes = max_bytes
        self.stored = 0
        self.truncated = False
        self.turns: list[tuple[Direction, float, bytearray]] = []
        self.offsets = {Direction.TO_SERVER: 0, Direction.TO_CLIENT: 0}
        self.gaps: list[tuple[Direction, int, int]] = []
        self.anomalies: list[Anomaly] = []
        self.transactions: list[htp.Tx] = []

    def data(self, direction: Direction, data: bytes, ts: float) -> None:
        self.offsets[direction] += len(data)
        if self.max_bytes is not None and self.stored + len(data) > self.max_bytes:
            data = data[: self.max_bytes - self.stored]
            if not self.truncated:
                self.truncated = True
                self.anomalies.append(Anomaly("truncated", direction, ts))
        if not data:
            return
        self.stored += len(data)
        if self.flow.transport == "tcp" and self.turns and self.turns[-1][0] is direction:
            self.turns[-1][2].extend(data)
        else:
            self.turns.append((direction, ts, bytearray(data)))

    def gap(self, direction: Direction, length: int) -> None:
        self.gaps.append((direction, self.offsets[direction], length))
        self.offsets[direction] += length

    def build(self, ev: Closed) -> Conversation:
        f = self.flow
        return Conversation(
            flow=f,
            transport=f.transport,
            client=f.client,
            server=f.server,
            start=f.start,
            end=ev.ts,
            close_reason=ev.reason,
            turns=[Turn(d, ts, bytes(b)) for d, ts, b in self.turns],
            gaps=self.gaps,
            anomalies=self.anomalies,
            transactions=self.transactions,
        )


def conversations(
    source: Source,
    *,
    server: ServerHint = None,
    idle_timeout: float | None = 3600.0,
    max_bytes: int | None = 64 * 1024 * 1024,
    http: htp.Config | None = None,
) -> Iterator[Conversation]:
    """Yields one ``Conversation`` per connection, once it closes.

    ``max_bytes`` caps the bytes kept per conversation (both directions
    together); ``None`` means no cap. Other options are those of
    ``reassemble()``. For UDP, each datagram is its own turn. With ``http``,
    ``transactions`` holds the libhtp transactions; ``turns`` then only holds
    bytes libhtp did not parse.
    """
    building: dict[int, _Builder] = {}
    for ev in _events(source, server, idle_timeout, http, overlaps=True):
        if isinstance(ev, Data):
            building[ev.flow.id].data(ev.direction, ev.data, ev.ts)
        elif isinstance(ev, Opened):
            building[ev.flow.id] = _Builder(ev.flow, max_bytes)
        elif isinstance(ev, Gap):
            building[ev.flow.id].gap(ev.direction, ev.length)
        elif isinstance(ev, Closed):
            yield building.pop(ev.flow.id).build(ev)
        elif isinstance(ev, htp.Tx):
            building[ev.flow.id].transactions.append(ev)
        else:
            _, flow, ts, direction = ev
            building[flow.id].anomalies.append(Anomaly("overlap", direction, ts))
