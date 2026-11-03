"""libhtp, exposed with its own model and names.

Pass a ``Config`` as ``http=`` to ``reassemble()`` or ``conversations()``.
Every TCP connection is then parsed by libhtp (0.5.53), and each HTTP
transaction is yielded as a ``Tx``, a copy of libhtp's ``htp_tx_t``::

    for ev in reassemble(h, http=htp.Config(keep_bodies=10_000_000)):
        match ev:
            case htp.Tx() as tx if tx.parsed_uri.path == b"/my/c2/dispatcher/":
                ...

Field names and values are libhtp's: byte strings are ``bytes`` (``None``
when libhtp has no value), numbers are ints, and the progress and auth
fields use the enums below. Two fields are not libhtp's: ``flow`` (the
connection) and ``ts`` (when the transaction was yielded). With
``keep_bodies``, ``request_body`` and ``response_body`` hold the bodies as
libhtp delivered them (de-chunked, and decompressed if enabled), cut at
``keep_bodies`` bytes each; compare with ``request_entity_len`` and
``response_entity_len`` to spot a cut.

A transaction is yielded when libhtp completes it, or when its connection
closes (check ``request_progress`` and ``response_progress``). If libhtp
stops parsing a connection (after a CONNECT tunnel, or on a parse error), the
rest of the connection comes as plain ``Data`` events.
"""

from __future__ import annotations

import enum
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._reassemble import Flow


class ServerPersonality(enum.IntEnum):
    """``enum htp_server_personality_t``"""

    MINIMAL = 0
    GENERIC = 1
    IDS = 2
    IIS_4_0 = 3
    IIS_5_0 = 4
    IIS_5_1 = 5
    IIS_6_0 = 6
    IIS_7_0 = 7
    IIS_7_5 = 8
    APACHE_2 = 9


class AuthType(enum.IntEnum):
    """``enum htp_auth_type_t``"""

    UNKNOWN = 0
    NONE = 1
    BASIC = 2
    DIGEST = 3
    BEARER = 4
    UNRECOGNIZED = 9


class RequestProgress(enum.IntEnum):
    """``enum htp_tx_req_progress_t``"""

    NOT_STARTED = 0
    LINE = 1
    HEADERS = 2
    BODY = 3
    TRAILER = 4
    COMPLETE = 5


class ResponseProgress(enum.IntEnum):
    """``enum htp_tx_res_progress_t``"""

    NOT_STARTED = 0
    LINE = 1
    HEADERS = 2
    BODY = 3
    TRAILER = 4
    COMPLETE = 5


@dataclass(frozen=True)
class Config:
    """libhtp configuration (``htp_cfg_t``). Defaults are libhtp's own.

    ``keep_bodies`` is not a libhtp setting: it keeps up to that many bytes
    of each request and response body in memory (``None``: bodies are not
    kept).
    """

    server_personality: ServerPersonality = ServerPersonality.MINIMAL
    request_decompression: bool = False
    response_decompression: bool = True
    parse_request_cookies: bool = True
    keep_bodies: int | None = None

    def _native(self) -> dict[str, Any]:
        d = asdict(self)
        d["server_personality"] = int(self.server_personality)
        return d


class Table:
    """libhtp's ``htp_table_t``: ordered ``(name, value)`` pairs; lookups by
    name ignore case and return the first match."""

    __slots__ = ("_pairs",)

    def __init__(self, pairs: list[tuple[bytes, bytes]]) -> None:
        self._pairs = pairs

    def get(self, name: bytes, default: bytes | None = None) -> bytes | None:
        name = name.lower()
        for k, v in self._pairs:
            if k.lower() == name:
                return v
        return default

    def __getitem__(self, name: bytes) -> bytes:
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def __contains__(self, name: object) -> bool:
        return isinstance(name, bytes) and self.get(name) is not None

    def __iter__(self) -> Iterator[tuple[bytes, bytes]]:
        return iter(self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)

    def __repr__(self) -> str:
        return f"htp.Table({self._pairs!r})"


@dataclass(frozen=True)
class Uri:
    """libhtp's ``htp_uri_t``."""

    scheme: bytes | None
    username: bytes | None
    password: bytes | None
    hostname: bytes | None
    port: bytes | None
    port_number: int
    path: bytes | None
    query: bytes | None
    fragment: bytes | None


@dataclass(eq=False)
class Tx:
    """A copy of libhtp's ``htp_tx_t``. See the module documentation."""

    flow: Flow
    ts: float
    request_line: bytes | None
    request_method: bytes | None
    request_method_number: int
    request_uri: bytes | None
    request_protocol: bytes | None
    request_protocol_number: int
    is_protocol_0_9: int
    parsed_uri: Uri | None
    parsed_uri_raw: Uri | None
    request_message_len: int
    request_entity_len: int
    request_headers: Table
    request_transfer_coding: int
    request_content_encoding: int
    request_content_type: bytes | None
    request_content_length: int
    request_cookies: Table
    request_auth_type: AuthType
    request_auth_username: bytes | None
    request_auth_password: bytes | None
    request_hostname: bytes | None
    request_port_number: int
    request_ignored_lines: int
    response_ignored_lines: int
    response_line: bytes | None
    response_protocol: bytes | None
    response_protocol_number: int
    response_status: bytes | None
    response_status_number: int
    response_status_expected_number: int
    response_message: bytes | None
    seen_100continue: int
    response_headers: Table
    response_message_len: int
    response_entity_len: int
    response_content_length: int
    response_transfer_coding: int
    response_content_encoding: int
    response_content_type: bytes | None
    flags: int
    request_progress: RequestProgress
    response_progress: ResponseProgress
    index: int
    request_body: bytes | None = field(default=None, repr=False)
    response_body: bytes | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        status = self.response_status_number if self.response_line is not None else "-"
        return f"<htp.Tx {self.request_method!r} {self.request_uri!r} -> {status}>"


def _uri(d: dict[str, Any] | None) -> Uri | None:
    return None if d is None else Uri(**d)


def _tx(flow: Flow, ts: float, fields: dict[str, Any]) -> Tx:
    fields["parsed_uri"] = _uri(fields["parsed_uri"])
    fields["parsed_uri_raw"] = _uri(fields["parsed_uri_raw"])
    for name in ("request_headers", "response_headers", "request_cookies"):
        fields[name] = Table(fields[name])
    fields["request_auth_type"] = AuthType(fields["request_auth_type"])
    fields["request_progress"] = RequestProgress(fields["request_progress"])
    fields["response_progress"] = ResponseProgress(fields["response_progress"])
    return Tx(flow=flow, ts=ts, **fields)


__all__ = [
    "AuthType",
    "Config",
    "RequestProgress",
    "ResponseProgress",
    "ServerPersonality",
    "Table",
    "Tx",
    "Uri",
]
