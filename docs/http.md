# HTTP

With `http=htp.Config(...)`, libhtp parses every TCP connection as HTTP.
libhtp is the HTTP parser of the Suricata IDS. flowreassemble vendors version
0.5.53 and exposes it with libhtp's own model and names: the objects are
copies of libhtp's structures, not a separate HTTP abstraction.

```python
from flowreassemble import htp, pcap, reassemble

config = htp.Config(keep_bodies=10_000_000)
for ev in reassemble(pcap.open_offline("c2.pcap"), http=config):
    match ev:
        case htp.Tx() as tx if tx.parsed_uri.path == b"/my/c2/dispatcher/":
            if b"magic" in tx.request_cookies:
                print(tx.request_body, tx.response_status_number, tx.response_body)
```

In `reassemble()`, each HTTP transaction comes as an `htp.Tx` event instead
of `Data` events. `Opened`, `Gap`, and `Closed` events still come as usual. In
`conversations()`, the transactions go to `conv.transactions`, and `turns`
keeps only the bytes libhtp didn't parse.

## Transactions

{class}`htp.Tx <flowreassemble.htp.Tx>` is a copy of libhtp's `htp_tx_t`,
with libhtp's field names: `request_method`, `request_uri`, `parsed_uri`,
`request_headers`, `request_cookies`, `request_auth_username`,
`response_status_number`, `response_headers`, and so on. The
[API reference](api.md#flowreassemblehtp) lists every field.

- Byte strings are `bytes`, and a field is `None` when libhtp has no value.
- Numbers are `int`. The progress and authentication fields use the enums
  `htp.RequestProgress`, `htp.ResponseProgress`, and `htp.AuthType`.
- Headers and cookies are `htp.Table` objects: ordered `(name, value)` pairs,
  where lookups by name ignore case and return the first match.
- `parsed_uri` and `parsed_uri_raw` are `htp.Uri` objects (libhtp's
  `htp_uri_t`).

Two fields aren't libhtp's: `flow`, the connection, and `ts`, the time the
transaction was yielded.

A transaction is yielded when libhtp completes it, or when its connection
closes. Check `request_progress` and `response_progress` to tell the two
apart: a transaction yielded at close can lack its response, or part of it.

## Configuration

`htp.Config` holds libhtp's settings, with libhtp's own defaults:

| Setting | Default | libhtp function |
| --- | --- | --- |
| `server_personality` | `htp.ServerPersonality.MINIMAL` | `htp_config_set_server_personality` |
| `request_decompression` | `False` | `htp_config_set_request_decompression` |
| `response_decompression` | `True` | `htp_config_set_response_decompression` |
| `parse_request_cookies` | `True` | `htp_config_set_parse_request_cookies` |
| `keep_bodies` | `None` | none (see below) |

The server personality decides how libhtp interprets ambiguous requests, the
way a given server would. Pick the server the C2 runs on when you know it.

## Bodies

`keep_bodies` isn't a libhtp setting. It keeps up to that many bytes of each
request and response body in `request_body` and `response_body`, as libhtp
delivered them: de-chunked, and decompressed if decompression is on. With the
default `None`, bodies aren't kept and both fields are `None`.

A body longer than `keep_bodies` is cut. Compare it with `request_entity_len`
or `response_entity_len` to tell. In `conversations()`, kept bodies count
toward `max_bytes`.

## When libhtp stops parsing

Some traffic isn't HTTP all the way through. When libhtp stops parsing a
connection, the rest of that connection comes as plain `Data` events (or
`turns`, in `conversations()`), starting with the bytes libhtp had read but
not parsed. That happens:

- after a `CONNECT` request or a `101 Switching Protocols` response, when the
  connection becomes a tunnel
- on a parse error
- on a gap that libhtp refuses, such as one inside a request line

Bytes that libhtp still holds when the connection closes also come as `Data`.
