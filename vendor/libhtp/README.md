# Vendored libhtp

libhtp 0.5.53 (the last release; libhtp reached end-of-life in July 2026),
from <https://github.com/OISF/libhtp/archive/refs/tags/0.5.53.tar.gz>
(SHA-256 `c6f4aadfc40a57eee5518555c2cc1b2cd38d6d5f8ad3a24e7cfc6a0963c524fb`).
BSD-3-Clause, see `LICENSE`.

Only `htp/` is kept. Changes from the release:

- `htp/Makefile.am` and `htp/lzma/Makefile.am` removed; `build.rs` builds the
  sources.
- `htp/htp_version.h` generated from `htp_version.h.in`.
- `htp/htp_config_auto_gen.h` added as a stub for the autoconf header.

Security fixes are this project's responsibility now: apply them here and
list them above.
