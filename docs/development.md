# Development

The source is at <https://github.com/nbareil/flowreassemble>. It has two
layers: a Rust engine (`src/`, compiled as `flowreassemble._native`) and the
Python API (`python/flowreassemble/`).

## Set up

Everything runs in the Nix dev shell, which provides Rust, maturin, uv,
Python, libpcap, zlib, and pkg-config:

```sh
nix develop
make dev      # create .venv and install the package in editable mode
```

| Command | What it does |
| --- | --- |
| `make test` | Rust unit tests, then rebuild and run pytest |
| `make lint` | rustfmt, clippy (warnings are errors), ruff |
| `make format` | Format Rust and Python code |
| `make docs` | Build this documentation into `docs/_build/html` (warnings are errors) |
| `make build` | Release wheel |

After changing Rust code, run `maturin develop --uv` before running a single
Python test:

```sh
uv run --no-sync pytest tests/test_tcp.py::test_rst_closes_the_flow
```

## Tests

Most behavior is tested with pytest, in `tests/`. `tests/packets.py` builds
frames and pcap files in pure Python (`Conn` drives a TCP connection), so the
tests need no fixture files and no third-party packet library. Rust unit
tests cover small internals.

## Continuous integration

GitHub Actions runs two workflows:

- `ci.yml`, on every push to `main` and every pull request: `make lint`,
  `make test`, and `make docs`, on Linux and macOS.
- `release.yml`, on version tags and on pull requests that change the build:
  builds the wheels (Linux x86_64 and aarch64, macOS universal2) and the
  source distribution, installs each wheel on a clean system, and runs the
  tests against it.

Linux wheels link a static libpcap built by `.github/build-libpcap.sh`, with
only the plain Linux capture backend. macOS wheels link the system libpcap.

## Releasing

1. Set the same version in `pyproject.toml` and `Cargo.toml`, and commit.
2. Tag the commit `vX.Y.Z` and push the tag.

On a version tag, `release.yml` checks that the tag matches the version,
creates a GitHub release with the wheels and the source distribution, and
uploads them to PyPI with trusted publishing.

## Documentation

This documentation is built with Sphinx from `docs/`, and hosted on Read the
Docs, which builds it from source on every push (configuration in
`.readthedocs.yaml`). The API reference comes from the docstrings, so
document public classes and fields there.
