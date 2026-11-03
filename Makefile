# Run inside the dev shell: `nix develop`.
.PHONY: dev build test test-rust test-python lint format docs

dev:
	uv sync --no-install-project
	maturin develop --uv

build:
	maturin build --release

test: test-rust test-python

test-rust:
	cargo test

test-python:
	maturin develop --uv
	uv run --no-sync pytest

docs:
	uv run --no-sync sphinx-build -W --keep-going -b html docs docs/_build/html

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	uv run --no-sync ruff check
	uv run --no-sync ruff format --check

format:
	cargo fmt
	uv run --no-sync ruff format
	uv run --no-sync ruff check --fix
