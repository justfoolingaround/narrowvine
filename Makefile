.PHONY: all build test typecheck proto clean

all: build

# uv invokes maturin, which compiles the Rust extension (see pyproject.toml).
# --reinstall-package keeps `make` correct even after `make clean` removed the
# built .so; plain `uv sync`/`uv run` also rebuild on Rust changes via
# tool.uv.cache-keys.
build:
	uv sync --reinstall-package narrowvine

test: build
	uv run pytest -q

typecheck: build
	uv run mypy

# Regenerate narrowvine/proto/license_protocol_pb2.py
proto:
	uv run --group codegen python scripts/gen_proto.py

clean:
	rm -rf narrowvine-core/target .venv .pytest_cache .mypy_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find narrowvine -name '_native*.so' -delete
