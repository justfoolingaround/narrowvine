#!/usr/bin/env python3
"""Regenerate ``license_protocol_pb2.py`` from ``license_protocol.proto``.

    uv run --group codegen python scripts/gen_proto.py
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
PROTO_DIR = HERE.parent / "narrowvine" / "proto"


def main() -> int:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            "-I",
            str(PROTO_DIR),
            f"--python_out={PROTO_DIR}",
            f"--pyi_out={PROTO_DIR}",
            str(PROTO_DIR / "license_protocol.proto"),
        ],
        check=True,
    )
    print(f"generated {PROTO_DIR / 'license_protocol_pb2.py'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
