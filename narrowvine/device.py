"""The CDM "device": the ``libwidevinecdm.so`` library itself."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from . import _native

_REPO_ROOT = Path(__file__).resolve().parents[1]


def libwidevinecdm_path(path: str | None = None) -> str:
    """Resolve the path of the proprietary ``libwidevinecdm.so``.

    Search order: explicit ``path``, ``$WIDEVINE_CDM_PATH``, the repository's
    ``vendor/`` directory, then the current working directory.
    """
    candidates = [
        path,
        os.environ.get("WIDEVINE_CDM_PATH"),
        str(_REPO_ROOT / "vendor" / "libwidevinecdm.so"),
        str(Path.cwd() / "libwidevinecdm.so"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    raise FileNotFoundError(
        "libwidevinecdm.so not found; pass a path or set WIDEVINE_CDM_PATH "
        f"(tried: {[c for c in candidates if c]})"
    )


@dataclass(frozen=True)
class Device:
    """A Widevine CDM device (the shared library and its version)."""

    path: str
    version: str

    @classmethod
    def load(cls, path: str | None = None) -> Device:
        """Load a ``Device`` from a ``libwidevinecdm.so`` path.

        With no argument the library is resolved from ``$WIDEVINE_CDM_PATH``,
        ``vendor/`` or the working directory.
        """
        resolved = libwidevinecdm_path(path)
        return cls(path=resolved, version=_native.libwidevinecdm_version(resolved))

    def __str__(self) -> str:
        return f"{Path(self.path).name} {self.version}"
