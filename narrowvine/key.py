"""Key metadata reported by the CDM.

The proprietary ``libwidevinecdm.so`` never exposes content key material: the
device private key is sealed inside the binary and the license is decrypted
internally. ``Key.key`` is therefore ``None``; the key *id*, type (from the
license protobuf) and status (from ``OnSessionKeysChange``) are available.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class KeyType(IntEnum):
    SIGNING = 1
    CONTENT = 2
    KEY_CONTROL = 3
    OPERATOR_SESSION = 4
    ENTITLEMENT = 5
    OEM_CONTENT = 6


class KeyStatus(IntEnum):
    """``cdm::KeyStatus``."""

    USABLE = 0
    INTERNAL_ERROR = 1
    EXPIRED = 2
    OUTPUT_RESTRICTED = 3
    OUTPUT_DOWNSCALED = 4
    STATUS_PENDING = 5
    RELEASED = 6


@dataclass
class Key:
    kid: bytes
    type: KeyType = KeyType.CONTENT
    status: KeyStatus = KeyStatus.USABLE
    system_code: int = 0
    key: bytes | None = None

    def __str__(self) -> str:
        return f"[{self.type.name}] {self.kid.hex()}:{self.status.name.lower()}"
