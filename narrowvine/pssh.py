"""Widevine PSSH (protection system specific header) parsing."""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass, field

from .proto import license_protocol_pb2 as wvproto

WIDEVINE_SYSTEM_ID = bytes.fromhex("edef8ba979d64acea3c827dcd51d21ed")

# pssh box: size(u32) 'pssh' version(u8) flags(3) system_id(16) [kids] data
_PSSH_HEADER = struct.Struct(">I4sB3s")
_UINT32 = struct.Struct(">I")
_SYSTEM_ID = struct.Struct(">16s")
_KEY_ID = struct.Struct(">16s")
_SYSTEM_ID_OFFSET = _PSSH_HEADER.size


@dataclass
class PSSH:
    """A parsed ``pssh`` box.

    Accepts the base64 string from an MPD's ``<cenc:pssh>`` or the raw box
    bytes from an init segment. ``key_ids`` falls back to the Widevine PSSH
    protobuf when the box is version 0.
    """

    system_id: bytes
    key_ids: list[bytes]
    data: bytes
    box: bytes = field(repr=False)

    def __init__(self, init_data: str | bytes):
        box = self._normalize(init_data)
        size, box_type, version, _ = _PSSH_HEADER.unpack_from(box)
        if box_type != b"pssh":
            raise ValueError("init data is not a pssh box")
        if size:
            if size > len(box):
                raise ValueError("truncated pssh box")
            box = box[:size]
        if len(box) < _SYSTEM_ID_OFFSET + _SYSTEM_ID.size + _UINT32.size:
            raise ValueError("pssh box too short")
        self.box = box

        offset = _SYSTEM_ID_OFFSET
        (self.system_id,) = _SYSTEM_ID.unpack_from(box, offset)
        offset += _SYSTEM_ID.size

        key_ids: list[bytes] = []
        if version > 0:
            (kid_count,) = _UINT32.unpack_from(box, offset)
            offset += _UINT32.size
            for _ in range(kid_count):
                (kid,) = _KEY_ID.unpack_from(box, offset)
                key_ids.append(kid)
                offset += _KEY_ID.size

        (data_size,) = _UINT32.unpack_from(box, offset)
        offset += _UINT32.size
        self.data = box[offset : offset + data_size]

        if not key_ids and self.system_id == WIDEVINE_SYSTEM_ID:
            pssh_data = wvproto.WidevinePsshData()
            pssh_data.ParseFromString(self.data)
            key_ids = [bytes(kid) for kid in pssh_data.key_ids]
        self.key_ids = key_ids

    @staticmethod
    def _normalize(init_data: str | bytes) -> bytes:
        if isinstance(init_data, str):
            return base64.b64decode(init_data)
        raw = bytes(init_data)
        if len(raw) >= _PSSH_HEADER.size and raw[4:8] == b"pssh":
            return raw
        try:
            decoded = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise ValueError("init data is neither a pssh box nor base64") from exc
        if len(decoded) < _PSSH_HEADER.size or decoded[4:8] != b"pssh":
            raise ValueError("init data is not a pssh box")
        return decoded

    def dumps(self) -> bytes:
        """The full ``pssh`` box, ready to hand to the CDM."""
        return self.box

    def __repr__(self) -> str:
        kids = ", ".join(kid.hex() for kid in self.key_ids)
        return f"PSSH(system_id={self.system_id.hex()}, key_ids=[{kids}])"
