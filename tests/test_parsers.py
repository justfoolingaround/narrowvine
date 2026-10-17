"""Offline unit tests for the container/PSSH parsers (no network, no CDM)."""

from __future__ import annotations

import base64
import struct

import pytest

import narrowvine
from narrowvine.proto import license_protocol_pb2 as wvproto
from narrowvine.utils.parsers import mp4

WIDEVINE_SYSTEM_ID = narrowvine.WIDEVINE_SYSTEM_ID


def _build_pssh(
    system_id: bytes,
    key_ids: list[bytes] | None = None,
    data: bytes = b"",
    version: int = 0,
) -> bytes:
    body = system_id
    if version > 0:
        body += struct.pack(">I", len(key_ids or [])) + b"".join(key_ids or [])
    body += struct.pack(">I", len(data)) + data
    size = 4 + 4 + 4 + len(body)  # size + 'pssh' + version/flags + body
    return struct.pack(">I4s", size, b"pssh") + bytes([version, 0, 0, 0]) + body


def test_pssh_v1_parses_key_ids_from_the_box():
    kid = bytes(range(16))
    box = _build_pssh(WIDEVINE_SYSTEM_ID, [kid], data=b"\x00\x01", version=1)
    pssh = narrowvine.PSSH(box)
    assert pssh.system_id == WIDEVINE_SYSTEM_ID
    assert pssh.key_ids == [kid]
    assert pssh.data == b"\x00\x01"
    assert pssh.dumps() == box


def test_pssh_v0_falls_back_to_the_widevine_protobuf():
    kid = bytes.fromhex("eb676abbcb345e96bbcf616630f1a3da")
    pssh_data = wvproto.WidevinePsshData()
    pssh_data.key_ids.append(kid)
    box = _build_pssh(WIDEVINE_SYSTEM_ID, data=pssh_data.SerializeToString())
    pssh = narrowvine.PSSH(box)
    assert pssh.key_ids == [kid]
    assert pssh.system_id == WIDEVINE_SYSTEM_ID


def test_pssh_accepts_base64_and_bytes():
    kid = bytes.fromhex("11" * 16)
    box = _build_pssh(WIDEVINE_SYSTEM_ID, [kid], version=1)
    assert narrowvine.PSSH(base64.b64encode(box).decode()).key_ids == [kid]
    assert narrowvine.PSSH(base64.b64encode(box)).key_ids == [kid]
    assert narrowvine.PSSH(box).key_ids == [kid]


def test_pssh_rejects_garbage():
    with pytest.raises(ValueError):
        narrowvine.PSSH(b"not a pssh box")
    with pytest.raises(ValueError):
        narrowvine.PSSH(b"\x00\x00\x00\x04pssh"[:8])


def test_avcc_to_annexb_roundtrip():
    avcc = b"\x00\x00\x00\x03\x65\x88\x84\x00\x00\x00\x02\x41\x9a"
    annexb = mp4.avcc_to_annexb(avcc)
    assert annexb == b"\x00\x00\x00\x01\x65\x88\x84\x00\x00\x00\x01\x41\x9a"
    assert mp4.avcc_nals(avcc) == [(0x65 & 0x1F, 3), (0x41 & 0x1F, 2)]


def test_avcc_nals_rejects_bad_chain():
    with pytest.raises(ValueError):
        mp4.avcc_nals(b"\x00\x00\x00\x10short")


def test_iter_boxes_reads_large_box_sizes():
    payload = b"data"
    box = struct.pack(">I4sQ", 1, b"mdat", 16 + len(payload)) + payload
    boxes = list(mp4.iter_boxes(box))
    assert len(boxes) == 1
    assert boxes[0].type == "mdat"
    assert boxes[0].header == 16
    assert mp4.box_payload(box, boxes[0]) == payload
