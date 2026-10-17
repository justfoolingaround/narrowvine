"""CENC sample decryption through the CDM.

Widevine 4.10.3050.0's ``Decrypt()`` has two quirks that make the subsample list
exactly as stored in ``senc`` unusable:

* ``num_subsamples > 1`` always returns ``kNoKey``;
* a single subsample can trip its internal AVCC/NAL parser.

The cipher spans are therefore flattened to ``[clear bytes][cipher stream]`` and
decrypted as a single subsample (equivalent for AES-CTR), with a retry that
neutralises the leading 4-byte NAL length for the parser. The CDM copies the
clear bytes through unchanged and they are restored here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .parsers.mp4 import Sample

if TYPE_CHECKING:
    from ..cdm import Cdm


def decrypt_cenc_sample(
    cdm: Cdm, key_id: bytes, sample: Sample
) -> bytes | None:
    """Decrypt one CENC sample, returning clear AVCC bytes or ``None``."""
    from ..cdm import ENCRYPTION_CENC, STATUS_SUCCESS

    if not sample.subsamples:
        out = cdm.decrypt(
            sample.data,
            key_id=key_id,
            iv=sample.iv,
            encryption_scheme=ENCRYPTION_CENC,
            timestamp=sample.timestamp_us,
        )
        return out["data"] if out["status"] == STATUS_SUCCESS else None

    off = 0
    clear, cipher = bytearray(), bytearray()
    for clear_bytes, cipher_bytes in sample.subsamples:
        clear += sample.data[off : off + clear_bytes]
        off += clear_bytes
        cipher += sample.data[off : off + cipher_bytes]
        off += cipher_bytes
    flat = bytes(clear) + bytes(cipher)
    clear_total = len(clear)

    def call(payload: bytes):
        return cdm.decrypt(
            payload,
            key_id=key_id,
            iv=sample.iv,
            subsamples=[(clear_total, len(cipher))],
            encryption_scheme=ENCRYPTION_CENC,
            timestamp=sample.timestamp_us,
        )

    out = call(flat)
    status, data = out["status"], out["data"]
    if status != STATUS_SUCCESS and clear_total >= 4:
        saved = flat[:4]
        retry = call(b"\x00\x00\x00\x00" + flat[4:])
        if retry["status"] == STATUS_SUCCESS and retry["data"] is not None:
            status, data = retry["status"], saved + retry["data"][4:]
    if status != STATUS_SUCCESS or data is None:
        return None

    decrypted = data
    result = bytearray()
    co, po = 0, clear_total
    for clear_bytes, cipher_bytes in sample.subsamples:
        result += decrypted[co : co + clear_bytes]
        co += clear_bytes
        result += decrypted[po : po + cipher_bytes]
        po += cipher_bytes
    return bytes(result)
