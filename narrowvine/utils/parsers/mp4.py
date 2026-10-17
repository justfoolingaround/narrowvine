"""Minimal ISO-BMFF (MP4) parsing for fragmented CENC media."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass

CONTAINERS = {
    "moov",
    "trak",
    "mdia",
    "minf",
    "stbl",
    "mvex",
    "moof",
    "traf",
    "stsd",
    "sinf",
    "schi",
    "encv",
    "enca",
    "avc1",
    "mp4a",
    "pssh",
}

_UINT16 = struct.Struct(">H")
_UINT32 = struct.Struct(">I")
_INT32 = struct.Struct(">i")
_UINT64 = struct.Struct(">Q")
_BOX = struct.Struct(">I4s")
_BOX_LARGE = struct.Struct(">I4sQ")
_SUBSAMPLE = struct.Struct(">HI")
_FULLBOX = struct.Struct(">B3s")


def _fullbox(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Return (version, flags) of a FullBox header at ``offset``."""
    version, raw_flags = _FULLBOX.unpack_from(buf, offset)
    return version, int.from_bytes(raw_flags, "big")


@dataclass
class Box:
    type: str
    start: int
    size: int
    header: int

    @property
    def payload(self) -> int:
        return self.start + self.header

    @property
    def end(self) -> int:
        return self.start + self.size


def _container_offset(box: Box) -> int:
    if box.type == "stsd":
        return box.header + 8
    if box.type in ("avc1", "encv"):
        return box.header + 78
    if box.type in ("mp4a", "enca"):
        return box.header + 28
    return box.header


def iter_boxes(buf: bytes, start: int = 0, end: int | None = None) -> Iterator[Box]:
    if end is None:
        end = len(buf)
    i = start
    while i + _BOX.size <= end:
        size, raw_type = _BOX.unpack_from(buf, i)
        typ = raw_type.decode("latin1", "replace")
        header = _BOX.size
        if size == 1:
            _, _, size = _BOX_LARGE.unpack_from(buf, i)
            header = _BOX_LARGE.size
        elif size == 0:
            size = end - i
        if size < header:
            break
        yield Box(typ, i, size, header)
        i += size


def iter_boxes_deep(buf: bytes, start: int = 0, end: int | None = None) -> Iterator[Box]:
    """Yield every box, descending into container boxes."""
    for box in iter_boxes(buf, start, end):
        yield box
        if box.type in CONTAINERS:
            yield from iter_boxes_deep(buf, box.start + _container_offset(box), box.end)


def find_box(buf: bytes, typ: str, start: int = 0, end: int | None = None) -> Box | None:
    """Depth-first search for the first box of the given type."""
    for box in iter_boxes(buf, start, end):
        if box.type == typ:
            return box
        if box.type in CONTAINERS:
            found = find_box(buf, typ, box.start + _container_offset(box), box.end)
            if found:
                return found
    return None


def box_payload(buf: bytes, box: Box) -> bytes:
    return buf[box.payload : box.end]


@dataclass
class Sample:
    data: bytes
    iv: bytes
    subsamples: list[tuple[int, int]]
    size: int
    timestamp_us: int


def parse_track(init: bytes, segment: bytes) -> list[Sample]:
    """Extract encrypted samples (CENC IVs/subsamples) from one fMP4 segment."""
    moof = find_box(segment, "moof")
    if moof is None:
        raise ValueError("no moof in segment")

    trun = find_box(segment, "trun", moof.payload, moof.end)
    if trun is None:
        raise ValueError("no trun in segment")
    p = box_payload(segment, trun)
    _, flags = _fullbox(p)
    (count,) = _UINT32.unpack_from(p, 4)
    off = 8
    if flags & 0x1:
        off += _INT32.size  # data_offset
    if flags & 0x4:
        off += _UINT32.size  # first_sample_flags
    sizes: list[int] = []
    ctos: list[int] = []
    for _ in range(count):
        if flags & 0x100:
            off += _UINT32.size  # sample duration
        if flags & 0x200:
            (size,) = _UINT32.unpack_from(p, off)
            sizes.append(size)
            off += _UINT32.size
        if flags & 0x400:
            off += _UINT32.size  # sample flags
        if flags & 0x800:
            (cto,) = _INT32.unpack_from(p, off)
            ctos.append(cto)
            off += _INT32.size

    senc = find_box(segment, "senc", moof.payload, moof.end)
    ivs: list[bytes] = []
    subs: list[list[tuple[int, int]]] = []
    if senc is not None:
        p = box_payload(segment, senc)
        version, sflags = _fullbox(p)
        (scount,) = _UINT32.unpack_from(p, 4)
        iv_size = 8 if version == 0 else 16
        off = 8
        for _ in range(scount):
            ivs.append(p[off : off + iv_size])
            off += iv_size
            entries: list[tuple[int, int]] = []
            if sflags & 0x2:
                (n,) = _UINT16.unpack_from(p, off)
                off += _UINT16.size
                for _ in range(n):
                    clear, cipher = _SUBSAMPLE.unpack_from(p, off)
                    off += _SUBSAMPLE.size
                    entries.append((clear, cipher))
            subs.append(entries)
    if len(ivs) != len(sizes):
        raise ValueError(f"senc/sample count mismatch: {len(ivs)} != {len(sizes)}")

    mdat = find_box(segment, "mdat")
    if mdat is None:
        raise ValueError("no mdat in segment")
    pos = mdat.payload
    samples: list[Sample] = []
    for i, size in enumerate(sizes):
        samples.append(
            Sample(
                data=segment[pos : pos + size],
                iv=ivs[i],
                subsamples=subs[i],
                size=size,
                timestamp_us=ctos[i] if i < len(ctos) else 0,
            )
        )
        pos += size
    return samples


def avcc_nals(data: bytes) -> list[tuple[int, int]]:
    """Return (nal_type, length) pairs for an AVCC (4-byte length prefixed) sample."""
    out: list[tuple[int, int]] = []
    q = 0
    while q + _UINT32.size <= len(data):
        (length,) = _UINT32.unpack_from(data, q)
        q += _UINT32.size
        if length == 0 or q + length > len(data):
            raise ValueError("bad AVCC NAL chain")
        out.append((data[q] & 0x1F, length))
        q += length
    if q != len(data):
        raise ValueError("trailing bytes in AVCC sample")
    return out


def avcc_to_annexb(data: bytes) -> bytes:
    out = bytearray()
    q = 0
    while q + _UINT32.size <= len(data):
        (length,) = _UINT32.unpack_from(data, q)
        q += _UINT32.size
        out += b"\x00\x00\x00\x01" + data[q : q + length]
        q += length
    return bytes(out)


def avcc_parameter_sets(avcc: bytes) -> bytes:
    """Annex B SPS/PPS from an AVCDecoderConfigurationRecord."""
    out = bytearray()
    i = 5
    for _ in range(avcc[i] & 0x1F):
        i += 1
        (length,) = _UINT16.unpack_from(avcc, i)
        i += _UINT16.size
        out += b"\x00\x00\x00\x01" + avcc[i : i + length]
        i += length
    for _ in range(avcc[i]):
        i += 1
        (length,) = _UINT16.unpack_from(avcc, i)
        i += _UINT16.size
        out += b"\x00\x00\x00\x01" + avcc[i : i + length]
        i += length
    return bytes(out)
