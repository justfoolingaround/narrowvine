"""PlayReady metadata decoding (no PlayReady CDM is available in this project)."""

from __future__ import annotations

import base64
from dataclasses import dataclass

from ..regex import PR_KID, PR_LA_URL

PLAYREADY_SYSTEM_ID = bytes.fromhex("9a04f07998404286ab92e65be0885f95")
PLAYREADY_LA_URL = (
    "https://test.playready.microsoft.com/service/rightsmanager.asmx"
    "?PlayRight=1&ContentKey=EAtsIJQPd5pFiRUrV9Layw=="
)
SMOOTH_MANIFEST = (
    "https://test.playready.microsoft.com/smoothstreaming/SSWSS720H264/"
    "SuperSpeedway_720.ism/manifest"
)


@dataclass
class PlayReadyHeader:
    xml: str
    kid_guid: str
    la_url: str


def guid_from_bytes(raw: bytes) -> str:
    """Canonical GUID string; PlayReady stores KIDs as little-endian GUIDs."""
    return (
        f"{raw[3]:02x}{raw[2]:02x}{raw[1]:02x}{raw[0]:02x}-"
        f"{raw[5]:02x}{raw[4]:02x}-{raw[7]:02x}{raw[6]:02x}-"
        f"{raw[8]:02x}{raw[9]:02x}-{raw[10:16].hex()}"
    )


def cenc_guid(raw: bytes) -> str:
    """Canonical GUID string from a big-endian CENC default_KID."""
    return (
        f"{raw[0:4].hex()}-{raw[4:6].hex()}-{raw[6:8].hex()}-"
        f"{raw[8:10].hex()}-{raw[10:16].hex()}"
    )


def parse_playready_object(data: bytes) -> PlayReadyHeader:
    """Parse a PlayReady PSSH payload (a UTF-16LE WRMHEADER document)."""
    xml = data.decode("utf-16-le", errors="ignore")
    kid = PR_KID.search(xml)
    la_url = PR_LA_URL.search(xml)
    if not kid or not la_url:
        raise ValueError("PlayReady object without KID/LA_URL")
    return PlayReadyHeader(
        xml=xml,
        kid_guid=guid_from_bytes(base64.b64decode(kid.group(1))),
        la_url=la_url.group(1),
    )
