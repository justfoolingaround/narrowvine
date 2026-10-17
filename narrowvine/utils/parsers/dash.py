"""DASH MPD parsing (Bitmovin test asset: one Period, SegmentTemplate)."""

from __future__ import annotations

import base64
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin

from ...pssh import WIDEVINE_SYSTEM_ID
from ..http import get
from ..regex import MPD_DEFAULT_KID, MPD_NUMBER, MPD_PSSH
from .mp4 import box_payload, iter_boxes_deep
from .playready import PLAYREADY_SYSTEM_ID

DASH_MPD = "https://cdn.bitmovin.com/content/assets/art-of-motion_drm/mpds/11331.mpd"


@dataclass
class DashTrack:
    representation_id: str
    init_url: str
    media_template: str  # contains $Number$
    width: int = 0
    height: int = 0


@dataclass
class DashInfo:
    mpd_url: str
    pssh: bytes
    key_id: bytes  # 16-byte default_KID
    video: DashTrack
    audio: DashTrack
    playready_pssh: bytes | None = None
    extra: dict = field(default_factory=dict)


def segment_url(track: DashTrack, number: int) -> str:
    """Expand a SegmentTemplate media URL for a segment number.

    Supports ``$Number$`` and the printf form ``$Number%04d$``.
    """

    def replace(match) -> str:
        width = match.group(1)
        return f"{number:0{int(width)}d}" if width else str(number)

    return MPD_NUMBER.sub(replace, track.media_template)


def parse_mpd(mpd_url: str = DASH_MPD, representation: str | None = None) -> DashInfo:
    text = get(mpd_url).text

    # The MPD may carry several ContentProtection elements (PlayReady first,
    # for example); pick the Widevine pssh box by its system id.
    pssh = None
    for encoded in MPD_PSSH.findall(text):
        candidate = base64.b64decode(encoded.strip())
        if len(candidate) >= 28 and candidate[12:28] == WIDEVINE_SYSTEM_ID:
            pssh = candidate
            break
    if pssh is None:
        raise ValueError("no Widevine PSSH in MPD")

    kid_match = MPD_DEFAULT_KID.search(text)
    if not kid_match:
        raise ValueError("no cenc:default_KID in MPD")
    key_id = bytes.fromhex(kid_match.group(1).replace("-", ""))

    root = ET.fromstring(text)
    video = _pick_adaptation(root, mpd_url, "video/mp4", representation)
    audio = _pick_adaptation(root, mpd_url, "audio/mp4", None)

    init = get(video.init_url).content
    playready = None
    for box in iter_boxes_deep(init):
        if box.type == "pssh":
            payload = box_payload(init, box)
            if payload[4:20] == PLAYREADY_SYSTEM_ID:
                size = struct.unpack_from(">I", payload, 20)[0]
                playready = payload[24 : 24 + size]
                break

    return DashInfo(
        mpd_url=mpd_url,
        pssh=pssh,
        key_id=key_id,
        video=video,
        audio=audio,
        playready_pssh=playready,
    )


def _pick_adaptation(
    root, mpd_url: str, mime: str, representation: str | None
) -> DashTrack:
    for adapt in root.iter():
        if not adapt.tag.endswith("AdaptationSet"):
            continue
        repetitions = [r for r in adapt if r.tag.endswith("Representation")]
        if not repetitions:
            continue
        adapt_mime = adapt.attrib.get("mimeType")
        template = next(
            (child for child in adapt if child.tag.endswith("SegmentTemplate")), None
        )
        for rep in repetitions:
            if rep.attrib.get("mimeType", adapt_mime) != mime:
                continue
            rid = rep.attrib["id"]
            if representation and rid != representation:
                continue
            rep_template = template
            if rep_template is None:
                rep_template = next(
                    (child for child in rep if child.tag.endswith("SegmentTemplate")),
                    None,
                )
            if rep_template is None:
                continue
            urls = (
                rep_template.attrib["initialization"]
                + "\n"
                + rep_template.attrib["media"]
            ).replace("$RepresentationID$", rid)
            init, media = urls.split("\n", 1)
            return DashTrack(
                representation_id=rid,
                init_url=urljoin(mpd_url, init),
                media_template=urljoin(mpd_url, media),
                width=int(rep.attrib.get("width", 0)),
                height=int(rep.attrib.get("height", 0)),
            )
    raise ValueError(f"no {mime} representation")
