"""HLS playlist parsing and AES-128 segment decryption."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

from ..crypto import aes_cbc_decrypt
from ..regex import HLS_KEY, HLS_MEDIA, HLS_VARIANT

HLS_MASTER = "https://cdn.bitmovin.com/content/assets/art-of-motion_drm/m3u8s/11331.m3u8"


@dataclass
class MediaPlaylist:
    key_url: str
    iv: bytes
    segments: list[str]


def parse_master(text: str, master_url: str = HLS_MASTER) -> tuple[list[str], str]:
    """Return (variant URLs, audio rendition URL) from a master playlist."""
    base = urljoin(master_url, ".")
    audio = HLS_MEDIA.search(text)
    variants = HLS_VARIANT.findall(text)
    if not audio or not variants:
        raise ValueError("master playlist without audio rendition or variants")
    return (
        [urljoin(base, variant.strip()) for variant in variants],
        urljoin(base, audio.group(1)),
    )


def parse_media(text: str, media_url: str) -> MediaPlaylist:
    key = HLS_KEY.search(text)
    if not key:
        raise ValueError("media playlist without AES-128 key")
    return MediaPlaylist(
        key_url=urljoin(media_url, key.group("uri")),
        iv=bytes.fromhex(key.group("iv")) if key.group("iv") else b"\x00" * 16,
        segments=[
            urljoin(media_url, line.strip())
            for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ],
    )


def decrypt_segment(key: bytes, playlist: MediaPlaylist, data: bytes) -> bytes:
    """Decrypt an HLS AES-128 segment using the playlist's IV."""
    return aes_cbc_decrypt(key, playlist.iv, data)
