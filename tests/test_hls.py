"""HLS branch of the Bitmovin test asset.

The 11331 HLS playlists are encrypted with plain HLS AES-128 (not Widevine), so
this exercises the playlist/key/AES path rather than the CDM.
"""

from __future__ import annotations

import pytest

import narrowvine  # noqa: F401  (ensures the package is importable)
from narrowvine.utils import http
from narrowvine.utils.parsers import hls

pytestmark = pytest.mark.network


def test_hls_master_lists_expected_renditions():
    master = http.get(hls.HLS_MASTER).text
    assert "#EXTM3U" in master
    variants, _ = hls.parse_master(master)
    assert len(variants) == 6


def test_hls_aes128_decrypts_video_segment():
    master = http.get(hls.HLS_MASTER).text
    variants, _ = hls.parse_master(master)
    playlist = http.get(variants[2]).text
    media = hls.parse_media(playlist, variants[2])
    assert media.segments

    key = http.get(media.key_url).content
    assert len(key) == 16

    clear = hls.decrypt_segment(key, media, http.get(media.segments[0]).content)
    # MPEG-TS: 188-byte packets, first byte of every packet is 0x47.
    assert clear[0] == 0x47, "decrypted stream is not MPEG-TS"
    assert len(clear) % 188 == 0
    assert all(clear[i] == 0x47 for i in range(0, min(len(clear), 188 * 20), 188))


def test_hls_aes128_decrypts_audio_segment():
    master = http.get(hls.HLS_MASTER).text
    _, audio_url = hls.parse_master(master)
    playlist = http.get(audio_url).text
    media = hls.parse_media(playlist, audio_url)

    key = http.get(media.key_url).content
    clear = hls.decrypt_segment(key, media, http.get(media.segments[0]).content)
    assert clear[0] == 0x47
    assert len(clear) % 188 == 0
