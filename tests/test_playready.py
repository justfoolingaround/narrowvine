"""PlayReady / SmoothStreaming tests.

There is no PlayReady CDM in this environment (the host layer wraps Google's
Widevine CDM), so these tests cover everything around PlayReady that a browser
needs before decryption: the SmoothStreaming manifest, the PlayReady PSSH and
the PlayReady LA_URL. Playback/decryption is explicitly out of scope.
"""

from __future__ import annotations

import base64

import pytest
import requests

import narrowvine
from narrowvine.utils import http
from narrowvine.utils.parsers import playready
from narrowvine.utils.regex import PR_PROTECTION_HEADER

pytestmark = pytest.mark.network


def test_dash_init_carries_playready_pssh(dash):
    assert dash.playready_pssh, "no PlayReady PSSH in the DASH init segment"
    header = playready.parse_playready_object(dash.playready_pssh)
    assert "WRMHEADER" in header.xml
    # Same 16 bytes as the CENC default_KID, just in GUID byte order.
    assert header.kid_guid == playready.cenc_guid(dash.key_id)
    assert "rightsmanager" in header.la_url


def test_playready_la_url_is_reachable():
    # A request without a valid challenge must still reach the service; any
    # HTTP response (including 4xx/5xx) proves the endpoint is alive.
    response = requests.get(playready.PLAYREADY_LA_URL, timeout=30)
    assert response.status_code < 600


def test_smoothstreaming_manifest():
    try:
        response = http.get(playready.SMOOTH_MANIFEST)
    except requests.HTTPError as exc:
        pytest.skip(f"SmoothStreaming test asset unavailable: {exc}")
    text = response.text
    assert "<SmoothStreamingMedia" in text
    match = PR_PROTECTION_HEADER.search(text)
    assert match
    header = base64.b64decode(match.group(1)).decode("utf-16-le", errors="ignore")
    assert "WRMHEADER" in header


def test_playready_is_a_different_key_system(dash):
    """The Widevine CDM must not be expected to handle PlayReady content."""
    assert playready.PLAYREADY_SYSTEM_ID != narrowvine.WIDEVINE_SYSTEM_ID
    assert not dash.pssh.startswith(playready.PLAYREADY_SYSTEM_ID)
