"""Fixtures for the narrowvine test suite."""

from __future__ import annotations

import os
import shutil

import pytest

import narrowvine
from narrowvine.utils import http
from narrowvine.utils.parsers import dash as dash_parser


def pytest_configure(config):
    config.addinivalue_line("markers", "network: needs internet")
    config.addinivalue_line("markers", "ffmpeg: needs the ffmpeg binary")


def pytest_collection_modifyitems(config, items):
    skip_network = os.environ.get("WIDEVINE_SKIP_NETWORK") == "1"
    has_ffmpeg = shutil.which("ffmpeg") is not None
    for item in items:
        if skip_network and "network" in item.keywords:
            item.add_marker(pytest.mark.skip(reason="WIDEVINE_SKIP_NETWORK=1"))
        if "ffmpeg" in item.keywords and not has_ffmpeg:
            item.add_marker(pytest.mark.skip(reason="ffmpeg not installed"))


def pytest_sessionstart(session):
    try:
        narrowvine.libwidevinecdm_path()
    except FileNotFoundError as exc:
        pytest.exit(str(exc))


@pytest.fixture(scope="session")
def dash() -> dash_parser.DashInfo:
    return dash_parser.parse_mpd(representation="360_800000")


@pytest.fixture(scope="session")
def video_init(dash) -> bytes:
    return http.get(dash.video.init_url).content


@pytest.fixture(scope="session")
def video_segment(dash) -> bytes:
    return http.get(dash_parser.segment_url(dash.video, 0)).content


@pytest.fixture(scope="session")
def audio_init(dash) -> bytes:
    return http.get(dash.audio.init_url).content


@pytest.fixture(scope="session")
def audio_segment(dash) -> bytes:
    return http.get(dash_parser.segment_url(dash.audio, 0)).content


@pytest.fixture
def licensed(dash):
    """An open CDM + session with the Bitmovin license applied."""
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load())
    with cdm.open() as session:
        challenge = cdm.get_license_challenge(session, dash.pssh)
        cdm.parse_license(session, narrowvine.request_license(challenge))
        yield cdm, session
