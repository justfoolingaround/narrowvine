"""Axinom v9 MultiFormat test vector (CENC).

Streaming license via the Axinom license service (JWT in ``X-AxDRM-Message``).
The JWT's ``message.license.allow_persistence`` is true and the server returns a
license with ``can_persist``, but Google's CDM on Linux refuses persistent
licenses because Linux lacks VMP (see chromiumembedded/cef#3404).
"""

from __future__ import annotations

import pytest

import narrowvine
from narrowvine.proto import license_protocol_pb2 as wvproto
from narrowvine.utils import http
from narrowvine.utils.cenc import decrypt_cenc_sample
from narrowvine.utils.parsers import dash as dash_parser
from narrowvine.utils.parsers import mp4

pytestmark = pytest.mark.network

MPD = "https://media.axprod.net/TestVectors/v9-MultiFormat/Encrypted_Cenc/Manifest.mpd"
LICENSE_URL = "https://drm-widevine-licensing.axtest.net/AcquireLicense"
KID = bytes.fromhex("f8c80c25690f47368132430e5c6994ce")

# Public Axinom test token (Axinom/public-test-vectors, ContentKeys/v9-MultiFormat.xml).
TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXJzaW9uIjoxLCJjb21fa2V5X2lkIjoiNjllNTQwODgt"
    "ZTllMC00NTMwLThjMWEtMWViNmRjZDBkMTRlIiwibWVzc2FnZSI6eyJ0eXBlIjoiZW50aXRsZW1lbnRfbWVz"
    "c2FnZSIsInZlcnNpb24iOjIsImxpY2Vuc2UiOnsiYWxsb3dfcGVyc2lzdGVuY2UiOnRydWV9LCJjb250ZW50"
    "X2tleXNfc291cmNlIjp7ImlubGluZSI6W3siaWQiOiJmOGM4MGMyNS02OTBmLTQ3MzYtODEzMi00MzBlNWM2"
    "OTk0Y2UiLCJlbmNyeXB0ZWRfa2V5IjoiaVhxNDlaODlzOGRDajBqbTJBN1h6UT09IiwidXNhZ2VfcG9saWN5"
    "IjoiUG9saWN5IEEifV19LCJjb250ZW50X2tleV91c2FnZV9wb2xpY2llcyI6W3sibmFtZSI6IlBvbGljeSBB"
    "IiwicGxheXJlYWR5Ijp7Im1pbl9kZXZpY2Vfc2VjdXJpdHlfbGV2ZWwiOjE1MCwicGxheV9lbmFibGVycyI6"
    "WyI3ODY2MjdEOC1DMkE2LTQ0QkUtOEY4OC0wOEFFMjU1QjAxQTciXX19XX19.k9OlwW0rUwuf5d5Eb0iO98"
    "AFR3qp7qKdFzSbg2PQj78"
)
HEADERS = {"X-AxDRM-Message": TOKEN}


@pytest.fixture(scope="session")
def axinom() -> dash_parser.DashInfo:
    return dash_parser.parse_mpd(MPD, representation="1")


def test_axinom_streaming_license_and_decrypt(axinom, tmp_path):
    assert axinom.key_id == KID
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load(), storage_dir=str(tmp_path))

    with cdm.open() as session:
        challenge = cdm.get_license_challenge(session, axinom.pssh)
        response = narrowvine.request_license(challenge, LICENSE_URL, HEADERS)
        cdm.parse_license(session, response)

        keys = {key.kid: key for key in session.keys}
        assert KID in keys
        assert keys[KID].status == narrowvine.KeyStatus.USABLE

        signed = wvproto.SignedMessage()
        signed.ParseFromString(response)
        licence = wvproto.License()
        licence.ParseFromString(signed.msg)
        assert licence.policy.can_persist  # from the JWT's allow_persistence

        init = http.get(axinom.video.init_url).content
        segment = http.get(dash_parser.segment_url(axinom.video, 1)).content
        sample = mp4.parse_track(init, segment)[0]
        clear = decrypt_cenc_sample(cdm, KID, sample)
        assert clear is not None
        assert mp4.avcc_nals(clear)


def test_axinom_persistent_license_is_refused_on_linux(axinom, tmp_path):
    """Google's CDM rejects kPersistentLicense on Linux (no VMP).

    The rejection happens before any host storage/FileIO call, so this is not
    something the host layer can work around.
    """
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load(), storage_dir=str(tmp_path))
    with pytest.raises(narrowvine.LicenseError):
        with cdm.open(session_type=narrowvine.SESSION_PERSISTENT_LICENSE) as session:
            cdm.get_license_challenge(session, axinom.pssh)
