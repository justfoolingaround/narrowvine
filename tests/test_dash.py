"""Widevine DASH tests against the Bitmovin "Art of Motion" test asset."""

from __future__ import annotations

import base64

import pytest

import narrowvine
from narrowvine.utils import http
from narrowvine.utils.cenc import decrypt_cenc_sample
from narrowvine.utils.parsers import dash as dash_parser
from narrowvine.utils.parsers import mp4

pytestmark = pytest.mark.network


def test_friendly_license_flow_with_context_managers(dash):
    device = narrowvine.Device.load()
    assert device.version == "4.10.3050.0"

    with narrowvine.Cdm.from_device(device) as cdm:
        with cdm.open() as session:
            challenge = cdm.get_license_challenge(session, dash.pssh)
            assert isinstance(challenge, bytes) and len(challenge) > 1000
            assert session.id and session.message == challenge

            cdm.parse_license(session, narrowvine.request_license(challenge))
            keys = cdm.get_keys(session)
            assert keys, "license did not produce any keys"
            assert all(key.status == narrowvine.KeyStatus.USABLE for key in keys)

            content = next(key for key in keys if key.kid == dash.key_id)
            assert content.type == narrowvine.KeyType.CONTENT
            # The proprietary CDM never reveals key material.
            assert content.key is None
        assert session._closed


def test_pssh_from_mpd_base64_and_box(dash):
    from_base64 = narrowvine.PSSH(base64.b64encode(dash.pssh).decode())
    from_box = narrowvine.PSSH(dash.pssh)
    assert from_base64.key_ids == from_box.key_ids == [dash.key_id]
    assert from_base64.system_id == narrowvine.WIDEVINE_SYSTEM_ID


def test_create_session_generates_challenge_for_pssh(licensed, dash):
    cdm, session = licensed
    assert session.message is not None
    assert dash.key_id in session.message


def test_load_session_unknown_is_rejected(licensed):
    cdm, _ = licensed
    with pytest.raises(narrowvine.LicenseError):
        cdm.load_session("00000000")


def test_decrypt_all_video_samples(dash, licensed):
    cdm, _ = licensed
    init = http.get(dash.video.init_url).content
    segment = http.get(dash_parser.segment_url(dash.video, 0)).content
    samples = mp4.parse_track(init, segment)
    assert len(samples) == 100

    for i, sample in enumerate(samples):
        clear = decrypt_cenc_sample(cdm, dash.key_id, sample)
        assert clear is not None, f"sample {i} failed to decrypt"
        assert mp4.avcc_nals(clear), f"sample {i} has no NAL units"

    first = decrypt_cenc_sample(cdm, dash.key_id, samples[0])
    assert [t for t, _ in mp4.avcc_nals(first)] == [6, 5]


def test_decode_video_with_cdm(dash, licensed, video_init):
    cdm, _ = licensed
    segment = http.get(dash_parser.segment_url(dash.video, 0)).content
    samples = mp4.parse_track(video_init, segment)
    width, height = dash.video.width, dash.video.height

    avcc = mp4.box_payload(video_init, mp4.find_box(video_init, "avcC"))
    params = mp4.avcc_parameter_sets(avcc)

    status = cdm.initialize_video_decoder(
        2, width, height, profile=2, format=2, extra_data=avcc,
        encryption_scheme=narrowvine.ENCRYPTION_UNENCRYPTED,
    )
    assert status == narrowvine.STATUS_SUCCESS, narrowvine.status_name(status)

    frames = 0
    for sample in samples[:40]:
        clear = decrypt_cenc_sample(cdm, dash.key_id, sample)
        assert clear is not None
        out = cdm.decrypt_and_decode_frame(
            params + mp4.avcc_to_annexb(clear),
            encryption_scheme=narrowvine.ENCRYPTION_UNENCRYPTED,
            timestamp=sample.timestamp_us,
        )
        if out["status"] == narrowvine.STATUS_SUCCESS:
            assert (out["width"], out["height"]) == (width, height)
            assert out["data"] is not None
            frames += 1
    assert frames > 0, "CDM produced no video frames"

    cdm.reset_decoder(narrowvine.STREAM_VIDEO)
    cdm.deinitialize_decoder(narrowvine.STREAM_VIDEO)


def test_decrypt_audio_samples(dash, licensed, audio_init, audio_segment):
    cdm, _ = licensed
    samples = mp4.parse_track(audio_init, audio_segment)
    assert len(samples) == 187

    for sample in samples:
        out = cdm.decrypt(
            sample.data,
            key_id=dash.key_id,
            iv=sample.iv,
            subsamples=sample.subsamples,
            encryption_scheme=narrowvine.ENCRYPTION_CENC,
            timestamp=sample.timestamp_us,
        )
        assert out["status"] == narrowvine.STATUS_SUCCESS, out
        assert out["data"], "no audio bytes"
        assert out["timestamp"] == sample.timestamp_us


def test_audio_decoder_is_not_supported_by_this_cdm(licensed):
    """Widevine 4.10.3050.0 ships video decoders but no audio decoder."""
    cdm, _ = licensed
    assert cdm.initialize_audio_decoder(2, 2, 16, 44100) == narrowvine.STATUS_INITIALIZATION_ERROR
    out = cdm.decrypt_and_decode_samples(b"", encryption_scheme=narrowvine.ENCRYPTION_UNENCRYPTED)
    assert out["status"] in (narrowvine.STATUS_DECODE_ERROR, narrowvine.STATUS_INITIALIZATION_ERROR)


def test_decrypt_without_license_returns_no_key(dash):
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load())
    sample = mp4.Sample(
        data=b"\x00" * 64,
        iv=b"\x00" * 8,
        subsamples=[(0, 64)],
        size=64,
        timestamp_us=0,
    )
    out = cdm.decrypt(
        sample.data,
        key_id=dash.key_id,
        iv=sample.iv,
        subsamples=sample.subsamples,
        encryption_scheme=narrowvine.ENCRYPTION_CENC,
    )
    assert out["status"] == narrowvine.STATUS_NO_KEY


def test_security_level_is_l3(dash):
    """Decode what the CDM tells the license server; proves the L3 identity."""
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load())
    with cdm.open() as session:
        message = cdm.get_license_challenge(session, dash.pssh)

        request = narrowvine.parse_license_request(message)
        assert request.client is not None
        assert request.client.token_type_name == "DRM_DEVICE_CERTIFICATE"
        assert request.client.token_length > 1000
        assert request.client.info["model_name"] == "ChromeCDM"
        assert request.client.info["widevine_cdm_version"] == cdm.version()

        keys = {key.key_id: key for key in narrowvine.parse_license_response(narrowvine.request_license(message))}
        content_key = keys[dash.key_id]
        assert content_key.level == 1  # SW_SECURE_CRYPTO
        assert content_key.level_name == "SW_SECURE_CRYPTO (L3)"
