#!/usr/bin/env python3
"""Decrypt the Bitmovin Widevine DASH asset and hand the clear result to ffmpeg.

    uv run python scripts/play_drm.py --segments 5 --ffplay

Video and audio are decrypted through the CDM, written as Annex B H.264 and ADTS
AAC, muxed by ffmpeg and (optionally) played by ffplay. Only clear media is
written, under ``--outdir``.
"""

from __future__ import annotations

import argparse
import os
import subprocess

import narrowvine
from narrowvine.utils import http
from narrowvine.utils.cenc import decrypt_cenc_sample
from narrowvine.utils.parsers import dash as dash_parser
from narrowvine.utils.parsers import mp4


def adts_header(frame_len: int, profile: int = 1, freq_index: int = 3, channels: int = 2) -> bytes:
    """AAC ADTS header (no CRC). profile=1 is AAC-LC, freq_index=3 is 48 kHz."""
    return bytes(
        [
            0xFF, 0xF1,
            (profile << 6) | (freq_index << 2) | (channels >> 2),
            ((channels & 3) << 6) | ((frame_len >> 11) & 0x3),
            (frame_len >> 3) & 0xFF,
            ((frame_len & 7) << 5) | 0x1F,
            0xFC,
        ]
    )


def decrypt(dash: dash_parser.DashInfo, segments: int, outdir: str) -> tuple[str, str]:
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load())
    video_init = http.get(dash.video.init_url).content
    audio_init = http.get(dash.audio.init_url).content
    avcc = mp4.box_payload(video_init, mp4.find_box(video_init, "avcC"))
    params = mp4.avcc_parameter_sets(avcc)

    video_path = os.path.join(outdir, "decrypted.h264")
    audio_path = os.path.join(outdir, "decrypted.aac")
    with cdm, cdm.open() as session:
        cdm.parse_license(
            session, narrowvine.request_license(cdm.get_license_challenge(session, dash.pssh))
        )
        with open(video_path, "wb") as video, open(audio_path, "wb") as audio:
            for number in range(segments):
                vseg = http.get(dash_parser.segment_url(dash.video, number)).content
                aseg = http.get(dash_parser.segment_url(dash.audio, number)).content

                for sample in mp4.parse_track(video_init, vseg):
                    clear = decrypt_cenc_sample(cdm, dash.key_id, sample)
                    if clear is None:
                        raise SystemExit(f"video sample failed in segment {number}")
                    if any(nal_type == 5 for nal_type, _ in mp4.avcc_nals(clear)):
                        video.write(params)  # refresh parameter sets at each IDR
                    video.write(mp4.avcc_to_annexb(clear))

                for sample in mp4.parse_track(audio_init, aseg):
                    out = cdm.decrypt(
                        sample.data,
                        key_id=dash.key_id,
                        iv=sample.iv,
                        subsamples=sample.subsamples,
                        encryption_scheme=narrowvine.ENCRYPTION_CENC,
                        timestamp=sample.timestamp_us,
                    )
                    if out["status"] != narrowvine.STATUS_SUCCESS:
                        raise SystemExit(f"audio sample failed in segment {number}")
                    audio.write(adts_header(len(out["data"]) + 7) + out["data"])
    return video_path, audio_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--segments", type=int, default=5)
    parser.add_argument("--outdir", default="/tmp/narrowvine_play")
    parser.add_argument("--ffplay", action="store_true", help="play the muxed result")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    dash = dash_parser.parse_mpd(representation="360_800000")
    print(f"CDM {narrowvine.Device.load().version} | KID {dash.key_id.hex()}")

    video, audio = decrypt(dash, args.segments, args.outdir)
    print(f"decrypted video -> {video}")
    print(f"decrypted audio -> {audio}")

    muxed = os.path.join(args.outdir, "decrypted.mp4")
    subprocess.run(
        [
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
            "-fflags", "+genpts", "-r", "25", "-i", video,
            "-i", audio,
            "-c:v", "copy", "-c:a", "aac", "-shortest", muxed,
        ],
        check=True,
    )
    print(f"muxed          -> {muxed}")

    if args.ffplay:
        env = {**os.environ, "SDL_VIDEODRIVER": "dummy", "SDL_AUDIODRIVER": "dummy"}
        rc = subprocess.run(
            ["ffplay", "-hide_banner", "-loglevel", "error", "-autoexit", muxed],
            env=env,
        ).returncode
        print(f"ffplay exit code: {rc}")
        return rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
