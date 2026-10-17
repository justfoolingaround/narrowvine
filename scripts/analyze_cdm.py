#!/usr/bin/env python3
"""Analyze a Widevine CDM shared library by path.

Checks the file/exports, reports the CDM version and interface, generates an
offline license challenge from a sample PSSH, decodes the client identity and
(optionally) walks a real license exchange.

    uv run python scripts/analyze_cdm.py /path/to/your/libwidevinecdm.so
    uv run python scripts/analyze_cdm.py /path/to/your/libwidevinecdm.so --json
    uv run python scripts/analyze_cdm.py --license-url https://... --json
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import narrowvine
from narrowvine.proto import license_protocol_pb2 as wvproto

REQUIRED_EXPORTS = (
    "InitializeCdmModule_4",
    "DeinitializeCdmModule",
    "CreateCdmInstance",
    "GetCdmVersion",
    "VerifyCdmHost_0",
)

# Baseline H.264 AVCDecoderConfigurationRecord (avc1.42c00d) used to probe the
# CDM's video decoder without needing media.
SAMPLE_AVCC = bytes.fromhex(
    "014d401effe10018674d401eecc05017fcb808800000030080000019478b16cd01000568e97b2c80"
)

# Bitmovin "Art of Motion" Widevine test PSSH (91-byte pssh box, base64).
SAMPLE_PSSH = (
    "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa"
    "7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="
)


def _exports(path: str) -> list[str]:
    """Return the required exports present, using dlopen + symbol lookup."""
    lib = ctypes.CDLL(path, mode=ctypes.RTLD_LOCAL)
    return [name for name in REQUIRED_EXPORTS if hasattr(lib, name)]


def _parse_client(message: bytes) -> dict[str, Any]:
    signed = wvproto.SignedMessage()
    signed.ParseFromString(message)
    message_type = wvproto.SignedMessage.MessageType.Name(signed.type)

    request = wvproto.LicenseRequest()
    request.ParseFromString(signed.msg)
    client = request.client_id
    return {
        "signed_message_type": message_type,
        "length": len(message),
        "request_type": wvproto.LicenseRequest.RequestType.Name(request.type),
        "client_token_type": wvproto.ClientIdentification.TokenType.Name(client.type),
        "client_token_bytes": len(client.token),
        "encrypted_client_id": request.HasField("encrypted_client_id"),
        "client_info": {nv.name: nv.value for nv in client.client_info},
    }


def analyze(
    path: str,
    pssh: str = SAMPLE_PSSH,
    license_url: str | None = None,
    source_sha256: bool = True,
) -> dict[str, Any]:
    """Analyze ``path`` and return a JSON-serializable report."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    raw = p.read_bytes()
    report: dict[str, Any] = {
        "path": str(p.resolve()),
        "size": len(raw),
        "is_elf": raw[:4] == b"\x7fELF",
    }
    if source_sha256:
        report["sha256"] = hashlib.sha256(raw).hexdigest()

    report["exports"] = _exports(str(p))
    report["exports_missing"] = [e for e in REQUIRED_EXPORTS if e not in report["exports"]]

    device = narrowvine.Device.load(str(p))
    report["version"] = device.version
    report["interface_version"] = narrowvine.CDM_INTERFACE_VERSION

    cdm = narrowvine.Cdm.from_device(device)
    report["initialized"] = cdm.initialized()
    with cdm.open() as session:
        message = cdm.get_license_challenge(session, pssh)
        report["challenge"] = _parse_client(message)
        try:
            report["challenge"]["pssh_key_ids"] = [
                kid.hex() for kid in narrowvine.PSSH(pssh).key_ids
            ]
        except ValueError:
            report["challenge"]["pssh_key_ids"] = []

        # Decrypt is codec-agnostic: this is the path used for audio (AES-CTR).
        probe = cdm.decrypt(b"\x00" * 16, encryption_scheme=narrowvine.ENCRYPTION_UNENCRYPTED)
        report["decrypt"] = narrowvine.status_name(probe["status"])

        audio = narrowvine.status_name(cdm.initialize_audio_decoder(2, 2, 16, 44100))
        report["audio_decoder"] = audio
        report["audio_decoder_supported"] = audio in ("success", "deferred_initialization")

        video = narrowvine.status_name(
            cdm.initialize_video_decoder(
                2,  # kCodecH264
                640,
                360,
                profile=2,  # kH264ProfileBaseline
                format=2,  # kI420
                extra_data=SAMPLE_AVCC,
                encryption_scheme=narrowvine.ENCRYPTION_UNENCRYPTED,
            )
        )
        cdm.deinitialize_decoder(narrowvine.STREAM_VIDEO)
        report["video_decoder"] = video
        report["video_decoder_supported"] = video in ("success", "deferred_initialization")

        if license_url:
            response = narrowvine.request_license(message, license_url)
            report["license"] = [
                {
                    "kid": key.key_id.hex(),
                    "type": wvproto.License.KeyContainer.KeyType.Name(key.key_type),
                    "level": key.level_name,
                }
                for key in narrowvine.parse_license_response(response)
            ]
    return report


def _decoder_text(status: Any) -> str:
    if not status:
        return "n/a"
    if status in ("success", "deferred_initialization"):
        return status
    return f"{status} (not implemented by this CDM)"


def _print_text(report: dict[str, Any]) -> None:
    print(f"file           {report['path']}")
    print(f"size           {report['size']} bytes")
    print(f"sha256         {report.get('sha256', 'n/a')}")
    print(f"elf            {report['is_elf']}")
    print(f"exports        {', '.join(report['exports']) or '(none)'}")
    if report["exports_missing"]:
        print(f"missing        {', '.join(report['exports_missing'])}")
    print(f"version        {report.get('version', '?')}")
    print(f"interface      {report['interface_version']} (requested)")
    print(f"initialized    {report.get('initialized')}")

    challenge = report.get("challenge")
    if challenge:
        print()
        print(f"challenge      {challenge['signed_message_type']} ({challenge['length']} bytes)")
        print(f"client         {challenge['client_token_type']} ({challenge['client_token_bytes']} bytes)")
        for name, value in challenge["client_info"].items():
            print(f"  {name:22} = {value}")
        if challenge.get("pssh_key_ids"):
            print(f"pssh key ids   {', '.join(challenge['pssh_key_ids'])}")
    print(f"decrypt        {report.get('decrypt')} (AES-CTR; this is the audio path)")
    print(f"audio decoder  {_decoder_text(report.get('audio_decoder'))}")
    print(f"video decoder  {_decoder_text(report.get('video_decoder'))}")

    for key in report.get("license", []):
        print(f"key            {key['kid']} {key['type']} {key['level']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="path to libwidevinecdm.so (default: $WIDEVINE_CDM_PATH, vendor/, cwd)",
    )
    parser.add_argument("--pssh", default=SAMPLE_PSSH, help="base64 pssh box to request a challenge for")
    parser.add_argument("--license-url", default=None, help="also fetch and parse a license from this URL")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--no-sha256", action="store_true", help="skip hashing the library")
    args = parser.parse_args(argv)

    try:
        path = args.path or narrowvine.libwidevinecdm_path()
        report = analyze(path, args.pssh, args.license_url, source_sha256=not args.no_sha256)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_text(report)
    return 0 if not report["exports_missing"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
