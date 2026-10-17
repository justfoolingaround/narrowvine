#!/usr/bin/env python3
"""Print the CDM version, device identity and granted key security levels.

    uv run python scripts/inspect_license.py
"""

from __future__ import annotations

import narrowvine
from narrowvine.utils.parsers import dash as dash_parser


def main() -> int:
    dash = dash_parser.parse_mpd(representation="360_800000")
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load())

    with cdm.open() as session:
        message = cdm.get_license_challenge(session, dash.pssh)

        print(f"CDM version: {cdm.version()}")
        request = narrowvine.parse_license_request(message)
        print(f"LicenseRequest.type: {request.request_type} (1=NEW)")
        if request.client:
            print(
                f"ClientIdentification: {request.client.token_type_name} "
                f"({request.client.token_length} byte device root of trust)"
            )
            for name, value in request.client.info.items():
                print(f"  {name} = {value}")

        print("KeyContainers:")
        licence = narrowvine.request_license(message)
        for key in narrowvine.parse_license_response(licence):
            print(
                f"  kid={key.key_id.hex()} type={key.key_type} "
                f"level={key.level} -> {key.level_name}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
