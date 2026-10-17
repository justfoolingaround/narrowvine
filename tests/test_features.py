"""FileIO (persistent state) and timer support, which need a real license."""

from __future__ import annotations

import pytest

import narrowvine

pytestmark = pytest.mark.network


def _licensed_cdm(tmp_path):
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load(), storage_dir=str(tmp_path))
    return cdm


def test_fileio_is_created_for_a_session(dash, tmp_path):
    cdm = _licensed_cdm(tmp_path)
    with cdm.open() as session:
        cdm.parse_license(
            session, narrowvine.request_license(cdm.get_license_challenge(session, dash.pssh))
        )
    assert cdm.stats()["fileio_created"] >= 1


def test_load_session_unknown_is_reported(dash, tmp_path):
    cdm = _licensed_cdm(tmp_path)
    with pytest.raises(narrowvine.LicenseError):
        cdm.load_session("00000000000000000000000000000000")


def test_timers_are_scheduled_and_fired(dash, tmp_path):
    cdm = _licensed_cdm(tmp_path)
    with cdm.open() as session:
        cdm.parse_license(
            session, narrowvine.request_license(cdm.get_license_challenge(session, dash.pssh))
        )
        # a rejected update makes the CDM ask the host for a timer
        rejected = cdm._native.update_session(session.id, b"garbage")
        assert not rejected["resolved"]
        assert cdm.stats()["timers_scheduled"] >= 1

        fired = cdm.wait(3.0)
        assert fired >= 1
        assert cdm.stats()["timers_fired"] >= 1
