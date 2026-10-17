"""Offline CDM binding tests (no license server needed)."""

from __future__ import annotations

import pytest

import narrowvine
from narrowvine.key import KeyStatus


def test_get_status_for_policy():
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load())
    assert cdm.get_status_for_policy(0) == KeyStatus.USABLE


def test_set_server_certificate_rejects_garbage():
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load())
    with pytest.raises(narrowvine.LicenseError):
        cdm.set_server_certificate(b"not a certificate")


def test_stats_start_at_zero():
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load())
    assert cdm.stats() == {
        "timers_scheduled": 0,
        "timers_fired": 0,
        "fileio_created": 0,
    }
