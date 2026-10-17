"""``SetServerCertificate`` with the public CWIP test proxy.

The proxy answers a ``SignedMessage{type=SERVICE_CERTIFICATE_REQUEST}`` with a
``SignedMessage{type=SERVICE_CERTIFICATE}`` whose ``msg`` is the
``SignedDrmCertificate`` the CDM expects.
"""

from __future__ import annotations

import pytest

import narrowvine
from narrowvine.proto import license_protocol_pb2 as wvproto
from narrowvine.utils import http

pytestmark = pytest.mark.network

PROXY = "https://cwip-shaka-proxy.appspot.com/no_auth"


def test_fetch_and_set_service_certificate(tmp_path):
    certificate = narrowvine.fetch_service_certificate(PROXY)

    signed_cert = wvproto.SignedDrmCertificate()
    signed_cert.ParseFromString(certificate)
    drm_cert = wvproto.DrmCertificate()
    drm_cert.ParseFromString(signed_cert.drm_certificate)
    assert wvproto.DrmCertificate.Type.Name(drm_cert.type) == "SERVICE"
    assert drm_cert.provider_id

    # The CDM wants the SignedDrmCertificate ...
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load(), storage_dir=str(tmp_path))
    cdm.set_server_certificate(certificate)

    # ... the friendly API also accepts the whole SignedMessage response.
    response = http.post_octet(PROXY, narrowvine.SERVICE_CERTIFICATE_REQUEST).content
    cdm2 = narrowvine.Cdm.from_device(narrowvine.Device.load(), storage_dir=str(tmp_path))
    cdm2.set_server_certificate(response)

    # A CDM accepts a service certificate only once; a second call is rejected.
    with pytest.raises(narrowvine.LicenseError):
        cdm.set_server_certificate(certificate)


def test_set_server_certificate_uses_certificate_for_a_license(dash, tmp_path):
    certificate = narrowvine.fetch_service_certificate(PROXY)
    cdm = narrowvine.Cdm.from_device(narrowvine.Device.load(), storage_dir=str(tmp_path))
    cdm.set_server_certificate(certificate)

    with cdm.open() as session:
        challenge = cdm.get_license_challenge(session, dash.pssh)
        cdm.parse_license(session, narrowvine.request_license(challenge))
        assert len(session.keys) == 5
        assert all(key.status == narrowvine.KeyStatus.USABLE for key in session.keys)
