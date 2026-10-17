"""Widevine license exchange, typed with the vendored ``license_protocol.proto``."""

from __future__ import annotations

from dataclasses import dataclass, field

from .key import KeyType
from .proto import license_protocol_pb2 as wvproto
from .utils.http import post_octet

WIDEVINE_LA_URL = "https://cwip-shaka-proxy.appspot.com/no_auth"

LEVEL_NAMES: dict[int, str] = {
    int(wvproto.License.KeyContainer.SW_SECURE_CRYPTO): "SW_SECURE_CRYPTO (L3)",
    int(wvproto.License.KeyContainer.SW_SECURE_DECODE): "SW_SECURE_DECODE (L3)",
    int(wvproto.License.KeyContainer.HW_SECURE_CRYPTO): "HW_SECURE_CRYPTO (L1/L2)",
    int(wvproto.License.KeyContainer.HW_SECURE_DECODE): "HW_SECURE_DECODE (L1)",
    int(wvproto.License.KeyContainer.HW_SECURE_ALL): "HW_SECURE_ALL (L1)",
}


@dataclass
class ClientIdentification:
    token_type: int
    token_length: int
    info: dict[str, str] = field(default_factory=dict)

    @property
    def token_type_name(self) -> str:
        return wvproto.ClientIdentification.TokenType.Name(self.token_type)


@dataclass
class LicenseRequest:
    request_type: int
    client: ClientIdentification | None


@dataclass
class KeyContainer:
    key_id: bytes
    key_type: int
    level: int

    @property
    def level_name(self) -> str:
        return LEVEL_NAMES.get(self.level, f"unknown({self.level})")


# SignedMessage{type = SERVICE_CERTIFICATE_REQUEST (4)}: ask a license server
# for its Widevine service certificate. The public CWIP test proxy returns one.
SERVICE_CERTIFICATE_REQUEST = bytes([0x08, 0x04])


def fetch_service_certificate(
    la_url: str = WIDEVINE_LA_URL,
    headers: dict[str, str] | None = None,
) -> bytes:
    """Ask a license server for its service certificate.

    Returns the ``SignedDrmCertificate`` bytes expected by
    :meth:`narrowvine.Cdm.set_server_certificate` (i.e. the ``msg`` field of the
    ``SignedMessage{SERVICE_CERTIFICATE}`` response).
    """
    response = post_octet(la_url, SERVICE_CERTIFICATE_REQUEST, headers).content
    signed = wvproto.SignedMessage()
    signed.ParseFromString(response)
    if signed.type != wvproto.SignedMessage.SERVICE_CERTIFICATE or not signed.msg:
        raise ValueError(
            f"license server did not return a service certificate (type={signed.type})"
        )
    return bytes(signed.msg)


def unwrap_service_certificate(data: bytes) -> bytes:
    """Accept either a ``SignedDrmCertificate`` or a service-certificate ``SignedMessage``.

    ``SetServerCertificate`` wants the ``SignedDrmCertificate`` bytes; callers
    often have the whole response from the license server.
    """
    if not data:
        return data
    try:
        signed = wvproto.SignedMessage()
        signed.ParseFromString(data)
        if signed.type == wvproto.SignedMessage.SERVICE_CERTIFICATE and signed.msg:
            return bytes(signed.msg)
    except Exception:  # noqa: BLE001 - not a SignedMessage, use as-is
        pass
    return data


def parse_license_request(data: bytes) -> LicenseRequest:
    """Parse a ``SignedMessage`` license request challenge."""
    signed = wvproto.SignedMessage()
    signed.ParseFromString(data)
    if signed.type != wvproto.SignedMessage.LICENSE_REQUEST:
        raise ValueError(f"not a license request (type={signed.type})")

    request = wvproto.LicenseRequest()
    request.ParseFromString(signed.msg)

    client = None
    if request.HasField("client_id"):
        cid = request.client_id
        client = ClientIdentification(
            token_type=cid.type,
            token_length=len(cid.token),
            info={nv.name: nv.value for nv in cid.client_info},
        )
    return LicenseRequest(request_type=request.type, client=client)


def parse_license_response(data: bytes) -> list[KeyContainer]:
    """Parse a ``SignedMessage`` license response into its key containers."""
    signed = wvproto.SignedMessage()
    signed.ParseFromString(data)
    if signed.type != wvproto.SignedMessage.LICENSE:
        raise ValueError(f"not a license response (type={signed.type})")

    license_ = wvproto.License()
    license_.ParseFromString(signed.msg)
    return [
        KeyContainer(key_id=key.id, key_type=key.type, level=key.level)
        for key in license_.key
    ]


def key_types(data: bytes) -> dict[bytes, KeyType]:
    """Map each key id in a license response to its ``KeyType``."""
    out: dict[bytes, KeyType] = {}
    for container in parse_license_response(data):
        try:
            out[container.key_id] = KeyType(container.key_type)
        except ValueError:
            out[container.key_id] = KeyType.CONTENT
    return out


def request_license(
    challenge: bytes,
    la_url: str = WIDEVINE_LA_URL,
    headers: dict[str, str] | None = None,
) -> bytes:
    """POST a license challenge to a license authority and return its response.

    ``headers`` carries provider requirements such as Axinom's
    ``X-AxDRM-Message: <JWT>``.
    """
    return post_octet(la_url, challenge, headers).content
