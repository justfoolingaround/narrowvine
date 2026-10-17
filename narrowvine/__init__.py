"""narrowvine: a friendly Python host layer for Google's Widevine CDM.

The Widevine implementation is the proprietary ``libwidevinecdm.so``, loaded by
the Rust extension. The public entry points are :class:`~narrowvine.cdm.Cdm`,
:class:`~narrowvine.device.Device`, :class:`~narrowvine.pssh.PSSH` and
:class:`~narrowvine.key.Key`; container/manifest helpers live under
:mod:`narrowvine.utils`.
"""

from __future__ import annotations

from .cdm import (
    CDM_INTERFACE_VERSION,
    ENCRYPTION_CBCS,
    ENCRYPTION_CENC,
    ENCRYPTION_UNENCRYPTED,
    INIT_DATA_CENC,
    INIT_DATA_KEYIDS,
    INIT_DATA_WEBM,
    SESSION_PERSISTENT_LICENSE,
    SESSION_TEMPORARY,
    STATUS_DECODE_ERROR,
    STATUS_DECRYPT_ERROR,
    STATUS_DEFERRED_INITIALIZATION,
    STATUS_INITIALIZATION_ERROR,
    STATUS_NEED_MORE_DATA,
    STATUS_NO_KEY,
    STATUS_SUCCESS,
    STREAM_AUDIO,
    STREAM_VIDEO,
    Cdm,
    Session,
    status_name,
)
from .device import Device, libwidevinecdm_path
from .exceptions import CdmError, LicenseError, NarrowvineError, SessionError
from .key import Key, KeyStatus, KeyType
from .license import (
    SERVICE_CERTIFICATE_REQUEST,
    WIDEVINE_LA_URL,
    fetch_service_certificate,
    parse_license_request,
    parse_license_response,
    request_license,
    unwrap_service_certificate,
)
from .pssh import PSSH, WIDEVINE_SYSTEM_ID

__version__ = "0.1.0"

__all__ = [
    "CDM_INTERFACE_VERSION",
    "ENCRYPTION_CBCS",
    "ENCRYPTION_CENC",
    "ENCRYPTION_UNENCRYPTED",
    "INIT_DATA_CENC",
    "INIT_DATA_KEYIDS",
    "INIT_DATA_WEBM",
    "PSSH",
    "SERVICE_CERTIFICATE_REQUEST",
    "SESSION_PERSISTENT_LICENSE",
    "SESSION_TEMPORARY",
    "STATUS_DECODE_ERROR",
    "STATUS_DECRYPT_ERROR",
    "STATUS_DEFERRED_INITIALIZATION",
    "STATUS_INITIALIZATION_ERROR",
    "STATUS_NEED_MORE_DATA",
    "STATUS_NO_KEY",
    "STATUS_SUCCESS",
    "STREAM_AUDIO",
    "STREAM_VIDEO",
    "WIDEVINE_LA_URL",
    "WIDEVINE_SYSTEM_ID",
    "Cdm",
    "CdmError",
    "Device",
    "Key",
    "KeyStatus",
    "KeyType",
    "LicenseError",
    "NarrowvineError",
    "Session",
    "SessionError",
    "__version__",
    "fetch_service_certificate",
    "libwidevinecdm_path",
    "parse_license_request",
    "parse_license_response",
    "request_license",
    "status_name",
    "unwrap_service_certificate",
]
