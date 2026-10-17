"""Friendly Widevine CDM API.

The actual Widevine implementation is Google's proprietary ``libwidevinecdm.so``
loaded through the Rust extension (:mod:`narrowvine._native`). This module adds
a small, session-oriented facade with context-manager support::

    from narrowvine import Cdm, Device, PSSH

    with Cdm.from_device(Device.load()) as cdm:
        with cdm.open() as session:
            challenge = cdm.get_license_challenge(session, pssh)
            ...

Timers requested by the CDM are scheduled on a background thread but fired on
the CDM's own thread by :meth:`Cdm.service_timers` / :meth:`Cdm.wait`. The CDM
is called from the thread that created it, which is what Chromium's host does.
"""

from __future__ import annotations

import time
from typing import Union

from . import _native
from . import license as wvlicense
from .device import Device
from .exceptions import CdmError, LicenseError, SessionError
from .key import Key, KeyStatus, KeyType
from .pssh import PSSH
from .utils.types import AudioSamplesResult, DecryptResult, FrameResult, SessionResult

# --- re-exported enums/constants from the native extension --------------------

CDM_INTERFACE_VERSION = _native.CDM_INTERFACE_VERSION
SESSION_TEMPORARY = _native.SESSION_TEMPORARY
SESSION_PERSISTENT_LICENSE = _native.SESSION_PERSISTENT_LICENSE
INIT_DATA_CENC = _native.INIT_DATA_CENC
INIT_DATA_KEYIDS = _native.INIT_DATA_KEYIDS
INIT_DATA_WEBM = _native.INIT_DATA_WEBM
ENCRYPTION_UNENCRYPTED = _native.ENCRYPTION_UNENCRYPTED
ENCRYPTION_CENC = _native.ENCRYPTION_CENC
ENCRYPTION_CBCS = _native.ENCRYPTION_CBCS
STREAM_AUDIO = _native.STREAM_AUDIO
STREAM_VIDEO = _native.STREAM_VIDEO
STATUS_SUCCESS = _native.STATUS_SUCCESS
STATUS_NEED_MORE_DATA = _native.STATUS_NEED_MORE_DATA
STATUS_NO_KEY = _native.STATUS_NO_KEY
STATUS_INITIALIZATION_ERROR = _native.STATUS_INITIALIZATION_ERROR
STATUS_DECRYPT_ERROR = _native.STATUS_DECRYPT_ERROR
STATUS_DECODE_ERROR = _native.STATUS_DECODE_ERROR
STATUS_DEFERRED_INITIALIZATION = _native.STATUS_DEFERRED_INITIALIZATION
status_name = _native.status_name_py

PsshLike = Union[PSSH, str, bytes]
SessionLike = Union["Session", str]


class Session:
    """An open CDM session. Use it as a context manager."""

    def __init__(self, cdm: Cdm, session_type: int = SESSION_TEMPORARY):
        self._cdm = cdm
        self.id: str | None = None
        self.message: bytes | None = None
        self.keys: list[Key] = []
        self.session_type = session_type
        self._closed = False

    def get_license_challenge(self, pssh: PsshLike) -> bytes:
        """Generate the (signed) license request for ``pssh``."""
        return self._cdm.get_license_challenge(self, pssh)

    def parse_license(self, licence: bytes) -> None:
        """Submit a license server response and record the resulting keys."""
        self._cdm.parse_license(self, licence)

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc_info) -> None:
        self._cdm.close(self)

    def __repr__(self) -> str:
        return f"Session(id={self.id!r}, keys={len(self.keys)})"


class Cdm:
    """A Widevine CDM. Use it as a context manager."""

    def __init__(self, device: Device, storage_dir: str | None = None):
        self.device = device
        self._native = _native.WidevineCdm(device.path, True, storage_dir)
        self._sessions: list[Session] = []
        self._closed = False

    @classmethod
    def from_device(
        cls, device: Device, storage_dir: str | None = None
    ) -> Cdm:
        """Create a CDM instance backed by ``device``.

        ``storage_dir`` is where persistent session/usage data is written; it
        defaults to ``$NARROWVINE_STORAGE`` or ``~/.local/share/narrowvine``.
        """
        return cls(device, storage_dir)

    # --- sessions ---------------------------------------------------------

    def open(self, session_type: int = SESSION_TEMPORARY) -> Session:
        """Open a new session (the CDM session is created on the first challenge).

        Pass ``session_type=SESSION_PERSISTENT_LICENSE`` to ask the CDM to store
        the license on disk (``load_session`` can restore it later).
        """
        self._check_open()
        session = Session(self, session_type)
        self._sessions.append(session)
        return session

    def load_session(
        self, session_id: str, session_type: int = SESSION_PERSISTENT_LICENSE
    ) -> Session:
        """Load a stored persistent session. Use the result as a context manager."""
        self._check_open()
        result = self._native.load_session(session_id, session_type)
        if not result.get("resolved") or not result.get("session_id"):
            raise LicenseError(
                result.get("error_message") or f"session {session_id!r} could not be loaded"
            )
        session = Session(self)
        session.id = result["session_id"]
        self._sessions.append(session)
        self._absorb(result)
        return session

    def get_license_challenge(self, session: SessionLike, pssh: PsshLike) -> bytes:
        session = self._resolve(session)
        if isinstance(pssh, (str, bytes)):
            pssh = PSSH(pssh)
        result = self._native.create_session_and_generate_request(
            pssh.dumps(), INIT_DATA_CENC, session.session_type
        )
        if not result.get("resolved") or not result.get("messages"):
            raise LicenseError(result.get("error_message") or "license challenge rejected")
        session.id = result["session_id"]
        session.message = result["messages"][0]["message"]
        return session.message

    def parse_license(self, session: SessionLike, licence: bytes) -> None:
        session = self._resolve(session)
        if session.id is None:
            raise SessionError("generate a license challenge before parsing a license")
        result = self._native.update_session(session.id, licence)
        if not result.get("resolved"):
            raise LicenseError(result.get("error_message") or "license rejected")
        self._absorb(result, wvlicense.key_types(licence))

    def get_keys(self, session: SessionLike) -> list[Key]:
        """Key ids/types/statuses resulting from the license (never key bytes)."""
        return list(self._resolve(session).keys)

    def close(self, session: SessionLike) -> None:
        session = self._resolve(session)
        if session._closed:
            return
        session._closed = True
        if session.id is not None:
            self._native.close_session(session.id)
        self._sessions.remove(session)

    # --- CDM-wide operations ---------------------------------------------

    def set_server_certificate(self, certificate: bytes) -> None:
        """Provide the service certificate used to encrypt license requests.

        Accepts either the ``SignedDrmCertificate`` or the whole
        ``SignedMessage{SERVICE_CERTIFICATE}`` returned by
        :func:`narrowvine.fetch_service_certificate`.
        """
        result = self._native.set_server_certificate(
            wvlicense.unwrap_service_certificate(certificate)
        )
        if not result.get("resolved"):
            raise LicenseError(
                result.get("error_message") or "server certificate rejected"
            )

    def get_status_for_policy(self, min_hdcp_version: int = 0) -> KeyStatus:
        """Key status for a hypothetical key with the given minimum HDCP policy."""
        result = self._native.get_status_for_policy(min_hdcp_version)
        if not result.get("resolved"):
            raise LicenseError(
                result.get("error_message") or "GetStatusForPolicy was rejected"
            )
        return KeyStatus(result["key_status"])

    def version(self) -> str:
        return self._native.version()

    def initialized(self) -> bool:
        return self._native.initialized()

    def stats(self) -> dict[str, int]:
        """Host-side counters (useful for diagnostics/tests)."""
        scheduled, fired, fileio = self._native.stats()
        return {
            "timers_scheduled": scheduled,
            "timers_fired": fired,
            "fileio_created": fileio,
        }

    # --- timers -----------------------------------------------------------

    def service_timers(self) -> int:
        """Fire due host timers on the CDM thread; returns how many fired."""
        self._check_open()
        before = self._native.stats()[1]
        result = self._native.service_timers()
        self._absorb(result)
        return self._native.stats()[1] - before

    def wait(self, timeout: float | None = None) -> int:
        """Service timers until no sessions remain or ``timeout`` seconds pass.

        This is the owner-thread event loop for simple scripts; a browser would
        call :meth:`service_timers` from its own loop instead.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        fired = 0
        while self._sessions:
            fired += self.service_timers()
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(0.02)
        return fired

    # --- low-level decrypt/decode passthroughs ----------------------------

    def decrypt(
        self,
        data: bytes,
        key_id: bytes = b"",
        iv: bytes = b"",
        subsamples: list[tuple[int, int]] | None = None,
        encryption_scheme: int = ENCRYPTION_CENC,
        crypt_byte_block: int = 0,
        skip_byte_block: int = 0,
        timestamp: int = 0,
    ) -> DecryptResult:
        return self._native.decrypt(
            data,
            key_id,
            iv,
            subsamples,
            encryption_scheme,
            crypt_byte_block,
            skip_byte_block,
            timestamp,
        )

    def decrypt_and_decode_frame(
        self,
        data: bytes,
        key_id: bytes = b"",
        iv: bytes = b"",
        subsamples: list[tuple[int, int]] | None = None,
        encryption_scheme: int = ENCRYPTION_CENC,
        crypt_byte_block: int = 0,
        skip_byte_block: int = 0,
        timestamp: int = 0,
    ) -> FrameResult:
        return self._native.decrypt_and_decode_frame(
            data,
            key_id,
            iv,
            subsamples,
            encryption_scheme,
            crypt_byte_block,
            skip_byte_block,
            timestamp,
        )

    def decrypt_and_decode_samples(
        self,
        data: bytes,
        key_id: bytes = b"",
        iv: bytes = b"",
        subsamples: list[tuple[int, int]] | None = None,
        encryption_scheme: int = ENCRYPTION_CENC,
        crypt_byte_block: int = 0,
        skip_byte_block: int = 0,
        timestamp: int = 0,
    ) -> AudioSamplesResult:
        return self._native.decrypt_and_decode_samples(
            data,
            key_id,
            iv,
            subsamples,
            encryption_scheme,
            crypt_byte_block,
            skip_byte_block,
            timestamp,
        )

    def initialize_audio_decoder(
        self,
        codec: int,
        channel_count: int,
        bits_per_channel: int,
        samples_per_second: int,
        extra_data: bytes = b"",
        encryption_scheme: int = ENCRYPTION_CENC,
    ) -> int:
        return self._native.initialize_audio_decoder(
            codec,
            channel_count,
            bits_per_channel,
            samples_per_second,
            extra_data,
            encryption_scheme,
        )

    def initialize_video_decoder(
        self,
        codec: int,
        width: int,
        height: int,
        profile: int = 0,
        format: int = 2,
        extra_data: bytes = b"",
        encryption_scheme: int = ENCRYPTION_CENC,
    ) -> int:
        return self._native.initialize_video_decoder(
            codec, width, height, profile, format, extra_data, encryption_scheme
        )

    def deinitialize_decoder(self, stream_type: int) -> None:
        self._native.deinitialize_decoder(stream_type)

    def reset_decoder(self, stream_type: int) -> None:
        self._native.reset_decoder(stream_type)

    # --- internals --------------------------------------------------------

    def _check_open(self) -> None:
        if self._closed:
            raise CdmError("CDM is closed")

    def _resolve(self, session: SessionLike) -> Session:
        self._check_open()
        if isinstance(session, Session):
            return session
        found = self._find(session)
        if found is None:
            raise SessionError(f"unknown session: {session!r}")
        return found

    def _find(self, session_id: str | None) -> Session | None:
        if session_id is None:
            return None
        for candidate in self._sessions:
            if candidate.id == session_id:
                return candidate
        return None

    def _absorb(self, result: SessionResult, types: dict[bytes, KeyType] | None = None) -> None:
        """Apply key/expiration events from a native result to our sessions."""
        types = types or {}
        for change in result.get("keys", []):
            session = self._find(change.get("session_id"))
            if session is None:
                continue
            session.keys = [
                Key(
                    kid=bytes(info["key_id"]),
                    type=types.get(bytes(info["key_id"]), KeyType.CONTENT),
                    status=KeyStatus(info["status"]),
                    system_code=info["system_code"],
                )
                for info in change["keys"]
            ]

    def __enter__(self) -> Cdm:
        return self

    def __exit__(self, *exc_info) -> None:
        for session in list(self._sessions):
            try:
                self.close(session)
            except Exception:  # noqa: BLE001 - never mask the body's exception
                pass
        self._closed = True
