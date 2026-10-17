"""Type stubs for the maturin-built extension ``narrowvine._native``.

The extension is `rust/src/python.rs`; keep this stub in sync with it
(`tests/test_native_stub.py` checks for drift).
"""

from .utils.types import (
    AudioSamplesResult,
    DecryptResult,
    FrameResult,
    SessionResult,
)

CDM_INTERFACE_VERSION: int
SESSION_TEMPORARY: int
SESSION_PERSISTENT_LICENSE: int
INIT_DATA_CENC: int
INIT_DATA_KEYIDS: int
INIT_DATA_WEBM: int
ENCRYPTION_UNENCRYPTED: int
ENCRYPTION_CENC: int
ENCRYPTION_CBCS: int
STREAM_AUDIO: int
STREAM_VIDEO: int
STATUS_SUCCESS: int
STATUS_NEED_MORE_DATA: int
STATUS_NO_KEY: int
STATUS_INITIALIZATION_ERROR: int
STATUS_DECRYPT_ERROR: int
STATUS_DECODE_ERROR: int
STATUS_DEFERRED_INITIALIZATION: int

class WidevineCdm:
    def __init__(
        self,
        lib_path: str,
        allow_persistent_state: bool = True,
        storage_dir: str | None = None,
    ) -> None: ...
    def stats(self) -> tuple[int, int, int]: ...
    def set_server_certificate(self, certificate: bytes) -> SessionResult: ...
    def get_status_for_policy(self, min_hdcp_version: int = 0) -> SessionResult: ...
    def service_timers(self) -> SessionResult: ...
    def version(self) -> str: ...
    def initialized(self) -> bool: ...
    def create_session_and_generate_request(
        self, init_data: bytes, init_data_type: int = 0, session_type: int = 0
    ) -> SessionResult: ...
    def load_session(
        self, session_id: bytes | str, session_type: int = 0
    ) -> SessionResult: ...
    def update_session(
        self, session_id: bytes | str, response: bytes
    ) -> SessionResult: ...
    def close_session(self, session_id: bytes | str) -> SessionResult: ...
    def decrypt(
        self,
        data: bytes,
        key_id: bytes = b"",
        iv: bytes = b"",
        subsamples: list[tuple[int, int]] | None = None,
        encryption_scheme: int = 1,
        crypt_byte_block: int = 0,
        skip_byte_block: int = 0,
        timestamp: int = 0,
    ) -> DecryptResult: ...
    def decrypt_and_decode_frame(
        self,
        data: bytes,
        key_id: bytes = b"",
        iv: bytes = b"",
        subsamples: list[tuple[int, int]] | None = None,
        encryption_scheme: int = 1,
        crypt_byte_block: int = 0,
        skip_byte_block: int = 0,
        timestamp: int = 0,
    ) -> FrameResult: ...
    def decrypt_and_decode_samples(
        self,
        data: bytes,
        key_id: bytes = b"",
        iv: bytes = b"",
        subsamples: list[tuple[int, int]] | None = None,
        encryption_scheme: int = 1,
        crypt_byte_block: int = 0,
        skip_byte_block: int = 0,
        timestamp: int = 0,
    ) -> AudioSamplesResult: ...
    def initialize_audio_decoder(
        self,
        codec: int,
        channel_count: int,
        bits_per_channel: int,
        samples_per_second: int,
        extra_data: bytes = b"",
        encryption_scheme: int = 1,
    ) -> int: ...
    def initialize_video_decoder(
        self,
        codec: int,
        width: int,
        height: int,
        profile: int = 0,
        format: int = 2,
        extra_data: bytes = b"",
        encryption_scheme: int = 1,
    ) -> int: ...
    def deinitialize_decoder(self, stream_type: int) -> None: ...
    def reset_decoder(self, stream_type: int) -> None: ...

def status_name_py(status: int) -> str: ...
def libwidevinecdm_version(lib_path: str) -> str: ...
