"""TypedDicts describing the dicts returned by the native CDM methods."""

from __future__ import annotations

from typing import TypedDict


class Message(TypedDict):
    session_id: str
    message_type: int
    message: bytes


class KeyInfo(TypedDict):
    key_id: bytes
    status: int
    status_name: str
    system_code: int


class KeysChange(TypedDict):
    session_id: str
    has_additional_usable_key: bool
    keys: list[KeyInfo]


class SessionResult(TypedDict, total=False):
    promise_id: int
    resolved: bool
    session_id: str | None
    exception: int
    system_code: int
    error_message: str
    key_status: int
    messages: list[Message]
    keys: list[KeysChange]
    expiration: float | None
    closed: list[str]


class DecryptResult(TypedDict):
    status: int
    status_name: str
    data: bytes | None
    timestamp: int


class FrameResult(TypedDict):
    status: int
    status_name: str
    format: int
    width: int
    height: int
    data: bytes | None
    plane_offsets: tuple[int, int, int]
    strides: tuple[int, int, int]
    timestamp: int


class AudioSamplesResult(TypedDict):
    status: int
    status_name: str
    format: int
    data: bytes | None
