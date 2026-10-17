"""Exceptions raised by narrowvine."""

from __future__ import annotations


class NarrowvineError(Exception):
    """Base class for all narrowvine errors."""


class CdmError(NarrowvineError):
    """The CDM could not be loaded or used."""


class SessionError(NarrowvineError):
    """A session handle was missing, closed or already used."""


class LicenseError(NarrowvineError):
    """The license request was rejected or the license response was invalid."""
