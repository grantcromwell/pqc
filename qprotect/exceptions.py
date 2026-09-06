from __future__ import annotations


class QProtectError(Exception):
    """Base exception for qprotect."""


class ProviderError(QProtectError):
    """An OpenSSL capability or invocation failed."""


class EnvelopeError(QProtectError):
    """An envelope is malformed, unsupported, or fails authentication."""


class KeyMaterialError(QProtectError):
    """A key is invalid or unsupported."""


class IdentityValidationError(QProtectError):
    """Sensitive identity data is malformed."""


class DiskSafetyError(QProtectError):
    """A destructive disk operation was requested without explicit approval."""
