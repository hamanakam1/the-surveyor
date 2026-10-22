"""Exceptions shared across The Surveyor.

Every error carries an operator-facing sentence, because the daemon is often
the only thing awake at 03:00 and its log is the only witness.
"""

from __future__ import annotations


class SurveyorError(Exception):
    """Base class for expected, reportable failures."""


class ConfigError(SurveyorError):
    """A configuration file or override is unusable."""


class ProbeError(SurveyorError):
    """A read-only system probe was refused or could not be executed."""


class ScannerError(SurveyorError):
    """A scanner failed in a way that should be attributed to that scanner."""


class StoreError(SurveyorError):
    """The survey ledger is unavailable, corrupt, or locked."""


class SchemaError(SurveyorError):
    """An OET document does not satisfy the schema."""


class LLMError(SurveyorError):
    """The optional local model refused or failed the request."""
