"""The Surveyor: empirical infrastructure cartography for the edge.

The public entry point is :func:`surveyor.cli.main`. Everything in this
package is read-only with respect to the machine being surveyed: scanners may
run a small allowlist of introspection commands, and never mutate state.
"""

from __future__ import annotations

__version__ = "1.0.0"
OET_VERSION = "1.0"

__all__ = ["OET_VERSION", "__version__"]
