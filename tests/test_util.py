"""The small helpers everything else leans on.

These are the functions whose failure would be quiet: a byte count rendered
as "unknown", a duration rendered as "0s", a boolean read as None. They are
cheap to test and worth testing.
"""

from __future__ import annotations

from surveyor.util import (
    boolish,
    canonical_json,
    clip,
    digest_of,
    human_bytes,
    human_duration,
    human_gib,
    humanize_key,
    sha256_hex,
    short_digest,
    slug,
    to_float,
    to_int,
)


def test_canonical_json_is_stable_whatever_the_order():
    first = canonical_json({"b": 1, "a": [3, 2]})
    second = canonical_json({"a": [3, 2], "b": 1})
    assert first == second
    assert first == '{"a":[3,2],"b":1}'


def test_canonical_json_falls_back_for_odd_values():
    """A value JSON cannot hold is stringified rather than dropped."""

    rendered = canonical_json({"when": object()})
    assert rendered.startswith('{"when":"<object object at ')


def test_digests_are_sha256():
    """A digest addresses the canonical bytes, not the string."""

    digest = digest_of("hello")
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
    assert digest.split(":", 1)[1] == sha256_hex('"hello"')


def test_short_digest_is_a_prefix():
    digest = digest_of("hello")
    assert short_digest(digest) == digest.split(":", 1)[1][:12]


def test_slug_is_lowercase_and_dashed():
    assert slug("My App") == "my-app"
    assert slug("  Weird__Name!! ") == "weird-name"
    assert slug("") == "unnamed"
    assert slug("---") == "unnamed"


def test_a_long_slug_keeps_its_identity():
    """Two long names that share a prefix must not become one node."""

    first = slug("a" * 200 + "one")
    second = slug("a" * 200 + "two")
    assert first != second
    assert len(first) <= 80
    # The digest is stable, so the id does not churn between surveys.
    assert first == slug("a" * 200 + "one")


def test_human_bytes():
    assert human_bytes(None) == "unknown"
    assert human_bytes(512) == "512 B"
    assert human_bytes(2048) == "2.0 KiB"
    assert human_bytes(1024**3) == "1.0 GiB"
    assert human_bytes(1024**4 * 3) == "3.0 TiB"


def test_human_gib():
    assert human_gib(None) == "unknown"
    assert human_gib(1024**3) == "1 GiB"
    assert human_gib(1024**4) == "1024 GiB"


def test_human_duration():
    assert human_duration(None) == "unknown"
    assert human_duration(30) == "30s"
    assert human_duration(90) == "1m"
    assert human_duration(3660) == "1h01m"
    assert human_duration(90000) == "1d01h"


def test_humanize_key():
    assert humanize_key("power_supply") == "Power supply"
    assert humanize_key("BAT0") == "Bat0"


def test_clip():
    assert clip("short", 10) == "short"
    assert clip("a" * 20, 10) == "aaaaaaaaa…"
    assert len(clip("a" * 20, 10)) == 10


def test_boolish():
    assert boolish("yes") is True
    assert boolish("ON") is True
    assert boolish("0") is False
    assert boolish("off") is False
    assert boolish("maybe") is None


def test_to_int():
    assert to_int(True) == 1
    assert to_int(7) == 7
    assert to_int(7.9) == 7
    assert to_int("1,024 bytes") == 1024
    assert to_int("no digits") is None
    assert to_int(None) is None


def test_to_float():
    assert to_float("1.5 GiB") == 1.5
    assert to_float(2) == 2.0
    assert to_float("nope") is None
