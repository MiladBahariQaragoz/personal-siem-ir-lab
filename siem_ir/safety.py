"""Fail-closed scope guard for siem_ir.

All attack scripts MUST call check(target) before execution.
Any target outside the configured lab.subnets is refused.
Malformed or missing input is ALSO refused — never default-allow.

Usage:
    from siem_ir.safety import check, ScopeError
    check("10.0.0.5")   # raises ScopeError if not in lab.subnets
"""

from __future__ import annotations

import ipaddress
import pathlib
import tomllib
import warnings
from typing import Any


class ScopeError(Exception):
    """Raised when a target is outside the authorized lab scope."""


# ---------------------------------------------------------------------------
# Module-level subnet cache — populated once at import time from lab.toml.
# Stored as a tuple to make accidental mutation immediately visible (TypeError).
# NOTE: this is NOT a security boundary on its own — Python callers can always
# rebind module attributes. The real guard is the fail-closed check() function.
# Tests should use reload() or monkeypatch the tuple; see reload() below.
# ---------------------------------------------------------------------------

_ALLOWED_SUBNETS: tuple[str, ...] = ()


def _load_subnets() -> list[str]:
    """Walk up from this file to find lab.toml and load lab.subnets.*.

    Returns an empty list (fail-closed) if lab.toml is missing or contains
    invalid TOML — a warning is emitted so the broken config is visible.
    """
    here = pathlib.Path(__file__).resolve()
    for parent in [here.parent, here.parent.parent, here.parent.parent.parent]:
        candidate = parent / "lab.toml"
        if candidate.exists():
            try:
                with candidate.open("rb") as fh:
                    data = tomllib.load(fh)
            except tomllib.TOMLDecodeError as exc:
                warnings.warn(
                    f"lab.toml at {candidate} is corrupt and could not be parsed "
                    f"({exc}). Falling back to empty subnet list — all targets will "
                    "be refused (fail-closed).",
                    stacklevel=2,
                )
                return []
            subnets = data.get("lab", {}).get("subnets", {})
            return list(subnets.values())
    return []


# Populate at import time (tests override via monkeypatch).
_ALLOWED_SUBNETS: tuple[str, ...] = tuple(_load_subnets())


def reload() -> None:
    """Re-read lab.toml and refresh the in-process subnet cache.

    Call this if lab.toml is modified while the process is running.
    The cache is module-global, so this affects all subsequent check() calls
    in the current process.
    """
    global _ALLOWED_SUBNETS
    _ALLOWED_SUBNETS = tuple(_load_subnets())


def check(target: Any) -> None:  # noqa: ANN401
    """Fail-closed scope check.

    Raises ScopeError if target is not a valid IP address inside an
    authorized lab subnet, or if input is malformed/missing.

    Args:
        target: The IP address string to check.

    Raises:
        ScopeError: Always, unless target is a valid IP inside lab.subnets.
    """
    # Non-string input → refuse immediately
    if not isinstance(target, str):
        raise ScopeError(
            f"Target must be a string IP address; got {type(target).__name__!r}"
        )

    # Empty string → refuse
    if not target.strip():
        raise ScopeError("Target IP address must not be empty.")

    # Parse IP — refuse if not a valid dotted-decimal address (no hostnames)
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        raise ScopeError(f"Invalid IP address: {target!r}")

    # Check against each authorized subnet
    allowed_networks = []
    for cidr in _ALLOWED_SUBNETS:
        try:
            allowed_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            # Bad CIDR in lab.toml — fail closed (don't allow everything)
            continue

    if not allowed_networks:
        raise ScopeError(
            "No authorized subnets configured in lab.toml — refusing all targets."
        )

    for network in allowed_networks:
        if addr in network:
            return  # authorized

    raise ScopeError(
        f"Target {target!r} is outside authorized lab subnets "
        f"({[str(n) for n in allowed_networks]}). Refusing."
    )
