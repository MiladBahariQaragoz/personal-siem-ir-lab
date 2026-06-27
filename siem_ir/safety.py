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
from typing import Any


class ScopeError(Exception):
    """Raised when a target is outside the authorized lab scope."""


# ---------------------------------------------------------------------------
# Module-level subnet cache — populated once at import time from lab.toml.
# Tests may monkeypatch _ALLOWED_SUBNETS directly to avoid disk I/O.
# ---------------------------------------------------------------------------

_ALLOWED_SUBNETS: list[str] = []


def _load_subnets() -> list[str]:
    """Walk up from this file to find lab.toml and load lab.subnets.*."""
    here = pathlib.Path(__file__).resolve()
    for parent in [here.parent, here.parent.parent, here.parent.parent.parent]:
        candidate = parent / "lab.toml"
        if candidate.exists():
            with candidate.open("rb") as fh:
                data = tomllib.load(fh)
            subnets = data.get("lab", {}).get("subnets", {})
            return list(subnets.values())
    return []


# Populate at import time (tests override via monkeypatch).
_ALLOWED_SUBNETS = _load_subnets()


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
