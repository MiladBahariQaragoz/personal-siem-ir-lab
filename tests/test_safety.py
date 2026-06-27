"""Tests for the fail-closed scope guard siem_ir.safety.

Security invariants:
1. In-subnet IP → passes (no exception).
2. Out-of-subnet IP → ScopeError raised.
3. Malformed IP string → ScopeError raised.
4. Empty string → ScopeError raised.
5. Non-string input → ScopeError raised.
"""
import pytest

from siem_ir.safety import ScopeError, check

# ---------------------------------------------------------------------------
# Fixtures — subnets patched directly so tests don't depend on lab.toml on disk
# ---------------------------------------------------------------------------

_ALLOWED_SUBNETS = ["10.0.0.0/24", "192.168.56.0/24"]


@pytest.fixture(autouse=True)
def patch_subnets(monkeypatch):
    """Override the loaded subnets so tests are self-contained."""
    import siem_ir.safety as safety_module

    monkeypatch.setattr(safety_module, "_ALLOWED_SUBNETS", _ALLOWED_SUBNETS)


# ---------------------------------------------------------------------------
# Happy path: in-subnet IPs pass without raising
# ---------------------------------------------------------------------------


def test_in_subnet_first_range():
    check("10.0.0.1")  # must not raise


def test_in_subnet_last_host_first_range():
    check("10.0.0.254")  # must not raise


def test_in_subnet_second_range():
    check("192.168.56.100")  # must not raise


# ---------------------------------------------------------------------------
# Failure: out-of-subnet IPs fail closed
# ---------------------------------------------------------------------------


def test_out_of_subnet_raises():
    with pytest.raises(ScopeError):
        check("8.8.8.8")


def test_out_of_subnet_adjacent_raises():
    """10.0.1.0 is NOT in 10.0.0.0/24."""
    with pytest.raises(ScopeError):
        check("10.0.1.0")


def test_loopback_out_of_subnet_raises():
    with pytest.raises(ScopeError):
        check("127.0.0.1")


# ---------------------------------------------------------------------------
# Failure: malformed / missing input fails closed (NEVER default-allow)
# ---------------------------------------------------------------------------


def test_empty_string_raises():
    with pytest.raises(ScopeError):
        check("")


def test_non_ip_string_raises():
    with pytest.raises(ScopeError):
        check("not-an-ip")


def test_none_raises():
    with pytest.raises(ScopeError):
        check(None)  # type: ignore[arg-type]


def test_integer_raises():
    with pytest.raises(ScopeError):
        check(123)  # type: ignore[arg-type]


def test_partial_ip_raises():
    with pytest.raises(ScopeError):
        check("10.0.0")


def test_hostname_raises():
    """Hostnames are not accepted — only dotted-decimal IPs."""
    with pytest.raises(ScopeError):
        check("victim.local")
