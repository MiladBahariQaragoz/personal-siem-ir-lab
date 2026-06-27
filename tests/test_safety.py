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


# ---------------------------------------------------------------------------
# Robustness: corrupt lab.toml must not crash import; must stay fail-closed
# ---------------------------------------------------------------------------


def test_corrupt_lab_toml_fails_closed(tmp_path, monkeypatch):
    """_load_subnets() must return [] on invalid TOML — not raise."""
    corrupt = tmp_path / "lab.toml"
    corrupt.write_text("this is not valid TOML <<<", encoding="utf-8")

    import siem_ir.safety as safety_module

    # Call _load_subnets with the candidate directory monkeypatched so it
    # finds our corrupt file.  We patch __file__ on the module so the walk
    # resolves to tmp_path.
    original_file = safety_module.__file__

    monkeypatch.setattr(safety_module, "__file__", str(tmp_path / "safety.py"))
    import warnings

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = safety_module._load_subnets()

    monkeypatch.setattr(safety_module, "__file__", original_file)

    assert result == [], "Corrupt TOML must produce empty subnet list (fail-closed)"
    assert any("corrupt" in str(w.message).lower() for w in caught), (
        "Expected a warning about the corrupt lab.toml"
    )


def test_no_subnets_refuses_all(monkeypatch):
    """check() with _ALLOWED_SUBNETS=[] must raise ScopeError for any IP."""
    import siem_ir.safety as safety_module

    monkeypatch.setattr(safety_module, "_ALLOWED_SUBNETS", [])
    with pytest.raises(ScopeError, match="[Nn]o authorized subnets"):
        check("10.0.0.1")
