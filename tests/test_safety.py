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
    """_load_subnets() must return [] on invalid TOML — not raise (SECURITY#3).
    Uses SIEM_IR_LAB_CONFIG env var to point at the corrupt file."""
    import warnings

    import siem_ir.safety as safety_module

    corrupt = tmp_path / "lab.toml"
    corrupt.write_text("this is not valid TOML <<<", encoding="utf-8")

    # Use the explicit env-var override so _load_subnets picks up our corrupt file.
    monkeypatch.setenv("SIEM_IR_LAB_CONFIG", str(corrupt))

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = safety_module._load_subnets()

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


# ---------------------------------------------------------------------------
# Security: SECURITY#2 — _ALLOWED_SUBNETS must be a tuple (immutable cache)
# ---------------------------------------------------------------------------


def test_allowed_subnets_is_tuple(tmp_path, monkeypatch):
    """_ALLOWED_SUBNETS must be stored as a tuple by reload() (SECURITY#2).
    The autouse fixture overrides with a list for check() tests — that's fine.
    Here we verify that reload() always writes a tuple."""
    import siem_ir.safety as safety_module

    # Point at a non-existent path so no lab.toml is found → empty tuple.
    monkeypatch.setenv("SIEM_IR_LAB_CONFIG", str(tmp_path / "nonexistent.toml"))
    safety_module.reload()

    assert isinstance(safety_module._ALLOWED_SUBNETS, tuple), (
        "reload() must store subnets as a tuple to prevent in-place mutation"
    )


def test_reload_refreshes_subnet_cache(tmp_path, monkeypatch):
    """reload() must re-read lab.toml and update _ALLOWED_SUBNETS (SECURITY#2).
    Uses SIEM_IR_LAB_CONFIG to point at a temp lab.toml."""
    import siem_ir.safety as safety_module

    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text('[lab.subnets]\nprimary = "172.16.0.0/24"\n', encoding="utf-8")

    monkeypatch.setenv("SIEM_IR_LAB_CONFIG", str(lab_toml))
    safety_module.reload()
    assert "172.16.0.0/24" in safety_module._ALLOWED_SUBNETS, (
        "reload() must update _ALLOWED_SUBNETS from the new lab.toml"
    )
    assert isinstance(safety_module._ALLOWED_SUBNETS, tuple), (
        "reload() must store subnets as a tuple"
    )


# ---------------------------------------------------------------------------
# Security: SECURITY#3 — env-var override honored; ancestor walk removed
# ---------------------------------------------------------------------------


def test_env_var_config_override_is_honored(tmp_path, monkeypatch):
    """SIEM_IR_LAB_CONFIG env var must take precedence over filesystem discovery
    (SECURITY#3 — config-confusion fix)."""
    import warnings

    import siem_ir.safety as safety_module

    lab_toml = tmp_path / "override.toml"
    lab_toml.write_text('[lab.subnets]\ntest = "192.0.2.0/24"\n', encoding="utf-8")

    monkeypatch.setenv("SIEM_IR_LAB_CONFIG", str(lab_toml))

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = safety_module._load_subnets()

    assert "192.0.2.0/24" in result, "Env-var override lab.toml must be loaded"
    # Resolved path must appear in the warning so operators can verify it.
    assert any(str(lab_toml) in str(w.message) for w in caught), (
        "Expected warning including the resolved config path"
    )


def test_unrelated_ancestor_lab_toml_not_loaded(tmp_path, monkeypatch):
    """An unrelated lab.toml in a parent directory must NOT be silently picked up
    (SECURITY#3 — only look at repo root, not 3 levels of ancestors)."""
    import siem_ir.safety as safety_module

    # Place a lab.toml with a recognizable subnet far up tmp_path
    ancestor = tmp_path / "ancestor"
    ancestor.mkdir()
    (ancestor / "lab.toml").write_text(
        '[lab.subnets]\nevil = "10.255.255.0/24"\n', encoding="utf-8"
    )

    # No SIEM_IR_LAB_CONFIG set; package root has no lab.toml.
    # Point the module's package root away from tmp_path to avoid picking up
    # any real lab.toml — use a deep subdirectory with no lab.toml above it
    # within the search depth.
    deep = tmp_path / "project" / "siem_ir"
    deep.mkdir(parents=True)
    monkeypatch.delenv("SIEM_IR_LAB_CONFIG", raising=False)
    monkeypatch.setattr(safety_module, "__file__", str(deep / "safety.py"))

    result = safety_module._load_subnets()

    assert "10.255.255.0/24" not in result, (
        "Unrelated ancestor lab.toml must not be loaded (SECURITY#3)"
    )
