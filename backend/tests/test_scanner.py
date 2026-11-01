"""
Automated Test Suite for RISK CHECKER.
Validates URL & SSRF filtering, security headers parsing, risk score calculation,
database persistence, and API handlers using mock data without external network calls.
"""

import os
import tempfile
import pytest
import sqlite3

from backend.database.db import (
    init_db, create_scan, update_scan_results, get_scan,
    get_all_scans, delete_scan, get_dashboard_stats, get_settings, update_settings
)
from backend.scanner.validator import parse_and_validate_target, is_ip_safe
from backend.scanner.risk_calculator import (
    calculate_risk_score, classify_risk_level, deduplicate_findings
)
from backend.scanner.web_scanner import SECURITY_HEADERS_SPEC
from backend.scanner.ssl_checker import check_hostname_match
from backend.app import app


# -------------------------------------------------------------
# 1. URL Validation & SSRF Protection Tests
# -------------------------------------------------------------
def test_ssrf_blocks_private_ips():
    """Ensure private and link-local ranges are rejected by default."""
    assert is_ip_safe("127.0.0.1", allow_local=False)[0] is False
    assert is_ip_safe("192.168.1.1", allow_local=False)[0] is False
    assert is_ip_safe("10.0.0.5", allow_local=False)[0] is False
    assert is_ip_safe("172.16.0.1", allow_local=False)[0] is False
    assert is_ip_safe("169.254.169.254", allow_local=False)[0] is False  # Cloud metadata
    assert is_ip_safe("::1", allow_local=False)[0] is False


def test_ssrf_allow_local_flag():
    """Verify local override flag permits loopback for testing."""
    assert is_ip_safe("127.0.0.1", allow_local=True)[0] is True
    assert is_ip_safe("192.168.1.50", allow_local=True)[0] is True
    # Cloud metadata is NEVER permitted even with allow_local
    assert is_ip_safe("169.254.169.254", allow_local=True)[0] is False


def test_public_ips_allowed():
    """Verify standard public IP is accepted."""
    assert is_ip_safe("8.8.8.8", allow_local=False)[0] is True
    assert is_ip_safe("93.184.216.34", allow_local=False)[0] is True


def test_invalid_urls_rejected():
    """Ensure invalid schemes and empty targets are rejected."""
    valid, err, _ = parse_and_validate_target("")
    assert valid is False
    assert "cannot be empty" in err

    valid, err, _ = parse_and_validate_target("ftp://example.com")
    assert valid is False
    assert "Unsupported scheme" in err


# -------------------------------------------------------------
# 2. Risk Score Engine Tests
# -------------------------------------------------------------
def test_risk_level_classification():
    """Check classification thresholds."""
    assert classify_risk_level(10) == "LOW"
    assert classify_risk_level(19) == "LOW"
    assert classify_risk_level(20) == "MEDIUM"
    assert classify_risk_level(39) == "MEDIUM"
    assert classify_risk_level(40) == "HIGH"
    assert classify_risk_level(69) == "HIGH"
    assert classify_risk_level(70) == "CRITICAL"
    assert classify_risk_level(100) == "CRITICAL"


def test_deduplicate_findings():
    """Ensure duplicate findings are collapsed to highest severity."""
    findings = [
        {"category": "Transport", "title": "Missing HSTS", "severity": "MEDIUM"},
        {"category": "Transport", "title": "Missing HSTS", "severity": "HIGH"},
        {"category": "Headers", "title": "Missing CSP", "severity": "MEDIUM"}
    ]
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 2
    hsts = next(f for f in deduped if f["title"] == "Missing HSTS")
    assert hsts["severity"] == "HIGH"


def test_risk_calculator_score_capping():
    """Test score bounds and category capping."""
    findings = [
        {"category": "Transport Security", "title": f"Finding {i}", "severity": "CRITICAL"}
        for i in range(10)
    ]
    result = calculate_risk_score(findings)
    assert 0 <= result["risk_score"] <= 100
    # Capped at Transport Security max cap (35)
    assert result["risk_score"] == 35
    assert result["risk_level"] == "MEDIUM"


# -------------------------------------------------------------
# 3. SSL Hostname Matching Tests
# -------------------------------------------------------------
def test_hostname_matching():
    """Verify CN and SAN wildcard matching logic."""
    assert check_hostname_match("example.com", "example.com", []) is True
    assert check_hostname_match("sub.example.com", None, ["*.example.com"]) is True
    assert check_hostname_match("other.com", "example.com", ["example.org"]) is False


# -------------------------------------------------------------
# 4. Database Operations Tests
# -------------------------------------------------------------
def test_database_lifecycle():
    """Create a temporary database and verify full scan lifecycle."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db = tf.name

    try:
        init_db(temp_db)

        # Create scan
        scan_id = create_scan("https://target.local", "target.local", "127.0.0.1", db_path=temp_db)
        assert scan_id > 0

        # Update scan
        findings = [
            {
                "category": "Headers",
                "title": "Missing CSP",
                "severity": "MEDIUM",
                "description": "CSP absent",
                "evidence": "N/A",
                "impact": "XSS risk",
                "recommendation": "Add CSP"
            }
        ]
        update_scan_results(
            scan_id=scan_id,
            status="COMPLETED",
            risk_score=25,
            risk_level="MEDIUM",
            scan_duration=1.45,
            findings=findings,
            web_data={"status": 200},
            ssl_data={"valid": True},
            port_data={"open_count": 1},
            dns_data={"ip": "127.0.0.1"},
            db_path=temp_db
        )

        # Retrieve scan
        record = get_scan(scan_id, db_path=temp_db)
        assert record is not None
        assert record["risk_score"] == 25
        assert len(record["findings"]) == 1
        assert record["web_data"]["status"] == 200

        # Dashboard stats
        stats = get_dashboard_stats(db_path=temp_db)
        assert stats["total_scans"] == 1
        assert stats["medium_risk_count"] == 1

        # Delete scan
        deleted = delete_scan(scan_id, db_path=temp_db)
        assert deleted is True
        assert get_scan(scan_id, db_path=temp_db) is None
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


# -------------------------------------------------------------
# 5. Flask API Route Tests
# -------------------------------------------------------------
@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_api_health(client):
    """Test health check route."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"


def test_api_scan_empty_target(client):
    """Test empty target validation."""
    res = client.post("/api/scan", json={"target": ""})
    assert res.status_code == 400
    data = res.get_json()
    assert "field" in data


def test_api_scan_ssrf_blocked(client):
    """Test that scanning private target without override is rejected by API."""
    res = client.post("/api/scan", json={"target": "http://127.0.0.1"})
    assert res.status_code == 400
    data = res.get_json()
    assert "security_restriction" in data or "error" in data


def test_api_settings(client):
    """Test settings get and update."""
    res = client.get("/api/settings")
    assert res.status_code == 200
    data = res.get_json()
    assert "settings" in data

    update_res = client.post("/api/settings", json={"theme": "dark", "timeout_seconds": "10"})
    assert update_res.status_code == 200
    assert update_res.get_json()["settings"]["timeout_seconds"] == "10"
