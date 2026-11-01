"""
End-to-End Integration Test for Local Lab Scanning and Report Generation.
Starts a background mock server on 127.0.0.1:8999, executes the full RISK CHECKER
pipeline, verifies SQLite persistence, and verifies PDF generation.
"""

import threading
import time
import os
import tempfile
from http.server import HTTPServer
from test_server import VulnerableMockHandler

from backend.database.db import init_db, create_scan, update_scan_results, get_scan
from backend.scanner.validator import parse_and_validate_target
from backend.scanner.web_scanner import analyze_website_security
from backend.scanner.port_scanner import scan_authorized_ports
from backend.scanner.risk_calculator import calculate_risk_score
from backend.reports.pdf_generator import generate_security_pdf_report


def test_full_pipeline_local_lab():
    # 1. Start test server on port 8999
    port = 8999
    httpd = HTTPServer(("127.0.0.1", port), VulnerableMockHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    time.sleep(0.5)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db = tf.name
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as pf:
        temp_pdf = pf.name

    try:
        init_db(temp_db)

        # 2. Validate target with allow_local=True
        target_str = f"http://127.0.0.1:{port}"
        valid, err, target_info = parse_and_validate_target(target_str, allow_local=True)
        assert valid is True, f"Validation failed: {err}"
        assert target_info["primary_ip"] == "127.0.0.1"

        # 3. Create initial scan
        scan_id = create_scan(target_info["normalized_url"], "127.0.0.1", "127.0.0.1", db_path=temp_db)
        assert scan_id > 0

        # 4. Web Security audit
        web_res = analyze_website_security(target_info, allow_local=True, timeout=5.0)
        assert web_res["status_code"] == 200
        # Check findings (missing CSP, HSTS, banner leak, cookie flags)
        titles = [f["title"] for f in web_res["findings"]]
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("Strict-Transport-Security" in t for t in titles)
        assert any("Server" in t for t in titles)

        # 5. Risk score calculation
        risk_res = calculate_risk_score(web_res["findings"])
        assert risk_res["risk_score"] > 0
        assert risk_res["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")

        # 6. Database save
        update_scan_results(
            scan_id=scan_id,
            status="COMPLETED",
            risk_score=risk_res["risk_score"],
            risk_level=risk_res["risk_level"],
            scan_duration=1.2,
            findings=risk_res["findings"],
            web_data=web_res,
            ssl_data={},
            port_data={},
            dns_data={"hostname": "127.0.0.1", "primary_ip": "127.0.0.1"},
            db_path=temp_db
        )

        saved_scan = get_scan(scan_id, db_path=temp_db)
        assert saved_scan["status"] == "COMPLETED"
        assert len(saved_scan["findings"]) > 0

        # 7. PDF Report Generation
        pdf_path = generate_security_pdf_report(saved_scan, temp_pdf)
        assert os.path.exists(pdf_path)
        assert os.path.getsize(pdf_path) > 1000  # Valid non-empty PDF
        print(f"[+] PDF generated successfully at {pdf_path} (size: {os.path.getsize(pdf_path)} bytes)")

    finally:
        httpd.shutdown()
        httpd.server_close()
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass
        if os.path.exists(temp_pdf):
            try:
                os.remove(temp_pdf)
            except Exception:
                pass
