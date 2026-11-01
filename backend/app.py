"""
RISK CHECKER — Intelligent Cybersecurity Risk Assessment Platform
Backend Flask REST API Server
"""

import os
import sys
import time
from datetime import datetime
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS

# Add root directory to path for imports
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
DIST_DIR = os.path.join(PROJECT_DIR, "frontend", "dist")
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from backend.database.db import (
    init_db, create_scan, update_scan_results, get_scan,
    get_all_scans, delete_scan, get_dashboard_stats, get_settings, update_settings
)
from backend.scanner.validator import parse_and_validate_target, resolve_host_ips
from backend.scanner.web_scanner import analyze_website_security
from backend.scanner.ssl_checker import analyze_ssl_certificate
from backend.scanner.port_scanner import scan_authorized_ports
from backend.scanner.risk_calculator import calculate_risk_score
from backend.reports.pdf_generator import generate_security_pdf_report

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Ensure database is initialized
init_db()


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint validating service status."""
    return jsonify({
        "status": "healthy",
        "service": "RISK CHECKER API",
        "timestamp": datetime.now().isoformat(),
        "version": "2.4.0",
        "database": "sqlite3_ready"
    }), 200


@app.route("/api/scan", methods=["POST"])
def run_scan():
    """
    Primary scanning endpoint.
    Accepts target URL/domain and authorization confirmation.
    Performs DNS resolution, SSRF validation, Web audit, SSL inspection,
    authorized Port checking, and risk score calculation.
    """
    data = request.get_json(silent=True) or {}
    target_input = data.get("target", "").strip()
    authorized = bool(data.get("authorized", False))
    scan_ports = bool(data.get("scan_ports", True))

    if not target_input:
        return jsonify({
            "error": "Target URL or hostname is required.",
            "field": "target"
        }), 400

    # Retrieve system settings (e.g. allow local dev scan)
    settings = get_settings()
    allow_local_dev = settings.get("allow_local_dev_scan", "false").lower() == "true"
    timeout_sec = float(settings.get("timeout_seconds", "8"))

    # Validate target and enforce SSRF protections
    start_time = time.time()
    is_valid, validation_err, target_info = parse_and_validate_target(
        target_input, allow_local=allow_local_dev
    )

    if not is_valid or not target_info:
        return jsonify({
            "error": validation_err or "Invalid or prohibited target destination.",
            "target": target_input,
            "security_restriction": "SSRF policy blocked private, loopback, or cloud metadata endpoints."
        }), 400

    hostname = target_info["hostname"]
    primary_ip = target_info["primary_ip"]
    all_ips = target_info["all_ips"]

    # Create initial scan record
    scan_id = create_scan(target_info["normalized_url"], hostname, primary_ip)

    all_findings = []

    try:
        # 1. DNS & IP Information Module
        dns_data = {
            "hostname": hostname,
            "primary_ip": primary_ip,
            "all_resolved_ips": all_ips,
            "ip_version": "IPv6" if ":" in primary_ip else "IPv4",
            "resolution_status": "SUCCESS"
        }

        # 2. Website Security Scanner Module
        web_results = analyze_website_security(
            target_info, allow_local=allow_local_dev, timeout=timeout_sec
        )
        all_findings.extend(web_results.get("findings", []))

        # 3. SSL/TLS Certificate Checker Module
        ssl_results = analyze_ssl_certificate(
            hostname, primary_ip, port=443, timeout=timeout_sec
        )
        all_findings.extend(ssl_results.get("findings", []))

        # 4. Authorized TCP Port Checking Module
        port_results = {}
        if scan_ports:
            port_results = scan_authorized_ports(
                primary_ip,
                hostname,
                is_authorized=authorized,
                timeout_per_port=1.0
            )
            all_findings.extend(port_results.get("findings", []))
        else:
            port_results = {
                "authorized": False,
                "skipped": True,
                "ports": [],
                "open_count": 0,
                "findings": []
            }

        # 5. Risk Score Calculator Module
        risk_evaluation = calculate_risk_score(
            all_findings,
            web_data=web_results,
            ssl_data=ssl_results,
            port_data=port_results
        )

        scan_duration = round(time.time() - start_time, 2)
        final_score = risk_evaluation["risk_score"]
        final_level = risk_evaluation["risk_level"]
        final_findings = risk_evaluation["findings"]

        # Persist full results to SQLite database
        update_scan_results(
            scan_id=scan_id,
            status="COMPLETED",
            risk_score=final_score,
            risk_level=final_level,
            scan_duration=scan_duration,
            findings=final_findings,
            web_data=web_results,
            ssl_data=ssl_results,
            port_data=port_results,
            dns_data=dns_data
        )

        # Retrieve saved complete scan object
        completed_scan = get_scan(scan_id)

        return jsonify({
            "success": True,
            "message": "Security risk assessment completed successfully.",
            "scan": completed_scan
        }), 201

    except Exception as e:
        scan_duration = round(time.time() - start_time, 2)
        update_scan_results(
            scan_id=scan_id,
            status="FAILED",
            risk_score=0,
            risk_level="UNKNOWN",
            scan_duration=scan_duration,
            findings=[{
                "category": "Scan Execution",
                "title": "Assessment Pipeline Error",
                "severity": "HIGH",
                "description": f"Internal scan failure occurred: {str(e)}",
                "evidence": str(e),
                "impact": "Incomplete audit output.",
                "recommendation": "Verify target accessibility and host network connectivity."
            }],
            web_data={},
            ssl_data={},
            port_data={},
            dns_data={"hostname": hostname, "primary_ip": primary_ip}
        )
        return jsonify({
            "error": f"Security assessment encountered an error: {str(e)}",
            "scan_id": scan_id
        }), 500


@app.route("/api/results", methods=["GET"])
def get_results():
    """Returns a specific scan result by ID or the latest scan."""
    scan_id_param = request.args.get("id")
    if scan_id_param:
        try:
            scan_id = int(scan_id_param)
            scan = get_scan(scan_id)
            if not scan:
                return jsonify({"error": f"Scan with ID {scan_id} not found."}), 404
            return jsonify({"scan": scan}), 200
        except ValueError:
            return jsonify({"error": "Invalid scan ID parameter."}), 400

    # If no ID provided, return latest completed scan
    all_scans = get_all_scans(limit=1)
    if not all_scans:
        return jsonify({"scan": None, "message": "No scans recorded yet."}), 200

    latest_id = all_scans[0]["id"]
    scan = get_scan(latest_id)
    return jsonify({"scan": scan}), 200


@app.route("/api/history", methods=["GET"])
def get_history():
    """Returns scan history list with summary metrics."""
    limit = request.args.get("limit", default=50, type=int)
    scans = get_all_scans(limit=limit)
    return jsonify({
        "total": len(scans),
        "scans": scans
    }), 200


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def delete_history_item(scan_id: int):
    """Deletes a scan record and its associated findings and details."""
    success = delete_scan(scan_id)
    if not success:
        return jsonify({"error": f"Scan ID {scan_id} not found."}), 404
    return jsonify({"success": True, "message": f"Scan {scan_id} successfully deleted."}), 200


@app.route("/api/dashboard", methods=["GET"])
def get_dashboard():
    """Returns aggregated security statistics, severity counts, and activity."""
    stats = get_dashboard_stats()
    return jsonify(stats), 200


@app.route("/api/report/<int:scan_id>", methods=["GET"])
def download_report(scan_id: int):
    """Generates and serves a downloadable PDF security audit report."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan ID {scan_id} not found."}), 404

    reports_dir = os.path.join(PROJECT_DIR, "reports")
    pdf_filename = f"RiskChecker_Report_{scan['hostname']}_{scan_id}.pdf"
    pdf_path = os.path.join(reports_dir, pdf_filename)

    try:
        generate_security_pdf_report(scan, pdf_path)
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=pdf_filename,
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate PDF report: {str(e)}"}), 500


@app.route("/api/settings", methods=["GET", "POST"])
def handle_settings():
    """Retrieve or update system settings."""
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        update_settings(payload)
        return jsonify({"success": True, "settings": get_settings()}), 200

    return jsonify({"settings": get_settings()}), 200


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    """Serves the production built React dashboard if present, or API status."""
    if path.startswith("api/"):
        return jsonify({"error": f"API endpoint '/{path}' not found."}), 404
    if os.path.exists(DIST_DIR):
        file_path = os.path.join(DIST_DIR, path)
        if path != "" and os.path.exists(file_path):
            return send_from_directory(DIST_DIR, path)
        return send_from_directory(DIST_DIR, "index.html")
    return jsonify({
        "service": "RISK CHECKER Backend API",
        "status": "online",
        "api_docs": "/api/health",
        "message": "Frontend static bundle not found. Run 'npm run build' inside frontend/ or launch Vite dev server."
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] Starting RISK CHECKER server on http://{host}:{port}...")
    try:
        from waitress import serve
        print("[*] Running with production multi-threaded Waitress WSGI server...")
        serve(app, host=host, port=port)
    except ImportError:
        app.run(host=host, port=port, debug=False)
