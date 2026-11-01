"""
Database layer for RISK CHECKER.
Manages SQLite storage for scans, findings, detailed audit payloads, and system settings.
"""

import sqlite3
import json
import os
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional, Any

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "risk_checker.db")


@contextmanager
def get_connection(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH) -> None:
    """Initialize database schema with tables and default settings."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Scans master table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'LOW',
                scan_duration REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT,
                impact TEXT,
                recommendation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        # Scan detailed JSON artifacts (web, ssl, port, dns)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL UNIQUE,
                web_data TEXT,
                ssl_data TEXT,
                port_data TEXT,
                dns_data TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        # Settings key-value table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        # Seed default settings if not exists
        default_settings = {
            "timeout_seconds": "8",
            "max_redirects": "5",
            "allow_local_dev_scan": "false",
            "authorized_domains": "localhost,127.0.0.1,example.com",
            "theme": "dark",
            "report_company_name": "Cybersecurity Assessment Team",
            "auto_port_scan": "true"
        }

        for k, v in default_settings.items():
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

        conn.commit()


def create_scan(target_url: str, hostname: str, ip_address: str, db_path: str = DB_PATH) -> int:
    """Create a new scan entry in PENDING status."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (target_url, hostname, ip_address, status)
            VALUES (?, ?, ?, 'PENDING')
        """, (target_url, hostname, ip_address))
        conn.commit()
        return cursor.lastrowid


def update_scan_results(
    scan_id: int,
    status: str,
    risk_score: int,
    risk_level: str,
    scan_duration: float,
    findings: List[Dict[str, Any]],
    web_data: Dict[str, Any],
    ssl_data: Dict[str, Any],
    port_data: Dict[str, Any],
    dns_data: Dict[str, Any],
    db_path: str = DB_PATH
) -> None:
    """Update scan status, risk score, findings, and detailed data."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE scans
            SET status = ?, risk_score = ?, risk_level = ?, scan_duration = ?
            WHERE id = ?
        """, (status, risk_score, risk_level, scan_duration, scan_id))

        # Remove previous findings if retrying
        cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))

        for f in findings:
            cursor.execute("""
                INSERT INTO findings (scan_id, category, title, severity, description, evidence, impact, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                f.get("category", "General"),
                f.get("title", "Untitled Finding"),
                f.get("severity", "LOW"),
                f.get("description", ""),
                f.get("evidence", ""),
                f.get("impact", ""),
                f.get("recommendation", "")
            ))

        # Insert or replace scan details
        cursor.execute("""
            INSERT INTO scan_details (scan_id, web_data, ssl_data, port_data, dns_data)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                web_data = excluded.web_data,
                ssl_data = excluded.ssl_data,
                port_data = excluded.port_data,
                dns_data = excluded.dns_data
        """, (
            scan_id,
            json.dumps(web_data),
            json.dumps(ssl_data),
            json.dumps(port_data),
            json.dumps(dns_data)
        ))

        conn.commit()


def get_scan(scan_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve full scan record by ID including findings and raw module details."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            return None

        scan_dict = dict(scan_row)

        cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END", (scan_id,))
        scan_dict["findings"] = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT * FROM scan_details WHERE scan_id = ?", (scan_id,))
        details_row = cursor.fetchone()
        if details_row:
            scan_dict["web_data"] = json.loads(details_row["web_data"] or "{}")
            scan_dict["ssl_data"] = json.loads(details_row["ssl_data"] or "{}")
            scan_dict["port_data"] = json.loads(details_row["port_data"] or "{}")
            scan_dict["dns_data"] = json.loads(details_row["dns_data"] or "{}")
        else:
            scan_dict["web_data"] = {}
            scan_dict["ssl_data"] = {}
            scan_dict["port_data"] = {}
            scan_dict["dns_data"] = {}

        return scan_dict


def get_all_scans(limit: int = 50, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Fetch recent scans list with summary data."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*,
                   COUNT(f.id) as finding_count
            FROM scans s
            LEFT JOIN findings f ON s.id = f.scan_id
            GROUP BY s.id
            ORDER BY s.created_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def delete_scan(scan_id: int, db_path: str = DB_PATH) -> bool:
    """Delete a scan by id (cascading findings and details)."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0


def get_dashboard_stats(db_path: str = DB_PATH) -> Dict[str, Any]:
    """Calculate and return operational statistics for the dashboard."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # Total scans
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        if total_scans == 0:
            return {
                "total_scans": 0,
                "low_risk_count": 0,
                "medium_risk_count": 0,
                "high_risk_count": 0,
                "critical_risk_count": 0,
                "average_risk_score": 0,
                "risk_distribution": [
                    {"name": "Low Risk", "value": 0, "color": "#10b981"},
                    {"name": "Medium Risk", "value": 0, "color": "#f59e0b"},
                    {"name": "High Risk", "value": 0, "color": "#f97316"},
                    {"name": "Critical Risk", "value": 0, "color": "#ef4444"}
                ],
                "latest_scan": None,
                "scan_history": [],
                "recent_activity": []
            }

        # Severity counts across all findings
        cursor.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
        severity_map = {row[0].upper(): row[1] for row in cursor.fetchall()}
        low_count = severity_map.get("LOW", 0)
        med_count = severity_map.get("MEDIUM", 0)
        high_count = severity_map.get("HIGH", 0)
        crit_count = severity_map.get("CRITICAL", 0)

        # Average risk score
        cursor.execute("SELECT AVG(risk_score) FROM scans WHERE status = 'COMPLETED'")
        avg_score_res = cursor.fetchone()[0]
        avg_score = round(avg_score_res, 1) if avg_score_res is not None else 0

        # Latest scan
        cursor.execute("SELECT id FROM scans ORDER BY created_at DESC LIMIT 1")
        latest_id_row = cursor.fetchone()
        latest_scan = get_scan(latest_id_row[0], db_path) if latest_id_row else None

        # Recent 10 scans for history chart
        cursor.execute("""
            SELECT id, target_url, hostname, risk_score, risk_level, created_at, status
            FROM scans
            WHERE status = 'COMPLETED'
            ORDER BY created_at ASC
            LIMIT 15
        """)
        scan_history = [
            {
                "id": row["id"],
                "target": row["hostname"] or row["target_url"],
                "score": row["risk_score"],
                "level": row["risk_level"],
                "date": row["created_at"][:10] if row["created_at"] else ""
            }
            for row in cursor.fetchall()
        ]

        # Recent activities
        cursor.execute("""
            SELECT id, target_url, hostname, risk_score, risk_level, created_at, status
            FROM scans
            ORDER BY created_at DESC
            LIMIT 5
        """)
        recent_activity = [dict(row) for row in cursor.fetchall()]

        return {
            "total_scans": total_scans,
            "low_risk_count": low_count,
            "medium_risk_count": med_count,
            "high_risk_count": high_count,
            "critical_risk_count": crit_count,
            "average_risk_score": avg_score,
            "risk_distribution": [
                {"name": "Low Risk", "value": low_count, "color": "#10b981"},
                {"name": "Medium Risk", "value": med_count, "color": "#f59e0b"},
                {"name": "High Risk", "value": high_count, "color": "#f97316"},
                {"name": "Critical Risk", "value": crit_count, "color": "#ef4444"}
            ],
            "latest_scan": latest_scan,
            "scan_history": scan_history,
            "recent_activity": recent_activity
        }


def get_settings(db_path: str = DB_PATH) -> Dict[str, str]:
    """Retrieve all current system settings."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM settings")
        return {row["key"]: row["value"] for row in cursor.fetchall()}


def update_settings(new_settings: Dict[str, str], db_path: str = DB_PATH) -> None:
    """Save or update system configuration."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        for k, v in new_settings.items():
            cursor.execute("""
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (str(k), str(v)))
        conn.commit()
