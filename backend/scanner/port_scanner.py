"""
TCP Port Analyzer for RISK CHECKER.
Performs connection-based checks on a small, predefined list of common service ports
strictly for authorized targets.
"""

import socket
import time
from typing import Dict, List, Any


# Standard predefined safe ports list
SAFE_PORT_CATALOG = [
    {
        "port": 21,
        "service": "FTP",
        "protocol": "TCP",
        "description": "File Transfer Protocol (Cleartext authentication and data transfer).",
        "exposure_risk": "MEDIUM",
        "exposure_note": "FTP transmits credentials and file data in cleartext unless FTPS/SFTP is enforced. Public exposure is rarely necessary."
    },
    {
        "port": 22,
        "service": "SSH",
        "protocol": "TCP",
        "description": "Secure Shell Remote Administration.",
        "exposure_risk": "LOW",
        "exposure_note": "Standard administrative service. Ensure password logins are disabled in favor of cryptographic keys, and rate-limit connection attempts."
    },
    {
        "port": 25,
        "service": "SMTP",
        "protocol": "TCP",
        "description": "Simple Mail Transfer Protocol.",
        "exposure_risk": "LOW",
        "exposure_note": "Standard mail exchange port. Verify the server is not operating as an open relay for spam transmission."
    },
    {
        "port": 53,
        "service": "DNS",
        "protocol": "TCP",
        "description": "Domain Name System (Zone transfers and large responses).",
        "exposure_risk": "LOW",
        "exposure_note": "Ensure unauthorized zone transfers (AXFR) are restricted to authorized secondary nameservers."
    },
    {
        "port": 80,
        "service": "HTTP",
        "protocol": "TCP",
        "description": "Hypertext Transfer Protocol (Unencrypted Web).",
        "exposure_risk": "LOW",
        "exposure_note": "Standard web port. Typically used to redirect users to encrypted HTTPS (port 443)."
    },
    {
        "port": 110,
        "service": "POP3",
        "protocol": "TCP",
        "description": "Post Office Protocol v3 (Cleartext mail retrieval).",
        "exposure_risk": "MEDIUM",
        "exposure_note": "Legacy unencrypted mail service. Consider migrating to POP3S (port 995) or modern OAuth2 solutions."
    },
    {
        "port": 143,
        "service": "IMAP",
        "protocol": "TCP",
        "description": "Internet Message Access Protocol (Cleartext mail sync).",
        "exposure_risk": "MEDIUM",
        "exposure_note": "Legacy unencrypted mail access. Consider migrating to IMAPS (port 993)."
    },
    {
        "port": 443,
        "service": "HTTPS",
        "protocol": "TCP",
        "description": "HTTP Secure (Encrypted Web).",
        "exposure_risk": "LOW",
        "exposure_note": "Standard secure web application entry point. Primary channel for TLS-encrypted web traffic."
    },
    {
        "port": 3306,
        "service": "MySQL",
        "protocol": "TCP",
        "description": "MySQL Database Server.",
        "exposure_risk": "HIGH",
        "exposure_note": "Database ports should generally remain internal within a private VPC or behind a VPN, not directly accessible from the public internet."
    },
    {
        "port": 3389,
        "service": "RDP",
        "protocol": "TCP",
        "description": "Microsoft Remote Desktop Protocol.",
        "exposure_risk": "HIGH",
        "exposure_note": "RDP exposed to the public internet is heavily targeted by credential stuffing, brute-force, and ransomware groups. Protect behind a VPN or MFA gateway."
    },
    {
        "port": 5432,
        "service": "PostgreSQL",
        "protocol": "TCP",
        "description": "PostgreSQL Database Server.",
        "exposure_risk": "HIGH",
        "exposure_note": "Database listener. Direct public exposure creates unnecessary attack surface for credential attacks or database vulnerabilities."
    },
    {
        "port": 8080,
        "service": "HTTP-Alt / Proxy",
        "protocol": "TCP",
        "description": "Alternative Web Server / Admin Interface / Proxy.",
        "exposure_risk": "LOW",
        "exposure_note": "Often used for administrative consoles, Jenkins, Tomcat, or development previews. Verify access controls."
    },
    {
        "port": 8443,
        "service": "HTTPS-Alt",
        "protocol": "TCP",
        "description": "Alternative SSL/TLS Web Service.",
        "exposure_risk": "LOW",
        "exposure_note": "Often used for management consoles or secondary microservices. Ensure proper TLS configuration."
    }
]


def check_port_connect(
    ip_address: str,
    port: int,
    timeout: float = 1.2
) -> str:
    """
    Performs a standard non-stealth TCP 3-way handshake connect attempt.
    Returns: 'OPEN', 'CLOSED', or 'TIMEOUT'
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            return "OPEN"
        else:
            return "CLOSED"
    except socket.timeout:
        return "TIMEOUT"
    except socket.error:
        return "CLOSED"
    finally:
        sock.close()


def scan_authorized_ports(
    ip_address: str,
    hostname: str,
    is_authorized: bool = False,
    timeout_per_port: float = 1.0,
    delay_between_ports: float = 0.05
) -> Dict[str, Any]:
    """
    Analyzes accessibility of predefined safe common ports.
    Requires explicit authorization confirmation.
    Does not attempt exploitation or banner manipulation.
    """
    if not is_authorized:
        return {
            "authorized": False,
            "error": "Scan halted: Explicit user authorization confirmation is required before scanning TCP ports.",
            "ports": [],
            "open_count": 0,
            "findings": []
        }

    port_results = []
    findings = []
    open_count = 0

    for port_def in SAFE_PORT_CATALOG:
        port_num = port_def["port"]
        status = check_port_connect(ip_address, port_num, timeout=timeout_per_port)

        port_entry = {
            "port": port_num,
            "service": port_def["service"],
            "protocol": port_def["protocol"],
            "status": status,
            "description": port_def["description"],
            "exposure_note": port_def["exposure_note"],
            "exposure_risk": port_def["exposure_risk"]
        }
        port_results.append(port_entry)

        if status == "OPEN":
            open_count += 1
            # Generate finding for exposed sensitive services (Databases, RDP, cleartext protocols)
            if port_def["exposure_risk"] in ("HIGH", "MEDIUM"):
                findings.append({
                    "category": "Port & Service Exposure",
                    "title": f"Exposed {port_def['service']} Service (Port {port_num})",
                    "severity": port_def["exposure_risk"],
                    "description": f"Port {port_num} ({port_def['service']}) was found accessible. (Note: An open port does not automatically indicate vulnerability, but indicates service accessibility).",
                    "evidence": f"TCP port {port_num} accepted connections on {ip_address}.",
                    "impact": port_def["exposure_note"],
                    "recommendation": f"Restrict access to port {port_num} using host firewalls or security groups unless public access is strictly required."
                })

        time.sleep(delay_between_ports)

    return {
        "authorized": True,
        "ports": port_results,
        "total_checked": len(port_results),
        "open_count": open_count,
        "findings": findings
    }
