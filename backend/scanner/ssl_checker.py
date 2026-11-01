"""
SSL/TLS Certificate Analyzer for RISK CHECKER.
Inspects certificate validity, expiration, trust chain, SANs, ciphers, and protocols.
"""

import socket
import ssl
import datetime
from typing import Dict, List, Any, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def analyze_ssl_certificate(
    hostname: str,
    ip_address: str,
    port: int = 443,
    timeout: float = 6.0
) -> Dict[str, Any]:
    """
    Connects to the target server via TLS, downloads the certificate,
    and analyzes its validity, expiration, issuer, subject, SANs, and cipher.
    """
    findings: List[Dict[str, Any]] = []
    cert_info: Dict[str, Any] = {
        "has_ssl": False,
        "valid": False,
        "hostname_matched": False,
        "expired": False,
        "days_remaining": None,
        "issuer": {},
        "subject": {},
        "sans": [],
        "tls_version": None,
        "cipher": None,
        "signature_algorithm": None,
        "key_size": None,
        "serial_number": None,
        "valid_from": None,
        "valid_until": None,
        "findings": []
    }

    # Attempt standard verified context first
    context = ssl.create_default_context()
    verified = False
    verification_error = None

    try:
        with socket.create_connection((ip_address, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                verified = True
                tls_version = ssl_sock.version()
                cipher_info = ssl_sock.cipher()
                raw_der = ssl_sock.getpeercert(binary_form=True)
                peer_dict = ssl_sock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        verification_error = str(e)
        # Attempt unverified retrieval to extract details for forensic review
        unverified_context = ssl._create_unverified_context()
        try:
            with socket.create_connection((ip_address, port), timeout=timeout) as sock:
                with unverified_context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                    tls_version = ssl_sock.version()
                    cipher_info = ssl_sock.cipher()
                    raw_der = ssl_sock.getpeercert(binary_form=True)
                    peer_dict = ssl_sock.getpeercert()
        except Exception as unv_err:
            return {
                **cert_info,
                "error": f"TLS Handshake failed: {str(unv_err)}",
                "verification_error": verification_error,
                "findings": [{
                    "category": "SSL/TLS Security",
                    "title": "TLS Handshake Failed",
                    "severity": "HIGH",
                    "description": f"Could not establish a TLS handshake on port {port}: {str(unv_err)}",
                    "evidence": verification_error or str(unv_err),
                    "impact": "Clients will encounter connection warnings or be unable to connect securely.",
                    "recommendation": "Check web server TLS certificate configuration and port binding."
                }]
            }
    except (socket.timeout, socket.error, ConnectionRefusedError) as net_err:
        return {
            **cert_info,
            "error": f"Cannot connect to SSL/TLS service on port {port}: {str(net_err)}",
            "findings": [{
                "category": "SSL/TLS Security",
                "title": "SSL/TLS Service Unreachable",
                "severity": "HIGH",
                "description": f"Could not establish a TCP connection to {hostname}:{port}.",
                "evidence": str(net_err),
                "impact": "No secure HTTPS transport detected on standard port 443.",
                "recommendation": "Ensure an SSL certificate is installed and port 443 is open and routed."
            }]
        }
    except Exception as e:
        return {
            **cert_info,
            "error": f"Unexpected SSL inspection error: {str(e)}",
            "findings": []
        }

    # Certificate DER parsed via cryptography library
    try:
        cert_obj = x509.load_der_x509_certificate(raw_der, default_backend())
    except Exception as e:
        return {
            **cert_info,
            "error": f"Failed to parse X.509 certificate: {str(e)}"
        }

    cert_info["has_ssl"] = True
    cert_info["tls_version"] = tls_version
    cert_info["cipher"] = {
        "name": cipher_info[0] if cipher_info else None,
        "protocol": cipher_info[1] if cipher_info else None,
        "bits": cipher_info[2] if cipher_info else None
    }

    # Parse Subject and Issuer
    subject_dict = {}
    for attribute in cert_obj.subject:
        subject_dict[attribute.oid._name] = attribute.value
    cert_info["subject"] = subject_dict

    issuer_dict = {}
    for attribute in cert_obj.issuer:
        issuer_dict[attribute.oid._name] = attribute.value
    cert_info["issuer"] = issuer_dict

    # Serial number
    cert_info["serial_number"] = hex(cert_obj.serial_number)

    # Validity dates
    # Support newer cryptography attributes (not_valid_before_utc) with fallback
    try:
        valid_from = cert_obj.not_valid_before_utc
        valid_until = cert_obj.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
    except AttributeError:
        valid_from = cert_obj.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        valid_until = cert_obj.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)

    cert_info["valid_from"] = valid_from.isoformat()
    cert_info["valid_until"] = valid_until.isoformat()

    days_remaining = (valid_until - now).days
    cert_info["days_remaining"] = days_remaining

    # Subject Alternative Names (SANs)
    sans = []
    try:
        san_ext = cert_obj.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    cert_info["sans"] = sans

    # Hostname matching check
    hostname_matched = check_hostname_match(hostname, subject_dict.get("commonName"), sans)
    cert_info["hostname_matched"] = hostname_matched

    # Check key size
    try:
        pub_key = cert_obj.public_key()
        cert_info["key_size"] = getattr(pub_key, "key_size", None)
    except Exception:
        pass

    try:
        cert_info["signature_algorithm"] = cert_obj.signature_hash_algorithm.name if cert_obj.signature_hash_algorithm else None
    except Exception:
        pass

    # Findings generation based on certificate properties
    is_expired = now > valid_until
    is_not_yet_valid = now < valid_from
    cert_info["expired"] = is_expired

    if is_expired:
        findings.append({
            "category": "SSL/TLS Security",
            "title": "SSL/TLS Certificate Expired",
            "severity": "CRITICAL",
            "description": f"The SSL certificate for {hostname} expired on {valid_until.strftime('%Y-%m-%d')}.",
            "evidence": f"Expiration Date: {valid_until.isoformat()} ({abs(days_remaining)} days ago)",
            "impact": "Users visiting the site will see severe security warnings blocking site access.",
            "recommendation": "Renew and install a new SSL/TLS certificate immediately."
        })
    elif days_remaining <= 14:
        findings.append({
            "category": "SSL/TLS Security",
            "title": "SSL Certificate Expiring Imminently",
            "severity": "HIGH",
            "description": f"The SSL certificate expires in {days_remaining} days.",
            "evidence": f"Expires on {valid_until.strftime('%Y-%m-%d')} ({days_remaining} days left)",
            "impact": "Service disruption and trust warnings if not renewed before expiration.",
            "recommendation": "Initiate automated certificate renewal process (e.g. ACME / Let's Encrypt)."
        })
    elif days_remaining <= 30:
        findings.append({
            "category": "SSL/TLS Security",
            "title": "SSL Certificate Approaching Expiration",
            "severity": "MEDIUM",
            "description": f"The SSL certificate expires in {days_remaining} days.",
            "evidence": f"Expires on {valid_until.strftime('%Y-%m-%d')} ({days_remaining} days left)",
            "impact": "Failure to renew will cause browser validation errors.",
            "recommendation": "Schedule certificate renewal within the next 2 weeks."
        })

    if is_not_yet_valid:
        findings.append({
            "category": "SSL/TLS Security",
            "title": "Certificate Not Yet Valid",
            "severity": "HIGH",
            "description": f"The certificate validity period begins in the future ({valid_from.strftime('%Y-%m-%d')}).",
            "evidence": f"Valid from: {valid_from.isoformat()}",
            "impact": "Clients will reject the certificate due to date validation failure.",
            "recommendation": "Check the system clock or reissue the certificate with the correct start timestamp."
        })

    if not verified and verification_error:
        # Check self-signed or untrusted
        is_self_signed = subject_dict == issuer_dict
        findings.append({
            "category": "SSL/TLS Security",
            "title": "Untrusted or Self-Signed Certificate",
            "severity": "HIGH",
            "description": "The TLS certificate is not signed by a recognized Certificate Authority (CA).",
            "evidence": f"Verification error: {verification_error}. Self-signed: {is_self_signed}",
            "impact": "Browsers will display an 'Untrusted Certificate' warning to visitors.",
            "recommendation": "Deploy a certificate signed by a publicly trusted CA (e.g., Let's Encrypt, DigiCert)."
        })

    if not hostname_matched:
        findings.append({
            "category": "SSL/TLS Security",
            "title": "SSL Certificate Name Mismatch",
            "severity": "HIGH",
            "description": f"Target hostname '{hostname}' does not match Common Name '{subject_dict.get('commonName')}' or any Subject Alternative Names.",
            "evidence": f"Hostname: {hostname}, SANs: {sans}, CN: {subject_dict.get('commonName')}",
            "impact": "Browsers will flag the connection as invalid and potentially hijacked.",
            "recommendation": "Reissue certificate including '{hostname}' in the Subject Alternative Name (SAN) extension."
        })

    # Protocol version check
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        findings.append({
            "category": "SSL/TLS Security",
            "title": f"Deprecated TLS Protocol Version ({tls_version})",
            "severity": "HIGH",
            "description": f"The server negotiated {tls_version}, which is deprecated and contains known cryptographic flaws.",
            "evidence": f"Negotiated Protocol: {tls_version}",
            "impact": "Vulnerable to protocol downgrade attacks like POODLE, BEAST, or SWEET32.",
            "recommendation": "Disable TLS 1.0/1.1 on the server. Support only TLS 1.2 and TLS 1.3."
        })

    # Weak key size check (RSA < 2048)
    if cert_info.get("key_size") and cert_info["key_size"] < 2048:
        findings.append({
            "category": "SSL/TLS Security",
            "title": "Weak Public Key Length",
            "severity": "MEDIUM",
            "description": f"The certificate uses a public key length of {cert_info['key_size']} bits, below the 2048-bit modern minimum.",
            "evidence": f"Key size: {cert_info['key_size']} bits",
            "impact": "Subject to mathematical factoring attacks with sufficient computing power.",
            "recommendation": "Reissue the certificate with an RSA key of at least 2048 bits (or ECDSA with P-256/P-384)."
        })

    cert_info["valid"] = verified and (not is_expired) and (not is_not_yet_valid) and hostname_matched
    cert_info["findings"] = findings
    return cert_info


def check_hostname_match(target_host: str, cn: Optional[str], sans: List[str]) -> bool:
    """Check if target hostname matches CN or SANs, supporting wildcard syntax (*.domain.com)."""
    target = target_host.lower().strip()
    candidates = [cn.lower().strip()] if cn else []
    for s in sans:
        candidates.append(s.lower().strip())

    for c in candidates:
        if c == target:
            return True
        # Wildcard match (e.g. *.example.com matches sub.example.com)
        if c.startswith("*."):
            suffix = c[1:]  # .example.com
            if target.endswith(suffix) and target.count(".") == c.count("."):
                return True
    return False
