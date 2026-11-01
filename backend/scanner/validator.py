"""
Security and target validator module for RISK CHECKER.
Enforces strict SSRF protections, URL validation, and safe redirect following.
"""

import socket
import ipaddress
import urllib.parse
from typing import Tuple, List, Optional, Dict, Any
import requests


# Known cloud metadata addresses
CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, GCP, Azure, DigitalOcean, OpenStack
    "100.100.100.200",   # Alibaba Cloud
    "192.0.0.192",       # Oracle Cloud
}

ALLOWED_SCHEMES = {"http", "https"}


def parse_and_validate_target(
    url_or_host: str,
    allow_local: bool = False
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """
    Validates a target input string.
    Ensures URL formatting, validates scheme, resolves DNS,
    and applies strict SSRF checks against private/cloud metadata ranges.

    Returns:
        (is_valid, error_message, target_info)
    """
    if not url_or_host or not isinstance(url_or_host, str):
        return False, "Target URL or hostname cannot be empty.", None

    raw_target = url_or_host.strip()
    
    # Auto-prepend https:// only if no URI scheme delimiter ("://") exists
    if "://" not in raw_target:
        raw_target = "https://" + raw_target

    try:
        parsed = urllib.parse.urlsplit(raw_target)
    except Exception as e:
        return False, f"Invalid URL structure: {str(e)}", None

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "Target contains no valid hostname.", None

    # Block credentials in URL (e.g. user:pass@host)
    if parsed.username or parsed.password:
        return False, "Target must not contain user credentials in the URL.", None

    # Port validation if specified
    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        return False, f"Invalid port number: {port}", None

    # Perform DNS Resolution
    dns_valid, dns_err, ip_addresses = resolve_host_ips(hostname)
    if not dns_valid or not ip_addresses:
        return False, f"DNS resolution failed for '{hostname}': {dns_err}", None

    # SSRF Protection Check
    for ip_str in ip_addresses:
        is_safe, reason = is_ip_safe(ip_str, allow_local=allow_local)
        if not is_safe:
            return False, f"SSRF Protection: Access to resolved IP {ip_str} ({hostname}) is blocked. Reason: {reason}", None

    primary_ip = ip_addresses[0]

    normalized_url = urllib.parse.urlunsplit((
        scheme,
        f"{hostname}:{port}" if port else hostname,
        parsed.path or "/",
        parsed.query,
        ""
    ))

    target_info = {
        "original_input": url_or_host,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "hostname": hostname,
        "port": port or (443 if scheme == "https" else 80),
        "primary_ip": primary_ip,
        "all_ips": ip_addresses,
        "path": parsed.path or "/"
    }

    return True, None, target_info


def resolve_host_ips(hostname: str) -> Tuple[bool, Optional[str], List[str]]:
    """Resolve all IPv4 and IPv6 addresses for a hostname."""
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        ips = []
        for item in addr_info:
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
        if not ips:
            return False, "No IP addresses resolved", []
        return True, None, ips
    except socket.gaierror as e:
        return False, str(e), []
    except Exception as e:
        return False, str(e), []


def is_ip_safe(ip_str: str, allow_local: bool = False) -> Tuple[bool, str]:
    """
    Verifies that the IP address does not target private, link-local, loopback,
    multicast, or cloud metadata endpoints.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "Invalid IP address representation"

    # Cloud metadata check
    if str(ip_obj) in CLOUD_METADATA_IPS:
        return False, "Cloud metadata service access prohibited"

    # Handle IPv6-mapped IPv4
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.is_loopback:
        if allow_local:
            return True, "Loopback allowed by development override"
        return False, "Loopback addresses (127.0.0.0/8, ::1) are blocked"

    if ip_obj.is_private:
        if allow_local:
            return True, "Private subnet allowed by development override"
        return False, "Private RFC1918 / unique-local networks are blocked"

    if ip_obj.is_link_local:
        return False, "Link-local addresses (169.254.0.0/16, fe80::/10) are blocked"

    if ip_obj.is_multicast:
        return False, "Multicast addresses are blocked"

    if ip_obj.is_reserved:
        return False, "Reserved IETF IP range blocked"

    if ip_obj.is_unspecified:
        return False, "Unspecified addresses (0.0.0.0, ::) are blocked"

    return True, "Safe public IP"


def safe_fetch_url(
    url: str,
    allow_local: bool = False,
    timeout: float = 8.0,
    max_redirects: int = 5,
    max_bytes: int = 2 * 1024 * 1024  # 2MB
) -> Tuple[bool, Optional[str], Optional[requests.Response], List[Dict[str, Any]]]:
    """
    Performs a safe HTTP request with manual redirect following.
    Re-validates each redirect hop against SSRF rules to prevent DNS rebinding
    and open-redirect attacks into internal infrastructure.

    Returns:
        (success, error_message, final_response, redirect_history)
    """
    current_url = url
    redirect_history = []
    session = requests.Session()
    # Custom User-Agent identifying the security tool
    session.headers.update({
        "User-Agent": "RiskChecker-SecurityBot/1.0 (+https://github.com/security/risk-checker)",
        "Accept": "*/*"
    })

    for hop in range(max_redirects + 1):
        is_valid, err, target_info = parse_and_validate_target(current_url, allow_local=allow_local)
        if not is_valid or not target_info:
            return False, f"Redirect to unsafe destination blocked: {err}", None, redirect_history

        try:
            resp = session.get(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                stream=True,
                verify=True
            )

            # Read response body within size cap
            content = bytearray()
            for chunk in resp.iter_content(chunk_size=8192):
                content.extend(chunk)
                if len(content) > max_bytes:
                    resp.close()
                    break
            
            # Record hop in history
            hop_record = {
                "hop": hop,
                "url": current_url,
                "status_code": resp.status_code,
                "ip": target_info["primary_ip"],
                "headers": dict(resp.headers)
            }
            redirect_history.append(hop_record)

            # Check if this is a redirect status
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    # Missing location header, terminate
                    return True, None, resp, redirect_history

                # Resolve relative redirects
                next_url = urllib.parse.urljoin(current_url, location)
                current_url = next_url
                continue
            else:
                # Terminal response reached
                return True, None, resp, redirect_history

        except requests.exceptions.SSLError as ssl_err:
            # We still want to report SSL errors back gracefully
            return False, f"SSL/TLS Connection Error: {str(ssl_err)}", None, redirect_history
        except requests.exceptions.Timeout:
            return False, f"Request timed out after {timeout} seconds", None, redirect_history
        except requests.exceptions.ConnectionError as conn_err:
            return False, f"Connection failed: {str(conn_err)}", None, redirect_history
        except Exception as e:
            return False, f"HTTP request failed: {str(e)}", None, redirect_history

    return False, f"Maximum redirect depth of {max_redirects} exceeded", None, redirect_history
