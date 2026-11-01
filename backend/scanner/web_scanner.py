"""
Website Security Scanner for RISK CHECKER.
Analyzes HTTPS enforcement, security headers, cookie attributes, redirect chains,
and server banner leakage.
"""

from typing import Dict, List, Any, Optional
import urllib.parse
import requests
from backend.scanner.validator import safe_fetch_url


# Target security headers to inspect
SECURITY_HEADERS_SPEC = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "category": "Transport Security",
        "description": "HTTP Strict Transport Security (HSTS) instructs browsers to only connect via HTTPS, mitigating SSL-stripping and man-in-the-middle attacks.",
        "impact": "Without HSTS, initial unencrypted connections may be intercepted or downgraded by network attackers.",
        "recommendation": "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' on HTTPS responses.",
        "validator": lambda val: "max-age" in val.lower()
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "category": "Injection Prevention",
        "description": "Content Security Policy (CSP) restricts the sources from which scripts, styles, images, and other resources can be loaded.",
        "impact": "Increases susceptibility to Cross-Site Scripting (XSS), data injection, and clickjacking attacks.",
        "recommendation": "Deploy a robust Content-Security-Policy header defining trusted script, style, and object sources.",
        "validator": lambda val: len(val.strip()) > 5
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "category": "MIME Sniffing",
        "description": "X-Content-Type-Options prevents browsers from MIME-sniffing a response away from the declared Content-Type.",
        "impact": "User-uploaded files disguised as images or text could be interpreted as executable HTML/JavaScript.",
        "recommendation": "Add the header 'X-Content-Type-Options: nosniff'.",
        "validator": lambda val: val.strip().lower() == "nosniff"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "category": "Clickjacking",
        "description": "X-Frame-Options dictates whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed>, or <object>.",
        "impact": "Pages lacking frame protection may be embedded by malicious third parties to execute UI redressing / clickjacking attacks.",
        "recommendation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP's 'frame-ancestors' directive.",
        "validator": lambda val: val.strip().upper() in ("DENY", "SAMEORIGIN")
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "category": "Information Disclosure",
        "description": "Referrer-Policy governs how much referrer information (URL paths, sensitive query tokens) is sent along with requests.",
        "impact": "Sensitive paths or parameter tokens may leak to third-party endpoints through the Referer header.",
        "recommendation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
        "validator": lambda val: val.strip().lower() in ("strict-origin-when-cross-origin", "no-referrer", "same-origin", "origin-when-cross-origin")
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "category": "Device Feature Security",
        "description": "Permissions-Policy allows site operators to selectively enable, disable, and modify browser features and APIs (geolocation, camera, microphone).",
        "impact": "Unrestricted browser features may be leveraged by embedded third-party scripts or iframes.",
        "recommendation": "Define a Permissions-Policy header restricting sensitive APIs (e.g., 'geolocation=(), camera=(), microphone=()').",
        "validator": lambda val: len(val.strip()) > 0
    }
}


def analyze_website_security(
    target_info: Dict[str, Any],
    allow_local: bool = False,
    timeout: float = 8.0
) -> Dict[str, Any]:
    """
    Executes a comprehensive defensive security audit of web configuration:
    - HTTP to HTTPS redirection check
    - Security headers check
    - Server information leakage
    - Cookie security flags
    - Safe redirect tracking
    """
    hostname = target_info["hostname"]
    normalized_url = target_info["normalized_url"]
    port = target_info.get("port")
    path = target_info.get("path", "/")
    scheme = target_info.get("scheme", "https")
    findings: List[Dict[str, Any]] = []

    if port and port not in (80, 443):
        if scheme == "http":
            http_url = f"http://{hostname}:{port}{path}"
            https_url = f"https://{hostname}/"
        else:
            https_url = f"https://{hostname}:{port}{path}"
            http_url = f"http://{hostname}/"
    else:
        https_url = f"https://{hostname}{path}"
        http_url = f"http://{hostname}{path}"

    # 1. Test HTTPS Connection
    https_success, https_err, https_resp, https_history = safe_fetch_url(
        https_url, allow_local=allow_local, timeout=timeout
    )

    # 2. Test HTTP to HTTPS redirection
    http_success, http_err, http_resp, http_history = safe_fetch_url(
        http_url, allow_local=allow_local, timeout=timeout
    )

    http_redirects_to_https = False
    if http_history and len(http_history) > 1:
        final_url = http_history[-1]["url"]
        if final_url.startswith("https://"):
            http_redirects_to_https = True
    elif http_resp and http_resp.url.startswith("https://"):
        http_redirects_to_https = True

    if not http_redirects_to_https:
        findings.append({
            "category": "Transport Security",
            "title": "Unenforced HTTPS Redirection",
            "severity": "HIGH",
            "description": "The web server does not automatically redirect unencrypted plaintext HTTP traffic to secure HTTPS.",
            "evidence": f"HTTP request to {http_url} did not enforce redirection to HTTPS. History: {[h.get('url') for h in http_history]}",
            "impact": "Users visiting via plain HTTP are vulnerable to active network interception, eavesdropping, and SSL stripping.",
            "recommendation": "Configure a permanent 301/308 redirect from HTTP (port 80) to HTTPS (port 443)."
        })

    # Pick the best response for header inspection (prefer HTTPS response if successful, else HTTP)
    active_resp = https_resp if (https_success and https_resp) else http_resp
    raw_headers = dict(active_resp.headers) if active_resp else {}
    status_code = active_resp.status_code if active_resp else None

    # Case-insensitive header dictionary
    headers_lower = {k.lower(): (k, v) for k, v in raw_headers.items()}

    # 3. Security Headers Evaluation
    headers_report = {}
    for header_name, spec in SECURITY_HEADERS_SPEC.items():
        h_key = header_name.lower()
        if h_key in headers_lower:
            orig_name, val = headers_lower[h_key]
            is_valid = spec["validator"](val)
            headers_report[header_name] = {
                "present": True,
                "value": val,
                "status": "PASS" if is_valid else "WARNING",
                "severity": spec["severity"]
            }
            if not is_valid:
                findings.append({
                    "category": spec["category"],
                    "title": f"Suboptimal {header_name} Configuration",
                    "severity": "LOW",
                    "description": f"The '{header_name}' header is present but does not meet standard hardening recommendations.",
                    "evidence": f"Header value: '{val}'",
                    "impact": spec["impact"],
                    "recommendation": spec["recommendation"]
                })
        else:
            headers_report[header_name] = {
                "present": False,
                "value": None,
                "status": "FAIL",
                "severity": spec["severity"]
            }
            findings.append({
                "category": spec["category"],
                "title": f"Missing {header_name} Header",
                "severity": spec["severity"],
                "description": spec["description"] + " (Note: Missing headers are configuration findings and do not automatically prove vulnerability).",
                "evidence": f"Header '{header_name}' was not detected in server response.",
                "impact": spec["impact"],
                "recommendation": spec["recommendation"]
            })

    # 4. Information Disclosure / Server Banners
    server_banner = raw_headers.get("Server") or raw_headers.get("server")
    powered_by = raw_headers.get("X-Powered-By") or raw_headers.get("x-powered-by")
    aspnet_version = raw_headers.get("X-AspNet-Version") or raw_headers.get("x-aspnet-version")

    info_disclosure = {}
    if server_banner:
        info_disclosure["server"] = server_banner
        # Check if version is leaked (e.g. Apache/2.4.41, nginx/1.18.0)
        if any(c.isdigit() for c in server_banner):
            findings.append({
                "category": "Information Disclosure",
                "title": "Web Server Version Banner Leaked",
                "severity": "LOW",
                "description": "The 'Server' response header exposes the underlying server software and exact version number.",
                "evidence": f"Server: {server_banner}",
                "impact": "Facilitates target profiling and CVE enumeration by malicious actors.",
                "recommendation": "Configure ServerTokens Prod (Apache), server_tokens off (Nginx), or strip the Server header."
            })

    if powered_by:
        info_disclosure["x_powered_by"] = powered_by
        findings.append({
            "category": "Information Disclosure",
            "title": "Technology Stack Disclosure (X-Powered-By)",
            "severity": "LOW",
            "description": "The 'X-Powered-By' header reveals the backend framework or runtime environment.",
            "evidence": f"X-Powered-By: {powered_by}",
            "impact": "Assists attackers in targeting technology-specific weaknesses.",
            "recommendation": "Disable the X-Powered-By header in application or framework configuration."
        })

    # 5. Cookie Security Checks
    cookies_analysis = []
    if active_resp and active_resp.cookies:
        for cookie in active_resp.cookies:
            c_secure = cookie.secure
            c_httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")
            # SameSite attribute check
            same_site = cookie._rest.get("SameSite") or cookie._rest.get("samesite")

            cookie_record = {
                "name": cookie.name,
                "secure": c_secure,
                "httponly": c_httponly,
                "samesite": same_site or "Not Set",
                "path": cookie.path,
                "domain": cookie.domain
            }
            cookies_analysis.append(cookie_record)

            if not c_secure:
                findings.append({
                    "category": "Cookie Security",
                    "title": f"Insecure Cookie Flag: '{cookie.name}' Missing Secure Attribute",
                    "severity": "MEDIUM",
                    "description": "A cookie was set without the 'Secure' attribute, meaning it could be transmitted over unencrypted HTTP.",
                    "evidence": f"Cookie '{cookie.name}' lacks Secure flag.",
                    "impact": "Susceptible to interception via network eavesdropping on plain HTTP channels.",
                    "recommendation": "Append the '; Secure' flag to all sensitive cookies."
                })

            if not c_httponly:
                findings.append({
                    "category": "Cookie Security",
                    "title": f"Cookie '{cookie.name}' Missing HttpOnly Flag",
                    "severity": "LOW",
                    "description": "A cookie was set without the 'HttpOnly' flag, allowing client-side scripts to access it.",
                    "evidence": f"Cookie '{cookie.name}' lacks HttpOnly flag.",
                    "impact": "In the event of an XSS flaw, an attacker could steal this cookie via document.cookie.",
                    "recommendation": "Set '; HttpOnly' on session identifiers and authentication tokens."
                })

    return {
        "https_supported": https_success,
        "https_error": https_err,
        "http_redirects_to_https": http_redirects_to_https,
        "status_code": status_code,
        "headers_inspected": headers_report,
        "raw_headers": raw_headers,
        "info_disclosure": info_disclosure,
        "cookies": cookies_analysis,
        "redirect_chain": https_history if https_history else http_history,
        "findings": findings
    }
