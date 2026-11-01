"""
RISK CHECKER — Local Demonstration Server
A lightweight, self-contained mock application designed for offline security audits
and local educational demonstration.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys


class VulnerableMockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "online", "mode": "lab_target"}')
            return

        if self.path == "/secure":
            # Hardened endpoint demo
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "geolocation=(), camera=()")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head><title>Hardened Target</title></head>
<body style="font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:40px;">
  <h1 style="color:#10b981;">Hardened Endpoint Baseline</h1>
  <p>This endpoint implements modern defense-in-depth security response headers.</p>
</body>
</html>""")
            return

        # Default root endpoint - Intentionally unhardened configuration for auditing
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Intentionally leaking server version banner
        self.send_header("Server", "DemoApp/1.0.4 (Ubuntu Linux)")
        self.send_header("X-Powered-By", "Express/4.17.1")
        # Intentionally insecure cookie lacking Secure and HttpOnly flags
        self.send_header("Set-Cookie", "session_id=demo_session_token_xyz; Path=/")
        # Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options
        self.end_headers()
        self.wfile.write(b"""<!DOCTYPE html>
<html>
<head><title>RISK CHECKER Demonstration Lab</title></head>
<body style="font-family:sans-serif;background:#090e1c;color:#e2e8f0;padding:40px;">
  <h1 style="color:#00f0ff;">Defensive Security Audit Target</h1>
  <p>This local demonstration server is intended for testing the RISK CHECKER scanner.</p>
  <ul>
    <li>Missing Content-Security-Policy (CSP)</li>
    <li>Missing HTTP Strict Transport Security (HSTS)</li>
    <li>Missing X-Frame-Options (Clickjacking defense)</li>
    <li>Missing X-Content-Type-Options (MIME sniffing defense)</li>
    <li>Server Banner Leaked in headers</li>
    <li>Insecure cookie set without Secure or HttpOnly flags</li>
  </ul>
</body>
</html>""")

    def log_message(self, format, *args):
        # Clean logging
        sys.stdout.write(f"[Local Lab Target] {self.address_string()} - {format % args}\n")


def run_demo_server(port=8080):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, VulnerableMockHandler)
    print(f"[*] RISK CHECKER Local Demonstration Lab Target running at http://127.0.0.1:{port}/")
    print(f"[*] Access /secure at http://127.0.0.1:{port}/secure for hardened baseline")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down local demonstration server...")
        httpd.server_close()


if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_demo_server(port)
