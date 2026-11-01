# RISK CHECKER — Intelligent Cybersecurity Risk Assessment Platform

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-black.svg)](https://flask.palletsprojects.com/)
[![React](https://img.shields.io/badge/React-18.3-cyan.svg)](https://react.dev/)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-3.4-38bdf8.svg)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Security Auditing](https://img.shields.io/badge/Auditing-Defensive%20Configuration-emerald.svg)]()

> **RISK CHECKER** is an enterprise-grade defensive cybersecurity web application designed to evaluate the security configuration posture of authorized websites, web servers, and network infrastructure.

---

## 🛡️ Core Capabilities

### 1. Website Security Scanner
- **HTTPS Enforcement**: Verifies transport encryption and permanent redirection from plaintext HTTP (port 80) to secure HTTPS (port 443).
- **Security Headers Inspection**:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (Clickjacking defense)
  - `X-Content-Type-Options` (MIME sniffing prevention)
  - `Referrer-Policy` (Information leakage mitigation)
  - `Permissions-Policy` (Hardware API restrictions)
- **Cookie Security Analysis**: Validates `Secure`, `HttpOnly`, and `SameSite` flags on all server-issued cookies.
- **Banner Information Disclosure**: Identifies version leakage in `Server` and `X-Powered-By` response headers.
- **Defensive Clarification**: Explicitly notes that missing headers are configuration gaps and do not automatically prove vulnerability.

### 2. SSL/TLS Certificate Analyzer
- **Validity & Expiration**: Tracks `notBefore` and `notAfter` dates with a countdown bar and warnings at ≤30 days and ≤14 days.
- **Chain of Trust & Verification**: Validates certificate against system trust stores and distinguishes self-signed or untrusted issuers.
- **Identity & SANs**: Inspects Common Name (CN), Organization (O), and Subject Alternative Names (SANs) with wildcard matching support.
- **Cryptographic Strength**: Measures public key length (flagging RSA < 2048 bits), signature algorithm (SHA-256), negotiated TLS version (TLS 1.2 / TLS 1.3), and negotiated cipher suites.

### 3. Authorized TCP Port Security Checker
- **Predefined Safe Service Ports**: Connection-based TCP checks on safe common ports:
  - `21` (FTP), `22` (SSH), `25` (SMTP), `53` (DNS), `80` (HTTP), `110` (POP3), `143` (IMAP), `443` (HTTPS), `3306` (MySQL), `3389` (RDP), `5432` (PostgreSQL), `8080` (HTTP-Alt), `8443` (HTTPS-Alt).
- **Strictly Authorized**: Requires explicit user authorization confirmation before executing.
- **Defensive Non-Stealth**: Standard 3-way handshake connect calls without stealth manipulation or exploit attempts.
- **Clear Guidance**: Notes that open ports indicate service accessibility, not automatic compromise.

### 4. IP & DNS Information
- Hostname extraction and IPv4 / IPv6 resolution.
- Resolves multiple IP endpoints and displays addressing version.

### 5. Transparent Rule-Based Risk Engine (0–100 Scale)
- **Risk Tiers**:
  - `0 – 19`: **LOW RISK** (Favorable configuration posture)
  - `20 – 39`: **MEDIUM RISK** (Moderate exposure or missing defense-in-depth)
  - `40 – 69`: **HIGH RISK** (Significant configuration gaps found)
  - `70 – 100`: **CRITICAL RISK** (Severe exposure requiring emergency mitigation)
- **Scoring Methodology**:
  - `CRITICAL`: +35 points
  - `HIGH`: +20 points
  - `MEDIUM`: +10 points
  - `LOW`: +4 points
- **Category Capping & Deduplication**: Maximum point caps per domain (e.g. SSL/TLS cap 45, Transport cap 35) prevent single-issue inflation. Duplicate findings collapse to the highest severity.

### 6. SOC Cyber Dashboard & Visualizations
- Dark navy (`#070b14`) and electric blue/cyan theme inspired by modern Security Operations Center interfaces.
- Animated circular SVG Risk Meter gauge.
- Real stored scan metrics (clean empty state when no scans exist).
- Recharts Donut Chart for severity distribution.
- Recharts Line Chart for historical risk trends.
- Filterable and searchable Security Findings table with collapsible evidence and recommendations.

### 7. SQLite Audit Database
- Stores complete scan logs, findings, raw module payloads, and settings.
- Parameterized queries to eliminate SQL injection risks.
- Cascading deletes and automatic schema initialization.

### 8. Downloadable PDF Security Reports (ReportLab)
- Automated generation of executive security deliverables suitable for academic demonstration and C-suite review.
- Contains RISK CHECKER branding, executive summary, score badges, detailed findings, evidence blocks, and scope limitations.

### 9. Server-Side Request Forgery (SSRF) Protection
- Rejects loopback (`127.0.0.0/8`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and link-local (`169.254.0.0/16`) addresses by default.
- Permanently blocks cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`).
- Validates every individual redirect hop against SSRF rules to prevent DNS rebinding and open redirect pivots.
- Optional explicit development toggle in Settings to permit localhost lab auditing.

### 10. Local Demonstration Lab Target
- Built-in `test_server.py` mock application providing an offline target for safe testing and grading without external internet dependencies.

---

## 🗂️ Project Structure

```
RISK_CHECKER/
├── backend/
│   ├── app.py                     # Flask REST API server & static frontend serving
│   ├── requirements.txt           # Python dependency specifications
│   ├── database/
│   │   └── db.py                  # SQLite schema, connection pool & queries
│   ├── scanner/
│   │   ├── validator.py           # SSRF protection, DNS resolver & safe redirect client
│   │   ├── web_scanner.py         # HTTP security headers, HTTPS redirect & cookie checks
│   │   ├── ssl_checker.py         # SSL/TLS certificate, cipher & validity inspector
│   │   ├── port_scanner.py        # Authorized TCP connection audit
│   │   └── risk_calculator.py     # Rule-based 0-100 risk scoring engine
│   ├── reports/
│   │   └── pdf_generator.py       # ReportLab PDF executive report builder
│   └── tests/
│       ├── test_scanner.py         # Comprehensive unit test suite (13 tests)
│       └── test_local_demo_scan.py# End-to-end integration test (lab pipeline + PDF)
├── frontend/
│   ├── package.json               # Node.js project & dependencies
│   ├── vite.config.js             # Vite config with API proxy
│   ├── tailwind.config.js         # Cyber dark theme color extensions
│   ├── postcss.config.js          # PostCSS configuration
│   ├── index.html                 # HTML entry point
│   └── src/
│       ├── main.jsx               # React DOM root
│       ├── App.jsx                # Application shell & state manager
│       ├── index.css              # Custom styling, scrollbars & glow effects
│       ├── services/
│       │   └── api.js             # Axios API client functions
│       ├── components/
│       │   ├── Sidebar.jsx        # 9-item functional navigation sidebar
│       │   ├── RiskMeter.jsx      # Animated SVG circular gauge
│       │   └── FindingsTable.jsx  # Searchable & filterable findings accordion
│       └── pages/
│           ├── Dashboard.jsx      # Executive SOC overview with charts
│           ├── NewScan.jsx        # Scanner console with multi-stage progress
│           ├── WebsiteSecurity.jsx# Headers, HTTPS & cookies analysis
│           ├── SslAnalysis.jsx    # Certificate, cipher & expiration analysis
│           ├── PortAnalysis.jsx   # Authorized common port audit table
│           ├── RiskAssessment.jsx # Risk score details & methodology
│           ├── ScanHistory.jsx    # SQLite historical audits table
│           ├── SecurityReports.jsx# PDF report download center
│           └── SettingsPage.jsx   # Timeouts, lab mode & branding settings
├── reports/                       # Generated PDF assessment files
├── test_server.py                 # Offline mock lab server for demonstrations
├── run_backend.ps1                # PowerShell script: launch backend API
├── run_frontend.ps1               # PowerShell script: launch Vite frontend
├── run_all.ps1                    # PowerShell script: launch single-server app
├── run_local_demo.ps1             # PowerShell script: launch mock lab target
└── README.md                      # Comprehensive documentation
```

---

## 🚀 Windows Installation & Execution Guide

### Prerequisites
- **Windows 10 / 11**
- **Python 3.10+** (Python 3.12 installed)
- **Node.js 18+** (Node.js 24 LTS installed)

---

### Step 1: Install Dependencies

#### Python Backend Dependencies:
Open PowerShell in the project directory:
```powershell
python -m pip install -r backend/requirements.txt
```

#### React Frontend Dependencies:
```powershell
cd frontend
npm install
npm run build
cd ..
```

---

### Step 2: Running the Application

You can run RISK CHECKER in **Single-Process Production Mode** (recommended) or in **Dual-Process Development Mode**:

#### Option A: Single-Process Mode (Fastest)
The Flask backend automatically serves both the REST API and the production-built React frontend:
```powershell
python backend/app.py
```
Or execute:
```powershell
.\run_all.ps1
```
Open your browser at **[http://127.0.0.1:5000](http://127.0.0.1:5000)**.

---

#### Option B: Dual-Process Development Mode (Hot Reloading)

1. **Terminal 1 — Backend:**
   ```powershell
   .\run_backend.ps1
   ```
   Backend runs at `http://127.0.0.1:5000`.

2. **Terminal 2 — Frontend (Vite Dev Server):**
   ```powershell
   .\run_frontend.ps1
   ```
   Vite runs at `http://127.0.0.1:5173` with instant hot-reloading and proxies all `/api` calls to the backend.

---

### Step 3: Running the Offline Demonstration Lab

To test the complete auditing pipeline locally without connecting to public websites:

1. **Start the local demonstration target server:**
   ```powershell
   .\run_local_demo.ps1
   ```
   This starts the mock target at `http://127.0.0.1:8080`.

2. **In RISK CHECKER:**
   - Go to **Settings** in the sidebar.
   - Check **"Permit Localhost & Private Subnet Lab Scans"** and click **Save Configuration**.
   - Go to **New Security Scan**, enter `http://127.0.0.1:8080`, check the authorization box, and click **Start Defensive Risk Assessment**.
   - View the detected findings (Missing CSP, Missing HSTS, Leaked Server Banner, Insecure Cookies, Port Status), explore the score, and click **Download PDF Report**.

---

## 🧪 Automated Testing

Automated tests validate URL validation, SSRF filtering, header parsing, risk scoring, database persistence, and PDF creation without external network dependencies:

Run all tests via pytest:
```powershell
python -m pytest backend/tests/ -v
```

Expected output:
```
backend/tests/test_local_demo_scan.py::test_full_pipeline_local_lab PASSED
backend/tests/test_scanner.py::test_ssrf_blocks_private_ips PASSED
backend/tests/test_scanner.py::test_ssrf_allow_local_flag PASSED
backend/tests/test_scanner.py::test_public_ips_allowed PASSED
backend/tests/test_scanner.py::test_invalid_urls_rejected PASSED
backend/tests/test_scanner.py::test_risk_level_classification PASSED
backend/tests/test_scanner.py::test_deduplicate_findings PASSED
backend/tests/test_scanner.py::test_risk_calculator_score_capping PASSED
backend/tests/test_scanner.py::test_hostname_matching PASSED
backend/tests/test_scanner.py::test_database_lifecycle PASSED
backend/tests/test_scanner.py::test_api_health PASSED
backend/tests/test_scanner.py::test_api_scan_empty_target PASSED
backend/tests/test_scanner.py::test_api_scan_ssrf_blocked PASSED
backend/tests/test_scanner.py::test_api_settings PASSED
======================= 14 passed in 4.16s =======================
```

---

## ⚖️ Ethical Use & Scope Limitations

> [!IMPORTANT]
> **Defensive Scope Notice:** RISK CHECKER performs non-destructive configuration analysis strictly evaluating publicly exposed response headers, cryptographic certificate properties, and standard TCP service banners. Missing security headers and service accessibility flags represent configuration baselines and do not automatically prove exploitable vulnerability.
> 
> Users must only assess systems that they own or for which they possess explicit written authorization.
