# Red Team Toolkit

Production-style full-stack vulnerability assessment platform using real scanner output from Nmap, Nuclei, WhatWeb, VirusTotal, and AbuseIPDB.

![Red Team Toolkit dashboard](https://raw.githubusercontent.com/vaibhaviacchanala-19/Red-Team-Toolkit/main/public/images/dashboard.png)

## What It Does

- Accepts a public domain or IP address.
- Blocks localhost, private, reserved, multicast, and documentation ranges for SSRF protection.
- Performs DNS, WHOIS, and basic subdomain reconnaissance.
- Runs Nmap service/version detection and parses Nmap NSE vulnerability script evidence.
- Runs Nuclei and parses JSONL findings into professional vulnerability records.
- Detects technologies with WhatWeb, with HTTP fingerprint fallback only for the Technologies tab.
- Pulls reputation data from VirusTotal and AbuseIPDB.
- Scores risk mainly from confirmed Nuclei findings, Nmap NSE vulnerability evidence, sensitive open services, and threat intel.
- Shows scanner confidence so unavailable tooling is not mistaken for a clean assessment.
- Saves reports to MongoDB and supports JSON/PDF export.

## Stack

- Backend: Node.js, Express, Mongoose
- Frontend: HTML, CSS, JavaScript
- Database: MongoDB
- Scanners: Nmap, Nuclei, WhatWeb
- Security: Helmet, CORS, rate limiting, input sanitization, SSRF checks, timeout handling, shell-free command execution

## API

- `POST /scan` with `{ "target": "example.com" }`
- `GET /history`
- `GET /report/history`
- `GET /report/:id`
- `GET /report/:id/pdf`
- `DELETE /report/:id`

## Local Setup

Install prerequisites:

```bash
npm install
```

Install scanner CLIs on the host:

```bash
nmap --version
nuclei -version
whatweb --version
```

Create `.env` from `.env.example`, then configure MongoDB and optional threat intelligence keys:

```text
MONGODB_URI=mongodb://localhost:27017/redteamtoolkit
VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

Start the app:

```bash
npm start
```

Open `http://localhost:3001`.

## Docker

```bash
docker compose up --build
```

The app runs on `http://localhost:3001` and MongoDB is available on `localhost:27017`.

## Scanner Notes

Nuclei findings are the primary vulnerability source. Nmap-derived vulnerability findings come from NSE vulnerability script output or materially risky exposed services such as SMB, RDP, databases, Redis, Docker API, and Elasticsearch. Missing HTTP headers are not used as vulnerability evidence.

If Nmap, Nuclei, WhatWeb, or threat intelligence APIs are unavailable, the report marks those modules as degraded or unavailable. It does not invent CVEs or fake scanner results.

For better vulnerability coverage, keep Nuclei templates fresh and leave `NMAP_ENABLE_VULN_SCRIPTS=true`. If scans are too slow in your environment, tune `NMAP_SCRIPTS`, `NMAP_TOP_PORTS`, and `NUCLEI_RATE_LIMIT`.

## Deployment

- Put the app behind a reverse proxy with TLS.
- Set `NODE_ENV=production`.
- Use a managed MongoDB instance or a persistent Docker volume.
- Keep Nuclei templates updated separately with `nuclei -update-templates`.
- Restrict who can access the scanner UI because it can initiate external network scans.
- Tune `NUCLEI_RATE_LIMIT`, `NMAP_TOP_PORTS`, and scanner timeouts for your authorization scope.

## Authorization

Use this toolkit only on systems you own or are explicitly authorized to test. Unauthorized scanning can be illegal.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
