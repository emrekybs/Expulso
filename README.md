# B24-engine

A local recon and asset-discovery workbench. It runs on your own computer. Enter a domain and get
subdomains with IP addresses and HTTP status, DNS, WHOIS, certificates, exposed services, web
technologies, directories, admin panels, API endpoints, cloud assets and screenshots, all in one
place. No login and no API keys are needed.

> For authorized security research and asset discovery only. Modules marked **Active** send
> requests to the target. Use them only on systems you are allowed to test.
> B24-engine does **not** run vulnerability tests (no XSS, SQL injection or similar).

## Quick start (one step)

Requirement: **Node.js 20 or newer** (https://nodejs.org).

- **Windows:** double-click `start.bat`
- **macOS:** double-click `start.command` (first time: right-click → Open)
- **Linux:** run `./start.sh`, or `npm run launch` from a terminal

The first run installs the dependencies and builds the app. Later runs start in seconds and open
`http://localhost:3000` in your browser. Stop it with Ctrl+C.

Manual steps, if you prefer:

```bash
npm install
npx playwright install chromium   # only needed for screenshots
npm run launch
```

## Install it as an app (desktop icon, opens directly)

Open `http://localhost:3000` once in Chrome or Edge, then:

- **Chrome / Edge:** click the install icon in the address bar (or menu → *Install B24-engine*).
  It gets its own window and an icon in the start menu, dock or desktop. Clicking the icon opens the app.
- **Android (Chrome):** menu → *Add to Home screen*.
- **iPhone / iPad (Safari):** Share → *Add to Home Screen*.

The icon is the B24 logo. The installed app needs `npm run launch` (or the start file) to be running,
because the app is served from your computer.

## What it finds

Use the **Asset Inventory** page (or the *Discovered assets* section of a Full Scan) to see everything
grouped into 11 categories:

| Category | Where it comes from |
| --- | --- |
| Subdomain (with IP, CNAME, HTTP status, title, screenshot) | Subdomains module |
| IP address | Subdomains, GeoIP & ASN, Exposed Services |
| Open port | Exposed Services (Shodan InternetDB cached index, no packets to the target) |
| Web app / technology | Web Technologies (about 130 signatures) |
| Directory / path | Directories |
| Admin panel | Admin Panels, Directories |
| API endpoint | JS Files (endpoints found in JavaScript) |
| Exposed service | Exposed Services (risky ports and CVEs in passive data) |
| Cloud asset | Cloud & CDN, CNAMEs to cloud hosts |
| Sensitive file | Exposure checks, Directories, JS secrets |
| SSL / certificate | Certificates, live TLS of the site |

## Modules

**Recon (passive: nothing is sent to the target)**
Subdomains · DNS · WHOIS · Certificates · Reverse DNS · Reverse IP · GeoIP & ASN · Cloud & CDN ·
Related Domains · Typosquatting · Exposed Services

**OSINT:** Google Dorks (links only) · Web OSINT · Emails

**Active (sends requests to the target):** HTTP Fingerprint · Web Technologies · WAF / CDN · Origin IP ·
JS Files · Directories · Admin Panels · Exposure · nuclei (info only)

**Full Scan:** choose *Passive only*, *Active only* or *Full* for one target or a bulk list. It produces an
assessment (risk grade, top priorities, attack-surface numbers, coverage), the asset inventory, and an
HTML / JSON / CSV report.

## Optional tools (used automatically when installed)

The **Tools** page shows what is installed and the install command for each.

| Tool | Used for |
| --- | --- |
| subfinder | Passive subdomain discovery (Subdomains module) |
| assetfinder | Passive subdomain discovery (Subdomains module) |
| findomain | Passive subdomain discovery (Subdomains module) |
| nuclei | Information-gathering templates only (`-severity info`, tags `tech,panel`); not a vulnerability scan |
| Chromium (Playwright) | Screenshots of live subdomains (Subdomains module, option *Screenshots*) |

A missing tool is skipped and reported in the scan. Built-in sources (crt.sh, Wayback CDX, RDAP,
DNS, AlienVault OTX, HackerTarget, RapidDNS, Shodan InternetDB, OSV.dev, and others) work without any of them.
The DNS brute force (knockpy-style, with wildcard detection) is built in and does not need knockpy installed.

## Notes and limits

- Free public sources rate-limit. A source that fails is shown with its error in the scan; the rest still run.
- Some sites block automated access (for example with a Cloudflare challenge page). The app reports that
  instead of showing an empty result.
- Requests to private, loopback and link-local addresses are blocked by the app's own checks.
- Results are kept in the browser for the session (Logs). Nothing is stored on a server.
- Screenshot files are saved in `data/screenshots` inside the project folder.

## Credits

The OSINT module reuses the extraction logic of
[z0m31en7/Uscrapper](https://github.com/z0m31en7/Uscrapper) (MIT), re-implemented in TypeScript.
