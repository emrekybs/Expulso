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

## Full Scan: how it works

A Full Scan runs in three stages, all on your computer:

1. **Target modules.** Passive modules first, then active ones if the mode asks for them.
2. **Chain.** Every live subdomain from stage 1 (one that resolves or answers over HTTP) gets its own run:
   DNS, GeoIP, exposed services, cloud, HTTP, web technologies, WAF and admin panels. The number of hosts is
   set in the form (default 15, maximum 50, 0 turns the chain off).
3. **Ports.** Each address found in the chain is port-scanned once, even when several hosts share it.

You can set a **scope** (for example `example.com, example.org`). Only those domains and their subdomains are
scanned; everything else is skipped. Bulk lists run up to two scans at a time.

Scans run on the server, so you can open other pages while one is running. Every scan is saved in
**History**, where you can reopen it, export it or delete it.

## Export

Each saved scan can be exported as a **PDF report** (rendered by the local Chromium), an **HTML report**,
**JSON** or **CSV** (findings only). The PDF needs Chromium, which the Tools page can install.

## What it finds

Use the **Asset Inventory** page (or the *Discovered assets* section of a scan) to see everything
grouped into 11 categories:

| Category | Where it comes from |
| --- | --- |
| Subdomain (with IP, CNAME, HTTP status, title, screenshot) | Subdomains module |
| IP address | Subdomains, GeoIP & ASN, ASN Ranges, Port Scan |
| Open port | Port Scan (TCP connect, with banners and optional nmap), Exposed Services (Shodan InternetDB, no packets to the target) |
| Web app / technology | Web Technologies (about 130 signatures) |
| Directory / path | Directories |
| Admin panel | Admin Panels, Directories |
| API endpoint | JS Files (endpoints in JavaScript), Archived URLs |
| Exposed service | Exposed Services (risky ports and CVEs in passive data) |
| Cloud asset | Cloud & CDN, Cloud Buckets (private buckets), CNAMEs to cloud hosts |
| Sensitive file | Exposure checks, Directories, JS secrets, Archived URLs, publicly listable buckets |
| SSL / certificate | Certificates, live TLS of the site |

## Modules

**Recon (passive: nothing is sent to the target)**
Subdomains · DNS · WHOIS · Certificates · Reverse DNS · Reverse IP · GeoIP & ASN · ASN Ranges · Cloud & CDN ·
Cloud Buckets · Related Domains · Typosquatting · Exposed Services

**OSINT:** Archived URLs (Wayback Machine and Common Crawl) · Google Dorks (links only) · Web OSINT · Emails

**Active (sends requests to the target):** Port Scan · HTTP Fingerprint · Web Technologies · WAF / CDN ·
Origin IP · JS Files · Directories · Admin Panels · Exposure · nuclei (info only)

**Port Scan** is a TCP connect scan built into the app. It offers common ports (about 100), web ports, all
65535 ports, or a custom list such as `22,80,8000-8100`. Speed can be careful, normal or fast. Banners are
read from open ports, and nmap adds service and version detection when it is installed. A TCP connect scan
cannot tell filtered ports from closed ones, and it does not do SYN or OS detection.

**Cloud Buckets** checks names built from the target on AWS S3, Google Cloud Storage and Azure Blob. A
publicly listable bucket is a high finding. A bucket that exists but is private is information only. Object
contents are never downloaded, and at most 20 file names per bucket are shown.

**Archived URLs** lists historic URLs from the Wayback Machine and Common Crawl. It flags sensitive file types
(backups, configs, dumps, version-control folders), API-style paths and the query parameter names used.
Archived URLs are never requested, and many no longer exist.

**ASN Ranges** maps each IP to its autonomous system (Team Cymru DNS) and lists the prefixes that AS announces,
with address counts (RIPEstat).

**Full Scan:** choose *Passive only*, *Active only* or *Full* for one target or a bulk list. It produces an
assessment (risk grade, top priorities, attack-surface numbers, coverage), the asset inventory, and an
HTML / JSON / CSV report.

## Optional tools (used automatically when installed)

The **Tools** page shows what is installed and the install command for each.

| Tool | Used for |
| --- | --- |
| subfinder, assetfinder, findomain, amass | Passive subdomain discovery (Subdomains module) |
| nmap | Service and version detection on the open ports found by Port Scan |
| feroxbuster or dirsearch | Path discovery in the Directories module (*Engine: Auto* picks feroxbuster first, then dirsearch) |
| nuclei | Information-gathering templates only (`-severity info`, tags `tech,panel`); not a vulnerability scan |
| Chromium (Playwright) | Screenshots of live subdomains and the PDF report |

The **Tools** page lists every tool with its status (installed, not installed, or an error with the message),
its version and the command it is used for. **Update** runs a fixed command from the app's catalogue, and
the output is shown on the page. Tools with no safe automatic update (findomain, nmap) show a note instead.

A missing tool is skipped and reported in the scan. Built-in sources (crt.sh, Wayback CDX, Common Crawl, RDAP,
DNS, AlienVault OTX, HackerTarget, RapidDNS, Shodan InternetDB, OSV.dev, RIPEstat and others) work without any
of them. The DNS brute force (knockpy-style, with wildcard detection), the port scanner and the directory
engine are built in.

## Notes and limits

- Free public sources rate-limit. A source that fails is shown with its error in the scan; the rest still run.
- Some sites block automated access (for example with a Cloudflare challenge page). The app reports that
  instead of showing an empty result.
- Requests to private, loopback and link-local addresses are blocked by the app's own checks.
- Saved scans, screenshots and temporary tool files live in the `data/` folder inside the project. Delete a scan
  from History, or delete the folder, to remove them. The folder is not part of the code and is ignored by git.
- Cloud Buckets and Archived URLs send requests to third-party services (cloud providers, web archives), not to
  the target. Their results may include names of public files, which you should treat as sensitive.

## Credits

The OSINT module reuses the extraction logic of
[z0m31en7/Uscrapper](https://github.com/z0m31en7/Uscrapper) (MIT), re-implemented in TypeScript.
