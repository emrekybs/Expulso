# Recon Panel

A local, domain-focused **passive recon & OSINT** workbench. Enter a domain (or IP, range or URL)
and run a full scan or single modules from one dashboard. It runs on your own machine and
installs as a desktop/phone app. No API keys are needed.

> For authorized security research and threat intelligence only. Modules marked **Active**
> send requests to the target. Use them only on systems you are allowed to test.

## Run it locally

Requirements: Node.js 20 or newer.

```bash
npm install
npm run build
npm start            # open http://localhost:3000
```

For development with hot reload: `npm run dev`.

## Install as an app (icon on your desktop / start menu / home screen)

The panel is a Progressive Web App. Open it once in Chrome or Edge at `http://localhost:3000`:

- **Desktop (Chrome / Edge):** click the install icon in the address bar (or menu → *Install Recon Panel*).
  It gets its own window and an icon in the start menu / dock. Launching the icon opens the app directly.
- **Android (Chrome):** menu → *Add to Home screen*.
- **iPhone / iPad (Safari):** Share → *Add to Home Screen*.

Installation needs a secure context, and `localhost` counts as one. The app is served by your
local `npm start`, so keep that process running while you use the icon.

## Modules

**Recon (passive: nothing is sent to the target)**
Subdomain Enumeration (passive sources, DNS resolution, HTTP status) · DNS Records (SPF, DMARC,
DKIM, MTA-STS, DNSSEC) · WHOIS / RDAP · Certificate Transparency · Reverse DNS · Reverse IP ·
GeoIP & ASN · Cloud & CDN Mapping · Related Domains · Typosquatting · Exposed Services
(Shodan InternetDB cached index)

**OSINT:** Google Dorks (links only) · OSINT Harvester (emails, social links, phones, authors) ·
Email Harvester (corporate and staff addresses, pattern detection)

**Active (sends requests to the target):** HTTP Fingerprint · Web Technologies (CMS, frameworks,
servers, CDNs, analytics, libraries with versions, outdated-version and CVE checks) ·
WAF / CDN Detection · Origin IP Finder · JS Crawler · Directory & Admin Finder · Exposure & Misconfig

**Full Scan:** passive only, active only or both, for one target or a bulk list. It produces an
assessment (risk score, top priorities, attack-surface numbers, coverage) and an HTML / JSON / CSV
report. **Logs** records every module call with its status, duration and request id.

## Notes and limits

- Data comes from public, keyless sources (crt.sh, Wayback CDX, RDAP, DNS-over-HTTPS, AlienVault OTX,
  HackerTarget, RapidDNS, RIPEstat, Shodan InternetDB, OSV.dev, provider IP-range lists). Free sources
  rate-limit, so a source can show an error; each source's status is shown in the scan and in Logs.
- Some sites block automated access (for example with a Cloudflare challenge page). The panel reports
  that instead of showing an empty result.
- There is no port scanner and no vulnerability-exploitation engine. Active modules use benign requests
  for discovery and detection only.
- Requests to private, loopback and link-local addresses are blocked.
- Scan results are kept in the browser for the session (Logs) and are not stored on a server.

## Credits

The OSINT Harvester reuses the extraction logic of
[z0m31en7/Uscrapper](https://github.com/z0m31en7/Uscrapper) (MIT), re-implemented in TypeScript.
