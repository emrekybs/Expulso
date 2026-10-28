# Recon Panel

A domain-focused **passive recon & OSINT** web panel. Analysts enter a domain (or IP,
range or URL) and run a full scan or any single module from one dashboard — no separate
tools to install. Built with Next.js, deploys to Vercel, and uses only **keyless public
sources** (no third-party API keys required).

> For authorized security research and threat intelligence only. The modules marked
> **Active** send requests to the target; use them only on systems you are allowed to test.

## Modules

**Recon (passive — nothing is sent to the target)**
Subdomain Enumeration · DNS Records (SPF/DMARC/DKIM/MTA-STS/DNSSEC) · WHOIS / RDAP ·
Certificate Transparency · Reverse DNS · Reverse IP · GeoIP & ASN · Cloud & CDN Mapping ·
Related Domains · Typosquatting

**OSINT**
Google Dorks (link generator) · OSINT Harvester (emails, socials, phones) · Email Harvester

**Active (sends requests to the target)**
HTTP Fingerprint · WAF / CDN Detection · Origin IP Finder (real IP behind a CDN) ·
JS Crawler (endpoints & secrets) · Directory & Admin Finder · Exposure & Misconfig

**Full Scan** runs many modules at once in **Passive only**, **Active only** or **Full**
mode, for a single target or a bulk list, and produces an HTML / JSON / CSV report.
**Logs** records every module call (status, duration, request id, errors) for the session.

## Local development

```bash
npm install
cp .env.example .env.local   # then edit the values
npm run dev                  # http://localhost:3000
```

```bash
npm run build && npm start   # production build
npm test                     # unit tests
```

## Configuration (environment variables)

| Variable | Required | Purpose |
| --- | --- | --- |
| `AUTH_USERNAME` | recommended | Login username (default `b24`). The same credentials can be shared by several people. |
| `AUTH_PASSWORD` | **yes in production** | Login password. **If unset, the panel is open without a login** — always set it on Vercel. |
| `AUTH_SECRET` | recommended | Secret used to sign the session cookie. Set a long random value; otherwise `AUTH_PASSWORD` is used. |

Sessions are a stateless, HMAC-signed cookie valid for 12 hours, so multiple users can
sign in with the same credentials on different devices.

## Deploy to Vercel

1. Push this repo to GitHub and import it in Vercel (framework: Next.js — auto-detected).
2. In **Settings → Environment Variables**, add `AUTH_USERNAME`, `AUTH_PASSWORD` and
   `AUTH_SECRET`.
3. Deploy. Each scan runs server-side within Vercel's function time limit; bulk scans are
   driven one target at a time from the browser so they never exceed it.

## Notes & limits

- All data comes from keyless public sources (crt.sh, RDAP, DNS-over-HTTPS, AlienVault OTX,
  HackerTarget, RapidDNS, RIPEstat, ipwho.is, provider IP-range lists, …). Some have free
  rate limits, so occasional "source unavailable" results are expected; each source's status
  is shown per scan and in the Logs page.
- There is no port scanner and no exploit/vulnerability-exploitation engine. Active modules
  perform content discovery and detection with benign requests only.
- Requests to private, loopback and link-local addresses are blocked (SSRF protection).

## Credits

OSINT Harvester reuses the extraction logic of
[z0m31en7/Uscrapper](https://github.com/z0m31en7/Uscrapper) (MIT), re-implemented in
TypeScript. Original HackerTarget-based tool by emrekybs.
