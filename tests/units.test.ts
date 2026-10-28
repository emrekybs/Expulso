import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTarget, splitTargets, expandCidr, registrableDomain, ipInCidr } from "../lib/target.ts";
import { interpretHt } from "../lib/hackertarget.ts";
import { generateVariations } from "../lib/modules/typosquatting.ts";
import { detectWaf, detectTech } from "../lib/modules/fingerprint-core.ts";
import { analyzeMail } from "../lib/modules/dns.ts";
import { matchTakeover } from "../lib/modules/takeover-core.ts";
import { buildWordlist, looksLikeAdmin } from "../lib/modules/wordlists.ts";

test("parseTarget classifies kinds", () => {
  assert.equal((parseTarget("example.com") as { kind: string }).kind, "domain");
  assert.equal((parseTarget("8.8.8.8") as { kind: string }).kind, "ip");
  assert.equal((parseTarget("https://x.example.com/a?b=1") as { kind: string }).kind, "url");
  assert.equal((parseTarget("192.168.1.0/24") as { kind: string }).kind, "cidr");
  assert.ok("error" in parseTarget("not a target !!"));
  assert.ok("error" in parseTarget("10.0.0.0/8")); // too large
});

test("splitTargets dedupes and trims", () => {
  assert.deepEqual(splitTargets("a.com, a.com\nb.com  c.com\n# comment"), ["a.com", "b.com", "c.com"]);
});

test("expandCidr /30 excludes network+broadcast", () => {
  assert.deepEqual(expandCidr("192.168.1.0/30"), ["192.168.1.1", "192.168.1.2"]);
});

test("registrableDomain handles multi-level TLDs", () => {
  assert.equal(registrableDomain("a.b.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("mail.example.com"), "example.com");
});

test("ipInCidr", () => {
  assert.ok(ipInCidr("1.1.1.5", "1.1.1.0/24"));
  assert.ok(!ipInCidr("1.1.2.5", "1.1.1.0/24"));
});

test("interpretHt maps quota and empty", () => {
  assert.throws(() => interpretHt("API count exceeded - Increase Quota with Membership"));
  assert.equal(interpretHt("No DNS A records found"), "");
  assert.equal(interpretHt("example.com,1.2.3.4"), "example.com,1.2.3.4");
});

test("generateVariations produces registered-shaped lookalikes", () => {
  const v = generateVariations("example.com");
  const domains = v.map((x) => x.domain);
  assert.ok(domains.includes("exemple.com") || domains.includes("exampl.com"));
  assert.ok(v.some((x) => x.kind === "tld-swap"));
  assert.ok(!domains.includes("example.com"));
});

test("detectWaf recognises Cloudflare", () => {
  const h = new Headers({ server: "cloudflare", "cf-ray": "abc-IST" });
  const m = detectWaf(h, "", []);
  assert.ok(m.some((x) => x.name === "Cloudflare" && x.confidence === "High"));
});

test("detectTech finds WordPress + nginx", () => {
  const h = new Headers({ server: "nginx/1.24.0" });
  const t = detectTech(h, '<link href="/wp-content/themes/x/style.css">');
  assert.ok(t.includes("nginx") && t.includes("WordPress"));
});

test("analyzeMail scores SPF/DMARC", () => {
  const m = analyzeMail(["v=spf1 include:x ~all"], ["v=DMARC1; p=none"], [], ["selector1"], false);
  assert.equal(m.spf.verdict, "fair");
  assert.equal(m.dmarc.verdict, "weak");
  const m2 = analyzeMail([], [], [], [], false);
  assert.equal(m2.spf.verdict, "missing");
});

test("matchTakeover needs cname + body unless body empty", () => {
  assert.equal(matchTakeover("x.github.io", "There isn't a GitHub Pages site here"), "GitHub Pages");
  assert.equal(matchTakeover("x.github.io", ""), "GitHub Pages");
  assert.equal(matchTakeover("x.example.com", "whatever"), null);
});

test("buildWordlist + looksLikeAdmin", () => {
  const wl = buildWordlist("admin", ["php"]);
  assert.ok(wl.includes("/admin"));
  assert.ok(wl.includes("/login.php"));
  assert.ok(looksLikeAdmin("/wp-admin", "", ""));
  assert.ok(looksLikeAdmin("/x", "Login", ""));
  assert.ok(!looksLikeAdmin("/about", "About us", "<p>hi</p>"));
});


// ---------------- Uscrapper extraction (regression for "no emails found") ----------------
import { extractFromHtml, decodeCfEmail, deobfuscate, challengeOf } from "../lib/modules/uscrapper-core.ts";

function cfEncode(email: string, key = 0x2a): string {
  return key.toString(16).padStart(2, "0") + [...email].map((c) => (c.charCodeAt(0) ^ key).toString(16).padStart(2, "0")).join("");
}

test("extracts mailto, visible text and script-embedded emails", () => {
  const html = `<html><head><title>Acme</title></head><body>
    <a href="mailto:info@acme.com?subject=hi">Mail us</a>
    <p>Sales: sales@acme.com</p>
    <script>var c = {"support":"support@acme.com"};</script>
  </body></html>`;
  const ex = extractFromHtml(html, "https://acme.com/", false);
  assert.ok(ex.emails.includes("info@acme.com"));
  assert.ok(ex.textEmails.includes("sales@acme.com"));
  assert.ok(ex.textEmails.includes("support@acme.com"), "script text must be scanned like the original get_text()");
  assert.equal(ex.title, "Acme");
});

test("decodes Cloudflare-protected addresses (data-cfemail and href hash)", () => {
  const hex = cfEncode("kariyer@acme.com.tr");
  assert.equal(decodeCfEmail(hex), "kariyer@acme.com.tr");
  const html = `<span class="__cf_email__" data-cfemail="${hex}">[email&#160;protected]</span>
                <a href="/cdn-cgi/l/email-protection#${cfEncode("hr@acme.com.tr")}">x</a>`;
  const ex = extractFromHtml(html, "https://acme.com.tr/", false);
  assert.ok(ex.emails.includes("kariyer@acme.com.tr"));
  assert.ok(ex.emails.includes("hr@acme.com.tr"));
});

test("deobfuscates [at] / [dot] written addresses", () => {
  assert.equal(deobfuscate("ahmet [at] acme [dot] com"), "ahmet@acme.com");
  assert.equal(deobfuscate("ahmet(at)acme(dot)com"), "ahmet@acme.com");
});

test("flags bot-challenge pages so empty results are explained, not silent", () => {
  assert.equal(challengeOf("<title>Just a moment...</title>"), 'Cloudflare "Just a moment" interstitial');
  assert.equal(challengeOf("<html><body>hello</body></html>"), null);
  const ex = extractFromHtml("<title>Just a moment...</title><div id='challenge-platform'></div>", "https://x.com/", false);
  assert.ok(ex.challenge);
});

// ---------------- Web technologies, passive ports, assessment ----------------
import { detectWebTech, outdatedFindings, versionLt } from "../lib/modules/webtech.ts";
import { analyzeInternetDb } from "../lib/modules/ports-passive.ts";
import { computeAssessment } from "../lib/assessment.ts";

test("detects WordPress + jQuery + nginx/Cloudflare with versions", () => {
  const headers = new Headers({ server: "cloudflare", "cf-ray": "abc-IST", "x-powered-by": "PHP/7.4.3" });
  const html = `<html><head>
    <meta name="generator" content="WordPress 5.8.1">
    <link rel="stylesheet" href="/wp-content/themes/x/style.css">
    <script src="https://cdn.example.com/jquery-3.4.1.min.js"></script>
    <script>gtag('config','G-ABCD1234XY')</script>
    <script src="https://www.googletagmanager.com/gtag/js?id=G-ABCD1234XY"></script>
  </head><body></body></html>`;
  const techs = detectWebTech({ headers, html });
  const names = techs.map((t) => t.name);
  assert.ok(names.includes("WordPress"));
  assert.ok(names.includes("Cloudflare"));
  assert.ok(names.includes("PHP"));
  const wp = techs.find((t) => t.name === "WordPress")!;
  assert.equal(wp.version, "5.8.1");
  const jq = techs.find((t) => t.name === "jQuery")!;
  assert.equal(jq.version, "3.4.1");
  assert.equal(techs.find((t) => t.name === "PHP")!.version, "7.4.3");
  assert.ok(names.includes("Google Analytics"));
});

test("WooCommerce implies WordPress", () => {
  const techs = detectWebTech({ headers: new Headers(), html: `<div class="woocommerce-page"></div>` });
  const wc = techs.find((t) => t.name === "WooCommerce");
  assert.ok(wc);
  assert.ok(techs.some((t) => t.name === "WordPress" && t.implied));
});

test("version comparison and outdated rules", () => {
  assert.ok(versionLt("3.4.1", "3.5.0"));
  assert.ok(!versionLt("3.5.0", "3.5.0"));
  assert.ok(versionLt("8.0", "8.2") && !versionLt("8.10", "8.2"));
  const f = outdatedFindings([
    { name: "jQuery", cat: "JavaScript library", version: "3.4.1", confidence: "high", evidence: "" },
    { name: "PHP", cat: "Language", version: "7.4.3", confidence: "high", evidence: "" },
    { name: "WordPress", cat: "CMS", version: "6.4", confidence: "high", evidence: "" },
  ]);
  const titles = f.map((x) => x.title).join(" | ");
  assert.match(titles, /jQuery 3\.4\.1/);
  assert.match(titles, /PHP 7\.4\.3 is end of life/);
  assert.ok(!titles.includes("WordPress 6.4"), "6.4 is current, must not be flagged");
});

test("InternetDB parser flags risky ports and CVEs without touching the target", () => {
  const h = analyzeInternetDb({ ip: "1.2.3.4", ports: [22, 443, 3389, 3389], hostnames: ["x.example.com"], cpes: ["cpe:/a:nginx:1.18"], tags: [], vulns: ["CVE-2021-23017"] }, "1.2.3.4");
  assert.equal(h.found, true);
  assert.deepEqual(h.ports.map((p) => p.port), [22, 443, 3389]);
  assert.equal(h.ports.find((p) => p.port === 3389)!.risk, "high");
  assert.deepEqual(h.cves, ["CVE-2021-23017"]);
  const none = analyzeInternetDb(null, "5.6.7.8");
  assert.equal(none.found, false);
});

test("assessment: score drops with severity, grade and priorities are ordered", () => {
  const clean = computeAssessment([{ id: "dns", ok: true, findings: [] }]);
  assert.equal(clean.score, 100);
  assert.equal(clean.grade, "A+");
  const bad = computeAssessment([
    { id: "dns", title: "DNS", ok: true, findings: [{ severity: "low", title: "weak spf", detail: "" }] },
    { id: "ports-passive", title: "Ports", ok: true, findings: [{ severity: "high", title: "RDP exposed", detail: "" }, { severity: "medium", title: "CVE list", detail: "" }] },
    { id: "exposure", title: "Exposure", ok: false, code: "timeout" },
  ]);
  assert.ok(bad.score < clean.score);
  assert.equal(bad.priorities[0].title, "RDP exposed");
  assert.equal(bad.coverage.failed, 1);
  assert.equal(bad.counts.high, 1);
});
