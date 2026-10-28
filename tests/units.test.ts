import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTarget, splitTargets, expandCidr, registrableDomain, ipInCidr } from "../lib/target.ts";
import { interpretHt } from "../lib/hackertarget.ts";
import { generateVariations } from "../lib/modules/typosquatting.ts";
import { detectWaf, detectTech } from "../lib/modules/fingerprint-core.ts";
import { analyzeMail } from "../lib/modules/dns.ts";
import { matchTakeover } from "../lib/modules/takeover-core.ts";
import { buildWordlist, looksLikeAdmin } from "../lib/modules/wordlists.ts";
import { issueToken, verifyToken } from "../lib/auth.ts";

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

test("auth token round-trip", () => {
  process.env.AUTH_SECRET = "test-secret";
  const { token } = issueToken("b24");
  assert.equal(verifyToken(token)?.username, "b24");
  assert.equal(verifyToken(token + "x"), null);
  assert.equal(verifyToken("a.b.c"), null);
});
