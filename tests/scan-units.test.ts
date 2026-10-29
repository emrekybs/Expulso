import { test } from "node:test";
import assert from "node:assert/strict";
import { inScope } from "../lib/target.ts";
import { parsePorts, portsForPreset, parseNmapGreppable } from "../lib/modules/port-scan.ts";
import { bucketNames } from "../lib/modules/cloud-buckets.ts";
import { parseFeroxLines, parseDirsearchJson } from "../lib/modules/dirs-engines.ts";
import { buildInventory } from "../lib/inventory.ts";

test("inScope allows the scope domains and their subdomains only", () => {
  assert.equal(inScope("example.com"), true, "empty scope allows everything");
  const scope = ["example.com"];
  assert.equal(inScope("example.com", scope), true);
  assert.equal(inScope("api.dev.example.com", scope), true);
  assert.equal(inScope("notexample.com", scope), false);
  assert.equal(inScope("example.com.evil.net", scope), false);
});

test("parsePorts reads single ports, ranges and rejects bad input", () => {
  assert.deepEqual(parsePorts("80, 443, 8000-8002, 80"), { ports: [80, 443, 8000, 8001, 8002] });
  assert.ok("error" in parsePorts("70000"));
  assert.ok("error" in parsePorts("9-3"));
  assert.ok("error" in parsePorts("abc"));
  assert.ok("error" in parsePorts("   "));
});

test("portsForPreset: web preset is small, custom uses the list", () => {
  const web = portsForPreset({ preset: "web", customPorts: "", speed: "normal", banners: false });
  assert.ok(web.includes(443) && web.length < 40);
  assert.deepEqual(portsForPreset({ preset: "custom", customPorts: "22,2222", speed: "normal", banners: false }), [22, 2222]);
  assert.throws(() => portsForPreset({ preset: "custom", customPorts: "x", speed: "normal", banners: false }));
});

test("bucketNames builds valid, unique names from the target", () => {
  const names = bucketNames("shop.example.com");
  assert.ok(names.includes("example"));
  assert.ok(names.includes("example-dev"));
  assert.ok(names.includes("dev-example"));
  assert.equal(new Set(names).size, names.length, "names are unique");
  assert.ok(names.every((n) => /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(n)), "every name is a valid bucket name");
  assert.ok(names.length <= 60);
});

test("parseFeroxLines reads default feroxbuster result lines and skips the rest", () => {
  const rows = parseFeroxLines([
    "200      GET       12l       34w      567c http://example.com/admin",
    "301      GET        9l       28w      311c http://example.com/images => http://example.com/images/",
    "Scanning http://example.com",
    "",
  ]);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0], { url: "http://example.com/admin", status: 200, size: 567 });
  assert.equal(rows[1].status, 301);
});

test("parseDirsearchJson reads the results array and tolerates bad input", () => {
  const json = JSON.stringify({ results: [{ url: "https://example.com/login", status: 200, "content-length": 1200 }, { url: "https://example.com/x", status: 302, redirect: "/login" }, { status: 200 }] });
  const rows = parseDirsearchJson(json);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].size, 1200);
  assert.equal(rows[1].redirect, "/login");
  assert.deepEqual(parseDirsearchJson("not json"), []);
});

test("buildInventory maps port, bucket, archive and ASN data and includes child hosts", () => {
  const inv = buildInventory(
    [
      {
        id: "ports-scan",
        title: "Port Scan",
        ok: true,
        data: { hosts: [{ ip: "203.0.113.5", open: [{ port: 3306, service: "mysql", banner: "", tls: false }, { port: 22, service: "ssh", banner: "SSH-2.0-OpenSSH", tls: false }] }] },
      },
      { id: "cloud-buckets", title: "Cloud Buckets", ok: true, data: { hits: [{ provider: "AWS S3", name: "acme-backup", state: "listable", url: "https://acme-backup.s3.amazonaws.com/" }] } },
      { id: "url-archive", title: "Archived URLs", ok: true, data: { api: ["https://example.com/api/v1/users"], sensitive: ["https://example.com/.env"], admin: [] } },
      { id: "asn-ranges", title: "ASN Ranges", ok: true, data: { asns: [{ asn: "15169", name: "GOOGLE", ipv4Prefixes: 3, addresses: 512 }] } },
    ],
    [{ host: "app.example.com", modules: [{ id: "ports-scan", title: "Port Scan", ok: true, data: { hosts: [{ ip: "203.0.113.5", open: [{ port: 3306, service: "mysql", banner: "", tls: false }] }] } }] }],
  );
  assert.equal(inv.port.length, 2, "the same host:port from the child is not counted twice");
  assert.ok(inv.exposed.some((e) => e.label === "203.0.113.5:3306"), "database port is an exposed service");
  assert.ok(inv.sensitive.some((e) => e.label === "AWS S3: acme-backup"), "public bucket listing is sensitive");
  assert.equal(inv.api.length, 1);
  assert.ok(inv.sensitive.some((e) => e.label === "https://example.com/.env"));
  assert.ok(inv.ip.some((e) => e.label === "AS15169 GOOGLE"));
});

test("port probe and banner grab work against a real local TCP service", async () => {
  const { probe, grabBanner } = await import("../lib/modules/port-scan.ts");
  const net = await import("node:net");
  const server = net.createServer((sock) => {
    sock.on("error", () => undefined); // the probe closes its side first; that reset is expected here
    sock.end("SSH-2.0-B24test\r\n");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as { port: number }).port;
  try {
    assert.equal(await probe("127.0.0.1", port, 1000), true);
    const closed = net.createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", () => resolve()));
    const freePort = (closed.address() as { port: number }).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    assert.equal(await probe("127.0.0.1", freePort, 1000), false);
    assert.match(await grabBanner("127.0.0.1", port, 1500), /SSH-2\.0-B24test/);
  } finally {
    server.close();
  }
});

test("parseNmapGreppable reads open ports and versions from nmap -oG output", () => {
  const lines = [
    "# Nmap 7.94 scan initiated",
    "Host: 203.0.113.5 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu/, 80/open/tcp//http//nginx 1.18.0/, 8443/closed/tcp//https-alt//",
    "# Nmap done",
  ];
  assert.deepEqual(parseNmapGreppable(lines), [
    { port: 22, service: "ssh", version: "OpenSSH 8.9p1 Ubuntu" },
    { port: 80, service: "http", version: "nginx 1.18.0" },
  ]);
});

test("vuln-core: reflection context, SQL errors, redirects, cookies and headers", async () => {
  const core = await import("../lib/modules/vuln-core.ts");
  const m = core.makeMarker("https://x.test/?q=1");
  assert.match(m, /^b24x[a-z0-9]+$/i);
  assert.deepEqual(core.reflectionContext(`<p>${m}"'<></p>`, m), { context: "html-text", unencoded: true });
  assert.deepEqual(core.reflectionContext(`<input value="${m}&quot;&#39;&lt;&gt;">`, m), { context: "attribute", unencoded: false });
  assert.equal(core.reflectionContext(`<script>var a="${m}"'<></script>`, m).context, "script");
  assert.equal(core.reflectionContext("nothing here", m).context, "none");
  assert.match(core.sqlErrorSignature("You have an error in your SQL syntax; check the manual") ?? "", /SQL syntax/);
  assert.equal(core.sqlErrorSignature("<html>hello</html>"), null);
  assert.equal(core.isRedirectParam("next"), true);
  assert.equal(core.isRedirectParam("id"), false);
  assert.deepEqual(core.queryParams("https://a.test/x?id=1&page=2&id=3"), ["id", "page"]);
  assert.equal(core.withParam("https://a.test/x?id=1", "id", "'"), "https://a.test/x?id=%27");
  const h = new Headers({ "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff" });
  assert.deepEqual(core.missingSecurityHeaders(h, true), ["Strict-Transport-Security"]);
  assert.deepEqual(core.cookieFlagProblems(["sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax", "theme=dark; Path=/"]), [{ name: "theme", missing: ["Secure", "HttpOnly", "SameSite"] }]);
});
