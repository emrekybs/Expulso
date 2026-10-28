import tls from "node:tls";
import { assertPublicHost, safeFetch, UserError } from "../net.ts";
import type { ParsedTarget } from "../target.ts";

export type Severity = "yüksek" | "orta" | "düşük" | "bilgi";
export type CheckStatus = "pass" | "warn" | "fail" | "info";

export interface Check {
  id: string;
  category: "Başlıklar" | "Çerezler" | "TLS / SSL" | "Bilgi ifşası" | "Hassas dosyalar" | "Yapılandırma";
  title: string;
  status: CheckStatus;
  severity: Severity;
  detail: string;
  value?: string;
  recommendation?: string;
}

export interface TlsInfo {
  protocol?: string;
  authorized: boolean;
  authError?: string;
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysLeft?: number;
  san: string[];
  fingerprint?: string;
}

export interface SecurityResult {
  target: string;
  finalUrl: string;
  status: number;
  redirects: { url: string; status: number }[];
  score: number;
  grade: string;
  checks: Check[];
  headers: { name: string; value: string }[];
  tls?: TlsInfo;
  robots?: { disallow: string[]; sitemaps: string[] };
  technologies: string[];
}

function getTls(host: string): Promise<TlsInfo> {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 8000 }, () => {
      const c = sock.getPeerCertificate();
      const daysLeft = c.valid_to ? Math.floor((new Date(c.valid_to).getTime() - Date.now()) / 86_400_000) : undefined;
      const info: TlsInfo = {
        protocol: sock.getProtocol() ?? undefined,
        authorized: sock.authorized,
        authError: sock.authorizationError ? String(sock.authorizationError) : undefined,
        subject: [c.subject?.CN].flat().join(", ") || undefined,
        issuer: [c.issuer?.O, c.issuer?.CN].flat().filter(Boolean).join(" — "),
        validFrom: c.valid_from ? new Date(c.valid_from).toISOString() : undefined,
        validTo: c.valid_to ? new Date(c.valid_to).toISOString() : undefined,
        daysLeft,
        san: (c.subjectaltname ?? "")
          .split(",")
          .map((s) => s.trim().replace(/^DNS:/, ""))
          .filter(Boolean)
          .slice(0, 50),
        fingerprint: c.fingerprint256,
      };
      sock.end();
      resolve(info);
    });
    sock.on("timeout", () => {
      sock.destroy();
      reject(new Error("timeout"));
    });
    sock.on("error", reject);
  });
}

const SENSITIVE: { path: string; title: string; test: (body: string, ct: string) => boolean; severity: Severity }[] = [
  { path: "/.git/HEAD", title: "Açık Git deposu (.git)", test: (b) => /^ref: refs\//m.test(b), severity: "yüksek" },
  { path: "/.env", title: "Ortam değişkenleri dosyası (.env)", test: (b, ct) => !/html/i.test(ct) && /^[A-Z][A-Z0-9_]{2,}=.+/m.test(b), severity: "yüksek" },
  { path: "/.DS_Store", title: "macOS dizin dosyası (.DS_Store)", test: (b) => b.includes("Bud1"), severity: "düşük" },
  { path: "/server-status", title: "Apache sunucu durum sayfası", test: (b) => /Apache Server Status/i.test(b), severity: "orta" },
  { path: "/phpinfo.php", title: "phpinfo() sayfası", test: (b) => /phpinfo\(\)|PHP Version/i.test(b) && /<table/i.test(b), severity: "orta" },
  { path: "/.svn/entries", title: "Açık SVN deposu (.svn)", test: (b, ct) => !/html/i.test(ct) && /^\d+\s*$/m.test(b.slice(0, 10)), severity: "yüksek" },
  { path: "/backup.zip", title: "Yedek arşivi (backup.zip)", test: (b, ct) => /zip|octet-stream/i.test(ct) && b.startsWith("PK"), severity: "yüksek" },
];

const SEVERITY_WEIGHT: Record<Severity, number> = { yüksek: 20, orta: 10, düşük: 4, bilgi: 0 };

export function gradeOf(score: number): string {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

export function analyzeHeaders(h: Headers, setCookies: string[], isHttps: boolean): Check[] {
  const c: Check[] = [];
  const get = (n: string) => h.get(n) ?? undefined;

  const hsts = get("strict-transport-security");
  if (!isHttps) c.push({ id: "https", category: "TLS / SSL", title: "HTTPS kullanımı", status: "fail", severity: "yüksek", detail: "Site HTTPS üzerinden sunulmuyor.", recommendation: "Geçerli bir TLS sertifikası ile HTTPS'e geçin." });
  else if (!hsts) c.push({ id: "hsts", category: "Başlıklar", title: "Strict-Transport-Security (HSTS)", status: "fail", severity: "orta", detail: "HSTS başlığı yok; SSL stripping saldırılarına açık olabilir.", recommendation: "Strict-Transport-Security: max-age=31536000; includeSubDomains" });
  else {
    const age = Number(hsts.match(/max-age=(\d+)/i)?.[1] ?? 0);
    c.push(
      age < 15552000
        ? { id: "hsts", category: "Başlıklar", title: "Strict-Transport-Security (HSTS)", status: "warn", severity: "düşük", detail: `max-age değeri kısa (${age} sn). En az 6 ay önerilir.`, value: hsts }
        : { id: "hsts", category: "Başlıklar", title: "Strict-Transport-Security (HSTS)", status: "pass", severity: "bilgi", detail: "HSTS doğru yapılandırılmış.", value: hsts },
    );
  }

  const csp = get("content-security-policy");
  if (!csp) c.push({ id: "csp", category: "Başlıklar", title: "Content-Security-Policy (CSP)", status: "fail", severity: "orta", detail: "CSP başlığı yok; XSS ve içerik enjeksiyonuna karşı ek koruma eksik.", recommendation: "Kaynakları kısıtlayan bir Content-Security-Policy tanımlayın." });
  else if (/unsafe-inline|unsafe-eval|\*\s|\*;/.test(csp)) c.push({ id: "csp", category: "Başlıklar", title: "Content-Security-Policy (CSP)", status: "warn", severity: "düşük", detail: "CSP mevcut ancak 'unsafe-inline', 'unsafe-eval' veya joker (*) içeriyor.", value: csp });
  else c.push({ id: "csp", category: "Başlıklar", title: "Content-Security-Policy (CSP)", status: "pass", severity: "bilgi", detail: "CSP tanımlı.", value: csp });

  const xfo = get("x-frame-options");
  if (xfo || /frame-ancestors/i.test(csp ?? "")) c.push({ id: "xfo", category: "Başlıklar", title: "Clickjacking koruması", status: "pass", severity: "bilgi", detail: "X-Frame-Options veya CSP frame-ancestors tanımlı.", value: xfo ?? "frame-ancestors (CSP)" });
  else c.push({ id: "xfo", category: "Başlıklar", title: "Clickjacking koruması", status: "fail", severity: "orta", detail: "X-Frame-Options / frame-ancestors yok; sayfa başka sitelerde çerçeve içine alınabilir.", recommendation: "X-Frame-Options: DENY veya CSP frame-ancestors 'self'" });

  const xcto = get("x-content-type-options");
  c.push(
    xcto?.toLowerCase() === "nosniff"
      ? { id: "xcto", category: "Başlıklar", title: "X-Content-Type-Options", status: "pass", severity: "bilgi", detail: "MIME türü koklama engellenmiş.", value: xcto }
      : { id: "xcto", category: "Başlıklar", title: "X-Content-Type-Options", status: "fail", severity: "düşük", detail: "nosniff tanımlı değil.", recommendation: "X-Content-Type-Options: nosniff" },
  );

  const rp = get("referrer-policy");
  c.push(
    rp
      ? { id: "rp", category: "Başlıklar", title: "Referrer-Policy", status: /unsafe-url/i.test(rp) ? "warn" : "pass", severity: /unsafe-url/i.test(rp) ? "düşük" : "bilgi", detail: /unsafe-url/i.test(rp) ? "unsafe-url tam URL'yi üçüncü taraflara sızdırır." : "Referrer-Policy tanımlı.", value: rp }
      : { id: "rp", category: "Başlıklar", title: "Referrer-Policy", status: "warn", severity: "düşük", detail: "Referrer-Policy tanımlı değil.", recommendation: "Referrer-Policy: strict-origin-when-cross-origin" },
  );

  const pp = get("permissions-policy");
  c.push(
    pp
      ? { id: "pp", category: "Başlıklar", title: "Permissions-Policy", status: "pass", severity: "bilgi", detail: "Tarayıcı özellik izinleri kısıtlanmış.", value: pp }
      : { id: "pp", category: "Başlıklar", title: "Permissions-Policy", status: "warn", severity: "düşük", detail: "Kamera, mikrofon, konum gibi özellikler için politika tanımlı değil." },
  );

  const acao = get("access-control-allow-origin");
  if (acao === "*") {
    const cred = get("access-control-allow-credentials") === "true";
    c.push({ id: "cors", category: "Yapılandırma", title: "CORS yapılandırması", status: cred ? "fail" : "warn", severity: cred ? "yüksek" : "düşük", detail: cred ? "Joker kaynak (*) kimlik bilgileriyle birlikte izinli." : "Tüm kaynaklara (*) izin veriliyor.", value: acao });
  }

  const server = get("server");
  if (server && /\d/.test(server)) c.push({ id: "server", category: "Bilgi ifşası", title: "Sunucu sürüm bilgisi", status: "warn", severity: "düşük", detail: "Server başlığı yazılım sürümünü açığa çıkarıyor; bilinen zafiyetlerin hedeflenmesini kolaylaştırır.", value: server });
  else if (server) c.push({ id: "server", category: "Bilgi ifşası", title: "Sunucu yazılımı", status: "info", severity: "bilgi", detail: "Sunucu yazılımı tanımlanabiliyor (sürüm gizli).", value: server });
  for (const n of ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]) {
    const v = get(n);
    if (v) c.push({ id: n, category: "Bilgi ifşası", title: `${n} başlığı`, status: "warn", severity: "düşük", detail: "Kullanılan teknoloji/sürüm bilgisi açığa çıkıyor.", value: v, recommendation: "Bu başlığı sunucu yapılandırmasından kaldırın." });
  }

  for (const sc of setCookies) {
    const name = sc.split("=")[0].trim();
    const missing: string[] = [];
    if (isHttps && !/;\s*secure/i.test(sc)) missing.push("Secure");
    if (!/;\s*httponly/i.test(sc)) missing.push("HttpOnly");
    if (!/;\s*samesite=/i.test(sc)) missing.push("SameSite");
    c.push(
      missing.length
        ? { id: `cookie-${name}`, category: "Çerezler", title: `Çerez: ${name}`, status: "warn", severity: missing.includes("Secure") ? "orta" : "düşük", detail: `Eksik bayraklar: ${missing.join(", ")}`, value: sc.split(";")[0].slice(0, 80) }
        : { id: `cookie-${name}`, category: "Çerezler", title: `Çerez: ${name}`, status: "pass", severity: "bilgi", detail: "Secure, HttpOnly ve SameSite bayrakları tanımlı." },
    );
  }
  return c;
}

export function detectTech(h: Headers, body: string): string[] {
  const t = new Set<string>();
  const server = h.get("server") ?? "";
  const s: [RegExp, string][] = [
    [/cloudflare/i, "Cloudflare"],
    [/nginx/i, "nginx"],
    [/apache/i, "Apache"],
    [/microsoft-iis/i, "Microsoft IIS"],
    [/litespeed/i, "LiteSpeed"],
    [/vercel/i, "Vercel"],
    [/gws|gfe/i, "Google"],
    [/AmazonS3|awselb/i, "Amazon Web Services"],
  ];
  for (const [re, n] of s) if (re.test(server)) t.add(n);
  if (h.get("cf-ray")) t.add("Cloudflare");
  if (h.get("x-vercel-id")) t.add("Vercel");
  if (h.get("x-amz-cf-id")) t.add("Amazon CloudFront");
  if (h.get("x-akamai-transformed") || /akamai/i.test(server)) t.add("Akamai");
  const xp = h.get("x-powered-by");
  if (xp) t.add(xp);
  const b: [RegExp, string][] = [
    [/wp-content|wp-includes/i, "WordPress"],
    [/Joomla!/i, "Joomla"],
    [/Drupal\.settings|\/sites\/default\/files/i, "Drupal"],
    [/__NEXT_DATA__|\/_next\/static/i, "Next.js"],
    [/__NUXT__|\/_nuxt\//i, "Nuxt"],
    [/data-reactroot|react-dom/i, "React"],
    [/ng-version=/i, "Angular"],
    [/cdn\.shopify\.com/i, "Shopify"],
    [/static\.wixstatic\.com/i, "Wix"],
    [/jquery(\.min)?\.js/i, "jQuery"],
    [/bootstrap(\.min)?\.(css|js)/i, "Bootstrap"],
    [/googletagmanager\.com/i, "Google Tag Manager"],
    [/google-analytics\.com|gtag\(/i, "Google Analytics"],
    [/recaptcha/i, "reCAPTCHA"],
  ];
  for (const [re, n] of b) if (re.test(body)) t.add(n);
  const gen = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i)?.[1];
  if (gen) t.add(gen);
  return [...t];
}

export async function runSecurity(t: ParsedTarget): Promise<SecurityResult> {
  if (t.kind === "cidr") throw new UserError("Güvenlik taraması için bir alan adı veya URL girin.");
  const startUrl = t.url ?? `https://${t.host}/`;
  await assertPublicHost(t.host);

  let res;
  try {
    res = await safeFetch(startUrl, { timeoutMs: 15000, maxBytes: 1_500_000 });
  } catch (e) {
    if (startUrl.startsWith("https://") && !t.url) res = await safeFetch(`http://${t.host}/`, { timeoutMs: 15000, maxBytes: 1_500_000 });
    else throw e;
  }
  const final = new URL(res.finalUrl);
  const isHttps = final.protocol === "https:";
  const checks = analyzeHeaders(res.headers, res.headers.getSetCookie?.() ?? [], isHttps);

  // HTTP -> HTTPS yönlendirmesi
  try {
    const plain = await safeFetch(`http://${final.host}/`, { timeoutMs: 8000, followRedirects: false, method: "GET", maxBytes: 2000 });
    const loc = plain.headers.get("location") ?? "";
    const redirectsToHttps = plain.status >= 300 && plain.status < 400 && loc.startsWith("https://");
    checks.push(
      redirectsToHttps
        ? { id: "redirect", category: "TLS / SSL", title: "HTTP → HTTPS yönlendirmesi", status: "pass", severity: "bilgi", detail: `HTTP istekleri HTTPS'e yönlendiriliyor (${plain.status}).` }
        : { id: "redirect", category: "TLS / SSL", title: "HTTP → HTTPS yönlendirmesi", status: "warn", severity: "orta", detail: "HTTP istekleri otomatik olarak HTTPS'e yönlendirilmiyor.", recommendation: "Tüm HTTP isteklerini 301 ile HTTPS'e yönlendirin." },
    );
  } catch {
    checks.push({ id: "redirect", category: "TLS / SSL", title: "HTTP → HTTPS yönlendirmesi", status: "info", severity: "bilgi", detail: "80 numaralı porta bağlanılamadı (yalnızca HTTPS sunuluyor olabilir)." });
  }

  // TLS sertifikası
  let tlsInfo: TlsInfo | undefined;
  if (isHttps) {
    try {
      tlsInfo = await getTls(final.hostname);
      if (!tlsInfo.authorized) checks.push({ id: "cert", category: "TLS / SSL", title: "Sertifika güveni", status: "fail", severity: "yüksek", detail: `Sertifika doğrulanamadı: ${tlsInfo.authError ?? "bilinmeyen hata"}` });
      else checks.push({ id: "cert", category: "TLS / SSL", title: "Sertifika güveni", status: "pass", severity: "bilgi", detail: "Sertifika güvenilir bir otorite tarafından imzalanmış." });
      if (tlsInfo.daysLeft !== undefined) {
        const d = tlsInfo.daysLeft;
        checks.push(
          d < 0
            ? { id: "cert-exp", category: "TLS / SSL", title: "Sertifika geçerlilik süresi", status: "fail", severity: "yüksek", detail: `Sertifikanın süresi ${-d} gün önce dolmuş.` }
            : d < 15
              ? { id: "cert-exp", category: "TLS / SSL", title: "Sertifika geçerlilik süresi", status: "warn", severity: "orta", detail: `Sertifikanın süresi ${d} gün içinde doluyor.` }
              : { id: "cert-exp", category: "TLS / SSL", title: "Sertifika geçerlilik süresi", status: "pass", severity: "bilgi", detail: `Sertifika ${d} gün daha geçerli.` },
        );
      }
      if (tlsInfo.protocol && /TLSv1(\.1)?$/.test(tlsInfo.protocol)) checks.push({ id: "tls-ver", category: "TLS / SSL", title: "TLS sürümü", status: "fail", severity: "orta", detail: `Eski protokol kullanılıyor: ${tlsInfo.protocol}` });
      else if (tlsInfo.protocol) checks.push({ id: "tls-ver", category: "TLS / SSL", title: "TLS sürümü", status: "pass", severity: "bilgi", detail: `Güncel protokol: ${tlsInfo.protocol}` });
    } catch {
      checks.push({ id: "cert", category: "TLS / SSL", title: "Sertifika bilgisi", status: "info", severity: "bilgi", detail: "TLS bağlantısı kurulamadı." });
    }
  }

  // Hassas dosyalar
  const origin = `${final.protocol}//${final.host}`;
  const sens = await Promise.all(
    SENSITIVE.map(async (s) => {
      try {
        const r = await safeFetch(origin + s.path, { timeoutMs: 6000, followRedirects: false, maxBytes: 20000 });
        const hit = r.status === 200 && s.test(r.body, r.headers.get("content-type") ?? "");
        return { s, hit };
      } catch {
        return { s, hit: false };
      }
    }),
  );
  const hits = sens.filter((x) => x.hit);
  for (const { s } of hits)
    checks.push({ id: `file-${s.path}`, category: "Hassas dosyalar", title: s.title, status: "fail", severity: s.severity, detail: `${s.path} herkese açık şekilde erişilebilir.`, value: origin + s.path, recommendation: "Bu dosyaya web üzerinden erişimi engelleyin ve içeriğini gözden geçirin." });
  if (!hits.length) checks.push({ id: "files", category: "Hassas dosyalar", title: "Yaygın hassas dosyalar", status: "pass", severity: "bilgi", detail: `${SENSITIVE.length} yaygın hassas yol kontrol edildi, erişilebilir olan bulunamadı.` });

  // robots.txt ve security.txt
  let robots: SecurityResult["robots"];
  try {
    const r = await safeFetch(`${origin}/robots.txt`, { timeoutMs: 6000, maxBytes: 100000 });
    if (r.status === 200 && !/<html/i.test(r.body.slice(0, 500))) {
      const lines = r.body.split(/\r?\n/);
      robots = {
        disallow: [...new Set(lines.filter((l) => /^\s*disallow\s*:/i.test(l)).map((l) => l.split(":").slice(1).join(":").trim()).filter(Boolean))].slice(0, 100),
        sitemaps: lines.filter((l) => /^\s*sitemap\s*:/i.test(l)).map((l) => l.split(":").slice(1).join(":").trim()).slice(0, 20),
      };
    }
  } catch {
    /* yok */
  }
  try {
    const r = await safeFetch(`${origin}/.well-known/security.txt`, { timeoutMs: 6000, maxBytes: 20000 });
    const ok = r.status === 200 && /contact:/i.test(r.body);
    checks.push({ id: "securitytxt", category: "Yapılandırma", title: "security.txt", status: ok ? "pass" : "info", severity: "bilgi", detail: ok ? "Güvenlik bildirim iletişim bilgisi yayınlanmış." : "security.txt bulunamadı (zafiyet bildirimi için önerilir)." });
  } catch {
    /* yok */
  }

  const penalty = checks.reduce((sum, ch) => sum + (ch.status === "fail" ? SEVERITY_WEIGHT[ch.severity] : ch.status === "warn" ? SEVERITY_WEIGHT[ch.severity] / 2 : 0), 0);
  const score = Math.max(0, Math.round(100 - penalty));
  const headers: SecurityResult["headers"] = [];
  res.headers.forEach((value, name) => headers.push({ name, value }));

  return {
    target: startUrl,
    finalUrl: res.finalUrl,
    status: res.status,
    redirects: res.redirects,
    score,
    grade: gradeOf(score),
    checks,
    headers: headers.sort((a, b) => a.name.localeCompare(b.name)),
    tls: tlsInfo,
    robots,
    technologies: detectTech(res.headers, res.body),
  };
}
