// Uscrapper (https://github.com/z0m31en7/Uscrapper, MIT) çıkarım mantığının
// TypeScript portu. Ağ erişimi içermez; böylece test edilebilir.
import * as cheerio from "cheerio";
import type { AnyNode } from "domhandler";

export const SOCIAL_PLATFORMS = [
  "instagram",
  "facebook",
  "whatsapp",
  "snapchat",
  "github",
  "reddit",
  "youtube",
  "linkedin",
  "twitter",
  "telegram",
  "discord",
  "pinterest",
  "x.com",
  // Orijinal listeye ek olarak:
  "tiktok",
  "t.me",
  "youtu.be",
  "medium.com",
  "vk.com",
  "mastodon",
  "threads.net",
  "bsky.app",
] as const;

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
// Orijinal üç telefon regex'i + uluslararası/TR formatı (+90 212 555 12 34)
const PHONE_RE = new RegExp(
  [
    String.raw`\b\+?\d{10,12}\b`,
    String.raw`(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}\)?[- ]?\d{4}\b`,
    String.raw`\(\d{3}\)\s\d{3}\s\d{5}`,
    String.raw`\+\d{1,3}[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}\b`,
  ]
    .map((x) => `(?:${x})`)
    .join("|"),
  "g",
);
const USERNAME_RE = /(?<![\w.@])@[A-Za-z0-9_]{2,}/g;
const ASSET_EXT = /\.(png|jpe?g|gif|svg|webp|ico|css|js)$/i;

const INLINE = new Set(["a", "span", "b", "strong", "i", "em", "small", "sup", "sub", "u", "abbr", "code", "label", "font", "mark", "s", "time"]);
const SKIP = new Set(["script", "style", "noscript", "template", "svg"]);

/** Sayfanın görünür metni (blok elemanlar arasına boşluk ekleyerek). */
export function visibleText($: cheerio.CheerioAPI): string {
  const out: string[] = [];
  const walk = (nodes: AnyNode[]) => {
    for (const n of nodes) {
      if (n.type === "text") out.push((n as unknown as { data: string }).data);
      else if (n.type === "tag" || n.type === "script" || n.type === "style") {
        const el = n as unknown as { name: string; children: AnyNode[]; attribs: Record<string, string> };
        if (SKIP.has(el.name) && !(el.name === "script" && el.attribs?.type === "application/ld+json")) continue;
        walk(el.children);
        if (!INLINE.has(el.name)) out.push(" ");
      }
    }
  };
  walk($.root().children().toArray());
  return out.join("").replace(/[ \t ]+/g, " ");
}

export interface PageExtraction {
  title: string;
  emails: string[];
  socialLinks: { url: string; platform: string }[];
  authors: string[];
  geolocations: string[];
  textEmails: string[];
  phones: string[];
  usernames: string[];
  links: string[];
}

export function platformOf(href: string): string | null {
  const l = href.toLowerCase();
  for (const p of SOCIAL_PLATFORMS) if (l.includes(p)) return p;
  return null;
}

const PLATFORM_LABEL: Record<string, string> = {
  "x.com": "X (Twitter)",
  twitter: "X (Twitter)",
  "t.me": "Telegram",
  "youtu.be": "YouTube",
  "medium.com": "Medium",
  "vk.com": "VK",
  "threads.net": "Threads",
  "bsky.app": "Bluesky",
  github: "GitHub",
  linkedin: "LinkedIn",
  youtube: "YouTube",
  tiktok: "TikTok",
  whatsapp: "WhatsApp",
};
export function platformLabel(p: string): string {
  return PLATFORM_LABEL[p] ?? p.charAt(0).toUpperCase() + p.slice(1);
}

export function extractFromHtml(html: string, pageUrl: string, nonStrict: boolean): PageExtraction {
  const $ = cheerio.load(html);
  const title = $("title").first().text().trim().slice(0, 200);
  const base = new URL(pageUrl);

  const emails = new Set<string>();
  const socialLinks = new Map<string, string>();
  const links = new Set<string>();

  $("a[href]").each((_, a) => {
    const href = ($(a).attr("href") ?? "").trim();
    if (!href) return;
    if (href.toLowerCase().includes("mailto:")) {
      const addr = decodeURIComponentSafe(href.replace(/^.*?mailto:/i, "").split("?")[0]);
      for (const one of addr.split(/[,;]/)) if (one.trim()) emails.add(one.trim());
      return;
    }
    const plat = platformOf(href);
    if (plat) socialLinks.set(href, plat);
    try {
      const abs = new URL(href, base);
      abs.hash = "";
      if ((abs.protocol === "http:" || abs.protocol === "https:") && abs.host === base.host) links.add(abs.toString());
    } catch {
      /* geçersiz bağlantı */
    }
  });

  const authors = new Set<string>();
  $('meta[name="author" i]').each((_, m) => {
    const c = $(m).attr("content")?.trim();
    if (c) authors.add(c);
  });
  const geolocations = new Set<string>();
  $('meta[name="geo.position" i], meta[name="ICBM" i]').each((_, m) => {
    const c = $(m).attr("content")?.trim();
    if (c) geolocations.add(c);
  });
  $('meta[name="geo.placename" i]').each((_, m) => {
    const c = $(m).attr("content")?.trim();
    if (c) geolocations.add(c);
  });

  const text = visibleText($);

  const textEmails = new Set<string>();
  for (const m of text.matchAll(EMAIL_RE)) {
    let e = m[0];
    if (e.toLowerCase().startsWith("email")) e = e.slice(5); // orijinal davranış
    if (!ASSET_EXT.test(e) && e.includes("@")) textEmails.add(e);
  }

  const phones = new Set<string>();
  for (const m of text.matchAll(PHONE_RE)) {
    const p = m[0].trim();
    const digits = p.replace(/\D/g, "");
    if (digits.length >= 10 && digits.length <= 15 && !/^(\d)\1+$/.test(digits)) phones.add(p);
  }

  const usernames = new Set<string>();
  if (nonStrict) for (const m of text.matchAll(USERNAME_RE)) usernames.add(m[0]);

  return {
    title,
    emails: [...emails],
    socialLinks: [...socialLinks].map(([url, platform]) => ({ url, platform })),
    authors: [...authors],
    geolocations: [...geolocations],
    textEmails: [...textEmails],
    phones: [...phones],
    usernames: [...usernames],
    links: [...links],
  };
}

/** Anahtar kelime modunda: sayfa metninde geçen kelimeler (büyük/küçük harf duyarsız). */
export function matchKeywords(html: string, keywords: string[]): string[] {
  const lower = html.toLocaleLowerCase("tr-TR");
  const lowerEn = html.toLowerCase();
  return keywords.filter((k) => lower.includes(k.toLocaleLowerCase("tr-TR")) || lowerEn.includes(k.toLowerCase()));
}

function decodeURIComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
