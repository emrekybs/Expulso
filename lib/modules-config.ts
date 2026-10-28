// İstemci tarafında da kullanılan modül tanımları (sidebar, sayfalar, arama).
import type { TargetKind } from "./target.ts";

export type ModuleId =
  | "uscrapper"
  | "subdomain"
  | "dns"
  | "whois"
  | "reverse-ip"
  | "geoip"
  | "reverse-dns"
  | "traceroute"
  | "port-scan"
  | "security";

export type ModuleGroup = "Web OSINT" | "Keşif" | "Ağ Analizi" | "Zafiyet";

export interface ModuleDef {
  id: ModuleId;
  title: string;
  short: string;
  description: string;
  group: ModuleGroup;
  accepts: TargetKind[];
  placeholder: string;
  sources: string[];
  /** HackerTarget ücretsiz limitine tabi mi */
  quota?: boolean;
  badge?: string;
}

export const MODULES: ModuleDef[] = [
  {
    id: "uscrapper",
    title: "Uscrapper — Web Kazıyıcı",
    short: "Uscrapper",
    description:
      "Web sitesinden e-posta adresleri, sosyal medya bağlantıları, yazar adları, coğrafi konumlar, telefon numaraları ve kullanıcı adlarını toplar. Aynı alan adında tarama (crawl) ve anahtar kelime araması destekler.",
    group: "Web OSINT",
    accepts: ["domain", "url"],
    placeholder: "https://ornek.com veya ornek.com",
    sources: ["Uscrapper mantığı (z0m31en7/Uscrapper)"],
    badge: "Yeni",
  },
  {
    id: "subdomain",
    title: "Alt Alan Adı Keşfi",
    short: "Subdomain Keşfi",
    description: "Sertifika şeffaflık kayıtları ve pasif DNS kaynaklarından alt alan adlarını toplar, aktif olanları DNS ile doğrular.",
    group: "Keşif",
    accepts: ["domain", "url"],
    placeholder: "ornek.com",
    sources: ["crt.sh", "HackerTarget", "AlienVault OTX", "Anubis", "CertSpotter"],
  },
  {
    id: "dns",
    title: "DNS Kayıtları",
    short: "DNS Kayıtları",
    description: "A, AAAA, CNAME, MX, NS, TXT, SOA ve CAA kayıtlarını sorgular; SPF/DMARC e-posta güvenliğini ve kullanılan servisleri analiz eder.",
    group: "Keşif",
    accepts: ["domain", "url"],
    placeholder: "ornek.com",
    sources: ["Cloudflare DoH", "Google DoH"],
  },
  {
    id: "whois",
    title: "WHOIS / RDAP",
    short: "WHOIS",
    description: "Alan adı veya IP adresinin kayıt bilgilerini, kayıt şirketini, tarihleri, durumları ve irtibat bilgilerini gösterir.",
    group: "Keşif",
    accepts: ["domain", "ip", "url"],
    placeholder: "ornek.com veya 8.8.8.8",
    sources: ["RDAP", "HackerTarget WHOIS"],
  },
  {
    id: "reverse-ip",
    title: "Ters IP Araması",
    short: "Ters IP",
    description: "Aynı IP adresinde barındırılan diğer alan adlarını listeler (paylaşımlı barındırma analizi).",
    group: "Keşif",
    accepts: ["domain", "ip", "url"],
    placeholder: "ornek.com veya 1.2.3.4",
    sources: ["HackerTarget"],
    quota: true,
  },
  {
    id: "geoip",
    title: "IP Konum (GeoIP)",
    short: "GeoIP",
    description: "IP adresinin ülke, şehir, ASN, kuruluş ve servis sağlayıcı bilgilerini harita üzerinde gösterir.",
    group: "Ağ Analizi",
    accepts: ["domain", "ip", "url"],
    placeholder: "8.8.8.8 veya ornek.com",
    sources: ["ipwho.is", "HackerTarget"],
  },
  {
    id: "reverse-dns",
    title: "Ters DNS",
    short: "Ters DNS",
    description: "IP adreslerinin PTR kayıtlarını (ana makine adlarını) çözer. IP aralıkları (CIDR) da desteklenir.",
    group: "Ağ Analizi",
    accepts: ["ip", "cidr", "domain", "url"],
    placeholder: "8.8.8.8 veya 8.8.8.0/24",
    sources: ["DoH PTR", "HackerTarget"],
  },
  {
    id: "traceroute",
    title: "Traceroute",
    short: "Traceroute",
    description: "Hedefe giden ağ rotasını, her atlamanın gecikme ve paket kaybı değerleriyle gösterir.",
    group: "Ağ Analizi",
    accepts: ["domain", "ip", "url"],
    placeholder: "ornek.com veya 1.1.1.1",
    sources: ["HackerTarget MTR"],
    quota: true,
  },
  {
    id: "port-scan",
    title: "Port Tarama",
    short: "Port Tarama",
    description: "Yaygın TCP portlarını tarar, açık servisleri risk seviyesi ve Türkçe açıklamalarla listeler.",
    group: "Zafiyet",
    accepts: ["domain", "ip", "url"],
    placeholder: "ornek.com veya 1.2.3.4",
    sources: ["HackerTarget Nmap"],
    quota: true,
  },
  {
    id: "security",
    title: "Güvenlik Taraması",
    short: "Güvenlik Taraması",
    description:
      "HTTP güvenlik başlıkları, çerez bayrakları, TLS sertifikası, bilgi ifşası ve açıkta kalan hassas dosyaları (.git, .env vb.) pasif olarak kontrol eder ve not verir.",
    group: "Zafiyet",
    accepts: ["domain", "url"],
    placeholder: "https://ornek.com",
    sources: ["Doğrudan HTTP/TLS analizi"],
  },
];

export const GROUP_ORDER: ModuleGroup[] = ["Web OSINT", "Keşif", "Ağ Analizi", "Zafiyet"];

export function getModule(id: string): ModuleDef | undefined {
  return MODULES.find((m) => m.id === id);
}
