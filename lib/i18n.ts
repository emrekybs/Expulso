// Türkçe çeviri yardımcıları. Değerler (alan adları, IP'ler vb.) asla
// değiştirilmez; yalnızca etiketler ve durum açıklamaları çevrilir.

let regionNames: Intl.DisplayNames | null = null;
export function countryName(code?: string | null): string {
  if (!code) return "";
  try {
    regionNames ??= new Intl.DisplayNames(["tr"], { type: "region" });
    return regionNames.of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

export function flagEmoji(code?: string | null): string {
  if (!code || !/^[a-z]{2}$/i.test(code)) return "";
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

export function formatDate(v?: string | number | Date | null, withTime = false): string {
  if (!v) return "";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return String(v);
  return d.toLocaleString("tr-TR", {
    day: "2-digit",
    month: "long",
    year: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
    timeZone: "Europe/Istanbul",
  });
}

export function relativeDays(v?: string | null): number | null {
  if (!v) return null;
  const d = new Date(v).getTime();
  if (Number.isNaN(d)) return null;
  return Math.round((d - Date.now()) / 86_400_000);
}

const STATUS_TR: Record<string, string> = {
  active: "Aktif",
  inactive: "Pasif",
  ok: "Normal",
  locked: "Kilitli",
  "client transfer prohibited": "İstemci transferi yasak",
  "client delete prohibited": "İstemci silmesi yasak",
  "client update prohibited": "İstemci güncellemesi yasak",
  "client renew prohibited": "İstemci yenilemesi yasak",
  "client hold": "İstemci tarafından askıda",
  "server transfer prohibited": "Sunucu transferi yasak",
  "server delete prohibited": "Sunucu silmesi yasak",
  "server update prohibited": "Sunucu güncellemesi yasak",
  "server renew prohibited": "Sunucu yenilemesi yasak",
  "server hold": "Sunucu tarafından askıda",
  "pending create": "Oluşturma bekliyor",
  "pending delete": "Silinme bekliyor",
  "pending renew": "Yenileme bekliyor",
  "pending transfer": "Transfer bekliyor",
  "pending update": "Güncelleme bekliyor",
  "redemption period": "Geri alım dönemi",
  "pending restore": "Geri yükleme bekliyor",
  "add period": "Ekleme dönemi",
  "auto renew period": "Otomatik yenileme dönemi",
  "renew period": "Yenileme dönemi",
  "transfer period": "Transfer dönemi",
  "associated": "İlişkili",
  "removed": "Kaldırıldı",
  "obscured": "Gizlenmiş",
  "private": "Gizli",
  "proxy": "Vekil (proxy)",
  validated: "Doğrulanmış",
};

/** "clientTransferProhibited https://icann.org/epp#..." gibi değerleri çevirir. */
export function translateStatus(raw: string): string {
  const clean = raw
    .replace(/https?:\/\/\S+/g, "")
    .replace(/\(.*?\)/g, "")
    .trim()
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase();
  return STATUS_TR[clean] ?? raw.replace(/https?:\/\/\S+/g, "").trim();
}

export const EVENT_TR: Record<string, string> = {
  registration: "Kayıt tarihi",
  expiration: "Bitiş tarihi",
  "last changed": "Son değişiklik",
  "last update of rdap database": "RDAP veritabanı güncellemesi",
  transfer: "Transfer tarihi",
  reregistration: "Yeniden kayıt",
  locked: "Kilitlenme",
  unlocked: "Kilit açılma",
  deletion: "Silinme",
  reinstantiation: "Yeniden etkinleştirme",
};

export const ROLE_TR: Record<string, string> = {
  registrant: "Kayıt sahibi",
  registrar: "Kayıt şirketi",
  administrative: "İdari irtibat",
  technical: "Teknik irtibat",
  abuse: "Kötüye kullanım irtibatı",
  billing: "Fatura irtibatı",
  reseller: "Bayi",
  sponsor: "Sponsor",
  noc: "Ağ operasyon merkezi (NOC)",
  proxy: "Vekil",
};

const WHOIS_KEYS: [RegExp, string][] = [
  [/^domain( name)?$/i, "Alan adı"],
  [/^registry domain id$/i, "Kayıt ID"],
  [/^registrar whois server$/i, "Kayıt şirketi WHOIS sunucusu"],
  [/^registrar url$/i, "Kayıt şirketi web adresi"],
  [/^(updated date|last updated|last modified|changed)( on)?$/i, "Güncellenme tarihi"],
  [/^(creation date|created( on)?|registered( on)?|registration time)$/i, "Oluşturulma tarihi"],
  [/^(registry expiry date|registrar registration expiration date|expir(y|ation) date|expires( on)?|paid-till)$/i, "Bitiş tarihi"],
  [/^(registrar|sponsoring registrar|registrar name|organization name)$/i, "Kayıt şirketi"],
  [/^registrar iana id$/i, "Kayıt şirketi IANA ID"],
  [/^registrar abuse contact email$/i, "Kötüye kullanım e-postası"],
  [/^registrar abuse contact phone$/i, "Kötüye kullanım telefonu"],
  [/^(domain status|status)$/i, "Durum"],
  [/^(name server|nserver|nameservers?)$/i, "Ad sunucusu"],
  [/^dnssec$/i, "DNSSEC"],
  [/^registrant( name)?$/i, "Kayıt sahibi"],
  [/^registrant organi[sz]ation$/i, "Kayıt sahibi kuruluş"],
  [/^registrant country$/i, "Kayıt sahibi ülke"],
  [/^registrant state\/province$/i, "Kayıt sahibi il/eyalet"],
  [/^registrant city$/i, "Kayıt sahibi şehir"],
  [/^registrant email$/i, "Kayıt sahibi e-posta"],
  [/^registrant phone$/i, "Kayıt sahibi telefon"],
  [/^admin (name|organi[sz]ation)$/i, "İdari irtibat"],
  [/^admin email$/i, "İdari irtibat e-posta"],
  [/^tech (name|organi[sz]ation)$/i, "Teknik irtibat"],
  [/^tech email$/i, "Teknik irtibat e-posta"],
  [/^netrange$/i, "Ağ aralığı"],
  [/^inetnum$/i, "Ağ aralığı"],
  [/^cidr$/i, "CIDR"],
  [/^(netname|net name)$/i, "Ağ adı"],
  [/^nethandle$/i, "Ağ tanıtıcısı"],
  [/^parent$/i, "Üst ağ"],
  [/^nettype$/i, "Ağ türü"],
  [/^originas|^origin$/i, "Kaynak AS"],
  [/^(orgname|org-name|organization|org)$/i, "Kuruluş"],
  [/^orgid$/i, "Kuruluş ID"],
  [/^(address|street)$/i, "Adres"],
  [/^city$/i, "Şehir"],
  [/^(stateprov|state)$/i, "İl / eyalet"],
  [/^postalcode$/i, "Posta kodu"],
  [/^country$/i, "Ülke"],
  [/^regdate$/i, "Kayıt tarihi"],
  [/^updated$/i, "Güncellenme tarihi"],
  [/^descr$/i, "Açıklama"],
  [/^(orgabuseemail|abuse-mailbox)$/i, "Kötüye kullanım e-postası"],
  [/^(orgabusephone)$/i, "Kötüye kullanım telefonu"],
  [/^(orgtechemail)$/i, "Teknik e-posta"],
  [/^source$/i, "Kaynak"],
];

export function translateWhoisKey(key: string): string {
  const k = key.trim();
  for (const [re, tr] of WHOIS_KEYS) if (re.test(k)) return tr;
  return k;
}
