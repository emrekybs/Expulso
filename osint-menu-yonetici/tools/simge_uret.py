#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OSINT simge paketini (simgeler/*.svg ve simgeler/liste.json) üretir.

  python3 tools/simge_uret.py

Her simge renkli bir daire üzerinde beyaz bir çizimdir; menüdeki
Kali/OSINT simgeleriyle uyumlu görünür. Yeni simge eklemek için ICONS
listesine bir satır ekleyip betiği tekrar çalıştırmanız yeterli.
"""
import json
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "simgeler")

W = 'stroke="#fff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" fill="none"'
F = 'fill="#fff"'
T = 'fill="#fff" font-family="DejaVu Sans, Liberation Sans, Arial, sans-serif" ' \
    'font-weight="bold" text-anchor="middle"'


def text(s, size=22, y=40):
    return '<text x="32" y="%s" font-size="%s" %s>%s</text>' % (y, size, T, s)


GLYPHS = {
    "osint": '<circle cx="28" cy="28" r="10" %s/><path d="M36 36l10 10" %s/>'
             '<path d="M18 28h20M28 18c-4 6-4 14 0 20M28 18c4 6 4 14 0 20" '
             'stroke="#fff" stroke-width="2" fill="none"/>' % (W, W),
    "sosyal-medya": '<circle cx="22" cy="32" r="5" %s/><circle cx="42" cy="21" r="5" %s/>'
                    '<circle cx="42" cy="43" r="5" %s/><path d="M26.5 29.5l11-6M26.5 34.5l11 6" %s/>'
                    % (F, F, F, W),
    "eposta": '<rect x="16" y="21" width="32" height="22" rx="3" %s/>'
              '<path d="M17 23l15 11 15-11" %s/>' % (W, W),
    "at-isareti": text("@", 30, 42),
    "telefon": '<path d="M22 17c2-1 4-1 5 1l3 6c1 2 0 3-1 4l-2 2c1 4 5 8 9 9l2-2c1-1 2-2 4-1'
               'l6 3c2 1 2 3 1 5l-2 3c-2 2-5 2-8 1-9-3-17-11-20-20-1-3-1-6 1-8z" %s/>' % F,
    "kullanici": '<circle cx="32" cy="25" r="8" %s/><path d="M17 47c1-8 7-13 15-13s14 5 15 13z" %s/>'
                 % (F, F),
    "kisi-arama": '<circle cx="27" cy="24" r="6.5" %s/><path d="M15 43c1-7 6-11 12-11 3 0 5 1 7 2" %s/>'
                  '<circle cx="40" cy="39" r="5.5" %s/><path d="M44 43l5 5" %s/>' % (F, W, W, W),
    "parmak-izi": '<path d="M22 44c-3-4-4-8-4-12a14 14 0 0 1 28 0M27 47c-2-4-3-9-3-14a8 8 0 0 1 16 0'
                  'c0 4 0 7-1 10M32 48c-2-5-2-10-2-15M38 46c1-3 1-6 1-9M46 37c0 3-1 6-2 8" %s/>' % W,
    "alan-adi": '<circle cx="32" cy="32" r="15" %s/><path d="M17 32h30M32 17c-6 8-6 22 0 30'
                'M32 17c6 8 6 22 0 30M20 24h24M20 40h24" stroke="#fff" stroke-width="2.5" '
                'fill="none"/>' % W,
    "ip-adresi": '<rect x="15" y="20" width="34" height="24" rx="4" %s/>%s' % (W, text("IP", 15, 37)),
    "dns": '<rect x="18" y="16" width="28" height="9" rx="2" %s/><rect x="18" y="28" width="28" '
           'height="9" rx="2" %s/><path d="M32 37v6M20 47h24" %s/><circle cx="23" cy="20.5" r="1.5" %s/>'
           '<circle cx="23" cy="32.5" r="1.5" %s/>' % (W, W, W, F, F),
    "ag": '<circle cx="32" cy="20" r="5" %s/><circle cx="19" cy="42" r="5" %s/>'
          '<circle cx="45" cy="42" r="5" %s/><path d="M30 24.5l-8 13M34 24.5l8 13M24 42h16" %s/>'
          % (F, F, F, W),
    "konum": '<path d="M32 49s-13-13-13-22a13 13 0 0 1 26 0c0 9-13 22-13 22z" %s/>'
             '<circle cx="32" cy="27" r="5" fill="#000" fill-opacity="0.25"/>' % F,
    "harita": '<path d="M16 21l10-4 12 4 10-4v26l-10 4-12-4-10 4z" %s/><path d="M26 17v26M38 21v26" %s/>'
              % (W, W),
    "resim": '<rect x="16" y="19" width="32" height="26" rx="3" %s/><circle cx="25" cy="27" r="3" %s/>'
             '<path d="M18 43l9-9 6 6 5-5 9 8" %s/>' % (W, F, W),
    "kamera": '<path d="M16 26c0-2 1-3 3-3h5l3-4h10l3 4h5c2 0 3 1 3 3v15c0 2-1 3-3 3H19c-2 0-3-1-3-3z" %s/>'
              '<circle cx="32" cy="33" r="6" %s/>' % (W, W),
    "video": '<path d="M26 20l18 12-18 12z" %s/>' % F,
    "dark-web": '<path d="M32 15c-2 6-12 10-12 21a12 12 0 0 0 24 0c0-11-10-15-12-21z" %s/>'
                '<path d="M32 22c-1 5-6 8-6 14a6 6 0 0 0 12 0c0-6-5-9-6-14z" %s/>'
                '<path d="M32 30v12" stroke="#fff" stroke-width="2.5"/>' % (W, W),
    "kripto": '<circle cx="32" cy="32" r="15" %s/>%s' % (W, text("₿", 20, 39)),
    "sizinti": '<ellipse cx="29" cy="20" rx="11" ry="4" %s/><path d="M18 20v20c0 2 5 4 11 4M40 20v9'
               'M18 30c0 2 5 4 11 4" %s/><path d="M42 33c3 4 5 6 5 9a5 5 0 0 1-10 0c0-3 2-5 5-9z" %s/>'
               % (W, W, F),
    "parola": '<circle cx="24" cy="32" r="7" %s/><path d="M31 32h17M42 32v6M47 32v5" %s/>' % (W, W),
    "kilit": '<rect x="19" y="29" width="26" height="19" rx="3" %s/><path d="M24 29v-5a8 8 0 0 1 16 0v5" %s/>'
             % (F, W),
    "kalkan": '<path d="M32 15l14 5v10c0 9-6 16-14 19-8-3-14-10-14-19V20z" %s/>'
              '<path d="M25 32l5 5 9-10" %s/>' % (W, W),
    "goz": '<path d="M14 32s7-11 18-11 18 11 18 11-7 11-18 11-18-11-18-11z" %s/>'
           '<circle cx="32" cy="32" r="5" %s/>' % (W, F),
    "hedef": '<circle cx="32" cy="32" r="13" %s/><circle cx="32" cy="32" r="5" %s/>'
             '<path d="M32 14v8M32 42v8M14 32h8M42 32h8" %s/>' % (W, F, W),
    "radar": '<circle cx="32" cy="32" r="15" %s/><circle cx="32" cy="32" r="8" stroke="#fff" '
             'stroke-width="2" fill="none"/><path d="M32 32l10-10" %s/><circle cx="38" cy="38" r="2" %s/>'
             % (W, W, F),
    "uydu": '<rect x="27" y="27" width="10" height="10" rx="1" transform="rotate(45 32 32)" %s/>'
            '<path d="M18 22l6 6M22 18l6 6M40 36l6 6M36 40l6 6" %s/>'
            '<path d="M17 38a9 9 0 0 0 9 9M17 44a3 3 0 0 0 3 3" %s/>' % (F, W, W),
    "wifi": '<path d="M16 28a23 23 0 0 1 32 0M21 34a15 15 0 0 1 22 0M26 40a7 7 0 0 1 12 0" %s/>'
            '<circle cx="32" cy="45" r="2.5" %s/>' % (W, F),
    "ucak": '<path d="M30 15c1-2 3-2 4 0v12l14 8v4l-14-4v8l4 3v3l-6-2-6 2v-3l4-3v-8l-14 4v-4l14-8z" %s/>'
            % F,
    "sirket": '<path d="M18 48V18h18v30M36 26h10v22M14 48h36" %s/><path d="M24 24h2M30 24h2M24 31h2M30 31h2'
              'M24 38h2M30 38h2M41 33h1M41 40h1" %s/>' % (W, W),
    "belge": '<path d="M20 15h17l8 8v26H20z" %s/><path d="M37 15v8h8M25 30h14M25 36h14M25 42h9" %s/>'
             % (W, W),
    "rapor": '<path d="M19 46V18M19 46h28" %s/><path d="M25 40v-8M32 40V25M39 40v-11M46 40v-5" %s/>' % (W, W),
    "arsiv": '<rect x="16" y="18" width="32" height="8" rx="2" %s/><path d="M19 26v20h26V26M28 33h8" %s/>'
             % (W, W),
    "bulut": '<path d="M23 44a8 8 0 0 1-1-16 11 11 0 0 1 21-3 9 9 0 0 1 2 19z" %s/>' % F,
    "sohbet": '<path d="M16 22c0-3 2-5 5-5h22c3 0 5 2 5 5v13c0 3-2 5-5 5H29l-8 7v-7c-3 0-5-2-5-5z" %s/>'
              '<circle cx="25" cy="29" r="2" %s/><circle cx="32" cy="29" r="2" %s/><circle cx="39" cy="29" '
              'r="2" %s/>' % (W, F, F, F),
    "hashtag": text("#", 30, 42),
    "kod": '<path d="M25 22l-9 10 9 10M39 22l9 10-9 10M35 18l-6 28" %s/>' % W,
    "terminal": '<rect x="14" y="18" width="36" height="28" rx="3" %s/><path d="M21 27l6 5-6 5M30 39h11" %s/>'
                % (W, W),
    "arac": '<path d="M41 16a9 9 0 0 0-10 12L17 42a3 3 0 0 0 5 5l14-14a9 9 0 0 0 12-10l-6 6-5-1-1-5z" %s/>' % F,
    "bocek": '<ellipse cx="32" cy="35" rx="9" ry="12" %s/><path d="M27 22a5 5 0 0 1 10 0M23 30h-7'
             'M23 38h-7M41 30h7M41 38h7M25 45l-5 4M39 45l5 4M32 25v22" %s/>' % (W, W),
    "zaman": '<circle cx="32" cy="32" r="15" %s/><path d="M32 23v10l7 4" %s/>' % (W, W),
    "veritabani": '<ellipse cx="32" cy="20" rx="13" ry="5" %s/><path d="M19 20v24c0 3 6 5 13 5s13-2 13-5V20'
                  'M19 32c0 3 6 5 13 5s13-2 13-5" %s/>' % (W, W),
    "arama": '<circle cx="29" cy="29" r="11" %s/><path d="M37 37l10 10" %s/>' % (W, W),
    "yildiz": '<path d="M32 15l5 11 12 1-9 8 3 12-11-6-11 6 3-12-9-8 12-1z" %s/>' % F,
}

# (dosya adı, renk, Türkçe ad, arama anahtar kelimeleri)
ICONS = [
    ("osint", "#367bf0", "OSINT", "genel osint istihbarat açık kaynak"),
    ("arama", "#2a7fff", "Arama", "search ara bul recon keşif"),
    ("sosyal-medya", "#e01b8a", "Sosyal Medya", "social media instagram twitter facebook"),
    ("eposta", "#5e5ce6", "E-posta", "email mail posta"),
    ("at-isareti", "#7b61ff", "@ İşareti", "email kullanıcı adı username at"),
    ("telefon", "#f57900", "Telefon Numarası", "phone number gsm telefon"),
    ("kullanici", "#26a269", "Kullanıcı Adı", "username kullanıcı kişi"),
    ("kisi-arama", "#2ec27e", "Kişi Arama", "person people kişi arama"),
    ("parmak-izi", "#1c71d8", "Parmak İzi / Kimlik", "fingerprint kimlik identity"),
    ("alan-adi", "#0b8fa8", "Alan Adı / Web", "domain website web alan adı whois"),
    ("ip-adresi", "#3584e4", "IP Adresi", "ip adres network"),
    ("dns", "#1a5fb4", "DNS / Sunucu", "dns server sunucu subdomain"),
    ("ag", "#0e7c86", "Ağ", "network ağ graph bağlantı"),
    ("konum", "#e01b24", "Konum", "location geo konum gps"),
    ("harita", "#2b9348", "Harita", "map harita geoint"),
    ("resim", "#c061cb", "Görsel", "image photo görsel resim exif"),
    ("kamera", "#9141ac", "Kamera / CCTV", "camera kamera cctv webcam"),
    ("video", "#e62117", "Video", "video youtube indir"),
    ("dark-web", "#613583", "Dark Web / Tor", "dark web tor onion"),
    ("kripto", "#f7931a", "Kripto Para", "crypto bitcoin kripto blockchain"),
    ("sizinti", "#c01c28", "Veri Sızıntısı", "leak breach sızıntı veri"),
    ("veritabani", "#865e3c", "Veritabanı", "database veritabanı db"),
    ("parola", "#e5a50a", "Parola / Anahtar", "password parola şifre key"),
    ("kilit", "#986a44", "Kilit / Güvenlik", "lock kilit güvenlik"),
    ("kalkan", "#1e8449", "Kalkan / Savunma", "shield kalkan savunma defense"),
    ("goz", "#0f6b5c", "Gözetleme", "eye göz izleme monitor"),
    ("hedef", "#c64600", "Hedef / Keşif", "target hedef recon keşif"),
    ("radar", "#2d8a3e", "Radar / Tarama", "radar tarama scan"),
    ("uydu", "#3d3846", "Uydu", "satellite uydu"),
    ("wifi", "#1c71d8", "Kablosuz Ağ", "wifi wireless kablosuz"),
    ("ucak", "#1a5fb4", "Uçuş Takibi", "flight uçak plane uçuş"),
    ("sirket", "#5e5c64", "Şirket / Kurum", "company şirket kurum business"),
    ("belge", "#4a6fa5", "Belge", "document belge pdf metadata"),
    ("rapor", "#26a269", "Raporlama", "report rapor grafik chart"),
    ("arsiv", "#8f6c3c", "Web Arşivi", "archive arşiv wayback"),
    ("bulut", "#62a0ea", "Bulut", "cloud bulut"),
    ("sohbet", "#2aabee", "Mesajlaşma", "chat telegram whatsapp mesaj"),
    ("hashtag", "#1d9bf0", "Hashtag", "hashtag etiket twitter"),
    ("kod", "#24292f", "Kod / GitHub", "code github kod git"),
    ("terminal", "#2e3436", "Terminal", "terminal komut cli"),
    ("arac", "#77767b", "Araç", "tool araç utility"),
    ("bocek", "#a51d2d", "Zafiyet", "bug zafiyet vulnerability"),
    ("zaman", "#5e5ce6", "Zaman Çizelgesi", "time zaman timeline"),
    ("yildiz", "#f6d32d", "Favori", "star yıldız favori"),
]

SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <circle cx="32" cy="32" r="30" fill="{color}"/>
  <circle cx="32" cy="32" r="30" fill="url(#p)" opacity="0.25"/>
  <defs><linearGradient id="p" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#fff"/><stop offset="1" stop-color="#000"/>
  </linearGradient></defs>
  {glyph}
</svg>
"""


def main():
    os.makedirs(OUT, exist_ok=True)
    meta = []
    for name, color, label, keywords in ICONS:
        with open(os.path.join(OUT, "osint-%s.svg" % name), "w", encoding="utf-8") as f:
            f.write(SVG.format(color=color, glyph=GLYPHS[name]))
        meta.append({"file": "osint-%s.svg" % name, "label": label, "keywords": keywords})
    with open(os.path.join(OUT, "liste.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("%d simge üretildi: %s" % (len(meta), os.path.normpath(OUT)))


if __name__ == "__main__":
    main()
