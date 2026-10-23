#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tek dosyalık kurulum betiği (osint-kur.sh) üretir.

  python3 tools/script_uret.py liste/araclar.ini -o osint-kur.sh

Üretilen betik: sistemi günceller, gerekli paketleri kurar, OSINT Menü
Yöneticisi'ni kurar ve listedeki bütün araçları menüye ekler. Uygulama
dosyaları, simgeler ve araç listesi betiğin içine gömülüdür.
"""
import argparse
import base64
import io
import os
import tarfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Kurulacak sistem paketleri (biri bulunamazsa diğerleri yine kurulur)
PACKAGES = [
    "git", "curl", "wget", "ca-certificates", "python3", "python3-pip", "python3-venv",
    "python3-dev", "build-essential", "libffi-dev", "libssl-dev", "pkg-config", "pipx",
    "python3-gi", "gir1.2-gtk-3.0", "golang-go", "cargo", "rustc", "nodejs", "npm",
    "tor", "torbrowser-launcher", "chromium", "firefox-esr", "libimage-exiftool-perl",
    "kismet", "sparrow-wifi", "aircrack-ng", "qgis", "marble", "docker.io",
    "docker-compose", "ffmpeg", "xdg-utils",
]

HEADER = r'''#!/usr/bin/env bash
# =====================================================================
#  OSINT Operatör - tek komutla kurulum
#
#    sudo bash osint-kur.sh            (onay sorar)
#    sudo bash osint-kur.sh --evet     (sormadan kurar)
#    sudo bash osint-kur.sh --sistem-guncelleme-yok   (apt adımını atlar)
#
#  Yaptıkları:
#   1) Sistemi günceller (apt full-upgrade) ve gerekli paketleri kurar
#   2) OSINT Menü Yöneticisi'ni kurar
#   3) Listedeki bütün araçları kurar, kategorilere ve menüye ekler
#  Günlük: /var/log/osint-kur.log
# =====================================================================
set -u
set -o pipefail

if [ "$(id -u)" -ne 0 ]; then
    exec sudo bash "$0" "$@"
fi

# "sudo: unable to resolve host" uyarısını gider (bilgisayar adı /etc/hosts'ta yoksa ekle)
HN="$(hostname)"
if [ -n "$HN" ] && ! grep -qw "$HN" /etc/hosts; then
    echo "127.0.1.1 $HN" >> /etc/hosts
fi

EVET=0; APT_ADIMI=1
for a in "$@"; do
    case "$a" in
        --evet|-y) EVET=1 ;;
        --sistem-guncelleme-yok) APT_ADIMI=0 ;;
    esac
done

LOG=/var/log/osint-kur.log
mkdir -p /var/log
if [ -n "${OSINT_KUR_ARKAPLAN:-}" ]; then
    exec >>"$LOG" 2>&1
fi

G='\033[1;32m'; Y='\033[1;33m'; B='\033[1;34m'; RD='\033[1;31m'; N='\033[0m'
adim() { printf "\n${B}==> %s${N}\n" "$*"; }
uyari() { printf "${Y}[!] %s${N}\n" "$*"; }
basari() { printf "${G}[✔] %s${N}\n" "$*"; }

REAL_USER="${SUDO_USER:-}"
if [ -z "$REAL_USER" ] || [ "$REAL_USER" = root ]; then
    REAL_USER="$(getent passwd 1000 | cut -d: -f1)"
fi
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"

printf "${G}"
cat <<'BANNER'
   ____  _____ _____ _   _ _______    _  __
  / __ \/ ____|_   _| \ | |__   __|  | |/ /
 | |  | | (___   | | |  \| |  | |     | ' / _   _ _ __
 | |  | |\___ \  | | | . ` |  | |     |  < | | | | '__|
 | |__| |____) |_| |_| |\  |  | |     | . \| |_| | |
  \____/|_____/|_____|_| \_|  |_|     |_|\_\\__,_|_|
BANNER
printf "${N}\n"
echo "Kullanıcı: $REAL_USER ($REAL_HOME)"
echo "Bu betik:"
[ "$APT_ADIMI" = 1 ] && echo "  - Sistemi GÜNCELLEYECEK (apt full-upgrade) ve gerekli paketleri kuracak"
echo "  - __ARAC_SAYISI__ aracı kurup menüye ekleyecek, kategorileri oluşturacak"
echo "  - Eski usulle kurulmuş araçlarınızı yeni sürümleriyle değiştirecek"
echo "    (eski menü kayıtları gizlenir, eski klasörler silinmez)"
echo
uyari "Sanal makinedeyseniz başlamadan önce bir ANLIK GÖRÜNTÜ (snapshot) alın."
uyari "İşlem internet hızına göre uzun sürebilir; bilgisayarı kapatmayın."
if [ "$EVET" != 1 ]; then
    read -r -p "Devam edilsin mi? [e/H] " cevap
    case "$cevap" in e|E|evet|EVET|y|Y) ;; *) echo "İptal edildi."; exit 1 ;; esac
fi

# Masaüstü oturumu güncelleme sırasında çökse bile kurulum yarıda kalmasın:
# betik terminalden bağımsız (arka planda) çalışır, bu pencere sadece günlüğü gösterir.
if [ -z "${OSINT_KUR_ARKAPLAN:-}" ]; then
    : >"$LOG.ilerleme"
    OSINT_KUR_ARKAPLAN=1 setsid nohup bash "$0" --evet "$@" >/dev/null 2>&1 < /dev/null &
    PID=$!
    echo
    echo "Kurulum arka planda başladı (PID $PID)."
    echo "Bu pencereyi kapatsanız ya da ekran donsa bile kurulum devam eder."
    echo "İlerlemeyi daha sonra izlemek için:  tail -f $LOG"
    echo
    sleep 2
    tail -n +1 -f "$LOG" --pid="$PID"
    exit 0
fi

adim "İnternet bağlantısı kontrol ediliyor"
if ! curl -sS -m 20 -o /dev/null https://github.com; then
    printf "${RD}[✘] github.com'a ulaşılamıyor. İnternet bağlantısını kontrol edin.${N}\n"
    exit 1
fi
basari "Bağlantı var"

export DEBIAN_FRONTEND=noninteractive
# Güncelleme sırasında masaüstü/ekran yöneticisi servisleri yeniden başlatılmasın
export NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1
APT=(apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

if [ "$APT_ADIMI" = 1 ]; then
    adim "Paket listesi güncelleniyor"
    if ! apt-get update 2>&1 | tee /tmp/osint-apt-update.log; then :; fi
    if grep -qE 'NO_PUBKEY|EXPKEYSIG|is not signed|invalid signature' /tmp/osint-apt-update.log; then
        uyari "Kali imza anahtarı eski; yeni anahtar indiriliyor (Kali'nin resmi adımı)"
        curl -fsSL https://archive.kali.org/archive-keyring.gpg \
            -o /usr/share/keyrings/kali-archive-keyring.gpg
        apt-get update
    fi

    adim "Sistem güncelleniyor (apt full-upgrade) - uzun sürebilir"
    if ! "${APT[@]}" full-upgrade; then
        uyari "Güncelleme hatayla bitti; düzeltme deneniyor"
        dpkg --configure -a
        "${APT[@]}" -f install
        "${APT[@]}" full-upgrade || uyari "Sistem güncellemesi tam bitmedi; günlüğe bakın: $LOG"
    fi
    basari "Sistem güncellendi"

    adim "Gerekli paketler kuruluyor"
    for p in __PAKETLER__; do
        if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed"; then
            echo "  = $p zaten kurulu"
        elif "${APT[@]}" install --no-install-recommends "$p" >/tmp/osint-apt-paket.log 2>&1; then
            echo "  + $p kuruldu"
        else
            uyari "$p kurulamadı (günlük: $LOG)"; cat /tmp/osint-apt-paket.log >>"$LOG"
        fi
    done
    "${APT[@]}" autoremove || true
    if command -v docker >/dev/null 2>&1 && [ -n "$REAL_USER" ]; then
        usermod -aG docker "$REAL_USER" 2>/dev/null || true
        systemctl enable --now docker >/dev/null 2>&1 || true
    fi
    systemctl enable --now tor >/dev/null 2>&1 || true
fi

adim "OSINT Menü Yöneticisi kuruluyor"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
sed '1,/^__YUK__$/d' "$0" | base64 -d | tar -xz -C "$WORK"
APP=/usr/share/osint-menu-yonetici/app
rm -rf "$APP"
mkdir -p "$APP/omy" /usr/share/osint-menu-yonetici/simgeler /opt/osint-tools
install -m 644 "$WORK"/app/omy/*.py "$APP/omy/"
install -m 755 "$WORK/app/osint_menu_yonetici.py" "$APP/"
install -m 644 "$WORK"/app/simgeler/* /usr/share/osint-menu-yonetici/simgeler/
install -m 755 "$WORK/app/osint-menu-yonetici" /usr/local/bin/osint-menu-yonetici
install -m 644 "$WORK/app/osint-menu-yonetici.desktop" /usr/share/applications/
mkdir -p /usr/share/osint-menu-yonetici/liste
install -m 644 "$WORK/araclar.ini" /usr/share/osint-menu-yonetici/liste/araclar.ini
basari "Kuruldu: osint-menu-yonetici (menü: Settings ▸ OSINT Menü Yöneticisi)"

adim "Araçlar kuruluyor ve menüye ekleniyor"
export OMY_REAL_USER="$REAL_USER" OMY_REAL_HOME="$REAL_HOME" XDG_MENU_PREFIX=xfce-
export PATH="/usr/local/bin:$PATH"
/usr/bin/python3 "$APP/osint_menu_yonetici.py" --toplu /usr/share/osint-menu-yonetici/liste/araclar.ini
SONUC=$?

if [ -n "$REAL_USER" ]; then
    # Açık oturumdaki menünün kendini yenilemesi için
    touch /etc/xdg/menus/applications-merged/osint-menu-yonetici.menu 2>/dev/null || true
fi

echo
basari "Kurulum bitti. Ayrıntılı günlük: $LOG"
echo "Değişikliklerin hepsinin oturtulması için bilgisayarı yeniden başlatmanız önerilir."
echo "Bir şeyi geri almak/düzenlemek için: osint-menu-yonetici"
exit $SONUC
__YUK__
'''


def build_payload(ini_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add(src, arc):
            tar.add(src, arcname=arc, filter=lambda ti: None if "__pycache__" in ti.name
                    else ti)
        for fn in ("osint_menu_yonetici.py", "osint-menu-yonetici", "osint-menu-yonetici.desktop"):
            add(os.path.join(HERE, fn), "app/" + fn)
        add(os.path.join(HERE, "omy"), "app/omy")
        add(os.path.join(HERE, "simgeler"), "app/simgeler")
        add(ini_path, "araclar.ini")
    return base64.encodebytes(buf.getvalue()).decode()


def count_tools(ini_path):
    import configparser
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=None,
                                   strict=False)
    cp.read(ini_path, encoding="utf-8")
    return sum(1 for s in cp.sections() if s.lower().startswith(("arac:", "araç:")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ini")
    ap.add_argument("-o", "--out", default="osint-kur.sh")
    a = ap.parse_args()
    script = HEADER.replace("__PAKETLER__", " ".join(PACKAGES)) \
        .replace("__ARAC_SAYISI__", str(count_tools(a.ini)))
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(script)
        f.write(build_payload(a.ini))
    os.chmod(a.out, 0o755)
    print("Üretildi: %s (%d KB)" % (a.out, os.path.getsize(a.out) // 1024))


if __name__ == "__main__":
    main()
