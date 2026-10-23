#!/usr/bin/env bash
# OSINT Menü Yöneticisi kurulum betiği
#   sudo ./install.sh
set -e

if [ "$(id -u)" -ne 0 ]; then
    exec sudo bash "$0" "$@"
fi

SRC="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APP="/usr/share/osint-menu-yonetici/app"

echo "[*] Gerekli paketler kuruluyor..."
export DEBIAN_FRONTEND=noninteractive
if ! apt-get install -y python3 python3-gi gir1.2-gtk-3.0 git python3-venv; then
    apt-get update
    apt-get install -y python3 python3-gi gir1.2-gtk-3.0 git python3-venv
fi
# İsteğe bağlı: pipx (pipx ile araç kurmak için)
apt-get install -y pipx >/dev/null 2>&1 || echo "[!] pipx kurulamadı; pipx kaynaklı araçlar için elle kurun."

echo "[*] Uygulama dosyaları kopyalanıyor..."
rm -rf "$APP"
mkdir -p "$APP/omy"
install -m 644 "$SRC"/omy/*.py "$APP/omy/"
install -m 755 "$SRC/osint_menu_yonetici.py" "$APP/"
rm -rf /usr/share/osint-menu-yonetici/simgeler
mkdir -p /usr/share/osint-menu-yonetici/simgeler
install -m 644 "$SRC"/simgeler/* /usr/share/osint-menu-yonetici/simgeler/
install -m 755 "$SRC/osint-menu-yonetici" /usr/local/bin/osint-menu-yonetici
install -m 644 "$SRC/osint-menu-yonetici.desktop" /usr/share/applications/osint-menu-yonetici.desktop
mkdir -p /opt/osint-tools /etc/osint-menu-yonetici /etc/xdg/menus/applications-merged

# Daha önce eklenmiş araçlar varsa dosyalarını yeniden üret
if [ -f /etc/osint-menu-yonetici/state.json ]; then
    /usr/bin/python3 "$APP/osint_menu_yonetici.py" --uygula || true
fi

echo
echo "[+] Kurulum tamamlandı."
echo "    Menüden: Settings / Ayarlar > OSINT Menü Yöneticisi"
echo "    Terminalden: osint-menu-yonetici"
