#!/usr/bin/env bash
# OSINT Menü Yöneticisi'ni kaldırır.
#   sudo ./uninstall.sh          -> yalnızca uygulamayı kaldırır, eklediğiniz araçlar menüde kalır
#   sudo ./uninstall.sh --hepsi  -> eklediğiniz menü kayıtlarını, komutları ve
#                                   simge/ad değişikliklerini de geri alır
#                                   (/opt/osint-tools ve /opt/pipx klasörlerine dokunulmaz)
set -e

if [ "$(id -u)" -ne 0 ]; then
    exec sudo bash "$0" "$@"
fi

if [ "${1:-}" = "--hepsi" ]; then
    echo "[*] Menü kayıtları, komutlar ve simge/ad değişiklikleri geri alınıyor..."
    if [ -f /usr/share/osint-menu-yonetici/app/osint_menu_yonetici.py ]; then
        /usr/bin/python3 /usr/share/osint-menu-yonetici/app/osint_menu_yonetici.py --temizle || true
    fi
    rm -f /etc/xdg/menus/applications-merged/osint-menu-yonetici.menu
    for f in /usr/share/applications/omy-*.desktop /usr/share/desktop-directories/omy-*.directory \
             /usr/local/bin/*; do
        [ -f "$f" ] && [ ! -L "$f" ] || continue
        if head -c 600 "$f" | grep -q "osint-menu-yonetici tarafından oluşturuldu"; then
            rm -f "$f"
        fi
    done
    rm -rf /etc/osint-menu-yonetici /usr/local/lib/osint-menu-yonetici
    rm -rf /usr/share/osint-menu-yonetici/icons /usr/share/osint-menu-yonetici/simgeler
fi

rm -rf /usr/share/osint-menu-yonetici/app
rmdir /usr/share/osint-menu-yonetici 2>/dev/null || true
rm -f /usr/local/bin/osint-menu-yonetici /usr/share/applications/osint-menu-yonetici.desktop
echo "[+] Kaldırıldı."
