#!/usr/bin/env bash
# OSINT sistem bilgisi toplayıcı - YALNIZCA OKUR, hiçbir şeyi değiştirmez.
# Menü yapısını, kurulu araçları ve sürümleri tek bir arşivde toplar.
#
#   bash sistem-bilgi.sh          (sudo GEREKMEZ, normal kullanıcınla çalıştır)
#
# Sonuç: ~/osint-sistem-bilgisi.tar.gz

set -u
OUT="$(mktemp -d)"
D="$OUT/osint-sistem-bilgisi"
mkdir -p "$D"
R="$D/rapor.txt"

bolum() { printf '\n===== %s =====\n' "$1" >>"$R"; }

{
    echo "Tarih: $(date)"
    echo "Kullanıcı: $(id -un) ($(id -u))   Ev: $HOME"
} >"$R"

bolum "İşletim sistemi"
cat /etc/os-release >>"$R" 2>&1
uname -a >>"$R" 2>&1

bolum "Masaüstü ve menü ortamı"
env | grep -E '^(XDG_|DESKTOP_SESSION|GTK_THEME|LANG|SHELL|PATH)=' | sort >>"$R"
if command -v xfconf-query >/dev/null 2>&1; then
    echo "GTK teması: $(xfconf-query -c xsettings -p /Net/ThemeName 2>/dev/null)" >>"$R"
    echo "Simge teması: $(xfconf-query -c xsettings -p /Net/IconThemeName 2>/dev/null)" >>"$R"
fi
ls /usr/share/icons >>"$R" 2>&1

bolum "Programlar ve sürümler"
for c in python3 pip3 pipx git go cargo rustc node npm docker docker-compose tor java ruby perl \
         curl wget xdg-open xfce4-terminal qterminal x-terminal-emulator; do
    p="$(command -v "$c" 2>/dev/null)"
    if [ -n "$p" ]; then
        if [ "$c" = go ]; then v="$(go version 2>&1)"; else v="$("$c" --version 2>&1 | head -1)"; fi
        printf '%-20s %-35s %s\n' "$c" "$p" "$v" >>"$R"
    else
        printf '%-20s YOK\n' "$c" >>"$R"
    fi
done
python3 -c 'import sys; print("Python modül yolu:", sys.path)' >>"$R" 2>&1

bolum "Disk alanı"
df -h / /opt /home 2>/dev/null >>"$R"

bolum "pipx (kullanıcı)"
pipx list --short >>"$R" 2>&1
bolum "pipx (sistem /opt/pipx)"
PIPX_HOME=/opt/pipx pipx list --short >>"$R" 2>&1

bolum "/opt içeriği"
ls -la /opt >>"$R" 2>&1

bolum "Git ile kurulmuş araçlar (/opt, ev klasörü)"
find /opt "$HOME" -maxdepth 4 -type d -name .git 2>/dev/null | while read -r g; do
    repo="$(dirname "$g")"
    url="$(git -C "$repo" config --get remote.origin.url 2>/dev/null)"
    st="$(git -C "$repo" status --porcelain --untracked-files=no 2>/dev/null | wc -l)"
    printf '%s | %s | değişmiş dosya: %s | sahibi: %s\n' "$repo" "$url" "$st" \
        "$(stat -c %U "$repo" 2>/dev/null)" >>"$R"
done

bolum "/usr/local/bin"
ls -la /usr/local/bin >>"$R" 2>&1
bolum "~/.local/bin"
ls -la "$HOME/.local/bin" >>"$R" 2>&1

bolum "Whisker menü ayarları"
cat "$HOME"/.config/xfce4/panel/whiskermenu-*.rc >>"$R" 2>&1

# Menü dosyalarının kopyası (menünün aynısını kurabilmem için)
mkdir -p "$D/etc-xdg-menus" "$D/user-menus" "$D/apps-system" "$D/apps-local" \
         "$D/apps-user" "$D/dirs-system" "$D/dirs-user" "$D/kali-menu"
cp -r /etc/xdg/menus/. "$D/etc-xdg-menus/" 2>/dev/null
cp -r "$HOME/.config/menus/." "$D/user-menus/" 2>/dev/null
cp /usr/share/applications/*.desktop "$D/apps-system/" 2>/dev/null
cp /usr/local/share/applications/*.desktop "$D/apps-local/" 2>/dev/null
cp -r "$HOME/.local/share/applications/." "$D/apps-user/" 2>/dev/null
cp /usr/share/desktop-directories/*.directory "$D/dirs-system/" 2>/dev/null
cp -r "$HOME/.local/share/desktop-directories/." "$D/dirs-user/" 2>/dev/null
ls /usr/share/kali-menu/applications >"$D/kali-menu/liste.txt" 2>/dev/null

tar -czf "$HOME/osint-sistem-bilgisi.tar.gz" -C "$OUT" osint-sistem-bilgisi
rm -rf "$OUT"
echo
echo "Tamam. Bu dosyayı gönder:  $HOME/osint-sistem-bilgisi.tar.gz"
echo "(İçinde sadece menü dosyaları, araç listesi ve sürüm bilgileri var; şifre ya da kişisel dosya yok.)"
