#!/usr/bin/env bash
# OSINT sistem bilgisi - 2. kısım. YALNIZCA OKUR, hiçbir şeyi değiştirmez.
#   bash sistem-bilgi-2.sh        (sudo gerekmez)
# Sonuç: ~/osint-sistem-bilgisi-2.txt

set -u
R="$HOME/osint-sistem-bilgisi-2.txt"
: >"$R"
bolum() { printf '\n===== %s =====\n' "$1" >>"$R"; }

bolum "Python sanal ortam desteği"
dpkg -l 'python3*-venv' 'python3-pip' 'python3-dev' 'build-essential' 2>/dev/null | grep '^ii' >>"$R"
T="$(mktemp -d)"
if python3 -m venv "$T/v" >>"$R" 2>&1 && "$T/v/bin/pip" --version >>"$R" 2>&1; then
    echo "venv: ÇALIŞIYOR" >>"$R"
else
    echo "venv: ÇALIŞMIYOR" >>"$R"
fi
rm -rf "$T"
ls /usr/lib/python3*/EXTERNALLY-MANAGED >>"$R" 2>&1

bolum "Menüdeki araçların komut dosyaları"
for c in aliens_eye blackbird sherlock lawliet social-analyzer socialscan tracer findigo no-infoga \
         phonenumber-osint facebookchecker gitsint instaloader osgint eyes h8mail holehe infoga \
         crawler domain_analyzer amass whatweb wpscan LinkScope ClipGrab.AppImage video-downloader \
         yt-dlp ffmpeg maltego recon-ng spiderfoot theHarvester eyewitness osintcase xosint google \
         torbrowser-launcher marble foxtrotgps; do
    p="$(command -v "$c" 2>/dev/null)"
    if [ -z "$p" ]; then printf '\n## %s: BULUNAMADI\n' "$c" >>"$R"; continue; fi
    real="$(readlink -f "$p")"
    pkg="$(dpkg -S "$real" 2>/dev/null | head -1 | cut -d: -f1)"
    [ -z "$pkg" ] && pkg="$(dpkg -S "$p" 2>/dev/null | head -1 | cut -d: -f1)"
    printf '\n## %s -> %s (paket: %s)\n' "$c" "$real" "${pkg:-YOK}" >>"$R"
    if [ -z "$pkg" ] && [ "$(stat -c %s "$real" 2>/dev/null || echo 0)" -lt 3000 ]; then
        head -12 "$real" 2>/dev/null | sed 's/^/    /' >>"$R"
    fi
done

bolum "/usr/share altındaki araç klasörleri (git?)"
for d in /usr/share/*/; do
    if [ -d "$d/.git" ]; then
        url="$(git -C "$d" config --get remote.origin.url 2>/dev/null)"
        ch="$(git -C "$d" status --porcelain --untracked-files=no 2>/dev/null | wc -l)"
        last="$(git -C "$d" log -1 --format=%cd --date=short 2>/dev/null)"
        printf '%s | %s | değişmiş: %s | son commit: %s | sahibi: %s\n' "$d" "$url" "$ch" "$last" \
            "$(stat -c %U "$d")" >>"$R"
    fi
done
for d in Aliens_eye blackbird Lawliet social-analyzer tracer GitSint instaloader Eyes h8mail \
         holehe LinkScope ClipGrab ffmpeg Video-Downloader; do
    [ -d "/usr/share/$d" ] && printf 'klasör: /usr/share/%s  (.git: %s, venv: %s)\n' "$d" \
        "$([ -d /usr/share/$d/.git ] && echo var || echo yok)" \
        "$(ls -d /usr/share/$d/*/bin/python 2>/dev/null | head -1)" >>"$R"
done

bolum "pip ile sisteme kurulmuş paketler (/usr/local)"
ls /usr/local/lib/python3*/dist-packages 2>/dev/null >>"$R"

bolum "APT kaynakları"
cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | grep -v '^#' | grep . >>"$R"
ls -la /var/lib/apt/lists/ 2>/dev/null | head -5 >>"$R"

bolum "APT simülasyonu (hiçbir şey kurulmaz, sadece ne olacağı hesaplanır)"
for p in pipx golang-go cargo npm docker.io tor kismet sparrow-wifi libimage-exiftool-perl \
         qgis marble aircrack-ng python3-venv; do
    pol="$(apt-cache policy "$p" 2>/dev/null | grep -E 'Installed|Candidate' | tr -s ' ' | tr '\n' ' ')"
    sim="$(apt-get -s install --no-install-recommends "$p" 2>/dev/null | grep -E '^[0-9]+ upgraded')"
    printf '%-24s %s | %s\n' "$p" "$pol" "${sim:-?}" >>"$R"
done

echo "Tamam. Bu dosyayı gönder: $R"
