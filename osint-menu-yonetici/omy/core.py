# -*- coding: utf-8 -*-
"""Çekirdek işlemler: durum dosyası, menü dosyaları, sarmalayıcı (wrapper)
betikler ve araç kurulumları. Bu modül GTK kullanmaz; komut satırından ve
testlerden de çağrılabilir.

Bütün dosyalar sistem geneline yazılır (ISO olarak dışa aktarıldığında
araçların ve menülerin de taşınması için):

  /etc/osint-menu-yonetici/state.json                 -> yönetilen her şeyin kaydı
  /etc/xdg/menus/applications-merged/osint-menu-yonetici.menu
                                                       -> menü yapısı (XDG birleştirme dosyası)
  /usr/share/desktop-directories/omy-*.directory       -> kendi kategorileriniz
  /usr/share/applications/omy-*.desktop                -> menüdeki araçlar
  /usr/local/bin/<komut>                               -> GitHub araçları için terminal komutu
  /opt/osint-tools/<araç>                              -> GitHub'dan indirilen araçlar
"""

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

from xml.sax.saxutils import escape as xml_escape

APP_ID = "osint-menu-yonetici"
PREFIX = "omy-"
MARKER = "# osint-menu-yonetici tarafından oluşturuldu"
TOOL_CATEGORY = "X-OSINT-Menu-Yonetici"

STATE_FILE = "/etc/osint-menu-yonetici/state.json"
ICON_DIR = "/usr/share/osint-menu-yonetici/icons"
APPS_DIR = "/usr/share/applications"
DIRS_DIR = "/usr/share/desktop-directories"
MERGE_FILE = "/etc/xdg/menus/applications-merged/osint-menu-yonetici.menu"
BIN_DIR = "/usr/local/bin"
TOOLS_DIR = "/opt/osint-tools"
RUNNER = "/usr/local/lib/osint-menu-yonetici/terminal-calistir"
PIPX_HOME = "/opt/pipx"
PACK_DIR = "/usr/share/osint-menu-yonetici/simgeler"
OVERRIDE_BASE = "/usr/local/share"
_REPO_PACK_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "simgeler")

# Hazır OSINT kategorileri: (ad, paket simgesi, açıklama)
CATEGORY_PRESETS = [
    ("OSINT Sosyal Medya", "osint-sosyal-medya", "Sosyal medya hesap ve gönderi araştırması"),
    ("OSINT E-posta", "osint-eposta", "E-posta adresi araştırması"),
    ("OSINT Telefon Numarası", "osint-telefon", "Telefon numarası araştırması"),
    ("OSINT Kullanıcı Adı", "osint-kullanici", "Kullanıcı adı araştırması"),
    ("OSINT Kişi Arama", "osint-kisi-arama", "Kişi ve kimlik araştırması"),
    ("OSINT Alan Adı & Web", "osint-alan-adi", "Alan adı, whois ve web sitesi analizi"),
    ("OSINT IP & Ağ", "osint-ip-adresi", "IP adresi ve ağ araştırması"),
    ("OSINT DNS & Alt Alan Adı", "osint-dns", "DNS kayıtları ve alt alan adları"),
    ("OSINT Görsel & Video", "osint-resim", "Görsel, video ve EXIF analizi"),
    ("OSINT Konum & Harita", "osint-konum", "Konum ve harita (GEOINT) araçları"),
    ("OSINT Dark Web", "osint-dark-web", "Tor ve dark web araştırması"),
    ("OSINT Kripto Para", "osint-kripto", "Kripto cüzdan ve blokzincir araştırması"),
    ("OSINT Veri Sızıntıları", "osint-sizinti", "Sızdırılmış veri ve parola kontrolü"),
    ("OSINT Şirket & Kurum", "osint-sirket", "Şirket ve kurum araştırması"),
    ("OSINT Belge & Metadata", "osint-belge", "Belge ve metadata analizi"),
    ("OSINT Web Arşivi", "osint-arsiv", "Web arşivi ve geçmiş kayıtlar"),
    ("OSINT Mesajlaşma", "osint-sohbet", "Telegram, WhatsApp ve sohbet araçları"),
    ("OSINT Kamera & CCTV", "osint-kamera", "Açık kamera ve IoT araştırması"),
    ("OSINT Uçuş & Gemi Takibi", "osint-ucak", "Uçuş ve gemi takibi"),
    ("Recon", "osint-hedef", "Keşif ve tarama araçları"),
    ("Raporlama", "osint-rapor", "Raporlama ve not alma araçları"),
]

SOURCE_TYPES = ("git", "local", "pipx", "apt", "existing")
SOURCES_WITH_WRAPPER = ("git", "local")

RUNNERS = {
    "auto": "Otomatik (dosya uzantısına göre)",
    "python": "Python (varsa sanal ortam)",
    "bash": "Bash",
    "sh": "sh",
    "ruby": "Ruby",
    "perl": "Perl",
    "node": "Node.js",
    "php": "PHP",
    "java": "Java (-jar)",
    "direct": "Doğrudan çalıştır",
}

EXT_RUNNER = {
    ".py": "python", ".pyw": "python",
    ".sh": "bash", ".bash": "bash",
    ".rb": "ruby", ".pl": "perl",
    ".js": "node", ".mjs": "node",
    ".php": "php", ".jar": "java",
}

COMMAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")

_TR = str.maketrans("çğıöşüÇĞİÖŞÜâîûÂÎÛ", "cgiosuCGIOSUaiuAIU")


class OmyError(Exception):
    """Kullanıcıya gösterilecek hata."""


# --------------------------------------------------------------------------
# Yol yardımcıları

def sys_path(path):
    """Gerçek sistem yolunu döndürür. Testlerde OMY_ROOT ile sahte bir kök
    dizin kullanılabilir; üretilen dosyaların içeriği her zaman gerçek
    yolları gösterir."""
    root = os.environ.get("OMY_ROOT", "/")
    return os.path.join(root, path.lstrip("/"))


def slugify(text, default="arac"):
    s = (text or "").translate(_TR).lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or default


def unique_id(base, taken):
    if base not in taken:
        return base
    i = 2
    while "%s-%d" % (base, i) in taken:
        i += 1
    return "%s-%d" % (base, i)


def path_key(path):
    return "/".join(path)


def name_from_source(source_type, value):
    """Kaynaktan (URL, klasör, paket) varsayılan bir araç adı çıkarır."""
    value = (value or "").strip().rstrip("/")
    if not value:
        return ""
    if source_type in ("git", "pipx"):
        value = re.sub(r"^git\+", "", value)
        value = value.split("#")[0].split("?")[0].rstrip("/")
        last = re.split(r"[/:]", value)[-1]
        last = re.sub(r"\.git$", "", last)
        last = re.split(r"[\[=<>@ ]", last)[0]
        return last
    if source_type == "local":
        base = os.path.basename(value)
        return os.path.splitext(base)[0] if os.path.isfile(value) else base
    return value.split()[0]


# --------------------------------------------------------------------------
# Durum (state.json)

def empty_state():
    return {"version": 1, "categories": [], "tools": [], "overrides": []}


def load_state():
    path = sys_path(STATE_FILE)
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
    except FileNotFoundError:
        return empty_state()
    except (OSError, ValueError) as e:
        raise OmyError("Durum dosyası okunamadı (%s): %s" % (path, e))
    state.setdefault("version", 1)
    state.setdefault("categories", [])
    state.setdefault("tools", [])
    state.setdefault("overrides", [])
    return state


def save_state(state):
    _write_file(sys_path(STATE_FILE),
                json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def cat_path(cat):
    return list(cat.get("parent", [])) + [cat["id"]]


def find_cat(state, cat_id):
    for c in state["categories"]:
        if c["id"] == cat_id:
            return c
    return None


def find_tool(state, tool_id):
    for t in state["tools"]:
        if t["id"] == tool_id:
            return t
    return None


def new_category_id(state, name):
    taken = {c["id"] for c in state["categories"]}
    return unique_id(PREFIX + slugify(name, "kategori"), taken)


def new_tool_id(state, name):
    taken = {t["id"] for t in state["tools"]}
    real_tools = sys_path(TOOLS_DIR)
    if os.path.isdir(real_tools):
        # Silinen araçlardan kalan klasörlerle çakışmasın
        taken |= set(os.listdir(real_tools))
    return unique_id(slugify(name), taken)


def desktop_id(tool):
    return "%s%s.desktop" % (PREFIX, tool["id"])


def is_under(path, prefix):
    return list(path[:len(prefix)]) == list(prefix)


def move_category(state, cat, new_parent):
    """Kategoriyi (içindekilerle birlikte) başka bir menünün altına taşır."""
    old = cat_path(cat)
    if is_under(new_parent, old):
        raise OmyError("Bir kategori kendi içine taşınamaz.")
    new = list(new_parent) + [cat["id"]]
    for c in state["categories"]:
        if c is not cat and is_under(c["parent"], old):
            c["parent"] = new + c["parent"][len(old):]
    for t in state["tools"]:
        if is_under(t["menu"], old):
            t["menu"] = new + t["menu"][len(old):]
    cat["parent"] = list(new_parent)


def remove_category(state, cat):
    """Kategoriyi siler; içindeki araç ve alt kategoriler bir üst menüye
    taşınır."""
    old = cat_path(cat)
    parent = list(cat["parent"])
    for c in state["categories"]:
        if c is not cat and is_under(c["parent"], old):
            c["parent"] = parent + c["parent"][len(old):]
    for t in state["tools"]:
        if is_under(t["menu"], old):
            t["menu"] = parent + t["menu"][len(old):]
    state["categories"].remove(cat)


def category_contents(state, cat):
    old = cat_path(cat)
    tools = [t for t in state["tools"] if is_under(t["menu"], old)]
    cats = [c for c in state["categories"]
            if c is not cat and is_under(c["parent"], old)]
    return tools, cats


# --------------------------------------------------------------------------
# Dosya yazma yardımcıları

def _write_file(path, content, mode=0o644):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".omy-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _is_ours(path):
    """Dosya bu uygulama tarafından oluşturulduysa True döner."""
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return False
        with open(path, "rb") as f:
            return MARKER.encode("utf-8") in f.read(600)
    except OSError:
        return False


def kf_escape(value):
    """Desktop dosyası (key file) string kaçışları."""
    return (str(value).replace("\\", "\\\\").replace("\n", "\\n")
            .replace("\t", "\\t").replace("\r", "\\r"))


_EXEC_RESERVED = set(" \t\n\"'\\><~|&;$*?#()`")


def exec_quote(arg):
    """Desktop Entry şartnamesine göre Exec argümanı tırnaklama."""
    if arg == "":
        return '""'
    if any(c in _EXEC_RESERVED for c in arg):
        arg = '"' + re.sub(r'([\\"`$])', r"\\\1", arg) + '"'
    return arg.replace("%", "%%")


def split_args(args):
    try:
        return shlex.split(args or "")
    except ValueError as e:
        raise OmyError("Parametreler hatalı (tırnak kapanmamış olabilir): %s" % e)


# --------------------------------------------------------------------------
# Menü dosyaları

def tool_exec(tool):
    argv = [tool["command"]] + split_args(tool.get("args", ""))
    if tool.get("terminal", True):
        argv = [RUNNER] + argv
    return " ".join(exec_quote(a) for a in argv)


def desktop_content(tool):
    lines = [
        "[Desktop Entry]",
        MARKER,
        "Type=Application",
        "Version=1.0",
        "Name=%s" % kf_escape(tool["name"]),
    ]
    if tool.get("comment"):
        lines.append("Comment=%s" % kf_escape(tool["comment"]))
    lines += [
        "Exec=%s" % kf_escape(tool_exec(tool)),
        "Icon=%s" % kf_escape(tool.get("icon") or "utilities-terminal"),
        "Terminal=%s" % ("true" if tool.get("terminal", True) else "false"),
        "Categories=%s;" % TOOL_CATEGORY,
        "StartupNotify=false",
        "X-OMY-Id=%s" % tool["id"],
        "",
    ]
    return "\n".join(lines)


def directory_content(cat):
    lines = [
        "[Desktop Entry]",
        MARKER,
        "Type=Directory",
        "Version=1.0",
        "Name=%s" % kf_escape(cat["name"]),
    ]
    if cat.get("comment"):
        lines.append("Comment=%s" % kf_escape(cat["comment"]))
    lines += ["Icon=%s" % kf_escape(cat.get("icon") or "folder"), ""]
    return "\n".join(lines)


def build_menu_xml(state):
    def new_node():
        return {"children": {}, "files": [], "directory": None}

    root = new_node()

    def node_at(path):
        n = root
        for name in path:
            n = n["children"].setdefault(name, new_node())
        return n

    for cat in state["categories"]:
        node_at(cat_path(cat))["directory"] = cat["id"] + ".directory"
    for tool in state["tools"]:
        node_at(tool["menu"])["files"].append(desktop_id(tool))

    out = []

    def emit(node, depth):
        ind = "  " * depth
        if node["directory"]:
            out.append("%s<Directory>%s</Directory>" % (ind, xml_escape(node["directory"])))
        if node["files"]:
            out.append("%s<Include>" % ind)
            for f in node["files"]:
                out.append("%s  <Filename>%s</Filename>" % (ind, xml_escape(f)))
            out.append("%s</Include>" % ind)
        for name, child in node["children"].items():
            out.append("%s<Menu>" % ind)
            out.append("%s  <Name>%s</Name>" % (ind, xml_escape(name)))
            emit(child, depth + 1)
            out.append("%s</Menu>" % ind)

    emit(root, 1)
    return "\n".join([
        '<!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"',
        ' "http://www.freedesktop.org/standards/menu-spec/1.0/menu.dtd">',
        "<!-- %s; elle düzenlemeyin, değişiklikler üzerine yazılır. -->" % MARKER.lstrip("# "),
        "<Menu>",
        "  <Name>Applications</Name>",
    ] + out + ["</Menu>", ""])


RUNNER_SCRIPT = """#!/usr/bin/env bash
%s
# Menüden açılan aracı çalıştırır, ardından terminali açık bırakır.
if [ "$#" -gt 0 ]; then
    printf '\\033[1;32m$ %%s\\033[0m\\n\\n' "$*"
    "$@"
    echo
    printf '\\033[1;34m[i]\\033[0m Aracı tekrar çalıştırmak için: \\033[1m%%s <parametreler>\\033[0m\\n\\n' "$1"
fi
exec "${SHELL:-/bin/bash}" -i
""" % MARKER


# --------------------------------------------------------------------------
# Sarmalayıcı (wrapper) betikler

def tool_dir(tool):
    return tool.get("source", {}).get("dir", "")


def resolve_runner(tool):
    """Wrapper'da kullanılacak komut satırını (argv) döndürür."""
    src = tool["source"]
    tdir = src["dir"]
    entry = src.get("entry", "")
    if not entry:
        raise OmyError("'%s' için çalıştırılacak dosya seçilmemiş." % tool["name"])
    if entry.startswith("venv:"):
        return [os.path.join(tdir, ".venv", "bin", entry[5:])]
    target = os.path.normpath(os.path.join(tdir, entry))
    runner = src.get("runner", "auto")
    if runner == "auto":
        runner = EXT_RUNNER.get(os.path.splitext(entry)[1].lower(), "direct")
    if runner == "python":
        venv_py = os.path.join(tdir, ".venv", "bin", "python")
        py = venv_py if os.path.exists(sys_path(venv_py)) else "python3"
        return [py, target]
    if runner == "java":
        return ["java", "-jar", target]
    if runner == "direct":
        return [target]
    return [runner, target]


def wrapper_content(tool):
    src = tool["source"]
    argv = resolve_runner(tool)
    lines = [
        "#!/usr/bin/env bash",
        MARKER,
        "# Araç: %s (%s)" % (tool["name"].replace("\n", " "), tool["id"]),
        "# Kurulum klasörü: %s" % src["dir"],
    ]
    if src.get("cd", True):
        lines.append("cd %s || exit 1" % shlex.quote(src["dir"]))
    lines.append("exec %s \"$@\"" % " ".join(shlex.quote(a) for a in argv))
    return "\n".join(lines) + "\n"


def command_conflict(command, tool_id=None, state=None):
    """Komut adı kullanılabilir mi? (engel, uyarı) ikilisi döndürür."""
    if not COMMAND_RE.match(command or ""):
        return ("Komut adı yalnızca harf, rakam, '.', '_', '+' ve '-' içerebilir "
                "ve boşluk içeremez.", None)
    if state is not None:
        for t in state["tools"]:
            if t["id"] != tool_id and t["command"] == command and \
                    t["source"]["type"] in SOURCES_WITH_WRAPPER:
                return ("'%s' komutu zaten '%s' aracı tarafından kullanılıyor."
                        % (command, t["name"]), None)
    target = sys_path(os.path.join(BIN_DIR, command))
    if os.path.lexists(target) and not _is_ours(target):
        return ("%s zaten var ve bu uygulamaya ait değil. Başka bir komut adı seçin."
                % os.path.join(BIN_DIR, command), None)
    other = shutil.which(command)
    if other and os.path.dirname(other) != BIN_DIR:
        return (None, "Sistemde zaten '%s' komutu var (%s). Yeni komut onun önüne "
                      "geçecek." % (command, other))
    return (None, None)


def write_wrapper(tool):
    content = wrapper_content(tool)
    target = resolve_runner(tool)[0]
    if target.startswith(tool["source"]["dir"].rstrip("/") + "/"):
        # Doğrudan çalıştırılan dosyanın çalıştırma izni olmalı.
        real = sys_path(target)
        if os.path.isfile(real) and not os.access(real, os.X_OK):
            try:
                os.chmod(real, os.stat(real).st_mode | 0o755)
            except OSError:
                pass
    _write_file(sys_path(os.path.join(BIN_DIR, tool["command"])), content, 0o755)


def remove_wrapper(command):
    path = sys_path(os.path.join(BIN_DIR, command))
    if _is_ours(path):
        os.unlink(path)


# --------------------------------------------------------------------------
# Uygula: durumdan bütün dosyaları üret

def apply(state):
    """state.json'u kaydeder ve menü/sarmalayıcı dosyalarını yeniden üretir.
    Uyarı mesajlarının listesini döndürür."""
    warnings = []
    save_state(state)
    _write_file(sys_path(RUNNER), RUNNER_SCRIPT, 0o755)

    wanted_desktop = set()
    for tool in state["tools"]:
        name = desktop_id(tool)
        wanted_desktop.add(name)
        try:
            _write_file(sys_path(os.path.join(APPS_DIR, name)), desktop_content(tool))
        except OmyError as e:
            warnings.append(str(e))

    wanted_dirs = set()
    for cat in state["categories"]:
        name = cat["id"] + ".directory"
        wanted_dirs.add(name)
        _write_file(sys_path(os.path.join(DIRS_DIR, name)), directory_content(cat))

    wanted_bins = set()
    for tool in state["tools"]:
        if tool["source"]["type"] not in SOURCES_WITH_WRAPPER:
            continue
        wanted_bins.add(tool["command"])
        target = sys_path(os.path.join(BIN_DIR, tool["command"]))
        if os.path.lexists(target) and not _is_ours(target):
            warnings.append("%s başka bir programa ait olduğu için '%s' komutu "
                            "oluşturulmadı." % (target, tool["name"]))
            continue
        try:
            write_wrapper(tool)
        except OmyError as e:
            warnings.append(str(e))

    _write_file(sys_path(MERGE_FILE), build_menu_xml(state))
    apply_overrides(state, warnings)

    # Artık kullanılmayan eski dosyaları temizle (yalnızca bizim dosyalarımız).
    for d, wanted, suffix in ((APPS_DIR, wanted_desktop, ".desktop"),
                              (DIRS_DIR, wanted_dirs, ".directory")):
        real = sys_path(d)
        if not os.path.isdir(real):
            continue
        for fn in os.listdir(real):
            if fn.startswith(PREFIX) and fn.endswith(suffix) and fn not in wanted:
                p = os.path.join(real, fn)
                if _is_ours(p):
                    os.unlink(p)
    real_bin = sys_path(BIN_DIR)
    if os.path.isdir(real_bin):
        for fn in os.listdir(real_bin):
            p = os.path.join(real_bin, fn)
            if fn not in wanted_bins and _is_ours(p):
                os.unlink(p)
    return warnings


_IMAGE_EXTS = (".png", ".svg", ".jpg", ".jpeg", ".ico", ".xpm", ".gif", ".webp")


def find_repo_images(real_dir, limit=80):
    """Aracın klasöründeki logo/simge olabilecek resimleri en olası olandan
    başlayarak döndürür."""
    found = []
    if not real_dir or not os.path.isdir(real_dir):
        return found
    for dirpath, dirnames, filenames in os.walk(real_dir):
        depth = os.path.relpath(dirpath, real_dir).count(os.sep)
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        if depth >= 3:
            dirnames[:] = []
        for fn in filenames:
            if not fn.lower().endswith(_IMAGE_EXTS):
                continue
            full = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size == 0 or size > 3 * 1024 * 1024:
                continue
            low = fn.lower()
            score = 0
            if "logo" in low or "icon" in low or "favicon" in low:
                score += 100
            if os.path.basename(real_dir).lower() in low:
                score += 30
            if low.endswith(".svg"):
                score += 10
            if any(w in low for w in ("screenshot", "screen", "demo", "example", "banner",
                                      "preview", "usage")):
                score -= 40
            found.append((score - depth * 5, full))
    found.sort(key=lambda x: (-x[0], x[1]))
    return [f for _s, f in found[:limit]]


def best_repo_icon(real_dir):
    """Adında logo/icon geçen ilk resmi döndürür (yoksa boş)."""
    for path in find_repo_images(real_dir, limit=20):
        low = os.path.basename(path).lower()
        if "logo" in low or "icon" in low:
            return path
    return ""


def pack_dir():
    """Hazır simge paketinin bulunduğu (gerçek) klasör."""
    real = sys_path(PACK_DIR)
    return real if os.path.isdir(real) else _REPO_PACK_DIR


def load_icon_pack():
    """Hazır OSINT simgelerini [{"path", "label", "keywords"}] olarak döndürür.
    path, menü dosyalarına yazılacak gerçek yoldur."""
    d = pack_dir()
    try:
        with open(os.path.join(d, "liste.json"), encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        return []
    installed = d != _REPO_PACK_DIR
    result = []
    for m in meta:
        real = os.path.join(d, m["file"])
        if os.path.isfile(real):
            result.append({"path": os.path.join(PACK_DIR, m["file"]) if installed else real,
                           "real": real, "label": m["label"],
                           "keywords": m.get("keywords", "")})
    return result


def pack_icon(name):
    """Paketteki simgenin yolunu döndürür (ör. "osint-eposta")."""
    for icon in load_icon_pack():
        if os.path.splitext(os.path.basename(icon["path"]))[0] == name:
            return icon["path"]
    return ""


def store_icon(icon, tool_or_cat_id):
    """Simge bir dosyaysa sistem simge klasörüne kopyalar ve yeni yolu
    döndürür; simge adıysa olduğu gibi döndürür. Kurulu simge paketindeki
    simgeler kopyalanmadan kullanılır."""
    icon = (icon or "").strip()
    if not icon or not os.path.isabs(icon):
        return icon
    if os.path.dirname(icon) == PACK_DIR:
        return icon
    real_icon_dir = sys_path(ICON_DIR)
    if os.path.dirname(sys_path(icon)) == real_icon_dir or \
            os.path.dirname(icon) == ICON_DIR:
        return icon
    if not os.path.isfile(icon):
        raise OmyError("Simge dosyası bulunamadı: %s" % icon)
    ext = os.path.splitext(icon)[1].lower() or ".png"
    os.makedirs(real_icon_dir, exist_ok=True)
    dest_name = tool_or_cat_id + ext
    shutil.copyfile(icon, os.path.join(real_icon_dir, dest_name))
    os.chmod(os.path.join(real_icon_dir, dest_name), 0o644)
    return os.path.join(ICON_DIR, dest_name)


def remove_icon(icon):
    if icon and os.path.dirname(icon) == ICON_DIR:
        p = sys_path(icon)
        if os.path.isfile(p):
            os.unlink(p)


# --------------------------------------------------------------------------
# Menüyü okuma (XFCE ile aynı kurallar, bkz. xdgmenu.py)

class MenuNode:
    def __init__(self, name, title, icon="", comment="", path=None, file=None):
        self.name = name
        self.title = title
        self.icon = icon or ""
        self.comment = comment or ""
        self.path = path or []
        self.file = file          # .directory dosyasının tam yolu (varsa)
        self.children = []
        self.entries = []


def real_user_home():
    """Masaüstünü kullanan asıl kullanıcının ev klasörü (root olarak
    çalışırken menüyü onun gördüğü gibi okuyabilmek için)."""
    home = os.environ.get("OMY_REAL_HOME")
    if home and os.path.isdir(home):
        return home
    import pwd
    user = os.environ.get("OMY_REAL_USER") or os.environ.get("SUDO_USER")
    uid = os.environ.get("PKEXEC_UID")
    try:
        if user and user != "root":
            return pwd.getpwnam(user).pw_dir
        if uid and uid != "0":
            return pwd.getpwuid(int(uid)).pw_dir
    except (KeyError, ValueError):
        pass
    if os.geteuid() != 0:
        return os.path.expanduser("~")
    # Hiçbir bilgi yoksa: grafik oturumu açık olan normal kullanıcıyı bul
    candidates = []
    for pw in pwd.getpwall():
        if pw.pw_uid >= 1000 and pw.pw_dir.startswith("/home/") and \
                os.path.isdir(os.path.join(pw.pw_dir, ".config", "xfce4")):
            candidates.append(pw.pw_dir)
    return candidates[0] if len(candidates) == 1 else None


def _adopt_real_user_env():
    if os.geteuid() != 0:
        return
    home = real_user_home()
    if home and home != "/root":
        os.environ.setdefault("XDG_CONFIG_HOME", os.path.join(home, ".config"))
        os.environ.setdefault("XDG_DATA_HOME", os.path.join(home, ".local", "share"))
    os.environ.setdefault("XDG_MENU_PREFIX", "xfce-")


def find_menu_file():
    from . import xdgmenu
    return xdgmenu.find_menu_file()


def scan_menu():
    """Uygulama menüsünü XFCE'nin gördüğü gibi okuyup MenuNode ağacı döndürür."""
    _adopt_real_user_env()
    from . import xdgmenu
    menu_file = xdgmenu.find_menu_file()
    if not menu_file:
        raise OmyError("Uygulama menüsü dosyası bulunamadı (/etc/xdg/menus/"
                       "xfce-applications.menu). XFCE kurulu mu?")
    try:
        menu = xdgmenu.parse(menu_file)
    except Exception as e:  # bozuk bir menü dosyası yüzünden çökmeyelim
        raise OmyError("Menü dosyası okunamadı (%s): %s" % (menu_file, e))

    def convert(m, path):
        de = xdgmenu.load_entry(m.directory_file) if m.directory_file else None
        node = MenuNode(m.name, (de.get("Name", True) if de else "") or m.name,
                        de.get("Icon") if de else "", de.get("Comment", True) if de else "",
                        path, m.directory_file)
        for sub in m.submenus:
            if sub.deleted:
                continue
            sde = xdgmenu.load_entry(sub.directory_file) if sub.directory_file else None
            if sde is not None and (sde.get_bool("NoDisplay") or sde.get_bool("Hidden")):
                continue
            node.children.append(convert(sub, path + [sub.name]))
        for desktop_id, e in sorted(m.entries.items()):
            if not e.visible():
                continue
            node.entries.append({
                "id": desktop_id,
                "title": e.get("Name", True) or desktop_id,
                "icon": e.get("Icon"),
                "comment": e.get("Comment", True),
                "file": e.path,
            })
        return node

    root = convert(menu, [])
    root.title = "Uygulama Menüsü"
    return root


def whisker_favorites():
    """Whisker menünün “Favorites” listesindeki uygulamalar."""
    from . import xdgmenu
    _adopt_real_user_env()
    cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    panel = os.path.join(cfg, "xfce4", "panel")
    ids = []
    try:
        files = sorted(f for f in os.listdir(panel)
                       if f.startswith("whiskermenu") and f.endswith(".rc"))
    except OSError:
        files = []
    for fn in files:
        try:
            with open(os.path.join(panel, fn), encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("favorites="):
                        ids = [x.strip() for x in line.split("=", 1)[1].split(",") if x.strip()]
                        break
        except OSError:
            continue
        if ids:
            break
    result = []
    for desktop_id in ids:
        path = xdgmenu.find_desktop_file(desktop_id)
        e = xdgmenu.load_entry(path) if path else None
        if e is None:
            continue
        result.append({"id": desktop_id, "title": e.get("Name", True) or desktop_id,
                       "icon": e.get("Icon"), "comment": e.get("Comment", True),
                       "file": path})
    return result


def collect_desktop_ids(node, out=None):
    if out is None:
        out = set()
    for e in node.entries:
        out.add(e["id"])
    for c in node.children:
        collect_desktop_ids(c, out)
    return out


# --------------------------------------------------------------------------
# Mevcut (sistemdeki) kategori ve uygulamaların ad/simgesini değiştirme
#
# /usr/share altındaki bir dosya için /usr/local/share altına aynı adlı bir
# kopya yazılır (XDG'de önceliklidir, paket güncellemeleri de bozmaz).
# Başka yerdeki dosyalar (ör. ~/.local/share) yerinde değiştirilir ve
# özgün hali "<dosya>.omy-yedek" olarak saklanır.

def unroot(path):
    """sys_path'in tersi: OMY_ROOT önekini kaldırır."""
    root = os.environ.get("OMY_ROOT", "/").rstrip("/")
    if root and path.startswith(root + "/"):
        return path[len(root):]
    return path


def override_kind_dir(kind):
    return "desktop-directories" if kind == "directory" else "applications"


def override_target(kind, orig):
    """(hedef yol, yerinde_mi) döndürür. Yollar mantıksal (OMY_ROOT'suz)."""
    sub = "/%s/" % override_kind_dir(kind)
    idx = orig.find(sub)
    if idx < 0:
        return orig, True
    base, rel = orig[:idx], orig[idx + len(sub):]
    if base == "/usr/share":
        return os.path.join(OVERRIDE_BASE, override_kind_dir(kind), rel), False
    return orig, True


def find_override(state, kind, ident):
    for ov in state.get("overrides", []):
        if ov["kind"] == kind and ov["id"] == ident:
            return ov
    return None


def set_override(state, kind, ident, orig, name, icon):
    """Mevcut bir kategori (kind="directory") ya da uygulamanın (kind="app")
    adını/simgesini değiştirir. orig: dosyanın gerçek tam yolu."""
    ov = find_override(state, kind, ident)
    if ov is None:
        logical = unroot(orig)
        target, in_place = override_target(kind, logical)
        if not os.path.isfile(sys_path(logical)):
            raise OmyError("Dosya bulunamadı: %s" % logical)
        ov = {"kind": kind, "id": ident, "orig": logical, "target": target,
              "backup": (target + ".omy-yedek") if in_place else ""}
        if ov["backup"] and not os.path.exists(sys_path(ov["backup"])):
            shutil.copy2(sys_path(logical), sys_path(ov["backup"]))
        state.setdefault("overrides", []).append(ov)
    ov["name"] = name or ""
    ov["icon"] = icon or ""
    return ov


def remove_override(state, ov):
    """Özgün hale geri döndürür."""
    target = sys_path(ov["target"])
    if ov.get("backup"):
        backup = sys_path(ov["backup"])
        if os.path.isfile(backup):
            shutil.copy2(backup, target)
            os.unlink(backup)
    elif _is_ours(target):
        os.unlink(target)
    state["overrides"].remove(ov)


def modify_entry_text(text, name, icon):
    """[Desktop Entry] grubundaki Name/Icon satırlarını değiştirir."""
    out = []
    group = None
    done_name = done_icon = False
    lines = text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if group == "[Desktop Entry]":
                if name and not done_name:
                    out.append("Name=%s" % kf_escape(name))
                if icon and not done_icon:
                    out.append("Icon=%s" % kf_escape(icon))
                done_name = done_icon = True
            group = stripped
            out.append(line)
            if group == "[Desktop Entry]":
                out.append(MARKER)
            continue
        if group == "[Desktop Entry]" and "=" in line and not stripped.startswith("#"):
            key = line.split("=", 1)[0].strip()
            if name and (key == "Name" or key.startswith("Name[")):
                if not done_name:
                    out.append("Name=%s" % kf_escape(name))
                    done_name = True
                continue
            if icon and key == "Icon":
                out.append("Icon=%s" % kf_escape(icon))
                done_icon = True
                continue
        if stripped == MARKER:
            continue
        out.append(line)
    if group == "[Desktop Entry]":
        if name and not done_name:
            out.append("Name=%s" % kf_escape(name))
        if icon and not done_icon:
            out.append("Icon=%s" % kf_escape(icon))
    return "\n".join(out) + "\n"


def apply_overrides(state, warnings):
    for ov in state.get("overrides", []):
        source = sys_path(ov["backup"] or ov["orig"])
        try:
            with open(source, encoding="utf-8") as f:
                text = f.read()
        except OSError:
            warnings.append("Özgün dosya bulunamadı: %s" % (ov["backup"] or ov["orig"]))
            continue
        target = sys_path(ov["target"])
        if not ov["backup"] and os.path.exists(target) and not _is_ours(target):
            warnings.append("%s başka bir programa ait; değiştirilmedi." % ov["target"])
            continue
        _write_file(target, modify_entry_text(text, ov.get("name"), ov.get("icon")))


def cleanup_all():
    """Bu uygulamanın yaptığı bütün menü değişikliklerini geri alır
    (indirilen araç klasörlerine dokunmaz)."""
    state = load_state()
    for ov in list(state.get("overrides", [])):
        try:
            remove_override(state, ov)
        except OSError:
            pass
    apply(empty_state())
    for p in (MERGE_FILE, RUNNER):
        if os.path.exists(sys_path(p)):
            os.unlink(sys_path(p))


# --------------------------------------------------------------------------
# Kurulum işlemleri

def run_cmd(argv, log, cwd=None, env=None):
    """Komutu çalıştırıp çıktısını satır satır log() ile iletir; çıkış kodunu
    döndürür."""
    log("$ %s\n" % " ".join(shlex.quote(a) for a in argv))
    full_env = dict(os.environ)
    full_env.update(env or {})
    full_env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    full_env["GIT_TERMINAL_PROMPT"] = "0"
    full_env["PYTHONUNBUFFERED"] = "1"
    try:
        p = subprocess.Popen(argv, cwd=cwd, env=full_env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        log("HATA: '%s' bulunamadı.\n" % argv[0])
        return 127
    for raw in iter(p.stdout.readline, b""):
        log(raw.decode("utf-8", "replace"))
    p.wait()
    if p.returncode != 0:
        log("[çıkış kodu: %d]\n" % p.returncode)
    return p.returncode


def _make_world_writable(path):
    """Araç klasörünü herkesin yazabileceği hale getirir; çoğu GitHub aracı
    çıktı ve önbellek dosyalarını kendi klasörüne yazar."""
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames + [""]:
            p = os.path.join(dirpath, name) if name else dirpath
            try:
                if os.path.islink(p):
                    continue
                st = os.stat(p)
                extra = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | \
                    stat.S_IROTH | stat.S_IWOTH
                if stat.S_ISDIR(st.st_mode) or st.st_mode & stat.S_IXUSR:
                    extra |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                os.chmod(p, st.st_mode | extra)
            except OSError:
                pass


def install_python_deps(real_dir, log):
    """requirements.txt / setup.py / pyproject.toml varsa .venv sanal ortamı
    kurar. Başarılıysa True, sorun olduysa False döndürür."""
    req = os.path.join(real_dir, "requirements.txt")
    has_req = os.path.isfile(req)
    has_pkg = any(os.path.isfile(os.path.join(real_dir, f))
                  for f in ("setup.py", "pyproject.toml"))
    if not has_req and not has_pkg:
        return True
    venv = os.path.join(real_dir, ".venv")
    ok = True
    if not os.path.isfile(os.path.join(venv, "bin", "python")):
        log("\n>>> Python sanal ortamı oluşturuluyor (.venv)\n")
        if run_cmd(["python3", "-m", "venv", "--system-site-packages", venv], log) != 0:
            log("HATA: Sanal ortam oluşturulamadı. 'sudo apt install python3-venv' "
                "ile paketi kurup tekrar deneyin.\n")
            return False
    pip = os.path.join(venv, "bin", "pip")
    run_cmd([pip, "install", "--upgrade", "pip", "setuptools", "wheel"], log)
    if has_req:
        log("\n>>> requirements.txt bağımlılıkları kuruluyor\n")
        if run_cmd([pip, "install", "-r", req], log, cwd=real_dir) != 0:
            ok = False
    if has_pkg:
        log("\n>>> Proje paketi kuruluyor (pip install .)\n")
        if run_cmd([pip, "install", real_dir], log, cwd=real_dir) != 0:
            if not has_req:
                ok = False
            log("Not: 'pip install .' başarısız oldu; betik doğrudan çalıştırılabilir.\n")
    return ok


def install_other_deps(real_dir, command, log):
    ok = True
    if os.path.isfile(os.path.join(real_dir, "Gemfile")) and shutil.which("bundle"):
        log("\n>>> Ruby bağımlılıkları kuruluyor (bundle install)\n")
        ok &= run_cmd(["bundle", "install"], log, cwd=real_dir) == 0
    if os.path.isfile(os.path.join(real_dir, "package.json")) and shutil.which("npm"):
        log("\n>>> Node.js bağımlılıkları kuruluyor (npm install)\n")
        ok &= run_cmd(["npm", "install"], log, cwd=real_dir) == 0
    if os.path.isfile(os.path.join(real_dir, "go.mod")):
        if shutil.which("go"):
            log("\n>>> Go projesi derleniyor\n")
            ok &= run_cmd(["go", "build", "-o", command, "."], log, cwd=real_dir) == 0
        else:
            log("Not: Go projesi ama 'go' yüklü değil (sudo apt install golang).\n")
    for script in ("install.sh", "setup.sh"):
        if os.path.isfile(os.path.join(real_dir, script)):
            log("Not: Depoda '%s' var. Güvenlik nedeniyle otomatik çalıştırılmadı; "
                "gerekirse klasörde elle çalıştırın.\n" % script)
    return ok


_SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__",
              "tests", "test", "docs", "doc", "examples", ".github"}
_SKIP_FILES = {"setup.py", "__init__.py", "conftest.py", "install.sh", "setup.sh",
               "uninstall.sh", "noxfile.py", "fabfile.py"}
_VENV_BASE = re.compile(r"^(python[0-9.]*|pip[0-9.]*|activate.*|Activate.*|"
                        r"easy_install.*|wheel|pydoc.*|normalizer|chardetect|"
                        r"f2py.*|distro|httpx|dotenv|markdown-it|pygmentize|"
                        r"tqdm|jsonschema|pyrsa-.*|websockets?|"
                        r"__pycache__)$")


def find_entry_candidates(real_dir, names=()):
    """Çalıştırılabilecek dosyaları en olası olandan başlayarak listeler.
    Her öğe (entry, açıklama) çiftidir."""
    names = {slugify(n) for n in names if n}
    names |= {n.replace("-", "_") for n in names}
    scored = []

    def score_file(rel, depth):
        base = os.path.basename(rel)
        stem, ext = os.path.splitext(base)
        if base in _SKIP_FILES or stem.lower().startswith("test"):
            return None
        full = os.path.join(real_dir, rel)
        executable = os.access(full, os.X_OK)
        if ext.lower() not in EXT_RUNNER and not executable:
            return None
        if ext.lower() in (".so", ".o", ".a", ".dll", ".txt", ".md", ".json"):
            return None
        s = 0
        if slugify(stem) in names or stem.lower() in names:
            s += 100
        if stem.lower() in ("main", "run", "cli", "app", "start", "__main__"):
            s += 40
        if depth == 0:
            s += 20
        if ext.lower() == ".py":
            s += 5
            try:
                with open(full, encoding="utf-8", errors="ignore") as f:
                    if "__main__" in f.read(200000):
                        s += 10
            except OSError:
                pass
        if executable and ext == "":
            s += 15
        return s

    for dirpath, dirnames, filenames in os.walk(real_dir):
        rel_dir = os.path.relpath(dirpath, real_dir)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        if depth >= 2:
            dirnames[:] = []
        for fn in filenames:
            rel = fn if depth == 0 else os.path.join(rel_dir, fn)
            s = score_file(rel, depth)
            if s is not None:
                scored.append((s, rel, rel))

    # pip ile kurulan komutlar yalnızca proje kendisi bir paketse listelenir;
    # aksi halde bağımlılıkların betikleri karışıklık yaratır.
    venv_bin = os.path.join(real_dir, ".venv", "bin")
    is_package = any(os.path.isfile(os.path.join(real_dir, f))
                     for f in ("setup.py", "pyproject.toml"))
    if is_package and os.path.isdir(venv_bin):
        for fn in os.listdir(venv_bin):
            if _VENV_BASE.match(fn):
                continue
            s = 60 + (100 if slugify(fn) in names else 0)
            scored.append((s, "venv:" + fn, "%s (pip ile kurulan komut)" % fn))

    scored.sort(key=lambda x: (-x[0], x[1].count(os.sep), x[1].lower()))
    return [(entry, label) for _s, entry, label in scored]


def install_git(url, tool_id, command, log):
    """Git deposunu /opt/osint-tools altına indirir ve bağımlılıkları kurar."""
    if not shutil.which("git"):
        raise OmyError("git yüklü değil (sudo apt install git).")
    url = url.strip()
    if re.match(r"^[\w.-]+/[\w.-]+$", url):
        url = "https://github.com/%s" % url
    tdir = os.path.join(TOOLS_DIR, tool_id)
    real = sys_path(tdir)
    if os.path.exists(real):
        raise OmyError("%s zaten var. Farklı bir ad seçin ya da klasörü silin." % tdir)
    os.makedirs(os.path.dirname(real), exist_ok=True)
    log(">>> Depo indiriliyor: %s\n" % url)
    if run_cmd(["git", "clone", "--depth", "1", "--recurse-submodules", url, real], log) != 0:
        shutil.rmtree(real, ignore_errors=True)
        raise OmyError("Depo indirilemedi. Adresi ve internet bağlantısını kontrol edin.")
    ok = install_python_deps(real, log)
    ok = install_other_deps(real, command, log) and ok
    _make_world_writable(real)
    return {"dir": tdir, "deps_ok": ok}


def install_local(src, tool_id, command, log):
    """Bilgisayardaki klasörü/dosyayı /opt/osint-tools altına kopyalar."""
    src = os.path.expanduser(src.strip())
    if not os.path.exists(src):
        raise OmyError("Bulunamadı: %s" % src)
    tdir = os.path.join(TOOLS_DIR, tool_id)
    real = sys_path(tdir)
    if os.path.exists(real):
        raise OmyError("%s zaten var. Farklı bir ad seçin ya da klasörü silin." % tdir)
    log(">>> Kopyalanıyor: %s -> %s\n" % (src, tdir))
    entry = ""
    if os.path.isdir(src):
        shutil.copytree(src, real, symlinks=True,
                        ignore=shutil.ignore_patterns(".venv", "__pycache__"))
    else:
        os.makedirs(real)
        shutil.copy2(src, real)
        entry = os.path.basename(src)
    ok = install_python_deps(real, log)
    ok = install_other_deps(real, command, log) and ok
    _make_world_writable(real)
    return {"dir": tdir, "deps_ok": ok, "entry": entry}


def pipx_env():
    return {"PIPX_HOME": PIPX_HOME, "PIPX_BIN_DIR": BIN_DIR,
            "PIPX_MAN_DIR": "/usr/local/share/man"}


def _pipx_apps():
    """pipx paketlerini {paket: [komutlar]} olarak döndürür."""
    env = dict(os.environ)
    env.update(pipx_env())
    try:
        out = subprocess.run(["pipx", "list", "--json"], env=env, capture_output=True,
                             text=True, timeout=60).stdout
        data = json.loads(out or "{}")
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    result = {}
    for name, info in data.get("venvs", {}).items():
        main = info.get("metadata", {}).get("main_package", {})
        result[name] = list(main.get("apps", []))
    return result


def install_pipx(spec, log):
    """pipx paketini sistem geneline (/opt/pipx, /usr/local/bin) kurar."""
    if not shutil.which("pipx"):
        raise OmyError("pipx yüklü değil (sudo apt install pipx).")
    spec = spec.strip()
    if re.match(r"^https?://", spec) or spec.startswith("github.com/"):
        spec = "git+" + (spec if spec.startswith("http") else "https://" + spec)
    before = _pipx_apps()
    if run_cmd(["pipx", "install", spec], log, env=pipx_env()) != 0:
        raise OmyError("pipx kurulumu başarısız oldu; ayrıntılar günlükte.")
    after = _pipx_apps()
    package, apps = None, []
    for name, a in after.items():
        if name not in before:
            package, apps = name, a
    if package is None:
        guess = slugify(name_from_source("pipx", spec))
        for name, a in after.items():
            if slugify(name) == guess:
                package, apps = name, a
    return {"package": package or name_from_source("pipx", spec), "apps": apps}


def install_apt(package, log):
    package = package.strip()
    if not re.match(r"^[a-z0-9][a-z0-9.+-]*$", package):
        raise OmyError("Geçersiz paket adı: %s" % package)
    if run_cmd(["apt-get", "install", "-y", package], log) != 0:
        log("\n>>> Paket listesi güncelleniyor ve tekrar deneniyor\n")
        run_cmd(["apt-get", "update"], log)
        if run_cmd(["apt-get", "install", "-y", package], log) != 0:
            raise OmyError("APT kurulumu başarısız oldu; ayrıntılar günlükte.")
    return {"package": package}


def update_tool(tool, log):
    """Aracı günceller (git pull / pipx upgrade / apt)."""
    src = tool["source"]
    t = src["type"]
    if t == "git":
        real = sys_path(src["dir"])
        if run_cmd(["git", "-c", "safe.directory=*", "-C", real, "pull", "--ff-only"],
                   log) != 0:
            raise OmyError("git pull başarısız oldu.")
        install_python_deps(real, log)
        install_other_deps(real, tool["command"], log)
        _make_world_writable(real)
    elif t == "local":
        real = sys_path(src["dir"])
        install_python_deps(real, log)
        install_other_deps(real, tool["command"], log)
    elif t == "pipx":
        if run_cmd(["pipx", "upgrade", src.get("package", "")], log, env=pipx_env()) != 0:
            raise OmyError("pipx upgrade başarısız oldu.")
    elif t == "apt":
        run_cmd(["apt-get", "update"], log)
        if run_cmd(["apt-get", "install", "-y", "--only-upgrade", src.get("package", "")],
                   log) != 0:
            raise OmyError("APT güncellemesi başarısız oldu.")
    else:
        log("Bu araç başka bir yolla kurulduğu için buradan güncellenemez.\n")


def uninstall_tool(tool, remove_files, log=lambda s: None):
    """Aracı durumdan bağımsız olarak diskten temizler. remove_files True ise
    indirilen klasör / pipx paketi de silinir."""
    src = tool["source"]
    if src["type"] in SOURCES_WITH_WRAPPER:
        remove_wrapper(tool["command"])
    remove_icon(tool.get("icon"))
    if not remove_files:
        return
    if src["type"] in SOURCES_WITH_WRAPPER and src.get("dir", "").startswith(TOOLS_DIR + "/"):
        shutil.rmtree(sys_path(src["dir"]), ignore_errors=True)
    elif src["type"] == "pipx" and src.get("package"):
        run_cmd(["pipx", "uninstall", src["package"]], log, env=pipx_env())
