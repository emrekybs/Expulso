# -*- coding: utf-8 -*-
"""XDG (freedesktop) uygulama menüsü okuyucusu.

XFCE'nin menü kütüphanesi garcon ile aynı kuralları uygular: MergeFile,
MergeDir, DefaultMergeDirs ("applications-merged"), Move, Include/Exclude,
OnlyUnallocated, Deleted, AppDir/DirectoryDir ve yerelleştirilmiş adlar.
Harici bir kütüphaneye ihtiyaç duymaz.
"""

import os
import xml.etree.ElementTree as ET

DESKTOP_ENV = "XFCE"


# --------------------------------------------------------------------------
# XDG klasörleri

def _env_dirs(name, default):
    value = os.environ.get(name, "")
    dirs = [d for d in value.split(":") if d] if value else []
    return dirs or default


def data_dirs():
    """Öncelik sırasına göre (ilk = en öncelikli) veri klasörleri."""
    home = os.environ.get("XDG_DATA_HOME") or \
        os.path.join(os.path.expanduser("~"), ".local", "share")
    return _dedupe([home] + _env_dirs("XDG_DATA_DIRS", ["/usr/local/share", "/usr/share"]))


def config_dirs():
    home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return _dedupe([home] + _env_dirs("XDG_CONFIG_DIRS", ["/etc/xdg"]))


def _dedupe(items):
    seen, out = set(), []
    for i in items:
        i = os.path.normpath(i)
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def menu_prefix():
    return os.environ.get("XDG_MENU_PREFIX", "xfce-")


def find_menu_file():
    prefix = menu_prefix()
    for name in (prefix + "applications.menu", "xfce-applications.menu", "applications.menu"):
        for d in config_dirs():
            p = os.path.join(d, "menus", name)
            if os.path.isfile(p):
                return p
    return None


# --------------------------------------------------------------------------
# Desktop dosyaları

def _locales():
    lang = ""
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        lang = os.environ.get(var, "")
        if lang:
            break
    lang = lang.split(".")[0].split("@")[0]
    if not lang or lang in ("C", "POSIX"):
        return []
    out = [lang]
    if "_" in lang:
        out.append(lang.split("_")[0])
    return out


_LOCALES = None


def _unescape(value):
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            n = value[i + 1]
            out.append({"s": " ", "n": "\n", "t": "\t", "r": "\r", "\\": "\\"}.get(n, "\\" + n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


class DesktopEntry:
    """[Desktop Entry] grubunu okuyan basit ayrıştırıcı."""

    def __init__(self, path):
        self.path = path
        self.data = {}
        group = None
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    group = line[1:-1]
                    continue
                if group == "Desktop Entry" and "=" in line:
                    k, v = line.split("=", 1)
                    self.data.setdefault(k.strip(), _unescape(v.strip()))

    def get(self, key, localized=False):
        global _LOCALES
        if localized:
            if _LOCALES is None:
                _LOCALES = _locales()
            for loc in _LOCALES:
                v = self.data.get("%s[%s]" % (key, loc))
                if v:
                    return v
        return self.data.get(key, "")

    def get_list(self, key):
        return [x for x in self.get(key).split(";") if x]

    def get_bool(self, key):
        return self.get(key).strip().lower() == "true"

    def visible(self):
        if self.get_bool("NoDisplay") or self.get_bool("Hidden"):
            return False
        only = self.get_list("OnlyShowIn")
        if only and DESKTOP_ENV not in only:
            return False
        return DESKTOP_ENV not in self.get_list("NotShowIn")


_ENTRY_CACHE = {}


def load_entry(path):
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return None
    cached = _ENTRY_CACHE.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        entry = DesktopEntry(path)
    except OSError:
        entry = None
    _ENTRY_CACHE[path] = (mtime, entry)
    return entry


def scan_app_dir(d):
    """Klasördeki .desktop dosyalarını {desktop-id: yol} olarak döndürür."""
    result = {}
    if not os.path.isdir(d):
        return result
    for root, dirs, files in os.walk(d, followlinks=True):
        dirs.sort()
        for fn in files:
            if fn.endswith(".desktop"):
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, d)
                result[rel.replace(os.sep, "-")] = full
    return result


def find_desktop_file(desktop_id):
    for d in data_dirs():
        apps = scan_app_dir(os.path.join(d, "applications"))
        if desktop_id in apps:
            return apps[desktop_id]
    return None


# --------------------------------------------------------------------------
# Menü ağacı

class _Menu:
    def __init__(self):
        self.name = ""
        self.directories = []
        self.app_dirs = []
        self.dir_dirs = []
        self.rules = []          # [("include"|"exclude", kural)]
        self.only_unallocated = None
        self.deleted = None
        self.submenus = []
        self.moves = []
        # sonuçlar
        self.directory_file = None
        self.entries = {}

    def merge(self, other):
        self.directories += other.directories
        self.app_dirs += other.app_dirs
        self.dir_dirs += other.dir_dirs
        self.rules += other.rules
        if other.only_unallocated is not None:
            self.only_unallocated = other.only_unallocated
        if other.deleted is not None:
            self.deleted = other.deleted
        self.submenus += other.submenus
        self.moves += other.moves


class MenuParser:
    def __init__(self):
        self._stack = []

    def parse(self, filename):
        self.root_file = filename
        root = _Menu()
        self._parse_file(filename, root, is_root=True)
        _dedupe_submenus(root)
        _apply_moves(root)
        _dedupe_submenus(root)
        _resolve(root, [], [])
        pool_cache = {}
        allocated = set()
        _allocate(root, False, allocated, pool_cache)
        _allocate(root, True, allocated, pool_cache)
        return root

    # --- dosya okuma
    def _parse_file(self, filename, menu, is_root=False):
        real = os.path.realpath(filename)
        if real in self._stack:
            return
        try:
            tree = ET.parse(filename)
        except (OSError, ET.ParseError):
            return
        node = tree.getroot()
        if node.tag != "Menu":
            return
        self._stack.append(real)
        try:
            self._parse_menu(node, menu, filename, keep_name=is_root)
        finally:
            self._stack.pop()

    def _parse_menu(self, node, menu, filename, keep_name=True):
        base = os.path.dirname(filename)
        for child in node:
            tag = child.tag
            text = (child.text or "").strip()
            if tag == "Menu":
                sub = _Menu()
                self._parse_menu(child, sub, filename)
                menu.submenus.append(sub)
            elif tag == "Name":
                if keep_name and text:
                    menu.name = text
            elif tag == "Directory" and text:
                menu.directories.append(text)
            elif tag == "AppDir" and text:
                menu.app_dirs.append(os.path.join(base, text))
            elif tag == "DefaultAppDirs":
                menu.app_dirs += [os.path.join(d, "applications") for d in reversed(data_dirs())]
            elif tag == "DirectoryDir" and text:
                menu.dir_dirs.append(os.path.join(base, text))
            elif tag == "DefaultDirectoryDirs":
                menu.dir_dirs += [os.path.join(d, "desktop-directories")
                                  for d in reversed(data_dirs())]
            elif tag == "OnlyUnallocated":
                menu.only_unallocated = True
            elif tag == "NotOnlyUnallocated":
                menu.only_unallocated = False
            elif tag == "Deleted":
                menu.deleted = True
            elif tag == "NotDeleted":
                menu.deleted = False
            elif tag in ("Include", "Exclude"):
                rule = ("or", [_parse_rule(c) for c in child])
                menu.rules.append((tag.lower(), rule))
            elif tag == "MergeFile":
                path = self._merge_file_path(child, text, filename)
                if path:
                    self._parse_file(path, menu)
            elif tag == "MergeDir" and text:
                self._merge_dir(os.path.join(base, text), menu)
            elif tag == "DefaultMergeDirs":
                name = os.path.splitext(os.path.basename(self.root_file))[0]
                if name == menu_prefix() + "applications":
                    name = "applications"
                for d in reversed(config_dirs()):
                    self._merge_dir(os.path.join(d, "menus", name + "-merged"), menu)
            elif tag == "Move":
                old = child.findtext("Old")
                new = child.findtext("New")
                if old and new:
                    menu.moves.append((old.strip(), new.strip()))

    def _merge_dir(self, d, menu):
        if not os.path.isdir(d):
            return
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".menu"):
                self._parse_file(os.path.join(d, fn), menu)

    def _merge_file_path(self, child, text, filename):
        if child.get("type") == "parent":
            # Aynı göreli yoldaki bir sonraki (daha düşük öncelikli) dosya
            dirs = config_dirs()
            for i, d in enumerate(dirs):
                prefix = d.rstrip("/") + "/"
                if filename.startswith(prefix):
                    rel = filename[len(prefix):]
                    for other in dirs[i + 1:]:
                        p = os.path.join(other, rel)
                        if os.path.isfile(p):
                            return p
            return None
        if not text:
            return None
        return text if os.path.isabs(text) else os.path.join(os.path.dirname(filename), text)


def _parse_rule(node):
    tag = node.tag
    text = (node.text or "").strip()
    if tag == "Filename":
        return ("filename", text)
    if tag == "Category":
        return ("category", text)
    if tag == "All":
        return ("all",)
    if tag in ("And", "Or", "Not"):
        return (tag.lower(), [_parse_rule(c) for c in node])
    return ("none",)


def _match(rule, desktop_id, categories):
    kind = rule[0]
    if kind == "filename":
        return rule[1] == desktop_id
    if kind == "category":
        return rule[1] in categories
    if kind == "all":
        return True
    if kind == "or":
        return any(_match(r, desktop_id, categories) for r in rule[1])
    if kind == "and":
        return bool(rule[1]) and all(_match(r, desktop_id, categories) for r in rule[1])
    if kind == "not":
        return not any(_match(r, desktop_id, categories) for r in rule[1])
    return False


def _dedupe_submenus(menu):
    merged = []
    by_name = {}
    for sub in menu.submenus:
        if sub.name in by_name:
            by_name[sub.name].merge(sub)
        else:
            by_name[sub.name] = sub
            merged.append(sub)
    menu.submenus = merged
    for sub in merged:
        _dedupe_submenus(sub)


def _find_path(menu, parts):
    for p in parts:
        menu = next((s for s in menu.submenus if s.name == p), None)
        if menu is None:
            return None
    return menu


def _apply_moves(menu):
    for old, new in menu.moves:
        old_parts = [p for p in old.split("/") if p]
        new_parts = [p for p in new.split("/") if p]
        if not old_parts or not new_parts:
            continue
        parent = _find_path(menu, old_parts[:-1])
        src = _find_path(menu, old_parts)
        if parent is None or src is None:
            continue
        parent.submenus.remove(src)
        dest_parent = menu
        for p in new_parts[:-1]:
            nxt = next((s for s in dest_parent.submenus if s.name == p), None)
            if nxt is None:
                nxt = _Menu()
                nxt.name = p
                dest_parent.submenus.append(nxt)
            dest_parent = nxt
        existing = next((s for s in dest_parent.submenus if s.name == new_parts[-1]), None)
        if existing is not None:
            existing.merge(src)
        else:
            src.name = new_parts[-1]
            dest_parent.submenus.append(src)
    for sub in menu.submenus:
        _apply_moves(sub)


def _resolve(menu, parent_apps, parent_dirs):
    menu.app_dirs = _dedupe(parent_apps + menu.app_dirs)
    menu.dir_dirs = _dedupe(parent_dirs + menu.dir_dirs)
    for name in reversed(menu.directories):
        for d in reversed(menu.dir_dirs):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                menu.directory_file = p
                break
        if menu.directory_file:
            break
    for sub in menu.submenus:
        _resolve(sub, menu.app_dirs, menu.dir_dirs)


def _pool(app_dirs, cache):
    key = tuple(app_dirs)
    if key not in cache:
        pool = {}
        for d in app_dirs:          # sonraki klasör önceliklidir
            pool.update(scan_app_dir(d))
        entries = {}
        for desktop_id, path in pool.items():
            e = load_entry(path)
            if e is None or e.get_bool("Hidden") or e.get("Type") != "Application":
                continue
            entries[desktop_id] = (e, set(e.get_list("Categories")))
        cache[key] = entries
    return cache[key]


def _allocate(menu, unallocated_pass, allocated, cache):
    if bool(menu.only_unallocated) == unallocated_pass:
        pool = _pool(menu.app_dirs, cache)
        chosen = {}
        for kind, rule in menu.rules:
            for desktop_id, (e, cats) in pool.items():
                if kind == "include":
                    if desktop_id not in chosen and \
                            (not unallocated_pass or desktop_id not in allocated) and \
                            _match(rule, desktop_id, cats):
                        chosen[desktop_id] = e
                elif desktop_id in chosen and _match(rule, desktop_id, cats):
                    del chosen[desktop_id]
        menu.entries = chosen
        if not unallocated_pass:
            allocated.update(chosen)
    for sub in menu.submenus:
        _allocate(sub, unallocated_pass, allocated, cache)


def parse(filename=None):
    """Menüyü okur. Döndürülen kök _Menu nesnesinde submenus (alt menüler),
    entries ({desktop-id: DesktopEntry}) ve directory_file bulunur."""
    filename = filename or find_menu_file()
    if not filename:
        raise FileNotFoundError("Uygulama menüsü dosyası (*applications.menu) bulunamadı.")
    return MenuParser().parse(filename)
