# -*- coding: utf-8 -*-
"""Toplu kurulum: bir liste dosyasındaki bütün kategori ve araçları tek
komutla kurar ve menüye ekler.

  sudo osint-menu-yonetici --toplu araclar.ini

Dosya biçimi (INI):

  [kategori: OSINT Dark Web]
  konum = OSINT              ; nerede oluşturulsun (boşsa en üst)
  simge = osint-dark-web     ; hazır simge adı, tema simgesi ya da dosya yolu
  renk = #613583             ; bu kategorideki rozet simgelerinin rengi

  [arac: Holehe]
  kaynak = pipx holehe       ; git <adres> | pipx <paket> | apt <paket(ler)> |
                             ; yerel <klasör/dosya> | kurulu <komut> | web <adres>
  kategori = OSINT email     ; "OSINT email" ya da "OSINT / OSINT email"
  komut = holehe             ; terminal komutu (boşsa addan üretilir)
  parametre = -h             ; menüden açılınca kullanılacak parametreler
  simge = otomatik           ; otomatik | depo:<dosya> | rozet | hazır simge |
                             ; tema simgesi | dosya yolu
  aciklama = E-posta hangi sitelerde kayıtlı
  calistir = holehe.py       ; (git/yerel) çalışacak dosya; boşsa otomatik bulunur
  calistirici = auto         ; auto | python | bash | node | direct ...
  klasorde = evet            ; (git/yerel) aracın klasöründe çalıştır
  terminal = evet            ; menüden terminalde aç
  paketler = tor cargo       ; önce kurulacak APT paketleri
  kurulum = cargo build --release   ; indirildikten sonra klasörde çalışacak komut
  ac = http://127.0.0.1:5000 ; web arayüzlü araç: menüden açınca tarayıcıda aç
  zorla = hayır              ; menüde aynı adlı araç olsa bile ekle

  [guncelle]
  kategoriler = OSINT, Frameworks   ; menüde zaten olan araçları güncelle

Zaten eklenmiş ya da menüde aynı adla bulunan araçlar atlanır; dosya tekrar
tekrar çalıştırılabilir.
"""

import configparser
import glob
import os
import re
import shlex
import shutil
import subprocess
import sys

from . import core

YES = ("evet", "e", "yes", "y", "true", "1", "açık", "acik")
PALETTE = ["#367bf0", "#e01b8a", "#5e5ce6", "#f57900", "#26a269", "#0b8fa8", "#613583",
           "#c01c28", "#c64600", "#1a5fb4", "#865e3c", "#2b9348"]


def _bool(value, default):
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in YES


def _norm(text):
    return " ".join((text or "").split()).casefold()


def _loose(text):
    return re.sub(r"[^a-z0-9]+", "", (text or "").translate(core._TR).casefold())


def _split_path(spec):
    for sep in ("▸", ">", "/"):
        if sep in spec:
            return [p.strip() for p in spec.split(sep) if p.strip()]
    return [spec.strip()] if spec.strip() else []


class Batch:
    def __init__(self, log=None):
        self.log = log or (lambda s: (sys.stdout.write(s), sys.stdout.flush()))
        self.state = core.load_state()
        self.ok, self.skipped, self.failed, self.notes = [], [], [], []
        self.cat_colors = {}
        self._rescan()

    def _rescan(self):
        try:
            self.tree = core.scan_menu()
        except core.OmyError as e:
            self.log("UYARI: mevcut menü okunamadı (%s); yalnızca bu araçla oluşturulan "
                     "kategoriler kullanılabilir.\n" % e)
            self.tree = None
        self.menus = []            # (yol, [başlıklar])
        self.menu_entries = {}     # normalize ad -> (başlık, kategori başlığı)
        if self.tree is not None:
            def visit(n, titles):
                for e in n.entries:
                    if not e["id"].startswith(core.PREFIX):
                        self.menu_entries.setdefault(_loose(e["title"]),
                                                     (e["title"], " ▸ ".join(titles)))
                for c in n.children:
                    t = titles + [c.title]
                    self.menus.append((c.path, t))
                    visit(c, t)
            visit(self.tree, [])
        known = {core.path_key(p) for p, _t in self.menus}
        titles = {core.path_key(p): t for p, t in self.menus}
        for cat in sorted(self.state["categories"], key=lambda c: len(c["parent"])):
            full = core.cat_path(cat)
            if core.path_key(full) not in known:
                t = list(titles.get(core.path_key(cat["parent"]), cat["parent"])) + [cat["name"]]
                self.menus.append((full, t))
                titles[core.path_key(full)] = t
                known.add(core.path_key(full))

    def find_menu(self, spec):
        """Başlığa göre menü yolunu bulur: (yol | None, hata | None)."""
        parts = _split_path(spec)
        if not parts:
            return [], None
        for key in (_norm, _loose):
            want = [key(p) for p in parts]
            matches = [p for p, t in self.menus if [key(x) for x in t[-len(parts):]] == want]
            if not matches:
                matches = [p for p, _t in self.menus
                           if [key(x) for x in p[-len(parts):]] == want]
            if len(matches) == 1:
                return matches[0], None
            if len(matches) > 1:
                exact = [m for m in matches if len(m) == len(parts)]
                if len(exact) == 1:
                    return exact[0], None
                return None, ("“%s” birden fazla yerde var; “Üst / %s” şeklinde yazın."
                              % (spec, spec))
        return None, None

    # ------------------------------------------------------------------
    def color_for(self, menu_path):
        for i in range(len(menu_path), 0, -1):
            c = self.cat_colors.get(core.path_key(menu_path[:i]))
            if c:
                return c
        key = _loose(menu_path[-1] if menu_path else "x")
        return PALETTE[sum(map(ord, key)) % len(PALETTE)]

    def resolve_icon(self, value, tool=None):
        """Simge değerini çözer; araç için gerekirse rozet üretir."""
        value = (value or "").strip()
        tool_dir = tool["source"].get("dir") if tool else None
        command = tool["command"] if tool else None
        low = value.lower()
        if low.startswith("depo:") and tool_dir:
            path = os.path.join(core.sys_path(tool_dir), value[5:].strip())
            if os.path.isfile(path):
                return path
            self.log("  ! Depoda simge bulunamadı (%s); başka simge kullanılacak.\n" % value[5:])
            value, low = "otomatik", "otomatik"
        if low in ("", "otomatik", "auto"):
            if tool_dir:
                best = core.best_repo_icon(core.sys_path(tool_dir))
                if best:
                    return best
            for name in (["kali-" + command, command] if command and
                         command != "xdg-open" else []):
                if _theme_has(name):
                    return name
            if tool is None:
                return ""
            low = "rozet"
        if low.startswith("rozet"):
            color = value.split(":", 1)[1].strip() if ":" in value else \
                self.color_for(tool["menu"] if tool else [])
            return core.make_badge(tool["name"] if tool else "?", color,
                                   "arac-" + (tool["id"] if tool else "x"))
        if value.startswith("osint-") and core.pack_icon(value):
            return core.pack_icon(value)
        return os.path.expanduser(value)

    def ensure_category(self, name, section):
        path, err = self.find_menu(name)
        if err:
            raise core.OmyError(err)
        icon = section.get("simge", "")
        if path is not None:
            cat = core.find_cat(self.state, path[-1]) if path else None
            if cat is not None and icon:
                cat["icon"] = core.store_icon(self.resolve_icon(icon), "kategori-" + cat["id"])
            if section.get("renk"):
                self.cat_colors[core.path_key(path)] = section["renk"].strip()
            self.log("  = kategori zaten var: %s\n" % name)
            return path
        parent = []
        if section.get("konum", "").strip():
            parent, err = self.find_menu(section["konum"])
            if err:
                raise core.OmyError(err)
            if parent is None:
                parent = self.ensure_category(_split_path(section["konum"])[-1],
                                              {"konum": " / ".join(
                                                  _split_path(section["konum"])[:-1])})
        cat = {"id": core.new_category_id(self.state, name), "name": name,
               "comment": section.get("aciklama", ""), "icon": "", "parent": list(parent)}
        preset = next((p for p in core.CATEGORY_PRESETS if _norm(p[0]) == _norm(name)), None)
        if not icon and preset:
            icon = preset[1]
        if icon:
            cat["icon"] = core.store_icon(self.resolve_icon(icon), "kategori-" + cat["id"])
        self.state["categories"].append(cat)
        core.apply(self.state)
        self._rescan()
        full = core.cat_path(cat)
        if section.get("renk"):
            self.cat_colors[core.path_key(full)] = section["renk"].strip()
        self.log("  + kategori oluşturuldu: %s\n" % name)
        return full

    def add_tool(self, name, sec):
        src_spec = sec.get("kaynak", "").strip()
        if " " not in src_spec:
            raise core.OmyError("'kaynak' satırı eksik ya da hatalı (ör. kaynak = git "
                                "https://github.com/kullanici/arac)")
        kind, value = src_spec.split(None, 1)
        kind = {"github": "git", "kurulu": "existing", "yerel": "local"}.get(kind.lower(),
                                                                            kind.lower())
        if kind not in core.SOURCE_TYPES:
            raise core.OmyError("Bilinmeyen kaynak türü: %s" % kind)
        if kind == "web":
            command = "xdg-open"
        else:
            command = sec.get("komut", "").strip() or \
                (value.split()[0] if kind == "existing" else core.slugify(name))

        for t in self.state["tools"]:
            if _loose(t["name"]) == _loose(name) or \
                    (kind != "web" and t["command"] == command):
                self.log("  = zaten ekli, atlandı: %s\n" % name)
                self.skipped.append(name)
                return
        old_ids = [x.strip() for x in sec.get("eski", "").split(",") if x.strip()]
        existing = self.menu_entries.get(_loose(name))
        if existing and not old_ids and not _bool(sec.get("zorla"), False):
            self.log("  = menüde zaten var (%s ▸ %s), yeniden kurulmadı.\n"
                     % (existing[1], existing[0]))
            self.skipped.append(name)
            return

        menu_spec = sec.get("kategori", "").strip()
        if not menu_spec:
            raise core.OmyError("'kategori' satırı eksik.")
        menu, err = self.find_menu(menu_spec)
        if err:
            raise core.OmyError(err)
        if menu is None:
            menu = self.ensure_category(_split_path(menu_spec)[-1],
                                        {"konum": " / ".join(_split_path(menu_spec)[:-1])})
        if not menu:
            raise core.OmyError("Araçlar en üst seviyeye değil, bir kategoriye eklenmelidir.")

        if kind in core.SOURCES_WITH_WRAPPER:
            err, warn = core.command_conflict(command, None, self.state)
            if err:
                raise core.OmyError(err)
            if warn:
                self.log("  ! %s\n" % warn)

        if sec.get("paketler", "").strip():
            self.log("  > gerekli sistem paketleri: %s\n" % sec["paketler"].strip())
            core.install_apt(sec["paketler"].strip(), self.log)

        tool_id = core.new_tool_id(self.state, name if kind == "web" else command)
        build = sec.get("kurulum", "").strip() or None
        src = {"type": kind}
        args = sec.get("parametre", "-h")
        terminal = _bool(sec.get("terminal"), True)
        deps_ok = True
        if kind == "web":
            src["url"] = value.strip()
            args, terminal = shlex.quote(value.strip()), False
        elif kind == "git":
            value = self._git_source(value)
            res = core.install_git(value, tool_id, command, self.log, build=build)
            src.update({"url": value, "dir": res["dir"], "build": build})
            deps_ok = res["deps_ok"]
        elif kind == "local":
            res = core.install_local(value, tool_id, command, self.log)
            src.update({"path": value, "dir": res["dir"], "entry": res.get("entry", "")})
            deps_ok = res["deps_ok"] and core.run_build(core.sys_path(res["dir"]), build,
                                                        self.log)
            src["build"] = build
        elif kind == "pipx":
            res = core.install_pipx(value, self.log, commands=[command])
            src.update({"url": value, "package": res["package"]})
            if res["apps"] and command not in res["apps"]:
                self.log("  > pipx paketinin komutu: %s\n" % ", ".join(res["apps"]))
                command = res["apps"][0]
        elif kind == "apt":
            res = core.install_apt(value, self.log)
            src["package"] = res["package"]
        if kind in ("existing", "apt") and not shutil.which(command):
            self.log("  ! '%s' komutu şu an bulunamadı; yine de menüye ekleniyor.\n" % command)

        if kind in core.SOURCES_WITH_WRAPPER:
            real = core.sys_path(src["dir"])
            entry = sec.get("calistir", "").strip() or src.get("entry", "")
            if not entry:
                cands = core.find_entry_candidates(real, [command, name, tool_id])
                if not cands:
                    raise core.OmyError("Çalıştırılacak dosya bulunamadı; 'calistir = "
                                        "dosya.py' satırı ekleyin. Klasör: %s" % src["dir"])
                entry = cands[0][0]
                self.log("  > başlangıç dosyası: %s\n" % entry)
            elif not entry.startswith("venv:") and not os.path.exists(os.path.join(real, entry)):
                raise core.OmyError("'%s' dosyası depoda yok (kurulum tamamlanamamış olabilir)."
                                    % entry)
            elif entry.startswith("venv:") and not os.path.exists(
                    os.path.join(real, ".venv", "bin", entry[5:])):
                raise core.OmyError("'%s' komutu sanal ortamda oluşmadı; bağımlılık "
                                    "kurulumu başarısız olmuş olabilir." % entry[5:])
            src.update({"entry": entry,
                        "runner": sec.get("calistirici", "auto").strip() or "auto",
                        "cd": _bool(sec.get("klasorde"), True)})

        tool = {"id": tool_id, "name": name, "command": command, "args": args,
                "comment": sec.get("aciklama", ""), "icon": "", "menu": list(menu),
                "terminal": terminal, "source": src}
        if sec.get("ac", "").strip():
            tool["open_url"] = sec["ac"].strip()
        also = []
        for spec in [x.strip() for x in sec.get("ek_kategori", "").split(",") if x.strip()]:
            path, err = self.find_menu(spec)
            if path:
                also.append(path)
            else:
                self.log("  ! Ek kategori bulunamadı: %s\n" % spec)
        if also:
            tool["also"] = also
        core.split_args(tool["args"])
        tool["icon"] = core.store_icon(self.resolve_icon(sec.get("simge"), tool),
                                       "arac-" + tool_id)
        self.state["tools"].append(tool)
        for w in core.apply(self.state):
            self.log("  ! %s\n" % w)
        self.ok.append(name)
        for old in old_ids:
            self._hide_old(old)
        if not deps_ok:
            self.notes.append("%s: bazı bağımlılıklar kurulamadı (günlüğe bakın)" % name)
        if sec.get("not", "").strip():
            self.notes.append("%s: %s" % (name, sec["not"].strip()))
        if kind == "web":
            self.log("  ✔ %s eklendi (web kısayolu)\n" % name)
        else:
            self.log("  ✔ %s eklendi → terminalde: %s\n" % (name, command))

    def _git_source(self, value):
        """'git /usr/share/Arac' gibi yerel bir klasör verilmişse onun
        GitHub adresini kullanır (yoksa klasörün kendisinden kopyalar)."""
        value = value.strip()
        if os.path.isdir(os.path.join(value, ".git")):
            try:
                url = subprocess.run(["git", "-c", "safe.directory=*", "-C", value, "config",
                                      "--get", "remote.origin.url"], capture_output=True,
                                     text=True, timeout=30).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                url = ""
            if url:
                self.log("  > %s klasörünün kaynağı: %s\n" % (value, url))
                return url
        return value

    def _hide_old(self, desktop_id):
        """Eski menü kaydını (yeni kurulum başarılı olduktan sonra) gizler."""
        from . import xdgmenu
        path = xdgmenu.find_desktop_file(desktop_id)
        if not path:
            return
        try:
            core.set_override(self.state, "app", desktop_id, path, "", "", hide=True)
            core.apply(self.state)
            self.log("  > eski menü kaydı gizlendi: %s\n" % desktop_id)
        except (OSError, core.OmyError) as e:
            self.log("  ! eski menü kaydı gizlenemedi (%s): %s\n" % (desktop_id, e))

    def run(self, path):
        cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=None,
                                       strict=False)
        cp.optionxform = str.lower
        try:
            with open(path, encoding="utf-8") as f:
                cp.read_file(f)
        except (OSError, configparser.Error) as e:
            raise core.OmyError("Liste dosyası okunamadı: %s" % e)

        def sections(prefixes):
            return [(s.split(":", 1)[1].strip(), cp[s]) for s in cp.sections()
                    if s.lower().startswith(prefixes)]
        cats = sections(("kategori:",))
        tools = sections(("arac:", "araç:"))
        update = cp["guncelle"] if cp.has_section("guncelle") else None
        for s in cp.sections():
            if not s.lower().startswith(("kategori:", "arac:", "araç:", "guncelle")):
                self.log("UYARI: tanınmayan bölüm atlandı: [%s]\n" % s)

        if cats:
            self.log("\n=== Kategoriler ===\n")
        for name, sec in cats:
            try:
                self.ensure_category(name, sec)
            except (OSError, core.OmyError) as e:
                self.log("  ✘ %s: %s\n" % (name, e))
                self.failed.append(name)

        for i, (name, sec) in enumerate(tools, 1):
            self.log("\n=== [%d/%d] %s ===\n" % (i, len(tools), name))
            try:
                self.add_tool(name, sec)
            except (OSError, core.OmyError) as e:
                self.log("  ✘ %s eklenemedi: %s\n" % (name, e))
                self.failed.append(name)

        updates = []
        if update is not None and update.get("kategoriler", "").strip():
            self.log("\n=== Menüde zaten olan araçlar güncelleniyor ===\n")
            from . import guncelle
            specs = [x.strip() for x in update["kategoriler"].split(",") if x.strip()]
            try:
                updates = guncelle.run(specs, self.log, self.find_menu)
            except (OSError, core.OmyError) as e:
                self.log("  ✘ Güncelleme yapılamadı: %s\n" % e)

        self.log("\n" + "=" * 60 + "\nÖZET\n" + "=" * 60 + "\n")
        self.log("Eklenen (%d): %s\n" % (len(self.ok), ", ".join(self.ok) or "-"))
        if self.skipped:
            self.log("Zaten vardı (%d): %s\n" % (len(self.skipped), ", ".join(self.skipped)))
        if updates:
            self.log("Güncelleme:\n")
            for title, status in updates:
                self.log("  - %s: %s\n" % (title, status))
        if self.failed:
            self.log("HATA (%d): %s\n" % (len(self.failed), ", ".join(self.failed)))
        if self.notes:
            self.log("Notlar:\n")
            for n in self.notes:
                self.log("  - %s\n" % n)
        self.log("\nMenü birkaç saniye içinde güncellenir. Açık terminallerde yeni komutlar "
                 "için 'hash -r' yazın ya da yeni terminal açın.\n")
        return 0 if not self.failed else 1


def _theme_has(name):
    if not name:
        return False
    for base in ("/usr/share/icons", "/usr/local/share/icons"):
        root = core.sys_path(base)
        if glob.glob(os.path.join(root, "*", "*", "apps", name + ".*")) or \
                glob.glob(os.path.join(root, "*", "apps", "*", name + ".*")):
            return True
    return bool(glob.glob(os.path.join(core.sys_path("/usr/share/pixmaps"), name + ".*")))
