# -*- coding: utf-8 -*-
"""Toplu kurulum: bir liste dosyasındaki bütün kategori ve araçları tek
komutla kurar ve menüye ekler.

  sudo osint-menu-yonetici --toplu araclar.ini

Dosya biçimi (INI):

  [kategori: OSINT Dark Web]
  konum = OSINT              ; nerede oluşturulsun (boşsa en üst)
  simge = osint-dark-web     ; hazır simge adı, tema simgesi ya da dosya yolu

  [arac: Holehe]
  kaynak = pipx holehe       ; git <adres> | pipx <paket> | apt <paket> |
                             ; yerel <klasör/dosya> | kurulu <komut>
  kategori = OSINT email     ; "OSINT email" ya da "OSINT / OSINT email"
  komut = holehe             ; terminal komutu (boşsa addan üretilir)
  parametre = -h             ; menüden açılınca kullanılacak parametreler
  simge = otomatik           ; otomatik | hazır simge | tema simgesi | dosya yolu
  aciklama = E-posta hangi sitelerde kayıtlı
  calistir = holehe.py       ; (git/yerel) çalışacak dosya; boşsa otomatik bulunur
  klasorde = evet            ; (git/yerel) aracın klasöründe çalıştır
  terminal = evet            ; menüden terminalde aç

Zaten eklenmiş (aynı komutlu) araçlar atlanır; dosya tekrar tekrar
çalıştırılabilir.
"""

import configparser
import glob
import os
import shutil
import sys

from . import core

YES = ("evet", "e", "yes", "y", "true", "1", "açık", "acik")


def _bool(value, default):
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in YES


def _split_path(spec):
    for sep in ("▸", ">", "/"):
        if sep in spec:
            return [p.strip() for p in spec.split(sep) if p.strip()]
    return [spec.strip()] if spec.strip() else []


class Batch:
    def __init__(self, log=None):
        self.log = log or (lambda s: (sys.stdout.write(s), sys.stdout.flush()))
        self.state = core.load_state()
        self.ok, self.skipped, self.failed = [], [], []
        self._rescan()

    def _rescan(self):
        try:
            self.tree = core.scan_menu()
        except core.OmyError as e:
            self.log("UYARI: mevcut menü okunamadı (%s); yalnızca bu araçla oluşturulan "
                     "kategoriler kullanılabilir.\n" % e)
            self.tree = None
        # (yol, [başlıklar]) listesi
        self.menus = []
        if self.tree is not None:
            def visit(n, titles):
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
                parent_titles = titles.get(core.path_key(cat["parent"]), cat["parent"])
                t = list(parent_titles) + [cat["name"]]
                self.menus.append((full, t))
                titles[core.path_key(full)] = t
                known.add(core.path_key(full))

    def find_menu(self, spec):
        """Başlığa göre menü yolunu bulur. (yol | None, hata mesajı)"""
        parts = [p.casefold() for p in _split_path(spec)]
        if not parts:
            return [], None
        matches = [p for p, t in self.menus
                   if [x.casefold() for x in t[-len(parts):]] == parts]
        if not matches:
            # internal ad ile de eşleşebilir
            matches = [p for p, _t in self.menus
                       if [x.casefold() for x in p[-len(parts):]] == parts]
        if len(matches) > 1:
            exact = [m for m in matches if len(m) == len(parts)]
            if len(exact) == 1:
                return exact[0], None
            return None, "“%s” birden fazla yerde var; “Üst / %s” şeklinde yazın." % (
                spec, spec)
        return (matches[0], None) if matches else (None, None)

    # ------------------------------------------------------------------
    def resolve_icon(self, value, tool_dir=None, command=None):
        value = (value or "").strip()
        if value.lower() in ("", "otomatik", "auto"):
            if tool_dir:
                best = core.best_repo_icon(core.sys_path(tool_dir))
                if best:
                    return best
            for name in (["kali-" + command, command] if command else []):
                if _theme_has(name):
                    return name
            return ""
        if value.startswith("osint-") and core.pack_icon(value):
            return core.pack_icon(value)
        return os.path.expanduser(value)

    def ensure_category(self, name, section):
        path, err = self.find_menu(name)
        if err:
            raise core.OmyError(err)
        icon = section.get("simge", "")
        if path is not None:
            # Var olan kategori; bizim oluşturduğumuzsa simgesini güncelle
            cat = core.find_cat(self.state, path[-1]) if path else None
            if cat is not None and icon:
                cat["icon"] = core.store_icon(self.resolve_icon(icon), "kategori-" + cat["id"])
            self.log("  = kategori zaten var: %s\n" % name)
            return path
        parent = []
        if section.get("konum", "").strip():
            parent, err = self.find_menu(section["konum"])
            if err:
                raise core.OmyError(err)
            if parent is None:
                parent = self.ensure_category(section["konum"], {})
        cat = {"id": core.new_category_id(self.state, name), "name": name,
               "comment": section.get("aciklama", ""), "icon": "", "parent": list(parent)}
        preset = next((p for p in core.CATEGORY_PRESETS if p[0].casefold() == name.casefold()),
                      None)
        if not icon and preset:
            icon = preset[1]
        cat["icon"] = core.store_icon(self.resolve_icon(icon), "kategori-" + cat["id"]) \
            if icon else ""
        self.state["categories"].append(cat)
        core.apply(self.state)
        self._rescan()
        self.log("  + kategori oluşturuldu: %s\n" % name)
        return core.cat_path(cat)

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
        command = sec.get("komut", "").strip() or \
            (value.split()[0] if kind == "existing" else core.slugify(name))
        for t in self.state["tools"]:
            if t["command"] == command or t["name"].casefold() == name.casefold():
                self.log("  = zaten ekli, atlandı: %s (%s)\n" % (name, command))
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

        tool_id = core.new_tool_id(self.state, command or name)
        src = {"type": kind}
        if kind == "git":
            res = core.install_git(value, tool_id, command, self.log)
            src.update({"url": value, "dir": res["dir"]})
        elif kind == "local":
            res = core.install_local(value, tool_id, command, self.log)
            src.update({"path": value, "dir": res["dir"], "entry": res.get("entry", "")})
        elif kind == "pipx":
            res = core.install_pipx(value, self.log)
            src.update({"url": value, "package": res["package"]})
            if res["apps"] and command not in res["apps"]:
                if sec.get("komut", "").strip():
                    self.log("  ! '%s' komutu pakette yok; paketin komutları: %s\n"
                             % (command, ", ".join(res["apps"])))
                command = res["apps"][0]
        elif kind == "apt":
            res = core.install_apt(value, self.log)
            src["package"] = res["package"]
        else:
            if not shutil.which(command):
                self.log("  ! '%s' komutu şu an bulunamadı; yine de menüye ekleniyor.\n"
                         % command)

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
                raise core.OmyError("'%s' dosyası depoda yok." % entry)
            src.update({"entry": entry, "runner": sec.get("calistirici", "auto").strip() or "auto",
                        "cd": _bool(sec.get("klasorde"), True)})

        tool = {"id": tool_id, "name": name, "command": command,
                "args": sec.get("parametre", "-h"), "comment": sec.get("aciklama", ""),
                "icon": "", "menu": list(menu), "terminal": _bool(sec.get("terminal"), True),
                "source": src}
        core.split_args(tool["args"])
        tool["icon"] = core.store_icon(
            self.resolve_icon(sec.get("simge"), src.get("dir"), command), "arac-" + tool_id)
        self.state["tools"].append(tool)
        for w in core.apply(self.state):
            self.log("  ! %s\n" % w)
        self.ok.append(name)
        self.log("  ✔ %s eklendi → terminalde: %s\n" % (name, command))

    def run(self, path):
        cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";", "#"))
        cp.optionxform = str.lower
        try:
            with open(path, encoding="utf-8") as f:
                cp.read_file(f)
        except (OSError, configparser.Error) as e:
            raise core.OmyError("Liste dosyası okunamadı: %s" % e)

        cats = [(s.split(":", 1)[1].strip(), cp[s]) for s in cp.sections()
                if s.lower().startswith("kategori:")]
        tools = [(s.split(":", 1)[1].strip(), cp[s]) for s in cp.sections()
                 if s.lower().startswith(("arac:", "araç:"))]
        unknown = [s for s in cp.sections()
                   if not s.lower().startswith(("kategori:", "arac:", "araç:"))]
        for s in unknown:
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

        self.log("\n=== Özet ===\n")
        self.log("Eklenen: %d  %s\n" % (len(self.ok), ", ".join(self.ok)))
        if self.skipped:
            self.log("Zaten ekli: %d  %s\n" % (len(self.skipped), ", ".join(self.skipped)))
        if self.failed:
            self.log("Hata: %d  %s\n" % (len(self.failed), ", ".join(self.failed)))
        self.log("Menü birkaç saniye içinde güncellenir. Açık terminallerde yeni komutlar "
                 "için 'hash -r' yazın ya da yeni terminal açın.\n")
        return 0 if not self.failed else 1


def _theme_has(name):
    if not name:
        return False
    for base in ("/usr/share/icons", "/usr/local/share/icons"):
        if glob.glob(os.path.join(core.sys_path(base), "*", "*", "apps", name + ".*")) or \
                glob.glob(os.path.join(core.sys_path(base), "*", "apps", "*", name + ".*")):
            return True
    return bool(glob.glob(os.path.join(core.sys_path("/usr/share/pixmaps"), name + ".*")))
