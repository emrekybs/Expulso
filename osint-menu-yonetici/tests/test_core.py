# -*- coding: utf-8 -*-
"""Çekirdek modül testleri. Sahte bir kök dizinde (OMY_ROOT) Kali/XFCE
benzeri bir menü kurar, araç ve kategoriler ekler, sonucu pyxdg ile okuyup
doğrular.

Çalıştırma:  python3 -m unittest discover -s tests -v
"""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = tempfile.mkdtemp(prefix="omy-test-")
os.environ["OMY_ROOT"] = ROOT
os.environ["XDG_CONFIG_DIRS"] = os.path.join(ROOT, "etc/xdg")
os.environ["XDG_DATA_DIRS"] = "%s:%s" % (os.path.join(ROOT, "usr/local/share"),
                                         os.path.join(ROOT, "usr/share"))
os.environ["XDG_CONFIG_HOME"] = os.path.join(ROOT, "home/.config")
os.environ["XDG_DATA_HOME"] = os.path.join(ROOT, "home/.local/share")
os.environ["XDG_MENU_PREFIX"] = "xfce-"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from omy import core  # noqa: E402


def write(rel, content):
    p = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(content).lstrip())


def setUpModule():
    write("etc/xdg/menus/xfce-applications.menu", """
        <!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
          "http://www.freedesktop.org/standards/menu-spec/1.0/menu.dtd">
        <Menu>
          <Name>Xfce</Name>
          <DefaultAppDirs/>
          <DefaultDirectoryDirs/>
          <Include><Category>X-Xfce-Toplevel</Category></Include>
          <Menu>
            <Name>Settings</Name>
            <Directory>xfce-settings.directory</Directory>
            <Include><Category>Settings</Category></Include>
          </Menu>
          <Menu>
            <Name>Other</Name>
            <Directory>xfce-other.directory</Directory>
            <OnlyUnallocated/>
            <Include><All/></Include>
          </Menu>
          <DefaultMergeDirs/>
        </Menu>
    """)
    write("etc/xdg/menus/applications-merged/osint.menu", """
        <!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
          "http://www.freedesktop.org/standards/menu-spec/1.0/menu.dtd">
        <Menu>
          <Name>Applications</Name>
          <Menu>
            <Name>osint</Name>
            <Directory>osint.directory</Directory>
            <Menu>
              <Name>osint-email</Name>
              <Directory>osint-email.directory</Directory>
              <Include><Category>X-Osint-Email</Category></Include>
            </Menu>
          </Menu>
        </Menu>
    """)
    write("usr/share/desktop-directories/osint.directory",
          "[Desktop Entry]\nType=Directory\nName=OSINT\nIcon=user\n")
    write("usr/share/desktop-directories/osint-email.directory",
          "[Desktop Entry]\nType=Directory\nName=OSINT email\nIcon=mail\n")
    write("usr/share/applications/holehe.desktop",
          "[Desktop Entry]\nType=Application\nName=Holehe\nExec=holehe\n"
          "Terminal=true\nCategories=X-Osint-Email;\n")


def tearDownModule():
    shutil.rmtree(ROOT, ignore_errors=True)


def find(node, path):
    for name in path:
        node = next(c for c in node.children if c.name == name)
    return node


class CoreTests(unittest.TestCase):
    def test_slug(self):
        self.assertEqual(core.slugify("Şifre Çözücü İğne"), "sifre-cozucu-igne")
        self.assertEqual(core.slugify("!!!"), "arac")
        self.assertEqual(core.name_from_source("git", "https://github.com/a/Eyes.git"), "Eyes")
        self.assertEqual(core.name_from_source("git", "git@github.com:a/b-c.git"), "b-c")
        self.assertEqual(core.name_from_source("pipx", "holehe==1.2"), "holehe")

    def test_exec_quote(self):
        self.assertEqual(core.exec_quote("-h"), "-h")
        self.assertEqual(core.exec_quote("a b"), '"a b"')
        self.assertEqual(core.exec_quote('x"$y'), '"x\\"\\$y"')
        self.assertEqual(core.exec_quote("50%"), "50%%")
        tool = {"command": "eyes", "args": "--mail 'a b'", "terminal": True}
        self.assertEqual(core.tool_exec(tool), core.RUNNER + ' eyes --mail "a b"')

    def test_scan_and_apply(self):
        tree = core.scan_menu()
        email = find(tree, ["osint", "osint-email"])
        self.assertEqual(email.title, "OSINT email")
        self.assertEqual([e["id"] for e in email.entries], ["holehe.desktop"])

        # Yerel bir "GitHub" deposu hazırla.
        repo = os.path.join(ROOT, "src", "darkx")
        os.makedirs(repo)
        with open(os.path.join(repo, "darkx.py"), "w") as f:
            f.write("import sys\nif __name__ == '__main__':\n"
                    "    print('DARKX', *sys.argv[1:])\n")
        with open(os.path.join(repo, "helper.py"), "w") as f:
            f.write("x = 1\n")
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "add", "."], check=True)
        subprocess.run(["git", "-C", repo, "-c", "user.email=a@b", "-c", "user.name=t",
                        "commit", "-qm", "ilk"], check=True)

        state = core.load_state()
        cat = {"id": core.new_category_id(state, "Dark Web"), "name": "Dark Web",
               "icon": "", "comment": "", "parent": ["osint"]}
        state["categories"].append(cat)
        top = {"id": core.new_category_id(state, "Yeni Üst"), "name": "Yeni Üst",
               "icon": "", "comment": "", "parent": []}
        state["categories"].append(top)
        self.assertEqual(cat["id"], "omy-dark-web")

        log = []
        res = core.install_git("file://" + repo, "darkx", "darkx", log.append)
        cands = core.find_entry_candidates(core.sys_path(res["dir"]), ["darkx"])
        self.assertEqual(cands[0][0], "darkx.py")
        tool = {"id": "darkx", "name": "DarkX", "command": "darkx", "args": "-h",
                "comment": "test", "icon": "", "menu": core.cat_path(cat),
                "terminal": True,
                "source": {"type": "git", "url": repo, "dir": res["dir"],
                           "entry": "darkx.py", "runner": "auto", "cd": True}}
        state["tools"].append(tool)
        state["tools"].append({
            "id": "eyes", "name": "Eyes", "command": "eyes", "args": "", "comment": "",
            "icon": "", "menu": ["osint", "osint-email"], "terminal": True,
            "source": {"type": "existing"}})
        warnings = core.apply(state)
        self.assertEqual(warnings, [])

        wrapper = core.sys_path("/usr/local/bin/darkx")
        # Wrapper gerçek sistem yollarını içerir; testte sahte köke çevir.
        with open(wrapper) as f:
            text = f.read().replace("/opt/osint-tools", ROOT + "/opt/osint-tools")
        test_wrapper = os.path.join(ROOT, "darkx-test")
        with open(test_wrapper, "w") as f:
            f.write(text)
        os.chmod(test_wrapper, 0o755)
        out = subprocess.run([test_wrapper, "merhaba", "dünya"], capture_output=True,
                             text=True).stdout
        self.assertEqual(out.strip(), "DARKX merhaba dünya")

        tree = core.scan_menu()
        email = find(tree, ["osint", "osint-email"])
        self.assertEqual(sorted(e["id"] for e in email.entries),
                         ["holehe.desktop", "omy-eyes.desktop"])
        dark = find(tree, ["osint", "omy-dark-web"])
        self.assertEqual(dark.title, "Dark Web")
        self.assertEqual([e["title"] for e in dark.entries], ["DarkX"])
        # Boş üst kategori de menüde (boş olarak) görünmeli.
        self.assertEqual(find(tree, ["omy-yeni-ust"]).title, "Yeni Üst")
        # Kendi araçlarımız "Other" menüsüne düşmemeli.
        other = find(tree, ["Other"]) if any(c.name == "Other" for c in tree.children) else None
        if other:
            self.assertNotIn("omy-darkx.desktop", [e["id"] for e in other.entries])

        # Kategoriyi en üste taşı: araç da birlikte taşınmalı.
        core.move_category(state, cat, [])
        self.assertEqual(tool["menu"], ["omy-dark-web"])
        with self.assertRaises(core.OmyError):
            core.move_category(state, cat, ["omy-dark-web"])
        core.apply(state)
        tree = core.scan_menu()
        self.assertEqual([e["id"] for e in find(tree, ["omy-dark-web"]).entries],
                         ["omy-darkx.desktop"])

        # Kategoriyi sil: araç üst menüye geçmeli, .directory dosyası silinmeli.
        core.remove_category(state, cat)
        self.assertEqual(tool["menu"], [])
        tool["menu"] = ["osint"]
        core.apply(state)
        self.assertFalse(os.path.exists(
            core.sys_path("/usr/share/desktop-directories/omy-dark-web.directory")))

        # Komut adı değişince eski wrapper silinmeli.
        tool["command"] = "darkx2"
        core.apply(state)
        self.assertFalse(os.path.exists(wrapper))
        self.assertTrue(os.path.exists(core.sys_path("/usr/local/bin/darkx2")))

        # Aracı tamamen kaldır.
        state["tools"].remove(tool)
        core.uninstall_tool(tool, True)
        core.apply(state)
        self.assertFalse(os.path.exists(core.sys_path("/opt/osint-tools/darkx")))
        self.assertFalse(os.path.exists(core.sys_path("/usr/share/applications/omy-darkx.desktop")))

    def test_conflict(self):
        p = core.sys_path("/usr/local/bin/baskasi")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write("#!/bin/sh\n")
        err, _warn = core.command_conflict("baskasi")
        self.assertIsNotNone(err)
        err, _warn = core.command_conflict("kötü ad")
        self.assertIsNotNone(err)
        self.assertEqual(core.command_conflict("yepyeni-komut"), (None, None))

    def test_desktop_file_parses(self):
        from gi.repository import GLib
        tool = {"id": "x", "name": 'Ad "tırnaklı" \\ ters', "command": "x",
                "args": "--q '$HOME \"a\"' 100%", "comment": "çok\nsatır",
                "icon": "", "terminal": True}
        kf = GLib.KeyFile()
        data = core.desktop_content(tool)
        kf.load_from_data(data, len(data.encode("utf-8")), GLib.KeyFileFlags.NONE)
        exec_line = kf.get_string("Desktop Entry", "Exec")
        ok, argv = GLib.shell_parse_argv(exec_line.replace("%%", "%"))
        self.assertEqual(argv, [core.RUNNER, "x", "--q", '$HOME "a"', "100%"])
        self.assertEqual(kf.get_string("Desktop Entry", "Name"), tool["name"])

    def test_icon_pack_and_presets(self):
        pack = core.load_icon_pack()
        self.assertGreater(len(pack), 30)
        for icon in pack:
            self.assertTrue(os.path.isfile(icon["real"]), icon)
        for name, icon, _comment in core.CATEGORY_PRESETS:
            self.assertTrue(core.pack_icon(icon), icon)

    def test_overrides(self):
        state = core.load_state()
        tree = core.scan_menu()
        email = find(tree, ["osint", "osint-email"])
        holehe = email.entries[0]
        icon = core.pack_icon("osint-eposta")
        core.set_override(state, "directory", os.path.basename(email.file), email.file,
                          "E-posta Araçları", icon)
        core.set_override(state, "app", holehe["id"], holehe["file"], "", "kali-holehe")
        self.assertEqual(core.apply(state), [])
        # /usr/share dosyaları değişmemeli, /usr/local/share altına kopya yazılmalı
        with open(os.path.join(ROOT, "usr/share/desktop-directories/osint-email.directory")) as f:
            self.assertIn("Name=OSINT email", f.read())
        tree = core.scan_menu()
        email = find(tree, ["osint", "osint-email"])
        self.assertEqual(email.title, "E-posta Araçları")
        self.assertEqual(email.icon, icon)
        h = [e for e in email.entries if e["id"] == "holehe.desktop"][0]
        self.assertEqual((h["title"], h["icon"]), ("Holehe", "kali-holehe"))

        # Kullanıcı klasöründeki dosya yerinde değişir, yedeği alınır
        user_dir = os.path.join(ROOT, "home/.local/share/desktop-directories")
        write("home/.local/share/desktop-directories/osint.directory",
              "[Desktop Entry]\nType=Directory\nName=OSINT\nName[tr]=OSINT TR\nIcon=user\n")
        tree = core.scan_menu()
        osint = find(tree, ["osint"])
        self.assertTrue(osint.file.startswith(user_dir))
        core.set_override(state, "directory", "osint.directory", osint.file, "OSINT Ana", "")
        core.apply(state)
        self.assertEqual(find(core.scan_menu(), ["osint"]).title, "OSINT Ana")
        self.assertTrue(os.path.exists(os.path.join(user_dir, "osint.directory.omy-yedek")))

        # Geri al
        for ov in list(state["overrides"]):
            core.remove_override(state, ov)
        core.apply(state)
        tree = core.scan_menu()
        self.assertEqual(find(tree, ["osint"]).title, "OSINT TR" if os.environ.get(
            "LANG", "").startswith("tr") else "OSINT")
        self.assertEqual(find(tree, ["osint", "osint-email"]).title, "OSINT email")
        self.assertFalse(os.path.exists(os.path.join(user_dir, "osint.directory.omy-yedek")))
        self.assertFalse(os.path.exists(os.path.join(
            ROOT, "usr/local/share/desktop-directories/osint-email.directory")))
        os.unlink(os.path.join(user_dir, "osint.directory"))

    def test_parser_rules(self):
        """Move, MergeFile type=parent, Not/And kuralları, OnlyUnallocated,
        kullanıcı menüsü ve Whisker favorileri."""
        from omy import xdgmenu
        write("usr/share/applications/sherlock.desktop",
              "[Desktop Entry]\nType=Application\nName=Sherlock\nName[tr]=Şerlok\n"
              "Exec=sherlock\nCategories=X-Osint-User;X-Gizli;\n")
        write("usr/share/applications/gizli.desktop",
              "[Desktop Entry]\nType=Application\nName=Gizli\nExec=x\nNoDisplay=true\n"
              "Categories=X-Osint-User;\n")
        write("home/.config/menus/xfce-applications.menu", """
            <!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
              "http://www.freedesktop.org/standards/menu-spec/1.0/menu.dtd">
            <Menu>
              <Name>Xfce</Name>
              <MergeFile type="parent">/etc/xdg/menus/xfce-applications.menu</MergeFile>
              <Menu>
                <Name>Kullanici</Name>
                <Include><And><Category>X-Osint-User</Category>
                  <Not><Filename>yok.desktop</Filename></Not></And></Include>
              </Menu>
              <Move><Old>Kullanici</Old><New>osint/Kullanici</New></Move>
            </Menu>
        """)
        old_lang = os.environ.get("LANG")
        os.environ["LANG"] = "tr_TR.UTF-8"
        xdgmenu._LOCALES = None
        try:
            tree = core.scan_menu()
        finally:
            os.unlink(os.path.join(ROOT, "home/.config/menus/xfce-applications.menu"))
            if old_lang is None:
                del os.environ["LANG"]
            else:
                os.environ["LANG"] = old_lang
            xdgmenu._LOCALES = None
        user = find(tree, ["osint", "Kullanici"])
        # NoDisplay olan gizlenir, yerelleştirilmiş ad kullanılır
        self.assertEqual([e["title"] for e in user.entries], ["Şerlok"])
        # Sistem menüsü de (parent) birleştirilmiş olmalı
        self.assertEqual(find(tree, ["osint", "osint-email"]).title, "OSINT email")
        # Diğer hiçbir yere ayrılmamış uygulamalar "Other"a düşer, sherlock düşmez
        other = find(tree, ["Other"])
        self.assertNotIn("sherlock.desktop", [e["id"] for e in other.entries])

        write("home/.config/xfce4/panel/whiskermenu-1.rc",
              "button-icon=kali\nfavorites=holehe.desktop,yok.desktop,sherlock.desktop\n")
        try:
            favs = core.whisker_favorites()
        finally:
            os.unlink(os.path.join(ROOT, "home/.config/xfce4/panel/whiskermenu-1.rc"))
        self.assertEqual([f["id"] for f in favs], ["holehe.desktop", "sherlock.desktop"])
        os.unlink(os.path.join(ROOT, "usr/share/applications/sherlock.desktop"))
        os.unlink(os.path.join(ROOT, "usr/share/applications/gizli.desktop"))

    def test_repo_images(self):
        d = os.path.join(ROOT, "repo-img")
        os.makedirs(os.path.join(d, "docs"))
        os.makedirs(os.path.join(d, "assets"))
        for rel in ("screenshot.png", "assets/logo.png", "assets/other.jpg", "docs/x.png"):
            with open(os.path.join(d, rel), "wb") as f:
                f.write(b"x")
        imgs = core.find_repo_images(d)
        self.assertEqual(os.path.relpath(imgs[0], d), "assets/logo.png")
        self.assertNotIn(os.path.join(d, "docs/x.png"), imgs)
        self.assertEqual(core.best_repo_icon(d), os.path.join(d, "assets/logo.png"))
        shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
