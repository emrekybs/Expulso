# -*- coding: utf-8 -*-
"""Toplu kurulum ve mevcut araçları güncelleme testleri (sahte kök dizinde)."""
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import test_core as fx  # noqa: E402  (ortam değişkenlerini ayarlar)

from omy import core, toplu  # noqa: E402

ROOT = fx.ROOT


def git(*args, cwd=None):
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t",
                    "-c", "init.defaultBranch=main"] + list(args),
                   cwd=cwd, check=True, capture_output=True)


def make_repo(path, files):
    os.makedirs(path)
    for rel, content in files.items():
        full = os.path.join(path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
    git("init", "-q", path)
    git("add", ".", cwd=path)
    git("commit", "-qm", "ilk", cwd=path)


def setUpModule():
    fx.setUpModule()


class TopluTests(unittest.TestCase):
    def test_batch(self):
        src = os.path.join(ROOT, "src")
        make_repo(os.path.join(src, "kucuk"), {
            "kucuk.py": "import sys\nprint('KUCUK', *sys.argv[1:])\n",
            "assets/logo.svg": "<svg xmlns='http://www.w3.org/2000/svg'/>",
        })
        # Menüde zaten olan, elle git ile kurulmuş "eski" bir araç
        bare = os.path.join(src, "eski.git")
        make_repo(os.path.join(src, "eski-kaynak"), {"run.sh": "#!/bin/sh\necho v1\n"})
        git("clone", "-q", "--bare", os.path.join(src, "eski-kaynak"), bare)
        eski = os.path.join(ROOT, "opt", "eski-arac")
        git("clone", "-q", bare, eski)
        kirli = os.path.join(ROOT, "opt", "kirli-arac")
        git("clone", "-q", bare, kirli)
        with open(os.path.join(kirli, "run.sh"), "a") as f:
            f.write("# elle değişiklik\n")
        for name, path in (("Eski", eski), ("Kirli", kirli)):
            fx.write("usr/share/applications/%s.desktop" % name.lower(),
                     "[Desktop Entry]\nType=Application\nName=%s\nExec=sh -c \"%s/run.sh;"
                     " bash\"\nTerminal=true\nCategories=X-Osint-Email;\n" % (name, path))
        # uzak depoya yeni sürüm gönder
        work = os.path.join(src, "eski-is")
        git("clone", "-q", bare, work)
        with open(os.path.join(work, "run.sh"), "w") as f:
            f.write("#!/bin/sh\necho v2\n")
        git("commit", "-qam", "v2", cwd=work)
        git("push", "-q", "origin", "HEAD", cwd=work)

        ini = os.path.join(ROOT, "liste.ini")
        with open(ini, "w") as f:
            f.write("""
[kategori: OSINT Dark Web]
konum = OSINT
renk = #613583

[arac: Kucuk]
kaynak = git file://%(src)s/kucuk
kategori = OSINT Dark Web
kurulum = echo derlendi > built.txt
aciklama = deneme

[arac: Holehe]
kaynak = kurulu holehe
kategori = OSINT email

[arac: Rozetli Arac]
kaynak = kurulu ls
kategori = OSINT  /  osint   EMAIL
parametre = -la

[arac: Wayback Machine]
kaynak = web https://web.archive.org/?a=1&b=2
kategori = OSINT Web Tools / General
simge = osint-arsiv

[arac: Web Uygulama]
kaynak = git file://%(src)s/kucuk
komut = webuyg
kategori = OSINT Dark Web
ac = http://127.0.0.1:5000
parametre =

[arac: Bozuk]
kaynak = git file://%(src)s/olmayan-depo
kategori = OSINT Dark Web

[guncelle]
kategoriler = OSINT
""" % {"src": src})

        out = []
        rc = toplu.Batch(log=out.append).run(ini)
        log = "".join(out)
        self.assertEqual(rc, 1, log)  # "Bozuk" hata vermeli, diğerleri devam etmeli
        state = core.load_state()
        names = {t["name"]: t for t in state["tools"]}
        self.assertEqual(sorted(names), ["Kucuk", "Rozetli Arac", "Wayback Machine",
                                         "Web Uygulama"], log)
        self.assertIn("menüde zaten var", log)  # Holehe yeniden kurulmadı

        kucuk = names["Kucuk"]
        tdir = core.sys_path(kucuk["source"]["dir"])
        self.assertTrue(os.path.exists(os.path.join(tdir, "built.txt")))
        self.assertTrue(kucuk["icon"].endswith(".svg"), kucuk["icon"])  # depodaki logo
        self.assertEqual(names["Rozetli Arac"]["menu"], ["osint", "osint-email"])
        badge = core.sys_path(names["Rozetli Arac"]["icon"])
        with open(badge) as f:
            self.assertIn(">RA<", f.read())

        web = names["Wayback Machine"]
        self.assertFalse(web["terminal"])
        with open(core.sys_path("/usr/share/applications/" + core.desktop_id(web))) as f:
            desktop = f.read()
        self.assertIn('Exec=xdg-open "https://web.archive.org/?a=1&b=2"', desktop)
        self.assertIn("Terminal=false", desktop)
        with open(core.sys_path("/usr/share/applications/" +
                                core.desktop_id(names["Web Uygulama"]))) as f:
            self.assertIn("--ac http://127.0.0.1:5000 webuyg", f.read())

        tree = core.scan_menu()
        self.assertEqual(fx.find(tree, ["osint", "omy-osint-dark-web"]).title, "OSINT Dark Web")
        general = fx.find(tree, ["omy-osint-web-tools", "omy-general"])
        self.assertEqual([e["title"] for e in general.entries], ["Wayback Machine"])

        # Güncelleme: temiz depo güncellenmeli, değiştirilmiş depoya dokunulmamalı
        with open(os.path.join(eski, "run.sh")) as f:
            self.assertIn("v2", f.read(), log)
        with open(os.path.join(kirli, "run.sh")) as f:
            self.assertIn("elle değişiklik", f.read())
        self.assertIn("yerel değişiklik", log)
        with open(core.sys_path("/var/log/osint-menu-yonetici/guncelleme.log")) as f:
            self.assertIn("reset --hard", f.read())

        # İkinci çalıştırma hiçbir şeyi bozmamalı
        out2 = []
        toplu.Batch(log=out2.append).run(ini)
        self.assertEqual(len(core.load_state()["tools"]), 4)
        self.assertIn("zaten ekli", "".join(out2))

        for name in ("eski", "kirli"):
            os.unlink(core.sys_path("/usr/share/applications/%s.desktop" % name))
        for t in list(state["tools"]):
            core.uninstall_tool(t, True)
        core.apply(core.empty_state())
        shutil.rmtree(src)

    def test_guard_and_exec_parsing(self):
        from omy import guncelle
        self.assertIsNone(guncelle._git_root("/root/.bashrc"))
        cands = guncelle.exec_candidates('sh -c "/bin/ls -h; ${SHELL:-bash}"')
        self.assertIn("/bin/ls", cands)


if __name__ == "__main__":
    unittest.main()
