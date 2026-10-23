# -*- coding: utf-8 -*-
"""Arayüz duman testi: sahte bir kök dizinde pencereyi açar, sürükle-bırak
işlemini taklit eder ve ekran görüntüleri kaydeder.

  xvfb-run -a python3 tests/gui_smoke.py <çıktı-klasörü>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import test_core as fx  # noqa: E402  (ortam değişkenlerini ayarlar)

# GTK'nın MIME veritabanını ve simge temasını bulabilmesi için gerçek
# /usr/share de arama yoluna eklenir.
os.environ["XDG_DATA_DIRS"] += ":/usr/share"

from gi.repository import GLib, Gtk  # noqa: E402

from omy import core, gui  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else "."


def shot(widget, name):
    win = widget.get_window()
    w, h = win.get_width(), win.get_height()
    from gi.repository import Gdk
    pb = Gdk.pixbuf_get_from_window(win, 0, 0, w, h)
    pb.savev(os.path.join(OUT, name), "png", [], [])
    print("kaydedildi:", name)


def main():
    fx.setUpModule()
    state = core.load_state()
    state["categories"].append({"id": "omy-dark-web", "name": "OSINT Dark Web",
                                "icon": "", "comment": "", "parent": ["osint"]})
    state["tools"].append({"id": "eyes", "name": "Eyes", "command": "eyes", "args": "-h",
                           "comment": "E-posta OSINT", "icon": "",
                           "menu": ["osint", "osint-email"], "terminal": True,
                           "source": {"type": "existing"}})
    state["tools"].append({"id": "darkx", "name": "DarkX", "command": "darkx", "args": "",
                           "comment": "", "icon": "", "menu": ["osint", "omy-dark-web"],
                           "terminal": True,
                           "source": {"type": "pipx", "package": "darkx"}})
    core.apply(state)

    win = gui.MainWindow()
    win.show_all()
    errors = []

    def step1():
        win.tree.expand_all()
        shot(win, "1-ana-pencere.png")
        # Sürükle-bırak mantığı: Eyes aracını Dark Web kategorisine taşı.
        win._do_move("tool", "eyes", ["osint", "omy-dark-web"])
        if core.find_tool(win.state, "eyes")["menu"] != ["osint", "omy-dark-web"]:
            errors.append("taşıma başarısız")
        tree = core.scan_menu()
        dark = fx.find(tree, ["osint", "omy-dark-web"])
        if sorted(e["id"] for e in dark.entries) != ["omy-darkx.desktop", "omy-eyes.desktop"]:
            errors.append("menüde taşıma görünmüyor: %r" % dark.entries)
        win.tree.expand_all()
        GLib.timeout_add(400, step2)
        return False

    def step2():
        shot(win, "2-tasindi.png")
        dlg = gui.ToolDialog(win, win.menus, menu_path=["osint", "osint-email"])
        dlg.source_entry.set_text("https://github.com/N0rz3/Eyes")
        GLib.timeout_add(400, step3, dlg)
        return False

    def step3(dlg):
        v = dlg.values()
        if v["name"] != "Eyes" or v["command"] != "eyes" or v["menu"] != ["osint", "osint-email"]:
            errors.append("form otomatik doldurma hatalı: %r" % v)
        shot(dlg, "3-arac-ekle.png")
        dlg.destroy()
        cdlg = gui.CategoryDialog(win, win.menus, parent_path=["osint"])
        cdlg.name_entry.set_text("OSINT Kripto")
        GLib.timeout_add(400, step4, cdlg)
        return False

    def step4(cdlg):
        shot(cdlg, "4-kategori.png")
        cdlg.destroy()
        win.search.set_text("dark")
        GLib.timeout_add(600, step5)
        return False

    def step5():
        shot(win, "5-arama.png")
        Gtk.main_quit()
        return False

    GLib.timeout_add(800, step1)
    Gtk.main()
    fx.tearDownModule()
    if errors:
        print("HATALAR:", errors)
        sys.exit(1)
    print("Arayüz testi başarılı.")


if __name__ == "__main__":
    main()
