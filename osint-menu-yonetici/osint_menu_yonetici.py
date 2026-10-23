#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OSINT Menü Yöneticisi

Kullanım:
  osint-menu-yonetici              Grafik arayüzü açar
  osint-menu-yonetici --uygula     Menü ve komut dosyalarını kayıttan yeniden üretir
  osint-menu-yonetici --liste      Eklenen kategori ve araçları listeler
  osint-menu-yonetici --temizle    Yapılan bütün menü değişikliklerini geri alır
  osint-menu-yonetici --yardim     Bu yardımı gösterir
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from omy import __version__, core  # noqa: E402


def cli_list():
    state = core.load_state()
    names = {c["id"]: c["name"] for c in state["categories"]}

    def label(path):
        return " ▸ ".join(names.get(p, p) for p in path) or "(en üst)"

    print("Kategoriler:")
    for c in state["categories"]:
        print("  %-30s  konum: %s" % (c["name"], label(c["parent"])))
    if not state["categories"]:
        print("  (yok)")
    print("\nÖzelleştirilen sistem öğeleri:")
    for ov in state.get("overrides", []):
        print("  %-30s  ad: %s  simge: %s" % (ov["id"], ov.get("name") or "-",
                                             ov.get("icon") or "-"))
    if not state.get("overrides"):
        print("  (yok)")
    print("\nAraçlar:")
    for t in state["tools"]:
        print("  %-20s  komut: %-16s  kategori: %s" % (t["name"], t["command"],
                                                      label(t["menu"])))
    if not state["tools"]:
        print("  (yok)")
    return 0


def cli_apply():
    if os.geteuid() != 0 and "OMY_ROOT" not in os.environ:
        print("Bu işlem için root yetkisi gerekli: sudo osint-menu-yonetici --uygula",
              file=sys.stderr)
        return 1
    warnings = core.apply(core.load_state())
    for w in warnings:
        print("UYARI:", w, file=sys.stderr)
    print("Menü ve komut dosyaları yeniden oluşturuldu.")
    return 0


def main(argv):
    args = argv[1:]
    try:
        if args and args[0] in ("-h", "--help", "--yardim", "--yardım"):
            print(__doc__.strip())
            return 0
        if args and args[0] in ("-v", "--version", "--surum", "--sürüm"):
            print(__version__)
            return 0
        if args and args[0] in ("--liste", "--list"):
            return cli_list()
        if args and args[0] in ("--uygula", "--apply"):
            return cli_apply()
        if args and args[0] in ("--temizle", "--clean"):
            if os.geteuid() != 0 and "OMY_ROOT" not in os.environ:
                print("Bu işlem için root yetkisi gerekli.", file=sys.stderr)
                return 1
            core.cleanup_all()
            print("Bütün menü değişiklikleri geri alındı (indirilen araç klasörleri duruyor).")
            return 0
        if args:
            print("Bilinmeyen seçenek: %s\n\n%s" % (args[0], __doc__.strip()), file=sys.stderr)
            return 2
    except core.OmyError as e:
        print("HATA:", e, file=sys.stderr)
        return 1

    try:
        from omy import gui
    except (ImportError, ValueError) as e:
        print("Grafik arayüz başlatılamadı: %s\nGerekli paketler: "
              "sudo apt install python3-gi gir1.2-gtk-3.0" % e, file=sys.stderr)
        return 1
    return gui.main()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
