# -*- coding: utf-8 -*-
"""OSINT Menü Yöneticisi - GTK3 arayüzü."""

import os
import threading
import traceback

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gdk, GdkPixbuf, Gio, GLib, Gtk, Pango  # noqa: E402

from . import __version__, core  # noqa: E402

APP_TITLE = "OSINT Menü Yöneticisi"
DND_TARGET = "OMY_ROW"

# TreeStore sütunları
C_KIND, C_IDENT, C_PATH, C_ICON, C_TITLE, C_DETAIL, C_FG, C_WEIGHT, C_TIP, C_FILE = range(10)

KIND_ORDER = {"root": 0, "favs": 1, "menu": 2, "cat": 2, "tool": 3, "sys": 3, "fav": 3}
MENU_KINDS = ("root", "menu", "cat")

SOURCE_LABELS = [
    ("git", "GitHub / Git deposu"),
    ("local", "Bilgisayarımdaki klasör veya dosya"),
    ("pipx", "pipx paketi (PyPI adı veya GitHub adresi)"),
    ("apt", "APT paketi (Kali deposundan)"),
    ("existing", "Zaten kurulu komut (pip, pipx, apt ile kurduğum)"),
]

SOURCE_HINTS = {
    "git": "Depo /opt/osint-tools altına indirilir, Python bağımlılıkları kendi sanal "
           "ortamına (.venv) kurulur ve aracı terminalde doğrudan adıyla "
           "çalıştırabilmeniz için /usr/local/bin içine bir komut oluşturulur.",
    "local": "Klasör veya dosya /opt/osint-tools altına kopyalanır (ISO'ya dahil olması "
             "için), bağımlılıklar kurulur ve terminal komutu oluşturulur.",
    "pipx": "Paket sistem geneline kurulur (/opt/pipx); komutu /usr/local/bin içine "
            "eklenir. Bu sayede ISO'daki her kullanıcı aracı kullanabilir.",
    "apt": "Paket apt-get ile kurulur ve seçtiğiniz kategoriye eklenir.",
    "existing": "Hiçbir şey kurulmaz; zaten kurulu olan komut menüye eklenir.",
}

SOURCE_PLACEHOLDERS = {
    "git": "https://github.com/kullanici/arac   veya   kullanici/arac",
    "local": "/home/kali/Downloads/arac",
    "pipx": "holehe   veya   https://github.com/kullanici/arac",
    "apt": "paket-adi",
    "existing": "komut-adi",
}

SOURCE_SHORT = {"git": "GitHub", "local": "Yerel", "pipx": "pipx", "apt": "APT",
                "existing": "Kurulu komut"}


def make_gicon(icon, fallback="application-x-executable"):
    icon = (icon or "").strip()
    if icon and os.path.isabs(icon):
        real = core.sys_path(icon) if not os.path.exists(icon) else icon
        if os.path.exists(real):
            return Gio.FileIcon.new(Gio.File.new_for_path(real))
        icon = ""
    names = [icon] if icon else []
    if icon.endswith((".png", ".svg", ".xpm")):
        names.insert(0, os.path.splitext(icon)[0])
    return Gio.ThemedIcon.new_from_names(names + [fallback])


def run_message(parent, kind, text, secondary=None, buttons=Gtk.ButtonsType.OK):
    dlg = Gtk.MessageDialog(transient_for=parent, modal=True, message_type=kind,
                            buttons=buttons, text=text)
    if secondary:
        dlg.format_secondary_text(secondary)
    resp = dlg.run()
    dlg.destroy()
    return resp


def error(parent, text, secondary=None):
    run_message(parent, Gtk.MessageType.ERROR, text, secondary)


def info(parent, text, secondary=None):
    run_message(parent, Gtk.MessageType.INFO, text, secondary)


def ask(parent, text, secondary=None):
    return run_message(parent, Gtk.MessageType.QUESTION, text, secondary,
                       Gtk.ButtonsType.YES_NO) == Gtk.ResponseType.YES


def grid_label(text):
    lbl = Gtk.Label(label=text, xalign=1)
    lbl.get_style_context().add_class("dim-label")
    return lbl


# --------------------------------------------------------------------------
# Uzun işlemler için günlük (log) penceresi

class TaskDialog(Gtk.Dialog):
    """İşlevi arka planda çalıştırır, çıktısını canlı gösterir."""

    def __init__(self, parent, title):
        super().__init__(title=title, transient_for=parent, modal=True)
        self.set_default_size(760, 460)
        self.close_btn = self.add_button("Kapat", Gtk.ResponseType.CLOSE)
        self.close_btn.set_sensitive(False)
        self.connect("delete-event", lambda *a: not self.close_btn.get_sensitive())

        box = self.get_content_area()
        box.set_spacing(8)
        box.set_border_width(10)
        head = Gtk.Box(spacing=8)
        self.spinner = Gtk.Spinner()
        self.status = Gtk.Label(label="Çalışıyor, lütfen bekleyin…", xalign=0)
        head.pack_start(self.spinner, False, False, 0)
        head.pack_start(self.status, True, True, 0)
        box.pack_start(head, False, False, 0)

        sw = Gtk.ScrolledWindow()
        sw.set_vexpand(True)
        self.view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
        self.view.set_wrap_mode(Gtk.WrapMode.CHAR)
        sw.add(self.view)
        box.pack_start(sw, True, True, 0)
        self.buf = self.view.get_buffer()
        self.result = None
        self.exc = None

    def _append(self, text):
        end = self.buf.get_end_iter()
        self.buf.insert(end, text)
        mark = self.buf.create_mark(None, self.buf.get_end_iter(), False)
        self.view.scroll_mark_onscreen(mark)
        self.buf.delete_mark(mark)
        return False

    def log(self, text):
        GLib.idle_add(self._append, text)

    def _finish(self):
        self.spinner.stop()
        self.close_btn.set_sensitive(True)
        if self.exc is None:
            self.status.set_markup("<b>✔ Tamamlandı.</b>")
        else:
            self.status.set_markup("<b>✘ Hata:</b> %s" % GLib.markup_escape_text(str(self.exc)))
        return False

    def execute(self, func, *args):
        """func(*args, log) çalıştırılır. (başarılı_mı, sonuç) döndürür."""
        def worker():
            try:
                self.result = func(*args, self.log)
            except core.OmyError as e:
                self.exc = e
                self.log("\nHATA: %s\n" % e)
            except Exception as e:  # beklenmeyen hata: ayrıntıyı göster
                self.exc = e
                self.log("\n" + traceback.format_exc())
            GLib.idle_add(self._finish)

        self.show_all()
        self.spinner.start()
        threading.Thread(target=worker, daemon=True).start()
        self.run()
        self.destroy()
        return self.exc is None, self.result


# --------------------------------------------------------------------------
# Simge seçici

def choose_image_file(parent):
    dlg = Gtk.FileChooserDialog(title="Simge dosyası seç", transient_for=parent,
                                action=Gtk.FileChooserAction.OPEN)
    dlg.add_buttons("İptal", Gtk.ResponseType.CANCEL, "Seç", Gtk.ResponseType.OK)
    flt = Gtk.FileFilter()
    flt.set_name("Resimler (png, svg, xpm, jpg, ico)")
    for pat in ("*.png", "*.svg", "*.xpm", "*.jpg", "*.jpeg", "*.ico"):
        flt.add_pattern(pat)
        flt.add_pattern(pat.upper())
    dlg.add_filter(flt)
    home = os.environ.get("OMY_REAL_HOME")
    if home and os.path.isdir(home):
        dlg.set_current_folder(home)
    elif os.path.isdir("/usr/share/pixmaps"):
        dlg.set_current_folder("/usr/share/pixmaps")
    path = dlg.get_filename() if dlg.run() == Gtk.ResponseType.OK else None
    dlg.destroy()
    return path


class IconChooserDialog(Gtk.Dialog):
    """Hazır OSINT simgeleri, sistem/Kali simge teması ve dosyadan seçim."""

    SYSTEM_LIMIT = 600
    RESP_FILE = 1

    def __init__(self, parent, current="", extra_dir=None):
        super().__init__(title="Simge Seç", transient_for=parent, modal=True)
        self.set_default_size(760, 560)
        self.add_button("Dosyadan seç…", self.RESP_FILE)
        self.add_buttons("İptal", Gtk.ResponseType.CANCEL, "Seç", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.result = None
        box = self.get_content_area()
        box.set_border_width(10)
        box.set_spacing(8)

        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Simge ara… (ör. mail, telefon, kali-, harita)")
        self.search.connect("search-changed", lambda *_a: self._refilter())
        box.pack_start(self.search, False, False, 0)

        self.notebook = Gtk.Notebook()
        box.pack_start(self.notebook, True, True, 0)

        # Hazır OSINT simgeleri
        self.pack_store = Gtk.ListStore(GdkPixbuf.Pixbuf, str, str, str)  # simge, ad, yol, arama
        self.pack_filter = self.pack_store.filter_new()
        self.pack_filter.set_visible_func(self._pack_visible)
        self.pack_view = self._make_view(self.pack_filter, pixbuf_col=0, text_col=1)
        for icon in core.load_icon_pack():
            try:
                pb = GdkPixbuf.Pixbuf.new_from_file_at_size(icon["real"], 48, 48)
            except GLib.Error:
                continue
            self.pack_store.append([pb, icon["label"], icon["path"],
                                    ("%s %s %s" % (icon["label"], icon["keywords"],
                                                   os.path.basename(icon["path"]))).casefold()])
        self._add_page(self.pack_view, "Hazır OSINT Simgeleri")

        # Aracın kendi klasöründeki resimler (logo, ikon…)
        self.repo_store = Gtk.ListStore(GdkPixbuf.Pixbuf, str, str, str)
        self.repo_filter = self.repo_store.filter_new()
        self.repo_filter.set_visible_func(self._pack_visible)
        self.repo_view = self._make_view(self.repo_filter, pixbuf_col=0, text_col=1)
        for path in core.find_repo_images(extra_dir) if extra_dir else []:
            try:
                pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(path, 48, 48, True)
            except GLib.Error:
                continue
            rel = os.path.relpath(path, extra_dir)
            self.repo_store.append([pb, os.path.basename(path), path, rel.casefold()])

        # Sistem / Kali simgeleri
        theme = Gtk.IconTheme.get_default()
        names = [n for n in theme.list_icons(None) if not n.endswith("-symbolic")]
        apps = set(theme.list_icons("Applications") or []) | set(theme.list_icons("Places") or [])
        self.all_icons = sorted(names, key=lambda n: (not n.startswith("kali"), n not in apps, n))
        self.sys_store = Gtk.ListStore(str, str)
        self.sys_view = self._make_view(self.sys_store, icon_name_col=0, text_col=1)
        self._add_page(self.sys_view, "Sistem / Kali Simgeleri")
        self.REPO_PAGE = -1
        if len(self.repo_store):
            self._add_page(self.repo_view, "Aracın Kendi Resimleri (%d)" % len(self.repo_store))
            self.REPO_PAGE = 2
        self.sys_info = Gtk.Label(xalign=0)
        self.sys_info.get_style_context().add_class("dim-label")
        box.pack_start(self.sys_info, False, False, 0)

        self.selected_label = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.MIDDLE)
        box.pack_start(self.selected_label, False, False, 0)
        self.notebook.connect("switch-page", lambda *_a: GLib.idle_add(self._refilter))
        self._fill_system()
        if self.REPO_PAGE >= 0 and not current:
            GLib.idle_add(self.notebook.set_current_page, self.REPO_PAGE)
        if current and os.path.basename(current).startswith("osint-"):
            for i, row in enumerate(self.pack_filter):
                if row[2] == current:
                    self.pack_view.select_path(Gtk.TreePath(i))
        self.show_all()

    def _add_page(self, view, title):
        sw = Gtk.ScrolledWindow()
        sw.add(view)
        self.notebook.append_page(sw, Gtk.Label(label=title))

    def _make_view(self, model, text_col, pixbuf_col=None, icon_name_col=None):
        view = Gtk.IconView(model=model)
        view.set_item_width(96)
        view.set_columns(-1)
        view.set_activate_on_single_click(False)
        pix = Gtk.CellRendererPixbuf(stock_size=Gtk.IconSize.DIALOG)
        view.pack_start(pix, False)
        if pixbuf_col is not None:
            view.add_attribute(pix, "pixbuf", pixbuf_col)
        else:
            view.add_attribute(pix, "icon-name", icon_name_col)
        txt = Gtk.CellRendererText(alignment=Pango.Alignment.CENTER, xalign=0.5,
                                   wrap_mode=Pango.WrapMode.WORD_CHAR, wrap_width=90)
        txt.set_property("size-points", 8)
        view.pack_start(txt, False)
        view.add_attribute(txt, "text", text_col)
        view.connect("item-activated", lambda *_a: self.response(Gtk.ResponseType.OK))
        view.connect("selection-changed", lambda *_a: self._show_selected())
        return view

    def _pack_visible(self, model, it, _data):
        q = self.search.get_text().strip().casefold()
        return not q or q in model[it][3]

    def _fill_system(self):
        q = self.search.get_text().strip().casefold()
        self.sys_store.clear()
        matches = [n for n in self.all_icons if not q or q in n.casefold()]
        for n in matches[:self.SYSTEM_LIMIT]:
            self.sys_store.append([n, n])
        more = len(matches) - self.SYSTEM_LIMIT
        self.sys_info.set_text(
            "%d simgeden ilk %d tanesi gösteriliyor; daraltmak için arayın." %
            (len(matches), self.SYSTEM_LIMIT) if more > 0 else
            "Kali araç simgeleri “kali-” ile başlar (ör. kali-sherlock).")
        self.sys_info.set_visible(self.notebook.get_current_page() == 1)

    def _refilter(self):
        self._show_selected()
        self.pack_filter.refilter()
        self.repo_filter.refilter()
        if self.notebook.get_current_page() == 1:
            self._fill_system()
        else:
            self.sys_info.set_visible(False)
        return False

    def _current(self):
        if self.notebook.get_current_page() == self.REPO_PAGE:
            items = self.repo_view.get_selected_items()
            return (self.repo_filter[items[0]][2], self.repo_filter[items[0]][1]) if items \
                else (None, None)
        if self.notebook.get_current_page() == 0:
            items = self.pack_view.get_selected_items()
            return (self.pack_filter[items[0]][2], self.pack_filter[items[0]][1]) if items \
                else (None, None)
        items = self.sys_view.get_selected_items()
        return (self.sys_store[items[0]][0],) * 2 if items else (None, None)

    def _show_selected(self):
        value, label = self._current()
        self.selected_label.set_markup("Seçili: <b>%s</b>" % GLib.markup_escape_text(label)
                                       if value else "")

    def choose(self):
        """Seçilen simgeyi (yol ya da tema adı) döndürür, iptalde None."""
        while True:
            resp = self.run()
            if resp == self.RESP_FILE:
                path = choose_image_file(self)
                if path:
                    self.result = path
                    break
                continue
            if resp == Gtk.ResponseType.OK:
                value, _label = self._current()
                if value is None:
                    continue
                self.result = value
            break
        self.destroy()
        return self.result


def icon_label(value):
    """Simge değerini kullanıcıya okunur biçimde gösterir."""
    if not value:
        return ""
    if os.path.isabs(value):
        base = os.path.basename(value)
        for icon in core.load_icon_pack():
            if os.path.basename(icon["path"]) == base and \
                    os.path.dirname(value) in (core.PACK_DIR, core.pack_dir()):
                return icon["label"]
        return base
    return value


class IconPicker(Gtk.Box):
    def __init__(self, parent_window, default_icon, extra_dir=None):
        super().__init__(spacing=6)
        self.extra_dir = extra_dir
        self.parent_window = parent_window
        self.default_icon = default_icon
        self.value = ""
        self.preview_btn = Gtk.Button()
        self.preview_btn.set_tooltip_text("Simge seç")
        self.preview = Gtk.Image()
        self.preview_btn.add(self.preview)
        self.preview_btn.connect("clicked", self._choose)
        self.label = Gtk.Label(xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.END,
                               width_chars=12)
        btn = Gtk.Button(label="Simge seç…")
        btn.set_image(Gtk.Image.new_from_icon_name("image-x-generic", Gtk.IconSize.BUTTON))
        btn.set_always_show_image(True)
        btn.connect("clicked", self._choose)
        self.clear_btn = Gtk.Button.new_from_icon_name("edit-clear", Gtk.IconSize.BUTTON)
        self.clear_btn.set_tooltip_text("Varsayılan simgeye dön")
        self.clear_btn.connect("clicked", lambda *_a: self.set(""))
        self.pack_start(self.preview_btn, False, False, 0)
        self.pack_start(self.label, True, True, 0)
        self.pack_start(self.clear_btn, False, False, 0)
        self.pack_start(btn, False, False, 0)
        self._update()

    def _update(self):
        self.preview.set_from_gicon(make_gicon(self.value, self.default_icon),
                                    Gtk.IconSize.DND)
        text = icon_label(self.value)
        if text:
            self.label.set_text(text)
            self.label.set_tooltip_text(self.value)
        else:
            self.label.set_markup("<i>Varsayılan simge</i>")
            self.label.set_tooltip_text(None)
        self.clear_btn.set_sensitive(bool(self.value))

    def _choose(self, _btn):
        value = IconChooserDialog(self.parent_window, self.value, self.extra_dir).choose()
        if value:
            self.set(value)

    def get(self):
        return self.value

    def set(self, value):
        self.value = (value or "").strip()
        self._update()


# --------------------------------------------------------------------------
# Menü (kategori) seçici

class MenuCombo(Gtk.ComboBox):
    def __init__(self, menus, allow_root, exclude_prefix=None):
        store = Gtk.ListStore(str, str, Gio.Icon)
        super().__init__(model=store)
        icon_cell = Gtk.CellRendererPixbuf()
        self.pack_start(icon_cell, False)
        self.add_attribute(icon_cell, "gicon", 2)
        cell = Gtk.CellRendererText(ellipsize=Pango.EllipsizeMode.START)
        self.pack_start(cell, True)
        self.add_attribute(cell, "text", 1)
        for path, label, icon in menus:
            if not path and not allow_root:
                continue
            if exclude_prefix is not None and core.is_under(path, exclude_prefix):
                continue
            if not isinstance(icon, Gio.Icon):
                icon = make_gicon(icon, "folder")
            store.append([core.path_key(path), label, icon])
        self.set_active(0 if len(store) else -1)

    def set_path(self, path):
        key = core.path_key(path)
        for i, row in enumerate(self.get_model()):
            if row[0] == key:
                self.set_active(i)
                return True
        return False

    def get_path(self):
        it = self.get_active_iter()
        if it is None:
            return None
        key = self.get_model()[it][0]
        return key.split("/") if key else []


# --------------------------------------------------------------------------
# Çalıştırılacak dosya / çalıştırıcı ayarları (GitHub ve yerel araçlar)

class EntryPanel(Gtk.Grid):
    def __init__(self, real_dir, names, src):
        super().__init__(column_spacing=10, row_spacing=8)
        self.entry_combo = Gtk.ComboBoxText.new_with_entry()
        self.entry_combo.set_hexpand(True)
        self.entries = core.find_entry_candidates(real_dir, names) \
            if os.path.isdir(real_dir) else []
        for entry, label in self.entries:
            self.entry_combo.append(entry, label)
        current = src.get("entry", "")
        if current:
            if not self.entry_combo.set_active_id(current):
                self.entry_combo.get_child().set_text(current)
        elif self.entries:
            self.entry_combo.set_active(0)

        self.runner_combo = Gtk.ComboBoxText()
        for key, label in core.RUNNERS.items():
            self.runner_combo.append(key, label)
        self.runner_combo.set_active_id(src.get("runner", "auto"))

        self.cd_check = Gtk.CheckButton(
            label="Komutu aracın kendi klasöründe çalıştır (önerilir)")
        self.cd_check.set_active(src.get("cd", True))
        self.cd_check.set_tooltip_text(
            "Birçok GitHub aracı kendi klasöründeki dosyaları (veri, ayar) göreli yolla "
            "okur. Bu seçenek açıkken komut, aracın klasörüne geçip çalışır. Kapalıyken "
            "bulunduğunuz klasörde çalışır.")

        self.attach(grid_label("Çalıştırılacak dosya"), 0, 0, 1, 1)
        self.attach(self.entry_combo, 1, 0, 1, 1)
        self.attach(grid_label("Çalıştırıcı"), 0, 1, 1, 1)
        self.attach(self.runner_combo, 1, 1, 1, 1)
        self.attach(self.cd_check, 1, 2, 1, 1)
        hint = Gtk.Label(xalign=0, wrap=True, max_width_chars=60)
        hint.set_markup("<small>Liste, klasördeki en olası başlangıç dosyasıyla başlar. "
                        "Doğru dosya listede yoksa yolunu (klasöre göre) yazabilirsiniz.</small>")
        hint.get_style_context().add_class("dim-label")
        self.attach(hint, 1, 3, 1, 1)

    def get_entry(self):
        active = self.entry_combo.get_active_id()
        text = self.entry_combo.get_child().get_text().strip()
        if active and any(label == text for e, label in self.entries if e == active):
            return active
        return text

    def apply_to(self, src):
        src["entry"] = self.get_entry()
        src["runner"] = self.runner_combo.get_active_id() or "auto"
        src["cd"] = self.cd_check.get_active()


class EntryDialog(Gtk.Dialog):
    """Kurulumdan sonra çalıştırılacak dosyayı seçtirir."""

    def __init__(self, parent, tool, warn, icon=""):
        super().__init__(title="Başlangıç dosyasını seçin", transient_for=parent, modal=True)
        self.add_buttons("İptal", Gtk.ResponseType.CANCEL, "Tamam", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        box = self.get_content_area()
        box.set_border_width(12)
        box.set_spacing(10)
        title = Gtk.Label(xalign=0, wrap=True)
        title.set_markup("<b>%s</b> indirildi. Terminalde <tt>%s</tt> yazınca hangi dosya "
                         "çalışsın?" % (GLib.markup_escape_text(tool["name"]),
                                        GLib.markup_escape_text(tool["command"])))
        box.pack_start(title, False, False, 0)
        if warn:
            w = Gtk.Label(xalign=0, wrap=True)
            w.set_markup("<span foreground='#e5a50a'>⚠ Bazı bağımlılıklar kurulamadı. "
                         "Araç yine de çalışabilir; sorun olursa günlüğü kontrol edin "
                         "veya “Güncelle” ile tekrar deneyin.</span>")
            box.pack_start(w, False, False, 0)
        self.panel = EntryPanel(core.sys_path(tool["source"]["dir"]),
                                [tool["command"], tool["name"], tool["id"]], tool["source"])
        box.pack_start(self.panel, False, False, 0)

        real_dir = core.sys_path(tool["source"]["dir"])
        self.icon_picker = IconPicker(self, "utilities-terminal", extra_dir=real_dir)
        self.icon_picker.set(icon or core.best_repo_icon(real_dir))
        row = Gtk.Box(spacing=10)
        row.pack_start(grid_label("Simge"), False, False, 0)
        row.pack_start(self.icon_picker, True, True, 0)
        box.pack_start(row, False, False, 0)
        if core.find_repo_images(real_dir, limit=1):
            hint = Gtk.Label(xalign=0, wrap=True)
            hint.set_markup("<small>Simge seçerken “Aracın Kendi Resimleri” sekmesinde "
                            "deponun içindeki logoları da bulabilirsiniz.</small>")
            hint.get_style_context().add_class("dim-label")
            box.pack_start(hint, False, False, 0)
        self.show_all()


# --------------------------------------------------------------------------
# Araç ekleme / düzenleme

class ToolDialog(Gtk.Dialog):
    def __init__(self, parent, menus, tool=None, menu_path=None):
        self.editing = tool is not None
        super().__init__(title="Aracı Düzenle" if self.editing else "Yeni Araç Ekle",
                         transient_for=parent, modal=True)
        self.set_default_size(640, -1)
        self.add_buttons("İptal", Gtk.ResponseType.CANCEL,
                         "Kaydet" if self.editing else "Ekle", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.tool = tool
        self._name_touched = self.editing
        self._cmd_touched = self.editing

        box = self.get_content_area()
        box.set_border_width(12)
        box.set_spacing(10)
        g = Gtk.Grid(column_spacing=10, row_spacing=8)
        box.pack_start(g, False, False, 0)
        row = 0

        self.source_combo = Gtk.ComboBoxText()
        for key, label in SOURCE_LABELS:
            self.source_combo.append(key, label)
        self.source_entry = Gtk.Entry(hexpand=True, activates_default=True)
        self.browse_dir = Gtk.Button.new_from_icon_name("folder-open", Gtk.IconSize.BUTTON)
        self.browse_dir.set_tooltip_text("Klasör seç")
        self.browse_dir.connect("clicked", self._browse, Gtk.FileChooserAction.SELECT_FOLDER)
        self.browse_file = Gtk.Button.new_from_icon_name("document-open", Gtk.IconSize.BUTTON)
        self.browse_file.set_tooltip_text("Tek bir dosya seç (ör. arac.py)")
        self.browse_file.connect("clicked", self._browse, Gtk.FileChooserAction.OPEN)
        src_box = Gtk.Box(spacing=4)
        src_box.pack_start(self.source_entry, True, True, 0)
        src_box.pack_start(self.browse_dir, False, False, 0)
        src_box.pack_start(self.browse_file, False, False, 0)

        if self.editing:
            src = tool["source"]
            lbl = Gtk.Label(xalign=0, selectable=True, wrap=True)
            text = SOURCE_SHORT.get(src["type"], src["type"])
            extra = src.get("url") or src.get("package") or ""
            if src.get("dir"):
                extra = (extra + "  →  " if extra else "") + src["dir"]
            lbl.set_text("%s%s" % (text, ("  ·  " + extra) if extra else ""))
            g.attach(grid_label("Kaynak"), 0, row, 1, 1)
            g.attach(lbl, 1, row, 1, 1)
            row += 1
        else:
            g.attach(grid_label("Kaynak türü"), 0, row, 1, 1)
            g.attach(self.source_combo, 1, row, 1, 1)
            row += 1
            self.source_label = grid_label("Adres")
            g.attach(self.source_label, 0, row, 1, 1)
            g.attach(src_box, 1, row, 1, 1)
            row += 1
            self.hint = Gtk.Label(xalign=0, wrap=True, max_width_chars=70)
            self.hint.get_style_context().add_class("dim-label")
            g.attach(self.hint, 1, row, 1, 1)
            row += 1

        self.name_entry = Gtk.Entry(hexpand=True, activates_default=True)
        self.name_entry.set_placeholder_text("Menüde görünecek ad")
        self.cmd_entry = Gtk.Entry(activates_default=True)
        self.cmd_entry.set_placeholder_text("Terminalde yazacağınız komut")
        self.args_entry = Gtk.Entry(activates_default=True)
        self.args_entry.set_placeholder_text("ör. -h  (boş bırakılabilir)")
        self.args_entry.set_tooltip_text(
            "Menüden tıklayınca terminalde komutla birlikte çalışacak parametreler. "
            "Genelde yardım ekranını göstermek için -h veya --help kullanılır.")
        self.comment_entry = Gtk.Entry(activates_default=True)
        self.comment_entry.set_placeholder_text("Kısa açıklama (isteğe bağlı)")
        self.menu_combo = MenuCombo(menus, allow_root=False)
        self.icon_picker = IconPicker(self, "utilities-terminal")
        self.terminal_check = Gtk.CheckButton(
            label="Menüden açınca terminalde çalıştır (komut satırı araçları için)")

        for label, widget in (("Görünen ad", self.name_entry),
                              ("Terminal komutu", self.cmd_entry),
                              ("Menü parametreleri", self.args_entry),
                              ("Açıklama", self.comment_entry),
                              ("Kategori", self.menu_combo),
                              ("Simge", self.icon_picker)):
            g.attach(grid_label(label), 0, row, 1, 1)
            g.attach(widget, 1, row, 1, 1)
            row += 1
        g.attach(self.terminal_check, 1, row, 1, 1)
        row += 1

        self.entry_panel = None
        if self.editing and tool["source"]["type"] in core.SOURCES_WITH_WRAPPER:
            frame = Gtk.Frame(label=" Terminal komutu ayarları ")
            self.entry_panel = EntryPanel(core.sys_path(tool["source"]["dir"]),
                                          [tool["command"], tool["name"], tool["id"]],
                                          tool["source"])
            self.entry_panel.set_border_width(10)
            frame.add(self.entry_panel)
            box.pack_start(frame, False, False, 0)

        self.name_entry.connect("changed", self._name_changed)
        self.cmd_entry.connect("changed", self._cmd_changed)
        self.source_entry.connect("changed", self._source_changed)
        self.source_combo.connect("changed", self._type_changed)

        if self.editing and tool["source"].get("dir"):
            self.icon_picker.extra_dir = core.sys_path(tool["source"]["dir"])
        if self.editing:
            self.name_entry.set_text(tool["name"])
            self.cmd_entry.set_text(tool["command"])
            self.args_entry.set_text(tool.get("args", ""))
            self.comment_entry.set_text(tool.get("comment", ""))
            self.icon_picker.set(tool.get("icon", ""))
            self.terminal_check.set_active(tool.get("terminal", True))
            self.menu_combo.set_path(tool["menu"])
            if tool["source"]["type"] in ("pipx", "apt"):
                self.cmd_entry.set_sensitive(True)
        else:
            self.args_entry.set_text("-h")
            self.terminal_check.set_active(True)
            self.source_combo.set_active_id("git")
            if menu_path:
                self.menu_combo.set_path(menu_path)
        self.show_all()
        if not self.editing:
            self._type_changed()

    # --- olaylar
    def _type_changed(self, *_a):
        t = self.source_combo.get_active_id()
        self.hint.set_markup("<small>%s</small>" % GLib.markup_escape_text(SOURCE_HINTS[t]))
        self.source_entry.set_placeholder_text(SOURCE_PLACEHOLDERS[t])
        self.source_label.set_text({"git": "Depo adresi", "local": "Konum",
                                    "pipx": "Paket", "apt": "Paket adı",
                                    "existing": "Komut"}[t])
        self.browse_dir.set_visible(t == "local")
        self.browse_file.set_visible(t == "local")
        self.cmd_entry.set_sensitive(t != "existing")
        self._source_changed()

    def _browse(self, _btn, action):
        title = "Klasör seç" if action == Gtk.FileChooserAction.SELECT_FOLDER else "Dosya seç"
        dlg = Gtk.FileChooserDialog(title=title, transient_for=self, action=action)
        dlg.add_buttons("İptal", Gtk.ResponseType.CANCEL, "Seç", Gtk.ResponseType.OK)
        home = os.environ.get("OMY_REAL_HOME") or os.path.expanduser("~")
        dlg.set_current_folder(home)
        if dlg.run() == Gtk.ResponseType.OK:
            self.source_entry.set_text(dlg.get_filename())
        dlg.destroy()

    def _source_changed(self, *_a):
        t = self.source_combo.get_active_id()
        value = self.source_entry.get_text()
        if t == "existing":
            self.cmd_entry.set_text(value.strip())
        base = core.name_from_source(t, value)
        if not self._name_touched:
            self.name_entry.handler_block_by_func(self._name_changed)
            self.name_entry.set_text(base)
            self.name_entry.handler_unblock_by_func(self._name_changed)
        if not self._cmd_touched and t != "existing":
            self._set_cmd(core.slugify(base, "") if base else "")

    def _set_cmd(self, value):
        self.cmd_entry.handler_block_by_func(self._cmd_changed)
        self.cmd_entry.set_text(value)
        self.cmd_entry.handler_unblock_by_func(self._cmd_changed)

    def _name_changed(self, *_a):
        self._name_touched = bool(self.name_entry.get_text())
        if not self._cmd_touched and not self.editing and \
                self.source_combo.get_active_id() != "existing":
            self._set_cmd(core.slugify(self.name_entry.get_text(), ""))

    def _cmd_changed(self, *_a):
        self._cmd_touched = bool(self.cmd_entry.get_text())

    # --- değerler
    def values(self):
        return {
            "type": self.tool["source"]["type"] if self.editing
            else self.source_combo.get_active_id(),
            "source": "" if self.editing else self.source_entry.get_text().strip(),
            "name": self.name_entry.get_text().strip(),
            "command": self.cmd_entry.get_text().strip(),
            "args": self.args_entry.get_text().strip(),
            "comment": self.comment_entry.get_text().strip(),
            "menu": self.menu_combo.get_path(),
            "icon": self.icon_picker.get(),
            "terminal": self.terminal_check.get_active(),
        }


# --------------------------------------------------------------------------
# Kategori ekleme / düzenleme

def preset_combo():
    store = Gtk.ListStore(str, Gio.Icon, str, object)
    store.append(["", make_gicon("", "folder-templates"), "— Seçin ya da kendiniz yazın —",
                  None])
    for name, icon, comment in core.CATEGORY_PRESETS:
        store.append([name, make_gicon(core.pack_icon(icon), "folder"), name,
                      (name, icon, comment)])
    combo = Gtk.ComboBox(model=store)
    pix = Gtk.CellRendererPixbuf()
    combo.pack_start(pix, False)
    combo.add_attribute(pix, "gicon", 1)
    txt = Gtk.CellRendererText()
    combo.pack_start(txt, True)
    combo.add_attribute(txt, "text", 2)
    combo.set_active(0)
    return combo


class PresetsDialog(Gtk.Dialog):
    """Hazır OSINT kategorilerini tek seferde oluşturur."""

    def __init__(self, parent, menus, parent_path, existing):
        super().__init__(title="Hazır OSINT Kategorileri", transient_for=parent, modal=True)
        self.set_default_size(560, 620)
        self.add_buttons("İptal", Gtk.ResponseType.CANCEL, "Seçilenleri Oluştur",
                         Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        box = self.get_content_area()
        box.set_border_width(12)
        box.set_spacing(8)
        lbl = Gtk.Label(xalign=0, wrap=True)
        lbl.set_markup("Oluşturmak istediğiniz kategorileri işaretleyin. Her biri kendi "
                       "simgesiyle gelir; adlarını ve simgelerini sonra değiştirebilirsiniz.")
        box.pack_start(lbl, False, False, 0)
        row = Gtk.Box(spacing=8)
        row.pack_start(grid_label("Nerede olsun?"), False, False, 0)
        self.parent_combo = MenuCombo(menus, allow_root=True)
        if parent_path is not None:
            self.parent_combo.set_path(parent_path)
        row.pack_start(self.parent_combo, True, True, 0)
        box.pack_start(row, False, False, 0)

        self.existing = existing
        self.checks = []
        lb = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        for name, icon, comment in core.CATEGORY_PRESETS:
            hb = Gtk.Box(spacing=10)
            hb.set_border_width(4)
            check = Gtk.CheckButton()
            img = Gtk.Image.new_from_gicon(make_gicon(core.pack_icon(icon), "folder"),
                                           Gtk.IconSize.LARGE_TOOLBAR)
            text = Gtk.Label(xalign=0)
            text.set_markup("<b>%s</b>\n<small>%s</small>" % (GLib.markup_escape_text(name),
                                                             GLib.markup_escape_text(comment)))
            hb.pack_start(check, False, False, 0)
            hb.pack_start(img, False, False, 0)
            hb.pack_start(text, True, True, 0)
            lb.add(hb)
            self.checks.append((check, text, (name, icon, comment)))
        sw = Gtk.ScrolledWindow()
        sw.set_vexpand(True)
        sw.add(lb)
        box.pack_start(sw, True, True, 0)
        sel = Gtk.Box(spacing=6)
        for label, value in (("Tümünü seç", True), ("Hiçbirini seçme", False)):
            b = Gtk.Button(label=label)
            b.connect("clicked", self._set_all, value)
            sel.pack_start(b, False, False, 0)
        box.pack_start(sel, False, False, 0)
        self.parent_combo.connect("changed", lambda *_a: self._mark_existing())
        self._mark_existing()
        self.show_all()

    def _mark_existing(self):
        path = self.parent_combo.get_path() or []
        names = self.existing(path)
        for check, _text, (name, _icon, _c) in self.checks:
            exists = name.casefold() in names
            check.set_sensitive(not exists)
            check.set_tooltip_text("Bu adda bir kategori burada zaten var" if exists else None)
            if exists:
                check.set_active(False)

    def _set_all(self, _btn, value):
        for check, _t, _p in self.checks:
            if check.get_sensitive():
                check.set_active(value)

    def values(self):
        return (self.parent_combo.get_path(),
                [p for check, _t, p in self.checks if check.get_active()])


class SystemItemDialog(Gtk.Dialog):
    """Sistemde zaten olan bir kategorinin ya da uygulamanın adını/simgesini
    değiştirir."""

    RESP_RESET = 1

    def __init__(self, parent, kind_label, title, icon, overridden):
        super().__init__(title="%s Özelleştir" % kind_label, transient_for=parent, modal=True)
        self.set_default_size(560, -1)
        if overridden:
            self.add_button("Varsayılana döndür", self.RESP_RESET)
        self.add_buttons("İptal", Gtk.ResponseType.CANCEL, "Kaydet", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        box = self.get_content_area()
        box.set_border_width(12)
        box.set_spacing(10)
        g = Gtk.Grid(column_spacing=10, row_spacing=8)
        box.pack_start(g, False, False, 0)
        self.name_entry = Gtk.Entry(hexpand=True, activates_default=True)
        self.name_entry.set_text(title)
        self.icon_picker = IconPicker(self, "folder" if kind_label == "Kategori"
                                      else "application-x-executable")
        self.icon_picker.set(icon)
        g.attach(grid_label("Ad"), 0, 0, 1, 1)
        g.attach(self.name_entry, 1, 0, 1, 1)
        g.attach(grid_label("Simge"), 0, 1, 1, 1)
        g.attach(self.icon_picker, 1, 1, 1, 1)
        hint = Gtk.Label(xalign=0, wrap=True, max_width_chars=60)
        hint.set_markup("<small>Bu öğe sistemde zaten vardı. Özgün dosya bozulmaz: "
                        "değişiklik ayrı bir kopya ile uygulanır ve istediğiniz zaman "
                        "“Varsayılana döndür” ile geri alınabilir.</small>")
        hint.get_style_context().add_class("dim-label")
        g.attach(hint, 1, 2, 1, 1)
        self.show_all()



class CategoryDialog(Gtk.Dialog):
    def __init__(self, parent, menus, cat=None, parent_path=None):
        editing = cat is not None
        super().__init__(title="Kategoriyi Düzenle" if editing else "Yeni Kategori",
                         transient_for=parent, modal=True)
        self.set_default_size(580, -1)
        self.add_buttons("İptal", Gtk.ResponseType.CANCEL,
                         "Kaydet" if editing else "Oluştur", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        box = self.get_content_area()
        box.set_border_width(12)
        box.set_spacing(10)
        g = Gtk.Grid(column_spacing=10, row_spacing=8)
        box.pack_start(g, False, False, 0)

        self.name_entry = Gtk.Entry(hexpand=True, activates_default=True)
        self.name_entry.set_placeholder_text("ör. OSINT Dark Web")
        self.comment_entry = Gtk.Entry(activates_default=True)
        self.comment_entry.set_placeholder_text("İsteğe bağlı")
        self.parent_combo = MenuCombo(menus, allow_root=True,
                                      exclude_prefix=core.cat_path(cat) if editing else None)
        self.icon_picker = IconPicker(self, "folder")
        rows = [("Kategori adı", self.name_entry),
                ("Nerede olsun?", self.parent_combo),
                ("Simge", self.icon_picker),
                ("Açıklama", self.comment_entry)]
        if not editing:
            self.preset_combo = preset_combo()
            self.preset_combo.connect("changed", self._preset_chosen)
            rows.insert(0, ("Hazır şablon", self.preset_combo))
        for row, (label, widget) in enumerate(rows):
            g.attach(grid_label(label), 0, row, 1, 1)
            g.attach(widget, 1, row, 1, 1)
        hint = Gtk.Label(xalign=0, wrap=True, max_width_chars=60)
        hint.set_markup("<small>“Uygulama Menüsü (en üst)” seçilirse kategori, sol taraftaki "
                        "Recon, OSINT gibi ana kategorilerin yanında görünür. Bir kategori "
                        "seçerseniz onun içinde alt kategori olur.\nNot: XFCE boş "
                        "kategorileri menüde göstermez; içine araç ekleyince görünür.</small>")
        hint.get_style_context().add_class("dim-label")
        g.attach(hint, 1, len(rows), 1, 1)

        if editing:
            self.name_entry.set_text(cat["name"])
            self.comment_entry.set_text(cat.get("comment", ""))
            self.icon_picker.set(cat.get("icon", ""))
            self.parent_combo.set_path(cat["parent"])
        elif parent_path is not None:
            self.parent_combo.set_path(parent_path)
        self.show_all()

    def _preset_chosen(self, combo):
        it = combo.get_active_iter()
        if it is None or combo.get_active() == 0:
            return
        name, icon, comment = combo.get_model()[it][3]
        self.name_entry.set_text(name)
        self.icon_picker.set(core.pack_icon(icon))
        self.comment_entry.set_text(comment)

    def values(self):
        return {"name": self.name_entry.get_text().strip(),
                "comment": self.comment_entry.get_text().strip(),
                "icon": self.icon_picker.get(),
                "parent": self.parent_combo.get_path()}


# --------------------------------------------------------------------------
# Ana pencere

class MainWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title=APP_TITLE)
        self.set_default_size(1000, 680)
        self.set_icon_name("preferences-desktop-menu")
        self.state = core.load_state()
        self.scan = None
        self.scan_error = None
        self.menus = []
        self.favs = []

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.add(outer)

        # Araç çubuğu
        bar = Gtk.Box(spacing=6)
        bar.set_border_width(8)
        outer.pack_start(bar, False, False, 0)
        self.infobar = Gtk.InfoBar(message_type=Gtk.MessageType.WARNING)
        self.infobar.set_show_close_button(True)
        self.infobar.connect("response", lambda ib, _r: ib.hide())
        self.infobar_label = Gtk.Label(xalign=0, wrap=True, selectable=True)
        self.infobar.get_content_area().add(self.infobar_label)
        self.infobar.set_no_show_all(True)
        self.infobar_label.show()
        outer.pack_start(self.infobar, False, False, 0)

        def button(label, icon, cb, tip):
            b = Gtk.Button(label=label)
            b.set_image(Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.BUTTON))
            b.set_always_show_image(True)
            b.set_tooltip_text(tip)
            b.connect("clicked", lambda *_a: cb())
            bar.pack_start(b, False, False, 0)
            return b

        self.btn_add = button("Araç Ekle", "list-add", self.on_add_tool,
                              "GitHub, pipx, APT ya da kurulu bir aracı menüye ekle")
        self.btn_add.get_style_context().add_class("suggested-action")
        self.btn_cat = button("Kategori Oluştur", "folder-new", self.on_add_category,
                              "Menüde yeni bir kategori ya da alt kategori oluştur")
        self.btn_presets = button("Hazır Kategoriler", "folder-templates", self.on_presets,
                                  "Simgeleriyle hazır OSINT kategorilerini tek seferde oluştur")
        self.btn_edit = button("Düzenle", "document-edit", self.on_edit,
                               "Seçili öğeyi düzenle; sistemdeki kategori ve uygulamaların "
                               "adını/simgesini de değiştirebilirsiniz")
        self.btn_del = button("Sil", "edit-delete", self.on_delete,
                              "Seçili aracı veya kategoriyi sil")
        self.btn_update = button("Güncelle", "view-refresh", self.on_update,
                                 "Aracı güncelle (git pull / pipx upgrade / apt)")
        self.btn_test = button("Dene", "media-playback-start", self.on_test,
                               "Aracı menüden açılmış gibi çalıştır")

        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Ara…")
        self.search.connect("search-changed", lambda *_a: self.rebuild())
        bar.pack_end(self.search, False, False, 0)
        self.show_sys = Gtk.CheckButton(label="Sistem uygulamalarını göster")
        self.show_sys.set_active(True)
        self.show_sys.connect("toggled", lambda *_a: self.rebuild())

        # Ağaç görünümü
        self.store = Gtk.TreeStore(str, str, str, Gio.Icon, str, str, str, int, str, str)
        self.store.set_default_sort_func(self._sort_func)
        self.store.set_sort_column_id(Gtk.TREE_SORTABLE_DEFAULT_SORT_COLUMN_ID,
                                      Gtk.SortType.ASCENDING)
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_enable_tree_lines(True)
        self.tree.set_tooltip_column(C_TIP)
        self.tree.set_search_column(C_TITLE)

        col = Gtk.TreeViewColumn("Menü")
        col.set_expand(True)
        icon_cell = Gtk.CellRendererPixbuf(stock_size=Gtk.IconSize.LARGE_TOOLBAR)
        col.pack_start(icon_cell, False)
        col.add_attribute(icon_cell, "gicon", C_ICON)
        text_cell = Gtk.CellRendererText()
        col.pack_start(text_cell, True)
        col.add_attribute(text_cell, "text", C_TITLE)
        col.add_attribute(text_cell, "foreground", C_FG)
        col.add_attribute(text_cell, "weight", C_WEIGHT)
        self.tree.append_column(col)

        detail_cell = Gtk.CellRendererText(ellipsize=Pango.EllipsizeMode.END)
        col2 = Gtk.TreeViewColumn("Komut / Tür", detail_cell, text=C_DETAIL, foreground=C_FG)
        col2.set_min_width(260)
        self.tree.append_column(col2)

        sw = Gtk.ScrolledWindow()
        sw.add(self.tree)
        sw.set_vexpand(True)
        outer.pack_start(sw, True, True, 0)

        tip = Gtk.Label(xalign=0, wrap=True)
        tip.set_markup(
            "<small>💡 <b>Kalın</b> öğeler sizin eklediklerinizdir; <b>sürükleyip</b> "
            "istediğiniz kategoriye bırakabilirsiniz. Gri öğeler sistemde zaten olanlardır; "
            "<b>Düzenle</b> ile onların da adını ve simgesini değiştirebilirsiniz. "
            "Değişiklikler menüye hemen uygulanır.</small>")
        tip.set_margin_start(8)
        tip.set_margin_end(8)
        tip.set_margin_top(4)
        tip.set_margin_bottom(4)
        bottom = Gtk.Box(spacing=8)
        bottom.pack_start(tip, True, True, 0)
        self.show_sys.set_margin_end(8)
        bottom.pack_end(self.show_sys, False, False, 0)
        outer.pack_start(bottom, False, False, 0)

        self.statusbar = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.statusbar.set_margin_start(8)
        self.statusbar.set_margin_end(8)
        self.statusbar.set_margin_top(4)
        self.statusbar.set_margin_bottom(4)
        outer.pack_start(Gtk.Separator(), False, False, 0)
        outer.pack_start(self.statusbar, False, False, 0)

        self.tree.get_selection().connect("changed", lambda *_a: self._update_buttons())
        self.tree.connect("row-activated", self._on_row_activated)
        self.tree.connect("button-press-event", self._on_button_press)
        self.tree.connect("drag-data-get", self._on_drag_data_get)
        self.tree.connect("drag-data-received", self._on_drag_data_received)
        self.tree.connect("key-press-event", self._on_key)
        self._targets = [Gtk.TargetEntry.new(DND_TARGET, Gtk.TargetFlags.SAME_WIDGET, 0)]
        self.tree.enable_model_drag_source(Gdk.ModifierType.BUTTON1_MASK, self._targets,
                                           Gdk.DragAction.MOVE)
        self.tree.enable_model_drag_dest(self._targets, Gdk.DragAction.MOVE)

        self.connect("destroy", Gtk.main_quit)
        self.reload(first=True)

    # ------------------------------------------------------------------ durum
    def set_status(self, text, warn=False):
        if warn:
            self.statusbar.set_markup("<span foreground='#e5a50a'>⚠ %s</span>"
                                      % GLib.markup_escape_text(text))
        else:
            self.statusbar.set_text(text)

    def _scan(self):
        try:
            self.scan = core.scan_menu()
            self.scan_error = None
        except core.OmyError as e:
            self.scan = None
            self.scan_error = str(e)
        try:
            self.favs = core.whisker_favorites()
        except Exception:  # favoriler yalnızca bilgi amaçlı; hata önemsiz
            self.favs = []
        if self.scan_error:
            self.infobar_label.set_markup(
                "<b>Mevcut menü okunamadı.</b> Yalnızca bu araçla eklediğiniz öğeler "
                "gösteriliyor.\n%s" % GLib.markup_escape_text(self.scan_error))
            self.infobar.show()
        else:
            self.infobar.hide()

    def reload(self, first=False):
        self._scan()
        expanded = None if first else self._expanded_keys()
        self.rebuild(expanded)
        if self.scan_error:
            self.set_status(self.scan_error, warn=True)
        else:
            self.set_status("Hazır. %d araç, %d kategori yönetiliyor."
                            % (len(self.state["tools"]), len(self.state["categories"])))

    def commit(self, message, select=None):
        """Durumu kaydedip menü dosyalarını yeniden üretir."""
        try:
            warnings = core.apply(self.state)
        except (OSError, core.OmyError) as e:
            error(self, "Değişiklikler kaydedilemedi.", str(e))
            return False
        expanded = self._expanded_keys()
        self._scan()
        self.rebuild(expanded, select)
        missing = []
        if self.scan is not None:
            ids = core.collect_desktop_ids(self.scan)
            missing = [t["name"] for t in self.state["tools"]
                       if core.desktop_id(t) not in ids]
        if warnings:
            self.set_status(" | ".join(warnings), warn=True)
        elif missing:
            self.set_status("Menüde görünmeyen araçlar var: %s (kategori silinmiş veya menü "
                            "dosyanız birleştirme klasörünü okumuyor olabilir)"
                            % ", ".join(missing), warn=True)
        else:
            self.set_status(message)
        return True

    # ------------------------------------------------------------ ağaç kurma
    def _sort_func(self, model, a, b, _data=None):
        ka, kb = KIND_ORDER.get(model[a][C_KIND], 3), KIND_ORDER.get(model[b][C_KIND], 3)
        if ka != kb:
            return -1 if ka < kb else 1
        ta, tb = (model[a][C_TITLE] or "").casefold(), (model[b][C_TITLE] or "").casefold()
        return (ta > tb) - (ta < tb)

    def _build_nodes(self):
        def node(kind, ident, path, title, icon, detail, fg=None, weight=400, tip=None,
                 fallback="application-x-executable", file=None):
            return {"kind": kind, "ident": ident, "path": list(path), "title": title,
                    "icon": make_gicon(icon, fallback), "detail": detail, "fg": fg,
                    "weight": weight, "tip": tip, "children": [], "file": file}

        def custom(kind, ident):
            return " (özelleştirildi)" if core.find_override(self.state, kind, ident) else ""

        root = node("root", "", [], "Uygulama Menüsü (en üst)", "start-here-kali",
                    "Ana menü", weight=700, fallback="start-here")
        index = {"": root}
        grey = "#8a8a8a"

        def add_sys(src, parent):
            key = core.path_key(src.path)
            dir_id = os.path.basename(src.file) if src.file else ""
            n = node("menu", src.name, src.path, src.title, src.icon,
                     "Kategori" + custom("directory", dir_id),
                     tip=src.comment or None, fallback="folder", file=src.file)
            parent["children"].append(n)
            index[key] = n
            for child in src.children:
                if not child.name.startswith(core.PREFIX):
                    add_sys(child, n)
            for e in src.entries:
                if e["id"].startswith(core.PREFIX):
                    continue
                n["children"].append(node("sys", e["id"], src.path, e["title"], e["icon"],
                                          "Sistem uygulaması" + custom("app", e["id"]),
                                          fg=grey, tip=e["comment"] or e["id"],
                                          file=e.get("file")))

        if self.favs:
            favs = node("favs", "", [], "Favoriler (Whisker menü)", "starred",
                        "Whisker'ın favori listesi", weight=700, fallback="emblem-favorite",
                        tip="Whisker menüdeki “Favorites” listesi. Bir uygulamayı favorilere "
                            "eklemek için menüde sağ tıklayıp “Add to Favorites” seçin.")
            for e in self.favs:
                favs["children"].append(node("fav", e["id"], [], e["title"], e["icon"],
                                             "Favori uygulama" + custom("app", e["id"]),
                                             fg=grey, tip=e["comment"] or e["id"],
                                             file=e["file"]))
            root["children"].append(favs)

        if self.scan is not None:
            for e in self.scan.entries:
                if not e["id"].startswith(core.PREFIX):
                    root["children"].append(node("sys", e["id"], [], e["title"], e["icon"],
                                                 "Sistem uygulaması" + custom("app", e["id"]),
                                                 fg=grey, file=e.get("file")))
            for child in self.scan.children:
                if not child.name.startswith(core.PREFIX):
                    add_sys(child, root)

        def ensure(path):
            key = core.path_key(path)
            if key in index:
                return index[key]
            parent = ensure(path[:-1])
            n = node("menu", path[-1], path, "%s (menüde bulunamadı)" % path[-1], "",
                     "Bu kategori artık yok", fg="#c01c28", fallback="dialog-warning")
            parent["children"].append(n)
            index[key] = n
            return n

        for cat in sorted(self.state["categories"], key=lambda c: len(c["parent"])):
            parent = ensure(cat["parent"])
            full = core.cat_path(cat)
            n = node("cat", cat["id"], full, cat["name"], cat.get("icon"), "Kendi kategorim",
                     weight=700, tip=cat.get("comment") or None, fallback="folder")
            parent["children"].append(n)
            index[core.path_key(full)] = n

        for tool in self.state["tools"]:
            parent = ensure(tool["menu"])
            src = tool["source"]
            detail = "%s   ·   %s" % (tool["command"], SOURCE_SHORT.get(src["type"], ""))
            tip = "%s\nTerminal komutu: %s\nKaynak: %s" % (
                tool.get("comment") or tool["name"], tool["command"],
                src.get("url") or src.get("package") or src.get("dir") or "kurulu komut")
            parent["children"].append(node("tool", tool["id"], tool["menu"], tool["name"],
                                           tool.get("icon"), detail, weight=700, tip=tip,
                                           fallback="utilities-terminal"))
        return root

    def _filter(self, n, query, show_sys):
        if n["kind"] in ("sys", "fav", "favs") and not show_sys:
            return None
        text = ("%s %s" % (n["title"], n["detail"])).casefold()
        if query and query in text and n["kind"] != "root":
            if show_sys:
                return n
            kept = dict(n)
            kept["children"] = [c for c in (self._filter(c, "", False) for c in n["children"])
                                if c]
            return kept
        kids = [c for c in (self._filter(c, query, show_sys) for c in n["children"]) if c]
        if n["kind"] in ("root", "menu", "cat", "favs"):
            if kids or not query or n["kind"] == "root":
                kept = dict(n)
                kept["children"] = kids
                return kept
            return None
        return None if query else n

    def rebuild(self, expanded=None, select=None):
        if expanded is None:
            expanded = self._expanded_keys() if len(self.store) else {"root:"}
        if select is None:
            select = self._selected_key()
        query = self.search.get_text().strip().casefold()
        tree = self._filter(self._build_nodes(), query, self.show_sys.get_active())

        self.store.clear()

        def insert(n, parent_it):
            it = self.store.append(parent_it, [n["kind"], n["ident"], core.path_key(n["path"]),
                                               n["icon"], n["title"], n["detail"], n["fg"],
                                               n["weight"], n["tip"], n["file"]])
            for c in n["children"]:
                insert(c, it)

        insert(tree, None)
        # Formlardaki kategori listesi
        self.menus = self._menu_list()

        def walk(model, path, it, _d):
            key = "%s:%s" % (model[it][C_KIND], model[it][C_PATH])
            if query or key in expanded:
                self.tree.expand_to_path(path)
            if select and (model[it][C_KIND], model[it][C_IDENT]) == select:
                self.tree.expand_to_path(path)
                self.tree.get_selection().select_iter(it)
                GLib.idle_add(self._scroll_to, path.copy())
            return False

        self.store.foreach(walk, None)
        self._update_buttons()

    def _scroll_to(self, path):
        self.tree.scroll_to_cell(path, None, True, 0.4, 0)
        return False

    def _menu_list(self, tree=None):
        """Formlardaki kategori listesi: (yol, "OSINT ▸ OSINT email", simge)."""
        result = []

        def visit(n, labels):
            if n["kind"] not in ("root", "menu", "cat"):
                return
            names = labels + [n["title"]] if n["kind"] != "root" else []
            result.append((n["path"], " ▸ ".join(names) if names
                           else "Uygulama Menüsü (en üst)", n["icon"]))
            for c in sorted(n["children"], key=lambda c: c["title"].casefold()):
                visit(c, names)

        visit(self._build_nodes(), [])
        return result

    def _expanded_keys(self):
        keys = set()

        def cb(_tv, path):
            row = self.store[path]
            keys.add("%s:%s" % (row[C_KIND], row[C_PATH]))
        self.tree.map_expanded_rows(cb)
        return keys

    def _selected_key(self):
        model, it = self.tree.get_selection().get_selected()
        if it is None:
            return None
        return (model[it][C_KIND], model[it][C_IDENT])

    def _selected(self):
        model, it = self.tree.get_selection().get_selected()
        if it is None:
            return None
        return model[it]

    def _menu_path_of(self, row):
        """Satırın bulunduğu (ya da kendisi olan) menünün yolu."""
        if row is None:
            return None
        path = row[C_PATH].split("/") if row[C_PATH] else []
        return path

    def _update_buttons(self):
        row = self._selected()
        kind = row[C_KIND] if row else None
        self.btn_edit.set_sensitive(kind in ("tool", "cat", "menu", "sys", "fav"))
        self.btn_del.set_sensitive(kind in ("tool", "cat"))
        tool = core.find_tool(self.state, row[C_IDENT]) if kind == "tool" else None
        self.btn_update.set_sensitive(bool(tool) and tool["source"]["type"] != "existing")
        self.btn_test.set_sensitive(kind in ("tool", "sys", "fav"))

    # -------------------------------------------------------------- olaylar
    def _on_row_activated(self, tree, path, _col):
        kind = self.store[path][C_KIND]
        if kind in ("tool", "cat", "sys", "fav"):
            self.on_edit()
        elif tree.row_expanded(path):
            tree.collapse_row(path)
        else:
            tree.expand_row(path, False)

    def _on_key(self, _w, event):
        if event.keyval == Gdk.KEY_Delete:
            self.on_delete()
            return True
        if event.keyval == Gdk.KEY_F2:
            self.on_edit()
            return True
        return False

    def _on_button_press(self, tree, event):
        hit = tree.get_path_at_pos(int(event.x), int(event.y))
        kind = self.store[hit[0]][C_KIND] if hit else None
        # Yalnızca kendi araç ve kategorilerimiz sürüklenebilir.
        if kind in ("tool", "cat"):
            tree.enable_model_drag_source(Gdk.ModifierType.BUTTON1_MASK, self._targets,
                                          Gdk.DragAction.MOVE)
        else:
            tree.unset_rows_drag_source()
        if event.button == 3 and event.type == Gdk.EventType.BUTTON_PRESS:
            if hit:
                tree.get_selection().select_path(hit[0])
            self._popup(event)
            return True
        return False

    def _popup(self, event):
        row = self._selected()
        kind = row[C_KIND] if row else None
        menu = Gtk.Menu()

        def item(label, cb, sensitive=True):
            mi = Gtk.MenuItem(label=label)
            mi.set_sensitive(sensitive)
            mi.connect("activate", lambda *_a: cb())
            menu.append(mi)

        item("Buraya araç ekle…", self.on_add_tool)
        item("Buraya alt kategori oluştur…", self.on_add_category)
        item("Buraya hazır OSINT kategorileri ekle…", self.on_presets)
        menu.append(Gtk.SeparatorMenuItem())
        item("Düzenle…" if kind in ("tool", "cat", None, "root") else "Adını / simgesini değiştir…",
             self.on_edit, kind in ("tool", "cat", "menu", "sys", "fav"))
        item("Sil", self.on_delete, kind in ("tool", "cat"))
        tool = core.find_tool(self.state, row[C_IDENT]) if kind == "tool" else None
        item("Güncelle", self.on_update, bool(tool) and tool["source"]["type"] != "existing")
        item("Dene (çalıştır)", self.on_test, kind in ("tool", "sys", "fav"))
        if tool and tool["source"].get("dir"):
            item("Klasörü aç", lambda: self._open_folder(tool["source"]["dir"]))
        menu.show_all()
        menu.popup_at_pointer(event)

    def _open_folder(self, path):
        try:
            Gio.AppInfo.launch_default_for_uri(Gio.File.new_for_path(path).get_uri(), None)
        except GLib.Error as e:
            error(self, "Klasör açılamadı.", e.message)

    # --- sürükle bırak
    def _on_drag_data_get(self, tree, _ctx, data, _info, _time):
        row = self._selected()
        if row is None:
            return
        payload = "%s\n%s" % (row[C_KIND], row[C_IDENT])
        data.set(data.get_target(), 8, payload.encode("utf-8"))

    def _on_drag_data_received(self, tree, ctx, x, y, data, _info, time):
        tree.stop_emission_by_name("drag-data-received")
        ok = False
        try:
            raw = data.get_data()
            kind, ident = bytes(raw).decode("utf-8").split("\n", 1) if raw else ("", "")
            dest = tree.get_dest_row_at_pos(x, y)
            if dest is not None and kind in ("tool", "cat") and \
                    self.store[dest[0]][C_KIND] not in ("favs", "fav"):
                path, pos = dest
                row = self.store[path]
                target = self._menu_path_of(row)
                if row[C_KIND] in ("root", "menu", "cat") and \
                        pos in (Gtk.TreeViewDropPosition.BEFORE,
                                Gtk.TreeViewDropPosition.AFTER) and row[C_KIND] != "root":
                    target = target[:-1]
                ok = True
                GLib.idle_add(self._do_move, kind, ident, target)
        finally:
            Gtk.drag_finish(ctx, ok, False, time)

    def _do_move(self, kind, ident, target):
        if kind == "tool":
            tool = core.find_tool(self.state, ident)
            if tool is None:
                return False
            if not target:
                self.set_status("Araçlar en üst seviyeye değil, bir kategoriye bırakılmalı.",
                                warn=True)
                return False
            if tool["menu"] == target:
                return False
            tool["menu"] = list(target)
            self.commit("“%s” taşındı." % tool["name"], select=("tool", ident))
        else:
            cat = core.find_cat(self.state, ident)
            if cat is None or cat["parent"] == target:
                return False
            try:
                core.move_category(self.state, cat, target)
            except core.OmyError as e:
                self.set_status(str(e), warn=True)
                return False
            self.commit("“%s” kategorisi taşındı." % cat["name"], select=("cat", ident))
        return False

    # -------------------------------------------------------------- eylemler
    def _current_menu_path(self):
        row = self._selected()
        if row is None:
            return None
        return self._menu_path_of(row)

    def on_add_tool(self):
        dlg = ToolDialog(self, self.menus, menu_path=self._current_menu_path())
        while True:
            if dlg.run() != Gtk.ResponseType.OK:
                dlg.destroy()
                return
            v = dlg.values()
            problem = self._validate_tool(v, None)
            if problem is None:
                break
        dlg.destroy()
        self._install_and_add(v)

    def _validate_tool(self, v, tool):
        if not v["name"]:
            error(self, "Lütfen bir ad yazın.")
            return True
        if not tool and not v["source"]:
            error(self, "Lütfen kaynağı (adres, klasör veya paket adı) yazın.")
            return True
        if v["menu"] is None:
            error(self, "Lütfen bir kategori seçin.",
                  "Listede kategori yoksa önce “Kategori Oluştur” ile bir tane oluşturun.")
            return True
        try:
            core.split_args(v["args"])
        except core.OmyError as e:
            error(self, str(e))
            return True
        if v["type"] in core.SOURCES_WITH_WRAPPER:
            err, warn = core.command_conflict(v["command"], tool["id"] if tool else None,
                                              self.state)
            if err:
                error(self, "Bu komut adı kullanılamıyor.", err)
                return True
            if warn and (not tool or tool["command"] != v["command"]) and \
                    not ask(self, "Aynı adlı bir komut zaten var. Devam edilsin mi?", warn):
                return True
        elif not v["command"] or " " in v["command"]:
            error(self, "Lütfen terminal komutunu (boşluksuz) yazın.")
            return True
        if v["type"] == "local" and not tool and \
                not os.path.exists(os.path.expanduser(v["source"])):
            error(self, "Seçilen konum bulunamadı.", v["source"])
            return True
        return None

    def _install_and_add(self, v):
        tool_id = core.new_tool_id(self.state, v["command"] or v["name"])
        src = {"type": v["type"]}
        t = v["type"]
        if t == "git":
            dlg = TaskDialog(self, "%s indiriliyor" % v["name"])
            ok, res = dlg.execute(core.install_git, v["source"], tool_id, v["command"])
            if not ok:
                return
            src.update({"url": v["source"], "dir": res["dir"], "runner": "auto",
                        "cd": True})
        elif t == "local":
            dlg = TaskDialog(self, "%s kopyalanıyor" % v["name"])
            ok, res = dlg.execute(core.install_local, v["source"], tool_id, v["command"])
            if not ok:
                return
            src.update({"path": v["source"], "dir": res["dir"], "runner": "auto",
                        "cd": True, "entry": res.get("entry", "")})
        elif t == "pipx":
            dlg = TaskDialog(self, "%s kuruluyor (pipx)" % v["name"])
            ok, res = dlg.execute(core.install_pipx, v["source"])
            if not ok:
                return
            src["package"] = res["package"]
            src["url"] = v["source"]
            if res["apps"] and v["command"] not in res["apps"]:
                v["command"] = res["apps"][0]
                info(self, "Komut adı “%s” olarak ayarlandı." % v["command"],
                     "pipx paketinin sağladığı komut(lar): %s" % ", ".join(res["apps"]))
        elif t == "apt":
            dlg = TaskDialog(self, "%s kuruluyor (APT)" % v["name"])
            ok, res = dlg.execute(core.install_apt, v["source"])
            if not ok:
                return
            src["package"] = res["package"]
        else:
            import shutil
            found = shutil.which(v["command"])
            if not found and not ask(self, "“%s” komutu bulunamadı." % v["command"],
                                     "Yine de menüye eklensin mi?"):
                return
            if found and found.startswith(("/home/", "/root/")) and not ask(
                    self, "Bu komut yalnızca bir kullanıcının ev klasöründe kurulu.",
                    "%s\n\nISO'daki diğer kullanıcılarda çalışmayabilir. Sistem geneline "
                    "kurmak için kaynak türü olarak “pipx paketi”ni seçmeniz önerilir. "
                    "Yine de eklensin mi?" % found):
                return

        tool = {"id": tool_id, "name": v["name"], "command": v["command"],
                "args": v["args"], "comment": v["comment"], "icon": "",
                "menu": v["menu"], "terminal": v["terminal"], "source": src}

        if t in core.SOURCES_WITH_WRAPPER:
            edlg = EntryDialog(self, tool, warn=not res.get("deps_ok", True), icon=v["icon"])
            while True:
                resp = edlg.run()
                if resp != Gtk.ResponseType.OK:
                    edlg.destroy()
                    if ask(self, "Araç eklenmedi. İndirilen dosyalar silinsin mi?",
                           src["dir"]):
                        core.uninstall_tool(tool, True)
                    return
                edlg.panel.apply_to(src)
                v["icon"] = edlg.icon_picker.get()
                if not src["entry"]:
                    error(self, "Lütfen çalıştırılacak dosyayı seçin.")
                    continue
                if not src["entry"].startswith("venv:") and not os.path.exists(
                        os.path.join(core.sys_path(src["dir"]), src["entry"])):
                    error(self, "Dosya bulunamadı.", src["entry"])
                    continue
                break
            edlg.destroy()

        if not v["icon"]:
            theme = Gtk.IconTheme.get_default()
            for cand in ("kali-" + v["command"], v["command"], "kali-" + core.slugify(v["name"])):
                if cand and theme.has_icon(cand):
                    v["icon"] = cand
                    break
        try:
            tool["icon"] = core.store_icon(v["icon"], "arac-" + tool_id)
        except (OSError, core.OmyError) as e:
            error(self, "Simge kopyalanamadı; varsayılan simge kullanılacak.", str(e))
        self.state["tools"].append(tool)
        if self.commit("“%s” eklendi." % tool["name"], select=("tool", tool_id)) and \
                t in core.SOURCES_WITH_WRAPPER:
            info(self, "“%s” hazır!" % tool["name"],
                 "Menüde seçtiğiniz kategoride görünecek. Terminalde şu komutla da "
                 "çalıştırabilirsiniz:\n\n    %s -h" % tool["command"])

    def on_add_category(self):
        dlg = CategoryDialog(self, self.menus, parent_path=self._current_menu_path())
        while True:
            if dlg.run() != Gtk.ResponseType.OK:
                dlg.destroy()
                return
            v = dlg.values()
            if not v["name"]:
                error(self, "Lütfen kategori adını yazın.")
                continue
            if v["parent"] is None:
                error(self, "Lütfen kategorinin yerini seçin.")
                continue
            break
        dlg.destroy()
        cat = {"id": core.new_category_id(self.state, v["name"]), "name": v["name"],
               "comment": v["comment"], "icon": "", "parent": v["parent"]}
        try:
            cat["icon"] = core.store_icon(v["icon"], "kategori-" + cat["id"])
        except (OSError, core.OmyError) as e:
            error(self, "Simge kopyalanamadı; varsayılan simge kullanılacak.", str(e))
        self.state["categories"].append(cat)
        self.commit("“%s” kategorisi oluşturuldu. Boş kategoriler menüde içine araç "
                    "ekleyince görünür." % cat["name"], select=("cat", cat["id"]))

    def on_edit(self):
        row = self._selected()
        if row is None:
            return
        if row[C_KIND] == "tool":
            self._edit_tool(core.find_tool(self.state, row[C_IDENT]))
        elif row[C_KIND] == "cat":
            self._edit_cat(core.find_cat(self.state, row[C_IDENT]))
        elif row[C_KIND] in ("menu", "sys", "fav"):
            self._edit_system(row)

    def _edit_system(self, row):
        kind = "directory" if row[C_KIND] == "menu" else "app"
        file = row[C_FILE]
        if not file:
            error(self, "Bu kategori özelleştirilemiyor.",
                  "Kategorinin bir tanım (.directory) dosyası yok.")
            return
        ident = os.path.basename(file) if kind == "directory" else row[C_IDENT]
        ov = core.find_override(self.state, kind, ident)
        current_icon = self._row_icon(row)
        dlg = SystemItemDialog(self, "Kategori" if kind == "directory" else "Uygulama",
                               row[C_TITLE], current_icon, ov is not None)
        resp = dlg.run()
        name, icon = dlg.name_entry.get_text().strip(), dlg.icon_picker.get()
        dlg.destroy()
        select = (row[C_KIND], row[C_IDENT])
        try:
            if resp == SystemItemDialog.RESP_RESET and ov is not None:
                core.remove_override(self.state, ov)
                self.commit("“%s” varsayılana döndürüldü." % row[C_TITLE], select=select)
                return
            if resp != Gtk.ResponseType.OK:
                return
            if name == row[C_TITLE] and icon == current_icon:
                return
            if icon and os.path.isabs(icon):
                icon = core.store_icon(icon, "ozel-" + core.slugify(ident))
            core.set_override(self.state, kind, ident, file,
                              name if name != row[C_TITLE] or (ov and ov.get("name")) else "",
                              icon if icon != current_icon or (ov and ov.get("icon")) else "")
        except (OSError, core.OmyError) as e:
            error(self, "Değiştirilemedi.", str(e))
            return
        self.commit("“%s” güncellendi." % (name or row[C_TITLE]), select=select)

    def _row_icon(self, row):
        """Satırdaki öğenin dosyada yazan simge değeri."""
        if row[C_KIND] == "fav":
            return next((e["icon"] for e in self.favs if e["id"] == row[C_IDENT]), "")
        if self.scan is None:
            return ""
        path = row[C_PATH].split("/") if row[C_PATH] else []
        node = self.scan
        for name in path:
            node = next((c for c in node.children if c.name == name), None)
            if node is None:
                return ""
        if row[C_KIND] == "menu":
            return node.icon
        for e in node.entries:
            if e["id"] == row[C_IDENT]:
                return e["icon"]
        return ""

    def on_presets(self):
        def existing(path):
            names = set()
            for c in self.state["categories"]:
                if c["parent"] == list(path):
                    names.add(c["name"].casefold())
            node = self.scan
            for name in path:
                node = next((c for c in node.children if c.name == name), None) if node else None
            if node is not None:
                names |= {c.title.casefold() for c in node.children}
            return names

        default = None
        for p, label, _icon in self.menus:
            if len(p) == 1 and label.strip().casefold() == "osint":
                default = p
        sel = self._current_menu_path()
        dlg = PresetsDialog(self, self.menus, sel if sel else default, existing)
        while True:
            if dlg.run() != Gtk.ResponseType.OK:
                dlg.destroy()
                return
            parent, chosen = dlg.values()
            if parent is None:
                error(self, "Lütfen kategorilerin yerini seçin.")
                continue
            if not chosen:
                error(self, "Hiç kategori seçmediniz.")
                continue
            break
        dlg.destroy()
        last = None
        for name, icon, comment in chosen:
            cat = {"id": core.new_category_id(self.state, name), "name": name,
                   "comment": comment, "icon": core.pack_icon(icon), "parent": list(parent)}
            self.state["categories"].append(cat)
            last = cat["id"]
        self.commit("%d kategori oluşturuldu. Boş kategoriler menüde içine araç ekleyince "
                    "görünür." % len(chosen), select=("cat", last))

    def _edit_tool(self, tool):
        if tool is None:
            return
        dlg = ToolDialog(self, self.menus, tool=tool)
        while True:
            if dlg.run() != Gtk.ResponseType.OK:
                dlg.destroy()
                return
            v = dlg.values()
            if self._validate_tool(v, tool) is not None:
                continue
            if dlg.entry_panel is not None:
                entry = dlg.entry_panel.get_entry()
                if not entry:
                    error(self, "Lütfen çalıştırılacak dosyayı seçin.")
                    continue
                if not entry.startswith("venv:") and not os.path.exists(
                        os.path.join(core.sys_path(tool["source"]["dir"]), entry)):
                    error(self, "Dosya bulunamadı.", entry)
                    continue
            break
        if dlg.entry_panel is not None:
            dlg.entry_panel.apply_to(tool["source"])
        dlg.destroy()
        if v["icon"] != tool.get("icon"):
            old = tool.get("icon")
            try:
                tool["icon"] = core.store_icon(v["icon"], "arac-" + tool["id"])
                if old != tool["icon"] and old and v["icon"] == "":
                    core.remove_icon(old)
            except (OSError, core.OmyError) as e:
                error(self, "Simge kopyalanamadı.", str(e))
        for key in ("name", "command", "args", "comment", "menu", "terminal"):
            tool[key] = v[key]
        self.commit("“%s” güncellendi." % tool["name"], select=("tool", tool["id"]))

    def _edit_cat(self, cat):
        if cat is None:
            return
        dlg = CategoryDialog(self, self.menus, cat=cat)
        while True:
            if dlg.run() != Gtk.ResponseType.OK:
                dlg.destroy()
                return
            v = dlg.values()
            if not v["name"]:
                error(self, "Lütfen kategori adını yazın.")
                continue
            if v["parent"] is None:
                error(self, "Lütfen kategorinin yerini seçin.")
                continue
            break
        dlg.destroy()
        try:
            if v["parent"] != cat["parent"]:
                core.move_category(self.state, cat, v["parent"])
            if v["icon"] != cat.get("icon"):
                cat["icon"] = core.store_icon(v["icon"], "kategori-" + cat["id"])
        except (OSError, core.OmyError) as e:
            error(self, "Kategori güncellenemedi.", str(e))
            return
        cat["name"], cat["comment"] = v["name"], v["comment"]
        self.commit("“%s” kategorisi güncellendi." % cat["name"], select=("cat", cat["id"]))

    def on_delete(self):
        row = self._selected()
        if row is None:
            return
        if row[C_KIND] == "tool":
            self._delete_tool(core.find_tool(self.state, row[C_IDENT]))
        elif row[C_KIND] == "cat":
            self._delete_cat(core.find_cat(self.state, row[C_IDENT]))

    def _delete_tool(self, tool):
        if tool is None:
            return
        src = tool["source"]
        dlg = Gtk.MessageDialog(transient_for=self, modal=True,
                                message_type=Gtk.MessageType.QUESTION,
                                buttons=Gtk.ButtonsType.NONE,
                                text="“%s” silinsin mi?" % tool["name"])
        check = None
        if src["type"] in core.SOURCES_WITH_WRAPPER:
            dlg.format_secondary_text("Menü kaydı ve “%s” terminal komutu kaldırılacak."
                                      % tool["command"])
            check = Gtk.CheckButton(label="İndirilen dosyaları da sil (%s)" % src["dir"])
            check.set_active(True)
        elif src["type"] == "pipx":
            dlg.format_secondary_text("Menü kaydı kaldırılacak.")
            check = Gtk.CheckButton(label="pipx paketini de kaldır (%s)" % src.get("package"))
            check.set_active(True)
        else:
            dlg.format_secondary_text("Yalnızca menü kaydı kaldırılacak; kurulu program "
                                      "sistemde kalır.")
        if check is not None:
            dlg.get_message_area().pack_start(check, False, False, 0)
            check.show()
        dlg.add_buttons("İptal", Gtk.ResponseType.CANCEL, "Sil", Gtk.ResponseType.OK)
        dlg.get_widget_for_response(Gtk.ResponseType.OK).get_style_context() \
            .add_class("destructive-action")
        resp = dlg.run()
        remove_files = bool(check and check.get_active())
        dlg.destroy()
        if resp != Gtk.ResponseType.OK:
            return
        self.state["tools"].remove(tool)
        try:
            if src["type"] == "pipx" and remove_files:
                TaskDialog(self, "pipx paketi kaldırılıyor").execute(
                    lambda log: core.uninstall_tool(tool, True, log))
            else:
                core.uninstall_tool(tool, remove_files)
        except OSError as e:
            error(self, "Bazı dosyalar silinemedi.", str(e))
        self.commit("“%s” silindi." % tool["name"])

    def _delete_cat(self, cat):
        if cat is None:
            return
        tools, cats = core.category_contents(self.state, cat)
        if tools or cats:
            sec = ("İçindeki %d araç ve %d alt kategori bir üst menüye taşınacak."
                   % (len(tools), len(cats)))
        else:
            sec = "Kategori boş."
        if not ask(self, "“%s” kategorisi silinsin mi?" % cat["name"], sec):
            return
        core.remove_category(self.state, cat)
        core.remove_icon(cat.get("icon"))
        self.commit("“%s” kategorisi silindi." % cat["name"])

    def on_update(self):
        row = self._selected()
        if row is None or row[C_KIND] != "tool":
            return
        tool = core.find_tool(self.state, row[C_IDENT])
        if tool is None or tool["source"]["type"] == "existing":
            return
        ok, _ = TaskDialog(self, "%s güncelleniyor" % tool["name"]).execute(
            core.update_tool, tool)
        if ok:
            self.commit("“%s” güncellendi." % tool["name"], select=("tool", tool["id"]))

    def on_test(self):
        row = self._selected()
        if row is None or row[C_KIND] not in ("tool", "sys", "fav"):
            return
        desktop = core.desktop_id(core.find_tool(self.state, row[C_IDENT])) \
            if row[C_KIND] == "tool" else row[C_IDENT]
        app = None
        for d in [core.sys_path(core.APPS_DIR)] + \
                [os.path.join(x, "applications") for x in
                 os.environ.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share").split(":")]:
            p = os.path.join(d, desktop)
            if os.path.isfile(p):
                app = Gio.DesktopAppInfo.new_from_filename(p)
                break
        if app is None:
            app = Gio.DesktopAppInfo.new(desktop)
        if app is None:
            error(self, "Uygulama dosyası bulunamadı.", desktop)
            return
        try:
            app.launch([], None)
            self.set_status("“%s” başlatıldı." % row[C_TITLE])
        except GLib.Error as e:
            error(self, "Uygulama başlatılamadı.", e.message)


def main():
    if os.environ.get("OMY_ICON_THEME"):
        Gtk.Settings.get_default().set_property("gtk-icon-theme-name",
                                                os.environ["OMY_ICON_THEME"])
    if os.geteuid() != 0 and "OMY_ROOT" not in os.environ:
        error(None, "Yönetici yetkisi gerekli",
              "OSINT Menü Yöneticisi sistem menüsünü ve /usr/local/bin klasörünü "
              "düzenlediği için root olarak çalışmalıdır.\n\nTerminalden şöyle açın:\n"
              "    sudo osint-menu-yonetici")
        return 1
    try:
        win = MainWindow()
    except core.OmyError as e:
        error(None, "Başlatılamadı", str(e))
        return 1
    win.set_title("%s %s" % (APP_TITLE, __version__))
    win.show_all()
    Gtk.main()
    return 0
