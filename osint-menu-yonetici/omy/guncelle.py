# -*- coding: utf-8 -*-
"""Menüde zaten olan (bu uygulamayla eklenmemiş) araçları güvenli şekilde
günceller.

- Git deposundan kurulanlar: `git pull --ff-only` (yerel değişiklik varsa
  dokunulmaz). requirements.txt değiştiyse ve depoda sanal ortam varsa
  bağımlılıklar yenilenir.
- pipx ile kurulanlar: `pipx upgrade`.
- APT paketlerine dokunulmaz (sistem güncellemesiyle güncellenirler).

Kullanıcının ev klasöründeki araçlar o kullanıcı olarak güncellenir; dosya
sahiplikleri bozulmaz. Her güncellemenin eski/yeni sürümü
/var/log/osint-menu-yonetici/guncelleme.log dosyasına yazılır; geri dönmek
için orada yazan `git -C <klasör> reset --hard <eski>` komutu kullanılabilir.
"""

import datetime
import os
import pwd
import shlex
import shutil
import subprocess

from . import core, xdgmenu

LOG_FILE = "/var/log/osint-menu-yonetici/guncelleme.log"
_WRAPPERS = {"sh", "bash", "zsh", "env", "exec", "sudo", "pkexec", "x-terminal-emulator",
             "xfce4-terminal", "qterminal", "gnome-terminal", "exec-in-shell", "python",
             "python3", "perl", "ruby", "node", "java", "-c", "-e", "-x", "--"}


def _owner(path):
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except (KeyError, OSError):
        return "root"


def _as_owner(path, argv):
    """Komutu, path'in sahibi olan kullanıcı olarak çalıştıracak argv."""
    owner = _owner(path)
    if owner == "root" or os.geteuid() != 0:
        return argv
    return ["runuser", "-u", owner, "--"] + argv


def _search_path():
    dirs = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin").split(":")
    home = core.real_user_home()
    if home:
        dirs.insert(0, os.path.join(home, ".local", "bin"))
    return ":".join(dirs)


def exec_candidates(exec_line):
    """Exec satırındaki olası program yollarını çıkarır."""
    try:
        tokens = shlex.split(exec_line.replace("%%", "%"))
    except ValueError:
        tokens = exec_line.split()
    found, queue = [], list(tokens)
    while queue:
        tok = queue.pop(0)
        if tok.startswith("%") or not tok:
            continue
        if " " in tok or ";" in tok or "&&" in tok:
            # sh -c "araç -h; bash" gibi iç içe komutlar
            for part in tok.replace("&&", ";").split(";"):
                try:
                    queue[0:0] = shlex.split(part)
                except ValueError:
                    pass
            continue
        base = os.path.basename(tok)
        if base in _WRAPPERS or tok.startswith("-") or "=" in tok:
            continue
        if os.path.isabs(tok):
            if os.path.exists(tok):
                found.append(tok)
            continue
        resolved = shutil.which(tok, path=_search_path())
        if resolved:
            found.append(resolved)
    return found


_NOT_TOOL_ROOTS = {"/", "/root", "/home", "/opt", "/usr", "/usr/local", "/usr/share", "/etc",
                   "/var", "/srv", "/tmp"}


def _git_root(path):
    """Aracın git deposunun kökü. Ev klasörünün kendisi gibi aracın kendisi
    olamayacak depolar (ör. dotfiles) hiçbir zaman döndürülmez."""
    d = path if os.path.isdir(path) else os.path.dirname(path)
    homes = {pw.pw_dir.rstrip("/") for pw in pwd.getpwall()}
    while d and d != "/":
        if os.path.isdir(os.path.join(d, ".git")):
            if d in _NOT_TOOL_ROOTS or d.rstrip("/") in homes:
                return None
            return d
        d = os.path.dirname(d)
    return None


def _pipx_venv(path):
    parts = path.split(os.sep)
    if "venvs" in parts:
        i = parts.index("venvs")
        if i >= 1 and i + 1 < len(parts) and "pipx" in parts[i - 1]:
            return os.sep.join(parts[:i]), parts[i + 1]
    return None


def _dpkg_owned(path):
    try:
        r = subprocess.run(["dpkg", "-S", path], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def classify(path):
    """("git", kök) | ("pipx", (pipx_home, paket)) | ("apt", paket_yolu) | (None, path)"""
    real = os.path.realpath(path)
    pv = _pipx_venv(real)
    if pv:
        return "pipx", pv
    # Wrapper betiği: içinde başka bir yolu çağırıyor olabilir (ör. bizim
    # sarmalayıcılarımız ya da elle yazılmış 'cd /opt/x && python3 x.py')
    root = _git_root(real)
    if root:
        return "git", root
    if _dpkg_owned(real) or _dpkg_owned(path):
        return "apt", path
    try:
        if os.path.getsize(real) < 4096:
            with open(real, encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for tok in shlex.split(text, comments=True, posix=True):
                if os.path.isabs(tok) and os.path.exists(tok) and tok != real:
                    sub = _git_root(os.path.realpath(tok))
                    if sub:
                        return "git", sub
                    pv = _pipx_venv(os.path.realpath(tok))
                    if pv:
                        return "pipx", pv
    except (OSError, ValueError):
        pass
    return None, path


def _log_line(text):
    path = core.sys_path(LOG_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write("%s  %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), text))


def _git(root, args, log, capture=False):
    argv = _as_owner(root, ["git", "-c", "safe.directory=*", "-C", root] + args)
    if capture:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout.strip()
    return core.run_cmd(argv, log), ""


_BROKEN_MARKERS = ("Traceback (most recent call last)", "ModuleNotFoundError", "ImportError",
                   "SyntaxError", "No such file or directory")


def smoke_test(cmd):
    """Aracı yardım parametresiyle kısa süre çalıştırır. Python/dosya hatası
    görülürse False döner (zaman aşımı ya da etkileşimli bekleme sorun sayılmaz)."""
    if not cmd:
        return True
    try:
        r = subprocess.run(cmd + ["-h"], capture_output=True, text=True, timeout=40,
                           stdin=subprocess.DEVNULL, env=dict(os.environ, TERM="dumb"))
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return True
    except OSError:
        return False
    return not any(m in out for m in _BROKEN_MARKERS)


def update_git(root, log, test_cmd=None):
    rc, before = _git(root, ["rev-parse", "HEAD"], log, capture=True)
    if rc != 0:
        log("  ! git deposu okunamadı, atlandı.\n")
        return "atlandı"
    rc, dirty = _git(root, ["status", "--porcelain", "--untracked-files=no"], log, capture=True)
    if dirty:
        log("  ! Klasörde elle yapılmış değişiklikler var; bozmamak için güncellenmedi.\n")
        return "atlandı (yerel değişiklik)"
    if _git(root, ["pull", "--ff-only"], log)[0] != 0:
        log("  ! git pull başarısız; araç olduğu gibi bırakıldı.\n")
        return "hata"
    _rc, after = _git(root, ["rev-parse", "HEAD"], log, capture=True)
    if after == before:
        return "zaten güncel"
    # Güncel sürüm çalışmıyorsa (ör. yeni bağımlılık istiyorsa) eski sürüme dön
    if test_cmd and not smoke_test(test_cmd) and _was_working(root, before, test_cmd, log):
        _git(root, ["reset", "-q", "--hard", before], log)
        log("  ! Yeni sürüm bu sistemde çalışmadı; eski sürüme geri dönüldü.\n")
        _log_line("git %s  %s -> %s denendi, çalışmadığı için geri alındı"
                  % (root, before[:12], after[:12]))
        return "yeni sürüm çalışmadı, eski sürümde bırakıldı"
    _log_line("git %s  %s -> %s   (geri almak için: git -C %s reset --hard %s)"
              % (root, before[:12], after[:12], shlex.quote(root), before[:12]))
    _rc, changed = _git(root, ["diff", "--name-only", before, after], log, capture=True)
    venv_pip = None
    for v in (".venv", "venv", "env"):
        p = os.path.join(root, v, "bin", "pip")
        if os.path.exists(p):
            venv_pip = p
    if venv_pip and "requirements.txt" in changed.split("\n"):
        log("  > requirements.txt değişti, bağımlılıklar yenileniyor\n")
        core.run_cmd(_as_owner(root, [venv_pip, "install", "-r",
                                      os.path.join(root, "requirements.txt")]), log)
    return "güncellendi (%s → %s)" % (before[:7], after[:7])


def _was_working(root, before, test_cmd, log):
    """Eski sürüm çalışıyor muydu? (Zaten bozuksa geri dönmenin anlamı yok.)"""
    _rc, now = _git(root, ["rev-parse", "HEAD"], log, capture=True)
    _git(root, ["reset", "-q", "--hard", before], log)
    ok = smoke_test(test_cmd)
    _git(root, ["reset", "-q", "--hard", now], log)
    return ok


def update_pipx(pipx_home, package, log):
    env = {"PIPX_HOME": pipx_home}
    if pipx_home.startswith("/opt/"):
        env.update({"PIPX_BIN_DIR": core.BIN_DIR, "PIPX_MAN_DIR": "/usr/local/share/man"})
    else:
        home = os.path.dirname(os.path.dirname(os.path.dirname(pipx_home))) \
            if pipx_home.endswith("/.local/share/pipx") else None
        if home:
            env["PIPX_BIN_DIR"] = os.path.join(home, ".local", "bin")
    owner_argv = _as_owner(pipx_home, ["env"] + ["%s=%s" % kv for kv in env.items()] +
                           ["pipx", "upgrade", package])
    if core.run_cmd(owner_argv, log) != 0:
        return "hata"
    _log_line("pipx %s (%s) yükseltildi" % (package, pipx_home))
    return "güncellendi"


def run(menu_specs, log, find_menu):
    """menu_specs: güncellenecek kategoriler ("hepsi" = bütün menü).
    find_menu: başlıktan menü yolunu bulan fonksiyon."""
    tree = core.scan_menu()

    def node_at(path):
        n = tree
        for name in path:
            n = next((c for c in n.children if c.name == name), None)
            if n is None:
                return None
        return n

    roots = []
    for spec in menu_specs:
        if spec.strip().lower() in ("hepsi", "all", "*"):
            roots = [tree]
            break
        path, err = find_menu(spec)
        if err or path is None:
            log("  ! Kategori bulunamadı: %s\n" % spec)
            continue
        n = node_at(path)
        if n is not None:
            roots.append(n)

    entries = []

    def collect(n):
        for e in n.entries:
            if not e["id"].startswith(core.PREFIX):
                entries.append(e)
        for c in n.children:
            collect(c)
    for r in roots:
        collect(r)

    done, results = set(), []
    for e in entries:
        de = xdgmenu.load_entry(e["file"]) if e.get("file") else None
        exec_line = de.get("Exec") if de else ""
        cands = exec_candidates(exec_line)
        kinds = [classify(p) for p in cands]
        kind = next((k for k in kinds if k[0] in ("git", "pipx")), None) or \
            next((k for k in kinds if k[0] == "apt"), None) or (None, None)
        key = (kind[0], str(kind[1]))
        if kind[0] in ("git", "pipx") and key in done:
            continue
        done.add(key)
        log("\n--- %s ---\n" % e["title"])
        if kind[0] == "git":
            log("  GitHub deposu: %s\n" % kind[1])
            test = [next((p for p in cands if classify(p) == kind), cands[0])] if cands else None
            status = update_git(kind[1], log, test)
        elif kind[0] == "pipx":
            log("  pipx paketi: %s\n" % kind[1][1])
            status = update_pipx(kind[1][0], kind[1][1], log)
        elif kind[0] == "apt":
            status = "APT paketi (sistem güncellemesiyle güncellenir)"
        else:
            status = "kurulum yöntemi anlaşılamadı, dokunulmadı"
        log("  → %s\n" % status)
        results.append((e["title"], status))
    return results
