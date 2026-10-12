#!/usr/bin/env python3
"""BGShare for Windows - peer-to-peer desktop app.

Every installed PC is an equal peer. This file adds the desktop parts around bgshare_peer.Peer:
* a pywebview (Edge WebView2) window showing the local UI at http://127.0.0.1:8890/
* a tray icon (Open / Start with Windows / Notifications / Quit); closing the window hides it to the tray
* native Windows toasts for incoming files and snippets (transfers are accepted automatically)
* native folder picker (Settings), native clipboard copy
* a log file at %APPDATA%\\BGShare\\bgshare.log with an exception hook
Any BGShare PC on the same network is treated as a teammate. Traffic between PCs is plain HTTP and is not encrypted.
"""
import argparse, logging, os, socket, sys, threading, time

import bgshare_peer as bp

APP = bp.APP
log = logging.getLogger("bgshare.desktop")

def resource(name):
    for base in (getattr(sys, "_MEIPASS", None), os.path.dirname(os.path.abspath(sys.executable)) if getattr(sys, "frozen", False) else None,
                 os.path.dirname(os.path.abspath(__file__))):
        if base and os.path.exists(os.path.join(base, name)): return os.path.join(base, name)
    return None

class _LogStream:
    """Windowed builds have no console: send print()/stderr output to the log."""
    def __init__(self, level): self.level = level; self.buf = ""
    def write(self, s):
        self.buf += s
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            if line.strip(): logging.getLogger("bgshare.stdio").log(self.level, line)
    def flush(self): pass
    def isatty(self): return False

# ---------------------------------------------------------------- Windows integration
def autostart_cmd():
    if getattr(sys, "frozen", False): return f'"{sys.executable}" --minimized'
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return f'"{pyw if os.path.exists(pyw) else sys.executable}" "{os.path.abspath(__file__)}" --minimized'

def get_autostart():
    if os.name != "nt": return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
            winreg.QueryValueEx(k, APP); return True
    except OSError:
        return False

def set_autostart(on):
    if os.name != "nt": return False
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as k:
        if on: winreg.SetValueEx(k, APP, 0, winreg.REG_SZ, autostart_cmd())
        else:
            try: winreg.DeleteValue(k, APP)
            except FileNotFoundError: pass
    return True

_mutex = None
def single_instance():
    """False if BGShare is already running for this user (named mutex)."""
    global _mutex
    if os.name != "nt": return True
    import ctypes
    _mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\BGShareDesktopSingleton")
    return ctypes.windll.kernel32.GetLastError() != 183      # ERROR_ALREADY_EXISTS

class ToastNotifier(bp.Notifier):
    """Native toasts: windows-toasts -> win10toast -> tray balloon. Also keeps the list the UI can read."""
    def __init__(self, app):
        super().__init__(); self.app = app; self.kind = None
        if os.name == "nt":
            try:
                from windows_toasts import WindowsToaster, Toast
                self._toaster, self._Toast, self.kind = WindowsToaster(APP), Toast, "windows-toasts"
            except Exception:
                try:
                    from win10toast import ToastNotifier as W10
                    self._toaster, self.kind = W10(), "win10toast"
                except Exception:
                    pass
        log.info("notifications via %s", self.kind or "tray")

    def notify(self, title, body, iid=None):
        super().notify(title, body, iid)
        if self.app.peer and not self.app.peer.cfg.get("notify", True): return
        self.app.update_tray_title()
        try:
            if self.kind == "windows-toasts":
                t = self._Toast(); t.text_fields = [title, body]
                t.on_activated = lambda *_: self.app.show()
                self._toaster.show_toast(t); return
            if self.kind == "win10toast":
                self._toaster.show_toast(title, body, icon_path=resource("bgshare.ico"), duration=6, threaded=True); return
        except Exception:
            log.exception("toast failed")
        if self.app.tray is not None:
            try: self.app.tray.notify(body, title)
            except Exception: pass

class Api:
    """Exposed to the page as window.pywebview.api."""
    def __init__(self, app): self._app = app
    def pick_files(self):
        import webview
        r = self._app.window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=True)
        return list(r or [])
    def pick_folder(self):
        import webview
        r = self._app.window.create_file_dialog(webview.FOLDER_DIALOG)
        return r[0] if r else None
    def copy_text(self, text): return bp.copy_to_clipboard(str(text))
    def open(self, path): return bp.open_path(path)
    def get_autostart(self): return get_autostart()
    def set_autostart(self, on):
        ok = set_autostart(bool(on)); self._app.refresh_tray(); return ok

class DesktopApp:
    def __init__(self, args):
        self.args = args; self.window = None; self.tray = None; self.peer = None; self.quitting = False

    def start_peer(self):
        self.peer = bp.Peer(port=self.args.port, notifier=ToastNotifier(self))
        try:
            self.peer.start()
        except OSError as e:
            log.error("cannot listen on port %d: %s", self.args.port, e); raise
        self.url = f"http://127.0.0.1:{self.peer.port}/"

    # ---- tray
    def start_tray(self):
        try:
            import pystray
            from PIL import Image
        except Exception as e:
            log.warning("tray unavailable: %s", e); return
        M = pystray.MenuItem
        menu = pystray.Menu(
            M("Open BGShare", lambda *_: self.show(), default=True),
            pystray.Menu.SEPARATOR,
            M("Start with Windows", lambda *_: (set_autostart(not get_autostart()), self.refresh_tray()),
              checked=lambda *_: get_autostart(), enabled=os.name == "nt"),
            M("Desktop notifications", lambda *_: self.toggle_notify(), checked=lambda *_: self.peer.cfg.get("notify", True)),
            pystray.Menu.SEPARATOR,
            M("Quit BGShare", lambda *_: self.quit()))
        p = resource("bgshare.png") or resource("bgshare.ico")
        img = Image.open(p) if p else Image.new("RGBA", (64, 64), (7, 92, 229, 255))
        self.tray = pystray.Icon(APP, img, APP, menu); self.tray.run_detached()

    def refresh_tray(self):
        if self.tray:
            try: self.tray.update_menu()
            except Exception: pass

    def update_tray_title(self):
        if self.tray and self.peer:
            n = self.peer.unread()
            try: self.tray.title = f"{APP} - {n} unread" if n else APP
            except Exception: pass

    def toggle_notify(self):
        self.peer.cfg["notify"] = not self.peer.cfg.get("notify", True); self.peer.save_cfg(); self.refresh_tray()

    # ---- window
    def show(self):
        if self.window:
            try: self.window.show(); self.window.restore()
            except Exception: log.exception("show window")
            try:
                import ctypes; ctypes.windll.user32.SetForegroundWindow(self.window.native.Handle.ToInt32())
            except Exception: pass

    def on_closing(self):
        if self.quitting: return True
        try: self.window.hide()
        except Exception: pass
        if not getattr(self, "_told", False) and self.tray:
            self._told = True
            self.peer.notifier.notify("BGShare is still running", "It keeps receiving files in the tray. Use the tray icon to open or quit.")
        return False

    def quit(self):
        self.quitting = True
        if self.tray:
            try: self.tray.stop()
            except Exception: pass
        if self.window:
            try: self.window.destroy()
            except Exception: pass

    def run(self):
        import webview
        self.start_peer()
        show_listener(self)
        self.window = webview.create_window(APP, url=self.url, width=1240, height=880, min_size=(380, 560), js_api=Api(self),
                                            hidden=bool(self.args.minimized), background_color="#FAFCFF")
        self.window.events.closing += self.on_closing
        webview.start(self.start_tray, gui="edgechromium" if os.name == "nt" else None, private_mode=False,
                      storage_path=os.path.join(bp.app_dir(), "webview"), icon=resource("bgshare.ico"))
        self.quitting = True; self.peer.stop(); log.info("BGShare stopped")

SHOW_PORT = 8891

def signal_running_instance():
    try:
        with socket.create_connection(("127.0.0.1", SHOW_PORT), timeout=3) as c:
            c.sendall(b"show\n"); return c.recv(16).startswith(b"ok")
    except OSError:
        return False

def kill_other_instances():
    if os.name != "nt": return
    import subprocess
    me = os.getpid()
    subprocess.run(["taskkill", "/F", "/FI", f"PID ne {me}", "/IM", os.path.basename(sys.executable)],
                   capture_output=True, check=False, creationflags=0x08000000)

def show_listener(app):
    """Lets a second launch (Start menu, desktop shortcut) bring this window back."""
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: srv.bind(("127.0.0.1", SHOW_PORT)); srv.listen(4)
    except OSError: log.exception("show listener failed"); return
    def loop():
        while True:
            try:
                c, _ = srv.accept()
                with c:
                    if c.recv(16).startswith(b"show"):
                        app.show(); c.sendall(b"ok")
            except Exception: log.exception("show listener")
    threading.Thread(target=loop, daemon=True).start()

def main():
    ap = argparse.ArgumentParser(description="BGShare desktop app (peer to peer)")
    ap.add_argument("--minimized", action="store_true", help="start hidden in the tray (used by Start with Windows)")
    ap.add_argument("--port", type=int, default=bp.DEFAULT_PORT)
    ap.add_argument("--headless", action="store_true", help="run the peer without a window (see bgshare_peer.py --help)")
    a, _rest = ap.parse_known_args()
    if a.headless:
        return bp.main(sys.argv[1:])
    path = bp.setup_logging(os.path.join(bp.app_dir(), "bgshare.log"))
    if sys.stdout is None or getattr(sys, "frozen", False):
        sys.stdout = _LogStream(logging.INFO); sys.stderr = _LogStream(logging.ERROR)
    log.info("BGShare %s starting (log %s)", bp.VERSION, path)
    if not single_instance():
        # Another copy is running (often hidden in the tray): ask it to show its window, then exit.
        ok = signal_running_instance()
        log.info("already running; asked it to show its window (%s)", "ok" if ok else "no reply")
        if ok: return
        # The other copy did not answer: it is stuck. Stop it and start fresh.
        kill_other_instances(); time.sleep(1.5)
        if not single_instance():
            log.error("could not take over from a stuck instance"); return
    try:
        DesktopApp(a).run()
    except Exception:
        log.exception("BGShare crashed"); raise

if __name__ == "__main__":
    main()
