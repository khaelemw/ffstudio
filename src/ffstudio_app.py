"""FF Studio desktop app: the same UI in a native window (pywebview / WebView2) with native file dialogs.
The web server still runs locally in a background thread; that's how the UI talks to Python.

    python ffstudio_app.py

Needs pywebview. Without it, this falls back to the browser version.
"""
import os, sys, threading, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# Install missing packages when run from source (the exe already bundles them).
if not getattr(sys, 'frozen', False):
    try:
        import bootstrap; bootstrap.ensure(include_optional=True)
    except Exception:
        pass
import ffstudio  # the local server + routes  (imports numpy/Pillow via ffassets)


def _start_server():
    srv = ffstudio.ThreadingHTTPServer(('127.0.0.1', ffstudio.PORT), ffstudio.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _dialog(kind):
    """The file-dialog constant, tolerant of the pywebview 5.x move to webview.FileDialog.*
    (webview.OPEN_DIALOG / SAVE_DIALOG are deprecated and warn on newer versions)."""
    import webview
    fd = getattr(webview, 'FileDialog', None)
    if fd is not None:
        return getattr(fd, kind)              # FileDialog.OPEN / FileDialog.SAVE  (pywebview >=5)
    return getattr(webview, kind + '_DIALOG')  # OPEN_DIALOG / SAVE_DIALOG          (legacy)


class Api:
    """Exposed to the page as window.pywebview.api.* — native file access the browser can't give us."""
    def pick_ff(self):
        import webview
        w = webview.active_window()
        r = w.create_file_dialog(_dialog('OPEN'), allow_multiple=False,
                                 file_types=('Fastfile (*.ff)', 'All files (*.*)'))
        if not r: return None
        return r[0] if isinstance(r, (list, tuple)) else r

    def pick_image(self):
        import webview
        w = webview.active_window()
        r = w.create_file_dialog(_dialog('OPEN'), allow_multiple=False,
                                 file_types=('Image (*.png;*.jpg;*.jpeg;*.tga;*.bmp;*.dds)', 'All files (*.*)'))
        if not r: return None
        return r[0] if isinstance(r, (list, tuple)) else r

    def save_copy(self, src, default_name='zm_mod.ff'):
        import webview
        w = webview.active_window()
        r = w.create_file_dialog(_dialog('SAVE'), save_filename=default_name)
        dst = (r[0] if isinstance(r, (list, tuple)) else r) if r else None
        if not dst: return None
        shutil.copy2(src, dst)
        return dst


def _browser_fallback(url):
    """No native window available (pywebview missing, or WebView2 runtime absent) — open the browser version
    and keep the local server alive. Uses input() only when there's a real console (source run); a windowed
    frozen exe has no stdin, so we just block the main thread instead of crashing on input()."""
    import webbrowser; webbrowser.open(url)
    has_console = bool(getattr(sys, 'stdin', None)) and sys.stdin is not None and sys.stdin.isatty()
    if has_console and not getattr(sys, 'frozen', False):
        try:
            input("FF Studio is open in your browser. Press Enter here to stop the server…")
            return
        except (EOFError, OSError):
            pass
    # windowed / no-console: keep the daemon server thread running until the process is closed
    import time
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass

def main():
    _start_server()
    url = f'http://127.0.0.1:{ffstudio.PORT}'
    try:
        import webview
    except ImportError:
        print("pywebview not installed; opening the browser version instead.  (Desktop app: pip install pywebview)")
        return _browser_fallback(url)
    try:
        webview.create_window('FF Studio', url, js_api=Api(), width=1280, height=820, min_size=(940, 600))
        icon = os.path.join(ffstudio.RES_DIR, 'ffstudio.ico')
        try:
            webview.start(icon=icon if os.path.isfile(icon) else None)
        except TypeError:                      # older pywebview without the icon argument
            webview.start()
    except Exception as e:
        # e.g. WebView2 runtime missing on this PC — degrade to the browser version rather than failing
        print(f"native window unavailable ({e}); opening the browser version instead.")
        _browser_fallback(url)


if __name__ == '__main__':
    main()
