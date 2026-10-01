"""FF Studio local web server and API routes (browser version).

Run `python ffstudio.py`, then open http://127.0.0.1:8799 (it tries to open your browser automatically).
For the desktop window, run ffstudio_app.py instead.
"""
import json, os, sys, threading, webbrowser, traceback, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# self-heal missing viewer packages (numpy/Pillow) when run directly. No-op if already present or frozen.
if not getattr(sys, 'frozen', False):
    try:
        import bootstrap; bootstrap.ensure(include_optional=False)
    except Exception:
        pass
import ffbuild
try:
    import ffassets
except Exception:
    ffassets = None

PORT = 8799
_HOSTS = {f'127.0.0.1:{PORT}', f'localhost:{PORT}'}
# resources (the HTML shell + bundled three.js) live next to this file when run from source, and inside the
# PyInstaller bundle (_MEIPASS) when frozen into a standalone exe.
RES_DIR = getattr(sys, '_MEIPASS', HERE)
HTML = os.path.join(RES_DIR, 'ffstudio.html')

_PREP = {}   # ff_path -> {stage, i, n, detail, done, error, assets}
def _do_prepare(ff):
    st = _PREP[ff] = {'stage': 'start', 'i': 0, 'n': 0, 'detail': 'reading fastfile', 'done': False}
    def cb(stage, i, n, detail): st.update(stage=stage, i=i, n=n, detail=detail)
    try:
        r = ffbuild.prepare(ff, cb)
        if ffassets:
            cb('assets', r['scripts'], r['scripts'], 'scanning assets')
            inv = ffassets.inventory(ff); st['assets'] = inv.get('count', 0)
        st.update(stage='done', done=True, detail=st.get('detail', 'ready'))
    except Exception as e:
        st.update(stage='error', done=True, error=str(e))


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype='application/json'):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _trusted(self, post=False):
        """Only answer requests addressed to this local server (blocks DNS rebinding) and, for POSTs, JSON requests
        (another site can't send one without a CORS preflight, which this server never grants)."""
        if self.headers.get('Host', '') not in _HOSTS:
            return False
        return not post or self.headers.get('Content-Type', '').startswith('application/json')

    def _json_body(self):
        n = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(n) or b'{}')

    def do_GET(self):
        if not self._trusted():
            return self._send(403, {'error': 'forbidden'})
        u = urllib.parse.urlparse(self.path)
        if u.path in ('/', '/index.html'):
            try:
                return self._send(200, open(HTML, encoding='utf-8').read(), 'text/html; charset=utf-8')
            except FileNotFoundError:
                return self._send(500, '<h1>ffstudio.html missing next to ffstudio.py</h1>', 'text/html')
        if u.path == '/favicon.ico':
            try:
                ico = open(os.path.join(RES_DIR, 'ffstudio.ico'), 'rb').read()
                return self._send(200, ico, 'image/x-icon')
            except FileNotFoundError:
                return self._send(404, {'error': 'no icon'})
        if u.path == '/three.min.js':
            try:
                js = open(os.path.join(RES_DIR, 'three.min.js'), 'rb').read()
                self.send_response(200); self.send_header('Content-Type', 'application/javascript')
                self.send_header('Cache-Control', 'max-age=86400'); self.send_header('Content-Length', str(len(js)))
                self.end_headers(); self.wfile.write(js); return
            except FileNotFoundError:
                return self._send(404, {'error': 'three.min.js not bundled'})
        if u.path == '/api/deps':
            return self._send(200, {k: v for k, v in ffbuild.check_deps().items() if not k.startswith('_')})
        if u.path == '/api/workshop':
            try:
                return self._send(200, ffbuild.list_ffs())
            except Exception as e:
                return self._send(200, {'mods': [], 'game_root': None, 'error': str(e)})
        if u.path == '/api/inventory':
            q = urllib.parse.parse_qs(u.query); ff = q.get('ff', [''])[0]
            if not ffassets: return self._send(200, {'error': 'asset backend unavailable', 'assets': []})
            try: return self._send(200, ffassets.inventory(ff))
            except Exception as e: return self._send(200, {'error': str(e), 'assets': []})
        if u.path == '/api/image':
            q = urllib.parse.parse_qs(u.query); ff = q.get('ff', [''])[0]; off = int(q.get('off', ['0'])[0])
            try:
                png, meta = ffassets.image_png(ff, off)
                self.send_response(200); self.send_header('Content-Type', 'image/png')
                self.send_header('Content-Length', str(len(png))); self.end_headers(); self.wfile.write(png); return
            except Exception as e:
                return self._send(200, {'error': str(e)})
        if u.path == '/api/font':
            q = urllib.parse.parse_qs(u.query); ff = q.get('ff', [''])[0]; off = int(q.get('off', ['0'])[0])
            try:
                ttf, meta = ffassets.font_bytes(ff, off)
                self.send_response(200); self.send_header('Content-Type', 'font/ttf')
                self.send_header('X-Font-Family', urllib.parse.quote(meta.get('family') or ''))
                self.send_header('X-Font-Glyphs', str(meta.get('glyphs') or 0))
                self.send_header('X-Font-Tables', urllib.parse.quote(','.join(meta.get('tables') or [])))
                self.send_header('Content-Length', str(len(ttf))); self.end_headers(); self.wfile.write(ttf); return
            except Exception as e:
                return self._send(200, {'error': str(e)})
        if u.path == '/api/progress':
            q = urllib.parse.parse_qs(u.query); ff = q.get('ff', [''])[0]
            return self._send(200, _PREP.get(ff, {'stage': 'idle', 'i': 0, 'n': 0, 'detail': '', 'done': False}))
        if u.path == '/api/export':
            q = urllib.parse.parse_qs(u.query)
            ff = q.get('ff', [''])[0]; off = int(q.get('off', ['0'])[0]); atype = q.get('type', [''])[0]
            try:
                fn, ct, data = ffassets.export_asset(ff, off, atype)
                self.send_response(200); self.send_header('Content-Type', ct)
                self.send_header('Content-Disposition', 'attachment; filename="%s"' % urllib.parse.quote(fn))
                self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data); return
            except Exception as e:
                return self._send(200, {'error': str(e)})
        if u.path == '/api/download':
            q = urllib.parse.parse_qs(u.query); path = q.get('path', [''])[0]
            if not os.path.isfile(path):
                return self._send(404, {'error': 'not found'})
            data = open(path, 'rb').read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(path)}"')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers(); self.wfile.write(data)
            return
        return self._send(404, {'error': 'no route'})

    def do_POST(self):
        if not self._trusted(post=True):
            return self._send(403, {'error': 'forbidden'})
        u = urllib.parse.urlparse(self.path)
        try:
            b = self._json_body()
            if u.path == '/api/open':
                r = ffbuild.open_ff(b['ff']); r['names'] = ffbuild.load_names(b['ff']); return self._send(200, r)
            if u.path == '/api/prepare':
                ff = b['ff']
                cur = _PREP.get(ff)
                if not (cur and not cur.get('done')):   # not already running
                    threading.Thread(target=_do_prepare, args=(ff,), daemon=True).start()
                return self._send(200, {'started': True})
            if u.path == '/api/decompile':
                return self._send(200, {'source': ffbuild.decompile(b['ff'], b['name'])})
            if u.path == '/api/names':
                return self._send(200, {'names': ffbuild.load_names(b['ff'])})
            if u.path == '/api/symbols':
                return self._send(200, {'symbols': ffbuild.symbols(b['ff'])})
            if u.path == '/api/xrefs':
                return self._send(200, {'refs': ffbuild.xrefs(b['ff'], b['symbol'])})
            if u.path == '/api/diagnostics':
                return self._send(200, {'problems': ffbuild.diagnostics(b['ff'], b['edits'])})
            if u.path == '/api/rename':
                names = ffbuild.load_names(b['ff']); old = b['old']; new = b['new'].strip()
                # resolve canonical hex token for `old` (which is the currently-displayed name)
                canonical = None
                for hx, fr in names.items():
                    if fr == old: canonical = hx; break
                if canonical is None and ffbuild._TOK.fullmatch(old): canonical = old
                if canonical is None:
                    return self._send(200, {'error': f"'{old}' isn't a hash symbol — plain names don't need aliasing."})
                if new == canonical:
                    names.pop(canonical, None)                           # revert to the raw hash token
                else:
                    err = ffbuild.validate_rename(b['ff'], canonical, new, names)
                    if err: return self._send(200, {'error': err})
                    names[canonical] = new
                ffbuild.save_names(b['ff'], names)
                return self._send(200, {'ok': True, 'canonical': canonical, 'names': names})
            if u.path == '/api/fxview':
                return self._send(200, ffassets.fx_view(b['ff'], int(b['off'])))
            if u.path == '/api/luaview':
                return self._send(200, ffassets.lua_view(b['ff'], int(b['off'])))
            if u.path == '/api/luabuild':
                try:
                    out = b.get('out') or (os.path.splitext(b['ff'])[0] + '.studio.ff')
                    return self._send(200, ffassets.lua_build(b['ff'], int(b['off']), b['source'], out))
                except Exception as e:
                    return self._send(200, {'error': str(e)})
            if u.path == '/api/imagereplace':
                try:
                    r = ffassets.image_replace(b['ff'], int(b['off']), b['path'],
                                               out_ff=b.get('out_ff'), out_xpak=b.get('out_xpak'))
                    return self._send(200, r)
                except Exception as e:
                    return self._send(200, {'error': str(e)})
            if u.path == '/api/matview':
                return self._send(200, ffassets.material_view(b['ff'], int(b['off'])))
            if u.path == '/api/tsview':
                return self._send(200, ffassets.techset_view(b['ff'], int(b['off'])))
            if u.path == '/api/meshview':
                try: return self._send(200, ffassets.mesh_view(b['ff'], int(b['off'])))
                except Exception as e: return self._send(200, {'error': str(e)})
            if u.path == '/api/stringtableview':
                try: return self._send(200, ffassets.stringtable_view(b['ff'], int(b['off'])))
                except Exception as e: return self._send(200, {'error': str(e)})
            if u.path == '/api/animview':
                try: return self._send(200, ffassets.anim_view(b['ff'], int(b['off'])))
                except Exception as e: return self._send(200, {'error': str(e)})
            if u.path == '/api/xmodelview':
                try: return self._send(200, ffassets.xmodel_view(b['ff'], int(b['off'])))
                except Exception as e: return self._send(200, {'error': str(e)})
            if u.path == '/api/skeleton':
                try: return self._send(200, ffassets.skeleton_view(b['ff'], int(b['off'])))
                except Exception as e: return self._send(200, {'error': str(e)})
            if u.path == '/api/meshskin':
                try: return self._send(200, ffassets.mesh_skin(b['ff'], int(b['off'])))
                except Exception as e: return self._send(200, {'error': str(e)})
            if u.path == '/api/structview':
                try: return self._send(200, ffassets.struct_view(b['ff'], int(b['off'])))
                except Exception as e: return self._send(200, {'error': str(e)})
            if u.path == '/api/modffs':
                try: return self._send(200, {'ffs': ffbuild.mod_ffs(b['ff'])})
                except Exception as e: return self._send(200, {'error': str(e), 'ffs': []})
            if u.path == '/api/ffstate':
                try: return self._send(200, ffbuild.studio_ff_state(b['ff']))
                except Exception as e: return self._send(200, {'error': str(e)})
            if u.path == '/api/toggleff':
                try: return self._send(200, ffbuild.toggle_studio_ff(b['ff'], b.get('built')))
                except Exception as e: return self._send(200, {'error': str(e)})
            if u.path == '/api/basematch':
                # match a mod animation to base-game models (retail fastfiles). First call builds a cached index
                # in the background; poll until status=='ready'. Each candidate carries its own ff path.
                try:
                    st = ffassets.base_index_state()
                    if st['status'] != 'ready':
                        if st['status'] in ('idle', 'building'): ffassets.start_base_index_build()
                        return self._send(200, {'status': ffassets.base_index_state()['status'],
                                                'msg': ffassets.base_index_state()['msg'], 'matches': []})
                    bones = ffassets.anim_view(b['ff'], int(b['off'])).get('bones', [])
                    return self._send(200, {'status': 'ready', 'matches': ffassets.base_match(bones)})
                except Exception as e:
                    return self._send(200, {'status': 'error', 'msg': str(e), 'matches': []})
            if u.path == '/api/build':
                logs = []
                out = b.get('out') or (os.path.splitext(b['ff'])[0] + '.studio.ff')
                res = ffbuild.build(b['ff'], b['edits'], out, names=b.get('names'),
                                    log=lambda *a: logs.append(' '.join(str(x) for x in a)))
                res['log'] = logs
                return self._send(200, res)
            return self._send(404, {'error': 'no route'})
        except Exception as e:
            return self._send(200, {'error': str(e), 'trace': traceback.format_exc(),
                                    'log': locals().get('logs', [])})


def main():
    srv = ThreadingHTTPServer(('127.0.0.1', PORT), H)
    url = f'http://127.0.0.1:{PORT}'
    print(f"FF Studio running at {url}")
    print("  (Ctrl+C to stop)")
    try:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
