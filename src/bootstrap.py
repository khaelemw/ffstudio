"""Installs the Python packages FF Studio needs into the interpreter running it, using its own pip.
Safe to run repeatedly; packages that are already present are skipped. Runs automatically when FF Studio is
started from source, or run it directly with `python bootstrap.py`.

Required : numpy, Pillow   (image and mesh decoding)
Optional : pywebview       (native desktop window; the browser version works without it)
"""
import importlib.util, subprocess, sys

# (pip name, import spec name, required?)
DEPS = [('numpy', 'numpy', True), ('Pillow', 'PIL', True), ('pywebview', 'webview', False)]

def missing(include_optional=True):
    out = []
    for pip_name, spec, req in DEPS:
        if not req and not include_optional:
            continue
        if importlib.util.find_spec(spec) is None:
            out.append((pip_name, spec, req))
    return out

def have_pip():
    return importlib.util.find_spec('pip') is not None

def install(pkgs, log=print):
    """pip-install the given pip names into this interpreter. Returns True on success."""
    if not pkgs:
        return True
    if not have_pip():
        log("  ! pip is not available in this Python — install it (python -m ensurepip --upgrade) or install the "
            "packages manually: pip install " + " ".join(pkgs))
        return False
    log("  installing: " + " ".join(pkgs) + "  (this runs once)")
    try:
        r = subprocess.run([sys.executable, '-m', 'pip', 'install', *pkgs],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        log(f"  ! pip failed to launch: {e}")
        return False
    if r.returncode != 0:
        # retry into the per-user site if the environment isn't writable (common on system Python)
        try:
            r2 = subprocess.run([sys.executable, '-m', 'pip', 'install', '--user', *pkgs],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if r2.returncode == 0:
                log("  installed into your per-user site-packages.")
                return True
            log((r.stdout or '')[-1500:]); log((r2.stdout or '')[-800:])
        except Exception:
            log((r.stdout or '')[-1500:])
        return False
    return True

def ensure(include_optional=True, log=print):
    """Ensure required (and optionally the optional) deps are present. Returns (ok_required, still_missing)."""
    need = missing(include_optional=include_optional)
    if not need:
        log("All FF Studio dependencies are present.")
        return True, []
    log("FF Studio needs a few Python packages:")
    for pip_name, _spec, req in need:
        log(f"   - {pip_name}" + ("" if req else "  (optional)"))
    # install required first, then optional (so a failure to get pywebview never blocks the browser version)
    req_pkgs = [p for p, _s, r in need if r]
    opt_pkgs = [p for p, _s, r in need if not r]
    ok_req = install(req_pkgs, log) if req_pkgs else True
    if opt_pkgs:
        install(opt_pkgs, log)   # best-effort; ignore result
    still = missing(include_optional=include_optional)
    still_required = [p for p, _s, r in still if r]
    if ok_req and not still_required:
        log("Dependencies ready.")
        return True, still
    log("Some required packages could not be installed automatically. Install them manually:")
    log("   pip install " + " ".join(p for p, _s, r in still if r))
    return False, still

if __name__ == '__main__':
    ok, _ = ensure(include_optional='--no-optional' not in sys.argv)
    sys.exit(0 if ok else 1)
