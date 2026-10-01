# Building FF Studio

## Run from source

Needs Python 3.8+.

```
pip install -r requirements.txt
python src/ffstudio_app.py      # desktop window (falls back to the browser if pywebview/WebView2 is missing)
python src/ffstudio.py          # browser version
```

Missing packages are installed automatically on launch (`src/bootstrap.py`).

## Build the exe

```
packaging\build_exe.bat
```

or `pyinstaller packaging/ffstudio.spec`. Output: `dist\FFStudio.exe`, a single windowed exe with Python,
numpy, Pillow, pywebview and the UI bundled.

Not bundled:

- **ACTS v3.2.1**: users extract [`acts.zip`](https://github.com/ate47/atian-cod-tools/releases/download/3.2.1/acts.zip)
  so `acts\bin\acts.exe` sits next to the exe.
- **BO3 Mod Tools**: installed through Steam and found automatically.
- **hksc**: optional; `hksc.exe` in a `tools\` folder next to the exe, or `HKSC_PATH`.

The exe writes its cache to `_studio_cache\` next to itself.
