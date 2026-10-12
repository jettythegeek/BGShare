# Setup guide

Build BGShare 2.1.0 on a Windows 10 or 11 PC. These steps assume you are cloning the repository, not installing a finished setup exe. End users who only need the app should download `BGShare-Setup.exe` from GitHub Releases and follow the quick start in the [README](../README.md).

The build runs from the `desktop/` folder. `build.ps1` switches to its own directory before it does anything, so the relative paths inside it (`requirements.txt`, `bgshare_desktop.py`, `installer.iss`, `dist\`, `Output\`) stay correct as long as those files stay together in `desktop/`.

## 1. Install Git

Git is how you clone this repository.

```powershell
winget install --id Git.Git -e --source winget
```

Or install it from <https://git-scm.com/download/win>. After installing, open a new terminal so `git` is on `PATH`.

## 2. Install Python 3.11, 3.12, 3.13, or 3.14

BGShare is developed and built on Python 3.11 through 3.14. On the python.org installer, tick **Add python.exe to PATH**.

```powershell
winget install --id Python.Python.3.13 -e --source winget
```

Any of `Python.Python.3.11`, `Python.Python.3.12`, `Python.Python.3.13`, or `Python.Python.3.14` is fine. Downloads: <https://www.python.org/downloads/windows/>.

Check it:

```powershell
py -3 --version
```

You should see a version from 3.11 up to 3.14. If `py` is not found, `python --version` is the fallback, which is also what `build.ps1` tries.

## 3. Install Inno Setup 6

Inno Setup builds `BGShare-Setup.exe`. Skip it only if you pass `-NoInstaller` and just want `BGShare.exe`.

```powershell
winget install --id JRSoftware.InnoSetup -e --source winget
```

Or download it from <https://jrsoftware.org/isdl.php>.

## 4. Clone the repository

```powershell
git clone https://github.com/jettythegeek/BGShare.git
cd BGShare
```

## 5. Build

From the `desktop` folder:

```powershell
cd desktop
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

You can also launch it from the repository root. The script still does its work inside `desktop/`:

```powershell
powershell -ExecutionPolicy Bypass -File .\desktop\build.ps1
```

What the script does, in order:

1. Finds `py -3` or `python` on `PATH`.
2. Creates `desktop\.venv` if it is not there.
3. Installs `desktop\requirements.txt` (pywebview, pystray, Pillow, Windows toasts, PyInstaller).
4. Compiles the Python sources to catch syntax errors.
5. Rebuilds `bgshare.ico` and `bgshare.png` from the logo embedded in `bgshare_peer.py`.
6. Runs PyInstaller.
7. Writes a temporary `version_info.txt` (gitignored) and, unless you skipped it, compiles `installer.iss` with Inno Setup.

### Flags

| Flag | Effect |
|---|---|
| *(none)* | One-folder build. This is the recommended default. The app starts faster because Windows does not unpack a single exe on every launch. |
| `-OneFile` | One `BGShare.exe` instead of a folder. Simpler to copy by hand. Slower to start. |
| `-NoInstaller` | Stop after PyInstaller. Use this when Inno Setup is not installed. |
| `-Version 2.1.0` | Version stamped into the exe and the installer. The default in the script is `2.1.0`. This does not change the version string inside `bgshare_peer.py`; see [Bumping the version](#9-bump-the-version-and-rebuild). |

Examples:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1 -NoInstaller
powershell -ExecutionPolicy Bypass -File .\build.ps1 -OneFile
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Version 2.1.0
```

## 6. Where the outputs land

All of these are gitignored. Do not commit them.

| Build | Path |
|---|---|
| One-folder (default) | `desktop\dist\BGShare\BGShare.exe` |
| `-OneFile` | `desktop\dist\BGShare.exe` |
| Installer | `desktop\Output\BGShare-Setup.exe` |

`desktop\build\` is PyInstaller's scratch folder. `desktop\version_info.txt` is the Windows version resource and is rewritten every build.

The installer requires administrator rights. It offers three tasks, all checked by default:

- a desktop shortcut
- start BGShare when the user signs in to Windows
- Windows Firewall rules on **private** networks for TCP 8890, UDP 8890, and the program itself

The wizard images are the Blue Giraffe logos in `desktop\wizard-*.bmp`.

## 7. Test the installer on two PCs

1. Copy `desktop\Output\BGShare-Setup.exe` to two Windows PCs on the same office network. Do not use guest Wi-Fi.
2. On each PC, run the installer, approve the administrator prompt, and leave every option checked.
3. Set each PC's network to **Private** (Settings, Network & internet, the connected network, Private).
4. Launch BGShare, enter a display name, and wait a few seconds.
5. Each PC should list the other under Send to. Send a small file in both directions, then send a snippet.
6. Confirm the file is in `Downloads\BGShare` on the receiving PC, the toast appeared, and the unread badge cleared when you opened Inbox.
7. If a PC cannot see the other, use the troubleshooting list in the [README](../README.md#troubleshooting). The log is `%APPDATA%\BGShare\bgshare.log`.

A second launch while BGShare is already running should bring the existing window back from the tray, not open a second copy.

## 8. Run from source (development)

The window needs Windows, Edge WebView2 (present on current Windows 11, and on Windows 10 once the runtime is installed), and the packages in `requirements.txt`.

```powershell
cd desktop
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py bgshare_desktop.py
```

`py bgshare_desktop.py --minimized` starts in the tray, which is what Start with Windows does.

Headless mode runs the peer with no window. It is the right way to test discovery and transfers, and it needs only the Python standard library (`bgshare_desktop.py` is not imported):

```powershell
py bgshare_peer.py --headless --name "Ada" --port 8890 --data-dir $env:TEMP\bgshare-a --download-dir $env:TEMP\bgshare-a-downloads
```

Useful headless flags:

| Flag | Meaning |
|---|---|
| `--name` | Display name. Without it, the first run has no name until something calls the settings API. |
| `--port` | TCP port for the peer API and the local UI. Default 8890. |
| `--discovery-port` | UDP announcement port. Default 8890. Two peers only see each other when this matches. |
| `--data-dir` | Where `config.json`, `history.json`, and `bgshare.log` go. Default `%APPDATA%\BGShare`. |
| `--download-dir` | Where received files are saved. |
| `--log` | Log file path. |

Give each test peer its own `--port`, `--data-dir`, and `--download-dir`. Keep `--discovery-port` the same on all of them. Stop a headless peer with Ctrl+C.

On a non-Windows machine the headless peer still runs (the standard library only). The window, tray, toasts, and installer do not.

## 9. Bump the version and rebuild

The version the app shows is `VERSION` in `desktop/bgshare_peer.py`. The version stamped on `BGShare.exe` and on the installer is the `-Version` argument of `build.ps1` (default `2.1.0`). The fallback in `desktop/installer.iss` (`#define MyAppVersion`) is used only when Inno Setup is invoked without `/DMyAppVersion`, which `build.ps1` always passes.

To release, for example, 2.2.0:

1. Set `VERSION = "2.2.0"` in `desktop/bgshare_peer.py`.
2. Set the default in `desktop/build.ps1`: `param(..., [string]$Version = "2.2.0")`.
3. Set `#define MyAppVersion "2.2.0"` in `desktop/installer.iss` so a manual Inno Setup compile matches.
4. Rebuild:

```powershell
cd desktop
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Or pass the flag without editing the script default: `.\build.ps1 -Version 2.2.0`. Do that **and** edit `VERSION` in `bgshare_peer.py`, or the window and the installer will disagree.

## 10. Distribute to the team

1. Build `desktop\Output\BGShare-Setup.exe` on one Windows PC.
2. Publish that file as a GitHub Release named with the version (for example `v2.1.0`), or copy it to a share the team already uses.
3. Send people the quick start in the [README](../README.md#quick-start-end-users): SmartScreen (**More info**, then **Run anyway**), the administrator prompt, and setting the network to Private.
4. Do not zip up `dist\BGShare\` as the normal install. The setup exe is what adds the firewall rules, the shortcut, and Start with Windows. A bare copy of the exe will run, but Windows Firewall will ask (or silently drop discovery) until those rules exist.

## 11. Uninstall

On each PC: Settings, Apps, Installed apps, BGShare, Uninstall. The Start menu also has **Uninstall BGShare**.

The uninstaller stops a running BGShare (including one sitting in the tray), removes the program files, removes the Start with Windows entry if the installer created it, and deletes the three firewall rules.

It leaves these alone on purpose:

- `%APPDATA%\BGShare` (settings, history, versions, `bgshare.log`)
- received files in `Downloads\BGShare`, or in whatever folder was chosen in Settings

Delete those folders yourself if the PC should keep nothing.
