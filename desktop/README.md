# BGShare for Windows (peer to peer), version 2.1.0

This folder is the Windows desktop app. The [repository README](../README.md), [setup guide](../docs/SETUP_GUIDE.md) and [user guide](../docs/USER_GUIDE.md) cover what BGShare is, how to install it, and how to use it. This page is the short reference for building from this folder.

Every PC with BGShare installed is an equal peer. There is no server, password or code. Every BGShare PC on the same network is a team member.

- **First run** asks only for your display name, prefilled with your Windows user name. Each PC keeps a stable device id.
- **Finding PCs** is automatic: BGShare announces itself on UDP 8890 by multicast (239.255.77.88) with a broadcast fallback.
- **Sending** works the same as in the BGShare server version: choose Everyone or specific people (chips with initials and an online dot; offline people are greyed out and cannot be selected), then drop files and add an optional version note.
  - Everyone means every PC that is online.
  - Files stream directly over TCP 8890 in 4 MB blocks, and an interrupted transfer resumes from where it stopped.
  - Text snippets of up to 1 MB are sent the same way.
- **Receiving** is automatic. You get a Windows notification, a chime and an unread badge. Files are saved to `Downloads\BGShare` (you can change this in Settings). The Copy button on a snippet uses the Windows clipboard.
- **Lists and versions:** Inbox, Sent, Everyone, Snippets and Archive are kept on each PC. Re-sending a file with the same name to the same people saves a new version on both PCs. You can download, restore and compare (text) versions.
- **My stats and Team analytics** count this PC's own history.
- **Traffic is not encrypted or authenticated.** Any BGShare PC on the network can send to you. Use BGShare only on trusted office networks. The app window only answers on 127.0.0.1 and needs a token that changes on every run.
- **Fonts:** DM Sans and Manrope (SIL Open Font License) are bundled, so the UI looks the same offline.

Files:

| File | Purpose |
|---|---|
| `bgshare_peer.py` | P2P core (standard library only). It can also run without a window: `python bgshare_peer.py --headless --name "Ada"` |
| `bgshare_desktop.py` | Desktop app: window (pywebview/WebView2), tray, toasts, Start with Windows, log |
| `build.ps1`, `installer.iss`, `wizard-*.bmp`, `make_icon.py` | Build scripts and installer |

Data and settings are in `%APPDATA%\BGShare` (`config.json`, `history.json`, `events.jsonl`, `versions\`, `snippets\`). The log is `%APPDATA%\BGShare\bgshare.log`; unhandled exceptions are written there too.

## Build (on Windows 10/11)

```powershell
# once: Python 3.11-3.14 from python.org, and optionally Inno Setup 6 for the installer
winget install JRSoftware.InnoSetup
# in this folder
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

The build produces `dist\BGShare\BGShare.exe` and `Output\BGShare-Setup.exe`. Options: `-OneFile` builds a single exe, `-NoInstaller` skips Inno Setup.

The installer needs admin rights. It adds firewall rules on private networks (TCP 8890, UDP 8890 and the program), a desktop shortcut and Start with Windows. All three options are checked by default. Uninstalling removes the firewall rules.

Make sure Windows treats the office network as Private. Firewall rules are only added for the private profile.

## Run from source

```powershell
py -m pip install -r requirements.txt
py bgshare_desktop.py            # --minimized starts in the tray
```
