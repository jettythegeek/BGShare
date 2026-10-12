# User guide

BGShare 2.1.0 sends files and text snippets from your PC straight to other BGShare PCs on the office network. There is no website to sign in to and no code to type. This guide is what you do after the installer has finished.

If BGShare is not installed yet, use the quick start in the [README](../README.md#quick-start-end-users). Build and IT steps are in the [setup guide](SETUP_GUIDE.md).

## 1. First run

Launch **BGShare** from the desktop shortcut or the Start menu.

The first screen asks for a display name. It is prefilled from your Windows user name. Change it if you want teammates to see something else (your real name is the usual choice). Choose **Continue**.

That name is what other PCs show in their Send to list. You can change it later in **Settings**. Each PC also keeps its own device id, so renaming yourself does not create a second person.

![First run](screenshots/p2p21-first-run.png)

## 2. Sending files

1. Open **Send files**. The sidebar shows the same action.
2. Under **Send to**, leave **Everyone** selected, or clear it and tick one or more people.
   - A green dot means that PC is online.
   - A grey dot means BGShare has seen that PC before but it is not online now. You cannot select it.
   - **Everyone** means every BGShare PC that is online at the moment you send, not a saved mailing list.
3. Drop files on the dashed area, or choose **browse**. Add more than one if you need to.
4. **Version note** is optional. A short line ("fixed the totals") shows up in version history.
5. Choose **Send to N people**, or **Send to everyone online**.

Large files show a progress bar. If the network drops mid-transfer, BGShare continues from the last completed block instead of starting over.

Sending the same file name to the same people again stores a new version. It does not create a second, unrelated item.

![Sending a file](screenshots/p2p21-home-send.png)

![Choosing everyone](screenshots/p2p21-everyone.png)

## 3. Snippets

A snippet is a piece of text up to 1 MB: a note, a link, a block of configuration. No attachment.

1. Open **Send snippet**.
2. Pick who receives it, the same way as a file.
3. Type a title and the text. The version note is optional.
4. Choose **Send snippet**.

On the receiving PC it shows up in Inbox and in Snippets. **Copy** puts the text on the Windows clipboard. **Reply** sends an updated version back to the person who sent it.

## 4. Inbox

When something arrives:

- BGShare plays a chime.
- Windows shows a toast. Clicking the toast opens the window.
- The window title and the Inbox row show an unread count, for example `(1) BGShare`.

Open **Inbox** to read it. Files have **Open** (opens the file) and **Folder** (shows it in File Explorer). Snippets have **Copy** and **Reply**. **History** is on each item.

The other lists are filters on the same history:

| List | What it shows |
|---|---|
| Inbox | Files and snippets other PCs sent you |
| Sent | What this PC sent |
| Everyone | Items that were sent to every online PC |
| Snippets | Text only |
| Archive | Items you deleted from the lists. The bytes of older versions can still be here. |

![Inbox and a resent file's history](screenshots/p2p21-inbox.png)

## 5. Version history

Open **History** on a file or snippet.

- Each send of the same name is a version (`v1`, `v2`, …) with who sent it, when, the size, and the version note.
- **Download** (or the version button) saves that exact copy.
- **Restore** on an older version makes it the current version. Restore publishes it as a new version, so nothing is thrown away.
- Tick two versions and choose **Compare** to see a text diff. Compare is for text files and snippets. A Word document or a zip has no line diff.

## 6. Stats

**My stats** is this PC only: how many files and snippets you sent and received today, this week, this month, and all time.

**Team analytics** is also this PC only. It groups your own send and receive history by teammate and by kind of file (documents, images, archives, and so on), for a week, a month, or all time. The screen says the numbers stay on this PC. Nobody else can open them, and they are not uploaded.

![Team analytics](screenshots/p2p21-team-analytics.png)

## 7. The tray

Closing the window does not quit BGShare. The window hides, and the giraffe icon stays in the notification area (check the arrow next to the clock if you do not see it). BGShare keeps receiving while it is in the tray.

The tray menu:

- **Open BGShare**
- **Start with Windows** (tick to turn it on or off)
- **Desktop notifications**
- **Quit BGShare** (this actually exits)

If you launch BGShare again while it is already running, the running window comes back. You do not get two copies.

Starting with Windows opens BGShare minimized to the tray, so it is already listening when you sign in.

## 8. Where files go

Received files are saved to:

```
Downloads\BGShare
```

If a file of that name is already there, the new one is saved beside it with a number in the name. A later version of the same shared item updates that item's file and keeps the older bytes in BGShare's version store.

To use a different folder: **Settings**, choose the folder, and save. The change applies to files received after that.

Snippets are not written into Downloads. They stay inside BGShare until you copy them.

## 9. Settings and the log

**Settings** holds your display name, the download folder, and whether desktop notifications are on.

The log file is:

```
%APPDATA%\BGShare\bgshare.log
```

Paste that into File Explorer's address bar. The same folder holds this PC's settings and history (`config.json`, `history.json`). You do not need to edit those by hand.

If the window will not come back, open the tray and choose **Open BGShare**. If the icon is gone, start BGShare from the shortcut. Details that help IT are in the [README troubleshooting section](../README.md#troubleshooting).
