#!/usr/bin/env python3
"""BGShare (Blue Giraffe edition) - single-file LAN file sharing with accounts,
private sends and git-like versioning. Python 3 standard library only.

Usage: python bgshare.py [--port 8080] [--dir ./lanshare-data] [--legacy-dir ./shared] [--password OFFICECODE]
"""
import argparse, datetime, difflib, mimetypes, hashlib, hmac, json, os, re, secrets, shutil, socket, sys, threading, time, unicodedata
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote

CHUNK = 4 * 1024 * 1024          # 4 MB I/O buffers
PBKDF2_ITER = 200_000
SESSION_DAYS = 30
LOCK = threading.RLock()
CFG = {"dir": None, "password": None}
DB = {"users": {}, "sessions": {}, "files": {}}
SNIPPET_MAX = 1024 * 1024          # 1 MB cap per snippet
DISCOVERY_PORT = 8889
EVENTS = []                         # in-memory copy of events.jsonl
ID_RE = re.compile(r"^[0-9a-f]{12,32}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

# ---------------------------------------------------------------- storage
def dpath(*p):
    return os.path.join(CFG["dir"], *p)

def obj_path(sha):
    if not SHA_RE.match(sha or ""):
        raise ValueError("bad hash")
    return dpath("objects", sha[:2], sha)

def load_db():
    for k in DB:
        try:
            with open(dpath(k + ".json"), encoding="utf-8") as f:
                DB[k] = json.load(f)
        except FileNotFoundError:
            DB[k] = {}

def save(k):
    p = dpath(k + ".json")
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        json.dump(DB[k], f, indent=1)
    os.replace(p + ".tmp", p)

def store_blob(tmp, sha):
    """Move a finished temp file into the content-addressed store (dedup)."""
    dst = obj_path(sha)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        os.remove(tmp)
    else:
        os.replace(tmp, dst)

def safe_name(name):
    """Sanitized plain display filename, or None. Strips all directory parts."""
    if not name:
        return None
    name = unicodedata.normalize("NFC", name).replace("\\", "/").split("/")[-1]
    name = re.sub(r'[\x00-\x1f<>:"|?*]', "_", name).strip().strip(".").strip()
    if not name or name in (".", ".."):
        return None
    if re.match(r"^(CON|PRN|AUX|NUL|COM\d|LPT\d)(\..*)?$", name, re.I):
        name = "_" + name
    return name[:200]

# ---------------------------------------------------------------- accounts
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITER)
    return salt.hex(), h.hex()

def find_user(name):
    n = name.strip().casefold()
    for uid, u in DB["users"].items():
        if u["name"].casefold() == n:
            return uid
    return None

def new_session(uid):
    tok = secrets.token_urlsafe(32)
    with LOCK:
        now = time.time()
        DB["sessions"] = {t: s for t, s in DB["sessions"].items() if s["exp"] > now}
        DB["sessions"][tok] = {"uid": uid, "exp": now + SESSION_DAYS * 86400}
        save("sessions")
    return tok

# ---------------------------------------------------------------- access rules
def audience_key(f):
    return "everyone" if f["to"] == "everyone" else ",".join(sorted(set(f["to"]) | {f["owner"]}))

def can_see(f, uid):
    return f["to"] == "everyone" or uid == f["owner"] or uid in f["to"]

def file_view(fid, f, uid):
    v = f["versions"][-1]
    users = DB["users"]
    nm = lambda i: users.get(i, {}).get("name", "?")
    return {"id": fid, "name": f["name"], "owner": f["owner"], "owner_name": nm(f["owner"]),
            "to": "everyone" if f["to"] == "everyone" else [{"id": i, "name": nm(i)} for i in f["to"]],
            "version": v["v"], "size": v["size"], "sha256": v["sha"], "uploader_name": nm(v["by"]),
            "time": v["time"], "note": v["note"], "versions": len(f["versions"]),
            "deleted": f.get("deleted", False), "deleted_at": f.get("deleted_at"), "can_delete": uid == f["owner"],
            "unread": is_unread(fid, f, uid), "kind": f.get("kind", "file"), "category": file_cat(f),
            **(snippet_preview(f) if f.get("kind") == "snippet" else {})}

def snippet_preview(f, n=3000):
    v = f["versions"][-1]
    txt = snippet_text(v, n + 4)
    return {"preview": txt[:n], "truncated": v["size"] > n, "lines": None if v["size"] > n else txt.count("\n") + 1}

def in_inbox(f, uid):
    """Private file sent to me, or a private file of mine that someone else updated."""
    return f["to"] != "everyone" and f["versions"][-1]["by"] != uid and (uid in f["to"] or uid == f["owner"])

def read_map(uid):
    """Per-user read state: {file_id: highest version number the user has opened/downloaded}.
    Users from older builds only had a 'seen' timestamp; convert it once."""
    u = DB["users"][uid]
    if "read" not in u:
        seen = u.get("seen", 0)
        u["read"] = {fid: max(v["v"] for v in f["versions"] if v["time"] <= seen)
                     for fid, f in DB["files"].items() if any(v["time"] <= seen for v in f["versions"])}
    return u["read"]

def is_unread(fid, f, uid):
    return (not f.get("deleted") and in_inbox(f, uid)
            and read_map(uid).get(fid, 0) < f["versions"][-1]["v"])

def mark_read(fid, f, uid):
    with LOCK:
        r = read_map(uid); v = f["versions"][-1]["v"]
        if r.get(fid, 0) < v:
            r[fid] = v; save("users")

def unread_list(uid):
    nm = lambda i: DB["users"].get(i, {}).get("name", "?")
    out = [{"id": fid, "name": f["name"], "version": f["versions"][-1]["v"], "by": nm(f["versions"][-1]["by"]),
            "time": f["versions"][-1]["time"], "kind": f.get("kind", "file")} for fid, f in DB["files"].items() if is_unread(fid, f, uid)]
    return sorted(out, key=lambda x: -x["time"])

# ---------------------------------------------------------------- categories
CATS = ["video", "image", "audio", "document", "spreadsheet", "slides", "pdf", "archive", "code", "text", "other", "snippet"]
_EXT = {"video": "mp4 mov avi mkv webm m4v wmv flv 3gp mpg mpeg", "image": "png jpg jpeg gif webp svg bmp heic heif tif tiff ico raw",
        "audio": "mp3 wav m4a aac flac ogg wma opus", "document": "doc docx odt rtf pages wpd",
        "spreadsheet": "xls xlsx xlsm csv ods numbers tsv", "slides": "ppt pptx odp key", "pdf": "pdf",
        "archive": "zip rar 7z tar gz tgz bz2 xz iso dmg cab", "text": "txt md log ini cfg conf rst",
        "code": "py js ts jsx tsx html htm css json xml yml yaml sh bat ps1 java c cpp h hpp cs go rs php sql rb kt swift ipynb"}
EXT_CAT = {e: c for c, es in _EXT.items() for e in es.split()}

def category(name, mime=None, kind="file"):
    """Classify by extension first, then by MIME type (upload header or guessed)."""
    if kind == "snippet": return "snippet"
    ext = os.path.splitext(name)[1][1:].lower()
    if ext in EXT_CAT: return EXT_CAT[ext]
    m = (mime or "").split(";")[0].strip().lower()
    if not m or m in ("application/octet-stream", "binary/octet-stream"):
        m = mimetypes.guess_type(name)[0] or ""
    for pre, c in (("video/", "video"), ("image/", "image"), ("audio/", "audio"), ("text/", "text")):
        if m.startswith(pre): return c
    if m == "application/pdf": return "pdf"
    if "zip" in m or "compressed" in m or "tar" in m: return "archive"
    if "spreadsheet" in m or "excel" in m: return "spreadsheet"
    if "presentation" in m or "powerpoint" in m: return "slides"
    if "word" in m or "opendocument.text" in m: return "document"
    if "json" in m or "javascript" in m or "xml" in m: return "code"
    return "other"

def file_cat(f, v=None):
    v = v or f["versions"][-1]
    return category(f["name"], v.get("mime"), f.get("kind", "file"))

# ---------------------------------------------------------------- event log (append-only JSONL)
# e: upload | download | snippet_send | snippet_copy | restore ; u: user; f: file; v: version; b: bytes; c: category
def log_event(e, uid, fid, v, size, cat):
    ev = {"t": round(time.time(), 3), "e": e, "u": uid, "f": fid, "v": v, "b": size, "c": cat}
    with LOCK:
        EVENTS.append(ev)
        with open(dpath("events.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev) + "\n")

def load_events():
    p = dpath("events.jsonl")
    if not os.path.exists(p):           # first run with metrics: backfill uploads from version history
        rows = []
        for fid, f in DB["files"].items():
            for v in f["versions"]:
                if v.get("restored_from") or re.match(r"^restore v\d+$", v.get("note") or ""):
                    continue
                rows.append({"t": v["time"], "e": "snippet_send" if f.get("kind") == "snippet" else "upload",
                             "u": v["by"], "f": fid, "v": v["v"], "b": v["size"], "c": file_cat(f, v), "bf": 1})
        rows.sort(key=lambda r: r["t"])
        with open(p + ".tmp", "w", encoding="utf-8") as fh:
            for r in rows: fh.write(json.dumps(r) + "\n")
        os.replace(p + ".tmp", p)
        if rows: print(f"Backfilled {len(rows)} past upload events into events.jsonl.")
    EVENTS.clear()
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            try: EVENTS.append(json.loads(line))
            except ValueError: pass       # tolerate a torn last line

def period_starts(now=None):
    """Local-time period boundaries; weeks start Monday."""
    d = datetime.datetime.fromtimestamp(now or time.time())
    today = d.replace(hour=0, minute=0, second=0, microsecond=0)
    week = today - datetime.timedelta(days=today.weekday())
    month = today.replace(day=1)
    return {"today": today.timestamp(), "week": week.timestamp(), "month": month.timestamp(), "all": 0}

def my_stats(uid, days=30):
    ps = period_starts(); days = max(7, min(int(days), 90))
    blank = lambda: {"count": 0, "bytes": 0}
    out = {p: {k: blank() for k in ("files_sent", "files_downloaded", "snippets_sent", "snippets_copied")} for p in ps}
    key = {"upload": "files_sent", "download": "files_downloaded", "snippet_send": "snippets_sent", "snippet_copy": "snippets_copied"}
    today = datetime.date.today(); first = today - datetime.timedelta(days=days - 1)
    series = {(first + datetime.timedelta(days=i)).isoformat(): {"sent": 0, "sent_bytes": 0, "down": 0, "down_bytes": 0} for i in range(days)}
    with LOCK:
        evs = [e for e in EVENTS if e["u"] == uid and e["e"] in key]
    for e in evs:
        k = key[e["e"]]
        for p, st in ps.items():
            if e["t"] >= st:
                out[p][k]["count"] += 1; out[p][k]["bytes"] += e["b"]
        day = datetime.date.fromtimestamp(e["t"]).isoformat()
        if day in series:
            s_ = series[day]; side = "sent" if e["e"] in ("upload", "snippet_send") else "down"
            s_[side] += 1; s_[side + "_bytes"] += e["b"]
    return {"periods": out, "series": [dict(day=d, **v) for d, v in series.items()]}

def team_stats(period="month"):
    st = period_starts().get(period, 0)
    cats = {c: {"sent": 0, "sent_bytes": 0, "down": 0, "down_bytes": 0} for c in CATS}
    people = set()
    with LOCK:
        evs = [e for e in EVENTS if e["t"] >= st and e["e"] in ("upload", "snippet_send", "download", "snippet_copy")]
    for e in evs:                       # aggregates only: no names, ids or titles leave this function
        c = cats.setdefault(e.get("c") or "other", {"sent": 0, "sent_bytes": 0, "down": 0, "down_bytes": 0})
        side = "sent" if e["e"] in ("upload", "snippet_send") else "down"
        c[side] += 1; c[side + "_bytes"] += e["b"]; people.add(e["u"])
    tot = {k: sum(c[k] for c in cats.values()) for k in ("sent", "sent_bytes", "down", "down_bytes")}
    return {"period": period if period in ("today", "week", "month", "all") else "all", "categories": cats,
            "totals": dict(tot, active_people=len(people))}

def add_version(uid, name, to, sha, size, note, kind="file", mime=None, fid=None):
    """Add a version to the matching file (same kind + name + audience) or create one. Caller holds LOCK."""
    now = time.time()
    if fid is None:
        key = audience_key({"to": to, "owner": uid})
        fid = next((i for i, f in DB["files"].items() if not f.get("deleted") and can_see(f, uid)
                    and f.get("kind", "file") == kind and f["name"].casefold() == name.casefold()
                    and audience_key(f) == key), None)
    ver = {"sha": sha, "size": size, "by": uid, "time": now, "note": note}
    if mime: ver["mime"] = mime
    if fid:
        f = DB["files"][fid]
        if f["versions"][-1]["sha"] == sha:
            return fid, f, True
        ver["v"] = f["versions"][-1]["v"] + 1; f["versions"].append(ver)
    else:
        fid = secrets.token_hex(8); ver["v"] = 1
        f = DB["files"][fid] = {"name": name, "owner": uid, "to": to, "created": now, "versions": [ver]}
        if kind != "file": f["kind"] = kind
    save("files")
    return fid, f, False

def snippet_text(v, limit=None):
    with open(obj_path(v["sha"]), "rb") as fh:
        raw = fh.read(limit) if limit else fh.read()
    return raw.decode("utf-8", "ignore" if limit else "replace")

# ---------------------------------------------------------------- LAN discovery (UDP)
def discovery_responder(http_port, udp_port=DISCOVERY_PORT):
    """Answer 'BGSHARE_DISCOVER' datagrams so desktop clients can find this server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", udp_port))
    except OSError as e:
        print(f"LAN discovery disabled (UDP {udp_port}: {e})"); return None
    reply = json.dumps({"app": "BGShare", "port": http_port, "host": socket.gethostname(), "proto": 1}).encode()
    def loop():
        while True:
            try:
                data, addr = sock.recvfrom(512)
                if data.strip().startswith(b"BGSHARE_DISCOVER"):
                    sock.sendto(reply, addr)
            except OSError:
                return
    threading.Thread(target=loop, daemon=True, name="discovery").start()
    return sock

# ---------------------------------------------------------------- migration
def migrate_legacy(legacy):
    legacy = os.path.realpath(legacy)
    marker = dpath(".migrated")
    if os.path.exists(marker) or not os.path.isdir(legacy) or legacy == CFG["dir"]:
        return
    names = [n for n in os.listdir(legacy) if os.path.isfile(os.path.join(legacy, n))
             and not n.startswith(".") and not n.endswith((".part", ".tmp"))]
    if not names:
        return
    try:
        with open(os.path.join(legacy, ".lanshare_meta.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
    except Exception:
        meta = {}
    with LOCK:
        sys_uid = find_user("legacy")
        if not sys_uid:   # placeholder owner for old anonymous uploads (cannot log in)
            sys_uid = secrets.token_hex(8)
            DB["users"][sys_uid] = {"name": "legacy", "salt": "", "hash": "!", "created": time.time()}
        n_ok = 0
        for n in names:
            src = os.path.join(legacy, n)
            h = hashlib.sha256(); size = 0
            with open(src, "rb") as fh:
                while True:
                    b = fh.read(CHUNK)
                    if not b: break
                    h.update(b); size += len(b)
            sha = h.hexdigest(); dst = obj_path(sha)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.exists(dst):
                shutil.move(src, dst)
            else:
                os.remove(src)
            m = meta.get(n, {})
            note = "migrated from shared/" + (" (uploaded by %s)" % m["uploader"] if m.get("uploader") else "")
            DB["files"][secrets.token_hex(8)] = {"name": safe_name(n) or "file", "owner": sys_uid, "to": "everyone",
                "created": m.get("time", time.time()), "versions": [{"v": 1, "sha": sha, "size": size, "by": sys_uid,
                "time": m.get("time", time.time()), "note": note}]}
            n_ok += 1
        save("users"); save("files")
        with open(marker, "w") as fh:
            fh.write(time.ctime())
    print(f"Migrated {n_ok} file(s) from {legacy} (originals moved into the version store).")

def lan_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # UDP connect sends nothing. 192.0.2.1 is the RFC 5737 documentation address, used only so the OS names this PC's LAN address.
        s.connect(("192.0.2.1", 1)); ips.add(s.getsockname()[0]); s.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    ips = {i for i in ips if not i.startswith("127.")}
    return sorted(ips) or ["127.0.0.1"]

# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BGShare/2.0"

    def log_message(self, fmt, *a):
        if sys.stderr:                      # None inside a windowed (no console) desktop build
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % a))

    def send_json(self, code, obj, extra=()):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        for k, v in extra: self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def err(self, code, msg):
        return self.send_json(code, {"error": msg})

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536: raise ValueError("too large")
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def uid(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "ls_session":
                s = DB["sessions"].get(v)
                if s and s["exp"] > time.time() and s["uid"] in DB["users"]:
                    return s["uid"]
        return None

    def get_file(self, fid, uid, allow_deleted=False):
        """Return file record if it exists AND uid may see it, else None (-> 404, no info leak)."""
        if not ID_RE.match(fid or ""): return None
        f = DB["files"].get(fid)
        if not f or not can_see(f, uid): return None
        if f.get("deleted") and not (allow_deleted and uid == f["owner"]): return None
        return f

    def route(self):
        u = urlparse(self.path)
        return u.path.rstrip("/") or "/", {k: v[-1] for k, v in parse_qs(u.query).items()}

    # ---------------- GET
    def do_HEAD(self): self.do_GET(head=True)

    def do_GET(self, head=False):
        path, q = self.route()
        if path == "/":
            b = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            if not head: self.wfile.write(b)
            return
        if path == "/favicon.svg":
            b = FAVICON.encode(); self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml"); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); return None if head else self.wfile.write(b)
        if path == "/api/config":
            return self.send_json(200, {"needs_code": bool(CFG["password"])})
        uid = self.uid()
        if not uid: return self.err(401, "sign in required")
        if path == "/api/me":
            with LOCK:
                ul = unread_list(uid)
            return self.send_json(200, {"id": uid, "name": DB["users"][uid]["name"], "unseen": len(ul), "unread": ul})
        if path == "/api/users":
            return self.send_json(200, sorted([{"id": i, "name": u["name"], "you": i == uid,
                                               "joined": u.get("created", 0)} for i, u in DB["users"].items()
                                              if u["hash"] != "!"], key=lambda x: x["name"].casefold()))
        if path == "/api/files":
            view = q.get("view", "everyone")
            out = []
            with LOCK:
                for fid, f in DB["files"].items():
                    if not can_see(f, uid): continue
                    dele = f.get("deleted", False)
                    if view == "archive":
                        ok = dele and f["owner"] == uid
                    elif dele:
                        ok = False
                    elif view == "inbox":
                        ok = f["to"] != "everyone" and (uid in f["to"] or in_inbox(f, uid))
                    elif view == "sent":
                        ok = f["owner"] == uid
                    elif view == "snippets":
                        ok = f.get("kind") == "snippet"
                    else:
                        ok = f["to"] == "everyone"
                    if ok: out.append(file_view(fid, f, uid))
            out.sort(key=lambda x: -x["time"])
            return self.send_json(200, out)
        if path == "/api/stats/me":
            return self.send_json(200, my_stats(uid, q.get("days") or 30))
        if path == "/api/stats/team":
            return self.send_json(200, team_stats(q.get("period", "month")))
        m = re.match(r"^/api/snippets/([^/]+)$", path)
        if m:
            f = self.get_file(m.group(1), uid, allow_deleted=True)
            if not f or f.get("kind") != "snippet": return self.err(404, "not found")
            v = self.version_of(f, q)
            if not v: return self.err(404, "no such version")
            if v["v"] == f["versions"][-1]["v"]: mark_read(m.group(1), f, uid)
            return self.send_json(200, {"id": m.group(1), "title": f["name"], "version": v["v"], "text": snippet_text(v)})
        m = re.match(r"^/api/files/([^/]+)/(history|diff)$", path)
        if m:
            f = self.get_file(m.group(1), uid, allow_deleted=True)
            if not f: return self.err(404, "not found")
            nm = lambda i: DB["users"].get(i, {}).get("name", "?")
            if m.group(2) == "history":
                mark_read(m.group(1), f, uid)          # opening the file's panel counts as read
                return self.send_json(200, {"file": file_view(m.group(1), f, uid), "versions": [
                    dict(v, by_name=nm(v["by"])) for v in reversed(f["versions"])]})
            return self.diff(f, q)
        m = re.match(r"^/f/([^/]+)(?:/.*)?$", path)
        if m:
            return self.serve(m.group(1), uid, q, head)
        self.err(404, "not found")

    def version_of(self, f, q):
        try:
            n = int(q.get("v") or f["versions"][-1]["v"])
        except ValueError:
            return None
        return next((v for v in f["versions"] if v["v"] == n), None)

    def diff(self, f, q):
        a = self.version_of(f, {"v": q.get("a")}); b = self.version_of(f, {"v": q.get("b")})
        if not a or not b: return self.err(400, "pick two valid versions")
        texts = []
        for v in (a, b):
            if v["size"] > 4 * 1024 * 1024: return self.err(415, "file too large to diff (4 MB limit)")
            with open(obj_path(v["sha"]), "rb") as fh: raw = fh.read()
            if b"\x00" in raw[:8192]: return self.err(415, "binary file - diff only works for text")
            try: texts.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                try: texts.append(raw.decode("cp1252"))
                except UnicodeDecodeError: return self.err(415, "not a text file")
        d = "".join(difflib.unified_diff(texts[0].splitlines(True), texts[1].splitlines(True),
                                         f"{f['name']} v{a['v']}", f"{f['name']} v{b['v']}", n=3))
        return self.send_json(200, {"a": a["v"], "b": b["v"], "diff": d or "(no differences)"})

    def serve(self, fid, uid, q, head):
        f = self.get_file(fid, uid, allow_deleted=True)
        if not f: return self.err(404, "not found")
        v = self.version_of(f, q)
        if not v: return self.err(404, "no such version")
        p = obj_path(v["sha"]); size = os.path.getsize(p)
        start, end, partial = 0, size - 1, False
        rng = self.headers.get("Range")
        if rng:
            mm = re.match(r"bytes=(\d*)-(\d*)$", rng.strip())
            bad = not mm or (mm.group(1) == "" and mm.group(2) == "")
            if not bad:
                if mm.group(1) == "": start = max(0, size - int(mm.group(2)))
                else:
                    start = int(mm.group(1))
                    if mm.group(2): end = min(int(mm.group(2)), size - 1)
                bad = start >= size or start > end
            if bad:
                self.send_response(416); self.send_header("Content-Range", f"bytes */{size}")
                self.send_header("Content-Length", "0"); self.end_headers(); return
            partial = True
        length = end - start + 1 if size else 0
        name = f["name"]
        if v["v"] != f["versions"][-1]["v"]:
            b_, e_ = os.path.splitext(name); name = f"{b_} (v{v['v']}){e_}"
        self.send_response(206 if partial else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("ETag", '"%s"' % v["sha"])
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(name))
        if partial: self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        if not head and v["v"] == f["versions"][-1]["v"]:
            mark_read(fid, f, uid)
        if head or length == 0: return
        self.wfile.flush()
        sent = 0
        with open(p, "rb") as fh:
            try:
                sent = self.connection.sendfile(fh, start, length) or 0   # zero-copy where the OS supports it
            except (AttributeError, OSError, ValueError):
                fh.seek(start + sent); left = length - sent
                while left > 0:
                    buf = fh.read(min(CHUNK, left))
                    if not buf: break
                    self.wfile.write(buf); left -= len(buf); sent += len(buf)
        # metrics: a full 200, or the final piece of a resumed download (open-ended "bytes=N-" range)
        resumed_tail = partial and start > 0 and end == size - 1 and re.match(r"bytes=\d+-$", (rng or "").strip())
        if sent == length and (not partial or resumed_tail):
            log_event("download", uid, fid, v["v"], size, file_cat(f, v))

    # ---------------- POST / PUT
    def do_POST(self):
        path, q = self.route()
        if path in ("/api/signup", "/api/login"):
            d = self.read_json()
            name = re.sub(r"\s+", " ", str(d.get("name", ""))).strip()[:40]
            pw = str(d.get("pin", ""))
            if path == "/api/signup":
                if CFG["password"] and not hmac.compare_digest(str(d.get("code", "")).encode(), CFG["password"].encode()):
                    return self.err(403, "wrong office code")
                if len(name) < 2 or not re.match(r"^[\w .'-]+$", name):
                    return self.err(400, "name must be 2-40 letters/numbers")
                if len(pw) < 4: return self.err(400, "PIN/password must be at least 4 characters")
                with LOCK:
                    if find_user(name): return self.err(409, "that name is taken")
                    uid = secrets.token_hex(8); salt, h = hash_pw(pw)
                    DB["users"][uid] = {"name": name, "salt": salt, "hash": h, "created": time.time(), "read": {}}
                    save("users")
            else:
                uid = find_user(name)
                u = DB["users"].get(uid) if uid else None
                ok = bool(u and u["hash"] != "!" and
                          hmac.compare_digest(hash_pw(pw, bytes.fromhex(u["salt"]))[1], u["hash"]))
                if not ok:
                    time.sleep(0.5); return self.err(401, "wrong name or PIN")
            tok = new_session(uid)
            return self.send_json(200, {"id": uid, "name": DB["users"][uid]["name"]}, [("Set-Cookie",
                f"ls_session={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_DAYS*86400}")])
        if path == "/api/logout":
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "ls_session":
                    with LOCK:
                        if DB["sessions"].pop(v, None): save("sessions")
            return self.send_json(200, {"ok": True}, [("Set-Cookie", "ls_session=; Path=/; Max-Age=0")])
        uid = self.uid()
        if not uid: return self.err(401, "sign in required")
        m = re.match(r"^/api/files/([^/]+)/read$", path)
        if m:
            f = self.get_file(m.group(1), uid)
            if not f: return self.err(404, "not found")
            mark_read(m.group(1), f, uid)
            return self.send_json(200, {"ok": True})
        if path == "/api/upload":
            return self.upload(uid, q)
        if path == "/api/device-token":       # desktop app: a separate session it can poll /api/me with
            return self.send_json(200, {"token": new_session(uid), "id": uid, "name": DB["users"][uid]["name"]})
        if path == "/api/snippets":
            return self.snippet(uid)
        m = re.match(r"^/api/files/([^/]+)/copied$", path)
        if m:
            f = self.get_file(m.group(1), uid)
            if not f or f.get("kind") != "snippet": return self.err(404, "not found")
            v = f["versions"][-1]; mark_read(m.group(1), f, uid)
            log_event("snippet_copy", uid, m.group(1), v["v"], v["size"], "snippet")
            return self.send_json(200, {"ok": True})
        m = re.match(r"^/api/files/([^/]+)/restore$", path)
        if m:
            with LOCK:
                f = self.get_file(m.group(1), uid)
                if not f: return self.err(404, "not found")
                v = self.version_of(f, q)
                if not v: return self.err(404, "no such version")
                nv = {"v": f["versions"][-1]["v"] + 1, "sha": v["sha"], "size": v["size"], "by": uid,
                      "time": time.time(), "note": (q.get("note") or f"restore v{v['v']}")[:140], "restored_from": v["v"]}
                if v.get("mime"): nv["mime"] = v["mime"]
                f["versions"].append(nv); save("files")
            log_event("restore", uid, m.group(1), nv["v"], 0, file_cat(f, nv))      # not counted as an upload
            return self.send_json(200, {"id": m.group(1), "version": nv["v"]})
        self.err(404, "not found")

    do_PUT = do_POST

    @staticmethod
    def parse_to(uid, to_raw):
        to_raw = (to_raw or "everyone").strip()
        if to_raw == "everyone": return "everyone"
        to = sorted({t for t in to_raw.split(",") if t and t != uid})
        if not to or any(t not in DB["users"] or DB["users"][t]["hash"] == "!" for t in to):
            return None
        return to

    def snippet(self, uid):
        n = int(self.headers.get("Content-Length") or 0)
        if n > SNIPPET_MAX * 6 + 65536:           # JSON-escaped text can be larger than the raw text
            self.close_connection = True; return self.err(413, "snippet too large (1 MB max)")
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self.err(400, "bad JSON")
        text = d.get("text")
        if not isinstance(text, str) or not text.strip(): return self.err(400, "snippet text is empty")
        raw = text.encode("utf-8")
        if len(raw) > SNIPPET_MAX: return self.err(413, "snippet too large (1 MB max)")
        note = str(d.get("note") or "")[:140]
        fid = d.get("id")
        with LOCK:
            if fid:                                 # edit = new version of an existing snippet
                f = self.get_file(str(fid), uid)
                if not f or f.get("kind") != "snippet": return self.err(404, "not found")
                title, to = f["name"], f["to"]
            else:
                title = re.sub(r"[\x00-\x1f]", " ", str(d.get("title") or "")).strip()[:120]
                if not title:
                    title = (text.strip().splitlines() or ["Snippet"])[0][:60] or "Snippet"
                to = self.parse_to(uid, ",".join(d["to"]) if isinstance(d.get("to"), list) else d.get("to"))
                if to is None: return self.err(400, "unknown recipient")
            sha = hashlib.sha256(raw).hexdigest()
            tmp = dpath("tmp", secrets.token_hex(12) + ".part")
            with open(tmp, "wb") as fh: fh.write(raw)
            store_blob(tmp, sha)
            fid, f, unchanged = add_version(uid, title, to, sha, len(raw), note, "snippet", "text/plain", fid=fid)
        if not unchanged:
            log_event("snippet_send", uid, fid, f["versions"][-1]["v"], len(raw), "snippet")
        return self.send_json(200 if unchanged else 201, {"id": fid, "title": f["name"], "version": f["versions"][-1]["v"],
                                                          "size": len(raw), "unchanged": unchanged})

    def upload(self, uid, q):
        name = safe_name(q.get("name", ""))
        if not name: return self.err(400, "invalid file name")
        to = self.parse_to(uid, q.get("to"))
        if to is None: return self.err(400, "unknown recipient")
        mime = (self.headers.get("Content-Type") or "").split(";")[0].strip()[:100]
        if mime in ("", "application/octet-stream", "application/x-www-form-urlencoded"): mime = None
        note = q.get("note", "")[:140]
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.err(411, "Content-Length required")
        os.makedirs(dpath("tmp"), exist_ok=True)
        tmp = dpath("tmp", secrets.token_hex(12) + ".part")
        h = hashlib.sha256(); left = length
        try:
            with open(tmp, "wb", buffering=0) as fh:
                buf = bytearray(CHUNK); mv = memoryview(buf)
                while left > 0:
                    n = self.rfile.readinto(mv[:min(CHUNK, left)])
                    if not n: break
                    h.update(mv[:n]); fh.write(mv[:n]); left -= n
            if left:
                os.remove(tmp); self.close_connection = True
                return self.err(400, "incomplete upload")
            sha = h.hexdigest()
            with LOCK:
                store_blob(tmp, sha)
                fid, f, unchanged = add_version(uid, name, to, sha, length, note, "file", mime)
            if not unchanged:
                log_event("upload", uid, fid, f["versions"][-1]["v"], length, file_cat(f))
        except Exception as e:
            try: os.remove(tmp)
            except OSError: pass
            self.close_connection = True
            return self.err(500, str(e))
        self.send_json(200 if unchanged else 201, {"id": fid, "name": f["name"], "version": f["versions"][-1]["v"],
                                                   "sha256": sha, "size": length, "unchanged": unchanged})

    def do_DELETE(self):
        path, q = self.route()
        uid = self.uid()
        if not uid: return self.err(401, "sign in required")
        m = re.match(r"^/api/files/([^/]+)$", path)
        if not m: return self.err(404, "not found")
        with LOCK:
            f = self.get_file(m.group(1), uid)
            if not f: return self.err(404, "not found")
            if f["owner"] != uid: return self.err(403, "only the sender can delete this file")
            f["deleted"] = True; f["deleted_at"] = time.time(); save("files")   # history kept on disk
        self.send_json(200, {"deleted": m.group(1), "archived": True})

# ---------------------------------------------------------------- UI
LOGO_PNG_B64 = "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"   # official logo from bluegiraffedev.com/assets/blue-giraffe-official.png (cropped, 400px)
FAVICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#1264d8"/><text x="32" y="41" text-anchor="middle" font-family="Arial,sans-serif" font-size="26" font-weight="700" fill="white">BG</text></svg>'      # bluegiraffedev.com/assets/favicon.svg

PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>BGShare · Blue Giraffe</title><link rel=icon id=favicon href="/favicon.svg"><meta name=theme-color content="#075ce5">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap" rel=stylesheet>
<style>
:root{--blue:#075ce5;--blue-d:#0549b8;--ink:#102c4a;--muted:#617487;--faint:#8294a5;--gold:#ffc953;--gold-soft:#fff5d6;--paper:#fafcff;--line:#dce7f1;--soft:#edf5ff;--ok:#23a988;--bad:#bc3d3d;
--r-sm:10px;--r-md:14px;--r-lg:20px;--r-xl:27px;--shadow:0 20px 60px #16446e0b;--shadow-pop:0 35px 100px #102c4a33;--ease:cubic-bezier(.2,.7,.2,1)}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 "DM Sans",system-ui,-apple-system,"Segoe UI",sans-serif}
button,input,select{font:inherit;color:inherit}button{cursor:pointer}h1,h2,h3{font-family:Manrope,"DM Sans",system-ui,sans-serif;margin:0;letter-spacing:-.03em}
a{color:var(--blue)}.hidden{display:none!important}.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
:focus{outline:none}:focus-visible{outline:3px solid #075ce555;outline-offset:2px;border-radius:8px}
.eyebrow{font-size:10.5px;letter-spacing:.15em;color:var(--blue);font-weight:700;margin:0 0 10px;text-transform:uppercase}
.wrap{width:min(1180px,calc(100% - 40px));margin:auto}
/* header */
header.top{height:84px;display:flex;align-items:center;gap:18px;border-bottom:1px solid var(--line)}
header.top>img{width:132px;height:62px;object-fit:contain}
.product{border-left:1px solid var(--line);padding-left:18px;display:flex;flex-direction:column;line-height:1.25}.product b{font:800 18px Manrope}.product span{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.hdr-actions{margin-left:auto;display:flex;align-items:center;gap:10px}
.online{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-right:6px;white-space:nowrap}.online i{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--ok);margin-right:7px;box-shadow:0 0 0 4px #23a98817;vertical-align:1px}
.online.off i{background:var(--bad);box-shadow:0 0 0 4px #bc3d3d17}
.ghost{border:1px solid var(--line);background:#fff;border-radius:999px;padding:9px 15px;font-size:13px;display:inline-flex;align-items:center;gap:7px;transition:.2s var(--ease)}.ghost:hover{border-color:#b9cde3;background:var(--soft)}
.ghost svg{width:16px;height:16px}.icon-btn{width:38px;height:38px;padding:0;justify-content:center}
.avatar{width:38px;height:38px;border:0;border-radius:50%;background:var(--blue);color:#fff;font:700 13px Manrope;display:grid;place-items:center;flex:none}
/* hero */
.hero{padding:56px 0 38px;display:grid;grid-template-columns:1fr 270px;align-items:end;gap:48px}
.hero h1{font-size:clamp(38px,5.6vw,68px);line-height:1.03;letter-spacing:-.055em}.hero h1 span{color:var(--blue)}
.hero p.lead{color:var(--muted);line-height:1.8;max-width:580px;font-size:16px;margin:16px 0 0}
.who{background:var(--soft);border:1px solid #d6e6fb;border-radius:var(--r-lg);padding:22px;display:flex;flex-direction:column}
.who small{font-size:9.5px;letter-spacing:.12em;color:var(--muted)}.who strong{font:700 21px Manrope;margin:8px 0 2px;letter-spacing:-.02em}.who span{font-size:12px;color:var(--blue)}
.who .stat{display:flex;gap:18px;margin-top:14px;padding-top:14px;border-top:1px solid #d6e6fb;font-size:12px;color:var(--muted)}.who .stat b{display:block;font:700 18px Manrope;color:var(--ink)}
/* banner */
.banner{display:flex;align-items:center;gap:14px;background:#fff;border:1px solid var(--line);border-left:4px solid var(--gold);border-radius:var(--r-md);padding:14px 18px;margin-bottom:22px;box-shadow:var(--shadow)}
.banner p{margin:0;flex:1;font-size:14px;color:var(--muted)}.banner p b{color:var(--ink)}
/* composer */
.card{background:#fff;border:1px solid var(--line);border-radius:var(--r-xl);padding:32px;box-shadow:var(--shadow)}
.send-head,.title-row,.modal-head{display:flex;justify-content:space-between;align-items:flex-end;gap:24px}
.send-head h2,.title-row h2{font-size:26px;letter-spacing:-.04em}
.field-label{font-size:11px;color:var(--muted);font-weight:600;display:block;margin-bottom:8px}.field-label span{font-weight:400}
.chips{display:flex;flex-wrap:wrap;gap:7px;justify-content:flex-end}
.chip{border:1px solid #cbdbea;border-radius:999px;padding:7px 13px;font-size:13px;background:var(--paper);display:inline-flex;align-items:center;gap:7px;transition:.15s var(--ease)}
.chip:hover{border-color:var(--blue)}.chip[aria-pressed=true]{background:var(--blue);border-color:var(--blue);color:#fff}
.chip .mini{width:20px;height:20px;border-radius:50%;background:var(--soft);color:var(--blue);font:700 10px Manrope;display:grid;place-items:center}.chip[aria-pressed=true] .mini{background:#ffffff2e;color:#fff}
.dropzone{margin-top:24px;min-height:210px;border:1.5px dashed #9cbce4;border-radius:var(--r-lg);background:#f7faff;display:flex;align-items:center;justify-content:center;gap:22px;transition:.2s var(--ease);padding:26px;cursor:pointer;position:relative}
.dropzone:hover,.dropzone:focus-visible{background:var(--soft);border-color:var(--blue);transform:translateY(-2px)}
.dropzone.dragging{background:#e3efff;border:2px solid var(--blue);transform:scale(1.01);box-shadow:0 0 0 6px #075ce514}
.dropzone.dragging .up-ic{transform:translateY(-6px) scale(1.06);box-shadow:0 14px 30px #075ce544}
.dropzone.dragging h3::after{content:" — release to send"}
.up-ic{width:58px;height:58px;border-radius:50%;background:var(--blue);color:#fff;display:grid;place-items:center;transition:.25s var(--ease);flex:none}.up-ic svg{width:26px;height:26px}
.dropzone h3{font-size:21px}.dropzone p{margin:4px 0 0;color:var(--muted)}.dropzone p u{color:var(--blue)}.dropzone small{margin-left:34px;color:var(--faint);font-size:11px;max-width:170px}
.note-row{display:grid;grid-template-columns:170px 1fr;align-items:center;margin-top:16px}
.note-row input{border:0;border-bottom:1px solid var(--line);padding:12px 3px;background:transparent;transition:.2s}.note-row input:focus{border-color:var(--blue);outline:none}
/* uploads */
.section{padding-top:52px}.title-row .count{font-size:12px;color:var(--muted)}
.upload-row{background:#fff;border:1px solid var(--line);border-radius:var(--r-md);padding:14px 16px;margin-top:10px;display:grid;grid-template-columns:40px 1fr auto;gap:14px;align-items:center;animation:rise .3s var(--ease)}
.upload-row .nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.upload-row .st{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.upload-row .pct{font:700 15px Manrope;color:var(--blue);font-variant-numeric:tabular-nums}
.progress{height:4px;background:var(--soft);border-radius:4px;margin-top:9px;overflow:hidden}.progress i{display:block;height:100%;background:var(--blue);width:0;border-radius:4px;transition:width .2s linear}
.upload-row.done .progress i{background:var(--ok)}.upload-row.fail .progress i{background:var(--bad);width:100%!important}.upload-row.done .pct{color:var(--ok)}.upload-row.fail .pct{color:var(--bad)}
/* tabs / filters */
.filters{display:flex;gap:4px;background:var(--soft);border-radius:999px;padding:4px}
.filters button{border:0;background:transparent;padding:9px 15px;border-radius:999px;font-size:12.5px;color:var(--muted);font-weight:600;display:inline-flex;gap:7px;align-items:center;white-space:nowrap;transition:.15s}
.filters button:hover{color:var(--ink)}.filters button[aria-selected=true]{background:#fff;color:var(--blue);box-shadow:0 2px 8px #174b7b12}
.badge{min-width:19px;height:19px;padding:0 6px;border-radius:999px;background:var(--gold);color:var(--ink);font:700 11px Manrope;display:inline-grid;place-items:center}
.badge.pop{animation:pop .45s var(--ease)}
/* file list */
.file-list{border-top:1px solid var(--line);margin-top:22px}
.file-row{display:grid;grid-template-columns:46px minmax(160px,1fr) 170px 128px auto;gap:18px;align-items:center;padding:16px 10px;border-bottom:1px solid var(--line);border-radius:12px;transition:background .2s;position:relative}
.file-row:hover{background:#f5f9ff}
.file-row.unread{background:linear-gradient(90deg,#fff9e6,#fff 60%)}.file-row.unread::before{content:"";position:absolute;left:-2px;top:16px;bottom:16px;width:3px;border-radius:3px;background:var(--gold)}
.file-row.unread .file-name::after{content:"New";margin-left:8px;font:700 9.5px Manrope;letter-spacing:.08em;text-transform:uppercase;color:#7a5a08;background:var(--gold-soft);padding:2px 7px;border-radius:999px;vertical-align:2px}
.ftype{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;position:relative;flex:none}.ftype svg{width:22px;height:22px}
.ftype em{position:absolute;bottom:-5px;right:-6px;font:700 8.5px Manrope;font-style:normal;background:#fff;border:1px solid var(--line);border-radius:5px;padding:0 4px;color:var(--muted);letter-spacing:.03em}
.file-name{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.meta{font-size:12px;color:var(--muted);margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.meta q{font-style:italic;color:var(--ink);quotes:"“" "”"}
.aud{font-size:11.5px;padding:7px 11px;border-radius:999px;background:var(--gold-soft);color:#7a5a08;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;justify-self:start;max-width:100%}.aud.all{background:var(--soft);color:var(--blue)}
.ver-btn{border:0;background:none;color:var(--blue);font-size:12px;font-weight:600;padding:6px 4px;text-align:left}.ver-btn:hover{text-decoration:underline}
.row-actions{display:flex;gap:7px;justify-content:flex-end}
.btn{border:0;border-radius:9px;padding:10px 14px;text-decoration:none;background:var(--blue);color:#fff;font-weight:600;font-size:12.5px;display:inline-flex;align-items:center;gap:7px;transition:.15s var(--ease);white-space:nowrap}
.btn:hover{background:var(--blue-d);transform:translateY(-1px)}.btn svg{width:15px;height:15px}
.btn.soft{background:var(--soft);color:var(--blue)}.btn.soft:hover{background:#dfecff}.btn.plain{background:#edf2f6;color:var(--muted)}.btn.plain:hover{background:#fdecec;color:var(--bad)}
.btn.wide{width:100%;justify-content:space-between;padding:14px 16px;font-size:14px}.btn.danger{background:var(--bad)}
.empty{text-align:center;padding:64px 20px;color:var(--muted)}.empty .art{width:76px;height:76px;margin:0 auto 16px;border-radius:24px;background:var(--soft);display:grid;place-items:center;color:var(--blue)}.empty .art svg{width:34px;height:34px}
.empty b{display:block;color:var(--ink);font:700 19px Manrope;margin-bottom:6px;letter-spacing:-.02em}
.skeleton{height:68px;border-bottom:1px solid var(--line);background:linear-gradient(90deg,#f3f7fc 25%,#e9f1fa 50%,#f3f7fc 75%);background-size:200% 100%;animation:shimmer 1.2s infinite}
footer{border-top:1px solid var(--line);margin-top:70px;height:92px;display:flex;align-items:center;justify-content:space-between;color:var(--muted);font-size:11px;gap:12px}footer b{color:var(--blue)}
/* dialogs */
dialog{border:1px solid var(--line);border-radius:24px;background:#fff;color:var(--ink);padding:30px;width:min(620px,calc(100% - 28px));max-height:calc(100vh - 40px);box-shadow:var(--shadow-pop)}
dialog[open]{animation:dlg .25s var(--ease)}dialog::backdrop{background:#0b2842b3;backdrop-filter:blur(7px)}
.modal-head{align-items:flex-start}.modal-head h2{font-size:24px;word-break:break-word}.modal-head .sub{color:var(--muted);font-size:13px;margin-top:4px}
.close{border:0;background:var(--soft);border-radius:50%;width:36px;height:36px;display:grid;place-items:center;flex:none;transition:.15s}.close:hover{background:#dfecff}.close svg{width:16px;height:16px}
#hist{width:min(780px,calc(100% - 28px))}
.vlist{margin-top:18px}.vrow{display:grid;grid-template-columns:26px 54px 1fr auto;gap:14px;padding:15px 4px;border-top:1px solid var(--line);align-items:center}
.vrow input{width:17px;height:17px;accent-color:var(--blue)}.vnum{font:800 18px Manrope;color:var(--blue)}.vrow.latest .vnum::after{content:"latest";display:block;font:600 9px "DM Sans";color:var(--ok);text-transform:uppercase;letter-spacing:.1em}
.vrow p{margin:3px 0 0;color:var(--muted);font-size:12px}.vrow code{font-size:11px;background:var(--paper);border:1px solid var(--line);padding:1px 6px;border-radius:6px;color:var(--muted)}
.vrow .acts{display:flex;gap:6px}
.diffbar{display:flex;align-items:center;gap:12px;justify-content:space-between;margin-top:6px;padding:14px;background:var(--soft);border-radius:var(--r-md);font-size:13px;color:var(--muted)}
.diff{margin-top:14px;border:1px solid var(--line);border-radius:var(--r-md);overflow:auto;max-height:46vh;font:12.5px/1.6 ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;background:#fff}
.diff div{padding:0 14px;white-space:pre}.diff .a{background:#e8f7f1;color:#0d6b52}.diff .d{background:#fdeeee;color:#9a2f2f}.diff .h{background:var(--soft);color:var(--blue);font-weight:600}.diff .f{color:var(--muted);background:var(--paper)}
.diff .msg{padding:22px;text-align:center;color:var(--muted);white-space:normal}
/* auth */
.auth-wrap{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(1100px 500px at 50% -10%,#e6f0ff,transparent)}
.auth{width:min(430px,100%);text-align:center;padding:36px 32px}.auth>img{width:170px;height:84px;object-fit:contain;margin:-6px auto 14px;display:block}
.auth h2{font-size:28px}.auth>p.copy{color:var(--muted);margin:8px 0 6px}
.seg{display:flex;gap:4px;background:var(--soft);border-radius:999px;padding:4px;margin:20px 0 6px}.seg button{flex:1;border:0;background:transparent;padding:9px;border-radius:999px;font-size:13px;font-weight:600;color:var(--muted)}.seg button[aria-selected=true]{background:#fff;color:var(--blue);box-shadow:0 2px 8px #174b7b12}
.auth label{display:block;text-align:left;font-size:11.5px;font-weight:600;margin-top:16px}
.auth input{display:block;width:100%;margin-top:7px;border:1px solid #ccdbea;border-radius:var(--r-sm);padding:13px;background:var(--paper);transition:.15s}.auth input:focus{border-color:var(--blue);box-shadow:0 0 0 4px #075ce51a;outline:none}
.auth .btn.wide{margin-top:22px}.auth .err{display:block;color:var(--bad);margin-top:12px;min-height:20px;font-size:13px}
.auth .foot{font-size:11px;color:var(--faint);margin-top:6px}
/* people */
.prow{display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}.prow .avatar{width:34px;height:34px;font-size:12px;background:var(--soft);color:var(--blue)}.prow .you{font-size:11px;color:var(--blue);margin-left:auto}.prow p{margin:0;font-size:12px;color:var(--muted)}
/* toast */
#toasts{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);display:flex;flex-direction:column;gap:8px;align-items:center;z-index:50;width:min(440px,calc(100% - 28px));pointer-events:none}
.toast{background:var(--ink);color:#fff;padding:12px 16px;border-radius:12px;box-shadow:0 14px 40px #102c4a40;font-size:13.5px;display:flex;gap:10px;align-items:center;animation:rise .3s var(--ease);pointer-events:auto;width:100%}
.toast.new{background:#fff;color:var(--ink);border:1px solid var(--line);border-left:4px solid var(--gold)}.toast.new b{color:var(--blue)}.toast.bad{background:var(--bad)}
.toast .ti{width:30px;height:30px;border-radius:9px;background:var(--soft);color:var(--blue);display:grid;place-items:center;flex:none}.toast .ti svg{width:16px;height:16px}.toast span{flex:1}
.toast.out{opacity:0;transform:translateY(8px);transition:.25s}
/* composer modes + snippets */
.mode{display:inline-flex;gap:4px;background:var(--soft);border-radius:999px;padding:4px;margin-bottom:14px}.mode button{border:0;background:transparent;padding:7px 14px;border-radius:999px;font-size:12.5px;font-weight:600;color:var(--muted);display:inline-flex;gap:6px;align-items:center}
.mode button svg{width:15px;height:15px}.mode button[aria-selected=true]{background:#fff;color:var(--blue);box-shadow:0 2px 8px #174b7b12}
.snip-form{margin-top:24px;display:grid;gap:12px}.snip-form input,.snip-form textarea{width:100%;border:1px solid #ccdbea;border-radius:var(--r-md);padding:13px 14px;background:var(--paper);transition:.15s}
.snip-form input:focus,.snip-form textarea:focus{border-color:var(--blue);box-shadow:0 0 0 4px #075ce51a;outline:none;background:#fff}
.snip-form textarea{min-height:190px;resize:vertical;font:13px/1.6 ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;tab-size:4}
.snip-foot{display:flex;align-items:center;gap:12px;justify-content:space-between;flex-wrap:wrap}.snip-foot .meter{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}.snip-foot .meter.over{color:var(--bad);font-weight:600}
.editing{display:flex;align-items:center;gap:10px;background:var(--gold-soft);color:#7a5a08;border-radius:var(--r-sm);padding:10px 14px;font-size:13px}.editing b{color:var(--ink)}.editing button{margin-left:auto}
.chips.locked{opacity:.55;pointer-events:none}
.file-row.snippet{grid-template-areas:"ic main aud ver act" "sn sn sn sn sn"}.file-row.snippet>.ftype{grid-area:ic}.file-row.snippet>.mainc{grid-area:main}.file-row.snippet>.aud{grid-area:aud}.file-row.snippet>.ver-btn{grid-area:ver}.file-row.snippet>.row-actions{grid-area:act}.file-row.snippet>.snip{grid-area:sn}
.snip{position:relative;margin:4px 0 2px 64px}.snip pre{margin:0;background:#0f2238;color:#dce7f1;border-radius:var(--r-md);padding:14px 16px;font:12.5px/1.6 ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;white-space:pre-wrap;word-break:break-word;max-height:168px;overflow:hidden;transition:max-height .3s var(--ease)}
.snip.open pre{max-height:60vh;overflow:auto}.snip.long:not(.open)::after{content:"";position:absolute;left:0;right:0;bottom:0;height:56px;border-radius:0 0 var(--r-md) var(--r-md);background:linear-gradient(transparent,#0f2238);pointer-events:none}
.snip .more{position:absolute;right:10px;bottom:10px;z-index:2;border:0;background:#ffffff1f;color:#fff;border-radius:999px;padding:6px 12px;font-size:12px;font-weight:600;backdrop-filter:blur(4px)}.snip .more:hover{background:#ffffff33}
.btn.copied{background:var(--ok)}
/* dashboards */
.dash-head{display:flex;justify-content:space-between;align-items:center;gap:16px;margin:22px 0 18px;flex-wrap:wrap}.dash-head p{margin:0;color:var(--muted);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.kpi{background:#fff;border:1px solid var(--line);border-radius:var(--r-lg);padding:18px 20px;box-shadow:var(--shadow)}
.kpi .k{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--muted);font-weight:600}.kpi .k i{width:26px;height:26px;border-radius:8px;display:grid;place-items:center;background:var(--soft);color:var(--blue)}.kpi .k i svg{width:15px;height:15px}
.kpi .n{font:800 30px Manrope;letter-spacing:-.04em;margin-top:10px;font-variant-numeric:tabular-nums}.kpi .b{font-size:12.5px;color:var(--muted)}
.chart-card{margin-top:16px;background:#fff;border:1px solid var(--line);border-radius:var(--r-lg);padding:20px 22px;box-shadow:var(--shadow)}
.chart-card h3{font-size:16px}.legend{display:flex;gap:16px;font-size:12px;color:var(--muted);flex-wrap:wrap}.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.chart-top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap}
svg.bars{width:100%;height:220px;display:block}svg.bars text{font:10.5px "DM Sans",sans-serif;fill:var(--faint)}svg.bars rect{transition:opacity .15s}svg.bars rect:hover{opacity:.75}
.team-grid{display:grid;grid-template-columns:320px 1fr;gap:16px;margin-top:16px}.donut-wrap{display:grid;place-items:center;position:relative}.donut-c{position:absolute;text-align:center}.donut-c b{display:block;font:800 26px Manrope;letter-spacing:-.03em}.donut-c span{font-size:11.5px;color:var(--muted)}
.cat-row{display:grid;grid-template-columns:150px 1fr 150px;gap:14px;align-items:center;padding:10px 0;border-bottom:1px solid var(--line);font-size:13px}.cat-row:last-child{border-bottom:0}
.cat-row .cn{display:flex;align-items:center;gap:9px;font-weight:600}.cat-row .dot{width:10px;height:10px;border-radius:3px;flex:none}.cat-row .track{height:8px;border-radius:5px;background:var(--soft);overflow:hidden}.cat-row .track i{display:block;height:100%;border-radius:5px}
.cat-row .cv{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}.cat-row .cv b{color:var(--ink)}
.privacy-note{display:flex;gap:8px;align-items:center;font-size:12px;color:var(--muted);margin-top:14px}.privacy-note svg{width:14px;height:14px}
@keyframes rise{from{opacity:0;transform:translateY(10px)}}@keyframes dlg{from{opacity:0;transform:translateY(14px) scale(.98)}}
@keyframes pop{0%{transform:scale(1)}40%{transform:scale(1.35)}100%{transform:scale(1)}}@keyframes shimmer{to{background-position:-200% 0}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media(max-width:900px){.file-row{grid-template-columns:44px 1fr auto}.aud{grid-column:2;grid-row:2}.ver-btn{grid-column:3;grid-row:2;justify-self:end}.row-actions{grid-column:3;grid-row:1}}
@media(max-width:980px){.kpis{grid-template-columns:repeat(2,1fr)}.team-grid{grid-template-columns:1fr}}
@media(max-width:760px){.file-row.snippet{grid-template-areas:none}.file-row.snippet>*{grid-area:auto}.snip{grid-column:1/-1;margin:6px 0 0}.cat-row{grid-template-columns:110px 1fr;}.cat-row .cv{grid-column:1/-1;text-align:left}.kpi .n{font-size:24px}.wrap{width:calc(100% - 28px)}header.top{height:70px;gap:12px}header.top>img{width:104px;height:50px}.product,.online,.hide-sm{display:none}
.hero{grid-template-columns:1fr;padding:30px 0 24px;gap:20px}.hero h1{font-size:36px}.hero p.lead{font-size:14.5px;line-height:1.65}.who{display:none}
.card{padding:20px;border-radius:var(--r-lg)}.send-head{flex-direction:column;align-items:stretch;gap:12px}.chips{justify-content:flex-start}
.dropzone{flex-direction:column;text-align:center;min-height:180px;gap:12px}.dropzone small{margin:6px 0 0;max-width:none}.note-row{grid-template-columns:1fr}
.title-row{flex-direction:column;align-items:stretch;gap:14px}.filters{overflow-x:auto;scrollbar-width:none}.filters button{flex:1;justify-content:center}
.file-row{grid-template-columns:40px 1fr;gap:6px 12px;padding:14px 6px}.ftype{width:40px;height:40px}.aud{grid-column:2;grid-row:2}.ver-btn{grid-column:2;grid-row:3;justify-self:start}.row-actions{grid-column:1/-1;grid-row:4;justify-content:stretch}.row-actions .btn{flex:1;justify-content:center}
.vrow{grid-template-columns:22px 44px 1fr}.vrow .acts{grid-column:2/-1}dialog{padding:22px}footer{flex-direction:column;justify-content:center;height:auto;padding:22px 0}.banner{flex-wrap:wrap}}
</style></head><body>
<!-- ============ sign-in ============ -->
<div id=authView class="auth-wrap hidden"><form class="card auth" id=authForm novalidate><img src="data:image/png;base64,""" + LOGO_PNG_B64 + r"""" alt="Blue Giraffe Development Ltd">
<p class=eyebrow id=authKicker>BGShare</p><h2 id=authTitle>Sign in to BGShare</h2><p class=copy id=authCopy>Enter your display name and PIN.</p>
<div class=seg role=tablist><button type=button role=tab id=tIn aria-selected=true>Sign in</button><button type=button role=tab id=tUp aria-selected=false>Create account</button></div>
<label>Display name<input id=aName autocomplete=username required></label>
<label>PIN or password<input id=aPin type=password autocomplete=current-password minlength=4 required></label>
<label id=codeRow class=hidden>Office code<input id=aCode type=password autocomplete=off></label>
<button class="btn wide" id=aGo type=submit><span>Continue</span><span aria-hidden=true>→</span></button><small class=err id=aErr role=alert></small>
</form></div>
<!-- ============ app ============ -->
<div id=appView class=hidden>
<header class="top wrap"><img src="data:image/png;base64,""" + LOGO_PNG_B64 + r"""" alt="Blue Giraffe"><div class=product><b>BGShare</b><span>Internal file transfer</span></div>
<div class=hdr-actions><span class=online id=online><i></i>Local network</span>
<button class="ghost icon-btn" id=muteBtn title="Mute notification sound" aria-pressed=false></button>
<button class="ghost hide-sm" id=peopleBtn><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round><circle cx=9 cy=8 r=3.5 /><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5a6.5 6.5 0 0 1 3.5 5.5"/></svg>Team</button>
<button class=avatar id=logout title="Sign out"></button></div></header>
<main class=wrap>
<section class=hero><div><p class=eyebrow>BGShare</p><h1>Send files</h1>
<p class=lead>Send to specific people or everyone. Re-uploading a file with the same name saves a new version.</p></div>
<aside class=who><small>SIGNED IN AS</small><strong id=welcomeName>—</strong><span>Team member</span><div class=stat><div><b id=stUnread>0</b>unread</div><div><b id=stSent>0</b>sent</div><div><b id=stPeople>0</b>people</div></div></aside></section>
<div class="banner hidden" id=notifyBanner role=region aria-label="Notifications"><div class=ti style="color:var(--blue)"><svg width=22 height=22 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg></div>
<p id=notifyText><b>Desktop alerts.</b> Show a desktop alert when a file or snippet is sent to you.</p>
<button class="btn" id=notifyYes>Turn on</button><button class=ghost id=notifyNo>Dismiss</button></div>
<section class=card aria-labelledby=sendTitle><div class=mode role=tablist aria-label="What to send"><button role=tab id=mFile aria-selected=true><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round aria-hidden=true><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg> Files</button><button role=tab id=mSnip aria-selected=false><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round aria-hidden=true><path d="M9 4h6a1 1 0 0 1 1 1v1H8V5a1 1 0 0 1 1-1z"/><path d="M16 5h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2M8 12h8M8 16h5"/></svg> Text snippet</button></div>
<div class=send-head><div><p class=eyebrow id=sendKicker>New transfer</p><h2 id=sendTitle>Choose recipients</h2></div>
<div><span class=field-label id=toLbl>Deliver to</span><div class=chips id=aud role=group aria-labelledby=toLbl></div></div></div>
<div id=fileMode><div class=dropzone id=drop tabindex=0 role=button aria-label="Choose files to send"><input id=pick type=file multiple hidden>
<div class=up-ic><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2.2 stroke-linecap=round stroke-linejoin=round><path d="M12 16V4M6 10l6-6 6 6M4 20h16"/></svg></div>
<div><h3>Drop files here</h3><p>or <u>choose from your device</u> · any size</p></div><small>Same name, same people → a new version</small></div>
<div class=note-row><label class=field-label for=note style="margin:0">Version note <span>optional</span></label><input id=note maxlength=140 placeholder="What changed in this version?"></div></div>
<form id=snipMode class="snip-form hidden" novalidate><div class="editing hidden" id=editBar></div>
<label class=sr for=sTitle>Title</label><input id=sTitle maxlength=120 placeholder="Title">
<label class=sr for=sText>Text</label><textarea id=sText spellcheck=false placeholder="Paste or type text"></textarea>
<div class=snip-foot><input id=sNote maxlength=140 placeholder="Version note (optional)" style="flex:1;min-width:200px"><span class=meter id=sMeter>0 B of 1 MB</span><button class=btn id=sGo type=submit><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round aria-hidden=true style="width:15px;height:15px"><path d="M22 2 11 13M22 2l-7 20-4-9-9-4z"/></svg><span>Send snippet</span></button></div></form></section>
<section class="section hidden" id=uploads aria-live=polite><div class=title-row><h2>Sending now</h2><span class=count id=queueCount></span></div><div id=upList></div></section>
<section class=section><div class=title-row><div><p class=eyebrow id=wsKicker>Your workspace</p><h2 id=wsTitle>Files and versions</h2></div>
<div class=filters role=tablist aria-label="File views"><button role=tab data-v=inbox aria-selected=true>Inbox <span class="badge hidden" id=badge></span></button><button role=tab data-v=sent aria-selected=false>Sent</button><button role=tab data-v=everyone aria-selected=false>Everyone</button><button role=tab data-v=snippets aria-selected=false>Snippets</button><button role=tab data-v=archive aria-selected=false>Archive</button><button role=tab data-v=stats aria-selected=false>My stats</button><button role=tab data-v=team aria-selected=false>Team</button></div></div>
<div id=list class=file-list aria-live=polite><div class=skeleton></div><div class=skeleton></div></div></section></main>
<footer class=wrap><span>© 2026 Blue Giraffe Development Ltd.</span><b>BGShare</b></footer></div>
<!-- ============ dialogs ============ -->
<dialog id=hist aria-labelledby=hTitle><div class=modal-head><div><p class=eyebrow>Version history</p><h2 id=hTitle></h2><div class=sub id=hSub></div></div><button class=close data-close aria-label=Close><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2.4 stroke-linecap=round><path d="M6 6l12 12M18 6 6 18"/></svg></button></div><div id=hBody></div></dialog>
<dialog id=people aria-labelledby=pTitle><div class=modal-head><div><p class=eyebrow>People</p><h2 id=pTitle>Accounts</h2><div class=sub>Registered users on this server.</div></div><button class=close data-close aria-label=Close><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2.4 stroke-linecap=round><path d="M6 6l12 12M18 6 6 18"/></svg></button></div><div id=peopleList style="margin-top:14px"></div></dialog>
<dialog id=confirmDlg aria-labelledby=cTitle style="width:min(440px,calc(100% - 28px))"><p class=eyebrow style="color:var(--bad)">Delete file</p><h2 id=cTitle style="font-size:22px"></h2><p style="color:var(--muted);margin:10px 0 22px">Removes it for everyone it was shared with. All versions stay in your Archive.</p>
<div style="display:flex;gap:8px;justify-content:flex-end"><button class=ghost data-close>Cancel</button><button class="btn danger" id=cYes>Delete for everyone</button></div></dialog>
<div id=toasts aria-live=polite></div>
<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const bytes=n=>{if(!n)return'0 B';const u=['B','KB','MB','GB','TB'],i=Math.min(Math.floor(Math.log(n)/Math.log(1024)),4);return(n/1024**i).toFixed(i>1?1:0)+' '+u[i]};
const age=t=>{const s=Math.max(0,Math.floor(Date.now()/1000-t));if(s<45)return'just now';if(s<3600)return Math.floor(s/60)+' min ago';if(s<86400)return Math.floor(s/3600)+' h ago';if(s<172800)return'yesterday';if(s<604800)return Math.floor(s/86400)+' days ago';return new Date(t*1000).toLocaleDateString()};
const full=t=>new Date(t*1000).toLocaleString(),initials=n=>n.split(/\s+/).map(x=>x[0]).slice(0,2).join('').toUpperCase();
const ICON={x:'<path d="M6 6l12 12M18 6 6 18"/>',dl:'<path d="M12 4v12M6 10l6 6 6-6M4 20h16"/>',trash:'<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3"/>',
bell:'<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',sound:'<path d="M11 5 6 9H3v6h3l5 4zM15.5 8.5a5 5 0 0 1 0 7M18.5 5.5a9 9 0 0 1 0 13"/>',mute:'<path d="M11 5 6 9H3v6h3l5 4zM22 9l-6 6M16 9l6 6"/>',
inbox:'<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5h13L22 12v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-6z"/>',send:'<path d="M22 2 11 13M22 2l-7 20-4-9-9-4z"/>',globe:'<circle cx=12 cy=12 r=9 /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',clip:'<path d="M9 4h6a1 1 0 0 1 1 1v1H8V5a1 1 0 0 1 1-1z"/><path d="M16 5h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2"/>',copy:'<rect x=9 y=9 width=12 height=12 rx=2 /><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',edit:'<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
up:'<path d="M12 19V5M5 12l7-7 7 7"/>',down:'<path d="M12 5v14M5 12l7 7 7-7"/>',chart:'<path d="M3 3v18h18M8 17V11M13 17V7M18 17v-4"/>',lock:'<rect x=4 y=11 width=16 height=10 rx=2 /><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',check:'<path d="m5 12 5 5L20 7"/>',arch:'<rect x=3 y=4 width=18 height=5 rx=1 /><path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9M10 13h4"/>'};
const svg=(k,w)=>'<svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width='+(w||2)+' stroke-linecap=round stroke-linejoin=round aria-hidden=true>'+ICON[k]+'</svg>';
// file-type icons: [category, colour, soft bg, glyph]
const DOC='<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>';
const FT={img:['#0c8a6c','#e6f6f1',DOC+'<circle cx=10 cy=13 r=1.5 /><path d="m19 19-4.5-4.5L8 21"/>'],vid:['#7b3fe4','#f1ebfd',DOC+'<path d="m10 11 5 3-5 3z"/>'],aud:['#c2410c','#fdf0e8',DOC+'<path d="M10 18v-6l5-1v6"/><circle cx=9 cy=18 r=1.3 /><circle cx=14 cy=17 r=1.3 />'],
pdf:['#c62828','#fdecec',DOC+'<path d="M9 13h6M9 17h4"/>'],doc:['#075ce5','#edf5ff',DOC+'<path d="M9 12h6M9 15h6M9 18h4"/>'],sheet:['#15803d','#e9f7ee',DOC+'<path d="M8 12h8v6H8zM12 12v6M8 15h8"/>'],
slide:['#d97706','#fff5d6',DOC+'<rect x=8 y=12 width=8 height=5 rx=1 />'],zip:['#6b5b2e','#f7f1e1',DOC+'<path d="M11 6h1M12 8h1M11 10h1M12 12h1M10.5 14h3v3h-3z"/>'],snippet:['#075ce5','#edf5ff','<path d="M9 4h6a1 1 0 0 1 1 1v1H8V5a1 1 0 0 1 1-1z"/><path d="M16 5h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2M8 12h8M8 16h5"/>'],code:['#102c4a','#eef2f7',DOC+'<path d="m10 12-2 2.5 2 2.5M14 12l2 2.5-2 2.5"/>'],txt:['#617487','#f1f5f9',DOC+'<path d="M9 12h6M9 15h6M9 18h3"/>'],any:['#617487','#f1f5f9',DOC]};
const EXT={img:'png jpg jpeg gif webp svg bmp heic tif tiff ico',vid:'mp4 mov avi mkv webm m4v',aud:'mp3 wav m4a aac flac ogg',pdf:'pdf',doc:'doc docx odt rtf pages',sheet:'xls xlsx csv ods numbers',slide:'ppt pptx odp key',zip:'zip rar 7z tar gz tgz bz2 xz iso dmg',code:'py js ts html css json xml yml yaml sh bat ps1 java c cpp h go rs php sql',txt:'txt md log ini cfg'};
const kind=n=>{const e=(n.includes('.')?n.split('.').pop():'').toLowerCase();for(const k in EXT)if(EXT[k].split(' ').includes(e))return[k,e];return['any',e]};
const ftype=(n,snip)=>{const[k,e]=snip?['snippet','TXT']:kind(n),[c,bg,g]=FT[k];return'<div class=ftype style="background:'+bg+';color:'+c+'"><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=1.8 stroke-linecap=round stroke-linejoin=round aria-hidden=true>'+g+'</svg>'+(e?'<em>'+esc(e.slice(0,4).toUpperCase())+'</em>':'')+'</div>'};
// toasts
function toast(html,cls,ms){const t=document.createElement('div');t.className='toast '+(cls||'');t.innerHTML=html;$('#toasts').append(t);setTimeout(()=>{t.classList.add('out');setTimeout(()=>t.remove(),300)},ms||3200)}
let me=null,users=[],view='inbox',sel=new Set(['everyone']),signup=false,files=[],known=null,needCode=false;
async function api(u,o){const r=await fetch(u,o);if(r.status==401&&!/\/api\/(login|signup)/.test(u)){showAuth();throw new Error('Please sign in again.')}
let j={};try{j=await r.json()}catch(e){}if(!r.ok)throw new Error(j.error||('Request failed ('+r.status+')'));return j}
// ---------- sound (Web Audio chime) ----------
let actx=null,muted=localStorage.getItem('bgshare_muted')=='1';
function unlockAudio(){try{if(!actx)actx=new(window.AudioContext||window.webkitAudioContext)();if(actx.state=='suspended')actx.resume()}catch(e){}}
['pointerdown','keydown'].forEach(e=>window.addEventListener(e,unlockAudio,{passive:true}));
function chime(){if(muted||!actx||actx.state!='running')return;const t=actx.currentTime,out=actx.createGain();out.gain.value=.18;out.connect(actx.destination);
[[659.25,0],[987.77,.11],[1318.5,.22]].forEach(([f,d])=>{const o=actx.createOscillator(),g=actx.createGain();o.type='sine';o.frequency.value=f;g.gain.setValueAtTime(0,t+d);g.gain.linearRampToValueAtTime(1,t+d+.015);g.gain.exponentialRampToValueAtTime(.001,t+d+.55);o.connect(g);g.connect(out);o.start(t+d);o.stop(t+d+.6)})}
function paintMute(){$('#muteBtn').innerHTML=svg(muted?'mute':'sound');$('#muteBtn').setAttribute('aria-pressed',muted);$('#muteBtn').title=muted?'Sound off — click to unmute':'Sound on — click to mute'}
$('#muteBtn').onclick=()=>{muted=!muted;localStorage.setItem('bgshare_muted',muted?'1':'0');paintMute();unlockAudio();if(!muted)setTimeout(chime,60);toast(muted?'Notification sound muted':'Notification sound on')};
// ---------- desktop notifications ----------
const canNotify=()=>'Notification' in window&&window.isSecureContext;
function setupBanner(){const b=$('#notifyBanner');if(window.pywebview)return b.classList.add('hidden');if(localStorage.getItem('bgshare_notify_dismissed')=='1'){b.classList.add('hidden');return}
if(!('Notification' in window)||!window.isSecureContext){if(localStorage.getItem('bgshare_insecure_seen')=='1')return b.classList.add('hidden');
$('#notifyText').innerHTML='<b>Desktop alerts are not available on this address.</b> Browsers allow them only on https or localhost. Sound, in-app messages and the Inbox badge still work.';
$('#notifyYes').textContent='OK';$('#notifyYes').onclick=()=>{localStorage.setItem('bgshare_insecure_seen','1');b.classList.add('hidden');unlockAudio()};$('#notifyNo').classList.add('hidden');b.classList.remove('hidden');return}
if(Notification.permission!='default')return b.classList.add('hidden');b.classList.remove('hidden');
$('#notifyYes').onclick=async()=>{unlockAudio();try{await Notification.requestPermission()}catch(e){}b.classList.add('hidden');toast(Notification.permission=='granted'?'Desktop alerts are on':'Desktop alerts blocked. In-app alerts still work.')};
$('#notifyNo').onclick=()=>{localStorage.setItem('bgshare_notify_dismissed','1');b.classList.add('hidden')}}
function notifyNew(items){chime();items.slice(0,3).forEach(it=>{toast('<div class=ti>'+svg('inbox')+'</div><span><b>'+esc(it.by)+'</b> sent you '+(it.kind=='snippet'?'a snippet: ':'')+'<b>'+esc(it.name)+'</b>'+(it.version>1?' (v'+it.version+')':'')+'</span>','new',6000);
if(canNotify()&&Notification.permission=='granted'){try{const n=new Notification(it.by+(it.kind=='snippet'?' sent you a snippet':' sent you a file'),{body:it.name+(it.version>1?' · version '+it.version:''),icon:'/favicon.svg',tag:'bgshare-'+it.id+'-'+it.version});n.onclick=()=>{window.focus();openTab('inbox');n.close()}}catch(e){}}});
if(items.length>3)toast('+'+(items.length-3)+' more in Inbox','new',6000)}
// ---------- badge: tab, title, favicon ----------
let lastCount=-1;function paintBadge(n){const b=$('#badge');b.textContent=n>99?'99+':n;b.classList.toggle('hidden',!n);if(n>lastCount&&lastCount>=0){b.classList.remove('pop');void b.offsetWidth;b.classList.add('pop')}lastCount=n;
document.title=(n?'('+n+') ':'')+'BGShare · Blue Giraffe';$('#stUnread').textContent=n;
const c=document.createElement('canvas');c.width=c.height=64;const x=c.getContext('2d');x.fillStyle='#1264d8';x.beginPath();x.roundRect?x.roundRect(0,0,64,64,16):x.rect(0,0,64,64);x.fill();
x.fillStyle='#fff';x.font='700 26px Arial,sans-serif';x.textAlign='center';x.fillText('BG',32,41);
if(n){x.fillStyle='#ffc953';x.beginPath();x.arc(46,18,17,0,7);x.fill();x.fillStyle='#102c4a';x.font='800 '+(n>9?17:22)+'px Arial,sans-serif';x.fillText(n>9?'9+':n,46,26)}
$('#favicon').href=c.toDataURL('image/png')}
// ---------- auth ----------
async function showAuth(){me=null;known=null;$('#appView').classList.add('hidden');$('#authView').classList.remove('hidden');try{needCode=(await (await fetch('/api/config')).json()).needs_code}catch(e){}setMode(signup);$('#aName').focus()}
function setMode(up){signup=up;$('#tIn').setAttribute('aria-selected',!up);$('#tUp').setAttribute('aria-selected',up);$('#aGo span').textContent=up?'Create account':'Continue';
$('#authTitle').textContent=up?'Create account':'Sign in to BGShare';$('#authCopy').textContent=up?'Choose a display name and PIN.':'Enter your display name and PIN.';
$('#authKicker').textContent=up?'New account':'BGShare';$('#codeRow').classList.toggle('hidden',!(up&&needCode));$('#aPin').autocomplete=up?'new-password':'current-password';$('#aErr').textContent=''}
$('#tIn').onclick=()=>setMode(false);$('#tUp').onclick=()=>setMode(true);
$('#authForm').onsubmit=async e=>{e.preventDefault();unlockAudio();$('#aErr').textContent='';$('#aGo').disabled=true;
try{await api(signup?'/api/signup':'/api/login',{method:'POST',body:JSON.stringify({name:$('#aName').value,pin:$('#aPin').value,code:$('#aCode').value})});$('#aPin').value='';await start()}catch(err){$('#aErr').textContent=err.message}$('#aGo').disabled=false};
$('#logout').onclick=async()=>{await fetch('/api/logout',{method:'POST'});if(inDesktop())try{window.pywebview.api.clear_session()}catch(e){}toast('Signed out');showAuth()};
async function start(){try{me=await api('/api/me')}catch(e){return}$('#authView').classList.add('hidden');$('#appView').classList.remove('hidden');
$('#welcomeName').textContent=me.name;$('#logout').textContent=initials(me.name);$('#logout').title='Signed in as '+me.name+' — sign out';paintMute();setupBanner();
known=new Set(me.unread.map(u=>u.id+':'+u.version));paintBadge(me.unseen);await refresh();desktopLink()}
// ---------- BGShare desktop app bridge (pywebview): give the app its own session so it can show native Windows toasts ----------
const inDesktop=()=>!!(window.pywebview&&window.pywebview.api);
async function desktopLink(){if(!inDesktop()||!me)return;$('#notifyBanner').classList.add('hidden');try{const r=await api('/api/device-token',{method:'POST'});await window.pywebview.api.register_session(r.token,r.name,location.origin)}catch(e){}}
window.addEventListener('pywebviewready',desktopLink);   // first load: remember, don't chime
// ---------- people / recipients ----------
function paintPeople(){const others=users.filter(u=>!u.you);[...sel].forEach(s=>{if(s!='everyone'&&!others.some(u=>u.id==s))sel.delete(s)});if(!sel.size)sel.add('everyone');
$('#aud').innerHTML='<button type=button class=chip data-id=everyone aria-pressed='+sel.has('everyone')+'>'+svg('globe')+'Everyone</button>'+others.map(u=>'<button type=button class=chip data-id="'+u.id+'" aria-pressed='+sel.has(u.id)+'><span class=mini>'+esc(initials(u.name))+'</span>'+esc(u.name)+'</button>').join('');
$$('#aud .chip svg').forEach(s=>{s.style.width='15px';s.style.height='15px'});
$('#peopleList').innerHTML=users.map(u=>'<div class=prow><span class=avatar>'+esc(initials(u.name))+'</span><div><b>'+esc(u.name)+'</b><p>Joined '+age(u.joined)+'</p></div>'+(u.you?'<span class=you>You</span>':'')+'</div>').join('');$('#stPeople').textContent=users.length}
$('#aud').onclick=e=>{const c=e.target.closest('.chip');if(!c)return;const id=c.dataset.id;if(id=='everyone')sel=new Set(['everyone']);else{sel.delete('everyone');sel.has(id)?sel.delete(id):sel.add(id);if(!sel.size)sel.add('everyone')}paintPeople()};
$('#peopleBtn').onclick=()=>$('#people').showModal();
// ---------- upload ----------
const drop=$('#drop'),pick=$('#pick');drop.onclick=()=>pick.click();drop.onkeydown=e=>{if(e.key=='Enter'||e.key==' '){e.preventDefault();pick.click()}};pick.onchange=()=>{send([...pick.files]);pick.value=''};
let depth=0;drop.addEventListener('dragenter',e=>{e.preventDefault();depth++;drop.classList.add('dragging')});drop.addEventListener('dragover',e=>{e.preventDefault();e.dataTransfer.dropEffect='copy'});
drop.addEventListener('dragleave',()=>{if(--depth<=0){depth=0;drop.classList.remove('dragging')}});drop.addEventListener('drop',e=>{e.preventDefault();depth=0;drop.classList.remove('dragging');send([...e.dataTransfer.files])});
window.addEventListener('dragover',e=>e.preventDefault());window.addEventListener('drop',e=>e.preventDefault());
let queue=[],active=0;function send(fs){if(!fs.length)return;const to=[...sel].join(','),note=$('#note').value.trim();fs.forEach(f=>queue.push({f,to,note}));$('#note').value='';pump()}
function qcount(){$('#queueCount').textContent=(queue.length+active)?(queue.length+active)+' in progress':'All sent'}
function pump(){$('#uploads').classList.remove('hidden');while(active<3&&queue.length){active++;upload(queue.shift()).finally(()=>{active--;qcount();pump();refresh();if(!active&&!queue.length)setTimeout(()=>{if(!active&&!queue.length){$('#uploads').classList.add('hidden');$('#upList').innerHTML=''}},6000)})}qcount()}
function upload({f,to,note}){return new Promise(res=>{const el=document.createElement('div');el.className='upload-row';
el.innerHTML=ftype(f.name)+'<div style="min-width:0"><div class=nm>'+esc(f.name)+'</div><div class=st>Starting…</div><div class=progress><i></i></div></div><div class=pct>0%</div>';$('#upList').prepend(el);
const st=el.querySelector('.st'),bar=el.querySelector('.progress i'),pc=el.querySelector('.pct'),t0=performance.now(),x=new XMLHttpRequest();
x.open('PUT','/api/upload?name='+encodeURIComponent(f.name)+'&to='+encodeURIComponent(to)+'&note='+encodeURIComponent(note));
x.upload.onprogress=e=>{const s=(performance.now()-t0)/1000,p=e.total?e.loaded/e.total*100:0,sp=e.loaded/1048576/Math.max(s,.001),left=sp>0?(e.total-e.loaded)/1048576/sp:0;
bar.style.width=p+'%';pc.textContent=Math.floor(p)+'%';st.textContent=bytes(e.loaded)+' of '+bytes(e.total)+' · '+sp.toFixed(1)+' MB/s'+(left>1?' · '+Math.ceil(left)+' s left':'')};
x.onload=()=>{const s=(performance.now()-t0)/1000;let j={};try{j=JSON.parse(x.responseText)}catch(e){}
if(x.status<300){el.classList.add('done');bar.style.width='100%';pc.textContent=j.unchanged?'Same':'v'+j.version;st.textContent=(j.unchanged?'No changes since v'+j.version:'Saved as version '+j.version)+' · '+bytes(f.size)+' in '+s.toFixed(1)+' s ('+(f.size/1048576/Math.max(s,.001)).toFixed(1)+' MB/s)';toast(esc(f.name)+(j.unchanged?' is unchanged':' sent'+(j.version>1?' as v'+j.version:'')))}
else{el.classList.add('fail');pc.textContent='Failed';st.textContent=j.error||('Error '+x.status);toast('Upload failed: '+esc(j.error||x.status),'bad')}res()};
x.onerror=()=>{el.classList.add('fail');pc.textContent='Failed';st.textContent='Network interrupted';toast('Network interrupted','bad');res()};x.send(f)})}
// ---------- clipboard ----------
async function copyText(t){if(navigator.clipboard&&window.isSecureContext){try{await navigator.clipboard.writeText(t);return true}catch(e){}}
const ta=document.createElement('textarea');ta.value=t;ta.setAttribute('readonly','');ta.style.cssText='position:fixed;top:-1000px;opacity:0';document.body.append(ta);ta.select();ta.setSelectionRange(0,t.length);
let ok=false;try{ok=document.execCommand('copy')}catch(e){}ta.remove();return ok}
const snipCache={};async function fullText(id,ver){const k=id+':'+ver;if(!snipCache[k])snipCache[k]=(await api('/api/snippets/'+id+'?v='+ver)).text;return snipCache[k]}
// ---------- composer mode ----------
let mode='file',editing=null;
function setComposer(m){mode=m;$('#mFile').setAttribute('aria-selected',m=='file');$('#mSnip').setAttribute('aria-selected',m=='snip');$('#fileMode').classList.toggle('hidden',m!='file');$('#snipMode').classList.toggle('hidden',m!='snip');
$('#sendTitle').textContent=editing?'Edit snippet':(m=='file'?'Choose recipients':'Share text');$('#sendKicker').textContent=editing?'New version':(m=='file'?'New transfer':'New snippet')}
$('#mFile').onclick=()=>{cancelEdit();setComposer('file')};$('#mSnip').onclick=()=>setComposer('snip');
const enc=new TextEncoder();function meter(){const n=enc.encode($('#sText').value).length,m=$('#sMeter');m.textContent=bytes(n)+' of 1 MB';m.classList.toggle('over',n>1048576);return n}
$('#sText').oninput=meter;$('#sText').onkeydown=e=>{if(e.key=='Enter'&&(e.ctrlKey||e.metaKey)){e.preventDefault();$('#snipMode').requestSubmit()}};
function cancelEdit(){editing=null;$('#editBar').classList.add('hidden');$('#aud').classList.remove('locked');$('#sTitle').disabled=false;$('#sGo span').textContent='Send snippet';setComposer(mode)}
async function startEdit(id,title,ver){const t=await fullText(id,ver);editing={id,ver};setComposer('snip');$('#sTitle').value=title;$('#sTitle').disabled=true;$('#sText').value=t;meter();$('#aud').classList.add('locked');
$('#editBar').innerHTML=svg('edit')+'<span>Editing <b>'+esc(title)+'</b> · saving creates v'+(ver+1)+' for the same people</span><button type=button class=ghost id=eCancel>Cancel</button>';$('#editBar').classList.remove('hidden');$('#editBar svg').style.cssText='width:16px;height:16px';
$('#eCancel').onclick=()=>{cancelEdit();$('#sText').value='';$('#sTitle').value='';meter()};$('#sGo span').textContent='Save new version';window.scrollTo({top:$('#snipMode').getBoundingClientRect().top+scrollY-140,behavior:'smooth'});$('#sText').focus()}
$('#snipMode').onsubmit=async e=>{e.preventDefault();const text=$('#sText').value;if(!text.trim())return toast('Type or paste some text first','bad');if(meter()>1048576)return toast('Snippets are limited to 1 MB','bad');
$('#sGo').disabled=true;try{const body=editing?{id:editing.id,text,note:$('#sNote').value}:{title:$('#sTitle').value,text,to:[...sel],note:$('#sNote').value};
const r=await api('/api/snippets',{method:'POST',body:JSON.stringify(body)});toast(r.unchanged?'No changes — still v'+r.version:(editing?'Saved '+esc(r.title)+' as v'+r.version:'Snippet <b>'+esc(r.title)+'</b> sent'));
$('#sText').value='';$('#sTitle').value='';$('#sNote').value='';meter();cancelEdit();refresh()}catch(err){toast(esc(err.message),'bad')}$('#sGo').disabled=false};
// ---------- dashboards ----------
const CATS=[['video','Video','#7b3fe4'],['image','Images','#0c8a6c'],['audio','Audio','#c2410c'],['document','Documents','#075ce5'],['spreadsheet','Spreadsheets','#15803d'],['slides','Slides','#d97706'],['pdf','PDF','#c62828'],['archive','Archives','#6b5b2e'],['code','Code','#102c4a'],['text','Text','#617487'],['other','Other','#a3b3c2'],['snippet','Snippets','#3b8bff']];
const PERIODS=[['today','Today'],['week','This week'],['month','This month'],['all','All time']];let period='week',teamMetric='sent_bytes',lastDash='';
function periodSeg(){return'<div class=filters role=tablist aria-label=Period id=pseg>'+PERIODS.map(([k,l])=>'<button role=tab data-p='+k+' aria-selected='+(k==period)+'>'+l+'</button>').join('')+'</div>'}
function bindSeg(){$$('#pseg [data-p]').forEach(b=>b.onclick=()=>{period=b.dataset.p;lastDash='';refresh()});$$('#tmetric [data-m]').forEach(b=>b.onclick=()=>{teamMetric=b.dataset.m;lastDash='';refresh()})}
const kpi=(icon,label,o,unit)=>'<div class=kpi><div class=k><i>'+svg(icon)+'</i>'+label+'</div><div class=n>'+o.count.toLocaleString()+'</div><div class=b>'+(unit||bytes(o.bytes))+'</div></div>';
function barChart(series){const W=760,H=220,pl=44,pb=26,pt=10,n=series.length,mx=Math.max(1,...series.map(d=>Math.max(d.sent_bytes,d.down_bytes))),bw=(W-pl-8)/n,y=v=>H-pb-(H-pb-pt)*v/mx;
let g='';for(let i=0;i<=3;i++){const v=mx*i/3,yy=y(v);g+='<line x1='+pl+' x2='+W+' y1='+yy+' y2='+yy+' stroke="#dce7f1" stroke-dasharray="'+(i?'3 4':'0')+'"/><text x='+(pl-6)+' y='+(yy+3)+' text-anchor=end>'+(i?bytes(v).replace(' ',''):'0')+'</text>'}
series.forEach((d,i)=>{const x=pl+i*bw+bw*.14,w=bw*.34,dt=new Date(d.day+'T12:00:00'),lbl=dt.toLocaleDateString(undefined,{day:'numeric',month:'short'});
g+='<rect x='+x+' y='+y(d.sent_bytes)+' width='+w+' height='+Math.max(0,H-pb-y(d.sent_bytes))+' rx=2.5 fill="#075ce5"><title>'+lbl+': sent '+d.sent+' ('+bytes(d.sent_bytes)+')</title></rect>';
g+='<rect x='+(x+w+1)+' y='+y(d.down_bytes)+' width='+w+' height='+Math.max(0,H-pb-y(d.down_bytes))+' rx=2.5 fill="#ffc953"><title>'+lbl+': downloaded '+d.down+' ('+bytes(d.down_bytes)+')</title></rect>';
if((n-1-i)%Math.ceil(n/8)==0)g+='<text x='+(pl+i*bw+bw/2)+' y='+(H-8)+' text-anchor=middle>'+lbl+'</text>'});
return'<svg class=bars viewBox="0 0 '+W+' '+H+'" preserveAspectRatio=none role=img aria-label="Daily bytes sent and downloaded">'+g+'</svg>'}
async function paintStats(){const d=await api('/api/stats/me?days=30'),p=d.periods[period],key=JSON.stringify([period,d]);if(key==lastDash)return;lastDash=key;
const tot=d.series.reduce((a,x)=>a+x.sent_bytes+x.down_bytes,0);
$('#list').innerHTML='<div class=dash-head><p>Your own activity · '+PERIODS.find(x=>x[0]==period)[1].toLowerCase()+' · server local time, weeks start Monday</p>'+periodSeg()+'</div>'+
'<div class=kpis>'+kpi('up','Files sent',p.files_sent)+kpi('down','Files downloaded',p.files_downloaded)+kpi('clip','Snippets sent',p.snippets_sent)+kpi('copy','Snippets copied',p.snippets_copied)+'</div>'+
'<div class=chart-card><div class=chart-top><h3>Last 30 days</h3><div class=legend><span><i style="background:#075ce5"></i>Sent</span><span><i style="background:#ffc953"></i>Downloaded</span></div></div>'+(tot?barChart(d.series):'<div class=empty style="padding:40px"><div class=art>'+svg('chart',1.8)+'</div><b>No activity</b>Sent and downloaded items appear here.</div>')+'</div>';bindSeg()}
function donut(rows,metric){const tot=rows.reduce((a,r)=>a+r.val,0),R=70,C=2*Math.PI*R;let off=0,g='<circle r='+R+' cx=90 cy=90 fill=none stroke="#edf5ff" stroke-width=22 />';
rows.filter(r=>r.val).forEach(r=>{const len=C*r.val/tot;g+='<circle r='+R+' cx=90 cy=90 fill=none stroke="'+r.color+'" stroke-width=22 stroke-dasharray="'+Math.max(0,len-1.5)+' '+(C-len+1.5)+'" stroke-dashoffset="'+(-off)+'" transform="rotate(-90 90 90)"><title>'+r.label+': '+r.fmt+'</title></circle>';off+=len});
return'<div class=donut-wrap><svg width=180 height=180 viewBox="0 0 180 180" role=img aria-label="Share by category">'+g+'</svg><div class=donut-c><b>'+(metric.endsWith('bytes')?bytes(tot):tot.toLocaleString())+'</b><span>'+(metric.startsWith('sent')?'sent':'downloaded')+'</span></div></div>'}
async function paintTeam(){const d=await api('/api/stats/team?period='+period),key=JSON.stringify([period,teamMetric,d]);if(key==lastDash)return;lastDash=key;const t=d.totals,isB=teamMetric.endsWith('bytes');
const rows=CATS.map(([k,l,c])=>{const x=d.categories[k]||{sent:0,sent_bytes:0,down:0,down_bytes:0};return{k,label:l,color:c,x,val:x[teamMetric],fmt:isB?bytes(x[teamMetric]):x[teamMetric]+' items'}}).sort((a,b)=>b.val-a.val),mx=Math.max(1,...rows.map(r=>r.val));
const M=[['sent_bytes','Sent · size'],['sent','Sent · count'],['down_bytes','Downloaded · size'],['down','Downloaded · count']];
$('#list').innerHTML='<div class=dash-head><p>Whole office · '+PERIODS.find(x=>x[0]==period)[1].toLowerCase()+'</p>'+periodSeg()+'</div>'+
'<div class=kpis>'+kpi('up','Items sent',{count:t.sent,bytes:t.sent_bytes})+kpi('down','Items downloaded',{count:t.down,bytes:t.down_bytes})+'<div class=kpi><div class=k><i>'+svg('chart')+'</i>Data moved</div><div class=n>'+bytes(t.sent_bytes+t.down_bytes)+'</div><div class=b>sent + downloaded</div></div>'+kpi('globe','Active people',{count:t.active_people,bytes:0},'sent or downloaded')+'</div>'+
'<div class=team-grid><div class=chart-card><div class=chart-top><h3>By category</h3></div>'+(t.sent+t.down?donut(rows,teamMetric):'<div class=empty style="padding:30px"><b>No activity</b></div>')+'</div>'+
'<div class=chart-card><div class=chart-top><h3>Categories</h3><div class=filters id=tmetric style="padding:3px">'+M.map(([k,l])=>'<button data-m='+k+' aria-selected='+(k==teamMetric)+' style="padding:6px 10px;font-size:11.5px">'+l+'</button>').join('')+'</div></div>'+
rows.map(r=>'<div class=cat-row><div class=cn><span class=dot style="background:'+r.color+'"></span>'+r.label+'</div><div class=track><i style="width:'+(100*r.val/mx)+'%;background:'+r.color+'"></i></div><div class=cv><b>'+r.x.sent+'</b> sent · '+bytes(r.x.sent_bytes)+'<br><b>'+r.x.down+'</b> dl · '+bytes(r.x.down_bytes)+'</div></div>').join('')+'</div></div>'+
'<div class=privacy-note>'+svg('lock')+'Totals only. File names, snippet titles and recipients are not shown.</div>';bindSeg()}
// ---------- lists ----------
const TITLES={inbox:['Your workspace','Files and versions'],sent:['Your workspace','Files and versions'],everyone:['Your workspace','Files and versions'],snippets:['Text','Snippets'],archive:['Your workspace','Archive'],stats:['Personal metrics','My stats'],team:['All users','Team analytics']};
function openTab(v){view=v;lastDash='';$('#wsKicker').textContent=TITLES[v][0];$('#wsTitle').textContent=TITLES[v][1];$$('.filters [data-v]').forEach(x=>x.setAttribute('aria-selected',x.dataset.v==v));refresh()}
$$('.filters [data-v]').forEach(b=>b.onclick=()=>openTab(b.dataset.v));
$('.filters').onkeydown=e=>{if(!/Arrow(Left|Right)/.test(e.key))return;const t=$$('.filters [data-v]'),i=t.findIndex(x=>x.dataset.v==view),n=t[(i+(e.key=='ArrowRight'?1:t.length-1))%t.length];n.focus();openTab(n.dataset.v)};
const EMPTY={inbox:['inbox','Inbox is empty','Files and snippets sent to you appear here.'],sent:['send','Nothing sent','Files and snippets you send appear here.'],everyone:['globe','No shared files','Files sent to Everyone appear here.'],archive:['arch','Archive is empty','Deleted files and their versions are kept here.'],snippets:['clip','No snippets','Use Text snippet above to share text.']};
function audText(f){return f.to=='everyone'?'<span class="aud all">Everyone</span>':'<span class=aud title="'+esc(f.to.map(t=>t.name).join(', '))+'">To: '+esc(f.to.map(t=>t.id==me.id?'You':t.name).join(', '))+'</span>'}
function paintList(){if(!files.length){const[i,b,p]=EMPTY[view];$('#list').innerHTML='<div class=empty><div class=art>'+svg(i,1.8)+'</div><b>'+b+'</b>'+p+'</div>';return}
$('#list').innerHTML=files.map(f=>f.kind=='snippet'?snipRow(f):'<article class="file-row'+(f.unread?' unread':'')+'">'+ftype(f.name)+'<div style="min-width:0"><div class=file-name title="'+esc(f.name)+'">'+esc(f.name)+'</div><div class=meta>'+bytes(f.size)+' · '+esc(f.uploader_name==me.name?'You':f.uploader_name)+' · <span title="'+full(f.time)+'">'+age(f.time)+'</span>'+(f.note?' · <q>'+esc(f.note)+'</q>':'')+'</div></div>'+
audText(f)+'<button class=ver-btn data-h="'+f.id+'" aria-label="Version history for '+esc(f.name)+'">v'+f.version+' · '+f.versions+' version'+(f.versions==1?'':'s')+'</button><div class=row-actions>'+
(f.deleted?'<span class=meta>Deleted '+age(f.deleted_at||f.time)+'</span>':'<a class=btn data-dl="'+f.id+'" href="/f/'+f.id+'/'+encodeURIComponent(f.name)+'">'+svg('dl')+'Download</a>')+
(f.can_delete&&!f.deleted?'<button class="btn plain" data-d="'+f.id+'" data-n="'+esc(f.name)+'" aria-label="Delete '+esc(f.name)+'">'+svg('trash')+'</button>':'')+'</div></article>').join('')}
const openSnips=new Set();
function snipRow(f){const o=openSnips.has(f.id),txt=o&&snipCache[f.id+':'+f.version]||f.preview;
return'<article class="file-row snippet'+(f.unread?' unread':'')+'">'+ftype(f.name,1)+'<div class=mainc style="min-width:0"><div class=file-name title="'+esc(f.name)+'">'+esc(f.name)+'</div><div class=meta>Snippet · '+bytes(f.size)+(f.lines?' · '+f.lines+' line'+(f.lines==1?'':'s'):'')+' · '+esc(f.uploader_name==me.name?'You':f.uploader_name)+' · <span title="'+full(f.time)+'">'+age(f.time)+'</span>'+(f.note?' · <q>'+esc(f.note)+'</q>':'')+'</div></div>'+
audText(f)+'<button class=ver-btn data-h="'+f.id+'">v'+f.version+' · '+f.versions+' version'+(f.versions==1?'':'s')+'</button><div class=row-actions>'+(f.deleted?'<span class=meta>Deleted</span>':'<button class=btn data-copy="'+f.id+'" data-ver='+f.version+'>'+svg('copy')+'Copy</button><button class="btn soft" data-edit="'+f.id+'" data-ver='+f.version+' data-n="'+esc(f.name)+'" aria-label="Edit '+esc(f.name)+'">'+svg('edit')+'</button>')+
(f.can_delete&&!f.deleted?'<button class="btn plain" data-d="'+f.id+'" data-n="'+esc(f.name)+'" aria-label="Delete '+esc(f.name)+'">'+svg('trash')+'</button>':'')+'</div>'+
'<div class="snip'+(o?' open':'')+(f.truncated||(f.lines||0)>8?' long':'')+'"><pre>'+esc(txt)+(f.truncated&&!o?'\n…':'')+'</pre>'+(f.truncated||(f.lines||0)>8?'<button class=more data-more="'+f.id+'" data-ver='+f.version+' aria-expanded='+o+'>'+(o?'Collapse':'Expand')+'</button>':'')+'</div></article>'}
let busy=false;async function refresh(){if(!me||busy)return;busy=true;try{const m=await api('/api/me');me=m;
const fresh=m.unread.filter(u=>!known.has(u.id+':'+u.version));m.unread.forEach(u=>known.add(u.id+':'+u.version));if(fresh.length)notifyNew(fresh);paintBadge(m.unseen);
if(view=='stats'||view=='team'){users=await api('/api/users');paintPeople();await(view=='stats'?paintStats():paintTeam())}else{
const [fs,us,sent]=await Promise.all([api('/api/files?view='+view),api('/api/users'),view=='sent'?null:api('/api/files?view=sent')]);files=fs;users=us;
$('#stSent').textContent=(sent||fs).length;paintPeople();paintList()}$('#online').classList.remove('off');$('#online').lastChild.textContent='Local network'}
catch(e){$('#online').classList.add('off');$('#online').lastChild.textContent='Reconnecting…'}busy=false}
$('#list').onclick=async e=>{const t=e.target.closest('[data-h],[data-d],[data-dl],[data-copy],[data-edit],[data-more]');if(!t)return;
if(t.dataset.copy){try{const ok=await copyText(await fullText(t.dataset.copy,+t.dataset.ver));if(!ok)throw new Error('Copy blocked. Select the text and press Ctrl+C.');
api('/api/files/'+t.dataset.copy+'/copied',{method:'POST'}).then(()=>refresh()).catch(()=>{});t.classList.add('copied');t.innerHTML=svg('check')+'Copied';toast('Copied to clipboard')}catch(err){toast(esc(err.message),'bad')}return}
if(t.dataset.edit)return startEdit(t.dataset.edit,t.dataset.n,+t.dataset.ver);
if(t.dataset.more){const id=t.dataset.more;if(openSnips.has(id))openSnips.delete(id);else{try{await fullText(id,+t.dataset.ver)}catch(err){return toast(esc(err.message),'bad')}openSnips.add(id)}paintList();setTimeout(refresh,300);return}
if(t.dataset.h)return hist(t.dataset.h);
if(t.dataset.dl){setTimeout(refresh,800);return}   // server marks it read when the download starts
if(t.dataset.d){$('#cTitle').textContent=t.dataset.n;$('#cYes').onclick=async()=>{$('#confirmDlg').close();try{await api('/api/files/'+t.dataset.d,{method:'DELETE'});toast('Deleted. Versions kept in Archive.')}catch(err){toast(esc(err.message),'bad')}refresh()};$('#confirmDlg').showModal();$('#cYes').focus()}};
$$('[data-close]').forEach(b=>b.onclick=()=>b.closest('dialog').close());
$$('dialog').forEach(d=>d.addEventListener('click',e=>{if(e.target==d)d.close()}));
// ---------- history / diff ----------
async function hist(id){let h;try{h=await api('/api/files/'+id+'/history')}catch(e){return toast(esc(e.message),'bad')}const f=h.file,vs=h.versions;
$('#hTitle').textContent=f.name;$('#hSub').textContent=vs.length+' version'+(vs.length==1?'':'s')+' · '+(f.to=='everyone'?'shared with everyone':'private: '+[f.owner_name].concat(f.to.map(t=>t.name)).join(', '))+(f.deleted?' · deleted':'');
$('#hBody').innerHTML='<div class=vlist>'+vs.map((v,i)=>'<div class="vrow'+(i==0?' latest':'')+'"><input type=checkbox class=dv value="'+v.v+'" aria-label="Compare version '+v.v+'"'+(i<2?' checked':'')+'><div class=vnum>v'+v.v+'</div><div style="min-width:0"><b>'+esc(v.by_name)+'</b>'+(v.note?' — '+esc(v.note):'')+'<p><span title="'+full(v.time)+'">'+age(v.time)+'</span> · '+bytes(v.size)+' · <code title="'+v.sha+'">'+v.sha.slice(0,10)+'</code></p></div>'+
'<div class=acts><a class="btn soft" href="/f/'+id+'/'+encodeURIComponent(f.name)+'?v='+v.v+'">'+svg('dl')+'v'+v.v+'</a>'+(i>0&&!f.deleted?'<button class="btn soft" data-r="'+v.v+'">Restore</button>':'')+'</div></div>').join('')+'</div>'+
(vs.length>1?'<div class=diffbar><span>Tick two versions to compare text files.</span><button class=btn id=dgo>Compare</button></div><div id=dout></div>':'');
const dlg=$('#hist');if(!dlg.open)dlg.showModal();refresh();
$$('#hBody [data-r]').forEach(b=>b.onclick=async()=>{try{const r=await api('/api/files/'+id+'/restore?v='+b.dataset.r,{method:'POST'});toast('Restored v'+b.dataset.r+' as new version v'+r.version);hist(id)}catch(e){toast(esc(e.message),'bad')}});
const dg=$('#dgo');if(dg)dg.onclick=async()=>{const sv=$$('.dv:checked').map(x=>+x.value).sort((a,b)=>a-b);if(sv.length!=2)return toast('Tick exactly two versions to compare');
try{const d=await api('/api/files/'+id+'/diff?a='+sv[0]+'&b='+sv[1]);$('#dout').innerHTML='<div class=diff role=region aria-label="Differences">'+d.diff.split('\n').map(l=>{const c=/^(\+\+\+|---)/.test(l)?'f':l[0]=='+'?'a':l[0]=='-'?'d':l.startsWith('@@')?'h':'';return'<div'+(c?' class='+c:'')+'>'+(esc(l)||' ')+'</div>'}).join('')+'</div>'}
catch(e){$('#dout').innerHTML='<div class=diff><div class=msg>'+esc(e.message)+'</div></div>'}}}
start().then(()=>{if(!me)showAuth()});setInterval(refresh,3000);setInterval(()=>{if(me&&files.length&&!busy&&view!='stats'&&view!='team')paintList()},30000);
</script></body></html>"""

def serve(port=8080, data_dir="./lanshare-data", legacy_dir="./shared", password=None,
          discovery=True, discovery_port=DISCOVERY_PORT, quiet=False):
    """Start the server and return it (not yet serving). The desktop app's Host mode calls this too."""
    CFG["dir"] = os.path.realpath(data_dir)
    os.makedirs(dpath("objects"), exist_ok=True); os.makedirs(dpath("tmp"), exist_ok=True)
    for n in os.listdir(dpath("tmp")):          # leftovers from interrupted uploads
        try: os.remove(dpath("tmp", n))
        except OSError: pass
    CFG["password"] = password
    load_db()
    if legacy_dir: migrate_legacy(legacy_dir)
    load_events()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    srv.discovery = discovery_responder(port, discovery_port) if discovery else None
    if not quiet:
        print(f"BGShare data folder: {CFG['dir']}")
        print("Coworkers open:")
        for ip in lan_ips():
            print(f"   http://{ip}:{port}/")
        if password: print("Office code required to create accounts.")
        if srv.discovery: print(f"LAN discovery answering on UDP {discovery_port}.")
        print("Press Ctrl+C to stop.", flush=True)
    return srv

def main():
    ap = argparse.ArgumentParser(description="BGShare - LAN file sharing")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--dir", default="./lanshare-data", help="data folder (accounts, versions, objects)")
    ap.add_argument("--legacy-dir", default="./shared", help="old v1 folder to import from once")
    ap.add_argument("--password", default=None, help="office code required to create an account")
    ap.add_argument("--discovery-port", type=int, default=DISCOVERY_PORT, help="UDP port for LAN auto-discovery")
    ap.add_argument("--no-discovery", action="store_true", help="don't answer desktop-app discovery")
    a = ap.parse_args()
    srv = serve(a.port, a.dir, a.legacy_dir, a.password, not a.no_discovery, a.discovery_port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        srv.server_close()

if __name__ == "__main__":
    main()
