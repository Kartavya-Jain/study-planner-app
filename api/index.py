"""Study Planner API: Vercel serverless function + local dev server.
Database: PostgreSQL when DATABASE_URL is set (Vercel/Neon), otherwise local SQLite file.
Schema lives in db/schema.sql.  Local run:  python api/index.py  ->  http://localhost:5050
"""
import hashlib, hmac, json, os, secrets, sqlite3
from http.server import BaseHTTPRequestHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUB = os.path.join(ROOT, "public")
URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
PG = bool(URL)
ON_VERCEL = bool(os.environ.get("VERCEL"))
FACULTY_CODE = os.environ.get("FACULTY_CODE", "FACULTY123")
KEY = hashlib.sha256((os.environ.get("SECRET_KEY") or URL or "local-dev-key").encode()).digest()
# per-user tables: (column, type) where t=text i=int b=bool
COLS = {"tasks": [("title", "t"), ("pri", "t"), ("due", "t"), ("status", "t")],
        "assignments": [("title", "t"), ("subject", "t"), ("due", "t"), ("done", "b")],
        "attendance": [("subject", "t"), ("att", "i"), ("total", "i")],
        "goals": [("title", "t"), ("target", "i"), ("cur", "i")],
        "notes": [("title", "t"), ("body", "t")],
        "courses": [("name", "t"), ("credits", "i"), ("gp", "i")]}
TYPES = {".html": "text/html", ".css": "text/css", ".js": "application/javascript", ".json": "application/json"}
READY = False

def conn():
    if PG:
        import psycopg2
        return psycopg2.connect(URL)
    c = sqlite3.connect(os.path.join(ROOT, "studyplanner.db")); c.execute("PRAGMA foreign_keys=ON"); return c

def tx(stmts):
    """Run [(sql, args), ...] in one transaction; return rows of the last statement."""
    c = conn()
    try:
        cur = c.cursor(); rows = []
        for s, a in stmts:
            cur.execute(s.replace("?", "%s") if PG else s, a)
            rows = cur.fetchall() if cur.description else []
        c.commit(); return rows
    finally: c.close()

q = lambda sql, a=(): tx([(sql, a)])

def ensure():
    global READY
    if READY: return
    for st in open(os.path.join(ROOT, "db", "schema.sql"), encoding="utf8").read().split(";"):
        if st.strip(): q(st)
    READY = True

def cast(k, v):
    return bool(v) if k == "b" else int(v or 0) if k == "i" else ("" if v is None else str(v))

sig = lambda u: hmac.new(KEY, u.encode(), "sha256").hexdigest()
hp = lambda pw, salt: hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000).hex()

class handler(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)): body = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def who(self):
        uid, _, s = self.headers.get("Authorization", "")[7:].partition(".")
        if not uid or not hmac.compare_digest(s, sig(uid)): return None
        r = q("SELECT id,name,email,role FROM accounts WHERE id=?", (uid,))
        return dict(zip(("id", "name", "email", "role"), r[0])) if r else None

    def auth(self, kind, d):
        d = d if isinstance(d, dict) else {}
        email, pw = str(d.get("email", "")).strip().lower(), str(d.get("password", ""))
        if "@" not in email or len(pw) < 4: return self.reply(400, {"error": "Valid email and 4+ character password required"})
        if kind == "register":
            name, role = str(d.get("name", "")).strip(), d.get("role", "student")
            if not name or role not in ("student", "faculty"): return self.reply(400, {"error": "Name and role required"})
            if role == "faculty" and d.get("code") != FACULTY_CODE: return self.reply(403, {"error": "Wrong faculty code"})
            if q("SELECT 1 FROM accounts WHERE email=?", (email,)): return self.reply(409, {"error": "Email already registered"})
            uid, salt = secrets.token_hex(6), secrets.token_hex(8)
            q("INSERT INTO accounts(id,name,email,role,salt,pw) VALUES(?,?,?,?,?,?)", (uid, name, email, role, salt, hp(pw, salt)))
        else:
            r = q("SELECT id,name,role,salt,pw FROM accounts WHERE email=?", (email,))
            if not r or not hmac.compare_digest(r[0][4], hp(pw, r[0][3])): return self.reply(401, {"error": "Wrong email or password"})
            uid, name, role = r[0][:3]
        self.reply(200, {"token": uid + "." + sig(uid), "user": {"id": uid, "name": name, "email": email, "role": role}})

    def api(self, m, p):
        if ON_VERCEL and not PG: return self.reply(503, {"error": "DATABASE_URL is not set. Add a Postgres database in Vercel > Storage, then redeploy."})
        try: d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or "null")
        except ValueError: return self.reply(400, {"error": "bad json"})
        try: ensure()
        except Exception as e: return self.reply(500, {"error": "Database error: " + str(e)[:200]})
        r = p[1] if len(p) > 1 else ""
        if m == "POST" and r in ("register", "login"): return self.auth(r, d)
        u = self.who()
        if not u: return self.reply(401, {"error": "login required"})
        fac, uid = u["role"] == "faculty", u["id"]
        if r == "me": return self.reply(200, u)
        if r in COLS:
            cols = COLS[r]; names = ",".join(c for c, _ in cols)
            if m == "GET":
                out = []
                for row in q(f"SELECT id,{names} FROM {r} WHERE owner=? ORDER BY id", (uid,)):
                    out.append({"id": row[0], **{c: (bool(v) if k == "b" else v) for (c, k), v in zip(cols, row[1:])}})
                return self.reply(200, out)
            if m == "PUT" and isinstance(d, list):
                ins = f"INSERT INTO {r}(owner,id,{names}) VALUES(?,?,{','.join('?' * len(cols))}) ON CONFLICT DO NOTHING"
                st = [(f"DELETE FROM {r} WHERE owner=?", (uid,))]
                for i in d:
                    if isinstance(i, dict): st.append((ins, (uid, str(i.get("id") or secrets.token_hex(4)), *[cast(k, i.get(c)) for c, k in cols])))
                tx(st); return self.reply(200, {"saved": len(d)})
        studs = q("SELECT id,name FROM accounts WHERE role='student' ORDER BY name")
        if r == "students" and fac: return self.reply(200, [{"id": i, "name": n} for i, n in studs])
        if r == "posted" and m == "GET":
            rows = q("SELECT p.id,p.title,p.subject,p.descr,p.due,p.all_students,p.faculty_id,a.name FROM posted p JOIN accounts a ON a.id=p.faculty_id ORDER BY p.created_at DESC,p.id")
            item = lambda x: {"id": x[0], "title": x[1], "subject": x[2], "desc": x[3], "due": x[4], "faculty_name": x[7]}
            if not fac:
                mine = {a for (a,) in q("SELECT post_id FROM posted_targets WHERE student_id=?", (uid,))}
                st = dict(q("SELECT post_id,status FROM progress WHERE student_id=?", (uid,)))
                return self.reply(200, [{**item(x), "status": st.get(x[0], "todo")} for x in rows if x[5] or x[0] in mine])
            tg = {}
            for a, s in q("SELECT post_id,student_id FROM posted_targets"): tg.setdefault(a, set()).add(s)
            pr = {(a, s): t for a, s, t in q("SELECT post_id,student_id,status FROM progress")}
            return self.reply(200, [{**item(x), "students": [{"name": n, "status": pr.get((x[0], i), "todo")} for i, n in studs if x[5] or i in tg.get(x[0], ())]}
                                    for x in rows if x[6] == uid])
        if r == "posted" and m == "POST" and fac and isinstance(d, dict):
            aud = d.get("audience", "all"); ok = {i for i, _ in studs}
            if not str(d.get("title", "")).strip() or not d.get("due") or (aud != "all" and not (isinstance(aud, list) and aud and set(aud) <= ok)):
                return self.reply(400, {"error": "title, due date and valid audience required"})
            pid = secrets.token_hex(4)
            st = [("INSERT INTO posted(id,faculty_id,title,subject,descr,due,all_students) VALUES(?,?,?,?,?,?,?)",
                   (pid, uid, str(d["title"]).strip(), str(d.get("subject", "")), str(d.get("desc", "")), str(d["due"]), aud == "all"))]
            if aud != "all": st += [("INSERT INTO posted_targets(post_id,student_id) VALUES(?,?)", (pid, s)) for s in aud]
            tx(st); return self.reply(200, {"ok": 1})
        if r == "posted" and m == "DELETE" and fac and len(p) == 3:
            q("DELETE FROM posted WHERE id=? AND faculty_id=?", (p[2], uid)); return self.reply(200, {"ok": 1})
        if r == "progress" and m == "POST" and not fac and isinstance(d, dict) and d.get("status") in ("todo", "doing", "done"):
            if not q("SELECT 1 FROM posted WHERE id=?", (str(d.get("aid")),)): return self.reply(404, {"error": "task not found"})
            q("INSERT INTO progress(post_id,student_id,status) VALUES(?,?,?) ON CONFLICT(post_id,student_id) DO UPDATE SET status=excluded.status,updated_at=CURRENT_TIMESTAMP",
              (str(d["aid"]), uid, d["status"]))
            return self.reply(200, {"ok": 1})
        self.reply(404, {"error": "not found"})

    def route(self, m):
        p = self.path.split("?")[0].strip("/").split("/")
        if p[0] == "api": return self.api(m, p)
        f = os.path.realpath(os.path.join(PUB, "/".join(p) or "index.html"))   # local dev only; Vercel serves /public itself
        if m != "GET" or not f.startswith(os.path.realpath(PUB)) or not os.path.isfile(f): return self.reply(404, b"Not found", "text/plain")
        with open(f, "rb") as fh: self.reply(200, fh.read(), TYPES.get(os.path.splitext(f)[1], "application/octet-stream"))

    do_GET = lambda self: self.route("GET")
    do_POST = lambda self: self.route("POST")
    do_PUT = lambda self: self.route("PUT")
    do_DELETE = lambda self: self.route("DELETE")
    def log_message(self, *a): pass

if __name__ == "__main__":
    from http.server import ThreadingHTTPServer
    port = int(os.environ.get("PORT", 5050))
    print(f"Study Planner running at http://localhost:{port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()
