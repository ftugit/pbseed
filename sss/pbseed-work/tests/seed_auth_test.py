#!/usr/bin/env python3
"""Seed-auth test suite (stages 1+2 + 2026-09-17 soft-delete phase):
original 17 checks + ban / policy / history / logout / logout-all /
geo-update + phase 13 (soft delete / admin endpoints regression).

Server: ./pbseed serve --http=127.0.0.1:8090 --dir=<fresh> with
  PB_SUPERUSER_EMAIL / PB_SUPERUSER_PASSWORD set (defaults below),
  SEED_DOMAIN=<same as SEED_TEST_DOMAIN>, SEED_GC_EVERY=2s (P1 test)
  and SEED_GEO_ALLOW_PRIVATE=1 (phase 10 uses a 127.0.0.1 fixture server).
Run:    SEED_TEST_DOMAIN=test.local python3 tests/seed_auth_test.py   (needs: pip install pynacl)

IP-change simulation: client sockets are bound to 127.0.0.2..127.0.0.14
via source_address, so the server sees different socket IPs.
"""
import base64, http.client, http.server, json, os, threading, time, urllib.parse, urllib.request, urllib.error
from nacl.signing import SigningKey

BASE = "http://127.0.0.1:8090"
SU_EMAIL = os.environ.get("PBSEED_SU_EMAIL", "admin@seed.local")
SU_PASS = os.environ.get("PBSEED_SU_PASS", "s3cure-admin-pass-1")
DOMAIN = os.environ.get("SEED_TEST_DOMAIN", "seed.local")
fails = []
def check(name, cond, extra=""):
    print(f"[{'OK' if cond else 'FAIL'}] seed {name}: {extra}"[:260]); fails.append(0 if cond else 1)

class BoundHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, src): super().__init__(); self._src = src
    def http_open(self, req):
        src = self._src
        return self.do_open(lambda h, **kw: http.client.HTTPConnection(h, source_address=(src, 0)), req)

_openers = {}
def _opener(src):
    if src not in _openers:
        _openers[src] = urllib.request.build_opener(BoundHTTPHandler(src)) if src else urllib.request.build_opener()
    return _openers[src]

def api(method, path, body=None, token=None, cookie=None, src=None):
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if token: h["Authorization"] = token
    if cookie: h["Cookie"] = "pb_seed=" + cookie
    req = urllib.request.Request(BASE + path, data=(json.dumps(body).encode() if body is not None else None),
                                 method=method, headers=h)
    try:
        with _opener(src).open(req, timeout=60) as r:
            sc = r.headers.get("Set-Cookie", "")
            raw = r.read().decode()
            ck = sc.split("pb_seed=")[1].split(";")[0] if "pb_seed=" in sc else None
            return r.status, (json.loads(raw) if raw else None), ck, sc
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode() or "null"), None, ""
        except Exception: return e.code, None, None, ""

class SeedUser:
    def __init__(self):
        self.sk = SigningKey.generate(); self.pk = self.sk.verify_key.encode().hex()
    def challenge(self, purpose):
        s, r, _, _ = api("POST", "/api/seed/challenge", {"public_key": self.pk, "purpose": purpose})
        assert s == 200, (s, r); return r["nonce"]
    def sign(self, purpose, nonce):
        return self.sk.sign(f"surreal-auth-v1:{DOMAIN}:{purpose}:{self.pk}:{nonce}".encode()).signature.hex()
    def login(self, purpose, device, src=None):
        n = self.challenge(purpose)
        t0 = time.perf_counter()
        s, r, ck, _ = api("POST", "/api/seed/login", {"public_key": self.pk, "signature": self.sign(purpose, n),
                   "purpose": purpose, "nonce": n, "device_name": device}, src=src)
        return s, r, ck, round((time.perf_counter() - t0) * 1000, 0)

def su_token():
    s, r, _, _ = api("POST", "/api/collections/_superusers/auth-with-password",
                     {"identity": SU_EMAIL, "password": SU_PASS})
    assert s == 200, (s, r); return r["token"]

def sessions_of(access, cookie):
    s, r, _, _ = api("GET", "/api/seed/sessions", token=access, cookie=cookie)
    if s != 200 or not isinstance(r, list):
        # Server-side failure (S2: SafeQuery fexpr bug returns 500) — report
        # it as a failed check instead of crashing the whole suite.
        check("sessions endpoint reachable", False, f"status={s} {str(r)[:80]}")
        return []
    return r

# ============================ phase 0: original 17 ============================
A, B = SeedUser(), SeedUser()
s, r, ck1, ms = A.login("register", "laptop")
check("A register", s == 200 and ck1 is not None, f"status={s} {ms}ms")
a1, c1 = r, ck1
s, r, ck2, ms = A.login("login", "phone")
check("A login 2nd device", s == 200, f"status={s} {ms}ms")
a2, c2 = r, ck2
s, r, ckB, _ = B.login("register", "b-device")
b1, cB = r, ckB

# ---- notes collection (TEST-ONLY, fix 2026-09-17) ----
# The production server no longer creates `notes`. The phases below used
# it as a neutral protected resource, so the suite bootstraps it itself
# through the public collections API with the same rules/fields the old
# production collection had (minus the server-side hooks: soft delete and
# the owner-transfer guard now live only in the Go test harness; rule
# checks here exercise PB rules alone).
su = su_token()
s, r, _, _ = api("GET", "/api/collections/users", token=su)
assert s == 200, (s, r)
_users_id = r["id"]
_read = 'visibility = "public" || owner = @request.auth.id'
s, r, _, _ = api("POST", "/api/collections", {
    "name": "notes", "type": "base",
    "listRule": _read, "viewRule": _read,
    "createRule": '@request.auth.id != "" && @request.body.owner = @request.auth.id',
    "updateRule": "owner = @request.auth.id",
    "deleteRule": "owner = @request.auth.id",
    "fields": [
        {"name": "title", "type": "text", "max": 255},
        {"name": "owner", "type": "relation", "collectionId": _users_id, "maxSelect": 1},
        {"name": "visibility", "type": "text", "max": 16},
        {"name": "created_at", "type": "autodate", "onCreate": True},
        {"name": "updated_at", "type": "autodate", "onCreate": True, "onUpdate": True},
        {"name": "deleted_at", "type": "date"},
    ],
}, token=su)
check("suite bootstrap: notes created via API (test-only)", s == 200, f"status={s} {str(r)[:120]}")

r = sessions_of(a1["access"], c1)
s = 200 if isinstance(r, list) else 500
devs = {d["device_name"]: d for d in (r or [])}
check("A sees 2 sessions masked (socket IP)", s == 200 and len(devs) == 2 and
      all(d["ip_masked"] == "127.0.*.*" for d in devs.values()), f"{devs}")
api("POST", "/api/collections/notes/records", {"title": "a-pub", "owner": a1["user_id"], "visibility": "public"}, token=a1["access"], cookie=c1)
api("POST", "/api/collections/notes/records", {"title": "a-priv", "owner": a1["user_id"], "visibility": "private"}, token=a1["access"], cookie=c1)
api("POST", "/api/collections/notes/records", {"title": "b-priv", "owner": b1["user_id"], "visibility": "private"}, token=b1["access"], cookie=cB)
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50")
check("guest SELECT * -> only public", s == 200 and [x["title"] for x in r["items"]] == ["a-pub"], f"{r and r['totalItems']}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=a1["access"], cookie=c1)
check("A SELECT * -> public+own", s == 200 and sorted(x["title"] for x in r["items"]) == ["a-priv", "a-pub"], f"{r and r['totalItems']}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=b1["access"], cookie=cB)
check("B SELECT * -> public+own", s == 200 and sorted(x["title"] for x in r["items"]) == ["a-pub", "b-priv"], f"{r and r['totalItems']}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=a1["access"])
check("token WITHOUT session cookie -> 401", s == 401, f"status={s} {str(r)[:60]}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=a1["access"], cookie="bogus.grant")
check("token with forged cookie -> 401", s == 401, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/revoke", {"grant_id": a1["session_id"]}, token=a1["access"], cookie=c1)
check("revoke own session", s == 200, f"status={s}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=a1["access"], cookie=c1)
check("revoked session -> 401 instant", s == 401, f"status={s}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=a2["access"], cookie=c2)
check("2nd device unaffected", s == 200 and r["totalItems"] == 2, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=c2)
check("renew ok", s == 200 and "access" in (r or {}), f"status={s}")
a2new = r["access"] if r else None
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=a2new, cookie=c2)
check("renewed access works", s == 200 and r["totalItems"] == 2, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=c1)
check("revoked cookie renew rejected", s == 401, f"status={s}")
n = A.challenge("login")
good = A.sign("login", n)
bad = good[:-2] + ("00" if not good.endswith("00") else "ff")
s, r, _, _ = api("POST", "/api/seed/login", {"public_key": A.pk, "signature": bad, "purpose": "login", "nonce": n, "device_name": "x"})
check("bad signature rejected (nonce burned)", s == 400, f"status={s} {str(r)[:60]}")
s, r, _, _ = api("POST", "/api/seed/login", {"public_key": A.pk, "signature": good, "purpose": "login", "nonce": n, "device_name": "x"})
check("burned nonce rejected (one-shot)", s == 400, f"status={s} {str(r)[:60]}")
s, r, _, _ = api("POST", "/api/collections/notes/records", {"title": "anon", "owner": b1["user_id"], "visibility": "public"})
check("guest create blocked", s == 400, f"status={s}")

# ================== phase 1: sessions shape (country/history/current) ==================
rows = sessions_of(a2new, c2)
by = {d["session_id"]: d for d in rows}
s2row = by.get(a2["session_id"], {})
check("sessions carry country+history+current",
      s2row.get("country") == "" and s2row.get("history") == [] and s2row.get("current") is True
      and by.get(a1["session_id"], {}).get("current") is False, f"{s2row}")

# ================== phase 2: lax IP change -> history ==================
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=c2, src="127.0.0.2")
check("lax renew from new IP ok", s == 200 and "access" in (r or {}), f"status={s}")
a2new = r["access"]
rows = sessions_of(a2new, c2)
s2row = {d["session_id"]: d for d in rows}.get(a2["session_id"], {})
h = s2row.get("history", [])
check("history gets ip_changed entry", len(h) == 1 and h[0].get("event") == "ip_changed"
      and h[0].get("prev_masked") == "127.0.*.*" and "prev_country" in h[0] and h[0].get("at"), f"{h}")
dump = json.dumps(rows)
check("no raw IP in sessions output", "127.0.0.1" not in dump and "127.0.0.2" not in dump, dump[:120])

# ================== phase 3: history capped at 10 ==================
for i in range(3, 14):
    s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=c2, src=f"127.0.0.{i}")
    assert s == 200, (i, s, r)
    a2new = r["access"]
rows = sessions_of(a2new, c2)
h = {d["session_id"]: d for d in rows}.get(a2["session_id"], {}).get("history", [])
check("history capped at 10 (chronological append)", len(h) == 10 and all(x.get("event") == "ip_changed" for x in h), f"len={len(h)}")

# ================== phase 4: personal policy kills on change ==================
AU = a2["user_id"]
s, r, _, _ = api("GET", "/api/seed/policy", token=a2new, cookie=c2)
check("policy default off", s == 200 and r == {"key": "kick_on_ip_change", "value": False, "source": "default"}, f"status={s} {r}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "me", "value": True}, token=a2new, cookie=c2)
check("user sets own policy", s == 200 and (r or {}).get("value") is True, f"status={s} {r}")
s, r, _, _ = api("GET", "/api/seed/policy", token=a2new, cookie=c2)
check("own policy reads back (source me)", s == 200 and (r or {}).get("value") is True and (r or {}).get("source") == "me", f"{r}")
s, r, _, _ = api("GET", "/api/seed/policy", token=b1["access"], cookie=cB)
check("other user unaffected (isolation)", s == 200 and (r or {}).get("value") is False, f"{r}")
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=c2, src="127.0.0.14")
check("strict renew from new IP -> 401 ip_changed", s == 401 and (r or {}).get("error") == "ip_changed", f"status={s} {r}")
su = su_token()
fq = urllib.parse.quote(f"grant_id = '{a2['session_id']}'")
s, r, _, _ = api("GET", f"/api/collections/seed_sessions/records?filter={fq}", token=su)
check("strict kill hard-revokes session", s == 200 and (r["items"][0]["revoked"] is True), f"status={s}")
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=c2, src="127.0.0.13")
check("killed session stays dead from old IP too", s == 401 and (r or {}).get("error") == "revoked", f"status={s} {r}")
s, r, ck3, _ = A.login("login", "tablet")
a3, c3 = r, ck3
check("fresh login after strict kill works", s == 200, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "me", "value": False}, token=a3["access"], cookie=c3)
check("user can switch own policy off", s == 200, f"status={s}")

# ================== phase 5: users update guard ==================
for field, val in [("banned", True), ("email", "x@y.zz"), ("ban_reason", "self"), ("banned_until", "2030-01-01T00:00:00Z")]:
    s, r, _, _ = api("PATCH", f"/api/collections/users/records/{AU}", {field: val}, token=a3["access"], cookie=c3)
    check(f"self PATCH {field} -> 403", s == 403, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "global", "value": True}, token=a3["access"], cookie=c3)
check("non-admin global policy set -> 403", s == 403, f"status={s}")

# ================== phase 6: ban ==================
BU = b1["user_id"]
s, _, _, _ = api("PATCH", f"/api/collections/users/records/{BU}", {"banned": True, "ban_reason": "test-ban"}, token=su)
assert s == 200, s
n = B.challenge("login")
s, r, _, _ = api("POST", "/api/seed/login", {"public_key": B.pk, "signature": B.sign("login", n),
               "purpose": "login", "nonce": n, "device_name": "x"})
check("banned login -> 403 + reason", s == 403 and (r or {}).get("error") == "banned" and (r or {}).get("reason") == "test-ban", f"status={s} {r}")
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=cB)
check("banned renew -> 403", s == 403 and (r or {}).get("error") == "banned", f"status={s}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=b1["access"], cookie=cB)
check("banned data access -> 403 instant", s == 403, f"status={s}")
n = B.challenge("register")
s, r, _, _ = api("POST", "/api/seed/login", {"public_key": B.pk, "signature": B.sign("register", n),
               "purpose": "register", "nonce": n, "device_name": "x"})
check("register banned key stays neutral", s == 400 and (r or {}).get("error") == "already_registered", f"status={s} {r}")

# ================== phase 7: banned_until lazy expiry ==================
fut = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
s, _, _, _ = api("PATCH", f"/api/collections/users/records/{BU}", {"banned_until": fut}, token=su)
assert s == 200, s
n = B.challenge("login")
s, r, _, _ = api("POST", "/api/seed/login", {"public_key": B.pk, "signature": B.sign("login", n),
               "purpose": "login", "nonce": n, "device_name": "x"})
check("ban with future until blocks", s == 403, f"status={s}")
past = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
s, _, _, _ = api("PATCH", f"/api/collections/users/records/{BU}", {"banned_until": past}, token=su)
assert s == 200, s
n = B.challenge("login")
s, r, ckB2, _ = api("POST", "/api/seed/login", {"public_key": B.pk, "signature": B.sign("login", n),
               "purpose": "login", "nonce": n, "device_name": "b2"})
check("expired ban allows login (lazy expiry)", s == 200, f"status={s} {r}")
s, _, _, _ = api("PATCH", f"/api/collections/users/records/{BU}", {"banned": False, "banned_until": "", "ban_reason": ""}, token=su)
assert s == 200, s
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=cB)
check("ban is non-destructive (old session renews)", s == 200, f"status={s}")

# ================== phase 8: logout + logout-all ==================
s, r, ck4, _ = A.login("login", "watch")
a4, c4 = r, ck4
s, r, _, sc = api("POST", "/api/seed/logout", {}, token=a3["access"], cookie=c3)
check("logout current ok + cookie cleared", s == 200 and (r or {}).get("ok") is True and "Max-Age=0" in sc, f"status={s} {sc[:80]}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=a3["access"], cookie=c3)
check("logged-out session dead", s == 401, f"status={s}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=a4["access"], cookie=c4)
check("other device unaffected by logout", s == 200, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/logout-all", {}, token=a4["access"], cookie=c4)
check("logout-all revokes live sessions", s == 200 and (r or {}).get("ok") is True and (r or {}).get("revoked") == 1, f"status={s} {r}")
s, r, _, _ = api("GET", "/api/collections/notes/records?perPage=50", token=a4["access"], cookie=c4)
check("post-logout-all access dead", s == 401, f"status={s}")
s, r, ck5, _ = A.login("login", "after-all")
a5, c5 = r, ck5
check("login works after logout-all", s == 200, f"status={s}")

# ================== phase 9: global policy + locked + resolution ==================
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "global", "value": True}, token=su)
check("superuser sets global on", s == 200 and (r or {}).get("value") is True, f"status={s} {r}")
s, r, _, _ = api("GET", "/api/seed/policy?scope=global", token=a5["access"], cookie=c5)
check("user reads global", s == 200 and r == {"key": "kick_on_ip_change", "value": True, "source": "global"}, f"{r}")
s, r, _, _ = api("GET", "/api/seed/policy", src="127.0.0.20")
check("guest reads global default", s == 200 and (r or {}).get("value") is True, f"status={s} {r}")
s, r, _, _ = api("GET", "/api/seed/policy?scope=me", src="127.0.0.20")
check("guest scope=me -> 400", s == 400, f"status={s}")
# Fresh user C inherits the global default (no personal row).
C = SeedUser()
s, r, ckC, _ = C.login("register", "phoneC")
aC, cC = r, ckC
check("C login ok", s == 200, f"status={s}")
s, r, _, _ = api("GET", "/api/seed/policy", token=aC["access"], cookie=cC)
check("C effective = global", s == 200 and (r or {}).get("value") is True and (r or {}).get("source") == "global", f"{r}")
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=cC, src="127.0.0.21")
check("C renew new IP under global strict -> 401", s == 401 and (r or {}).get("error") == "ip_changed", f"status={s} {r}")
s, r, ckC2, _ = C.login("login", "phoneC2")
aC2, cC2 = r, ckC2
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "me", "value": False}, token=aC2["access"], cookie=cC2)
check("C sets personal off (override)", s == 200, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=cC2, src="127.0.0.22")
check("personal-false beats global-true (renew ok)", s == 200 and "access" in (r or {}), f"status={s} {r}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "global", "value": True, "locked": True}, token=su)
check("superuser locks global", s == 200, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "me", "value": True}, token=aC2["access"], cookie=cC2)
check("own row update allowed under lock", s == 200, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "me", "value": True}, token=b1["access"], cookie=cB)
check("new override under locked global -> 403 locked", s == 403 and (r or {}).get("error") == "locked", f"status={s} {r}")
s, r, _, _ = api("DELETE", "/api/seed/policy?scope=me", token=aC2["access"], cookie=cC2)
check("own row delete allowed under lock", s == 200 and (r or {}).get("deleted") == 1, f"status={s} {r}")
s, r, _, _ = api("GET", "/api/seed/policy", token=aC2["access"], cookie=cC2)
check("after delete, falls back to locked global", s == 200 and (r or {}).get("value") is True and (r or {}).get("source") == "global", f"{r}")
s, r, _, _ = api("DELETE", "/api/seed/policy?scope=me", token=aC2["access"], cookie=cC2)
check("delete missing row -> deleted 0", s == 200 and (r or {}).get("deleted") == 0, f"status={s} {r}")
s, r, _, _ = api("DELETE", "/api/seed/policy?scope=global", token=aC2["access"], cookie=cC2)
check("non-admin global delete -> 403", s == 403, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "me", "value": True}, token=su)
check("superuser scope=me -> 400", s == 400, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "me"}, token=aC2["access"], cookie=cC2)
check("missing value -> 400", s == 400, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "all", "value": True}, token=aC2["access"], cookie=cC2)
check("bad scope -> 400", s == 400, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/policy", {"key": "a'b", "scope": "me", "value": True}, token=aC2["access"], cookie=cC2)
check("bad key -> 400", s == 400, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "me", "value": True}, src="127.0.0.23")
check("guest set -> 401", s == 401, f"status={s}")
s, r, _, _ = api("DELETE", "/api/seed/policy?scope=global", token=su)
check("superuser deletes global", s == 200 and (r or {}).get("deleted") == 1, f"status={s} {r}")
s, r, _, _ = api("GET", "/api/seed/policy", token=aC2["access"], cookie=cC2)
check("all gone -> default off", s == 200 and (r or {}).get("value") is False and (r or {}).get("source") == "default", f"{r}")

# ================== phase 10: geo update with progress ==================
GZ = open("tests/fixtures/country-test.mmdb.gz", "rb").read()
gate = threading.Event()
class Drip(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/country-test.mmdb.gz":
            self.send_error(404); return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(GZ)))
        self.end_headers()
        try:
            self.wfile.write(GZ[:64]); self.wfile.flush()
            gate.wait(15)
            for i in range(64, len(GZ), 64):
                self.wfile.write(GZ[i:i+64]); self.wfile.flush()
                time.sleep(0.01)
        except (BrokenPipeError, ConnectionResetError):
            pass
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Drip)
threading.Thread(target=srv.serve_forever, daemon=True).start()
gurl = f"http://127.0.0.1:{srv.server_address[1]}/country-test.mmdb.gz"
s, r, _, _ = api("GET", "/api/seed/geo/status", token=su)
check("geo status idle pre-update", s == 200 and r["state"] == "idle" and r["db"] is None, f"{r}")
s, r, _, _ = api("GET", "/api/seed/geo/lookup?ip=203.0.113.5", token=su)
check("geo lookup no-db -> empty", s == 200 and r["country"] == "", f"{r}")
s, r, _, _ = api("POST", "/api/seed/geo/update", {"url": gurl}, token=su)
check("geo update starts", s == 200 and r.get("started") is True, f"status={s} {r}")
st = {}
for _ in range(200):
    s, st, _, _ = api("GET", "/api/seed/geo/status", token=su)
    if st["state"] == "downloading" and st["downloaded_bytes"] > 0:
        break
    time.sleep(0.02)
check("geo progress observable mid-download", st["state"] == "downloading" and 0 < st["downloaded_bytes"] < st["total_bytes"], f"{st}")
s, r, _, _ = api("POST", "/api/seed/geo/update", {"url": gurl}, token=su)
check("concurrent geo update -> 409 busy", s == 409 and r.get("error") == "busy", f"status={s} {r}")
s, r, _, _ = api("POST", "/api/seed/geo/update", {"url": "ftp://x/y"}, token=su)
check("geo bad url -> 400", s == 400, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/geo/update", {}, token=a5["access"], cookie=c5)
check("user geo update -> 403", s == 403, f"status={s}")
s, r, _, _ = api("POST", "/api/seed/geo/update", {}, src="127.0.0.24")
check("guest geo update -> 401", s == 401, f"status={s}")
gate.set()
st = {}
for _ in range(300):
    s, st, _, _ = api("GET", "/api/seed/geo/status", token=su)
    if st["state"] in ("ready", "error"):
        break
    time.sleep(0.02)
check("geo update completes", st["state"] == "ready" and st["percent"] == 100, f"{st}")
check("geo meta sane", st["db"]["release"] == "custom" and st["db"]["bytes"] == 1680 and len(st["db"]["sha256"]) == 64 and st["downloaded_bytes"] == st["total_bytes"] == len(GZ), f"{st['db']}")
for ip, cc in [("203.0.113.5", "US"), ("198.51.100.9", "DE"), ("192.0.2.7", "JP")]:
    s, r, _, _ = api("GET", f"/api/seed/geo/lookup?ip={ip}", token=su)
    check(f"geo lookup {ip} -> {cc}", s == 200 and r["country"] == cc, f"{r}")
for ip in ("127.0.0.5", "10.1.2.3", "8.8.8.8"):
    s, r, _, _ = api("GET", f"/api/seed/geo/lookup?ip={ip}", token=su)
    check(f"geo lookup {ip} -> empty", s == 200 and r["country"] == "", f"{r}")
s, r, _, _ = api("GET", "/api/seed/geo/lookup?ip=zzz", token=su)
check("geo lookup bad ip -> 400", s == 400, f"status={s}")
s, r, _, _ = api("GET", "/api/seed/geo/lookup?ip=203.0.113.5", token=a5["access"], cookie=c5)
check("user geo lookup -> 403", s == 403, f"status={s}")
s, r, _, _ = api("GET", "/api/seed/geo/status", token=a5["access"], cookie=c5)
check("user geo status -> 403", s == 403, f"status={s}")
s, r, _, _ = api("GET", "/api/seed/geo/status", src="127.0.0.25")
check("guest geo status -> 401", s == 401, f"status={s}")
srv.shutdown(); srv.server_close()


# ================== phase 11: batch regressions (H1/H2/L10/P1) ==================
# H1: 100 same-key personal rows must not hide the global row (planted LAST).
HKEY = "kick_regress_h1"
uids = []
for i in range(150):
    s, r, _, _ = api("POST", "/api/collections/users/records",
                     {"email": f"h1-{i}@seed.local", "password": "password123", "passwordConfirm": "password123"}, token=su)
    assert s == 200, (s, r); uids.append(r["id"])
for i, uid in enumerate(uids):
    s, r, _, _ = api("POST", "/api/collections/seed_settings/records",
                     {"key": HKEY, "value": False, "user": uid}, token=su)
    assert s == 200, (s, r)
s, r, _, _ = api("POST", "/api/collections/seed_settings/records",
                 {"key": HKEY, "value": True}, token=su)
assert s == 200, (s, r)
s, r, _, _ = api("GET", f"/api/seed/policy?key={HKEY}&scope=global", token=a5["access"], cookie=c5)
check("H1 global resolves under 150-key crowd", s == 200 and r.get("value") is True and r.get("source") == "global", f"{r}")

# H2: signature minted for another domain must not verify here.
H = SeedUser()
n = H.challenge("register")
evil = H.sk.sign(f"surreal-auth-v1:evil.test:register:{H.pk}:{n}".encode()).signature.hex()
s, r, _, _ = api("POST", "/api/seed/login", {"public_key": H.pk, "signature": evil,
               "purpose": "register", "nonce": n, "device_name": "x"})
check("H2 cross-domain signature rejected", s == 400, f"status={s} {r}")

# L10 (REMOVED 2026-09-17): the owner-transfer guard existed only to
# protect the production `notes` collection. `notes` no longer ships in
# production, the hook was deleted with it (see Go harness
# testNotesOwnerGuard for the preserved behaviour), and PB rules alone
# govern this test-only collection. Kept as a rule sanity check:
s, r, _, _ = api("POST", "/api/collections/notes/records",
                 {"title": "l10", "owner": a5["user_id"], "visibility": "private"},
                 token=a5["access"], cookie=c5)
assert s == 200, (s, r); nid = r["id"]
s, r, _, _ = api("PATCH", f"/api/collections/notes/records/{nid}", {"title": "l10b"},
                 token=a5["access"], cookie=c5)
check("notes owner can still update own fields", s == 200 and r.get("owner") == a5["user_id"], f"status={s} {r}")

# P1: expired challenge disappears via GC ticker (server booted with SEED_GC_EVERY=2s).
s, r, _, _ = api("POST", "/api/collections/seed_challenges/records",
                 {"public_key": "ab" * 32, "nonce": "gc-regress-1", "purpose": "login",
                  "used": False, "expires": "2020-01-01T00:00:00Z"}, token=su)
assert s == 200, (s, r); gcid = r["id"]
gone = False
for _ in range(40):
    time.sleep(0.5)
    s, _, _, _ = api("GET", f"/api/collections/seed_challenges/records/{gcid}", token=su)
    if s == 404:
        gone = True; break
check("P1 expired challenge GC'd by ticker", gone, "still present after 20s" if not gone else "")


# ================== phase 12: batch-2 regressions (M5/M8/L3/L4/P4/P2/L8/nonce-race) ==================
import threading as _th
# M5: garbage banned_until keeps the ban (fail-closed).
M5 = SeedUser(); s, m5r, m5ck, _ = M5.login("register", "m5")
api("PATCH", f"/api/collections/users/records/{m5r['user_id']}", {"banned": True, "banned_until": "garbage!!!"}, token=su)
s, r, _, _ = M5.login("login", "m5b")
check("M5 garbage banned_until keeps ban", s == 403, f"status={s} {r}")

# M8: junk policy key rejected on write.
s, r, _, _ = api("POST", "/api/seed/policy", {"scope": "me", "key": "junk_evil_key", "value": True}, token=a5["access"], cookie=c5)
check("M8 junk policy key -> 400", s == 400, f"status={s} {r}")

# L3: racing registers — no 500s, exactly one winner.
L3 = SeedUser()
l3st = []
def _reg():
    try:
        n = L3.challenge("register")
        s, _, _, _ = api("POST", "/api/seed/login", {"public_key": L3.pk, "signature": L3.sign("register", n),
                      "purpose": "register", "nonce": n, "device_name": "l3"})
        l3st.append(s)
    except Exception: l3st.append(0)
ths = [_th.Thread(target=_reg) for _ in range(10)]
[t.start() for t in ths]; [t.join() for t in ths]
check("L3 register race: one winner, no 500", sorted(l3st).count(200) == 1 and not [x for x in l3st if x >= 500], f"{sorted(l3st)}")

# Nonce double-spend race: same nonce twice concurrently — exactly one 200.
NR = SeedUser(); nrn = NR.challenge("register")
nrst = []
def _nr():
    try:
        s, _, _, _ = api("POST", "/api/seed/login", {"public_key": NR.pk, "signature": NR.sign("register", nrn),
                      "purpose": "register", "nonce": nrn, "device_name": "nr"})
        nrst.append(s)
    except Exception: nrst.append(0)
ths = [_th.Thread(target=_nr) for _ in range(2)]
[t.start() for t in ths]; [t.join() for t in ths]
check("nonce race: exactly one winner", sorted(nrst) == [200, 400], f"{sorted(nrst)}")

# L4: 1200 sessions — logout-all revokes every single one.
L4 = SeedUser(); s, l4r, l4ck, _ = L4.login("register", "l4")
for i in range(1199):
    s, l4r, l4ck, _ = L4.login("login", f"l4-{i}")
    assert s == 200, (i, s)
s, r, _, _ = api("POST", "/api/seed/logout-all", {}, token=l4r["access"], cookie=l4ck)
check("L4 logout-all revokes 1200/1200", s == 200 and r.get("revoked") == 1200, f"{r}")

# P4: expired session is collected by the GC ticker.
P4 = SeedUser(); s, p4r, p4ck, _ = P4.login("register", "p4")
s, r, _, _ = api("GET", f"/api/collections/seed_sessions/records?filter=grant_id='{p4r['session_id']}'", token=su)
sid = r["items"][0]["id"]
api("PATCH", f"/api/collections/seed_sessions/records/{sid}", {"expires": "2020-01-01T00:00:00Z"}, token=su)
gone = False
for _ in range(40):
    time.sleep(0.5)
    s, _, _, _ = api("GET", f"/api/collections/seed_sessions/records/{sid}", token=su)
    if s == 404:
        gone = True; break
check("P4 expired session GC'd by ticker", gone, "still present after 20s" if not gone else "")

# P2: ban enforced on data access via e.Auth (no re-SELECT).
s, r, _, _ = api("GET", "/api/collections/notes/records", token=m5r["access"], cookie=m5ck)
check("P2 banned user data access -> 403", s == 403, f"status={s} {str(r)[:80]}")

# L8: expires_in wiring (900 access / 300 challenge with stock settings).
s, r, _, _ = api("POST", "/api/seed/challenge", {"public_key": L4.pk, "purpose": "login"})
ch_ok = s == 200 and r.get("expires_in") == 300
s, r, _, _ = L4.login("login", "l8")
check("L8 challenge expires_in == 300", ch_ok, "")
check("L8 login expires_in == 900", s == 200 and r.get("expires_in") == 900, f"{r}")

# ================== phase 13: soft delete + admin endpoints (2026-09-17) ==================
# Regression checks for REPORT-2026-09-17, rewritten after the fixes onto
# seed_sessions (the only production soft-delete collection now that notes
# is test-only). Soft delete uses deleted_at: empty = alive.
SD = SeedUser(); s, sdr, sdck, _ = SD.login("register", "sd")
su = su_token()

fqg = urllib.parse.quote(f"grant_id = '{sdr['session_id']}'")
s, r, _, _ = api("GET", f"/api/collections/seed_sessions/records?filter={fqg}", token=su)
assert s == 200 and (r or {}).get("items"), (s, r)
sd_rid = r["items"][0]["id"]
check("new session has created_at/updated_at", bool(r["items"][0].get("created_at")) and bool(r["items"][0].get("updated_at")),
      str(r["items"][0])[:140])

# admin-only guards (user token is refused everywhere)
for label, call in [
    ("user /deleted -> 403",       lambda: api("GET", "/api/seed/deleted?collection=seed_sessions", token=sdr["access"], cookie=sdck)),
    ("user hard-delete -> 403",    lambda: api("POST", "/api/seed/hard-delete", {"collection": "seed_sessions", "ids": [sd_rid]}, token=sdr["access"], cookie=sdck)),
    ("user impact -> 403",         lambda: api("GET", f"/api/seed/impact?collection=users&id={sdr['user_id']}", token=sdr["access"], cookie=sdck)),
    ("user erase -> 403",          lambda: api("POST", "/api/seed/erase", {"user_id": sdr["user_id"]}, token=sdr["access"], cookie=sdck)),
]:
    s, r, _, _ = call()
    check(label, s == 403, f"status={s} {str(r)[:60]}")

# soft delete via API keeps the row (deleted_at stamp), nothing is physically removed
s, _, _, _ = api("DELETE", f"/api/collections/seed_sessions/records/{sd_rid}", token=su)
check("session DELETE returns 204 (soft)", s == 204, f"status={s}")
fqi = urllib.parse.quote(f"id = '{sd_rid}'")
s, r, _, _ = api("GET", f"/api/collections/seed_sessions/records?filter={fqi}", token=su)
row = (r or {}).get("items", [{}])[0] if (r or {}).get("items") else {}
check("soft-deleted session kept with deleted_at stamp", s == 200 and bool(row.get("deleted_at")),
      f"status={s} deleted_at={row.get('deleted_at')!r}")
check("soft-deleted session also revoked", bool(row.get("revoked")), str(row)[:120])

# soft-deleted session cookie is dead (middleware isSoftDeleted check)
s, r, _, _ = api("POST", "/api/seed/renew", {}, cookie=sdck)
check("soft-deleted session renew rejected", s == 401, f"status={s}")

# S1 (CRITICAL): live sessions must survive the GC ticker (2s here), and
# fresh soft-deleted rows stay within the retention window.
time.sleep(3)
s, r, _, _ = api("GET", f"/api/collections/seed_sessions/records?filter={fqg}", token=su)
check("S1 session row survives GC ticks", s == 200 and (r or {}).get("totalItems") == 1,
      f"status={s} {str(r)[:80]}")

# S6: superuser restore must actually restore (was a silent no-op).
s, r, _, _ = api("POST", "/api/seed/restore", {"collection": "seed_sessions", "ids": [sd_rid]}, token=su)
check("S6 superuser restore works", s == 200 and (r or {}).get("restored") == 1, f"status={s} {str(r)[:80]}")
s, r, _, _ = api("GET", f"/api/collections/seed_sessions/records?filter={fqi}", token=su)
row = (r or {}).get("items", [{}])[0] if (r or {}).get("items") else {}
check("restored session deleted_at cleared", s == 200 and not row.get("deleted_at"), str(row)[:120])
check("restored session stays revoked (re-login required)", bool(row.get("revoked")), str(row)[:120])

# S4: cross-user restore must stay refused.
api("DELETE", f"/api/collections/seed_sessions/records/{sd_rid}", token=su)
s, r, _, _ = api("POST", "/api/seed/restore", {"collection": "seed_sessions", "ids": [sd_rid]},
                 token=a5["access"], cookie=c5)
check("S4 cross-user restore refused", s == 200 and (r or {}).get("restored") == 0, f"status={s} {str(r)[:80]}")

# S2: the deleted-list endpoint must answer 200 to the superuser.
s, r, _, _ = api("GET", "/api/seed/deleted?collection=seed_sessions", token=su)
check("S2 /deleted answers superuser", s == 200 and isinstance(r, list) and any(x.get("id") == sd_rid for x in (r or [])),
      f"status={s} {str(r)[:100]}")

# hard delete by superuser physically removes the record
s, r, _, _ = api("POST", "/api/seed/hard-delete", {"collection": "seed_sessions", "ids": [sd_rid]}, token=su)
check("superuser hard-delete works", s == 200 and (r or {}).get("deleted") == 1, f"status={s} {str(r)[:80]}")
s, r, _, _ = api("GET", f"/api/collections/seed_sessions/records?filter={fqi}", token=su)
check("hard-deleted session gone", s == 200 and (r or {}).get("totalItems") == 0, f"status={s}")

print(f"DONE fails={sum(fails)}/{len(fails)}")
