#!/usr/bin/env python3
"""Живая проверка «админ+»: первый админ защищён от бана и смены
роли, он один повышает до admin; суперюзер выше защиты."""
import json, subprocess, urllib.request, urllib.error
from nacl.signing import SigningKey

BASE, DOMAIN, DIR = "http://127.0.0.1:8120", "seed.local", "/tmp/pbverify"

def api(method, path, body=None, token=None, cookie=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if token: req.add_header("Authorization", token)
    if cookie: req.add_header("Cookie", "pb_seed=" + cookie)
    data = json.dumps(body).encode() if body is not None else None
    ck = None
    try:
        r = urllib.request.urlopen(req, data=data, timeout=10)
        raw = r.read().decode()
        for h in r.headers.get_all("Set-Cookie") or []:
            if h.startswith("pb_seed="): ck = h.split(";")[0][len("pb_seed="):]
        return r.status, (json.loads(raw) if raw else None), ck
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode() or "null"), None
        except Exception: return e.code, None, None

def console(*args):
    return subprocess.run(["./pbseed", "--dir", DIR] + list(args),
                          capture_output=True, text=True, cwd="/home/user/sss/pbseed-work")

class U:
    def __init__(self):
        self.sk = SigningKey.generate(); self.pk = self.sk.verify_key.encode().hex()
    def register(self):
        s, r, _ = api("POST", "/api/seed/challenge", {"public_key": self.pk, "purpose": "register"})
        sig = self.sk.sign(f"surreal-auth-v1:{DOMAIN}:register:{self.pk}:{r['nonce']}".encode()).signature.hex()
        s, r, ck = api("POST", "/api/seed/login",
                       {"public_key": self.pk, "signature": sig, "purpose": "register",
                        "nonce": r["nonce"], "device_name": "dev"})
        assert s == 200, (s, r)
        self.access, self.cookie, self.id = r["access"], ck, r["user_id"]

results = []
def check(name, cond, extra=""):
    results.append(cond)
    print(("OK   " if cond else "FAIL ") + name + ("" if cond else f"  ← {extra}"))

s, r, _ = api("POST", "/api/collections/_superusers/auth-with-password",
              {"identity": "root@seed.test", "password": "rootpass123"})
su = r["token"]

# поднимаем суточный лимит регистраций, чтобы три ключа прошли подряд
s, r, _ = api("POST", "/api/seed/gateway-config", {"key": "reg_per_day", "value": 50}, token=su)
assert s == 200, (s, r)

P, A, T = U(), U(), U()
P.register(); A.register(); T.register()
check("консоль: первый админ (будущий админ+)", console("user", "role", P.pk, "admin").returncode == 0)
check("консоль: второй админ", console("user", "role", A.pk, "admin").returncode == 0)

s, r, _ = api("PATCH", f"/api/collections/users/records/{P.id}",
              {"banned": True, "ban_reason": "заговор"}, token=A.access, cookie=A.cookie)
check("второй админ НЕ банит админ+ (403)", s == 403, f"{s} {r}")
s, r, _ = api("GET", f"/api/collections/users/records/{P.id}", token=su)
check("админ+ остался незабаненным в базе", s == 200 and r.get("banned") is False, f"{r}")

s, r, _ = api("PATCH", f"/api/collections/users/records/{P.id}", {"role": "user"},
              token=A.access, cookie=A.cookie)
check("второй админ НЕ понижает админ+ (403)", s == 403, f"{s} {r}")

s, r, _ = api("PATCH", f"/api/collections/users/records/{T.id}", {"role": "admin"},
              token=P.access, cookie=P.cookie)
check("админ+ повышает до admin (200)", s == 200, f"{s} {r}")
s, r, _ = api("PATCH", f"/api/collections/users/records/{T.id}", {"role": "moderator"},
              token=A.access, cookie=A.cookie)
check("второй админ понижает нового админа (200)", s == 200, f"{s} {r}")
s, r, _ = api("PATCH", f"/api/collections/users/records/{T.id}", {"role": "admin"},
              token=A.access, cookie=A.cookie)
check("второй админ НЕ повышает до admin (403)", s == 403, f"{s} {r}")

s, r, _ = api("PATCH", f"/api/collections/users/records/{P.id}",
              {"banned": True, "ban_reason": "решение владельца"}, token=su)
check("суперюзер банит админ+ (200)", s == 200, f"{s} {r}")

fails = [i for i, ok in enumerate(results) if not ok]
print(f"\nитог: {len(results)-len(fails)}/{len(results)}")
