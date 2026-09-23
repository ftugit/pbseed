#!/usr/bin/env python3
"""Живая проверка сервиса без тестового сьюта: честность README,
роли, суперюзер, заголовок-IP, кик по смене адреса, хуки, аудит."""
import hashlib, hmac, json, subprocess, urllib.parse, urllib.request, urllib.error
from nacl.signing import SigningKey

BASE = "http://127.0.0.1:8120"
DOMAIN = "seed.local"
DIR = "/tmp/pbverify"
SU_EMAIL, SU_PASS = "root@seed.test", "rootpass123"
IPKEY = b"test-ip-key-0123456789abcdef"

results = []
def check(name, cond, extra=""):
    results.append((name, bool(cond), extra))
    print(("OK   " if cond else "FAIL ") + name + ("" if cond else f"  ← {extra}"))

def api(method, path, body=None, token=None, cookie=None, ip=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if token: req.add_header("Authorization", token)
    if cookie: req.add_header("Cookie", "pb_seed=" + cookie)
    if ip: req.add_header("CF-Connecting-IP", ip)
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

class SeedUser:
    def __init__(self):
        self.sk = SigningKey.generate(); self.pk = self.sk.verify_key.encode().hex()
        self.access = self.cookie = self.grant = None
        self.id = None
    def login(self, purpose, device, ip):
        s, r, _ = api("POST", "/api/seed/challenge", {"public_key": self.pk, "purpose": purpose})
        if s != 200: return s, r
        nonce = r["nonce"]
        sig = self.sk.sign(f"surreal-auth-v1:{DOMAIN}:{purpose}:{self.pk}:{nonce}".encode()).signature.hex()
        s, r, ck = api("POST", "/api/seed/login",
                       {"public_key": self.pk, "signature": sig, "purpose": purpose,
                        "nonce": nonce, "device_name": device}, ip=ip)
        if s == 200:
            self.access, self.cookie, self.grant = r["access"], ck, ck.split(".")[0]
            self.id = r.get("user_id")
        return s, r
    def register(self, ip): return self.login("register", "dev-" + self.pk[:6], ip)
    def renew(self, ip=None):
        s, r, _ = api("POST", "/api/seed/renew", {}, token=self.access, cookie=self.cookie, ip=ip)
        return s, r

SU = {}
def su_token():
    s, r, _ = api("POST", "/api/collections/_superusers/auth-with-password",
                  {"identity": SU_EMAIL, "password": SU_PASS})
    assert s == 200, (s, r)
    SU["token"] = r["token"]; return SU["token"]

def audit_rows(limit=200):
    s, r, _ = api("GET", f"/api/collections/seed_audit/records?perPage={limit}&sort=-created_at", token=SU["token"])
    assert s == 200, (s, r)
    return r["items"]

def rw(rows, action, pred=None):
    return [x for x in rows if x["action"] == action and (pred is None or pred(x))]

# ================================================================
print("== Фаза 0: суперюзер и честность README ==")
su = su_token()
check("суперюзер получает токен", bool(su))

routes = [
    ("POST", "/api/seed/challenge", {"public_key": "x"}), ("POST", "/api/seed/login", {}),
    ("POST", "/api/seed/renew", None),
    ("POST", "/api/seed/logout", None), ("POST", "/api/seed/logout-all", None),
    ("GET", "/api/seed/sessions", None), ("GET", "/api/seed/policy?key=kick_on_ip_change", None),
    ("POST", "/api/seed/policy", {}), ("DELETE", "/api/seed/policy?key=kick_on_ip_change", None),
    ("POST", "/api/seed/geo/update", {}), ("GET", "/api/seed/geo/status", None),
    ("GET", "/api/seed/geo/lookup?ip=1.2.3.4", None), ("POST", "/api/seed/hard-delete", {}),
    ("POST", "/api/seed/restore", {}), ("GET", "/api/seed/deleted", None),
    ("POST", "/api/seed/erase", {}), ("GET", "/api/seed/impact?collection=users&id=x", None),
    ("POST", "/api/seed/impersonate", {}), ("GET", "/api/seed/firewall/status", None),
    ("POST", "/api/seed/firewall/unlock", {}), ("GET", "/api/seed/gateway-config", None),
    ("POST", "/api/seed/gateway-config", {}), ("DELETE", "/api/seed/gateway-config?key=login", None),
    ("GET", "/api/collections/users/records/cursor", None),
]
missing = []
for m, p, b in routes:
    s, _, _ = api(m, p, b, token=su)
    if s == 404: missing.append(f"{m} {p}")
check(f"README: все {len(routes)} эндпоинтов существуют (нет 404)", not missing, str(missing))

s, r, _ = api("POST", "/api/seed/gateway-config", {"key": "register", "value": False}, token=su)
check("README: гейтвей-конфиг доступен суперюзеру", s == 200, f"{s} {r}")
u_dis = SeedUser()
s, r = u_dis.register("10.50.0.2")
check("README: 403 register_disabled при выключенной регистрации",
      s == 403 and r and r.get("error") == "register_disabled", f"{s} {r}")
s, r, _ = api("DELETE", "/api/seed/gateway-config?key=register", token=su)
check("возврат регистрации: откат удалением переопределения", s == 200 and r.get("deleted") == 1, f"{s} {r}")

s, r, _ = api("GET", "/api/seed/gateway-config", token=su)
check("README: ответ гейтвей-конфига прочитан", s == 200 and r, f"status={s} body={str(r)[:200]}")
params = {p["key"]: p for p in (r or {}).get("params", [])}
expect = {"register": "1", "login": "1", "renew": "1", "reg_per_day": "2",
          "logins_per_day": "100", "max_fails": "10", "fail_lock": "15m"}
check("README: 7 параметров гейтвея и их стандарты",
      len(params) == 7 and all(params.get(k, {}).get("default") == v for k, v in expect.items()))

# ================================================================
print("\n== Фаза 1: роли — чтение и записи ==")
U, M, A = SeedUser(), SeedUser(), SeedUser()
s, r = U.register("10.51.1.1"); check("регистрация юзера", s == 200, f"{s} {r}")
s, r = M.register("10.51.2.1"); check("регистрация модератора", s == 200, f"{s} {r}")
s, r = A.register("10.51.3.1"); check("регистрация админа", s == 200, f"{s} {r}")
check("консоль выдаёт роль модератора", console("user", "role", M.pk, "moderator").returncode == 0)
check("консоль выдаёт роль админа", console("user", "role", A.pk, "admin").returncode == 0)

for who, name, want in ((U, "юзер", 1), (M, "модератор", 3), (A, "админ", 3)):
    s, r, _ = api("GET", "/api/collections/users/records?perPage=100", token=who.access, cookie=who.cookie)
    n = len(r["items"]) if s == 200 and r else -1
    check(f"список пользователей: {name} видит {want}", s == 200 and n == want, f"status={s} n={n}")
s, r, _ = api("GET", "/api/collections/users/records?perPage=100")
check("гость: список пользователей пуст (правило-фильтр)", s == 200 and len(r["items"]) == 0)

def view_rec(who, rid):
    s, r, _ = api("GET", f"/api/collections/users/records/{rid}", token=who.access, cookie=who.cookie)
    return s
for who, name, ok in ((U, "юзер", False), (M, "модератор", True), (A, "админ", True)):
    s = view_rec(who, A.id)
    check(f"чужой профиль: {name} — {'видит' if ok else 'не видит (404)'}",
          (s == 200) == ok, f"status={s}")

def patch_rec(who, rid, body):
    s, r, _ = api("PATCH", f"/api/collections/users/records/{rid}", body, token=who.access, cookie=who.cookie)
    return s, r
s, r = patch_rec(U, U.id, {"name": "self-name"})
check("юзер правит СВОЮ запись (незащищённое поле)", s == 200, f"{s} {r}")
s, r = patch_rec(U, A.id, {"name": "hack"})
check("юзер НЕ правит чужую запись", s in (403, 404), f"{s} {r}")
s, r = patch_rec(M, U.id, {"name": "mod-hack"})
check("модератор НЕ правит чужую запись (правило: своё+админ)", s in (403, 404), f"{s} {r}")
s, r = patch_rec(A, U.id, {"name": "by-admin"})
check("админ правит чужую запись", s == 200, f"{s} {r}")
s, r = patch_rec(U, U.id, {"role": "admin"})
check("юзер НЕ повышает себе роль (защищённое поле)", s == 403, f"{s} {r}")
s, r = patch_rec(M, M.id, {"role": "admin"})
check("модератор НЕ повышает себе роль", s == 403, f"{s} {r}")
s, r = patch_rec(A, U.id, {"role": "admin"})
check("админ НЕ назначает админа через API", s == 403, f"{s} {r}")
s, r, _ = api("POST", "/api/collections/users/records", {"email": "x@seed.local", "password": "password1234"}, token=U.access, cookie=U.cookie)
check("создание записи через штатный API закрыто", s in (400, 403, 404), f"{s} {r}")

print("\n== Фаза 2: админские поверхности ==")
for who, name, ok in ((U, "юзер", False), (M, "модератор", False), (A, "админ", True)):
    s, r, _ = api("GET", "/api/seed/gateway-config", token=who.access, cookie=who.cookie)
    check(f"гейтвей-конфиг: {name} — {'доступен' if ok else 'запрещён (403)'}", (s == 200) == ok, f"status={s} body={str(r)[:120]}")
    s, r, _ = api("GET", "/api/collections/seed_audit/records?perPage=5", token=who.access, cookie=who.cookie)
    check(f"журнал: {name} — {'доступен' if ok else 'запрещён (403)'}", (s == 200) == ok, f"status={s}")
for path in ("/api/seed/firewall/status", "/api/seed/geo/status"):
    s, r, _ = api("GET", path, token=A.access, cookie=A.cookie)
    check(f"{path}: админ запрещён (только суперюзер)", s == 403, f"status={s}")
    s, r, _ = api("GET", path, token=su)
    check(f"{path}: суперюзер работает", s == 200, f"status={s}")

# политики
s, r, _ = api("POST", "/api/seed/policy", {"key": "kick_on_ip_change", "value": True, "scope": "me"}, token=U.access, cookie=U.cookie)
check("политика: юзер пишет ЛИЧНУЮ", s == 200, f"{s} {r}")
s, r, _ = api("POST", "/api/seed/policy", {"key": "kick_on_ip_change", "value": True, "scope": "global"}, token=U.access, cookie=U.cookie)
check("политика: юзер НЕ пишет глобальную (403)", s == 403, f"{s} {r}")
s, r, _ = api("POST", "/api/seed/policy", {"key": "kick_on_ip_change", "value": True, "scope": "global"}, token=M.access, cookie=M.cookie)
check("политика: модератор НЕ пишет глобальную (403)", s == 403, f"{s} {r}")
s, r, _ = api("POST", "/api/seed/policy", {"key": "kick_on_ip_change", "value": True, "scope": "global", "locked": True}, token=A.access, cookie=A.cookie)
check("политика: админ пишет глобальную с замком", s == 200, f"{s} {r}")
s, r, _ = api("POST", "/api/seed/policy", {"key": "kick_on_ip_change", "value": False, "scope": "me"}, token=M.access, cookie=M.cookie)
check("политика: личное переопределение при замке запрещено (403)", s == 403, f"{s} {r}")
s, r, _ = api("DELETE", "/api/seed/policy?key=kick_on_ip_change&scope=global", token=A.access, cookie=A.cookie)
check("политика: админ снимает глобальную", s == 200, f"{s} {r}")

# токен без куки
s, r, _ = api("GET", "/api/seed/sessions", token=U.access)
check("токен без куки: 401 session_required", s == 401 and r.get("error") == "session_required", f"{s} {r}")

# ================================================================
print("\n== Фаза 3: имперсонация (маска) ==")
s, r, _ = api("POST", "/api/seed/impersonate", {"user_id": U.id}, token=M.access, cookie=M.cookie)
check("маска: модератору запрещено (403)", s == 403, f"{s} {r}")
s, r, mk = api("POST", "/api/seed/impersonate", {"user_id": U.id}, token=A.access, cookie=A.cookie)
check("маска: админ входит под юзером", s == 200 and mk, f"{s} {r}")
if s == 200:
    s2, r2, _ = api("GET", "/api/seed/sessions", token=r["access"], cookie=mk)
    mask_sess = [x for x in (r2 or []) if x.get("current") and x.get("device_name") == "@administrator"]
    check("маска: у исполнителя видна своя маска-сессия", s2 == 200 and len(mask_sess) == 1, f"{s2} {r2}")
    s3, r3, _ = api("POST", "/api/seed/impersonate", {"user_id": ""}, token=r["access"], cookie=mk)
    check("маска: снятие маски", s3 == 200 and r3.get("unmasked"), f"{s3} {r3}")

# ================================================================
print("\n== Фаза 4: заголовок-IP, история и кик ==")
K = SeedUser()
s, r = K.register("10.52.1.1")
check("регистрация под заголовком-адресом 10.52.1.1", s == 200, f"{s} {r}")
rows = audit_rows()
reg = rw(rows, "auth.register")
hmac_ok, masked_ok = False, False
for x in reg:
    d = x.get("detail", {})
    if d.get("ip_masked") == "10.52.*.*":
        masked_ok = True
        want = "h1:" + hmac.new(IPKEY, b"10.52.1.1|", hashlib.sha256).hexdigest()
        hmac_ok = d.get("ip_hash") == want
check("журнал: адрес взят из заголовка (маска 10.52.*.*)", masked_ok)
check("журнал: ip_hash = HMAC(IP|) с ключом окружения", hmac_ok)

s, r, _ = api("GET", "/api/seed/sessions", token=K.access, cookie=K.cookie, ip="10.52.1.1")
check("сессии: у нового юзера одна живая сессия", s == 200 and len(r) == 1, f"{s} {r}")

# отзыв одной своей сессии по гранту (эндпоинт /api/seed/revoke)
K2 = SeedUser(); K2.sk, K2.pk = K.sk, K.pk
s2, r2 = K2.login("login", "revokable", "10.52.1.1")
check("вторая сессия для отзыва", s2 == 200, f"{s2} {r2}")
s2, r2, _ = api("POST", "/api/seed/revoke", {"grant_id": K2.grant}, token=K.access, cookie=K.cookie, ip="10.52.1.1")
check("revoke: своя сессия отзывается по гранту", s2 == 200 and r2.get("ok"), f"{s2} {r2}")
s2, r2, _ = api("POST", "/api/seed/revoke", {"grant_id": K2.grant}, token=M.access, cookie=M.cookie, ip="10.51.2.1")
check("revoke: чужой грант — 404", s2 == 404, f"{s2} {r2}")

s, r = K.renew("10.52.1.1")
check("продление с тем же адресом — 200", s == 200, f"{s} {r}")
s, r = K.renew("10.52.2.2")
check("продление с новым адресом без кика — 200", s == 200, f"{s} {r}")
s, r, _ = api("GET", "/api/seed/sessions", token=K.access, cookie=K.cookie, ip="10.52.2.2")
mine = next((x for x in (r or []) if x.get("session_id") == K.grant), None)
hist = mine.get("history") if mine else None
check("история сессии: смена адреса записана", isinstance(hist, list) and any(h.get("event") == "ip_changed" for h in hist), f"{hist}")
s, r = K.renew("10.52.2.2")
check("сессия: новый адрес принят (повторное продление без новой смены)", s == 200, f"{s} {r}")
s, r, _ = api("GET", "/api/seed/sessions", token=K.access, cookie=K.cookie, ip="10.52.2.2")
mine = next((x for x in (r or []) if x.get("session_id") == K.grant), None)
n_ipch = len([h for h in (mine or {}).get("history", []) if h.get("event") == "ip_changed"])
check("сессия: событие смены ровно одно (адрес зафиксирован)", n_ipch == 1, f"n={n_ipch}")

s, r, _ = api("POST", "/api/seed/policy", {"key": "kick_on_ip_change", "value": True, "scope": "me"}, token=K.access, cookie=K.cookie, ip="10.52.2.2")
check("кик: юзер включает личную политику", s == 200, f"{s} {r}")
s, r = K.renew("10.52.3.3")
check("кик: продление с новым адресом — 401 ip_changed", s == 401 and r.get("error") == "ip_changed", f"{s} {r}")
s, r, _ = api("GET", "/api/seed/sessions", token=K.access, cookie=K.cookie, ip="10.52.3.3")
check("кик: сессия отозвана", s == 401 or (s == 200 and (not r or r[0].get("revoked"))), f"{s} {str(r)[:200]}")
rows = audit_rows()
kf = rw(rows, "auth.renew_failed", lambda x: x.get("detail", {}).get("reason") == "ip_changed")
check("аудит: ровно одна строка renew_failed(ip_changed)", len(kf) == 1, f"n={len(kf)}")

# ================================================================
print("\n== Фаза 5: хук автонастройки гейтвея ==")
s, r, _ = api("POST", "/api/seed/gateway-config", {"key": "reg_per_day", "value": 60}, token=A.access, cookie=A.cookie)
check("хук-вход: админ ослабляет reg_per_day=60 (200)", s == 200, f"{s} {r}")
s, r, _ = api("GET", "/api/seed/gateway-config", token=A.access, cookie=A.cookie)
p = next(x for x in r["params"] if x["key"] == "reg_per_day")
check("хук: переопределение снято автонастройкой (снова стандарт)", p["value"] == "2" and p["source"] != "база", f"{p}")
s, r, _ = api("POST", "/api/seed/gateway-config", {"key": "reg_per_day", "value": 5}, token=A.access, cookie=A.cookie)
check("хук: умеренное значение (5) не трогается", s == 200, f"{s} {r}")
s, r, _ = api("GET", "/api/seed/gateway-config", token=A.access, cookie=A.cookie)
p = next(x for x in r["params"] if x["key"] == "reg_per_day")
check("хук: 5 осталось в базе", p["value"] == "5" and p["source"] == "база", f"{p}")
s, r, _ = api("DELETE", "/api/seed/gateway-config?key=reg_per_day", token=A.access, cookie=A.cookie)
check("откат переопределения удалением", s == 200 and r.get("deleted") == 1, f"{s} {r}")
s, r, _ = api("POST", "/api/seed/gateway-config", {"key": "reg_per_day", "value": 60}, token=M.access, cookie=M.cookie)
check("хук: модератор до конфига не допущен (403)", s == 403, f"{s} {r}")

# ================================================================
print("\n== Фаза 6: хук каскада бана ==")
V = SeedUser()
s, r = V.register("10.53.1.1"); check("жертва бана: регистрация", s == 200, f"{s} {r}")
s, r = V.login("login", "second", "10.53.1.1"); check("жертва бана: вторая сессия", s == 200, f"{s} {r}")
s, r = patch_rec(A, V.id, {"banned": True, "ban_reason": "флуд"})
check("бан через REST админом", s == 200, f"{s} {r}")
rows = audit_rows()
kills = rw(rows, "session.kill", lambda x: x.get("detail", {}).get("reason") == "ban_cascade")
check("хук каскада: ровно одна строка session.kill(ban_cascade)", len(kills) == 1, f"n={len(kills)}")
check("хук каскада: отозваны обе сессии", kills and kills[0].get("detail", {}).get("revoked") == 2, f"{kills[:1]}")
check("хук каскада: исполнитель — админ", kills and kills[0].get("actor_kind") == "admin", f"{kills[:1]}")
s, r = V.renew("10.53.1.1")
check("забаненный: сессии отозваны каскадом — 401 revoked", s == 401 and r.get("error") == "revoked", f"{s} {r}")
s, r = patch_rec(A, V.id, {"ban_reason": "флуд и спам"})
check("повторная правка забаненного (200)", s == 200, f"{s} {r}")
rows = audit_rows()
kills2 = rw(rows, "session.kill", lambda x: x.get("detail", {}).get("reason") == "ban_cascade")
check("хук каскада: при нуле отзывов дубль строки НЕ появился", len(kills2) == 1, f"n={len(kills2)}")
V2 = SeedUser(); V2.sk, V2.pk = V.sk, V.pk
s, r = V2.login("login", "after-unban", "10.53.1.2")
check("пока бан действует: вход — 403 banned", s == 403 and r.get("error") == "banned", f"{s} {r}")
s, r = patch_rec(A, V.id, {"banned": False, "ban_reason": ""})
check("разбан через REST", s == 200, f"{s} {r}")
s, r = V2.login("login", "after-unban-2", "10.53.1.3")
check("после разбана вход снова работает", s == 200, f"{s} {r}")

# ================================================================
print("\n== Фаза 7: целостность аудита (дубли/пропуски) ==")
rows = audit_rows(500)
def dcount(action, pred=None): return len(rw(rows, action, pred))
acts = {}
for x in rows: acts[x["action"]] = acts.get(x["action"], 0) + 1
print("картина журнала по действиям:")
for k in sorted(acts): print(f"  {k}: {acts[k]}")

seen, dupes = set(), []
for x in rows:
    key = (x["action"], x.get("actor_id"), json.dumps(x.get("detail"), sort_keys=True), x.get("created_at"))
    if key in seen: dupes.append(key[0])
    seen.add(key)
check("аудит: полных дублей строк нет", not dupes, str(dupes[:5]))

check("аудит: регистрации записаны", dcount("auth.register") >= 5)
check("аудит: входы записаны", dcount("auth.login") >= 2)
check("аудит: отказ регистрации записан", dcount("auth.register_denied") >= 1)
check("аудит: маска записана", dcount("impersonate.start") == 1 and dcount("impersonate.stop") == 1)
gc = rw(rows, "gateway.config")
sets_su = [x for x in gc if x.get("detail", {}).get("op") == "set" and x.get("actor_kind") == "superuser"]
sets_a = [x for x in gc if x.get("detail", {}).get("op") == "set" and x.get("actor_kind") == "admin"]
hook_del = [x for x in gc if x.get("detail", {}).get("hook") == "autotune"]
man_del = [x for x in gc if x.get("detail", {}).get("op") == "delete" and not x.get("detail", {}).get("hook")]
check("аудит: 1 смена конфига от суперюзера (регистрация выкл)", len(sets_su) == 1, f"n={len(sets_su)}")
check("аудит: 2 смены конфига от админа (60 и 5)", len(sets_a) == 2, f"n={len(sets_a)}")
check("аудит: снос автонастройкой атрибутирован хуком (ровно 1 строка)", len(hook_del) == 1, f"n={len(hook_del)}")
check("аудит: ручные удаления параметров (ровно 2 строки: регистр и лимит, без хука)", len(man_del) == 2, f"n={len(man_del)}")
check("аудит: консоль роли писала напрямую, строк журнала от неё нет",
      all(x.get("actor_kind") != "console" for x in rows))

# ================================================================
print("\n== ИТОГ ==")
fails = [x for x in results if not x[1]]
print(f"проверок: {len(results)}; прошло: {len(results)-len(fails)}; провалов: {len(fails)}")
for f in fails: print("  ПРОВАЛ:", f[0], f[2])
