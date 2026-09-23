package main

// sessions_audit_test.go — привязка журнала к сессиям: у обычных
// юзеров это их кука-сессия, у маски — маска-сессия, у суперюзера —
// настоящая строка в `seed_sessions`, которая не рвётся при обновлении
// токена (продлевается тем же грантом).

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

// saSuperuserLogin входит суперюзером по паролю через штатный эндпоинт
// и возвращает токен из ответа.
//
// Параметры:
//   - t: *testing.T — тест;
//   - do: func — исполняющий запросы каркас (serveMux);
//   - email: string — почта суперюзера;
//   - password: string — пароль.
//
// Возвращает: string — токен доступа.
func saSuperuserLogin(t *testing.T, do func(string, string, map[string]string, string) (*http.Response, string), email, password string) string {
	t.Helper()
	res, body := do(http.MethodPost, "/api/collections/_superusers/auth-with-password", nil,
		`{"identity":"`+email+`","password":"`+password+`"}`)
	if res.StatusCode != 200 {
		t.Fatalf("superuser login status=%d body=%s", res.StatusCode, body)
	}
	var lr struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal([]byte(body), &lr)
	if lr.Token == "" {
		t.Fatalf("superuser login: empty token, body=%s", body)
	}
	return lr.Token
}

// saAuditSession возвращает поле `session` самой свежей строки журнала
// с указанным действием.
//
// Параметры:
//   - t: *testing.T — тест;
//   - app: core.App — приложение;
//   - action: string — ключ действия.
//
// Возвращает: string — значение `session` (пусто, если строк нет).
func saAuditSession(t *testing.T, app core.App, action string) string {
	t.Helper()
	rows, err := app.FindRecordsByFilter("seed_audit", `action={:a}`, "-created_at", 1, 0,
		map[string]any{"a": action})
	if err != nil || len(rows) == 0 {
		t.Fatalf("no audit row %s: %v", action, err)
	}
	return asStr(rows[0].Get("session"))
}

// TestSuperuserSessionBinding — вход суперюзера заводит настоящую
// сессию, и действия этим токеном ссылаются на неё в журнале.
func TestSuperuserSessionBinding(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)

	su, _ := mustSuperuser(t, app)
	tok := saSuperuserLogin(t, do, su.Email(), "root-password-123")

	// Сессия создана: суперюзер, зарезервированное имя, маркер токена.
	sess, err := app.FindFirstRecordByData("seed_sessions", "superuser_id", su.Id)
	if err != nil || sess == nil {
		t.Fatalf("no superuser session row: %v", err)
	}
	if asStr(sess.Get("device_name")) != "@superuser" || asStr(sess.Get("token_hash")) == "" {
		t.Fatalf("superuser session wrong: device=%q token_hash=%q",
			asStr(sess.Get("device_name")), asStr(sess.Get("token_hash")))
	}
	grant := asStr(sess.Get("grant_id"))

	// Строка входа несёт эту же сессию.
	if got := saAuditSession(t, app, "superuser.login"); got != grant {
		t.Errorf("superuser.login session=%q, want %q", got, grant)
	}

	// Действие токеном (бан юзера) тоже ссылается на сессию.
	victim := mustUser(t, app, "session-victim@seed.test")
	res, body := do(http.MethodPatch, "/api/collections/users/records/"+victim.Id,
		map[string]string{"Authorization": tok}, `{"banned":true}`)
	if res.StatusCode != 200 {
		t.Fatalf("ban status=%d body=%s", res.StatusCode, body)
	}
	if got := saAuditSession(t, app, "records.update"); got != grant {
		t.Errorf("records.update session=%q, want %q", got, grant)
	}
}

// TestSuperuserSessionRefreshContinuity — обновление токена не рвёт
// сессию: грант тот же, маркер перевыпущен, журнал продолжает ссылаться
// на ту же сессию.
func TestSuperuserSessionRefreshContinuity(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)

	su, _ := mustSuperuser(t, app)
	tok1 := saSuperuserLogin(t, do, su.Email(), "root-password-123")

	// JWT живёт с точностью до секунды: чтобы обновлённый токен отличался
	// от исходного, ждём больше секунды (в жизни refresh и так позже).
	time.Sleep(1100 * time.Millisecond)
	res, body := do(http.MethodPost, "/api/collections/_superusers/auth-refresh",
		map[string]string{"Authorization": tok1}, `{}`)
	if res.StatusCode != 200 {
		t.Fatalf("refresh status=%d body=%s", res.StatusCode, body)
	}
	var rr struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal([]byte(body), &rr)
	if rr.Token == "" {
		t.Fatalf("refresh token missing, body=%s", body)
	}
	if rr.Token == tok1 {
		t.Fatalf("refresh returned the identical token")
	}

	rows, err := app.FindRecordsByFilter("seed_sessions", `superuser_id={:u}`, "", 10, 0,
		map[string]any{"u": su.Id})
	if err != nil || len(rows) != 1 {
		t.Fatalf("superuser sessions=%d, want exactly 1 (refresh must not fork)", len(rows))
	}
	sess := rows[0]
	if asStr(sess.Get("token_hash")) != suTokenHash(rr.Token) {
		t.Errorf("session token_hash not rotated to the refreshed token")
	}
	grant := asStr(sess.Get("grant_id"))

	victim := mustUser(t, app, "session-refresh@seed.test")
	res, body = do(http.MethodPatch, "/api/collections/users/records/"+victim.Id,
		map[string]string{"Authorization": rr.Token}, `{"banned":true}`)
	if res.StatusCode != 200 {
		t.Fatalf("ban status=%d body=%s", res.StatusCode, body)
	}
	if got := saAuditSession(t, app, "records.update"); got != grant {
		t.Errorf("post-refresh session=%q, want %q", got, grant)
	}
}

// TestUserSessionBinding — действия обычного юзера ссылаются на его
// кука-сессию (грант из куки).
func TestUserSessionBinding(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)

	access, ck, uid := edRegister(t, do)
	res, body := do(http.MethodPatch, "/api/collections/users/records/"+uid,
		map[string]string{"Authorization": access, "Cookie": seedCookieName + "=" + ck},
		`{"name":"Сессия Имя"}`)
	if res.StatusCode != 200 {
		t.Fatalf("self update status=%d body=%s", res.StatusCode, body)
	}
	want := strings.SplitN(ck, ".", 2)[0] // грант — первая половина куки
	if got := saAuditSession(t, app, "records.update"); got != want {
		t.Errorf("user records.update session=%q, want %q", got, want)
	}
	// Сама регистрация тоже несёт сессию (кука уже стоит в ответе).
	if got := saAuditSession(t, app, "auth.register"); got != want {
		t.Errorf("auth.register session=%q, want %q", got, want)
	}
}

// TestMaskSessionBinding — действия под маской ссылаются на
// маска-сессию (кука маски), а не на сессию исполнителя.
func TestMaskSessionBinding(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)

	target := mustUser(t, app, "mask-session-target@seed.test")
	_, suTok := mustSuperuser(t, app)

	res, body := do(http.MethodPost, "/api/seed/impersonate",
		map[string]string{"Authorization": suTok}, `{"user_id":"`+target.Id+`"}`)
	if res.StatusCode != 200 {
		t.Fatalf("impersonate status=%d body=%s", res.StatusCode, body)
	}
	maskCk, _ := maskCookieAndAccess(res, body)
	if maskCk == "" {
		t.Fatalf("no mask cookie")
	}
	maskGrant := strings.SplitN(maskCk, ".", 2)[0]

	// Под маской исполнитель правит профиль цели — своим токеном, но
	// кука несёт маска-сессию.
	res, body = do(http.MethodPatch, "/api/collections/users/records/"+target.Id,
		map[string]string{"Authorization": suTok, "Cookie": seedCookieName + "=" + maskCk},
		`{"name":"Под Маской"}`)
	if res.StatusCode != 200 {
		t.Fatalf("masked update status=%d body=%s", res.StatusCode, body)
	}
	row, err := app.FindFirstRecordByData("seed_audit", "action", "records.update")
	if err != nil || row == nil {
		t.Fatalf("no records.update row: %v", err)
	}
	if got := asStr(row.Get("session")); got != maskGrant {
		t.Errorf("masked session=%q, want mask grant %q", got, maskGrant)
	}
	if got := asStr(row.Get("on_behalf_of")); got != target.Id {
		t.Errorf("on_behalf_of=%q, want %q", got, target.Id)
	}
}
