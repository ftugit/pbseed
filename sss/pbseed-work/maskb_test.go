package main

// maskb_test.go — маска администратора, модель B (маска = подпись).
//
// В отличие от прежней модели (маска выпускала токен юзера и тем самым
// «понижала» исполнителя до его прав), модель B сохраняет исполнителю
// СОБСТВЕННЫЕ права: токен в ответе — это токен самого исполнителя, а
// сессия маски несёт атрибуцию «от чьего имени» (on_behalf_of), которая
// попадает в журнал действий. Эти тесты проверяют:
//
//   - выданный маской токен сохраняет права исполнителя (суперюзер и
//     админ после маски всё ещё могут администрировать);
//   - сессия маски помечена зарезервированным именем и полем
//     on_behalf_of;
//   - действие исполнителя под маской записывается в журнал с указанием
//     «от чьего имени»;
//   - снятие маски отзывает маску-сессию.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// serveMux поднимает маршруты тестового приложения (как это делает
// ApiScenario) и возвращает функцию для произвольного числа запросов к
// одному и тому же приложению. Адрес сокета выставляется локальным,
// чтобы не срабатывал ограничитель частоты.
//
// Параметры:
//   - t: *testing.T — тест;
//   - app: *tests.TestApp — подготовленное приложение (newSeedTestApp).
//
// Возвращает:
//   - func(method, url string, headers map[string]string, body string) (*http.Response, string)
//     — выполненный запрос: статус/заголовки и тело ответа.
func serveMux(t *testing.T, app *tests.TestApp) func(method, url string, headers map[string]string, body string) (*http.Response, string) {
	t.Helper()
	baseRouter, err := apis.NewRouter(app)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	se := new(core.ServeEvent)
	se.App = app
	se.Router = baseRouter
	if err := app.OnServe().Trigger(se, func(*core.ServeEvent) error { return nil }); err != nil {
		t.Fatalf("serve: %v", err)
	}
	mux, err := se.Router.BuildMux()
	if err != nil {
		t.Fatalf("mux: %v", err)
	}
	return func(method, url string, headers map[string]string, body string) (*http.Response, string) {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234" // исключён из ограничителя частоты
		req.Header.Set("content-type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Result(), rec.Body.String()
	}
}

// maskCookieAndAccess разбирает ответ маски: куку сессии и выданный токен.
//
// Параметры:
//   - res: *http.Response — ответ эндпоинта маски;
//   - body: string — тело ответа.
//
// Возвращает:
//   - string — значение куки сессии ("грант.секрет");
//   - string — токен доступа из ответа.
func maskCookieAndAccess(res *http.Response, body string) (string, string) {
	ck := ""
	for _, c := range res.Cookies() {
		if c.Name == seedCookieName {
			ck = c.Value
		}
	}
	var parsed struct {
		Access string `json:"access"`
	}
	_ = json.Unmarshal([]byte(body), &parsed)
	return ck, parsed.Access
}

// TestMaskBSuperuserKeepsPower — модель B: суперюзер надевает маску и
// выданный маской токен ВСЁ ЕЩЁ суперюзерский (может администрировать),
// а действие записывается в журнал «от чьего имени».
func TestMaskBSuperuserKeepsPower(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	target := mustUser(t, app, "maskb-su-target@seed.test")
	victim := mustUser(t, app, "maskb-su-victim@seed.test")
	_, suTok := mustSuperuser(t, app)

	do := serveMux(t, app)

	// Шаг 1: суперюзер надевает маску целевого юзера.
	res1, body1 := do(http.MethodPost, "/api/seed/impersonate",
		map[string]string{"Authorization": suTok},
		`{"user_id":"`+target.Id+`"}`)
	if res1.StatusCode != 200 {
		t.Fatalf("impersonate status=%d body=%s", res1.StatusCode, body1)
	}
	if !strings.Contains(body1, `"masked":true`) || !strings.Contains(body1, `"masked_as":"`+target.Id+`"`) {
		t.Fatalf("impersonate body lacks masked/masked_as: %s", body1)
	}
	maskCk, maskTok := maskCookieAndAccess(res1, body1)
	if maskCk == "" || maskTok == "" {
		t.Fatalf("missing cookie/access: ck=%q", maskCk)
	}

	// Шаг 2: ТОКЕН, выданный маской, всё ещё администрирует — бан жертвы
	// через REST проходит (в прежней модели этот токен был юзерским и бан
	// бы не удался).
	res2, body2 := do(http.MethodPatch, "/api/collections/users/records/"+victim.Id,
		map[string]string{"Authorization": maskTok, "Cookie": seedCookieName + "=" + maskCk},
		`{"banned":true,"ban_reason":"maskb"}`)
	if res2.StatusCode != 200 {
		t.Fatalf("ban under mask status=%d body=%s", res2.StatusCode, body2)
	}

	// Шаг 3: жертва действительно забанена.
	got, err := app.FindRecordById("users", victim.Id)
	if err != nil || !asBool(got.Get("banned")) {
		t.Fatalf("victim not banned: %v", err)
	}

	// Шаг 4: журнал содержит правку «от чьего имени» (маска).
	audit, err := app.FindFirstRecordByData("seed_audit", "action", "records.update")
	if err != nil || audit == nil {
		t.Fatalf("no audit row for users.update: %v", err)
	}
	if asStr(audit.Get("on_behalf_of")) != target.Id {
		t.Errorf("audit on_behalf_of=%q, want %q", asStr(audit.Get("on_behalf_of")), target.Id)
	}
	if asStr(audit.Get("actor_kind")) != "superuser" {
		t.Errorf("audit actor_kind=%q, want superuser", asStr(audit.Get("actor_kind")))
	}
}

// TestMaskBAdminKeepsAdminRights — модель B: админ по роли надевает маску
// и выданный токен сохраняет админские права.
func TestMaskBAdminKeepsAdminRights(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	admin := mustUser(t, app, "maskb-admin@seed.test")
	admin.Set("role", seedRoleAdmin)
	if err := app.Save(admin); err != nil {
		t.Fatalf("save admin: %v", err)
	}
	target := mustUser(t, app, "maskb-adm-target@seed.test")
	victim := mustUser(t, app, "maskb-adm-victim@seed.test")

	do := serveMux(t, app)

	res1, body1 := do(http.MethodPost, "/api/seed/impersonate",
		map[string]string{"Authorization": mustToken(t, admin)},
		`{"user_id":"`+target.Id+`"}`)
	if res1.StatusCode != 200 {
		t.Fatalf("impersonate status=%d body=%s", res1.StatusCode, body1)
	}
	maskCk, maskTok := maskCookieAndAccess(res1, body1)

	// Выданный маской токен — токен админа: бан жертвы проходит.
	res2, body2 := do(http.MethodPatch, "/api/collections/users/records/"+victim.Id,
		map[string]string{"Authorization": maskTok, "Cookie": seedCookieName + "=" + maskCk},
		`{"banned":true}`)
	if res2.StatusCode != 200 {
		t.Fatalf("ban under mask status=%d body=%s", res2.StatusCode, body2)
	}

	audit, err := app.FindFirstRecordByData("seed_audit", "action", "records.update")
	if err != nil || audit == nil {
		t.Fatalf("no audit row: %v", err)
	}
	if asStr(audit.Get("on_behalf_of")) != target.Id {
		t.Errorf("audit on_behalf_of=%q, want %q", asStr(audit.Get("on_behalf_of")), target.Id)
	}
	if asStr(audit.Get("actor_kind")) != seedRoleAdmin {
		t.Errorf("audit actor_kind=%q, want admin", asStr(audit.Get("actor_kind")))
	}
}

// TestMaskBSessionMarked — сессия маски помечена зарезервированным
// именем и атрибуцией «от чьего имени».
func TestMaskBSessionMarked(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	admin := mustUser(t, app, "maskb-sess-admin@seed.test")
	admin.Set("role", seedRoleAdmin)
	if err := app.Save(admin); err != nil {
		t.Fatalf("save admin: %v", err)
	}
	target := mustUser(t, app, "maskb-sess-target@seed.test")

	do := serveMux(t, app)
	res, body := do(http.MethodPost, "/api/seed/impersonate",
		map[string]string{"Authorization": mustToken(t, admin)},
		`{"user_id":"`+target.Id+`"}`)
	if res.StatusCode != 200 {
		t.Fatalf("impersonate status=%d body=%s", res.StatusCode, body)
	}
	maskCk, _ := maskCookieAndAccess(res, body)
	grant := strings.SplitN(maskCk, ".", 2)[0]
	sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", grant)
	if err != nil || sess == nil {
		t.Fatalf("mask session not found: %v", err)
	}
	if asStr(sess.Get("device_name")) != seedAdminDeviceName {
		t.Errorf("device_name=%q, want %q", asStr(sess.Get("device_name")), seedAdminDeviceName)
	}
	if asStr(sess.Get("on_behalf_of")) != target.Id {
		t.Errorf("on_behalf_of=%q, want %q", asStr(sess.Get("on_behalf_of")), target.Id)
	}
	// У админа-по-роли сессия маски принадлежит самому исполнителю.
	if asStr(sess.Get("user")) != admin.Id {
		t.Errorf("mask session user=%q, want wearer %q", asStr(sess.Get("user")), admin.Id)
	}
	// Журнал фиксации самой маски.
	start, err := app.FindFirstRecordByData("seed_audit", "action", "impersonate.start")
	if err != nil || start == nil {
		t.Fatalf("no impersonate.start audit row: %v", err)
	}
}

// TestMaskBUnmask — снятие маски (пустой user_id) отзывает маску-сессию.
func TestMaskBUnmask(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	admin := mustUser(t, app, "maskb-unmask-admin@seed.test")
	admin.Set("role", seedRoleAdmin)
	if err := app.Save(admin); err != nil {
		t.Fatalf("save admin: %v", err)
	}
	target := mustUser(t, app, "maskb-unmask-target@seed.test")

	do := serveMux(t, app)
	res, body := do(http.MethodPost, "/api/seed/impersonate",
		map[string]string{"Authorization": mustToken(t, admin)},
		`{"user_id":"`+target.Id+`"}`)
	if res.StatusCode != 200 {
		t.Fatalf("impersonate status=%d body=%s", res.StatusCode, body)
	}
	maskCk, maskTok := maskCookieAndAccess(res, body)
	grant := strings.SplitN(maskCk, ".", 2)[0]

	// Снятие маски тем же исполнителем.
	res2, body2 := do(http.MethodPost, "/api/seed/impersonate",
		map[string]string{"Authorization": maskTok, "Cookie": seedCookieName + "=" + maskCk},
		`{}`)
	if res2.StatusCode != 200 {
		t.Fatalf("unmask status=%d body=%s", res2.StatusCode, body2)
	}
	if !strings.Contains(body2, `"unmasked":true`) {
		t.Fatalf("unmask body: %s", body2)
	}
	sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", grant)
	if err != nil || sess == nil {
		t.Fatalf("mask session gone: %v", err)
	}
	if !asBool(sess.Get("revoked")) {
		t.Errorf("mask session not revoked after unmask")
	}
}
