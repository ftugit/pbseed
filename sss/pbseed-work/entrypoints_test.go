package main

// entrypoints_test.go — покрытие аудита по точкам входа: новая
// коллекция, созданная через REST/панель, аудируется автоматически
// (ничего добавлять не нужно), а штатные входы юзеров (пароль и
// продление токена) наблюдаются наравне с гейтвеем.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
)

// TestAuditReadableByRoleAdmin — журнал читает не только суперюзер, но
// и роль «admin»; обычный юзер и гость получают отказ; запись журнала
// запрещена всем по-прежнему.
func TestAuditReadableByRoleAdmin(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)

	// Строка в журнале появляется после регистрации.
	priv, pk := gwNewKey(t)
	st, body, ck := gwSession(t, do, priv, pk, "register", "dev")
	if st != 200 {
		t.Fatalf("register status=%d body=%s", st, body)
	}
	var lr struct {
		Access string `json:"access"`
	}
	_ = json.Unmarshal([]byte(body), &lr)
	hdr := map[string]string{
		"Authorization": lr.Access,
		"Cookie":        seedCookieName + "=" + ck,
	}

	// Обычный юзер: журнал закрыт.
	res, _ := do(http.MethodGet, "/api/collections/seed_audit/records", hdr, "")
	if res.StatusCode == 200 {
		t.Fatalf("plain user can read audit")
	}

	// Роль «admin»: журнал читается.
	user, err := app.FindFirstRecordByData("users", "email", pk+"@seed.local")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	user.Set("role", seedRoleAdmin)
	if err := app.Save(user); err != nil {
		t.Fatalf("save role: %v", err)
	}
	res, out := do(http.MethodGet, "/api/collections/seed_audit/records?perPage=10", hdr, "")
	if res.StatusCode != 200 {
		t.Fatalf("role-admin read status=%d body=%s", res.StatusCode, out)
	}
	if !strings.Contains(out, "auth.register") {
		t.Fatalf("audit rows missing: %s", out)
	}

	// Запись журнала запрещена даже админу по роли.
	_, suTok := mustSuperuser(t, app)
	res, out = do(http.MethodPost, "/api/collections/seed_audit/records",
		map[string]string{"Authorization": suTok}, `{"action":"x"}`)
	if res.StatusCode != 403 || !strings.Contains(out, "audit_immutable") {
		t.Fatalf("audit write status=%d body=%s, want 403 audit_immutable", res.StatusCode, out)
	}
}

// TestRestNewCollectionAutoAudited — доказательство для документации:
// чтобы аудитировать новую таблицу со штатным CRUD, не нужно ничего
// делать — сквозные хуки пишут строки для ЛЮБОЙ коллекции.
func TestRestNewCollectionAutoAudited(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)
	hdr := map[string]string{"Authorization": suTok}

	res, body := do(http.MethodPost, "/api/collections", hdr,
		`{"name":"audit_extra","type":"base","fields":[{"name":"title","type":"text"}]}`)
	if res.StatusCode != 200 {
		t.Fatalf("create collection status=%d body=%s", res.StatusCode, body)
	}
	// Создание самой коллекции тоже зафиксировано.
	if row := saFindLatest(t, app, "collections.create"); row == nil {
		t.Fatalf("no collections.create row")
	}

	// Запись в новую коллекцию: создание, правка, удаление.
	res, body = do(http.MethodPost, "/api/collections/audit_extra/records", hdr, `{"title":"раз"}`)
	if res.StatusCode != 200 {
		t.Fatalf("create record status=%d body=%s", res.StatusCode, body)
	}
	var rec struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &rec)

	res, body = do(http.MethodPatch, "/api/collections/audit_extra/records/"+rec.ID, hdr, `{"title":"два"}`)
	if res.StatusCode != 200 {
		t.Fatalf("update record status=%d body=%s", res.StatusCode, body)
	}
	res, body = do(http.MethodDelete, "/api/collections/audit_extra/records/"+rec.ID, hdr, "")
	if res.StatusCode != 204 {
		t.Fatalf("delete record status=%d body=%s", res.StatusCode, body)
	}

	// Все три действия — в журнале с именем новой коллекции.
	for _, act := range []string{"records.create", "records.update", "records.delete"} {
		row := saFindLatest(t, app, act)
		if row == nil {
			t.Fatalf("no %s row for new collection", act)
		}
		if d := fwDetail(row); d["collection"] != "audit_extra" {
			t.Errorf("%s detail=%v, want collection=audit_extra", act, d)
		}
	}
}

// TestStockUserAuthAudited — штатные точки входа юзеров (парольный
// вход и продление токена через REST) наблюдаются, даже если основной
// путь — гейтвей.
func TestStockUserAuthAudited(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)

	u := mustUser(t, app, "stock-auth@seed.test")

	// Неверный пароль — фиксация гостевой строкой.
	res, body := do(http.MethodPost, "/api/collections/users/auth-with-password", nil,
		`{"identity":"stock-auth@seed.local","password":"не тот пароль"}`)
	if res.StatusCode != 400 && res.StatusCode != 403 {
		t.Fatalf("stock bad login status=%d body=%s", res.StatusCode, body)
	}
	row := saFindLatest(t, app, "auth.api_login_failed")
	if row == nil {
		t.Fatalf("no auth.api_login_failed row")
	}
	if d := fwDetail(row); d["method"] != "password" || d["ip_masked"] == "" {
		t.Errorf("failed stock login detail=%v", d)
	}

	// Продление токена штатным эндпоинтом — тоже наблюдаемо (кука
	// обязательна: без неё запрос остановил бы мидлвара сессий).
	_, ck := mustSession(t, app, u.Id, "stock-device")
	res, body = do(http.MethodPost, "/api/collections/users/auth-refresh",
		map[string]string{"Authorization": mustToken(t, u), "Cookie": seedCookieName + "=" + ck}, `{}`)
	if res.StatusCode != 200 {
		t.Fatalf("stock refresh status=%d body=%s", res.StatusCode, body)
	}
	row = saFindLatest(t, app, "auth.api_refresh")
	if row == nil {
		t.Fatalf("no auth.api_refresh row")
	}
	if asStr(row.Get("actor_id")) != u.Id {
		t.Errorf("refresh actor=%q, want %q", asStr(row.Get("actor_id")), u.Id)
	}
}

// saFindLatest возвращает самую свежую строку журнала по действию.
//
// Параметры:
//   - t: *testing.T — тест;
//   - app: core.App — приложение;
//   - action: string — ключ действия.
//
// Возвращает: *core.Record — строка или nil.
func saFindLatest(t *testing.T, app core.App, action string) *core.Record {
	t.Helper()
	rows, err := app.FindRecordsByFilter("seed_audit", `action={:a}`, "-created_at", 1, 0,
		map[string]any{"a": action})
	if err != nil || len(rows) == 0 {
		return nil
	}
	return rows[0]
}
