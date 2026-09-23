package main

// audit_test.go — журнал действий ведёт слежку за всеми, независимо
// от прав: обычные юзера (входы, правки себя, политики, выходы),
// отказы и неудачные входы тоже фиксируются.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/types"
)

// asJSONRaw приводит значение JSON-поля к байтам независимо от того,
// в каком виде PocketBase его отдал.
//
// Параметры:
//   - v: any — значение из Record.Get.
//
// Возвращает: []byte — содержимое JSON (nil, если тип не распознан).
func asJSONRaw(v any) []byte {
	switch x := v.(type) {
	case types.JSONRaw:
		return x
	case []byte:
		return x
	case string:
		return []byte(x)
	}
	return nil
}

// edRegister проходит полный цикл «челлендж → подпись → регистрация»
// через HTTP и возвращает токен, куку сессии и ид нового пользователя.
//
// Параметры:
//   - t: *testing.T — тест;
//   - do: func(method, url string, headers map[string]string, body string) (*http.Response, string)
//     — исполняющий запросы каркас (serveMux).
//
// Возвращает:
//   - string — токен доступа;
//   - string — кука сессии ("грант.секрет");
//   - string — ид созданного пользователя.
func edRegister(t *testing.T, do func(string, string, map[string]string, string) (*http.Response, string)) (string, string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	pk := strings.ToLower(hex.EncodeToString(pub))
	res, body := do(http.MethodPost, "/api/seed/challenge", nil, `{"public_key":"`+pk+`","purpose":"register"}`)
	if res.StatusCode != 200 {
		t.Fatalf("challenge status=%d body=%s", res.StatusCode, body)
	}
	var ch struct {
		Nonce string `json:"nonce"`
	}
	_ = json.Unmarshal([]byte(body), &ch)
	msg := seedMsgPrefix + seedDomain() + ":register:" + pk + ":" + ch.Nonce
	sig := strings.ToLower(hex.EncodeToString(ed25519.Sign(priv, []byte(msg))))
	res, body = do(http.MethodPost, "/api/seed/login", nil,
		`{"public_key":"`+pk+`","signature":"`+sig+`","purpose":"register","nonce":"`+ch.Nonce+`","device_name":"audit-test"}`)
	if res.StatusCode != 200 {
		t.Fatalf("register status=%d body=%s", res.StatusCode, body)
	}
	var lr struct {
		Access string `json:"access"`
		UserID string `json:"user_id"`
	}
	_ = json.Unmarshal([]byte(body), &lr)
	ck := ""
	for _, c := range res.Cookies() {
		if c.Name == seedCookieName {
			ck = c.Value
		}
	}
	return lr.Access, ck, lr.UserID
}

// TestAuditRegisterAndLogout — вход и выход обычного юзера пишутся
// в журнал с его исполнительством.
func TestAuditRegisterAndLogout(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	do := serveMux(t, app)

	access, ck, uid := edRegister(t, do)
	reg, err := app.FindFirstRecordByData("seed_audit", "action", "auth.register")
	if err != nil || reg == nil {
		t.Fatalf("no auth.register audit row: %v", err)
	}
	if asStr(reg.Get("actor_id")) != uid || asStr(reg.Get("actor_kind")) != seedRoleUser {
		t.Errorf("register actor wrong: id=%q kind=%q", asStr(reg.Get("actor_id")), asStr(reg.Get("actor_kind")))
	}

	res, body := do(http.MethodPost, "/api/seed/logout",
		map[string]string{"Authorization": access, "Cookie": seedCookieName + "=" + ck}, `{}`)
	if res.StatusCode != 200 {
		t.Fatalf("logout status=%d body=%s", res.StatusCode, body)
	}
	out, err := app.FindFirstRecordByData("seed_audit", "action", "session.logout")
	if err != nil || out == nil {
		t.Fatalf("no session.logout audit row: %v", err)
	}
	if asStr(out.Get("actor_id")) != uid {
		t.Errorf("logout actor=%q, want %q", asStr(out.Get("actor_id")), uid)
	}
}

// TestAuditLoginFailedBadSignature — неудачная подпись фиксируется
// гостевой строкой журнала.
func TestAuditLoginFailedBadSignature(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	do := serveMux(t, app)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	pk := strings.ToLower(hex.EncodeToString(pub))
	res, body := do(http.MethodPost, "/api/seed/challenge", nil, `{"public_key":"`+pk+`","purpose":"login"}`)
	if res.StatusCode != 200 {
		t.Fatalf("challenge status=%d body=%s", res.StatusCode, body)
	}
	var ch struct {
		Nonce string `json:"nonce"`
	}
	_ = json.Unmarshal([]byte(body), &ch)
	// Подпись форматно верная (128 hex), но неверная по содержанию.
	res, body = do(http.MethodPost, "/api/seed/login", nil,
		`{"public_key":"`+pk+`","signature":"`+strings.Repeat("ab", 64)+`","purpose":"login","nonce":"`+ch.Nonce+`","device_name":"x"}`)
	if res.StatusCode != 400 {
		t.Fatalf("expected 400, got %d body=%s", res.StatusCode, body)
	}
	row, err := app.FindFirstRecordByData("seed_audit", "action", "auth.login_failed")
	if err != nil || row == nil {
		t.Fatalf("no auth.login_failed audit row: %v", err)
	}
	if asStr(row.Get("actor_kind")) != "guest" {
		t.Errorf("failed login actor_kind=%q, want guest", asStr(row.Get("actor_kind")))
	}
}

// TestAuditSelfUpdateLogged — правка своего профиля обычным юзером
// попадает в журнал со списком изменённых полей.
func TestAuditSelfUpdateLogged(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	u := mustUser(t, app, "audit-self@seed.test")
	_, ck := mustSession(t, app, u.Id, "audit-device")
	do := serveMux(t, app)

	res, body := do(http.MethodPatch, "/api/collections/users/records/"+u.Id,
		map[string]string{"Authorization": mustToken(t, u), "Cookie": seedCookieName + "=" + ck},
		`{"name":"Аудит Имя"}`)
	if res.StatusCode != 200 {
		t.Fatalf("self update status=%d body=%s", res.StatusCode, body)
	}
	row, err := app.FindFirstRecordByData("seed_audit", "action", "records.update")
	if err != nil || row == nil {
		t.Fatalf("no records.update audit row: %v", err)
	}
	if asStr(row.Get("actor_id")) != u.Id || asStr(row.Get("actor_kind")) != seedRoleUser {
		t.Errorf("self update actor wrong: %q %q", asStr(row.Get("actor_id")), asStr(row.Get("actor_kind")))
	}
	// Детали несут коллекцию и список изменённых полей.
	detail := string(asJSONRaw(row.Get("detail")))
	if !strings.Contains(detail, `"users"`) || !strings.Contains(detail, `"name"`) {
		t.Errorf("detail lacks collection/fields: %s", detail)
	}
}

// TestAuditDeniedNotLogged — отклонённая правка (самозапись роли)
// в журнал не попадает: пишутся только состоявшиеся операции.
func TestAuditDeniedNotLogged(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	u := mustUser(t, app, "audit-denied@seed.test")
	_, ck := mustSession(t, app, u.Id, "audit-device")
	do := serveMux(t, app)

	res, body := do(http.MethodPatch, "/api/collections/users/records/"+u.Id,
		map[string]string{"Authorization": mustToken(t, u), "Cookie": seedCookieName + "=" + ck},
		`{"role":"admin"}`)
	if res.StatusCode != 403 {
		t.Fatalf("expected 403, got %d body=%s", res.StatusCode, body)
	}
	rows, err := app.FindRecordsByFilter("seed_audit", "action = {:a}", "", 10, 0, dbx.Params{"a": "records.update"})
	if err == nil && len(rows) > 0 {
		t.Errorf("denied update leaked into audit: %d rows", len(rows))
	}
}

// TestAuditImmutable — журнал нельзя изменить через REST никому, даже
// суперюзеру: создание, правка и удаление строк отклоняются (403).
// Серверная запись при этом работает (журнал пишется самим сервером).
func TestAuditImmutable(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	// Серверная запись — единственный легальный путь наполнения журнала.
	rec := core.NewRecord(mustCollection(t, app, "seed_audit"))
	rec.Set("action", "test.seed")
	if err := app.Save(rec); err != nil {
		t.Fatalf("server-side audit write: %v", err)
	}

	t.Run("create forbidden", func(t *testing.T) {
		runWithApp(t, func(app2 *tests.TestApp) tests.ApiScenario {
			_, su := mustSuperuser(t, app2)
			return tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/api/collections/seed_audit/records",
				Headers:         map[string]string{"Authorization": su},
				Body:            strings.NewReader(`{"action":"forged"}`),
				ExpectedStatus:  403,
				ExpectedContent: []string{`"audit_immutable"`},
			}
		})
	})

	t.Run("update forbidden", func(t *testing.T) {
		runWithApp(t, func(app2 *tests.TestApp) tests.ApiScenario {
			_, su := mustSuperuser(t, app2)
			r := core.NewRecord(mustCollection(t, app2, "seed_audit"))
			r.Set("action", "test.upd")
			if err := app2.Save(r); err != nil {
				t.Fatalf("seed row: %v", err)
			}
			return tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/seed_audit/records/" + r.Id,
				Headers:         map[string]string{"Authorization": su},
				Body:            strings.NewReader(`{"action":"rewritten"}`),
				ExpectedStatus:  403,
				ExpectedContent: []string{`"audit_immutable"`},
			}
		})
	})

	t.Run("delete forbidden", func(t *testing.T) {
		runWithApp(t, func(app2 *tests.TestApp) tests.ApiScenario {
			_, su := mustSuperuser(t, app2)
			r := core.NewRecord(mustCollection(t, app2, "seed_audit"))
			r.Set("action", "test.del")
			if err := app2.Save(r); err != nil {
				t.Fatalf("seed row: %v", err)
			}
			sc := tests.ApiScenario{
				Method:          http.MethodDelete,
				URL:             "/api/collections/seed_audit/records/" + r.Id,
				Headers:         map[string]string{"Authorization": su},
				ExpectedStatus:  403,
				ExpectedContent: []string{`"audit_immutable"`},
			}
			sc.AfterTestFunc = func(t testing.TB, a *tests.TestApp, res *http.Response) {
				if _, err := a.FindRecordById("seed_audit", r.Id); err != nil {
					t.Error("audit row was deleted despite audit_immutable")
				}
			}
			return sc
		})
	})
}

// TestAuditKeepDaysMin — срок хранения журнала не может быть меньше
// недели: меньшие значения округляются вверх, мусор и пусто = вечно.
func TestAuditKeepDaysMin(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},    // пусто = вечно
		{"0", 0},   // ноль = вечно
		{"-5", 0},  // отрицательное = вечно
		{"abc", 0}, // мусор = вечно
		{"3", 7},   // меньше недели -> неделя
		{"6", 7},   // меньше недели -> неделя
		{"7", 7},   // ровно неделя
		{"30", 30}, // месяц как задан
	}
	for _, c := range cases {
		t.Setenv("SEED_AUDIT_KEEP_DAYS", c.in)
		if got := auditKeepDays(); got != c.want {
			t.Errorf("SEED_AUDIT_KEEP_DAYS=%q: got %d, want %d", c.in, got, c.want)
		}
	}
}

// TestAuditPersonalPolicyLogged — личная политика обычного юзера тоже
// пишется в журнал (слежка за всеми, не только за администрацией).
func TestAuditPersonalPolicyLogged(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	u := mustUser(t, app, "audit-policy@seed.test")
	_, ck := mustSession(t, app, u.Id, "audit-device")
	do := serveMux(t, app)

	res, body := do(http.MethodPost, "/api/seed/policy",
		map[string]string{"Authorization": mustToken(t, u), "Cookie": seedCookieName + "=" + ck},
		`{"value":true,"scope":"me"}`)
	if res.StatusCode != 200 {
		t.Fatalf("policy set status=%d body=%s", res.StatusCode, body)
	}
	row, err := app.FindFirstRecordByData("seed_audit", "action", "policy.set")
	if err != nil || row == nil {
		t.Fatalf("no policy.set audit row: %v", err)
	}
	if asStr(row.Get("actor_id")) != u.Id {
		t.Errorf("policy actor=%q, want %q", asStr(row.Get("actor_id")), u.Id)
	}
}
