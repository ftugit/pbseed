package main

// automation_test.go — регрессионные тесты по мотивам живой проверки
// без сьюта (сентябрь 2026). Живой зонд поймал три дефекта, которые
// синтетика того времени не замечала:
//
//  1. Отказ, который не останавливал цепочку: `seedErr` возвращал
//     результат записи ответа (`nil` при успехе), и хуки/мидлвары
//     шли дальше поверх записанного 401/403 — клиент получал
//     склеенное тело (ошибка + успешный JSON), а запрещённое
//     действие исполнялось. Тесты ниже требуют ЧИСТОЕ тело отказа
//     (ровно один JSON) и отсутствие побочных эффектов в базе.
//  2. Хук «автонастройка» не видел запись конфига через эндпоинт
//     `/api/seed/gateway-config` (внутреннее сохранение минует
//     REST-хуки коллекции) — проверяются оба пути записи.
//  3. Повторный вход суперюзера в ту же секунду выпускает тот же
//     токен, и создание второй строки сессии падало на уникальном
//     индексе `token_hash` — проверяется идемпотентное переиспользование.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// oneJSON проверяет, что тело ответа — ровно один объект JSON (без
// хвоста), и возвращает его. Это главный барьер против склеенных
// ответов «отказ + успех», которые раньше проходили тесты на
// подстроки.
//
// Параметры:
//   - t: *testing.T — тест;
//   - body: string — тело ответа.
//
// Возвращает: map[string]any — разобранный объект.
func oneJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(body))
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("тело не JSON: %v (тело: %.120s)", err, body)
	}
	if dec.More() {
		t.Fatalf("тело содержит больше одного JSON (склеенный ответ): %.200s", body)
	}
	return out
}

// newAutomationApp — каркас общего назначения плюс хуки автоматизации
// (общий каркас их не ставит: они появились позже него).
//
// Параметры:
//   - t: *testing.T — тест.
//
// Возвращает: *tests.TestApp — приложение с хуками автоматизации.
func newAutomationApp(t *testing.T) *tests.TestApp {
	t.Helper()
	app := newSeedTestApp(t)
	installAutomationHooks(app)
	return app
}

// gwAuditHookRows считает строки журнала конфигурации, атрибутированные
// хуком (деталь несёт имя хука).
//
// Параметры:
//   - t: *testing.T — тест;
//   - app: core.App — приложение;
//   - hook: string — имя хука из `detail.hook`.
//
// Возвращает: []*core.Record — найденные строки.
func gwAuditHookRows(t *testing.T, app core.App, hook string) []*core.Record {
	t.Helper()
	rows, err := app.FindRecordsByFilter("seed_audit", `action={:a}`, "-created_at", 200, 0,
		map[string]any{"a": "gateway.config"})
	if err != nil {
		t.Fatalf("журнал: %v", err)
	}
	out := make([]*core.Record, 0, len(rows))
	for _, r := range rows {
		if fwDetail(r)["hook"] == hook {
			out = append(out, r)
		}
	}
	return out
}

// TestRejectStopsChainCleanBody — отказ обязан рвать цепочку: клиент
// получает ровно один чистый JSON ошибки, а база — никаких изменений.
// Регрессия против `seedErr`, возвращавшего nil (исполнение продолжалось
// поверх записанного отказа).
func TestRejectStopsChainCleanBody(t *testing.T) {
	t.Run("гость без токена: чистый 401 без тела конфига", func(t *testing.T) {
		app := newSeedTestApp(t)
		do := serveMux(t, app)
		res, body := do(http.MethodGet, "/api/seed/gateway-config", nil, "")
		if res.StatusCode != 401 {
			t.Fatalf("status=%d, want 401", res.StatusCode)
		}
		got := oneJSON(t, body)
		if got["error"] != "auth_required" {
			t.Fatalf("error=%v, want auth_required", got["error"])
		}
		if _, leaked := got["params"]; leaked {
			t.Fatalf("в отказ просочился конфиг: %.200s", body)
		}
	})

	t.Run("самоповышение роли: 403 и роль в базе НЕ меняется", func(t *testing.T) {
		app := newSeedTestApp(t)
		do := serveMux(t, app)
		u := mustUser(t, app, "chain-stop@seed.test")
		_, ck := mustSession(t, app, u.Id, "dev")
		res, body := do(http.MethodPatch, "/api/collections/users/records/"+u.Id,
			map[string]string{"Authorization": mustToken(t, u), "Cookie": seedCookieName + "=" + ck},
			`{"role":"admin"}`)
		if res.StatusCode != 403 {
			t.Fatalf("status=%d, want 403; body=%.120s", res.StatusCode, body)
		}
		oneJSON(t, body) // склеенного «403 + успешное тело» быть не должно
		got, err := app.FindRecordById("users", u.Id)
		if err != nil {
			t.Fatalf("повторное чтение: %v", err)
		}
		if strings.EqualFold(asStr(got.Get("role")), seedRoleAdmin) {
			t.Fatalf("роль сохранилась несмотря на отказ: %q", asStr(got.Get("role")))
		}
	})

	t.Run("забаненный: мидлвар рвёт цепочку до обработчика", func(t *testing.T) {
		app := newSeedTestApp(t)
		do := serveMux(t, app)
		u := mustUser(t, app, "chain-stop-banned@seed.test")
		u.Set("banned", true)
		u.Set("ban_reason", "проверка")
		if err := app.Save(u); err != nil {
			t.Fatalf("бан: %v", err)
		}
		_, ck := mustSession(t, app, u.Id, "dev")
		res, body := do(http.MethodGet, "/api/seed/sessions",
			map[string]string{"Authorization": mustToken(t, u), "Cookie": seedCookieName + "=" + ck}, "")
		if res.StatusCode != 403 {
			t.Fatalf("status=%d, want 403; body=%.200s", res.StatusCode, body)
		}
		got := oneJSON(t, body)
		if got["error"] != "banned" || got["reason"] != "проверка" {
			t.Fatalf("тело отказа: %v", got)
		}
	})

	t.Run("отозванная сессия: чистый 401 без списка сессий", func(t *testing.T) {
		app := newSeedTestApp(t)
		do := serveMux(t, app)
		u := mustUser(t, app, "chain-stop-revoked@seed.test")
		grant, ck := mustSession(t, app, u.Id, "dev")
		if sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", grant); err == nil {
			sess.Set("revoked", true)
			if err := app.Save(sess); err != nil {
				t.Fatalf("отзыв: %v", err)
			}
		} else {
			t.Fatalf("сессия: %v", err)
		}
		res, body := do(http.MethodGet, "/api/seed/sessions",
			map[string]string{"Authorization": mustToken(t, u), "Cookie": seedCookieName + "=" + ck}, "")
		if res.StatusCode != 401 {
			t.Fatalf("status=%d, want 401; body=%.200s", res.StatusCode, body)
		}
		got := oneJSON(t, body)
		if got["error"] != "session_revoked" {
			t.Fatalf("error=%v, want session_revoked", got["error"])
		}
	})
}

// TestAutotuneViaConfigEndpoint — предохранитель «автонастройка»
// обязан срабатывать и при записи через `/api/seed/gateway-config`
// (внутреннее сохранение минует REST-хуки коллекции — регрессия
// против хука, видевшего только штатный REST).
func TestAutotuneViaConfigEndpoint(t *testing.T) {
	app := newAutomationApp(t)
	do := serveMux(t, app)
	u := mustUser(t, app, "autotune-admin@seed.test")
	u.Set("role", seedRoleAdmin)
	if err := app.Save(u); err != nil {
		t.Fatalf("роль: %v", err)
	}
	_, ck := mustSession(t, app, u.Id, "dev")
	hdr := map[string]string{"Authorization": mustToken(t, u), "Cookie": seedCookieName + "=" + ck}

	res, body := do(http.MethodPost, "/api/seed/gateway-config", hdr, `{"key":"reg_per_day","value":60}`)
	if res.StatusCode != 200 {
		t.Fatalf("запись 60: status=%d body=%.200s", res.StatusCode, body)
	}

	// Переопределение снято хуком: действует стандарт, источник — не база.
	res, body = do(http.MethodGet, "/api/seed/gateway-config", hdr, "")
	if res.StatusCode != 200 {
		t.Fatalf("чтение: status=%d", res.StatusCode)
	}
	var cfg struct {
		Params []struct {
			Key, Value, Source string
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("разбор конфига: %v", err)
	}
	var p *struct{ Key, Value, Source string }
	for i := range cfg.Params {
		if cfg.Params[i].Key == "reg_per_day" {
			p = &cfg.Params[i]
		}
	}
	if p == nil || p.Value != "2" || p.Source == "база" {
		t.Fatalf("reg_per_day после хука: %+v (ждём стандарт не из базы)", p)
	}
	if rows := gwAuditHookRows(t, app, hookAutotune); len(rows) != 1 {
		t.Fatalf("строк журнала с хуком %q: %d, ждём 1", hookAutotune, len(rows))
	}

	// Умеренное значение предела не достигает и остаётся в базе.
	res, body = do(http.MethodPost, "/api/seed/gateway-config", hdr, `{"key":"reg_per_day","value":5}`)
	if res.StatusCode != 200 {
		t.Fatalf("запись 5: status=%d body=%.200s", res.StatusCode, body)
	}
	res, body = do(http.MethodGet, "/api/seed/gateway-config", hdr, "")
	if res.StatusCode != 200 {
		t.Fatalf("чтение 2: status=%d", res.StatusCode)
	}
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("разбор конфига 2: %v", err)
	}
	p = nil
	for i := range cfg.Params {
		if cfg.Params[i].Key == "reg_per_day" {
			p = &cfg.Params[i]
		}
	}
	if p == nil || p.Value != "5" || p.Source != "база" {
		t.Fatalf("reg_per_day=5 должен остаться в базе: %+v", p)
	}
	if rows := gwAuditHookRows(t, app, hookAutotune); len(rows) != 1 {
		t.Fatalf("хук сработал повторно: строк %d, ждём 1", len(rows))
	}
}

// TestAutotuneViaRecordsRest — тот же предохранитель на штатном REST
// коллекции `seed_gateway` (прямая запись суперюзера).
func TestAutotuneViaRecordsRest(t *testing.T) {
	app := newAutomationApp(t)
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)
	hdr := map[string]string{"Authorization": suTok}

	res, body := do(http.MethodPost, "/api/collections/seed_gateway/records", hdr,
		`{"key":"reg_per_day","value":"77"}`)
	if res.StatusCode != 200 {
		t.Fatalf("создание строки: status=%d body=%.200s", res.StatusCode, body)
	}
	if row, err := app.FindFirstRecordByData("seed_gateway", "key", "reg_per_day"); err == nil && row != nil {
		t.Fatalf("строка-переопределение не снята хуком: %v", asStr(row.Get("value")))
	}
	if rows := gwAuditHookRows(t, app, hookAutotune); len(rows) != 1 {
		t.Fatalf("строк журнала с хуком %q: %d, ждём 1", hookAutotune, len(rows))
	}
}

// TestBanCascadeRevokesAndDedupes — бан через REST немедленно отзывает
// все живые сессии забаненного одной строкой журнала; повторная правка
// забаненного без отзывов дубль строки не создаёт.
func TestBanCascadeRevokesAndDedupes(t *testing.T) {
	app := newAutomationApp(t)
	do := serveMux(t, app)

	admin := mustUser(t, app, "cascade-admin@seed.test")
	admin.Set("role", seedRoleAdmin)
	if err := app.Save(admin); err != nil {
		t.Fatalf("роль: %v", err)
	}
	_, adminCk := mustSession(t, app, admin.Id, "admin-dev")
	hdr := map[string]string{"Authorization": mustToken(t, admin), "Cookie": seedCookieName + "=" + adminCk}

	victim := mustUser(t, app, "cascade-victim@seed.test")
	_, _ = mustSession(t, app, victim.Id, "первое-устройство")
	_, _ = mustSession(t, app, victim.Id, "второе-устройство")

	res, body := do(http.MethodPatch, "/api/collections/users/records/"+victim.Id, hdr,
		`{"banned":true,"ban_reason":"флуд"}`)
	if res.StatusCode != 200 {
		t.Fatalf("бан: status=%d body=%.200s", res.StatusCode, body)
	}

	sessions, err := app.FindRecordsByFilter("seed_sessions", `user={:u}`, "", 0, 0,
		map[string]any{"u": victim.Id})
	if err != nil || len(sessions) != 2 {
		t.Fatalf("сессии жертвы: n=%d err=%v", len(sessions), err)
	}
	for _, s := range sessions {
		if !asBool(s.Get("revoked")) {
			t.Fatalf("сессия %q не отозвана каскадом", asStr(s.Get("device_name")))
		}
	}

	kills, err := app.FindRecordsByFilter("seed_audit", `action={:a}`, "", 0, 0,
		map[string]any{"a": "session.kill"})
	if err != nil || len(kills) != 1 {
		t.Fatalf("строк session.kill: %d (err=%v), ждём 1", len(kills), err)
	}
	d := fwDetail(kills[0])
	if d["reason"] != "ban_cascade" || fmt.Sprint(d["revoked"]) != "2" || d["user_id"] != victim.Id {
		t.Fatalf("детали каскада: %v", d)
	}
	if asStr(kills[0].Get("actor_kind")) != "admin" || asStr(kills[0].Get("actor_id")) != admin.Id {
		t.Fatalf("исполнитель каскада: %s/%s", asStr(kills[0].Get("actor_kind")), asStr(kills[0].Get("actor_id")))
	}

	// Повторная правка забаненного: отзывов нет — строка не дублируется.
	res, body = do(http.MethodPatch, "/api/collections/users/records/"+victim.Id, hdr,
		`{"ban_reason":"флуд и спам"}`)
	if res.StatusCode != 200 {
		t.Fatalf("повторная правка: status=%d body=%.200s", res.StatusCode, body)
	}
	kills, err = app.FindRecordsByFilter("seed_audit", `action={:a}`, "", 0, 0,
		map[string]any{"a": "session.kill"})
	if err != nil || len(kills) != 1 {
		t.Fatalf("дубль строки каскада: %d (err=%v)", len(kills), err)
	}
}

// TestAutotuneBoundaryAndConsole — граница предела (50 ещё проходит,
// 51 уже снимается) и консольный путь записи `gateway set`: он минует
// и REST-хуки, и эндпоинт, поэтому предохранитель встроен прямо в него.
func TestAutotuneBoundaryAndConsole(t *testing.T) {
	app := newRegistryTestApp(t)

	// Граница: 50 == предел — остаётся в базе, хук не срабатывает.
	if _, err := gatewaySetParam(app, "reg_per_day", "50"); err != nil {
		t.Fatalf("запись 50: %v", err)
	}
	if v, src := gwResolve(app, gwPRegPerDay); v != "50" || src != "база" {
		t.Fatalf("50 должен остаться в базе: %q %q", v, src)
	}
	if rows := gwAuditHookRows(t, app, hookAutotune); len(rows) != 0 {
		t.Fatalf("хук сработал на граничном значении: строк %d", len(rows))
	}

	// 51 > предела — строка снимается сразу после записи.
	if _, err := gatewaySetParam(app, "reg_per_day", "51"); err != nil {
		t.Fatalf("запись 51: %v", err)
	}
	if v, src := gwResolve(app, gwPRegPerDay); v != "2" || src == "база" {
		t.Fatalf("51 должен быть снят хуком: %q %q", v, src)
	}
	if rows := gwAuditHookRows(t, app, hookAutotune); len(rows) != 1 {
		t.Fatalf("строк журнала с хуком %q: %d, ждём 1", hookAutotune, len(rows))
	}
}

// TestBanCascadeBySuperuser — каскад бана от суперюзера: исполнитель в
// строке журнала — суперюзер (а не админ по роли).
func TestBanCascadeBySuperuser(t *testing.T) {
	app := newAutomationApp(t)
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)

	victim := mustUser(t, app, "cascade-su-victim@seed.test")
	_, _ = mustSession(t, app, victim.Id, "устройство")

	res, body := do(http.MethodPatch, "/api/collections/users/records/"+victim.Id,
		map[string]string{"Authorization": suTok}, `{"banned":true,"ban_reason":"решение суперюзера"}`)
	if res.StatusCode != 200 {
		t.Fatalf("бан суперюзером: status=%d body=%.200s", res.StatusCode, body)
	}
	kills, err := app.FindRecordsByFilter("seed_audit", `action={:a}`, "", 0, 0,
		map[string]any{"a": "session.kill"})
	if err != nil || len(kills) != 1 {
		t.Fatalf("строк session.kill: %d (err=%v), ждём 1", len(kills), err)
	}
	if kind := asStr(kills[0].Get("actor_kind")); kind != "superuser" {
		t.Fatalf("исполнитель каскада: %q, ждём superuser", kind)
	}
	if fwDetail(kills[0])["reason"] != "ban_cascade" {
		t.Fatalf("детали каскада: %v", fwDetail(kills[0]))
	}
}

// TestSuperuserSameSecondDoubleLogin — повторный вход суперюзера в ту
// же секунду выпускает тот же токен; сессия переиспользуется
// идемпотентно, без падения на уникальном индексе `token_hash`.
func TestSuperuserSameSecondDoubleLogin(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)
	su, _ := mustSuperuser(t, app)

	// Перехватываем стандартный лог: прежняя реализация роняла в него
	// «token_hash: Value must be unique» при совпавших токенах.
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	login := func() string {
		res, body := do(http.MethodPost, "/api/collections/_superusers/auth-with-password", nil,
			`{"identity":"`+su.Email()+`","password":"root-password-123"}`)
		if res.StatusCode != 200 {
			t.Fatalf("вход: status=%d body=%.200s", res.StatusCode, body)
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil || out.Token == "" {
			t.Fatalf("токен из ответа: %v", err)
		}
		return out.Token
	}
	tok1, tok2 := login(), login()

	if strings.Contains(buf.String(), "Value must be unique") {
		t.Fatalf("уникальный индекс token_hash не пережил повторный вход: %s", buf.String())
	}
	if sess := superuserSessionByToken(app, tok2); sess == nil {
		t.Fatalf("сессия второму токену не найдена")
	}
	if tok1 == tok2 {
		// Токены совпали (вход в одну секунду) — строка сессии одна.
		rows, err := app.FindRecordsByFilter("seed_sessions", `superuser_id={:u}`, "", 0, 0,
			map[string]any{"u": su.Id})
		if err != nil || len(rows) != 1 {
			t.Fatalf("сессий суперюзера: %d (err=%v), ждём 1", len(rows), err)
		}
	} else {
		t.Logf("токены различаются (входы в разные секунды) — проверка идемпотентности не сработала, но ошибок нет")
	}
}
