package main

// firewall_test.go — фаервол панели на журнале действий: блокировка
// адреса за порог неудачных входов, суточное отключение панели,
// снятие блокировок (консоль и суперюзер с рабочей сессией), аудит
// входов суперюзера и правок коллекций из панели.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

// fwLogin пытается войти суперюзером по паролу через штатный эндпоинт.
//
// Параметры:
//   - do: func — исполняющий запросы каркас (serveMux);
//   - email: string — почта суперюзера;
//   - password: string — пароль.
//
// Возвращает: int — код ответа.
func fwLogin(do func(string, string, map[string]string, string) (*http.Response, string), email, password string) int {
	res, _ := do(http.MethodPost, "/api/collections/_superusers/auth-with-password", nil,
		`{"identity":"`+email+`","password":"`+password+`"}`)
	return res.StatusCode
}

// fwCountAudit считает строки журнала по действию.
//
// Параметры:
//   - t: *testing.T — тест;
//   - app: core.App — приложение;
//   - action: string — ключ действия.
//
// Возвращает: int — число строк.
func fwCountAudit(t *testing.T, app core.App, action string) int {
	t.Helper()
	rows, err := app.FindRecordsByFilter("seed_audit", "action={:a}", "", 500, 0, map[string]any{"a": action})
	if err != nil {
		t.Fatalf("audit count %s: %v", action, err)
	}
	return len(rows)
}

// TestFirewallIPBlockAndUnlock — порог неудачных входов блокирует
// адрес; суперюзер с рабочей сессией снимает блокировку через API.
func TestFirewallIPBlockAndUnlock(t *testing.T) {
	app := newSeedTestApp(t)
	t.Setenv("SEED_FIREWALL", "1")
	t.Setenv("SEED_FIREWALL_FAILS", "3")
	t.Setenv("SEED_FIREWALL_BLOCKS", "100") // суточное отключение не мешать
	do := serveMux(t, app)

	su, suTok := mustSuperuser(t, app)
	email := su.Email()

	for i := 0; i < 3; i++ {
		if st := fwLogin(do, email, "wrong-password"); st != 400 {
			t.Fatalf("bad attempt #%d: status=%d, want 400", i, st)
		}
	}
	// Верный пароль уже не помогает: адрес заблокирован.
	if st := fwLogin(do, email, "root-password-123"); st != 403 {
		t.Fatalf("locked login: status=%d, want 403", st)
	}
	if n := fwCountAudit(t, app, fwActLoginFail); n != 3 {
		t.Errorf("login_failed rows=%d, want 3", n)
	}
	if n := fwCountAudit(t, app, fwActLockIP); n != 1 {
		t.Errorf("lock_ip rows=%d, want 1", n)
	}

	// Разблокировка суперюзером с рабочей сессией.
	res, body := do(http.MethodPost, "/api/seed/firewall/unlock",
		map[string]string{"Authorization": suTok}, `{"ip":"127.0.0.1"}`)
	if res.StatusCode != 200 {
		t.Fatalf("api unlock status=%d body=%s", res.StatusCode, body)
	}
	if st := fwLogin(do, email, "root-password-123"); st != 200 {
		t.Fatalf("login after unlock: status=%d, want 200", st)
	}
	row, err := app.FindFirstRecordByData("seed_audit", "action", fwActUnlock)
	if err != nil || row == nil {
		t.Fatalf("no firewall.unlock row: %v", err)
	}
	if d := fwDetail(row); d["what"] != "ip" || d["by"] != "api" {
		t.Errorf("unlock detail=%v, want what=ip by=api", d)
	}
	if n := fwCountAudit(t, app, fwActLogin); n != 1 {
		t.Errorf("superuser.login rows=%d, want 1", n)
	}
}

// TestFirewallPanelOffAndConsole — порог блокировок за сутки отключает
// панель до конца суток; через API отключение не снимается
// (console_only), снимается только консолью сервера.
func TestFirewallPanelOffAndConsole(t *testing.T) {
	app := newSeedTestApp(t)
	t.Setenv("SEED_FIREWALL", "1")
	t.Setenv("SEED_FIREWALL_FAILS", "1")
	t.Setenv("SEED_FIREWALL_BLOCKS", "3")
	do := serveMux(t, app)

	su, suTok := mustSuperuser(t, app)
	email := su.Email()

	// Две блокировки адресов уже были сегодня (разные нарушители).
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	auditWriteRow(app, nil, "", "", fwActLockIP, map[string]any{
		"ip_hash": "h-aaa", "ip_masked": "10.1.1.*", "until": future, "fails": 5})
	auditWriteRow(app, nil, "", "", fwActLockIP, map[string]any{
		"ip_hash": "h-bbb", "ip_masked": "10.2.2.*", "until": future, "fails": 5})

	// Третья блокировка (наш адрес) добирает порог — панель гаснет.
	if st := fwLogin(do, email, "wrong-password"); st != 400 {
		t.Fatalf("bad attempt: status=%d, want 400", st)
	}
	if n := fwCountAudit(t, app, fwActPanelOff); n != 1 {
		t.Fatalf("panel_off rows=%d, want 1", n)
	}
	if st := fwLogin(do, email, "root-password-123"); st != 403 {
		t.Fatalf("login with panel off: status=%d, want 403", st)
	}
	// Интерфейс панели тоже закрыт.
	res, _ := do(http.MethodGet, "/_/", nil, "")
	if res.StatusCode != 403 {
		t.Errorf("dashboard during panel_off: status=%d, want 403", res.StatusCode)
	}

	// API не даёт снять отключение панели.
	res, body := do(http.MethodPost, "/api/seed/firewall/unlock",
		map[string]string{"Authorization": suTok}, `{"what":"panel"}`)
	if res.StatusCode != 403 || !strings.Contains(body, "console_only") {
		t.Fatalf("api panel unlock: status=%d body=%s, want 403 console_only", res.StatusCode, body)
	}

	// Консоль снимает отключение панели и блокировку адреса.
	fc := newFirewallCommand(app)
	sub, _, err := fc.Find([]string{"unlock-panel"})
	if err != nil {
		t.Fatalf("unlock-panel command: %v", err)
	}
	if err := sub.RunE(sub, nil); err != nil {
		t.Fatalf("unlock-panel run: %v", err)
	}
	subIP, _, err := fc.Find([]string{"unlock-ip"})
	if err != nil {
		t.Fatalf("unlock-ip command: %v", err)
	}
	if err := subIP.RunE(subIP, nil); err != nil { // без аргумента — все адреса
		t.Fatalf("unlock-ip run: %v", err)
	}
	if st := fwLogin(do, email, "root-password-123"); st != 200 {
		t.Fatalf("login after console unlock: status=%d, want 200", st)
	}
}

// TestFirewallAuditWorksWhenDisabled — журнал входов суперюзера ведётся
// даже при выключенном фаерволе; блокировок при этом нет.
func TestFirewallAuditWorksWhenDisabled(t *testing.T) {
	app := newSeedTestApp(t) // каркас по умолчанию гасит фаервол
	do := serveMux(t, app)

	su, _ := mustSuperuser(t, app)
	email := su.Email()

	if st := fwLogin(do, email, "wrong-password"); st != 400 {
		t.Fatalf("bad attempt: status=%d, want 400", st)
	}
	if st := fwLogin(do, email, "root-password-123"); st != 200 {
		t.Fatalf("good login: status=%d, want 200", st)
	}
	fail, err := app.FindFirstRecordByData("seed_audit", "action", fwActLoginFail)
	if err != nil || fail == nil {
		t.Fatalf("no superuser.login_failed row: %v", err)
	}
	d := fwDetail(fail)
	if d["method"] != "password" || d["ip_hash"] == "" || d["ip_masked"] == "" {
		t.Errorf("failed login detail=%v", d)
	}
	ok, err := app.FindFirstRecordByData("seed_audit", "action", fwActLogin)
	if err != nil || ok == nil {
		t.Fatalf("no superuser.login row: %v", err)
	}
	if n := fwCountAudit(t, app, fwActLockIP); n != 0 {
		t.Errorf("lock_ip rows=%d, want 0 (firewall disabled)", n)
	}
}

// TestFirewallStatusEndpoint — статус фаервола отдаётся только
// суперюзеру.
func TestFirewallStatusEndpoint(t *testing.T) {
	app := newSeedTestApp(t)
	t.Setenv("SEED_FIREWALL", "1")
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)

	res, body := do(http.MethodGet, "/api/seed/firewall/status",
		map[string]string{"Authorization": suTok}, "")
	if res.StatusCode != 200 {
		t.Fatalf("status: %d %s", res.StatusCode, body)
	}
	var st map[string]any
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("status body: %v", err)
	}
	if st["enabled"] != true || st["limits"] == nil {
		t.Errorf("status payload=%s", body)
	}

	res, _ = do(http.MethodGet, "/api/seed/firewall/status", nil, "")
	if res.StatusCode != 403 {
		t.Errorf("status without token: %d, want 403", res.StatusCode)
	}
}

// TestCollectionAuditLogged — правка правил коллекции через штатный
// REST (так ходит панель) пишется в журнал со списком изменённых
// правил.
func TestCollectionAuditLogged(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)

	users := mustCollection(t, app, "users")
	res, body := do(http.MethodPatch, "/api/collections/"+users.Id,
		map[string]string{"Authorization": suTok},
		`{"listRule":"@request.auth.id != ''"}`)
	if res.StatusCode != 200 {
		t.Fatalf("collection patch status=%d body=%s", res.StatusCode, body)
	}
	row, err := app.FindFirstRecordByData("seed_audit", "action", "collections.update")
	if err != nil || row == nil {
		t.Fatalf("no collections.update row: %v", err)
	}
	d := fwDetail(row)
	if d["collection"] != "users" {
		t.Errorf("detail.collection=%v, want users", d["collection"])
	}
	rules, _ := d["rules"].([]any)
	found := false
	for _, r := range rules {
		if r == "listRule" {
			found = true
		}
	}
	if !found {
		t.Errorf("detail.rules=%v, want listRule among them", d["rules"])
	}
	if asStr(row.Get("actor_kind")) != "superuser" {
		t.Errorf("actor_kind=%q, want superuser", asStr(row.Get("actor_kind")))
	}
}
