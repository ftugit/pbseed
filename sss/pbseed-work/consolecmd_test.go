package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

// consolecmd_test.go — тесты консольных команд по шаблону
// TestSetUserRoleConsole: чистая база реестра, действия вызываются
// напрямую (как их вызывает cobra-обёртка).

// consoleSession создаёт живую сессию пользователя для тестов консоли.
func consoleSession(t *testing.T, app core.App, userId, grant string) *core.Record {
	t.Helper()
	s := core.NewRecord(mustCollection(t, app, "seed_sessions"))
	s.Set("user", userId)
	s.Set("grant_id", grant)
	s.Set("device_name", "test-device")
	if err := app.Save(s); err != nil {
		t.Fatalf("create session %s: %v", grant, err)
	}
	return s
}

// TestConsoleBanUnban проверяет консольный бан: бессрочный, срочный,
// отклонение прошедшего срока и снятие бана. Попутно проверяется
// запись действий в журнал.
func TestConsoleBanUnban(t *testing.T) {
	app := newRegistryTestApp(t)
	key := strings.Repeat("c1", 32)
	u := mustUser(t, app, key+"@seed.local")

	if err := userSetBan(app, key, "флуд", ""); err != nil {
		t.Fatalf("ban permanent: %v", err)
	}
	got, _ := app.FindRecordById("users", u.Id)
	if !userBanned(got) {
		t.Fatalf("user must be banned")
	}
	if asStr(got.Get("ban_reason")) != "флуд" || asStr(got.Get("banned_until")) != "" {
		t.Errorf("ban fields wrong: %q / %q", asStr(got.Get("ban_reason")), asStr(got.Get("banned_until")))
	}

	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	if err := userSetBan(app, key, "", future); err != nil {
		t.Fatalf("ban until future: %v", err)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := userSetBan(app, key, "", past); err == nil {
		t.Errorf("past deadline must be rejected")
	}

	if err := userClearBan(app, key); err != nil {
		t.Fatalf("unban: %v", err)
	}
	got, _ = app.FindRecordById("users", u.Id)
	if userBanned(got) {
		t.Fatalf("ban must be cleared")
	}

	rows, err := consoleAuditTail(app, "user.ban", "", 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("audit user.ban rows: %d, %v", len(rows), err)
	}
	if _, err := consoleAuditTail(app, "user.ban", u.Id, 10); err != nil {
		t.Fatalf("audit by actor: %v", err)
	}
}

// TestConsoleUserDelete проверяет мягкое и физическое удаление.
func TestConsoleUserDelete(t *testing.T) {
	app := newRegistryTestApp(t)

	softKey := strings.Repeat("d1", 32)
	u := mustUser(t, app, softKey+"@seed.local")
	if err := userSoftDelete(app, softKey); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	got, _ := app.FindRecordById("users", u.Id)
	if asStr(got.Get("deleted_at")) == "" {
		t.Fatalf("deleted_at must be set")
	}

	hardKey := strings.Repeat("d2", 32)
	hu := mustUser(t, app, hardKey+"@seed.local")
	consoleSession(t, app, hu.Id, "grant-hard")
	if err := userHardDelete(app, hardKey); err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if r, err := app.FindFirstRecordByData("users", "email", hardKey+"@seed.local"); err == nil && r != nil {
		t.Fatalf("hard-deleted record still present")
	}
	rows, err := app.FindRecordsByFilter("seed_sessions", "user={:u}", "", 10, 0,
		map[string]any{"u": hu.Id})
	if err != nil || len(rows) != 0 {
		t.Fatalf("sessions of hard-deleted user: %d, %v", len(rows), err)
	}
}

// TestConsoleKillSessions проверяет отзыв сессий: все сразу и одну по
// идентификатору, включая отказ на чужой/неизвестный идентификатор.
func TestConsoleKillSessions(t *testing.T) {
	app := newRegistryTestApp(t)
	key := strings.Repeat("e1", 32)
	u := mustUser(t, app, key+"@seed.local")
	consoleSession(t, app, u.Id, "grant-aaa")
	consoleSession(t, app, u.Id, "grant-bbb")

	n, err := userKillSessions(app, key, "", true)
	if err != nil || n != 2 {
		t.Fatalf("kill all: %d, %v", n, err)
	}
	rows, err := app.FindRecordsByFilter("seed_sessions", "user={:u} && revoked=true", "", 10, 0,
		map[string]any{"u": u.Id})
	if err != nil || len(rows) != 2 {
		t.Fatalf("revoked rows: %d, %v", len(rows), err)
	}

	consoleSession(t, app, u.Id, "grant-ccc")
	n, err = userKillSessions(app, key, "grant-ccc", false)
	if err != nil || n != 1 {
		t.Fatalf("kill one: %d, %v", n, err)
	}
	if _, err := userKillSessions(app, key, "grant-zzz", false); err == nil {
		t.Errorf("unknown grant must fail")
	}
}

// TestConsoleErase проверяет GDPR-стирание через консольный путь.
func TestConsoleErase(t *testing.T) {
	app := newRegistryTestApp(t)
	key := strings.Repeat("f1", 32)
	u := mustUser(t, app, key+"@seed.local")
	consoleSession(t, app, u.Id, "grant-erase")

	if err := EraseUser(app, u.Id); err != nil {
		t.Fatalf("erase: %v", err)
	}
	got, _ := app.FindRecordById("users", u.Id)
	if !strings.HasPrefix(asStr(got.Get("email")), "erased-") {
		t.Fatalf("email not anonymized: %q", asStr(got.Get("email")))
	}
	rows, err := app.FindRecordsByFilter("seed_sessions", "user={:u}", "", 10, 0,
		map[string]any{"u": u.Id})
	if err != nil || len(rows) != 0 {
		t.Fatalf("sessions after erase: %d, %v", len(rows), err)
	}
}

// TestConsolePolicy проверяет политики: глобальная строка, персональная,
// откат после удаления и запрет замка на персональной строке.
func TestConsolePolicy(t *testing.T) {
	app := newRegistryTestApp(t)
	key := strings.Repeat("a2", 32)
	u := mustUser(t, app, key+"@seed.local")

	if value, src := policyEffective(app, seedPolicyKick, u.Id); value || src != "по умолчанию" {
		t.Fatalf("default policy: %v %q", value, src)
	}
	if err := policySetRow(app, seedPolicyKick, "", true, false); err != nil {
		t.Fatalf("global set: %v", err)
	}
	if value, src := policyEffective(app, seedPolicyKick, u.Id); !value || src != "глобальная" {
		t.Fatalf("global policy: %v %q", value, src)
	}
	if err := policySetRow(app, seedPolicyKick, u.Id, false, false); err != nil {
		t.Fatalf("personal set: %v", err)
	}
	if value, src := policyEffective(app, seedPolicyKick, u.Id); value || src != "персональная" {
		t.Fatalf("personal policy: %v %q", value, src)
	}
	if err := policySetRow(app, seedPolicyKick, u.Id, false, true); err == nil {
		t.Errorf("lock on personal row must be rejected")
	}

	existed, err := policyDeleteRow(app, seedPolicyKick, u.Id)
	if err != nil || !existed {
		t.Fatalf("personal delete: %v %v", existed, err)
	}
	if value, src := policyEffective(app, seedPolicyKick, u.Id); !value || src != "глобальная" {
		t.Fatalf("after rollback: %v %q", value, src)
	}

	rows, err := settingsListRows(app, "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("settings rows: %d, %v", len(rows), err)
	}
	rows, err = settingsListRows(app, u.Id)
	if err != nil || len(rows) != 0 {
		t.Fatalf("user rows after delete: %d, %v", len(rows), err)
	}
}

// TestConsoleGateway проверяет параметры гейтвея: запись отличного от
// стандарта значения, отказ на равное стандарту и сброс к константе.
func TestConsoleGateway(t *testing.T) {
	app := newRegistryTestApp(t)

	written, err := gatewaySetParam(app, "reg_per_day", "5")
	if err != nil || written != "5" {
		t.Fatalf("gateway set: %q, %v", written, err)
	}
	if v, src := gwResolve(app, gwPRegPerDay); v != "5" || src != "база" {
		t.Fatalf("resolve after set: %q %q", v, src)
	}

	if _, err := gatewaySetParam(app, "reg_per_day", "2"); !errors.Is(err, errSettingsDefault) {
		t.Errorf("default-equal value must be rejected, got %v", err)
	}
	if _, err := gatewaySetParam(app, "no_such_param", "1"); !errors.Is(err, errSettingsKey) {
		t.Errorf("unknown key must be rejected, got %v", err)
	}

	deleted, err := gatewayResetParam(app, "reg_per_day")
	if err != nil || !deleted {
		t.Fatalf("gateway reset: %v, %v", deleted, err)
	}
	if v, src := gwResolve(app, gwPRegPerDay); v != "2" || src != "константа" {
		t.Fatalf("resolve after reset: %q %q", v, src)
	}
	deleted, err = gatewayResetParam(app, "reg_per_day")
	if err != nil || deleted {
		t.Fatalf("second reset must be a no-op: %v, %v", deleted, err)
	}
}

// TestConsoleDBOps проверяет сжатие базы и согласованную копию.
func TestConsoleDBOps(t *testing.T) {
	app := newRegistryTestApp(t)
	if err := dbVacuumTo(app); err != nil {
		t.Fatalf("vacuum: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := dbBackupTo(app, dst); err != nil {
		t.Fatalf("backup: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil || info.Size() == 0 {
		t.Fatalf("backup file missing or empty: %v", err)
	}

	rows, err := consoleAuditTail(app, "db.backup", "", 5)
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit db.backup rows: %d, %v", len(rows), err)
	}
}

// TestConsoleAuditTail проверяет чтение журнала: фильтр по действию и
// пометку «выполнено консолью» в деталях.
func TestConsoleAuditTail(t *testing.T) {
	app := newRegistryTestApp(t)
	consoleAudit(app, "console.test", map[string]any{"what": "x"})

	rows, err := consoleAuditTail(app, "console.test", "", 5)
	if err != nil || len(rows) != 1 {
		t.Fatalf("tail rows: %d, %v", len(rows), err)
	}
	detail := fwDetail(rows[0])
	if detail["by"] != "console" || detail["what"] != "x" {
		t.Fatalf("detail must carry by=console: %v", detail)
	}
	if asStr(rows[0].Get("actor_kind")) != "console" {
		t.Fatalf("console row actor_kind=%q, want console", asStr(rows[0].Get("actor_kind")))
	}
	if rows, err := consoleAuditTail(app, "no.such.action", "", 5); err != nil || len(rows) != 0 {
		t.Fatalf("wrong filter must give empty tail: %d, %v", len(rows), err)
	}
}

// TestConsoleListings убеждается, что функции вывода не падают на
// реальных данных (пользователь с сессией).
func TestConsoleListings(t *testing.T) {
	app := newRegistryTestApp(t)
	key := strings.Repeat("b3", 32)
	u := mustUser(t, app, key+"@seed.local")
	consoleSession(t, app, u.Id, "grant-list")

	if err := userList(app, "", false, 50); err != nil {
		t.Fatalf("user list: %v", err)
	}
	if err := userList(app, "admin", false, 50); err != nil {
		t.Fatalf("user list filtered: %v", err)
	}
	if err := userShow(app, key); err != nil {
		t.Fatalf("user show: %v", err)
	}
	if err := userSessions(app, key); err != nil {
		t.Fatalf("user sessions: %v", err)
	}
	if err := userSessions(app, strings.Repeat("00", 32)); err == nil {
		t.Errorf("sessions of unknown key must fail")
	}
}
