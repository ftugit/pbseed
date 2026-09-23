package main

// gatewaycfg_test.go — переопределение констант защиты гейтвея через
// базу: права доступа, валидация «значение обязано отличаться от
// стандарта», приоритет базы над окружением и откат удалением строки.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// gwCfg вызывает эндпоинты настройки гейтвея с токеном.
//
// Параметры:
//   - t: *testing.T — тест;
//   - do: func — каркас запросов;
//   - method, url: string — запрос;
//   - tok: string — токен (может быть пуст);
//   - body: string — тело запроса.
//
// Возвращает: int — код ответа;
// string — тело ответа.
func gwCfg(t *testing.T, do func(string, string, map[string]string, string) (*http.Response, string),
	method, url, tok, body string) (int, string) {
	t.Helper()
	h := map[string]string{}
	if tok != "" {
		h["Authorization"] = tok
	}
	res, out := do(method, url, h, body)
	return res.StatusCode, out
}

// TestGatewayConfigRights — настройку видят и меняют суперюзер и роль
// «admin»; гость и обычный пользователь — нет. Ролевой админ идёт с
// кукой сессии (модель сессий).
func TestGatewayConfigRights(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)

	if st, _ := gwCfg(t, do, http.MethodGet, "/api/seed/gateway-config", "", ""); st != 401 {
		t.Fatalf("guest status=%d, want 401", st)
	}

	// Обычный пользователь через гейтвей (токен + кука сессии —
	// модель сессий требует куку для запросов от имени юзера).
	priv, pk := gwNewKey(t)
	st, body, ck := gwSession(t, do, priv, pk, "register", "dev")
	if st != 200 {
		t.Fatalf("register status=%d body=%s", st, body)
	}
	var lr struct {
		Access string `json:"access"`
	}
	_ = json.Unmarshal([]byte(body), &lr)
	userHdr := map[string]string{
		"Authorization": lr.Access,
		"Cookie":        seedCookieName + "=" + ck,
	}
	res, _ := do(http.MethodGet, "/api/seed/gateway-config", userHdr, "")
	if res.StatusCode != 403 {
		t.Fatalf("user status=%d, want 403", res.StatusCode)
	}

	// Админ по роли получает доступ: чтение и запись.
	user, err := app.FindFirstRecordByData("users", "email", pk+"@seed.local")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	user.Set("role", seedRoleAdmin)
	if err := app.Save(user); err != nil {
		t.Fatalf("save role: %v", err)
	}
	res, got := do(http.MethodGet, "/api/seed/gateway-config", userHdr, "")
	if res.StatusCode != 200 {
		t.Fatalf("role-admin GET status=%d body=%s", res.StatusCode, got)
	}
	for _, k := range []string{`"register"`, `"login"`, `"renew"`, `"reg_per_day"`,
		`"logins_per_day"`, `"max_fails"`, `"fail_lock"`} {
		if !strings.Contains(got, k) {
			t.Errorf("GET misses %s: %s", k, got)
		}
	}
	if !strings.Contains(got, `"константа"`) {
		t.Errorf("expected default source: %s", got)
	}
	res, got = do(http.MethodPost, "/api/seed/gateway-config", userHdr,
		`{"key":"reg_per_day","value":1}`)
	if res.StatusCode != 200 {
		t.Fatalf("role-admin set status=%d body=%s", res.StatusCode, got)
	}
	res, got = do(http.MethodDelete, "/api/seed/gateway-config?key=reg_per_day", userHdr, "")
	if res.StatusCode != 200 {
		t.Fatalf("role-admin delete status=%d body=%s", res.StatusCode, got)
	}
	// Смена настройки ролевым админом пишется в журнал с ним как
	// исполнителем.
	if row := saFindLatest(t, app, "gateway.config"); row == nil ||
		row.GetString("actor_id") != user.Id {
		t.Fatalf("gateway.config row not attributed to role admin")
	}

	// Суперюзер тоже видит полную картину (включая неизменяемые
	// параметры).
	st, got = gwCfg(t, do, http.MethodGet, "/api/seed/gateway-config", suTok, "")
	if st != 200 {
		t.Fatalf("superuser status=%d body=%s", st, got)
	}
	if !strings.Contains(got, `"readonly"`) {
		t.Errorf("GET misses readonly section: %s", got)
	}
}

// TestGatewayConfigSetValidation — ключи и значения проверяются, а
// переопределение, равное стандарту, отклоняется (в любой записи).
func TestGatewayConfigSetValidation(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)

	set := func(body string) (int, string) {
		return gwCfg(t, do, http.MethodPost, "/api/seed/gateway-config", suTok, body)
	}
	if st, body := set(`{"key":"nope","value":false}`); st != 400 || !strings.Contains(body, "bad_key") {
		t.Fatalf("bad key status=%d body=%s", st, body)
	}
	if st, body := set(`{"key":"reg_per_day","value":"текст"}`); st != 400 || !strings.Contains(body, "bad_value") {
		t.Fatalf("bad value status=%d body=%s", st, body)
	}
	if st, body := set(`{"key":"max_fails","value":-1}`); st != 400 || !strings.Contains(body, "bad_value") {
		t.Fatalf("negative status=%d body=%s", st, body)
	}
	// Равные стандарту — в каждой форме записи.
	for _, body := range []string{
		`{"key":"register","value":true}`,
		`{"key":"reg_per_day","value":2}`,
		`{"key":"fail_lock","value":"15m"}`,
		`{"key":"fail_lock","value":"900s"}`, // то же самое, другая запись
	} {
		if st, out := set(body); st != 400 || !strings.Contains(out, "default_value") {
			t.Fatalf("default %s status=%d body=%s", body, st, out)
		}
	}
	// Равное стандарту не должно создавать строку.
	if r := gwDBRow(app, gwPFailLock); r != nil {
		t.Fatalf("default row was written")
	}
}

// TestGatewayConfigOverride — записанное переопределение немедленно
// действует, приоритетнее окружения, а удаление строки откатывает к
// константе; смена настройки пишется в журнал.
func TestGatewayConfigOverride(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)

	set := func(body string) (int, string) {
		return gwCfg(t, do, http.MethodPost, "/api/seed/gateway-config", suTok, body)
	}

	// Окружение задаёт 5, база — 1: действует база.
	t.Setenv("SEED_GATEWAY_REG_PER_DAY", "5")
	if st, body := set(`{"key":"reg_per_day","value":1}`); st != 200 {
		t.Fatalf("set status=%d body=%s", st, body)
	}
	priv1, pk1 := gwNewKey(t)
	if st, body := gwAttempt(t, do, priv1, pk1, "register", "dev"); st != 200 {
		t.Fatalf("register #1 status=%d body=%s", st, body)
	}
	priv2, pk2 := gwNewKey(t)
	st, body := gwAttempt(t, do, priv2, pk2, "register", "dev")
	if st != 403 || !strings.Contains(body, "register_limit") {
		t.Fatalf("register #2 status=%d body=%s, want 403 register_limit", st, body)
	}
	if row := saFindLatest(t, app, "auth.register_denied"); row == nil {
		t.Fatalf("no register_denied row")
	}

	// Выключатель регистрации через базу.
	if st, body := set(`{"key":"register","value":false}`); st != 200 {
		t.Fatalf("set register status=%d body=%s", st, body)
	}
	priv3, pk3 := gwNewKey(t)
	st, body = gwAttempt(t, do, priv3, pk3, "register", "dev")
	if st != 403 || !strings.Contains(body, "register_disabled") {
		t.Fatalf("disabled register status=%d body=%s", st, body)
	}

	// GET отражает источник «база».
	_, got := gwCfg(t, do, http.MethodGet, "/api/seed/gateway-config", suTok, "")
	if !strings.Contains(got, `"база"`) {
		t.Fatalf("expected db source: %s", got)
	}

	// Удаление переопределений — откат: регистрация снова работает
	// (окружение разрешает 5 в сутки, использовано два).
	st, _ = gwCfg(t, do, http.MethodDelete, "/api/seed/gateway-config?key=register", suTok, "")
	if st != 200 {
		t.Fatalf("delete register status=%d", st)
	}
	st, _ = gwCfg(t, do, http.MethodDelete, "/api/seed/gateway-config?key=reg_per_day", suTok, "")
	if st != 200 {
		t.Fatalf("delete reg_per_day status=%d", st)
	}
	if st, body := gwAttempt(t, do, priv3, pk3, "register", "dev"); st != 200 {
		t.Fatalf("rollback register status=%d body=%s, want 200", st, body)
	}

	// Смена настройки фиксируется журналом.
	if row := saFindLatest(t, app, "gateway.config"); row == nil {
		t.Fatalf("no gateway.config row")
	}
}

// TestGatewayConfigReadonly — раздел неизменяемых параметров: текущие
// значения присутствуют, а секреты (ключ HMAC, пароль суперюзера) не
// раскрываются — только факт наличия.
func TestGatewayConfigReadonly(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)

	t.Setenv("SEED_IP_KEY", "super-secret-hmac-key-0123456789")
	t.Setenv("PB_SUPERUSER_PASSWORD", "hunter2-secret-pw")

	st, body := gwCfg(t, do, http.MethodGet, "/api/seed/gateway-config", suTok, "")
	if st != 200 {
		t.Fatalf("status=%d body=%s", st, body)
	}
	// Неизменяемые параметры видны.
	for _, k := range []string{`"domain"`, `"gc_every"`, `"firewall"`, `"audit_keep_days"`} {
		if !strings.Contains(body, k) {
			t.Errorf("readonly misses %s", k)
		}
	}
	// Секреты не утекают.
	for _, secret := range []string{"super-secret-hmac-key-0123456789", "hunter2-secret-pw"} {
		if strings.Contains(body, secret) {
			t.Errorf("secret leaked: %s", secret)
		}
	}
	// Факт наличия ключа отмечен.
	if !strings.Contains(body, "HMAC") {
		t.Errorf("expected HMAC marker: %s", body)
	}
}

// TestSettingsGoAPI — программный доступ к конфигурации (аналог
// useSettings().get/set для хуков): чтение с источником, запись с
// валидацией, откат удалением.
func TestSettingsGoAPI(t *testing.T) {
	app := newSeedTestApp(t)

	// Чтение стандарта.
	v, src, ok := settingsGet(app, "max_fails")
	if !ok || v != "10" || src != "константа" {
		t.Fatalf("get default: %q %q %v", v, src, ok)
	}
	if _, _, ok := settingsGet(app, "nope"); ok {
		t.Fatalf("unknown key must be not ok")
	}

	// Запись отличия.
	if _, err := settingsSet(app, "max_fails", 5); err != nil {
		t.Fatalf("set: %v", err)
	}
	v, src, _ = settingsGet(app, "max_fails")
	if v != "5" || src != "база" {
		t.Fatalf("after set: %q %q", v, src)
	}

	// Равное стандарту — отклоняется.
	if _, err := settingsSet(app, "max_fails", 10); err != errSettingsDefault {
		t.Fatalf("equal-to-default must fail, got %v", err)
	}
	// Мусор — отклоняется.
	if _, err := settingsSet(app, "max_fails", "много"); err != errSettingsValue {
		t.Fatalf("bad value must fail, got %v", err)
	}
	// Неизвестный ключ.
	if _, err := settingsSet(app, "nope", 1); err != errSettingsKey {
		t.Fatalf("unknown key must fail, got %v", err)
	}

	// Откат удалением.
	deleted, err := settingsDelete(app, "max_fails")
	if err != nil || !deleted {
		t.Fatalf("delete: %v %v", deleted, err)
	}
	v, src, _ = settingsGet(app, "max_fails")
	if v != "10" || src != "константа" {
		t.Fatalf("after delete: %q %q", v, src)
	}

	// Окружение — прослойка между базой и константой.
	t.Setenv("SEED_GATEWAY_MAX_FAILS", "7")
	v, src, _ = settingsGet(app, "max_fails")
	if v != "7" || src != "окружение" {
		t.Fatalf("env layer: %q %q", v, src)
	}
	if _, err := settingsSet(app, "max_fails", 3); err != nil {
		t.Fatalf("set over env: %v", err)
	}
	v, src, _ = settingsGet(app, "max_fails")
	if v != "3" || src != "база" {
		t.Fatalf("db beats env: %q %q", v, src)
	}
}

// TestSettingsHookAudit — изменение конфигурации серверным хуком
// фиксируется журналом с именем хука; неудачные попытки не пишутся.
func TestSettingsHookAudit(t *testing.T) {
	app := newSeedTestApp(t)

	if _, err := settingsSetByHook(app, "test2_enable_hook", "max_fails", 4); err != nil {
		t.Fatalf("hook set: %v", err)
	}
	row := saFindLatest(t, app, "gateway.config")
	if row == nil {
		t.Fatalf("no gateway.config row after hook set")
	}
	d := fwDetail(row)
	if d["hook"] != "test2_enable_hook" || d["op"] != "set" || d["key"] != "max_fails" {
		t.Fatalf("hook set detail=%v", d)
	}
	if row.GetString("actor_kind") != "guest" || row.GetString("actor_id") != "" {
		t.Fatalf("hook row must be server-side: kind=%q id=%q",
			row.GetString("actor_kind"), row.GetString("actor_id"))
	}

	// Откат хуком — тоже с именем хука (строки ищутся по операции:
	// внутри одной миллисекунды порядок «последних» нестабилен).
	if _, err := settingsDeleteByHook(app, "test2_enable_hook", "max_fails"); err != nil {
		t.Fatalf("hook delete: %v", err)
	}
	rows, err := app.FindRecordsByFilter("seed_audit",
		`action={:a} && detail.op={:op}`, "", 1, 0,
		map[string]any{"a": "gateway.config", "op": "delete"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("hook delete row not found: %v %d", err, len(rows))
	}
	if d := fwDetail(rows[0]); d["hook"] != "test2_enable_hook" || d["key"] != "max_fails" {
		t.Fatalf("hook delete detail=%v", d)
	}

	// Неудачная запись (равная стандарту) строку не порождает.
	before, _ := app.CountRecords("seed_audit")
	if _, err := settingsSetByHook(app, "h", "max_fails", 10); err != errSettingsDefault {
		t.Fatalf("expected default reject, got %v", err)
	}
	after, _ := app.CountRecords("seed_audit")
	if before != after {
		t.Fatalf("failed hook set must not audit: %d -> %d", before, after)
	}
}
