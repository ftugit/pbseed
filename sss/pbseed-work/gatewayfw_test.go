package main

// gatewayfw_test.go — защита гейтвея: лимит регистраций с адреса,
// лимит входов аккаунта, запирание ключа за неудачи подряд и три
// независимых выключателя (регистрация, вход, продление). Отказы
// защиты сами пишутся в журнал.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// gwNewKey генерирует свежую пару ключей и возвращает приватный ключ
// и hex открытого.
//
// Параметры:
//   - t: *testing.T — тест.
//
// Возвращает: ed25519.PrivateKey — приватный ключ;
// string — открытый ключ в hex.
func gwNewKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return priv, strings.ToLower(hex.EncodeToString(pub))
}

// gwSession проходит челлендж и пытается войти/зарегистрироваться
// указанным ключом; устройство — обычное либо зарезервированное (для
// управляемых неудач). Дополнительно возвращает сессионную куку
// ответа (для запросов от имени вошедшего пользователя).
//
// Параметры:
//   - t: *testing.T — тест;
//   - do: func — исполняющий запросы каркас (serveMux);
//   - priv: ed25519.PrivateKey — приватный ключ;
//   - pk: string — открытый ключ (hex);
//   - purpose: string — «login» или «register»;
//   - device: string — имя устройства.
//
// Возвращает: int — код ответа;
// string — тело ответа;
// string — значение куки сессии («грант.секрет», пусто при отказе).
func gwSession(t *testing.T, do func(string, string, map[string]string, string) (*http.Response, string),
	priv ed25519.PrivateKey, pk, purpose, device string) (int, string, string) {
	t.Helper()
	res, body := do(http.MethodPost, "/api/seed/challenge", nil,
		`{"public_key":"`+pk+`","purpose":"`+purpose+`"}`)
	if res.StatusCode != 200 {
		t.Fatalf("challenge status=%d body=%s", res.StatusCode, body)
	}
	var ch struct {
		Nonce string `json:"nonce"`
	}
	_ = json.Unmarshal([]byte(body), &ch)
	msg := seedMsgPrefix + seedDomain() + ":" + purpose + ":" + pk + ":" + ch.Nonce
	sig := strings.ToLower(hex.EncodeToString(ed25519.Sign(priv, []byte(msg))))
	res, body = do(http.MethodPost, "/api/seed/login", nil,
		`{"public_key":"`+pk+`","signature":"`+sig+`","purpose":"`+purpose+
			`","nonce":"`+ch.Nonce+`","device_name":"`+device+`"}`)
	ck := ""
	for _, c := range res.Cookies() {
		if c.Name == seedCookieName {
			ck = c.Value
		}
	}
	return res.StatusCode, body, ck
}

// gwAttempt — gwSession без куки (историческая сигнатура для тестов,
// где сессия не нужна).
//
// Возвращает: int — код ответа;
// string — тело ответа.
func gwAttempt(t *testing.T, do func(string, string, map[string]string, string) (*http.Response, string),
	priv ed25519.PrivateKey, pk, purpose, device string) (int, string) {
	t.Helper()
	st, body, _ := gwSession(t, do, priv, pk, purpose, device)
	return st, body
}

// TestGatewayRegisterLimit — не более порога регистраций в сутки с
// одного адреса; попытка сверх лимита отклоняется и пишется в журнал.
func TestGatewayRegisterLimit(t *testing.T) {
	app := newSeedTestApp(t)
	t.Setenv("SEED_GATEWAY_REG_PER_DAY", "2")
	do := serveMux(t, app)

	for i := 0; i < 2; i++ {
		priv, pk := gwNewKey(t)
		if st, body := gwAttempt(t, do, priv, pk, "register", "dev"); st != 200 {
			t.Fatalf("register #%d status=%d body=%s", i, st, body)
		}
	}
	priv, pk := gwNewKey(t)
	st, body := gwAttempt(t, do, priv, pk, "register", "dev")
	if st != 403 || !strings.Contains(body, "register_limit") {
		t.Fatalf("over-limit register status=%d body=%s, want 403 register_limit", st, body)
	}
	row := saFindLatest(t, app, "auth.register_denied")
	if row == nil {
		t.Fatalf("no auth.register_denied row")
	}
	if d := fwDetail(row); d["reason"] != "register_limit" || d["ip_hash"] == "" {
		t.Errorf("denied detail=%v", d)
	}
}

// TestGatewayLoginLimit — не более порога входов аккаунта в сутки.
func TestGatewayLoginLimit(t *testing.T) {
	app := newSeedTestApp(t)
	t.Setenv("SEED_GATEWAY_LOGINS_PER_DAY", "3")
	do := serveMux(t, app)

	priv, pk := gwNewKey(t)
	if st, body := gwAttempt(t, do, priv, pk, "register", "dev"); st != 200 {
		t.Fatalf("register status=%d body=%s", st, body)
	}
	for i := 0; i < 3; i++ {
		if st, body := gwAttempt(t, do, priv, pk, "login", "dev"); st != 200 {
			t.Fatalf("login #%d status=%d body=%s", i, st, body)
		}
	}
	st, body := gwAttempt(t, do, priv, pk, "login", "dev")
	if st != 403 || !strings.Contains(body, "login_limit") {
		t.Fatalf("over-limit login status=%d body=%s, want 403 login_limit", st, body)
	}
	if row := saFindLatest(t, app, "auth.login_denied"); row == nil {
		t.Fatalf("no auth.login_denied row")
	}
}

// TestGatewayFailStreakLock — порог неудач подряд ОДНОГО АДРЕСА
// запирает адрес: счётчик общий для всех ключей (перебор сидов и
// прыжки между аккаунтами идут с разных ключей, но с одного адреса).
// После истечения срока запирания адрес отходит, успешный вход
// сбрасывает серию.
func TestGatewayFailStreakLock(t *testing.T) {
	app := newSeedTestApp(t)
	t.Setenv("SEED_GATEWAY_MAX_FAILS", "3")
	t.Setenv("SEED_GATEWAY_FAIL_LOCK", "15m")
	do := serveMux(t, app)

	// Рабочий аккаунт на этом адресе.
	priv, pk := gwNewKey(t)
	if st, body := gwAttempt(t, do, priv, pk, "register", "dev"); st != 200 {
		t.Fatalf("register status=%d body=%s", st, body)
	}
	// Три неудачи подряд с ТРЁХ РАЗНЫХ ключей: поключевой счётчик не
	// набрал бы и одной, общий — набирает три.
	for i := 0; i < 3; i++ {
		fpriv, fpk := gwNewKey(t)
		if st, _ := gwAttempt(t, do, fpriv, fpk, "login", "@x"); st != 400 {
			t.Fatalf("bad device attempt #%d status=%d, want 400", i, st)
		}
	}
	// Четвёртая попытка — верным ключом с верной подписью, но заперт
	// адрес, а не ключ.
	st, body := gwAttempt(t, do, priv, pk, "login", "dev")
	if st != 403 || !strings.Contains(body, "failures_locked") {
		t.Fatalf("locked address status=%d body=%s, want 403 failures_locked", st, body)
	}
	row := saFindLatest(t, app, "auth.login_denied")
	if row == nil || fwDetail(row)["reason"] != "failures_locked" {
		t.Fatalf("no failures_locked denied row")
	}

	// Срок запирания истёк — адрес снова пробует себя.
	t.Setenv("SEED_GATEWAY_FAIL_LOCK", "1ns")
	if st, body := gwAttempt(t, do, priv, pk, "login", "dev"); st != 200 {
		t.Fatalf("post-lock login status=%d body=%s, want 200", st, body)
	}
	// Успех обнулил серию: одна неудача больше не запирает.
	fpriv, fpk := gwNewKey(t)
	if st, _ := gwAttempt(t, do, fpriv, fpk, "login", "@x"); st != 400 {
		t.Fatalf("single bad device status=%d, want 400", st)
	}
	if st, body := gwAttempt(t, do, priv, pk, "login", "dev"); st != 200 {
		t.Fatalf("login after reset status=%d body=%s, want 200", st, body)
	}
}

// TestGatewaySwitches — регистрация, вход и продление отключаются по
// отдельности; отказы фиксируются журналом.
func TestGatewaySwitches(t *testing.T) {
	app := newSeedTestApp(t)
	do := serveMux(t, app)
	priv, pk := gwNewKey(t)

	t.Setenv("SEED_REGISTER", "0")
	st, body := gwAttempt(t, do, priv, pk, "register", "dev")
	if st != 403 || !strings.Contains(body, "register_disabled") {
		t.Fatalf("disabled register status=%d body=%s", st, body)
	}
	if row := saFindLatest(t, app, "auth.register_denied"); row == nil {
		t.Fatalf("no register_denied row")
	}
	t.Setenv("SEED_REGISTER", "1")
	if st, body := gwAttempt(t, do, priv, pk, "register", "dev"); st != 200 {
		t.Fatalf("register after re-enable status=%d body=%s", st, body)
	}

	t.Setenv("SEED_LOGIN", "0")
	st, body = gwAttempt(t, do, priv, pk, "login", "dev")
	if st != 403 || !strings.Contains(body, "login_disabled") {
		t.Fatalf("disabled login status=%d body=%s", st, body)
	}
	if row := saFindLatest(t, app, "auth.login_denied"); row == nil {
		t.Fatalf("no login_denied row")
	}
	t.Setenv("SEED_LOGIN", "1")

	// Продление: нужна живая сессия (осталась от регистрации).
	access, ck, _ := edRegister(t, do) // второй аккаунт — свой хвост куки
	_ = access
	t.Setenv("SEED_RENEW", "0")
	res, body := do(http.MethodPost, "/api/seed/renew",
		map[string]string{"Cookie": seedCookieName + "=" + ck}, `{}`)
	if res.StatusCode != 403 || !strings.Contains(body, "renew_disabled") {
		t.Fatalf("disabled renew status=%d body=%s", res.StatusCode, body)
	}
	if row := saFindLatest(t, app, "auth.renew_failed"); row == nil ||
		fwDetail(row)["reason"] != "renew_disabled" {
		t.Fatalf("no renew_failed(renew_disabled) row")
	}
	t.Setenv("SEED_RENEW", "1")
	res, _ = do(http.MethodPost, "/api/seed/renew",
		map[string]string{"Cookie": seedCookieName + "=" + ck}, `{}`)
	if res.StatusCode != 200 {
		t.Fatalf("renew after re-enable status=%d, want 200", res.StatusCode)
	}
}
