package main

// gatewayfw.go — защита гейтвея (вход по ключу, регистрация,
// продление сессии).
//
// Меры:
//
//   - регистрация и вход могут быть полностью отключены по отдельности
//     (равно как и продление сессии);
//   - не более порога регистраций в сутки с одного адреса;
//   - не более порога входов в сутки на один аккаунт;
//   - порог НЕУДАЧ ВХОДА ПОДРЯД на один ключ запирает ключ на срок
//     запирания (успешный вход сбрасывает счётчик).
//
// Стандартные пороги и их переопределения (база → окружение →
// константа) описаны в `settings.go`; там же — программный доступ к
// конфигурации и эндпоинты `/api/seed/gateway-config`.
//
// Защита работает поверх журнала: счётчики читаются по строкам
// `seed_audit`, а каждый отказ гейтвея сам пишется в журнал
// (`auth.register_denied`, `auth.login_denied`, продление —
// `auth.renew_failed` с причиной) — наблюдения защита не ослабляет.

import (
	"errors"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// errGatewayDenied — маркер отказа гейтвея. Ответ клиенту уже записан
// (403), ошибка нужна только чтобы прервать обработчик: роутер
// игнорирует ошибку, если ответ уже отправлен.
var errGatewayDenied = errors.New("gateway denied")

// gwCountToday считает строки журнала за текущие сутки по действию и
// дополнительному фильтру.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - action: string — ключ действия;
//   - extra: string — дополнительный фильтр (может быть пуст);
//   - params: dbx.Params — параметры дополнительного фильтра.
//
// Возвращает: int — число строк с начала суток.
func gwCountToday(app core.App, action, extra string, params dbx.Params) int {
	filter := `action={:gw_a} && created_at >= {:gw_day}`
	p := dbx.Params{
		"gw_a":   action,
		"gw_day": fwDayStart(time.Now()).UTC().Format("2006-01-02 15:04:05.000Z"),
	}
	if strings.TrimSpace(extra) != "" {
		filter += " && " + extra
		for k, v := range params {
			p[k] = v
		}
	}
	rows, err := app.FindRecordsByFilter("seed_audit", filter, "", 500, 0, p)
	if err != nil {
		return 0
	}
	return len(rows)
}

// gwFailStreak считает неудачи входа подряд С ОДНОГО АДРЕСА: строки
// `auth.login_failed` с этим `ip_hash`, идущие ПОСЛЕ последнего
// успешного входа с того же адреса (успех обнуляет серию).
//
// Счётчик один на адрес, а не на ключ — иначе защита бессмысленна:
// ключ либо зарегистрирован либо нет, а реальные атаки — это перебор
// сидов (много разных ключей с одного адреса) и прыжки между
// аккаунтами с неверными подписями. По одному ключу каждая такая
// попытка — первая и последняя, и порог никогда бы не достигался.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - ipHash: string — хэш адреса соединения.
//
// Возвращает: int — длина серии неудач;
// time.Time — момент последней неудачи (нулевое время, если неудач нет).
func gwFailStreak(app core.App, ipHash string) (int, time.Time) {
	fails, err := app.FindRecordsByFilter("seed_audit",
		`action={:gw_a} && detail.ip_hash={:gw_h}`, "-created_at", 200, 0,
		dbx.Params{"gw_a": "auth.login_failed", "gw_h": ipHash})
	if err != nil || len(fails) == 0 {
		return 0, time.Time{}
	}
	// Последний успех с этого адреса обнуляет серию.
	lastLogin := fwLastRow(app, "auth.login", `detail.ip_hash={:gw_h}`,
		dbx.Params{"gw_h": ipHash})
	lastOK := time.Time{}
	if lastLogin != nil {
		lastOK = fwRowTime(lastLogin)
	}
	n := 0
	for _, r := range fails {
		if !fwRowTime(r).After(lastOK) {
			break
		}
		n++
	}
	return n, fwRowTime(fails[0])
}

// gwDeny пишет отказ гейтвея в журнал и возвращает ответ 403. Отказы
// наблюдаются наравне с событиями: защита не оставляет слепых мест.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса;
//   - action: string — ключ действия журнала (…_denied);
//   - code: string — код отказа для клиента;
//   - pk: string — открытый ключ попытки;
//   - reason: string — причина отказа.
//
// Возвращает: error — ненулевой маркер после записанного ответа 403
// (важно: `seedErr` возвращает `nil` при успешной записи, поэтому для
// прерывания обработчика нужен отдельный маркер).
func gwDeny(e *core.RequestEvent, action, code, pk, reason string) error {
	ip := e.RealIP()
	auditLogAs(e, nil, action, map[string]any{
		"public_key": pk,
		"reason":     reason,
		"ip_hash":    fwIPHash(ip),
		"ip_masked":  maskIP(ip),
	})
	_ = seedErr(e, 403, code)
	return errGatewayDenied
}

// gwGateRegister проверяет защиту перед регистрацией: выключатель и
// лимит регистраций в сутки с адреса.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса;
//   - pk: string — открытый ключ попытки.
//
// Возвращает: error — отказ (403) или nil.
func gwGateRegister(e *core.RequestEvent, pk string) error {
	if !gwOn(e.App, gwPRegister) {
		return gwDeny(e, "auth.register_denied", "register_disabled", pk, "register_disabled")
	}
	iph := fwIPHash(e.RealIP())
	if gwCountToday(e.App, "auth.register", `detail.ip_hash={:gw_h}`, dbx.Params{"gw_h": iph}) >= gwIntOf(e.App, gwPRegPerDay) {
		return gwDeny(e, "auth.register_denied", "register_limit", pk, "register_limit")
	}
	return nil
}

// gwGateLogin проверяет защиту перед входом существующего ключа:
// выключатель, порог неудач подряд с адреса и лимит входов в сутки.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса;
//   - pk: string — открытый ключ попытки.
//
// Возвращает: error — отказ (403) или nil.
func gwGateLogin(e *core.RequestEvent, pk string) error {
	if !gwOn(e.App, gwPLogin) {
		return gwDeny(e, "auth.login_denied", "login_disabled", pk, "login_disabled")
	}
	streak, lastFail := gwFailStreak(e.App, fwIPHash(e.RealIP()))
	if streak >= gwIntOf(e.App, gwPMaxFails) && time.Since(lastFail) < gwDurOf(e.App, gwPFailLock) {
		return gwDeny(e, "auth.login_denied", "failures_locked", pk, "failures_locked")
	}
	user, err := e.App.FindFirstRecordByData("users", "email", pk+"@seed.local")
	if err == nil && user != nil &&
		gwCountToday(e.App, "auth.login", `actor_id={:gw_u}`, dbx.Params{"gw_u": user.Id}) >= gwIntOf(e.App, gwPLoginsPerDay) {
		return gwDeny(e, "auth.login_denied", "login_limit", pk, "login_limit")
	}
	return nil
}
