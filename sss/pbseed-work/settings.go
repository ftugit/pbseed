package main

// settings.go — ядро конфигурации сервиса.
//
// Конфигурация = стандартные константы + переопределения в базе.
// Порядок разрешения каждого параметра: строка `seed_gateway` (если
// есть) → переменная окружения (если задана) → константа. База хранит
// ТОЛЬКО переопределения: запись значения, равного стандарту,
// запрещена, а удаление строки возвращает параметр к окружению или
// константе.
//
// Это же — программный доступ к конфигурации для серверных хуков
// (аналог `{get, set} = useSettings()`):
//
//	value, source, ok := settingsGet(app, "reg_per_day")
//	if _, err := settingsSet(app, "max_fails", 5); err != nil { … }
//	settingsDelete(app, "max_fails") // откат к стандарту
//
// Ошибки настроек — маркеры `errSettingsKey`, `errSettingsValue`,
// `errSettingsDefault`; обработчики переводят их в коды ответа.
//
// Доступ через REST: `/api/seed/gateway-config` — суперюзер или
// пользователь с ролью `admin` (ролевой админ идёт с кукой сессии,
// как любой пользователь).

import (
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

// Маркеры ошибок настроек.
var (
	errSettingsKey     = errors.New("settings: unknown key")
	errSettingsValue   = errors.New("settings: bad value")
	errSettingsDefault = errors.New("settings: value equals default")
)

// Стандартные значения защиты гейтвея — константы. Они же критерий
// при записи в базу: переопределение, равное стандарту, отклоняется.
const (
	gwDefaultRegister     = true             // регистрация включена
	gwDefaultLogin        = true             // вход включён
	gwDefaultRenew        = true             // продление включено
	gwDefaultRegPerDay    = 2                // регистраций в сутки с адреса
	gwDefaultLoginsPerDay = 100              // входов аккаунта в сутки
	gwDefaultMaxFails     = 10               // неудач подряд до запирания
	gwDefaultFailLock     = 15 * time.Minute // срок запирания ключа
)

// Виды значений параметров настройки.
const (
	gwBool = "bool" // переключатель: 1/0
	gwInt  = "int"  // целое число >= 0
	gwDur  = "dur"  // длительность формата Go («15m», «90s»)
)

// gwParam описывает один настраиваемый параметр.
//
// Поля:
//   - Key: string — имя в базе и в ответах эндпоинта;
//   - Kind: string — вид значения (gwBool/gwInt/gwDur);
//   - Env: string — переменная окружения (прослойка между базой и
//     константой);
//   - Def: string — стандартное значение в канонической форме.
type gwParam struct {
	Key  string
	Kind string
	Env  string
	Def  string
}

// Реестр настраиваемых параметров (переопределяются через базу).
var (
	gwPRegister     = gwParam{"register", gwBool, "SEED_REGISTER", "1"}
	gwPLogin        = gwParam{"login", gwBool, "SEED_LOGIN", "1"}
	gwPRenew        = gwParam{"renew", gwBool, "SEED_RENEW", "1"}
	gwPRegPerDay    = gwParam{"reg_per_day", gwInt, "SEED_GATEWAY_REG_PER_DAY", "2"}
	gwPLoginsPerDay = gwParam{"logins_per_day", gwInt, "SEED_GATEWAY_LOGINS_PER_DAY", "100"}
	gwPMaxFails     = gwParam{"max_fails", gwInt, "SEED_GATEWAY_MAX_FAILS", "10"}
	gwPFailLock     = gwParam{"fail_lock", gwDur, "SEED_GATEWAY_FAIL_LOCK", "15m"}

	gwParams = []gwParam{
		gwPRegister, gwPLogin, gwPRenew,
		gwPRegPerDay, gwPLoginsPerDay, gwPMaxFails, gwPFailLock,
	}
)

// gwParamByKey ищет параметр реестра по имени.
//
// Параметры:
//   - key: string — имя параметра.
//
// Возвращает: *gwParam — параметр или nil, если имя неизвестно.
func gwParamByKey(key string) *gwParam {
	for i := range gwParams {
		if gwParams[i].Key == key {
			return &gwParams[i]
		}
	}
	return nil
}

// --- нормализация значений ------------------------------------------------

// gwNormBool приводит значение к каноническому «1»/«0».
//
// Параметры:
//   - raw: any — булево, число или строка из запроса.
//
// Возвращает: string — «1» или «0»;
// bool — удалось ли распознать значение.
func gwNormBool(raw any) (string, bool) {
	switch v := raw.(type) {
	case bool:
		if v {
			return "1", true
		}
		return "0", true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "on", "yes":
			return "1", true
		case "0", "false", "off", "no":
			return "0", true
		}
	case float64:
		if v == 0 {
			return "0", true
		}
		if v == 1 {
			return "1", true
		}
	}
	return "", false
}

// gwNormInt приводит значение к канонической десятичной записи.
// Отрицательные и дробные значения не принимаются.
//
// Параметры:
//   - raw: any — число или строка из запроса.
//
// Возвращает: string — каноническая запись;
// bool — удалось ли распознать значение.
func gwNormInt(raw any) (string, bool) {
	var n int64
	switch v := raw.(type) {
	case float64:
		if v != float64(int64(v)) || v < 0 {
			return "", false
		}
		n = int64(v)
	case int:
		if v < 0 {
			return "", false
		}
		n = int64(v)
	case int64:
		if v < 0 {
			return "", false
		}
		n = v
	case string:
		p, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || p < 0 {
			return "", false
		}
		n = p
	default:
		return "", false
	}
	return strconv.FormatInt(n, 10), true
}

// gwNormDur приводит значение к канонической записи длительности.
// Нулевые и отрицательные сроки не принимаются.
//
// Параметры:
//   - raw: any — строка формата Go («15m», «1h30m») из запроса.
//
// Возвращает: string — каноническая запись;
// bool — удалось ли распознать значение.
func gwNormDur(raw any) (string, bool) {
	s, ok := raw.(string)
	if !ok {
		return "", false
	}
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d <= 0 {
		return "", false
	}
	return d.String(), true
}

// gwNormalize приводит значение параметра к канонической форме его
// вида.
//
// Параметры:
//   - p: *gwParam — параметр;
//   - raw: any — значение из запроса.
//
// Возвращает: string — каноническая форма;
// bool — значение распознано.
func gwNormalize(p *gwParam, raw any) (string, bool) {
	switch p.Kind {
	case gwBool:
		return gwNormBool(raw)
	case gwInt:
		return gwNormInt(raw)
	case gwDur:
		return gwNormDur(raw)
	}
	return "", false
}

// gwIsDefault сообщает, совпадает ли каноническое значение со
// стандартом параметра (длительности сравниваются по смыслу).
//
// Параметры:
//   - p: *gwParam — параметр;
//   - v: string — каноническое значение.
//
// Возвращает: bool — совпадает ли.
func gwIsDefault(p *gwParam, v string) bool {
	if p.Kind == gwDur {
		dv, err1 := time.ParseDuration(v)
		dd, err2 := time.ParseDuration(p.Def)
		return err1 == nil && err2 == nil && dv == dd
	}
	return v == p.Def
}

// --- разрешение параметра ---------------------------------------------------

// gwDBRow читает строку переопределения параметра из базы.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - p: gwParam — параметр.
//
// Возвращает: *core.Record — строка или nil, если переопределения нет.
func gwDBRow(app core.App, p gwParam) *core.Record {
	r, err := app.FindFirstRecordByData("seed_gateway", "key", p.Key)
	if err != nil {
		return nil
	}
	return r
}

// gwResolve вычисляет действующее значение параметра (база →
// окружение → константа) и его источник.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - p: gwParam — параметр.
//
// Возвращает: string — каноническое значение;
// string — источник: «база», «окружение» или «константа».
func gwResolve(app core.App, p gwParam) (string, string) {
	if r := gwDBRow(app, p); r != nil {
		return asStr(r.Get("value")), "база"
	}
	if raw := strings.TrimSpace(os.Getenv(p.Env)); raw != "" {
		if v, ok := gwNormalize(&p, raw); ok {
			return v, "окружение"
		}
	}
	return p.Def, "константа"
}

// gwOn сообщает, включён ли переключатель гейтвея.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - p: gwParam — параметр-переключатель.
//
// Возвращает: bool — состояние.
func gwOn(app core.App, p gwParam) bool {
	v, _ := gwResolve(app, p)
	return v == "1"
}

// gwIntOf сообщает действующий числовой порог.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - p: gwParam — параметр-число.
//
// Возвращает: int — порог.
func gwIntOf(app core.App, p gwParam) int {
	v, _ := gwResolve(app, p)
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		n, _ = strconv.Atoi(p.Def)
	}
	return n
}

// gwDurOf сообщает действующую длительность.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - p: gwParam — параметр-длительность.
//
// Возвращает: time.Duration — срок.
func gwDurOf(app core.App, p gwParam) time.Duration {
	v, _ := gwResolve(app, p)
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		d, _ = time.ParseDuration(p.Def)
	}
	return d
}

// --- программный доступ (для хуков) -----------------------------------------

// settingsGet читает параметр по ключу — аналог
// `useSettings().get`. Действующее значение разрешается как база →
// окружение → константа.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - key: string — ключ параметра.
//
// Возвращает: string — действующее каноническое значение;
// string — источник («база», «окружение», «константа»);
// bool — ключ известен.
func settingsGet(app core.App, key string) (string, string, bool) {
	p := gwParamByKey(key)
	if p == nil {
		return "", "", false
	}
	v, src := gwResolve(app, *p)
	return v, src, true
}

// settingsSet записывает переопределение параметра — аналог
// `useSettings().set`. Значение нормализуется; равное стандарту
// отклоняется (база хранит только отличия). Аудит остаётся за
// вызывающим (ему виден контекст запроса).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - key: string — ключ параметра;
//   - raw: any — значение (булево, число или строка).
//
// Возвращает: string — записанное каноническое значение;
// error — `errSettingsKey`, `errSettingsValue`, `errSettingsDefault`
// либо ошибку хранилища.
func settingsSet(app core.App, key string, raw any) (string, error) {
	p := gwParamByKey(key)
	if p == nil {
		return "", errSettingsKey
	}
	v, ok := gwNormalize(p, raw)
	if !ok {
		return "", errSettingsValue
	}
	if gwIsDefault(p, v) {
		return "", errSettingsDefault
	}
	if r := gwDBRow(app, *p); r != nil {
		r.Set("value", v)
		if err := app.Save(r); err != nil {
			return "", err
		}
		return v, nil
	}
	col, err := app.FindCollectionByNameOrId("seed_gateway")
	if err != nil {
		return "", err
	}
	rec := core.NewRecord(col)
	rec.Set("key", p.Key)
	rec.Set("value", v)
	if err := app.Save(rec); err != nil {
		return "", err
	}
	return v, nil
}

// settingsDelete удаляет переопределение параметра — откат к
// окружению/константе.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - key: string — ключ параметра.
//
// Возвращает: bool — существовала ли строка;
// error — `errSettingsKey` либо ошибку хранилища.
func settingsDelete(app core.App, key string) (bool, error) {
	p := gwParamByKey(key)
	if p == nil {
		return false, errSettingsKey
	}
	r := gwDBRow(app, *p)
	if r == nil {
		return false, nil
	}
	if err := app.Delete(r); err != nil {
		return false, err
	}
	return true, nil
}

// settingsSetByHook записывает переопределение от имени серверного
// хука и фиксирует это в журнале с именем хука. Хук — серверный код
// без запроса, поэтому исполнитель в строке не человек, а источник
// указывается полем `hook` в `detail`.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - hookName: string — имя хука (атрибуция в журнале);
//   - key: string — ключ параметра;
//   - raw: any — значение.
//
// Возвращает: string — записанное каноническое значение;
// error — те же маркеры, что у `settingsSet`.
func settingsSetByHook(app core.App, hookName, key string, raw any) (string, error) {
	v, err := settingsSet(app, key, raw)
	if err != nil {
		return "", err
	}
	auditWriteRow(app, nil, "", "", "gateway.config", map[string]any{
		"key": key, "value": v, "op": "set", "hook": truncRunes(hookName, 64),
	})
	return v, nil
}

// settingsDeleteByHook снимает переопределение от имени серверного
// хука и фиксирует это в журнале с именем хука.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - hookName: string — имя хука (атрибуция в журнале);
//   - key: string — ключ параметра.
//
// Возвращает: bool — существовала ли строка;
// error — `errSettingsKey` либо ошибку хранилища.
func settingsDeleteByHook(app core.App, hookName, key string) (bool, error) {
	deleted, err := settingsDelete(app, key)
	if err != nil {
		return false, err
	}
	if deleted {
		auditWriteRow(app, nil, "", "", "gateway.config", map[string]any{
			"key": key, "op": "delete", "hook": truncRunes(hookName, 64),
		})
	}
	return deleted, nil
}

// --- картина конфигурации ----------------------------------------------------

// settingsView собирает все переопределяемые параметры с действующим
// значением, источником и стандартом.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: []map[string]any — список для ответа клиенту.
func settingsView(app core.App) []map[string]any {
	out := make([]map[string]any, 0, len(gwParams))
	for _, p := range gwParams {
		v, src := gwResolve(app, p)
		out = append(out, map[string]any{
			"key":     p.Key,
			"value":   v,
			"source":  src,
			"default": p.Def,
			"env":     p.Env,
		})
	}
	return out
}

// bool01 кодирует булево строкой «1»/«0» — единый канонический вид
// переключателей в ответах.
//
// Параметры:
//   - b: bool — значение.
//
// Возвращает: string — «1» или «0».
func bool01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// seedGCEvery сообщает период фоновой очистки (переменная
// `SEED_GC_EVERY`, по умолчанию 5 минут).
//
// Возвращает: time.Duration — период.
func seedGCEvery() time.Duration {
	every := 5 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("SEED_GC_EVERY")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			every = d
		} else {
			log.Printf("[seed] WARN: bad SEED_GC_EVERY=%q, using default", raw)
		}
	}
	return every
}

// settingsReadonlyView собирает параметры, которые НЕ переопределяются
// через базу: текущее значение и место установки. Секреты не
// раскрываются — только факт наличия.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: []map[string]any — список для ответа клиенту.
func settingsReadonlyView(app core.App) []map[string]any {
	keep := auditKeepDays()
	keepS := "вечно"
	if keep > 0 {
		keepS = strconv.Itoa(keep)
	}
	ipKeyS := "не задан (устаревший SHA-256)"
	if len(seedIPKey()) > 0 {
		ipKeyS = "задан (HMAC)"
	}
	suMail := os.Getenv("PB_SUPERUSER_EMAIL")
	if strings.TrimSpace(suMail) == "" {
		suMail = "не задан"
	}
	suPass := "не задан"
	if strings.TrimSpace(os.Getenv("PB_SUPERUSER_PASSWORD")) != "" {
		suPass = "задан"
	}
	rows := []struct{ key, value, where string }{
		{"domain", seedDomain(), "окружение"},
		{"ip_key", ipKeyS, "окружение"},
		{"cookie_insecure", bool01(!seedCookieSecure()), "окружение"},
		{"gc_every", seedGCEvery().String(), "только при запуске"},
		{"audit_keep_days", keepS, "окружение"},
		{"geo_allow_private", bool01(geoAllowPrivate()), "окружение"},
		{"firewall", bool01(fwEnabled()), "окружение"},
		{"firewall_fails", strconv.Itoa(fwFails()), "окружение"},
		{"firewall_window", fwWindow().String(), "окружение"},
		{"firewall_lock", fwLockDur().String(), "окружение"},
		{"firewall_blocks", strconv.Itoa(fwBlocksPerDay()), "окружение"},
		{"superuser_email", suMail, "только при запуске"},
		{"superuser_password", suPass, "только при запуске"},
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{"key": r.key, "value": r.value, "where": r.where})
	}
	return out
}

// --- эндпоинты настройки ----------------------------------------------------

// gwConfigGuard пропускает к настройке суперюзера и пользователя с
// ролью «admin». Ролевой админ приходит с кукой сессии, как любой
// пользователь (мидлвара сессий его не пропускает без неё).
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: error — ответ 401/403 или nil.
func gwConfigGuard(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	if !seedAdmin(e.Auth) {
		return seedErr(e, 403, "forbidden")
	}
	return nil
}

// seedGatewayConfigGet — GET /api/seed/gateway-config. Полная картина
// конфигурации: переопределяемые параметры (значение, источник,
// стандарт) и неизменяемые (значение, место установки). Доступ:
// суперюзер или роль «admin».
//
// Ответ 200: {params: [{key, value, source, default, env}],
// readonly: [{key, value, where}]}
// Ошибки: 401 (нет токена), 403 (не администратор).
func seedGatewayConfigGet(e *core.RequestEvent) error {
	if err := gwConfigGuard(e); err != nil {
		return err
	}
	return e.JSON(200, map[string]any{
		"params":   settingsView(e.App),
		"readonly": settingsReadonlyView(e.App),
	})
}

// seedGatewayConfigSet — POST /api/seed/gateway-config. Записывает
// переопределение параметра в базу. Тело: {key: string, value: …}.
// Доступ: суперюзер или роль «admin». Значение обязано отличаться от
// стандартного — равное стандарту отклоняется (400 `default_value`):
// база хранит только переопределения, откат — удалением строки.
//
// Ответ 200: {ok: true, key, value}
// Ошибки: 400 (`bad_key`, `bad_value`, `default_value`),
// 401 (нет токена), 403 (не администратор).
func seedGatewayConfigSet(e *core.RequestEvent) error {
	if err := gwConfigGuard(e); err != nil {
		return err
	}
	var b struct {
		Key   string `json:"key"`
		Value any    `json:"value"`
	}
	_ = e.BindBody(&b)
	key := strings.TrimSpace(b.Key)
	v, err := settingsSet(e.App, key, b.Value)
	switch {
	case err == errSettingsKey:
		return seedErr(e, 400, "bad_key")
	case err == errSettingsValue:
		return seedErr(e, 400, "bad_value")
	case err == errSettingsDefault:
		return seedErr(e, 400, "default_value")
	case err != nil:
		return seedErr(e, 500, "store_failed")
	}
	auditLog(e, "gateway.config", map[string]any{"key": key, "value": v, "op": "set"})
	// Внутреннее сохранение минует REST-хуки — предохранитель
	// «автонастройка» вызывается здесь тем же телом, что и там.
	autotuneRegPerDay(e.App)
	return e.JSON(200, map[string]any{"ok": true, "key": key, "value": v})
}

// seedGatewayConfigDelete — DELETE /api/seed/gateway-config?key=…
// Удаляет переопределение: параметр возвращается к окружению или
// константе. Доступ: суперюзер или роль «admin».
//
// Ответ 200: {ok: true, deleted: 0|1}
// Ошибки: 400 (`bad_key`), 401 (нет токена), 403 (не администратор).
func seedGatewayConfigDelete(e *core.RequestEvent) error {
	if err := gwConfigGuard(e); err != nil {
		return err
	}
	key := strings.TrimSpace(e.Request.URL.Query().Get("key"))
	deleted, err := settingsDelete(e.App, key)
	switch {
	case err == errSettingsKey:
		return seedErr(e, 400, "bad_key")
	case err != nil:
		return seedErr(e, 500, "store_failed")
	}
	if !deleted {
		return e.JSON(200, map[string]any{"ok": true, "deleted": 0})
	}
	auditLog(e, "gateway.config", map[string]any{"key": key, "op": "delete"})
	return e.JSON(200, map[string]any{"ok": true, "deleted": 1})
}
