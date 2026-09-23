package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/types"
)

// Аутентификация seed (ed25519): челлендж -> подпись -> вход
// (короткоживущий токен доступа + долгоживущая кука сессии).
// Каждый запрос с токеном пользователя обязан нести живую куку сессии.
//
// Схема портирована с оригинала на SurrealDB
// (server/install/database/01_auth.surql):
//   - баны (banned / ban_reason / banned_until) проверяются при входе,
//     продлении и на каждом запросе (мидлвара); срок истекает лениво,
//     планировщик не нужен;
//   - проверка IP при продлении: персональная политика «выгонять при смене
//     IP» убивает сессию; иначе старая маска и страна уходят в историю
//     сессии (не более 10 записей);
//   - выход с текущего устройства и выход со всех устройств;
//   - список сессий отдаёт маску IP, страну, историю и флаг «текущая».

const (
	// seedMsgPrefix — префикс подписываемого сообщения (версия схемы).
	seedMsgPrefix = "surreal-auth-v1:"
	// seedCookieName — имя куки сессии (значение: "грант.секрет").
	seedCookieName = "pb_seed"

	// seedChallengeTTL — время жизни челленджа (нонса).
	seedChallengeTTL = 5 * time.Minute
	// seedSessionDays — время жизни сессии в днях (кука).
	seedSessionDays = 30

	// seedAccessTTL — справочный срок жизни токена доступа в секундах;
	// реальное значение берётся из коллекции users (authToken.duration),
	// на которую этот срок и выставляется при старте.
	seedAccessTTL = 900

	// seedHistoryCap — максимум записей смены IP на одну сессию.
	seedHistoryCap = 10

	// seedAdminDeviceName — зарезервированное имя сессии маски
	// администратора (имперсонация). Пишется только сервером; обычные
	// входы не могут использовать имена из зарезервированного
	// пространства (префикс "@", см. isReservedDeviceName). UI должен
	// отображать это имя особой меткой (цвет/название), а не текстом.
	seedAdminDeviceName = "@administrator"

	// seedSuperuserSessionDevice — зарезервированное имя сессии
	// суперюзера (вход панели или REST). Как и маска, имя из
	// пространства «@...» обычным входам недоступно.
	seedSuperuserSessionDevice = "@superuser"
)

// Роли пользователей сайта (колонка `role` коллекции `users`):
//   - user — видит и меняет только своё;
//   - moderator — читает всех пользователей (только просмотр);
//   - admin — модератор + действия модерации: бан, восстановление и
//     жёсткое удаление записей, политики, маска администратора.
//
// Суперюзер ролей не имеет: он выше любых правил и проверяется
// отдельно (см. seedAdmin).
const (
	seedRoleUser      = "user"
	seedRoleModerator = "moderator"
	seedRoleAdmin     = "admin"
)

// seedAdmin сообщает, есть ли у записи права администратора сайта:
// суперюзер либо пользователь с ролью `admin`.
//
// Параметры:
//   - a: *core.Record — авторизованная запись (может быть nil).
//
// Возвращает: bool — разрешены ли админские действия.
func seedAdmin(a *core.Record) bool {
	if a == nil {
		return false
	}
	if a.IsSuperuser() {
		return true
	}
	return strings.EqualFold(asStr(a.Get("role")), seedRoleAdmin)
}

var (
	// rxHex64 — формат открытого ключа: 64 шестнадцатеричных символа.
	rxHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// rxHex128 — формат подписи: 128 шестнадцатеричных символов.
	rxHex128 = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// ---------------------------------------------------------------- помощники

// nowISO возвращает текущее время в UTC в формате RFC3339Nano.
//
// Возвращает: string — строка времени, напр. "2026-09-17T12:00:00.000Z".
func nowISO() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// seedDomain возвращает домен-привязку подписи (защита от подмены между
// экземплярами: подпись, созданная для одного домена, не пройдёт на
// другом). Задаётся переменной окружения.
//
// Возвращает: string — значение SEED_DOMAIN или "seed.local" по умолчанию.
func seedDomain() string {
	if d := strings.TrimSpace(os.Getenv("SEED_DOMAIN")); d != "" {
		return d
	}
	return "seed.local"
}

// seedAccessTTLValue возвращает реальный срок жизни токена доступа —
// длительность из настроек коллекции users, а при недоступности
// справочное значение 900.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: int — срок жизни токена в секундах.
func seedAccessTTLValue(app core.App) int {
	if users, err := app.FindCollectionByNameOrId("users"); err == nil && users != nil {
		if d := users.AuthToken.Duration; d > 0 {
			return int(d)
		}
	}
	return seedAccessTTL
}

// isoExpired сообщает, истёк ли срок в строке времени.
//
// Параметры:
//   - raw: any — строка времени (пустая или нераспознаваемая = истёк).
//
// Возвращает: bool — true, если срок прошёл или значение негодное.
func isoExpired(raw any) bool {
	s, _ := raw.(string)
	if s == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, s); err != nil {
			return true
		}
	}
	return !t.After(time.Now())
}

// asStr приводит значение к строке.
//
// Параметры:
//   - v: any — значение из Record.Get (строка, дата, булево и т.п.).
//
// Возвращает: string — текстовое представление; пустая строка для nil,
// неподдерживаемых типов и нулевых дат. Понимает types.DateTime —
// тип, который PocketBase возвращает для полей-дат.
func asStr(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	// Record.Get для DateField/AutodateField отдаёт types.DateTime,
	// а не строку — сериализуем его в канонический вид.
	if dt, ok := v.(types.DateTime); ok {
		if dt.IsZero() {
			return ""
		}
		return dt.String()
	}
	return ""
}

// asBool приводит значение к булеву.
//
// Параметры:
//   - v: any — значение из Record.Get.
//
// Возвращает: bool — значение; для не-булевых типов — false.
func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// truncRunes обрезает строку до заданного числа символов (по рунам,
// а не байтам — многосимвольные буквы не режутся пополам).
//
// Параметры:
//   - s: string — исходная строка;
//   - n: int — максимальная длина в рунах.
//
// Возвращает: string — строку не длиннее n рун.
func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// isReservedDeviceName сообщает, попадает ли имя устройства в
// зарезервированное пространство (начинается с "@"). Такие имена
// использует только сервер (маска администратора); обычные входы с ними
// отклоняются, чтобы никто не выдал свою сессию за служебную.
//
// Параметры:
//   - s: string — имя устройства из запроса.
//
// Возвращает: bool — истинно для имён вида "@..." (пробелы в начале
// игнорируются).
func isReservedDeviceName(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "@")
}

// maskIP маскирует IP-адрес для отображения.
//
// Параметры:
//   - ip: string — исходный адрес.
//
// Возвращает: string — маску: "85.76.130.44" -> "85.76.*.*",
// для IPv6 — первые 3 группы + "::*"; пустой вход -> пустой выход.
func maskIP(ip string) string {
	if ip == "" {
		return ""
	}
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		if len(parts) < 3 {
			return ip + "::*"
		}
		return strings.Join(parts[:3], ":") + "::*"
	}
	o := strings.Split(ip, ".")
	if len(o) == 4 {
		return o[0] + "." + o[1] + ".*.*"
	}
	return "*.*.*.*"
}

// geoCountry определена в geo.go (поиск страны по локальной геобазе;
// "" пока база не загружена).

// cookieVal читает значение куки из запроса.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса;
//   - name: string — имя куки.
//
// Возвращает: string — значение куки или "" если куки нет.
func cookieVal(e *core.RequestEvent, name string) string {
	c, err := e.Request.Cookie(name)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}

// seedCookieSecure сообщает, ставить ли куке флаг Secure.
// Включено по умолчанию (прод работает по HTTPS); локальная разработка
// по чистому HTTP отключается переменной окружения (на программных
// клиентов, вроде тестов, флаг не влияет).
//
// Возвращает: bool — ложь только при PB_COOKIE_INSECURE=1.
func seedCookieSecure() bool { return os.Getenv("PB_COOKIE_INSECURE") != "1" }

// setSeedCookie устанавливает куку сессии (только для чтения скриптами,
// режим SameSite=Lax).
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса;
//   - value: string — значение куки ("грант.секрет");
//   - maxAge: int — время жизни в секундах (отрицательное — удалить).
func setSeedCookie(e *core.RequestEvent, value string, maxAge int) {
	e.SetCookie(&http.Cookie{
		Name:     seedCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   seedCookieSecure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// clearSeedCookie удаляет куку сессии.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
func clearSeedCookie(e *core.RequestEvent) {
	setSeedCookie(e, "", -1)
}

// seedErr формирует стандартный ответ-ошибку.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса;
//   - status: int — код состояния HTTP;
//   - code: string — машинный код ошибки.
//
// Возвращает: error — ответ вида {\"error\": \"код\"} с указанным статусом.
// errSeedResponded — маркер «ответ уже записан, цепочку остановить».
// Обработчики и хуки обязаны возвращать НЕ-nil после отказа: иначе
// вызывающий код решит, что всё в порядке, и продолжит работу поверх
// уже отправленного 401/403 (утечка тела и исполнение запрещённого
// действия). Сам ответ к этому моменту уже записан, поэтому ошибка
// ничего не дописывает — она только рвёт цепочку.
var errSeedResponded = errors.New("seed: response written")

func seedErr(e *core.RequestEvent, status int, code string) error {
	_ = e.JSON(status, map[string]any{"error": code})
	return errSeedResponded
}

// --- баны ----------------------------------------------------------------
// Модель оригинала: бан с причиной и сроком ("" = бессрочно), срок
// истекает лениво при проверке — планировщик не нужен.

// userBanned сообщает, забанен ли пользователь прямо сейчас.
//
// Параметры:
//   - user: *core.Record — запись пользователя.
//
// Возвращает: bool — забанен ли. Пустой срок бана = бессрочно; мусор в
// сроке трактуется как бан (закрытая модель отказов).
func userBanned(user *core.Record) bool {
	if user == nil || !asBool(user.Get("banned")) {
		return false
	}
	until := asStr(user.Get("banned_until"))
	if until == "" {
		return true // пустой срок = бессрочно
	}
	// Мусор в сроке бана сохраняет бан (строгий подход).
	t, err := time.Parse(time.RFC3339Nano, until)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, until); err != nil {
			return true
		}
	}
	return t.After(time.Now())
}

// userBannedFrom проверяет бан по сырым значениям — путь продления не
// тратится на чтение всей записи пользователя.
//
// Параметры:
//   - banned: bool — флаг бана;
//   - banReason: string — причина (используется вызывающим для ответа);
//   - bannedUntil: string — срок бана ("" = бессрочно).
//
// Возвращает: bool — действует ли бан на текущий момент.
func userBannedFrom(banned bool, banReason, bannedUntil string) bool {
	if !banned {
		return false
	}
	if bannedUntil == "" {
		return true // пустой срок = бессрочно
	}
	// Мусор в сроке бана сохраняет бан (строгий подход).
	t, err := time.Parse(time.RFC3339Nano, bannedUntil)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, bannedUntil); err != nil {
			return true
		}
	}
	return t.After(time.Now())
}

// banErr формирует ответ «забанен» (403) с причиной, если она задана.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса;
//   - user: *core.Record — запись пользователя.
//
// Возвращает: error — ответ {\"error\": \"banned\", \"reason\"?: string}.
func banErr(e *core.RequestEvent, user *core.Record) error {
	out := map[string]any{"error": "banned"}
	if r := asStr(user.Get("ban_reason")); r != "" {
		out["reason"] = r
	}
	if u := asStr(user.Get("banned_until")); u != "" {
		out["until"] = u
	}
	_ = e.JSON(403, out)
	return errSeedResponded // остановить цепочку (см. errSeedResponded)
}

// --- история сессии ------------------------------------------------------
// Модель оригинала: история смен адреса — только дописывание, не более
// 10 записей (хранятся самые свежие). Порт дополнительно пишет старую
// страну (по спецификации).

// getHistory читает историю сессии из любого представления, в котором
// PocketBase может отдать JSON-поле.
//
// Параметры:
//   - sess: *core.Record — запись сессии.
//
// Возвращает: []any — список событий истории (пустой список, если
// истории нет или значение не распознано).
func getHistory(sess *core.Record) []any {
	switch v := sess.Get("history").(type) {
	case []any:
		if v != nil {
			return v
		}
	case types.JSONRaw: // то, что фактически возвращает PB для JSON-полей
		var out []any
		if len(v) > 0 {
			_ = json.Unmarshal(v, &out)
		}
		if out != nil {
			return out
		}
	case string:
		var out []any
		if v != "" {
			_ = json.Unmarshal([]byte(v), &out)
		}
		if out != nil {
			return out
		}
	case []byte:
		var out []any
		if len(v) > 0 {
			_ = json.Unmarshal(v, &out)
		}
		if out != nil {
			return out
		}
	}
	return []any{}
}

// pushHistory дописывает событие в историю сессии, обрезая её до лимита
// (остаются самые свежие записи).
//
// Параметры:
//   - sess: *core.Record — запись сессии;
//   - entry: map[string]any — событие, напр. {event, prev_masked, prev_country, at}.
func pushHistory(sess *core.Record, entry map[string]any) {
	h := append(getHistory(sess), entry)
	if len(h) > seedHistoryCap {
		h = h[len(h)-seedHistoryCap:]
	}
	sess.Set("history", h)
}

// --- IP сессии -----------------------------------------------------------

// Ключ для хэшей адресов. Без ключа используется устаревший простой
// SHA256 (подбор по утечке строки возможен, ведь грант лежит в той же
// строке и куке) с предупреждением при старте; с ключом — HMAC и ленивая
// миграция старых хэшей без массового разлогина.

// seedIPKey возвращает ключ HMAC для хэшей адресов из переменной окружения.
//
// Возвращает: []byte — ключ; пустой срез, если переменная не задана.
func seedIPKey() []byte {
	if k := strings.TrimSpace(os.Getenv("SEED_IP_KEY")); k != "" {
		return []byte(k)
	}
	return nil
}

// seedIPHash считает хэш адреса для хранения в сессии (сырой адрес
// никогда не сохраняется).
//
// Параметры:
//   - ip: string — клиентский адрес;
//   - grant: string — идентификатор гранта (соль, уникален на сессию);
//   - key: []byte — ключ HMAC (пустой = устаревший простой хэш).
//
// Возвращает: string — "h1:<шестнадцатеричный HMAC>" либо устаревший
// хэш без префикса.
func seedIPHash(ip, grant string, key []byte) string {
	if len(key) > 0 {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(ip + "|" + grant))
		return "h1:" + hex.EncodeToString(m.Sum(nil))
	}
	return security.SHA256(ip + "|" + grant)
}

// seedIPMatch сверяет адрес с сохранённым хэшем. Во время миграции
// проверяются оба варианта: сначала HMAC, затем устаревший хэш
// (префикс "h1:" однозначен: "h" не является шестнадцатеричной цифрой).
//
// Параметры:
//   - stored: string — сохранённый хэш;
//   - ip: string — текущий адрес;
//   - grant: string — идентификатор гранта;
//   - key: []byte — ключ HMAC.
//
// Возвращает: bool — совпадает ли адрес (сравнение без утечки времени).
func seedIPMatch(stored, ip, grant string, key []byte) bool {
	if len(key) > 0 && security.Equal(stored, seedIPHash(ip, grant, key)) {
		return true
	}
	return security.Equal(stored, security.SHA256(ip+"|"+grant))
}

// adoptIP записывает текущий адрес соединения в сессию: хэш, маску и
// страну. Сырой адрес не сохраняется.
//
// Параметры:
//   - sess: *core.Record — запись сессии;
//   - grant: string — идентификатор гранта;
//   - ip: string — текущий адрес.
func adoptIP(sess *core.Record, grant, ip string) {
	sess.Set("ip_hash", seedIPHash(ip, grant, seedIPKey()))
	sess.Set("ip_masked", maskIP(ip))
	sess.Set("ip_country", geoCountry(ip))
}

// --- политики (поведение при смене IP) ------------------------------------
// Модель настроек: таблица строк {ключ, значение, пользователь?, замок}.
// Порядок разрешения: персональная строка -> глобальная строка -> ложь.
// Заблокированная глобальная строка запрещает пользователям СОЗДАВАТЬ
// персональные переопределения; суперюзер не ограничен. Любая ошибка
// разрешения даёт ложь (открытая модель отказов, как в оригинале).

// seedPolicyKick — ключ политики «выгонять при смене IP».
const seedPolicyKick = "kick_on_ip_change"

// findSetting находит одну строку настроек по точной паре (ключ,
// пользователь). Персональная и глобальная строки ищутся отдельными
// запросами со связанными параметрами, поэтому множество персональных
// строк с одним ключом не может заслонить глобальную.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - key: string — ключ настройки;
//   - userId: string — id пользователя ("" = глобальная строка).
//
// Возвращает: *core.Record — найденную строку или nil.
func findSetting(app core.App, key, userId string) *core.Record {
	if userId == "" {
		r, _ := app.FindFirstRecordByFilter("seed_settings", "key = {:key} && user = null", dbx.Params{"key": key})
		return r
	}
	r, _ := app.FindFirstRecordByFilter("seed_settings", "key = {:key} && user = {:user}", dbx.Params{"key": key, "user": userId})
	return r
}

// seedPolicy разрешает действующее значение политики для пользователя.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - userId: string — id пользователя;
//   - key: string — ключ политики.
//
// Возвращает:
//   - bool — значение;
//   - string — источник: "me" (персональная строка), "global"
//     (глобальная) или "default" (ничего не задано, значение ложь).
func seedPolicy(app core.App, userId, key string) (bool, string) {
	if userId != "" {
		if r := findSetting(app, key, userId); r != nil {
			return asBool(r.Get("value")), "me"
		}
	}
	if r := findSetting(app, key, ""); r != nil {
		return asBool(r.Get("value")), "global"
	}
	return false, "default"
}

// rxPolicyKey — допустимые символы ключа настройки (1–64 символа).
var rxPolicyKey = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// seedPolicyGet — GET /api/seed/policy?key=<ключ>&scope=<me|global>.
// Чтение действующей политики. Область по умолчанию: у пользователя —
// "me", у гостя и администратора (суперюзер или роль "admin") — "global".
//
// Ответ 200: {key: string, value: bool, source: "me"|"global"|"default"}
// Ошибки: 400 (неверный ключ или область).
func seedPolicyGet(e *core.RequestEvent) error {
	key := strings.TrimSpace(e.Request.URL.Query().Get("key"))
	if key == "" {
		key = seedPolicyKick
	}
	if !rxPolicyKey.MatchString(key) {
		return seedErr(e, 400, "bad_key")
	}
	scope := strings.ToLower(strings.TrimSpace(e.Request.URL.Query().Get("scope")))
	a := e.Auth
	if a == nil || seedAdmin(a) {
		if scope == "" {
			scope = "global"
		}
		if scope != "global" {
			return seedErr(e, 400, "bad_scope")
		}
		v, src := seedPolicy(e.App, "", key)
		return e.JSON(200, map[string]any{"key": key, "value": v, "source": src})
	}
	if scope == "" {
		scope = "me"
	}
	if scope != "me" && scope != "global" {
		return seedErr(e, 400, "bad_scope")
	}
	uid := ""
	if scope == "me" {
		uid = a.Id
	}
	v, src := seedPolicy(e.App, uid, key)
	return e.JSON(200, map[string]any{"key": key, "value": v, "source": src})
}

// seedPolicySet — POST /api/seed/policy.
// Запись политики. Тело: {key?: string, value: bool, scope?: "me"|"global",
// locked?: bool}. Область "me" (по умолчанию у пользователя) обновляет
// персональную строку; при заблокированной глобальной строке СОЗДАНИЕ
// новой персональной запрещено (403 "locked"), редактирование своей
// существующей — разрешено. Область "global" доступна только администратору (суперюзер или роль "admin").
//
// Ответ 200: {key: string, value: bool, scope: "me"|"global"}
// Ошибки: 400 (ключ вне списка записываемых, неверное значение/область),
// 401 (нет токена), 403 (чужая область / заблокировано).
func seedPolicySet(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	var b struct {
		Key    string `json:"key"`
		Value  *bool  `json:"value"`
		Scope  string `json:"scope"`
		Locked *bool  `json:"locked"`
	}
	_ = e.BindBody(&b)
	key := strings.TrimSpace(b.Key)
	if key == "" {
		key = seedPolicyKick
	}
	if !rxPolicyKey.MatchString(key) {
		return seedErr(e, 400, "bad_key")
	}
	// На запись открыт только известный ключ (мусорные ключи не нужны:
	// продление читает ровно один ключ). Чтение остаётся открытым для
	// старых строк.
	if key != seedPolicyKick {
		return seedErr(e, 400, "bad_key")
	}
	if b.Value == nil {
		return seedErr(e, 400, "bad_value")
	}
	scope := strings.ToLower(strings.TrimSpace(b.Scope))
	isSU := seedAdmin(e.Auth)
	if scope == "" {
		if isSU {
			scope = "global"
		} else {
			scope = "me"
		}
	}
	if scope != "me" && scope != "global" {
		return seedErr(e, 400, "bad_scope")
	}
	if scope == "global" && !isSU {
		return seedErr(e, 403, "forbidden")
	}
	if scope == "me" && isSU {
		// Суперюзеру личная область недоступна (его ид нет в users);
		// админ по роли — обычный пользователь, ему переопределение можно.
		if e.Auth.IsSuperuser() {
			return seedErr(e, 400, "bad_scope")
		}
	}

	uid := ""
	if scope == "me" {
		uid = e.Auth.Id
	}
	if r := findSetting(e.App, key, uid); r != nil {
		// Обновление своей строки разрешено и под заблокированной
		// глобальной — замок охраняет СОЗДАНИЕ, а не правку значения.
		r.Set("value", *b.Value)
		if scope == "global" && b.Locked != nil {
			r.Set("locked", *b.Locked)
		}
		if scope == "me" {
			r.Set("locked", false)
		}
		if err := e.App.Save(r); err != nil {
			return seedErr(e, 500, "store_failed")
		}
		auditLog(e, "policy.set", map[string]any{"key": key, "value": *b.Value, "scope": scope})
		return e.JSON(200, map[string]any{"key": key, "value": *b.Value, "scope": scope})
	}
	// Путь создания: заблокированная глобальная строка запрещает НОВЫЕ
	// персональные переопределения.
	if scope == "me" {
		if g := findSetting(e.App, key, ""); g != nil && asBool(g.Get("locked")) {
			return seedErr(e, 403, "locked")
		}
	}
	col, err := e.App.FindCollectionByNameOrId("seed_settings")
	if err != nil {
		return seedErr(e, 500, "no_store")
	}
	rec := core.NewRecord(col)
	rec.Set("key", key)
	rec.Set("value", *b.Value)
	if uid != "" {
		rec.Set("user", uid)
		rec.Set("locked", false)
	} else if b.Locked != nil {
		rec.Set("locked", *b.Locked)
	}
	if err := e.App.Save(rec); err != nil {
		// Проиграли гонку создания: перечитываем и обновляем.
		if r := findSetting(e.App, key, uid); r != nil {
			r.Set("value", *b.Value)
			if scope == "global" && b.Locked != nil {
				r.Set("locked", *b.Locked)
			}
			if err2 := e.App.Save(r); err2 == nil {
				auditLog(e, "policy.set", map[string]any{"key": key, "value": *b.Value, "scope": scope})
				return e.JSON(200, map[string]any{"key": key, "value": *b.Value, "scope": scope})
			}
		}
		return seedErr(e, 500, "store_failed")
	}
	auditLog(e, "policy.set", map[string]any{"key": key, "value": *b.Value, "scope": scope})
	return e.JSON(200, map[string]any{"key": key, "value": *b.Value, "scope": scope})
}

// seedPolicyDelete — DELETE /api/seed/policy?key=<ключ>&scope=<me|global>.
// Удаляет персональное переопределение (пользователь возвращается к
// глобальному значению) либо глобальную строку. Удаление разрешено
// всегда — откат возможен только к значению по умолчанию.
//
// Ответ 200: {ok: true, deleted: 0|1}
// Ошибки: 400 (неверный ключ/область), 401 (нет токена),
// 403 (глобальная область без прав администратора).
func seedPolicyDelete(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	key := strings.TrimSpace(e.Request.URL.Query().Get("key"))
	if key == "" {
		key = seedPolicyKick
	}
	if !rxPolicyKey.MatchString(key) {
		return seedErr(e, 400, "bad_key")
	}
	scope := strings.ToLower(strings.TrimSpace(e.Request.URL.Query().Get("scope")))
	isSU := seedAdmin(e.Auth)
	if scope == "" {
		if isSU {
			scope = "global"
		} else {
			scope = "me"
		}
	}
	if scope != "me" && scope != "global" {
		return seedErr(e, 400, "bad_scope")
	}
	if scope == "global" && !isSU {
		return seedErr(e, 403, "forbidden")
	}
	if scope == "me" && isSU {
		// Суперюзеру личная область недоступна (его ид нет в users);
		// админ по роли — обычный пользователь, ему переопределение можно.
		if e.Auth.IsSuperuser() {
			return seedErr(e, 400, "bad_scope")
		}
	}
	uid := ""
	if scope == "me" {
		uid = e.Auth.Id
	}
	r := findSetting(e.App, key, uid)
	if r == nil {
		return e.JSON(200, map[string]any{"ok": true, "deleted": 0})
	}
	if err := e.App.Delete(r); err != nil {
		return seedErr(e, 500, "store_failed")
	}
	auditLog(e, "policy.delete", map[string]any{"key": key, "scope": scope})
	return e.JSON(200, map[string]any{"ok": true, "deleted": 1})
}

// ---------------------------------------------------------------- маршруты

// auditKeepDaysMin — нижняя граница хранения журнала: аудит короче
// недели смысла не имеет, поэтому значения меньше округляются вверх.
const auditKeepDaysMin = 7

// auditKeepDays возвращает действующий срок хранения журнала действий
// в днях по переменной окружения `SEED_AUDIT_KEEP_DAYS`. Пусто, ноль и
// отрицательные значения означают «вечно» (0). Положительные значения
// не могут быть меньше недели.
//
// Возвращает: int — срок хранения в днях; 0 = хранить вечно.
func auditKeepDays() int {
	raw := strings.TrimSpace(os.Getenv("SEED_AUDIT_KEEP_DAYS"))
	if raw == "" {
		return 0
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days <= 0 {
		return 0 // мусор/«0» трактуем как «вечно»
	}
	if days < auditKeepDaysMin {
		days = auditKeepDaysMin
	}
	return days
}

// seedGC удаляет просроченные строки служебных таблиц: челленджи живут
// 5 минут, надгробия использованных нонсов — 24 часа; без чистки обе
// таблицы росли бы по строке на каждую попытку входа. Также удаляются
// истёкшие сессии (отобранные, но не истёкшие, остаются до истечения)
// и запускается сборщик мягко удалённых записей. Работает по фоновому
// таймеру, вне горячего пути запросов.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func seedGC(app core.App) {
	cutoff := time.Now().UTC().Format(time.RFC3339Nano)
	for _, col := range []string{"seed_challenges", "seed_used"} {
		_, _ = app.NonconcurrentDB().NewQuery(
			"DELETE FROM " + col + " WHERE expires IS NULL OR expires < {:cutoff}",
		).Bind(dbx.Params{"cutoff": cutoff}).Execute()
	}
	// Истёкшие сессии удаляются целиком; мягко удалённые пропускаются —
	// у них свой сборщик в мягком удалении.
	_, _ = app.NonconcurrentDB().NewQuery(
		"DELETE FROM seed_sessions WHERE (deleted_at IS NULL OR deleted_at = '') AND expires IS NOT NULL AND expires < {:cutoff}",
	).Bind(dbx.Params{"cutoff": cutoff}).Execute()
	// Журнал действий: срок хранения задаётся переменной окружения в
	// днях, но не меньше недели (пусто/0/мусор = вечно).
	if days := auditKeepDays(); days > 0 {
		keepCutoff := time.Now().AddDate(0, 0, -days).UTC().Format("2006-01-02 15:04:05.000Z")
		_, _ = app.NonconcurrentDB().NewQuery(
			"DELETE FROM seed_audit WHERE created_at < {:cutoff}",
		).Bind(dbx.Params{"cutoff": keepCutoff}).Execute()
	}
	// Физическая очистка записей, мягко удалённых более 30 дней назад.
	softDeleteGC(app)
}

// startSeedGC запускает сборщик мусора: одна чистка при старте, далее по
// таймеру из переменной окружения (по умолчанию 5 минут).
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func startSeedGC(app core.App) {
	every := seedGCEvery()
	log.Printf("[seed] gc started (every %s)", every.String())
	seedGC(app)
	t := time.NewTicker(every)
	go func() {
		defer t.Stop()
		for range t.C {
			seedGC(app)
		}
	}()
}

// seedChallenge — POST /api/seed/challenge. Выдаёт одноразовый челлендж
// (нонс) для подписи входа/регистрации. Доступен всем.
//
// Тело запроса: {public_key: string (hex, 64 символа),
// purpose: "login"|"register"}
// Ответ 200: {nonce: string (32 символа), expires_in: int (300)}
// Ошибки: 400 (неверный ключ или назначение).
func seedChallenge(e *core.RequestEvent) error {
	var b struct {
		PublicKey string `json:"public_key"`
		Purpose   string `json:"purpose"`
	}
	_ = e.BindBody(&b) // при ошибке разбора — нулевая структура

	pk := strings.ToLower(b.PublicKey)
	if !rxHex64.MatchString(pk) {
		return seedErr(e, 400, "bad_public_key")
	}
	if b.Purpose != "login" && b.Purpose != "register" {
		return seedErr(e, 400, "bad_purpose")
	}

	col, err := e.App.FindCollectionByNameOrId("seed_challenges")
	if err != nil {
		return seedErr(e, 500, "no_store")
	}
	rec := core.NewRecord(col)
	rec.Set("public_key", pk)
	rec.Set("nonce", security.RandomString(32))
	rec.Set("purpose", b.Purpose)
	rec.Set("used", false)
	rec.Set("expires", time.Now().Add(seedChallengeTTL).UTC().Format(time.RFC3339Nano))
	if err := e.App.Save(rec); err != nil {
		return seedErr(e, 500, "store_failed")
	}
	return e.JSON(200, map[string]any{"nonce": rec.Get("nonce"), "expires_in": int(seedChallengeTTL.Seconds())})
}

// seedLogin — POST /api/seed/login. Проверяет подпись над челленджем и
// выдаёт токен доступа + куку сессии. Регистрация создаёт пользователя,
// вход проверяет бан. Подписываемое сообщение:
// "surreal-auth-v1:<домен>:<назначение>:<открытый ключ>:<нонс>".
//
// Тело запроса: {public_key: string, signature: string (hex, 128),
// purpose: "login"|"register", nonce: string, device_name?: string}
// Ответ 200: {access: string, session_id: string, user_id: string,
// expires_in: int} + кука сессии.
// Ошибки: 400 (формат ключа/подписи, нет челленджа, плохая подпись,
// уже зарегистрирован), 403 (забанен), 404 (нет пользователя),
// 500 (ошибки хранилища/токена).
func seedLogin(e *core.RequestEvent) error {
	var b struct {
		PublicKey  string `json:"public_key"`
		Signature  string `json:"signature"`
		Purpose    string `json:"purpose"`
		Nonce      string `json:"nonce"`
		DeviceName string `json:"device_name"`
	}
	_ = e.BindBody(&b)

	pk := strings.ToLower(b.PublicKey)
	sig := strings.ToLower(b.Signature)
	if !rxHex64.MatchString(pk) {
		return seedErr(e, 400, "bad_public_key")
	}
	if !rxHex128.MatchString(sig) {
		return seedErr(e, 400, "bad_signature")
	}
	if b.Purpose != "login" && b.Purpose != "register" {
		return seedErr(e, 400, "bad_purpose")
	}
	// Зарезервированное пространство имён ("@...") принадлежит серверу
	// (маска администратора) — обычный вход с таким именем отклоняется.
	if isReservedDeviceName(b.DeviceName) {
		auditLogAs(e, nil, "auth.login_failed", map[string]any{
			"public_key": pk, "purpose": b.Purpose, "reason": "reserved_device_name",
			"ip_hash": fwIPHash(e.RealIP()),
		})
		return seedErr(e, 400, "reserved_device_name")
	}

	// Защита гейтвея: выключатели и лимиты. Отказы пишутся в журнал —
	// наблюдение защита не ослабляет.
	if b.Purpose == "register" {
		if err := gwGateRegister(e, pk); err != nil {
			return err
		}
	} else {
		if err := gwGateLogin(e, pk); err != nil {
			return err
		}
	}

	ch, err := e.App.FindFirstRecordByData("seed_challenges", "nonce", b.Nonce)
	if err != nil || ch == nil ||
		asStr(ch.Get("public_key")) != pk ||
		asStr(ch.Get("purpose")) != b.Purpose {
		return seedErr(e, 400, "no_challenge")
	}
	if asBool(ch.Get("used")) || isoExpired(ch.Get("expires")) {
		return seedErr(e, 400, "no_challenge")
	}

	// Атомарная одноразовость: уникальный индекс по нонсу не даёт
	// использовать его дважды. Нонс сжигается ДО проверки подписи
	// (неверная подпись тоже убивает нонс).
	usedCol, err := e.App.FindCollectionByNameOrId("seed_used")
	if err != nil {
		return seedErr(e, 500, "no_store")
	}
	used := core.NewRecord(usedCol)
	used.Set("nonce", b.Nonce)
	used.Set("expires", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339Nano))
	ch.Set("used", true)
	// Одна транзакция: надгробие нонса + отметка челленджа.
	if err := e.App.RunInTransaction(func(txApp core.App) error {
		if err := txApp.Save(used); err != nil {
			return err
		}
		return txApp.Save(ch)
	}); err != nil {
		return seedErr(e, 400, "no_challenge")
	}

	msg := seedMsgPrefix + seedDomain() + ":" + b.Purpose + ":" + pk + ":" + b.Nonce
	pub, err1 := hex.DecodeString(pk)
	sg, err2 := hex.DecodeString(sig)
	if err1 != nil || err2 != nil || !ed25519.Verify(pub, []byte(msg), sg) {
		auditLogAs(e, nil, "auth.login_failed", map[string]any{
			"public_key": pk, "purpose": b.Purpose, "reason": "bad_signature",
			"ip_hash": fwIPHash(e.RealIP()),
		})
		return seedErr(e, 400, "bad_signature")
	}

	email := pk + "@seed.local"
	user, err := e.App.FindFirstRecordByData("users", "email", email)
	if b.Purpose == "register" {
		if err == nil && user != nil {
			auditLogAs(e, nil, "auth.login_failed", map[string]any{
				"public_key": pk, "purpose": b.Purpose, "reason": "already_registered",
				"ip_hash": fwIPHash(e.RealIP()),
			})
			return seedErr(e, 400, "already_registered")
		}
		ucol, err := e.App.FindCollectionByNameOrId("users")
		if err != nil {
			return seedErr(e, 500, "no_store")
		}
		user = core.NewRecord(ucol)
		user.Set("email", email)
		user.Set("password", security.RandomString(48))
		user.Set("emailVisibility", false)
		user.Set("role", seedRoleUser) // регистрация всегда даёт роль "user"
		if err := e.App.Save(user); err != nil {
			// Гонка одновременных регистраций: проигравший упирается в
			// уникальный индекс почты — проверяем повторным чтением.
			if _, err2 := e.App.FindFirstRecordByData("users", "email", email); err2 == nil {
				auditLogAs(e, nil, "auth.login_failed", map[string]any{
					"public_key": pk, "purpose": b.Purpose, "reason": "already_registered",
					"ip_hash": fwIPHash(e.RealIP()),
				})
				return seedErr(e, 400, "already_registered")
			}
			return seedErr(e, 500, "store_failed")
		}
	} else {
		if err != nil || user == nil {
			auditLogAs(e, nil, "auth.login_failed", map[string]any{
				"public_key": pk, "purpose": b.Purpose, "reason": "no_user",
				"ip_hash": fwIPHash(e.RealIP()),
			})
			return seedErr(e, 404, "no_user")
		}
		if userBanned(user) {
			auditLogAs(e, nil, "auth.login_failed", map[string]any{
				"public_key": pk, "purpose": b.Purpose, "reason": "banned",
				"ip_hash": fwIPHash(e.RealIP()),
			})
			return banErr(e, user)
		}
	}

	// Токен выпускается ДО создания сессии: сбой выпуска не должен
	// оставлять сиротливую сессию (и куку).
	access, err := user.NewAuthToken()
	if err != nil {
		return seedErr(e, 500, "token_failed")
	}

	grant, secret, err := openSeedSession(e, user, b.DeviceName)
	if err != nil {
		return err
	}

	setSeedCookie(e, grant+"."+secret, seedSessionDays*86400)

	// Журнал: успешный вход/регистрация — кто, с какого устройства и
	// адреса (сырой адрес не пишется, только маска и страна).
	action := "auth.login"
	if b.Purpose == "register" {
		action = "auth.register"
	}
	ip := e.RealIP()
	auditLogAs(e, user, action, map[string]any{
		"device":    truncRunes(b.DeviceName, 200),
		"ip_masked": maskIP(ip),
		"ip_hash":   fwIPHash(ip),
		"country":   geoCountry(ip),
	})

	return e.JSON(200, map[string]any{
		"access":     access,
		"session_id": grant,
		"user_id":    user.Id,
		"expires_in": seedAccessTTLValue(e.App),
	})
}

// openSeedSession создаёт и сохраняет новую сессию пользователя,
// возвращая грант и секрет для куки. Общий путь для обычного входа и
// маски администратора (имперсонации): одинаковая запись адреса,
// истории и сроков.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса (адрес сокета, хранилище);
//   - user: *core.Record — пользователь, которому открывается сессия;
//   - deviceName: string — имя устройства (серверные вызовы могут
//     передавать зарезервированное имя).
//
// Возвращает:
//   - string — грант (идентификатор сессии в куке);
//   - string — секрет (вторая половина куки);
//   - error — ответ-ошибка (уже обёрнут в seedErr).
func openSeedSession(e *core.RequestEvent, user *core.Record, deviceName string) (string, string, error) {
	ip := e.RealIP() // без доверенного прокси — адрес сокета
	grant := security.RandomString(24)
	secret := security.RandomString(32)

	scol, err := e.App.FindCollectionByNameOrId("seed_sessions")
	if err != nil {
		return "", "", seedErr(e, 500, "no_store")
	}
	sess := core.NewRecord(scol)
	sess.Set("user", user.Id)
	sess.Set("grant_id", grant)
	sess.Set("secret_hash", security.SHA256(secret))
	sess.Set("device_name", truncRunes(deviceName, 200))
	if ip != "" {
		adoptIP(sess, grant, ip)
	} else {
		sess.Set("ip_hash", "")
		sess.Set("ip_masked", "")
		sess.Set("ip_country", "")
	}
	sess.Set("history", []any{})
	sess.Set("revoked", false)
	sess.Set("last_seen", nowISO())
	sess.Set("expires", time.Now().AddDate(0, 0, seedSessionDays).UTC().Format(time.RFC3339Nano))
	if err := e.App.Save(sess); err != nil {
		return "", "", seedErr(e, 500, "store_failed")
	}
	return grant, secret, nil
}

// suTokenHash считает устойчивый маркер носимого токена суперюзера:
// у суперюзера нет грантов и кук, его «сессия» узнаётся по хэшу
// bearer-токена. Сам токен в базу не попадает.
//
// Параметры:
//   - token: string — bearer-токен (может быть пуст).
//
// Возвращает: string — SHA256-хэш токена (пусто для пустого токена).
func suTokenHash(token string) string {
	if token == "" {
		return ""
	}
	return security.SHA256(token)
}

// bearerToken достаёт токен из заголовка Authorization запроса.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: string — токен без префикса «Bearer » (пусто, если его нет).
func bearerToken(e *core.RequestEvent) string {
	h := strings.TrimSpace(e.Request.Header.Get("Authorization"))
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}

// suSessionExpires считает срок жизни сессии суперюзера по настройкам
// коллекции `_superusers` (столько же живёт и сам токен); запасной
// срок — 30 дней.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: string — срок в формате RFC3339Nano (UTC).
func suSessionExpires(app core.App) string {
	days := 30
	if col, err := app.FindCollectionByNameOrId("_superusers"); err == nil &&
		col.AuthToken.Duration > 0 {
		return time.Now().Add(time.Duration(col.AuthToken.Duration) * time.Second).
			UTC().Format(time.RFC3339Nano)
	}
	return time.Now().AddDate(0, 0, days).UTC().Format(time.RFC3339Nano)
}

// superuserSessionByToken ищет живую сессию суперюзера по маркеру токена.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - token: string — bearer-токен.
//
// Возвращает: *core.Record — сессия или nil.
func superuserSessionByToken(app core.App, token string) *core.Record {
	h := suTokenHash(token)
	if h == "" {
		return nil
	}
	sess, err := app.FindFirstRecordByData("seed_sessions", "token_hash", h)
	if err != nil {
		return nil
	}
	return sess
}

// suSessionAfterAuth привязывает сессию суперюзера к свежевыпущенному
// токену: при обновлении токена (refresh) существующая сессия
// продлевается и получает новый маркер, при чистом входе создаётся
// новая строка. Так у суперюзера — как и у всех — появляется сессия,
// и журнал может сослаться на неё.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса (адрес, старый токен);
//   - su: *core.Record — запись суперюзера;
//   - token: string — новый токен из ответа авторизации.
func suSessionAfterAuth(e *core.RequestEvent, su *core.Record, token string) {
	app := e.App
	newHash := suTokenHash(token)
	if newHash == "" {
		return
	}
	// Refresh: старый токен ещё в заголовке — продлеваем его сессию.
	if oldHash := suTokenHash(bearerToken(e)); oldHash != "" && oldHash != newHash {
		if sess, err := app.FindFirstRecordByData("seed_sessions", "token_hash", oldHash); err == nil && sess != nil {
			sess.Set("token_hash", newHash)
			sess.Set("expires", suSessionExpires(app))
			sess.Set("last_seen", nowISO())
			if err := app.Save(sess); err != nil {
				log.Printf("[seed] superuser session refresh failed: %v", err)
			}
			return
		}
	}
	// Идемпотентность: повторный вход в ту же секунду выпускает тот же
	// токен (одинаковые клейма времени) — сессия с его маркером уже есть.
	if sess, err := app.FindFirstRecordByData("seed_sessions", "token_hash", newHash); err == nil && sess != nil {
		sess.Set("expires", suSessionExpires(app))
		sess.Set("last_seen", nowISO())
		if err := app.Save(sess); err != nil {
			log.Printf("[seed] superuser session refresh failed: %v", err)
		}
		return
	}
	scol, err := app.FindCollectionByNameOrId("seed_sessions")
	if err != nil {
		return
	}
	grant := security.RandomString(40)
	sess := core.NewRecord(scol)
	sess.Set("superuser_id", su.Id)
	sess.Set("grant_id", grant)
	sess.Set("token_hash", newHash)
	sess.Set("device_name", seedSuperuserSessionDevice)
	adoptIP(sess, grant, e.RealIP())
	sess.Set("history", []any{})
	sess.Set("revoked", false)
	sess.Set("last_seen", nowISO())
	sess.Set("expires", suSessionExpires(app))
	if err := app.Save(sess); err != nil {
		log.Printf("[seed] superuser session create failed: %v", err)
		return
	}
	log.Printf("[seed] superuser session opened: %s (%s)", su.Email(), maskIP(e.RealIP()))
}

// installSuperuserSessions заводит суперюзеру настоящие сессии: строка
// в `seed_sessions` создаётся на каждый успешный вход (пароль,
// одноразовый код, OAuth2) и продлевается при обновлении токена.
// Панель и REST суперюзера идут через эти же события, поэтому покрытие
// полное.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func installSuperuserSessions(app core.App) {
	app.OnRecordAuthRequest("_superusers").BindFunc(func(e *core.RecordAuthRequestEvent) error {
		err := e.Next()
		if err == nil && e.Record != nil {
			suSessionAfterAuth(e.RequestEvent, e.Record, e.Token)
		}
		return err
	})
}

// seedImpersonate — POST /api/seed/impersonate. Маска администратора
// (модель B): маска — это ПОДПИСЬ, а не смена личности. Исполнитель
// (суперюзер или админ) продолжает действовать СВОИМ токеном и со СВОИМИ
// правами (суперюзер может всё, админ — админское), а маска лишь
// фиксирует, от чьего имени он работает: создаётся сессия исполнителя с
// зарезервированным именем "@administrator" и полем `on_behalf_of`
// (целевой юзер), а действие пишется в журнал `seed_audit`. Целевой
// пользователь при этом никак не затрагивается (у него не появляется
// ни токена, ни сессии).
//
// Снятие маски: тот же эндпоинт с пустым `user_id` — отзывает текущую
// маску-сессию и чистит куку (аналог выхода из маски).
//
// Доступно только суперюзеру/админу. Каждая маска записывается в журнал.
//
// Тело запроса: {user_id: string} (пустой = снять маску).
// Ответ 200 (надеть): {access: string, session_id: string,
// masked_as: string, expires_in: int, masked: true} + кука сессии.
// Ответ 200 (снять): {ok: true, unmasked: true}.
// Ошибки: 403 (нет прав), 404 (нет юзера), 500 (ошибки хранилища/токена).
func seedImpersonate(e *core.RequestEvent) error {
	if !seedAdmin(e.Auth) {
		return seedErr(e, 403, "forbidden")
	}
	var b struct {
		UserID string `json:"user_id"`
	}
	_ = e.BindBody(&b)
	uid := strings.TrimSpace(b.UserID)

	// Пустой user_id — снятие маски: отзываем маску-сессию (если она
	// текущая) и чистим куку. Идемпотентно.
	if uid == "" {
		if sess := currentSessionByCookie(e); sess != nil && asStr(sess.Get("on_behalf_of")) != "" &&
			(e.Auth.IsSuperuser() || asStr(sess.Get("user")) == e.Auth.Id) {
			sess.Set("revoked", true)
			_ = e.App.Save(sess)
			auditLog(e, "impersonate.stop", map[string]any{"target": asStr(sess.Get("on_behalf_of"))})
		}
		clearSeedCookie(e)
		return e.JSON(200, map[string]any{"ok": true, "unmasked": true})
	}

	target, err := e.App.FindRecordById("users", uid)
	if err != nil || target == nil {
		return seedErr(e, 404, "no_user")
	}
	wearer := e.Auth

	// Токен выпускается ДО создания сессии: сбой выпуска не должен
	// оставлять сиротливую сессию. Токен — исполнителя (модель B): права
	// остаются его собственными.
	access, err := wearer.NewAuthToken()
	if err != nil {
		return seedErr(e, 500, "token_failed")
	}
	// Сессия маски. Поле `user` — связь с users, поэтому владелец сессии
	// зависит от исполнителя: админ по роли — сам исполнитель (его сессия,
	// видна ему в списке устройств); суперюзер в users отсутствует, его
	// маска вешается на целевого юзера (суперюзер минует мидлвару сессий,
	// так что на правах это не сказывается).
	sessionOwner := wearer
	if wearer.IsSuperuser() {
		sessionOwner = target
	}
	grant, secret, err := openSeedSession(e, sessionOwner, seedAdminDeviceName)
	if err != nil {
		return err
	}
	// Помечаем сессию атрибуцией «от чьего имени» (модель B).
	if sess, serr := e.App.FindFirstRecordByData("seed_sessions", "grant_id", grant); serr == nil && sess != nil {
		sess.Set("on_behalf_of", target.Id)
		_ = e.App.Save(sess)
	}
	setSeedCookie(e, grant+"."+secret, seedSessionDays*86400)
	auditLog(e, "impersonate.start", map[string]any{"target": target.Id})
	log.Printf("[seed] mask on: actor=%s kind=%s on_behalf_of=%s (session %s)", wearer.Id, actorKind(wearer), target.Id, grant)
	return e.JSON(200, map[string]any{
		"access":     access,
		"session_id": grant,
		"masked_as":  target.Id,
		"expires_in": seedAccessTTLValue(e.App),
		"masked":     true,
	})
}

// renewBan — минимальный набор полей пользователя для проверки бана
// (путь продления не читает всю запись пользователя целиком).
type renewBan struct {
	Banned      bool   `db:"banned"`
	BanReason   string `db:"ban_reason"`
	BannedUntil string `db:"banned_until"`
}

// seedRenew — POST /api/seed/renew. Продление токена по куке сессии.
// Проверяет секрет куки, отзыв/истечение, бан пользователя и адрес
// соединения: смена адреса при включённой политике убивает сессию
// (401 "ip_changed"), иначе новые маска и страна пишутся в сессию, а
// старые уходят в историю. Семантика пометок времени: обычная
// активность обновляет только `last_seen` (`updated_at` не двигается);
// любое изменение данных сессии двигает `updated_at`.
//
// Заголовки: кука сессии. Тело не требуется.
// Ответ 200: {access: string, expires_in: int}
// Ошибки: 401 (нет/неверна кука, сессия отозвана, истекла или убита
// сменой адреса), 403 (забанен), 500 (ошибка выпуска токена).
func seedRenew(e *core.RequestEvent) error {
	raw := cookieVal(e, seedCookieName)
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return seedErr(e, 401, "no_session")
	}
	sess, err := e.App.FindFirstRecordByData("seed_sessions", "grant_id", parts[0])
	if err != nil || sess == nil {
		return seedErr(e, 401, "no_session")
	}
	if !security.Equal(asStr(sess.Get("secret_hash")), security.SHA256(parts[1])) {
		return seedErr(e, 401, "no_session")
	}
	// Выключатель продления сессий (защита гейтвея): отказ пишется в
	// журнал наравне с прочими неудачами продления.
	if !gwOn(e.App, gwPRenew) {
		auditLogAs(e, nil, "auth.renew_failed", map[string]any{
			"grant": parts[0], "user_id": asStr(sess.Get("user")), "reason": "renew_disabled",
		})
		return seedErr(e, 403, "renew_disabled")
	}
	if asBool(sess.Get("revoked")) || isoExpired(sess.Get("expires")) {
		auditLogAs(e, nil, "auth.renew_failed", map[string]any{
			"grant": parts[0], "user_id": asStr(sess.Get("user")), "reason": "revoked",
		})
		return seedErr(e, 401, "revoked")
	}
	userId := asStr(sess.Get("user"))
	// Лёгкая проверка бана: читаем 3 колонки вместо всей записи.
	var ban renewBan
	if err := e.App.DB().NewQuery(
		"SELECT banned, ban_reason, banned_until FROM users WHERE id = {:id}",
	).Bind(dbx.Params{"id": userId}).One(&ban); err != nil {
		auditLogAs(e, nil, "auth.renew_failed", map[string]any{
			"grant": parts[0], "user_id": userId, "reason": "no_user",
		})
		return seedErr(e, 401, "no_user")
	}
	if userBannedFrom(ban.Banned, ban.BanReason, ban.BannedUntil) {
		auditLogAs(e, nil, "auth.renew_failed", map[string]any{
			"grant": parts[0], "user_id": userId, "reason": "banned",
		})
		out := map[string]any{"error": "banned"}
		if ban.BanReason != "" {
			out["reason"] = ban.BanReason
		}
		_ = e.JSON(403, out)
		return errSeedResponded // остановить цепочку (см. errSeedResponded)
	}

	// --- проверка адреса (адрес сокета подделать нельзя; заголовки
	// вне доверенного прокси игнорируются) ---
	// Семантика `updated_at`: активность (`last_seen`) его НЕ трогает;
	// любое реальное изменение данных сессии (адрес, страна, хэш,
	// история, отзыв) — трогает. Поэтому накапливается dataChanged, а
	// «тихое» обновление `last_seen` идёт сырым UPDATE в обход автодат.
	dataChanged := false
	curIP := e.RealIP()
	if curIP != "" {
		stored := asStr(sess.Get("ip_hash"))
		switch {
		case stored == "":
			// Первая запись адреса — принятие, не смена (без истории и кика).
			adoptIP(sess, parts[0], curIP)
			dataChanged = true
		case !seedIPMatch(stored, curIP, parts[0], seedIPKey()):
			// Адрес изменился.
			if kick, _ := seedPolicy(e.App, userId, seedPolicyKick); kick {
				sess.Set("revoked", true)
				sess.Set("last_seen", nowISO())
				_ = e.App.Save(sess) // отзыв — изменение данных, `updated_at` двигается
				auditLogAs(e, nil, "auth.renew_failed", map[string]any{
					"grant": parts[0], "user_id": userId, "reason": "ip_changed",
				})
				return seedErr(e, 401, "ip_changed")
			}
			pushHistory(sess, map[string]any{
				"event":        "ip_changed",
				"prev_masked":  asStr(sess.Get("ip_masked")),
				"prev_country": asStr(sess.Get("ip_country")),
				"at":           nowISO(),
			})
			adoptIP(sess, parts[0], curIP)
			dataChanged = true
		default:
			// Тот же адрес: страну всё равно обновляем — геобаза могла
			// обновиться с момента входа.
			if newCC := geoCountry(curIP); newCC != asStr(sess.Get("ip_country")) {
				sess.Set("ip_country", newCC)
				dataChanged = true
			}
			// Ленивая миграция: старые хэши переводим на HMAC.
			if !strings.HasPrefix(stored, "h1:") && len(seedIPKey()) > 0 {
				adoptIP(sess, parts[0], curIP)
				dataChanged = true
			}
		}
	}

	sess.Set("last_seen", nowISO())
	if dataChanged {
		_ = e.App.Save(sess) // автодаты подвинут `updated_at`
	} else {
		// Только `last_seen`: сырой UPDATE, чтобы автодаты не трогали
		// `updated_at` на каждой активности.
		_, _ = e.App.NonconcurrentDB().NewQuery(
			"UPDATE seed_sessions SET last_seen = {:ls} WHERE id = {:id}",
		).Bind(dbx.Params{"ls": asStr(sess.Get("last_seen")), "id": sess.Id}).Execute()
	}

	// Полная запись пользователя нужна только для выпуска токена — читаем
	// после всех проверок уровня сессии (отзыв/срок/бан уже пройдены).
	user, err := e.App.FindRecordById("users", userId)
	if err != nil || user == nil {
		auditLogAs(e, nil, "auth.renew_failed", map[string]any{
			"grant": parts[0], "user_id": userId, "reason": "no_user",
		})
		return seedErr(e, 401, "no_user")
	}
	access, err := user.NewAuthToken()
	if err != nil {
		return seedErr(e, 500, "token_failed")
	}
	return e.JSON(200, map[string]any{"access": access, "expires_in": seedAccessTTLValue(e.App)})
}

// seedRevoke — POST /api/seed/revoke. Отзыв одной своей сессии по её
// идентификатору (нужны токен и живая кука).
//
// Тело запроса: {grant_id: string}
// Ответ 200: {ok: true}
// Ошибки: 401 (нет токена), 404 (сессия не найдена или чужая).
func seedRevoke(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	var b struct {
		GrantID string `json:"grant_id"`
	}
	_ = e.BindBody(&b)

	sess, err := e.App.FindFirstRecordByData("seed_sessions", "grant_id", b.GrantID)
	if err != nil || sess == nil || asStr(sess.Get("user")) != e.Auth.Id {
		return seedErr(e, 404, "no_session")
	}
	sess.Set("revoked", true)
	if err := e.App.Save(sess); err != nil {
		return seedErr(e, 500, "store_failed")
	}
	auditLog(e, "session.revoke", map[string]any{"grant_id": b.GrantID})
	return e.JSON(200, map[string]any{"ok": true})
}

// seedLogout — POST /api/seed/logout. Выход с текущего устройства:
// отзывает сессию из куки и чистит куку. Если сессия уже не найдена —
// всё равно успешный ответ (выход «наилучшим образом»).
//
// Заголовки: токен + живая кука сессии.
// Ответ 200: {ok: true} + очистка куки.
// Ошибки: 401 (нет токена).
func seedLogout(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	raw := cookieVal(e, seedCookieName)
	grant := ""
	if parts := strings.SplitN(raw, ".", 2); len(parts) == 2 && parts[0] != "" {
		if sess, err := e.App.FindFirstRecordByData("seed_sessions", "grant_id", parts[0]); err == nil && sess != nil &&
			asStr(sess.Get("user")) == e.Auth.Id {
			sess.Set("revoked", true)
			_ = e.App.Save(sess)
			grant = parts[0]
		}
	}
	clearSeedCookie(e)
	auditLog(e, "session.logout", map[string]any{"grant_id": grant})
	return e.JSON(200, map[string]any{"ok": true})
}

// seedLogoutAll — POST /api/seed/logout-all. Выход со всех устройств:
// отзывает ВСЕ свои сессии одним запросом к базе (сложность не зависит
// от их числа) и чистит куку.
//
// Заголовки: токен + живая кука сессии.
// Ответ 200: {ok: true, revoked: int} + очистка куки.
// Ошибки: 401 (нет токена), 500 (ошибка хранилища).
func seedLogoutAll(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	// Один UPDATE вместо N сохранений — сложность не зависит от числа сессий.
	result, err := e.App.NonconcurrentDB().NewQuery(
		"UPDATE seed_sessions SET revoked = 1, updated_at = {:now} WHERE user = {:uid} AND revoked = 0 AND (deleted_at IS NULL OR deleted_at = '')",
	).Bind(dbx.Params{"uid": e.Auth.Id, "now": nowISO()}).Execute()
	if err != nil {
		return seedErr(e, 500, "store_failed")
	}
	n, _ := result.RowsAffected()
	clearSeedCookie(e)
	auditLog(e, "session.logout_all", map[string]any{"revoked": n})
	return e.JSON(200, map[string]any{"ok": true, "revoked": n})
}

// ---------------------------------------------------------------- мидлвара

// seedSessionMiddleware — слой привязки токена к сессии: запрос с
// токеном пользователя обязан нести живую куку сессии, а профиль не
// должен быть забанен (бан проверяется на входе, продлении И на каждом
// запросе). Пропускает без куки: гостевые запросы (решают правила
// самого API), суперюзера и служебные пути (челлендж, вход, продление,
// имперсонация, здоровье, панель, аутентификация суперюзеров).
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: error — 401 session_required/session_revoked,
// 403 banned либо продолжение цепочки (e.Next()).
func seedSessionMiddleware(e *core.RequestEvent) error {
	path := e.Request.URL.Path
	for _, s := range []string{
		"/api/seed/challenge",
		"/api/seed/login",
		"/api/seed/renew",
		"/api/seed/impersonate", // вызывается токеном суперюзера, кука не нужна; права решает обработчик
		"/api/health",
		"/api/_/",
		"/api/collections/_superusers",
	} {
		if strings.HasPrefix(path, s) {
			return e.Next()
		}
	}

	a := e.Auth
	if a == nil {
		return e.Next() // гость: решают правила API (публичные данные остаются публичными)
	}
	if a.IsSuperuser() {
		return e.Next()
	}

	raw := cookieVal(e, seedCookieName)
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return seedErr(e, 401, "session_required")
	}
	sess, err := e.App.FindFirstRecordByData("seed_sessions", "grant_id", parts[0])
	if err != nil || sess == nil {
		return seedErr(e, 401, "session_required")
	}
	if !security.Equal(asStr(sess.Get("secret_hash")), security.SHA256(parts[1])) {
		return seedErr(e, 401, "session_required")
	}
	if asStr(sess.Get("user")) != a.Id {
		return seedErr(e, 401, "session_required")
	}
	if asBool(sess.Get("revoked")) || isoExpired(sess.Get("expires")) {
		return seedErr(e, 401, "session_revoked")
	}
	// Мягко удалённые сессии приравнены к отозванным.
	if isSoftDeleted(sess) {
		return seedErr(e, 401, "session_revoked")
	}
	// Профиль уже загружен вместе с токеном — повторный запрос к базе
	// на каждый вызов не нужен.
	if userBanned(a) {
		return banErr(e, a)
	}
	return e.Next()
}

// ---------------------------------------------------------------- защита users

// protectUsersFields запрещает обычным пользователям менять служебные
// поля через API: почта управляется сервером (она отображает открытый
// ключ 1-в-1), бан и роль назначает только админ/суперюзер — так
// пользователь не может сам себя повысить или разбаниться.
// Персональная политика смены адреса хранится в настройках, не в users.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func protectUsersFields(app core.App) {
	protected := []string{"email", "banned", "ban_reason", "banned_until", "role"}
	app.OnRecordUpdateRequest("users").BindFunc(func(e *core.RecordRequestEvent) error {
		if seedAdmin(e.Auth) {
			orig, err := e.App.FindRecordById("users", e.Record.Id)
			if err != nil || orig == nil {
				return e.Next() // пусть сам PB ответит 404
			}
			if !e.Auth.IsSuperuser() {
				// Админ по роли управляет баном и ролями, но не почтой:
				// она отображает открытый ключ 1-в-1 (почту меняет только
				// суперюзер).
				if asStr(orig.Get("email")) != asStr(e.Record.Get("email")) {
					return seedErr(e.RequestEvent, 403, "forbidden")
				}
				// «Админ+» (первый админ по дате создания, см.
				// adminplus.go) защищён от бана и любых смены роли
				// всеми, кроме суперюзера. Роль охраняется целиком:
				// иначе защиту обходили бы связкой «понизить, затем
				// забанить уже не-админа». Консоль не ограничена.
				if isAdminPlus(e.App, orig) {
					if asBool(e.Record.Get("banned")) && !asBool(orig.Get("banned")) {
						return seedErr(e.RequestEvent, 403, "forbidden")
					}
					if !strings.EqualFold(asStr(e.Record.Get("role")), asStr(orig.Get("role"))) {
						return seedErr(e.RequestEvent, 403, "forbidden")
					}
				}
				// Запрет плодить админов: повысить до "admin" может
				// суперюзер, консоль (./pbseed user role) и «админ+».
				// Обычный админ по роли назначает лишь user и moderator;
				// снять роль (понизить) с не-«админ+» — можно.
				if strings.EqualFold(asStr(e.Record.Get("role")), seedRoleAdmin) &&
					!strings.EqualFold(asStr(orig.Get("role")), seedRoleAdmin) &&
					!isAdminPlus(e.App, e.Auth) {
					return seedErr(e.RequestEvent, 403, "forbidden")
				}
			}
			// Журнал пишется сквозным аудитом записей (audit.go):
			// сюда попадают только состоявшиеся правки, строка несёт
			// коллекцию, ид и список изменённых полей.
			return e.Next()
		}
		orig, err := e.App.FindRecordById("users", e.Record.Id)
		if err != nil || orig == nil {
			return e.Next() // пусть сам PB ответит 404
		}
		for _, f := range protected {
			var same bool
			if f == "banned" {
				same = asBool(orig.Get(f)) == asBool(e.Record.Get(f))
			} else {
				same = asStr(orig.Get(f)) == asStr(e.Record.Get(f))
			}
			if !same {
				return seedErr(e.RequestEvent, 403, "forbidden")
			}
		}
		return e.Next()
	})
}

// ---------------------------------------------------------------- схема БД

// autoDates добавляет коллекции автоматические поля времени.
//
// Параметры:
//   - c: *core.Collection — коллекция, которой добавляют поля
//     `created_at` (при создании) и `updated_at` (при создании и обновлении).
func autoDates(c *core.Collection) {
	c.Fields.Add(&core.AutodateField{Name: "created_at", OnCreate: true})
	c.Fields.Add(&core.AutodateField{Name: "updated_at", OnCreate: true, OnUpdate: true})
}

// migrateAutodateNames переименовывает старые поля времени
// (созданные ранними версиями) в канонические. Свежие коллекции сразу
// создаются с новыми именами, поэтому для них операция ничего не делает.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - colName: string — имя коллекции.
//
// Возвращает: error — ошибка переименования.
func migrateAutodateNames(app core.App, colName string) error {
	for _, pair := range [][2]string{{"created", "created_at"}, {"updated", "updated_at"}} {
		if _, err := renameField(app, colName, pair[0], pair[1]); err != nil {
			return err
		}
	}
	return nil
}

// ensureFields добавляет недостающие поля существующей коллекции
// (безопасно для обновлений: развёрнутые тома получают новые поля без
// потери данных).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - colName: string — имя коллекции;
//   - fields: ...core.Field — поля, которых может не хватать.
//
// Возвращает: error — коллекция не найдена или ошибка сохранения.
func ensureFields(app core.App, colName string, fields ...core.Field) error {
	col, err := app.FindCollectionByNameOrId(colName)
	if err != nil {
		return err
	}
	missing := false
	for _, f := range fields {
		if col.Fields.GetByName(f.GetName()) == nil {
			col.Fields.Add(f)
			missing = true
		}
	}
	if !missing {
		return nil
	}
	if err := app.Save(col); err != nil {
		return err
	}
	log.Printf("[seed] fields added (collection %s)", colName)
	return nil
}

// ensureSeedSchema создаёт коллекции аутентификации на первом запуске и
// выравнивает стоковую коллекцию пользователей: токены на 15 минут,
// саморегистрация по паролю закрыта (вход только по подписи), поля
// модерации и пометка стирания. Операция идемпотентна и безопасна для
// обновления (старые тома получают новые поля/индексы без потери данных).
// Стоковые поля времени коллекции пользователей не трогаются: это
// системные имена, на которые завязаны панель и клиентские библиотеки;
// все коллекции сервиса используют свои `created_at`/`updated_at`.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: error — ошибка схемы (запуск прерывается).
func ensureSeedSchema(app core.App) error {
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		return err
	}
	touched := false
	if users.AuthToken.Duration != seedAccessTTL {
		users.AuthToken.Duration = seedAccessTTL
		touched = true
	}
	if users.CreateRule != nil {
		users.CreateRule = nil
		touched = true
	}
	if touched {
		if err := app.Save(users); err != nil {
			return err
		}
	}
	// Поля модерации, роль и пометка GDPR-стирания.
	if err := ensureFields(app, "users",
		&core.BoolField{Name: "banned"},
		&core.TextField{Name: "ban_reason", Max: 255},
		&core.TextField{Name: "banned_until", Max: 64},
		&core.SelectField{Name: "role", Values: []string{seedRoleUser, seedRoleModerator, seedRoleAdmin}, MaxSelect: 1},
		&core.DateField{Name: "deleted_at"},
	); err != nil {
		return err
	}
	// Бэкфилл роли: старым записям без роли назначается "user"
	// (идемпотентно — уже заполненные строки не трогаются).
	if _, err := app.NonconcurrentDB().NewQuery(
		"UPDATE users SET role = {:r} WHERE role IS NULL OR role = ''",
	).Bind(dbx.Params{"r": seedRoleUser}).Execute(); err != nil {
		return err
	}

	// Служебные коллекции описаны в едином реестре схемы
	// (schema_registry.go): создание недостающих, добавление полей,
	// восстановление правил, подтверждение индексов.
	if err := syncSeedSchema(app); err != nil {
		return err
	}
	// Односторонняя миграция: старое поле строгости адреса переезжает в
	// персональные строки настроек, затем поле удаляется. Без потерь.
	if err := migrateStrictIP(app); err != nil {
		return err
	}
	// Миграция имён полей времени в коллекциях, созданных старыми
	// версиями: на развёрнутых базах старые имена переименовываются.
	// Список коллекций берётся из реестра схемы.
	for i := range seedSchema {
		if err := migrateAutodateNames(app, seedSchema[i].Name); err != nil {
			return err
		}
	}
	// Правила коллекции пользователей приводятся к базовым (ролевым):
	// своё видит каждый, чтение всех — админ/модератор, изменение чужих
	// записей — админ. Применяются автоматически с записью в лог
	// (см. schema_registry.go).
	applyUsersRules(app)
	return ensureSeedSettings(app)
}

// proxyHeadersFromEnv читает список доверенных заголовков прокси из
// переменной окружения `PROXY_HEADERS` (через запятую, например
// «CF-Connecting-IP» или «X-Forwarded-For, CF-Connecting-IP»). Пустая
// или отсутствующая переменная даёт стандарт — одиночный
// `X-Forwarded-For`. Используется только первым стартом, пока список
// настроек пуст (уже настроенная база окружением не перезаписывается).
//
// Возвращает: []string — список заголовков (никогда не пустой).
func proxyHeadersFromEnv() []string {
	out := []string{}
	for _, h := range strings.Split(os.Getenv("PROXY_HEADERS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return []string{"X-Forwarded-For"}
	}
	return out
}

// ensureSeedSettings укрепляет свежие установки (никогда не затирает
// уже настроенное админом): доверенный прокси для определения реального
// адреса клиента и защита от флуда на эндпоинтах входа и стоковых путях.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: error — ошибка сохранения настроек.
func ensureSeedSettings(app core.App) error {
	s := app.Settings()
	changed := false
	if len(s.TrustedProxy.Headers) == 0 {
		// PaaS-прокси дописывает заголовок; правая запись — клиент глазами
		// последнего прокси. Пока все запросы приходят через прокси,
		// подделка заголовка клиентом невозможна. Прямые запросы без
		// заголовка используют неподделываемый адрес сокета. Список
		// заголовков берётся из окружения (сборка/деплой), стандарт —
		// X-Forwarded-For.
		s.TrustedProxy.Headers = proxyHeadersFromEnv()
		s.TrustedProxy.UseLeftmostIP = false
		changed = true
	}
	if !s.RateLimits.Enabled {
		s.RateLimits.Enabled = true
		s.RateLimits.ExcludedIPs = []string{"127.0.0.1", "::1"}
		s.RateLimits.Rules = []core.RateLimitRule{
			{Label: "POST /api/seed/challenge", Audience: core.RateLimitRuleAudienceGuest, MaxRequests: 20, Duration: 60},
			{Label: "POST /api/seed/login", Audience: core.RateLimitRuleAudienceGuest, MaxRequests: 20, Duration: 60},
			{Label: "POST /api/seed/renew", MaxRequests: 30, Duration: 60},
			{Label: "*:auth", MaxRequests: 2, Duration: 3},
			{Label: "*:create", MaxRequests: 20, Duration: 5},
			{Label: "/api/batch", MaxRequests: 3, Duration: 1},
			{Label: "/api/", MaxRequests: 300, Duration: 10},
		}
		changed = true
	}
	// На каждом запуске логируем действующее состояние защиты от флуда
	// (сами правила — данные админа, здесь они не сливаются).
	nSeed := 0
	for _, r := range s.RateLimits.Rules {
		if strings.Contains(r.Label, "/api/seed/") {
			nSeed++
		}
	}
	log.Printf("[seed] rate limits: enabled=%v rules=%d seed_rules=%d", s.RateLimits.Enabled, len(s.RateLimits.Rules), nSeed)
	if !changed {
		return nil
	}
	return app.Save(s)
}

// migrateStrictIP — односторонняя миграция старых томов: поле строгости
// адреса у пользователей переносится в персональные строки настроек
// (ключ «выгонять при смене адреса»), после чего поле удаляется.
// Существующие персональные настройки имеют приоритет. Идемпотентна.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: error — ошибка чтения или сохранения.
func migrateStrictIP(app core.App) error {
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		return err
	}
	if users.Fields.GetByName("strict_ip") == nil {
		return nil // уже мигрировано (или поля никогда не было)
	}
	rows, err := app.FindRecordsByFilter("users", "strict_ip = true", "", 10000, 0)
	if err != nil {
		return err
	}
	for _, u := range rows {
		if findSetting(app, seedPolicyKick, u.Id) != nil {
			continue
		}
		col, err := app.FindCollectionByNameOrId("seed_settings")
		if err != nil {
			return err
		}
		rec := core.NewRecord(col)
		rec.Set("key", seedPolicyKick)
		rec.Set("value", true)
		rec.Set("user", u.Id)
		rec.Set("locked", false)
		if err := app.Save(rec); err != nil {
			return err
		}
	}
	users.Fields.RemoveByName("strict_ip")
	if err := app.Save(users); err != nil {
		return err
	}
	log.Printf("[seed] migration done (strict_ip_moved %d)", len(rows))
	return nil
}

// ensureSuperuserFromEnv создаёт первого суперюзера из переменных
// окружения на свежих установках (удобно для контейнеров: без
// интерактивной настройки). Никогда не перезаписывает существующего
// суперюзера и никогда не роняет запуск.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Окружение: переменная почты и переменная пароля суперюзера
// (пароль от 8 символов).
func ensureSuperuserFromEnv(app core.App) {
	email := strings.TrimSpace(os.Getenv("PB_SUPERUSER_EMAIL"))
	pass := os.Getenv("PB_SUPERUSER_PASSWORD")
	if email == "" || pass == "" {
		return
	}
	if _, err := app.FindFirstRecordByData("_superusers", "email", email); err == nil {
		log.Printf("[seed] superuser exists, env bootstrap skipped (%s)", email)
		return
	}
	col, err := app.FindCollectionByNameOrId("_superusers")
	if err != nil {
		log.Printf("[seed] ERROR: superuser env bootstrap failed: %v", err)
		return
	}
	rec := core.NewRecord(col)
	rec.Set("email", email)
	rec.Set("password", pass)
	if err := app.Save(rec); err != nil {
		log.Printf("[seed] ERROR: superuser env bootstrap failed (password min 8 chars?): %v", err)
		return
	}
	log.Printf("[seed] superuser created from env (%s)", email)
}
