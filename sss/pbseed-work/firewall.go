package main

// firewall.go — фаервол панели на основе журнала действий.
//
// Журнал здесь — не только летопись, но и источник решений: по его
// строкам фаервол считает неудачные входы суперюзера и принимает
// меры. Два уровня защиты:
//
//  1. Временная блокировка адреса: если с одного адреса за окно
//     наблюдения пришло пороговое число неудачных входов в панель
//     (пароль, одноразовый код, OAuth2), адрес блокируется на срок
//     блокировки. Снять её может консоль сервера или суперюзер с
//     рабочей сессией через /api/seed/firewall/unlock.
//
//  2. Полное отключение панели: если за сутки набралось пороговое
//     число блокировок адресов, вход в панель (и авторизация
//     суперюзера через REST) и интерфейс панели «/_/» отключаются до
//     конца суток. Это отключение снимается ТОЛЬКО консолью сервера
//     (команда `firewall unlock-panel`) — через API его снять нельзя.
//
// Все события фаервола пишутся в тот же журнал `seed_audit` теми же
// серверными функциями записи: неудачные входы (`superuser.login_failed`),
// блокировки (`firewall.lock_ip`, `firewall.panel_off`) и разблокировки
// (`firewall.unlock`). Поскольку журнал неизменяем через REST, подделать
// или затереть историю атаки нельзя.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
	"github.com/spf13/cobra"
)

// Ключи действий журнала, которыми пользуется фаервол.
const (
	fwActLogin     = "superuser.login"        // успешный вход суперюзера
	fwActLoginFail = "superuser.login_failed" // неудачный вход суперюзера
	fwActLockIP    = "firewall.lock_ip"       // блокировка адреса (уровень 1)
	fwActPanelOff  = "firewall.panel_off"     // отключение панели (уровень 2)
	fwActUnlock    = "firewall.unlock"        // разблокировка (консоль или API)
)

// fwEnvDuration читает длительность из переменной окружения с запасным
// значением; мусор и пусто дают запасное.
//
// Параметры:
//   - name: string — имя переменной;
//   - def: time.Duration — запасное значение.
//
// Возвращает: time.Duration — прочитанная или запасная длительность.
func fwEnvDuration(name string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// fwEnvInt читает целое из переменной окружения с запасным значением;
// мусор, пусто и неположительные значения дают запасное.
//
// Параметры:
//   - name: string — имя переменной;
//   - def: int — запасное значение.
//
// Возвращает: int — прочитанное или запасное значение.
func fwEnvInt(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// fwEnabled сообщает, включён ли фаервол (по умолчанию да; отключается
// значением «0»/«false»/«off»/«no» переменной SEED_FIREWALL).
//
// Возвращает: bool — состояние фаервола.
func fwEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SEED_FIREWALL"))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// fwFails — порог неудачных входов с одного адреса для блокировки.
//
// Возвращает: int — порог (переменная SEED_FIREWALL_FAILS, по умолчанию 5).
func fwFails() int { return fwEnvInt("SEED_FIREWALL_FAILS", 5) }

// fwWindow — окно наблюдения за неудачными входами.
//
// Возвращает: time.Duration — окно (переменная SEED_FIREWALL_WINDOW,
// по умолчанию 15 минут).
func fwWindow() time.Duration { return fwEnvDuration("SEED_FIREWALL_WINDOW", 15*time.Minute) }

// fwLockDur — срок временной блокировки адреса.
//
// Возвращает: time.Duration — срок (переменная SEED_FIREWALL_LOCK,
// по умолчанию 30 минут).
func fwLockDur() time.Duration { return fwEnvDuration("SEED_FIREWALL_LOCK", 30*time.Minute) }

// fwBlocksPerDay — сколько блокировок адресов за сутки отключают
// панель до конца суток.
//
// Возвращает: int — порог (переменная SEED_FIREWALL_BLOCKS, по умолчанию 3).
func fwBlocksPerDay() int { return fwEnvInt("SEED_FIREWALL_BLOCKS", 3) }

// fwIPHash считает устойчивый хэш адреса для фаервола (без грантовой
// соли сессий — один адрес должен всегда давать один хэш).
//
// Параметры:
//   - ip: string — адрес клиента.
//
// Возвращает: string — хэш адреса.
func fwIPHash(ip string) string { return seedIPHash(ip, "", seedIPKey()) }

// fwEndOfDay возвращает конец текущих суток по часам сервера.
//
// Параметры:
//   - now: time.Time — текущий момент.
//
// Возвращает: time.Time — полночь следующих суток.
func fwEndOfDay(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
}

// fwDetail раскладывает JSON-поле `detail` строки журнала в словарь.
//
// Параметры:
//   - rec: *core.Record — строка журнала.
//
// Возвращает: map[string]any — содержимое `detail` (пустой словарь при
// ошибке или отсутствии поля).
func fwDetail(rec *core.Record) map[string]any {
	out := map[string]any{}
	if rec == nil {
		return out
	}
	switch v := rec.Get("detail").(type) {
	case types.JSONRaw:
		_ = json.Unmarshal(v, &out)
	case []byte:
		_ = json.Unmarshal(v, &out)
	case string:
		_ = json.Unmarshal([]byte(v), &out)
	case map[string]any:
		return v
	}
	return out
}

// fwDetailUntil читает срок «до» из `detail.until` строки журнала
// (формат RFC3339).
//
// Параметры:
//   - rec: *core.Record — строка журнала.
//
// Возвращает: time.Time — срок (нулевое время, если не задан/испорчен).
func fwDetailUntil(rec *core.Record) time.Time {
	s, _ := fwDetail(rec)["until"].(string)
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// fwRowTime возвращает время создания строки журнала.
//
// Параметры:
//   - rec: *core.Record — строка журнала.
//
// Возвращает: time.Time — время создания (нулевое при ошибке).
func fwRowTime(rec *core.Record) time.Time {
	if rec == nil {
		return time.Time{}
	}
	return rec.GetDateTime("created_at").Time()
}

// fwLastRow ищет самую свежую строку журнала по действию и
// дополнительному фильтру (язык штатных фильтров).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - action: string — ключ действия;
//   - extra: string — дополнительный фильтр (может быть пуст);
//   - params: dbx.Params — параметры дополнительного фильтра.
//
// Возвращает: *core.Record — строка или nil.
func fwLastRow(app core.App, action, extra string, params dbx.Params) *core.Record {
	filter := "action={:fw_a}"
	p := dbx.Params{"fw_a": action}
	if strings.TrimSpace(extra) != "" {
		filter += " && " + extra
		for k, v := range params {
			p[k] = v
		}
	}
	rows, err := app.FindRecordsByFilter("seed_audit", filter, "-created_at", 1, 0, p)
	if err != nil || len(rows) == 0 {
		return nil
	}
	return rows[0]
}

// fwPanelOffUntil сообщает, до какого момента панель отключена.
// Отключение действует, если есть строка `firewall.panel_off` с будущим
// сроком и после неё не было консольной разблокировки
// (`firewall.unlock` c what=panel).
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: time.Time — момент окончания отключения (нулевое время —
// панель работает).
func fwPanelOffUntil(app core.App) time.Time {
	off := fwLastRow(app, fwActPanelOff, "", nil)
	if off == nil {
		return time.Time{}
	}
	until := fwDetailUntil(off)
	if until.IsZero() || !until.After(time.Now()) {
		return time.Time{}
	}
	unlock := fwLastRow(app, fwActUnlock, `detail.what={:fw_w}`, dbx.Params{"fw_w": "panel"})
	if unlock != nil && !fwRowTime(unlock).Before(fwRowTime(off)) {
		return time.Time{}
	}
	return until
}

// fwIPLockedUntil сообщает, до какого момента заблокирован адрес.
// Блокировка действует, если есть строка `firewall.lock_ip` с этим
// хэшем адреса и будущим сроком, не отменённая более поздней
// разблокировкой (what=ip).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - ipHash: string — хэш адреса.
//
// Возвращает: time.Time — момент окончания блокировки (нулевое время —
// адрес свободен).
func fwIPLockedUntil(app core.App, ipHash string) time.Time {
	lock := fwLastRow(app, fwActLockIP, `detail.ip_hash={:fw_h}`, dbx.Params{"fw_h": ipHash})
	if lock == nil {
		return time.Time{}
	}
	until := fwDetailUntil(lock)
	if until.IsZero() || !until.After(time.Now()) {
		return time.Time{}
	}
	unlock := fwLastRow(app, fwActUnlock,
		`detail.what={:fw_w} && detail.ip_hash={:fw_h}`,
		dbx.Params{"fw_w": "ip", "fw_h": ipHash})
	if unlock != nil && !fwRowTime(unlock).Before(fwRowTime(lock)) {
		return time.Time{}
	}
	return until
}

// fwFailCount считает неудачные входы суперюзера с адреса за период.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - ipHash: string — хэш адреса;
//   - since: time.Time — начало периода.
//
// Возвращает: int — число неудачных входов.
func fwFailCount(app core.App, ipHash string, since time.Time) int {
	rows, err := app.FindRecordsByFilter("seed_audit",
		`action={:fw_a} && detail.ip_hash={:fw_h} && created_at >= {:fw_s}`,
		"", 500, 0, dbx.Params{
			"fw_a": fwActLoginFail,
			"fw_h": ipHash,
			"fw_s": since.UTC().Format("2006-01-02 15:04:05.000Z"),
		})
	if err != nil {
		return 0
	}
	return len(rows)
}

// fwDayStart возвращает начало текущих суток по часам сервера.
//
// Параметры:
//   - now: time.Time — текущий момент.
//
// Возвращает: time.Time — полночь текущих суток.
func fwDayStart(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}

// fwLockCountToday считает блокировки адресов за текущие сутки.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: int — число блокировок с начала суток.
func fwLockCountToday(app core.App) int {
	rows, err := app.FindRecordsByFilter("seed_audit",
		`action={:fw_a} && created_at >= {:fw_s}`, "", 500, 0, dbx.Params{
			"fw_a": fwActLockIP,
			"fw_s": fwDayStart(time.Now()).UTC().Format("2006-01-02 15:04:05.000Z"),
		})
	if err != nil {
		return 0
	}
	return len(rows)
}

// fwActiveLocks собирает действующие блокировки адресов (срок ещё не
// истёк и нет более поздней разблокировки).
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: []*core.Record — строки блокировок (могут быть с одного
// адреса только самые свежие).
func fwActiveLocks(app core.App) []*core.Record {
	rows, err := app.FindRecordsByFilter("seed_audit",
		`action={:fw_a}`, "-created_at", 500, 0, dbx.Params{"fw_a": fwActLockIP})
	if err != nil {
		return nil
	}
	var out []*core.Record
	seen := map[string]bool{}
	for _, r := range rows { // от свежих к старым
		h, _ := fwDetail(r)["ip_hash"].(string)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if !fwIPLockedUntil(app, h).IsZero() {
			out = append(out, r)
		}
	}
	return out
}

// fwDeny пишет отказ 403 в ответ и возвращает непустую ошибку, чтобы
// остановить цепочку хука. Один только ответ не годится: запись ответа
// возвращает nil, и цепочка посчитала бы отказ успехом и продолжила бы
// авторизацию.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса;
//   - code: string — код отказа (тело {"error": code}).
//
// Возвращает: error — всегда непустая ошибка.
func fwDeny(e *core.RequestEvent, code string) error {
	if err := seedErr(e, 403, code); err != nil {
		return err
	}
	return errors.New(code)
}

// fwGatePre проверяет фаервол ДО авторизации суперюзера: отключение
// панели и блокировка адреса.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: error — отказ (403) или nil, если путь свободен.
func fwGatePre(e *core.RequestEvent) error {
	if !fwEnabled() {
		return nil
	}
	if until := fwPanelOffUntil(e.App); !until.IsZero() {
		return fwDeny(e, "panel_off")
	}
	if until := fwIPLockedUntil(e.App, fwIPHash(e.RealIP())); !until.IsZero() {
		return fwDeny(e, "firewall_locked")
	}
	return nil
}

// fwOnAuthFailed фиксирует неудачный вход суперюзера и запускает
// эскалацию: порог неудач → блокировка адреса, порог блокировок за
// сутки → отключение панели.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - e: *core.RequestEvent — событие запроса;
//   - method: string — способ входа (password/otp/oauth2);
//   - identity: string — кем пытались войти (почта).
func fwOnAuthFailed(app core.App, e *core.RequestEvent, method, identity string) {
	ip := e.RealIP()
	iph := fwIPHash(ip)
	auditWriteRow(app, nil, "", "", fwActLoginFail, map[string]any{
		"identity":  truncRunes(identity, 255),
		"method":    method,
		"ip_masked": maskIP(ip),
		"ip_hash":   iph,
	})
	if !fwEnabled() {
		return
	}
	n := fwFailCount(app, iph, time.Now().Add(-fwWindow()))
	if n < fwFails() || !fwIPLockedUntil(app, iph).IsZero() {
		return
	}
	lockUntil := time.Now().Add(fwLockDur())
	auditWriteRow(app, nil, "", "", fwActLockIP, map[string]any{
		"ip_hash":   iph,
		"ip_masked": maskIP(ip),
		"until":     lockUntil.Format(time.RFC3339),
		"fails":     n,
	})
	log.Printf("[seed] firewall: IP %s locked until %s (%d failed superuser logins)",
		maskIP(ip), lockUntil.Format("15:04:05"), n)
	locks := fwLockCountToday(app)
	if locks >= fwBlocksPerDay() && fwPanelOffUntil(app).IsZero() {
		until := fwEndOfDay(time.Now())
		auditWriteRow(app, nil, "", "", fwActPanelOff, map[string]any{
			"until":       until.Format(time.RFC3339),
			"locks_today": locks,
		})
		log.Printf("[seed] firewall: panel OFF until %s (%d address locks today)",
			until.Format("2006-01-02 15:04"), locks)
	}
}

// fwOnAuthSuccess фиксирует успешный вход суперюзера (пароль,
// одноразовый код или OAuth2) — с какого адреса и каким способом.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - e: *core.RequestEvent — событие запроса;
//   - method: string — способ входа;
//   - actor: *core.Record — запись суперюзера.
func fwOnAuthSuccess(app core.App, e *core.RequestEvent, method string, actor *core.Record) {
	ip := e.RealIP()
	// Сессия суперюзера уже создана к этому моменту (хук успешной
	// авторизации отработал внутри цепочки) — ссылаемся на неё.
	session := ""
	if actor != nil {
		if rows, err := app.FindRecordsByFilter("seed_sessions",
			`superuser_id={:fw_su}`, "-created_at", 1, 0, dbx.Params{"fw_su": actor.Id}); err == nil && len(rows) > 0 {
			session = asStr(rows[0].Get("grant_id"))
		}
	}
	auditWriteRow(app, actor, "", session, fwActLogin, map[string]any{
		"method":    method,
		"ip_masked": maskIP(ip),
		"ip_hash":   fwIPHash(ip),
	})
}

// installFirewallHooks подключает фаервол к авторизации суперюзера:
// пароль, одноразовый код (и его запрос), OAuth2. Панель и REST для
// суперюзера идут через эти же эндпоинты, поэтому покрытие полное.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func installFirewallHooks(app core.App) {
	app.OnRecordAuthWithPasswordRequest("_superusers").BindFunc(func(e *core.RecordAuthWithPasswordRequestEvent) error {
		if err := fwGatePre(e.RequestEvent); err != nil {
			return err
		}
		err := e.Next()
		if err != nil {
			fwOnAuthFailed(e.App, e.RequestEvent, "password", e.Identity)
			return err
		}
		fwOnAuthSuccess(e.App, e.RequestEvent, "password", e.Record)
		return nil
	})

	app.OnRecordAuthWithOTPRequest("_superusers").BindFunc(func(e *core.RecordAuthWithOTPRequestEvent) error {
		if err := fwGatePre(e.RequestEvent); err != nil {
			return err
		}
		err := e.Next()
		if err != nil {
			id := ""
			if e.Record != nil {
				id = e.Record.Email()
			}
			fwOnAuthFailed(e.App, e.RequestEvent, "otp", id)
			return err
		}
		fwOnAuthSuccess(e.App, e.RequestEvent, "otp", e.Record)
		return nil
	})

	app.OnRecordAuthWithOAuth2Request("_superusers").BindFunc(func(e *core.RecordAuthWithOAuth2RequestEvent) error {
		if err := fwGatePre(e.RequestEvent); err != nil {
			return err
		}
		err := e.Next()
		if err != nil {
			fwOnAuthFailed(e.App, e.RequestEvent, "oauth2", e.ProviderName)
			return err
		}
		fwOnAuthSuccess(e.App, e.RequestEvent, "oauth2", e.Record)
		return nil
	})

	// Запрос одноразового кода тоже считается входной точкой: при
	// отключённой панели или заблокированном адресе код не высылается.
	app.OnRecordRequestOTPRequest("_superusers").BindFunc(func(e *core.RecordCreateOTPRequestEvent) error {
		if err := fwGatePre(e.RequestEvent); err != nil {
			return err
		}
		return e.Next()
	})
}

// fwPanelMiddleware не пускает в интерфейс панели «/_/», пока панель
// отключена фаерволом.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: error — отказ (403) либо продолжение цепочки.
func fwPanelMiddleware(e *core.RequestEvent) error {
	if strings.HasPrefix(e.Request.URL.Path, "/_/") && fwEnabled() {
		if until := fwPanelOffUntil(e.App); !until.IsZero() {
			return seedErr(e, 403, "panel_off")
		}
	}
	return e.Next()
}

// seedFirewallStatus отдаёт суперюзеру состояние фаервола.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: error — результат ответа.
func seedFirewallStatus(e *core.RequestEvent) error {
	if e.Auth == nil || !e.Auth.IsSuperuser() {
		return seedErr(e, 403, "forbidden")
	}
	panel := fwPanelOffUntil(e.App)
	panelOut := ""
	if !panel.IsZero() {
		panelOut = panel.Format(time.RFC3339)
	}
	var locks []map[string]any
	for _, r := range fwActiveLocks(e.App) {
		d := fwDetail(r)
		locks = append(locks, map[string]any{
			"ip_masked": d["ip_masked"],
			"until":     d["until"],
		})
	}
	return e.JSON(200, map[string]any{
		"enabled":         fwEnabled(),
		"panel_off_until": panelOut,
		"locks_today":     fwLockCountToday(e.App),
		"active_locks":    locks,
		"limits": map[string]any{
			"fails":          fwFails(),
			"window_minutes": int(fwWindow().Minutes()),
			"lock_minutes":   int(fwLockDur().Minutes()),
			"blocks_per_day": fwBlocksPerDay(),
		},
	})
}

// seedFirewallUnlock снимает ВРЕМЕННУЮ блокировку адреса по запросу
// суперюзера с рабочей сессией. Отключение панели через API не
// снимается — только консолью сервера.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: error — результат ответа.
func seedFirewallUnlock(e *core.RequestEvent) error {
	if e.Auth == nil || !e.Auth.IsSuperuser() {
		return seedErr(e, 403, "forbidden")
	}
	var b struct {
		IP   string `json:"ip"`
		What string `json:"what"`
	}
	if err := e.BindBody(&b); err != nil {
		return seedErr(e, 400, "bad_request")
	}
	if strings.EqualFold(strings.TrimSpace(b.What), "panel") {
		return seedErr(e, 403, "console_only")
	}
	ip := strings.TrimSpace(b.IP)
	if ip == "" {
		return seedErr(e, 400, "bad_ip")
	}
	iph := fwIPHash(ip)
	if fwIPLockedUntil(e.App, iph).IsZero() {
		return seedErr(e, 404, "no_lock")
	}
	auditLog(e, fwActUnlock, map[string]any{
		"what":      "ip",
		"ip_hash":   iph,
		"ip_masked": maskIP(ip),
		"by":        "api",
	})
	return e.JSON(200, map[string]any{"ok": true})
}

// newFirewallCommand собирает консольную команду `firewall`: статус,
// снятие блокировок адресов и снятие отключения панели. Консоль —
// единственный способ включить панель после суточного отключения.
//
// Параметры:
//   - app: core.App — приложение PocketBase (уже загружено каркасом).
//
// Возвращает: *cobra.Command — готовая команда `firewall`.
func newFirewallCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:   "firewall",
		Short: "Audit-based panel firewall: status and unlocks",
	}

	statusCmd := &cobra.Command{
		Use:          "status",
		Short:        "Show firewall state (panel off, active address locks)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Фаервол: включён=%v (порог=%d неудач за %s, блокировка %s, отключение панели при %d блокировках/сутки)\n",
				fwEnabled(), fwFails(), fwWindow(), fwLockDur(), fwBlocksPerDay())
			if until := fwPanelOffUntil(app); !until.IsZero() {
				fmt.Printf("Панель ОТКЛЮЧЕНА до %s (снять: pbseed firewall unlock-panel)\n",
					until.Format("2006-01-02 15:04:05 MST"))
			} else {
				fmt.Println("Панель работает.")
			}
			locks := fwActiveLocks(app)
			if len(locks) == 0 {
				fmt.Println("Активных блокировок адресов нет.")
				return nil
			}
			fmt.Printf("Активные блокировки адресов: %d (блокировок за сутки: %d)\n", len(locks), fwLockCountToday(app))
			for _, r := range locks {
				d := fwDetail(r)
				fmt.Printf("  %s до %s (%v неудач)\n", d["ip_masked"], d["until"], d["fails"])
			}
			return nil
		},
	}

	unlockIPCmd := &cobra.Command{
		Use:          "unlock-ip [IP]",
		Short:        "Unlock an IP address (no argument = unlock all locked addresses)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return errors.New("нужен один адрес или ничего (разблокировать все)")
			}
			var hashes []struct{ ip, hash string }
			if len(args) == 1 {
				ip := strings.TrimSpace(args[0])
				hashes = append(hashes, struct{ ip, hash string }{ip, fwIPHash(ip)})
			} else {
				for _, r := range fwActiveLocks(app) {
					h, _ := fwDetail(r)["ip_hash"].(string)
					m, _ := fwDetail(r)["ip_masked"].(string)
					hashes = append(hashes, struct{ ip, hash string }{m, h})
				}
			}
			done := 0
			for _, x := range hashes {
				if x.hash == "" {
					continue
				}
				auditWriteConsole(app, fwActUnlock, map[string]any{
					"what":      "ip",
					"ip_hash":   x.hash,
					"ip_masked": x.ip,
				})
				done++
			}
			fmt.Printf("Разблокировано адресов: %d (консоль)\n", done)
			return nil
		},
	}

	unlockPanelCmd := &cobra.Command{
		Use:          "unlock-panel",
		Short:        "Re-enable the admin panel after a daily shutdown (console only)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fwPanelOffUntil(app).IsZero() {
				fmt.Println("Панель не отключена.")
				return nil
			}
			auditWriteConsole(app, fwActUnlock, map[string]any{
				"what": "panel",
			})
			fmt.Println("Панель включена (консоль).")
			return nil
		},
	}

	command.AddCommand(statusCmd, unlockIPCmd, unlockPanelCmd)
	return command
}
