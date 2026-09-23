package main

import (
	"log"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// automation.go — серверные хуки автоматизации (дорожная карта из
// README: хуки читают конфиг ядром и меняют его обёртками ByHook с
// атрибуцией имени хука в журнале).

// hookAutotune — имя хука-предохранителя (атрибуция в журнале).
const hookAutotune = "autotune"

// regPerDayCap — потолок суточных регистраций с адреса: переопределения
// в базе сверх него снимаются хуком «автонастройка».
const regPerDayCap = 50

// autotuneRegPerDay — тело предохранителя: если действующее значение
// `reg_per_day` выше предела, строка-переопределение снимается
// обёрткой `settingsDeleteByHook` (журнал несёт имя хука «autotune»).
//
// Вызывается из всех трёх точек записи конфигурации: штатного REST
// коллекции `seed_gateway`, эндпоинта `/api/seed/gateway-config` и
// консольной команды `gateway set` — последние две пишут внутренним
// сохранением и минуют REST-хуки, поэтому предохранитель дублируется
// в каждой точке тем же телом.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func autotuneRegPerDay(app core.App) {
	if gwIntOf(app, gwPRegPerDay) <= regPerDayCap {
		return
	}
	value, _ := gwResolve(app, gwPRegPerDay)
	if _, err := settingsDeleteByHook(app, hookAutotune, gwPRegPerDay.Key); err != nil {
		log.Printf("[seed] autotune failed: %v", err)
	} else {
		log.Printf("[seed] autotune: reg_per_day=%s выше предела %d — переопределение снято", value, regPerDayCap)
	}
}

// installAutomationHooks подключает хуки автоматизации:
//
//  1. «Автонастройка» — не даёт ослабить `reg_per_day` в базе сверх
//     предела: строка-переопределение снимается обёрткой
//     `settingsDeleteByHook`, строка журнала несёт имя хука.
//  2. «Каскад бана» — бан пользователя через REST немедленно отзывает
//     все его живые сессии (одним запросом, как /api/seed/logout-all);
//     консольный бан отзыва не требует — там сессии гаснут проверками
//     продления.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func installAutomationHooks(app core.App) {
	// Предохранитель конфигурации на штатном REST коллекции
	// `seed_gateway` (исполнители события — только админ и суперюзер,
	// прочие отказываются раньше, до хука). Запись через эндпоинт
	// `/api/seed/gateway-config` ловится вторым вызовом того же тела.
	autotune := func(e *core.RecordRequestEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		// Код после Next() выполняется только после успешного сохранения.
		autotuneRegPerDay(app)
		return nil
	}
	app.OnRecordCreateRequest("seed_gateway").BindFunc(autotune)
	app.OnRecordUpdateRequest("seed_gateway").BindFunc(autotune)

	// Каскад бана: забаненному сразу нечего продлевать — отзываем все
	// живые сессии. Если отзываемых нет (повторная правка забаненного),
	// строка в журнал не пишется — дублей не появляется.
	app.OnRecordUpdateRequest("users").BindFunc(func(e *core.RecordRequestEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		if !userBanned(e.Record) {
			return nil
		}
		result, err := e.App.NonconcurrentDB().NewQuery(
			"UPDATE seed_sessions SET revoked = 1, updated_at = {:now} WHERE user = {:uid} AND revoked = 0 AND (deleted_at IS NULL OR deleted_at = '')",
		).Bind(dbx.Params{"uid": e.Record.Id, "now": nowISO()}).Execute()
		if err != nil {
			log.Printf("[seed] ban cascade revoke failed: %v", err)
			return nil
		}
		if n, _ := result.RowsAffected(); n > 0 {
			auditLogAs(e.RequestEvent, e.Auth, "session.kill", map[string]any{
				"user_id": e.Record.Id, "revoked": n, "reason": "ban_cascade",
			})
		}
		return nil
	})
}
