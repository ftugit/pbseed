package main

// audit.go — журнал действий на сайте (слежка за всеми).
//
// Журнал фиксирует действия ВСЕХ действующих лиц независимо от их
// прав: обычных юзеров (входы, правки своего профиля, политики,
// отзыв сессий, восстановления), модераторов, админов и суперюзера
// (включая его правки через панель). Каждая строка: кто (ид, уровень,
// подпись), что сделал, детали; если действие выполнено под маской —
// ещё и «от чьего имени».
//
// Записываются только СОСТОЯВШИЕСЯ операции (отказы и ошибки не
// попадают в строки записей; исключение — события входа: успешные,
// неудачные и заблокированные входы пишутся всегда, это материал для
// разбора инцидентов). Системная возня (сборка мусора, продление
// `last_seen`, служебные таблицы) не логируется: в журнал попадают
// только действия через API.

import (
	"log"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/pocketbase/pocketbase/core"
)

// currentSessionByCookie находит живую сессию запроса по куке.
// Используется журналом для выяснения атрибуции маски; проверка
// секрета здесь не нужна — секреты уже проверил мидлвара, а журнал
// лишь подпись, не источник прав.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: *core.Record — сессия по куке или nil (куки нет/не найдена).
func currentSessionByCookie(e *core.RequestEvent) *core.Record {
	raw := cookieVal(e, seedCookieName)
	if raw == "" {
		// Регистрация и первый вход: кука уже поставлена в ответ, но её
		// ещё нет в самом запросе — читаем из ответа.
		for _, c := range (&http.Response{Header: e.Response.Header()}).Cookies() {
			if c.Name == seedCookieName && c.Value != "" {
				raw = c.Value
				break
			}
		}
	}
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 || parts[0] == "" {
		return nil
	}
	sess, err := e.App.FindFirstRecordByData("seed_sessions", "grant_id", parts[0])
	if err != nil {
		return nil
	}
	return sess
}

// actorKind описывает уровень исполнителя для журнала.
//
// Параметры:
//   - a: *core.Record — авторизованная запись.
//
// Возвращает: string — "superuser", "admin", "moderator", "user" или "".
func actorKind(a *core.Record) string {
	if a == nil {
		return ""
	}
	if a.IsSuperuser() {
		return "superuser"
	}
	switch strings.ToLower(asStr(a.Get("role"))) {
	case seedRoleAdmin:
		return seedRoleAdmin
	case seedRoleModerator:
		return seedRoleModerator
	default:
		return seedRoleUser
	}
}

// actorLabel собирает человекочитаемую подпись исполнителя: почта
// (суперюзер) или открытый ключ (обычные юзера), урезанная до 255.
//
// Параметры:
//   - a: *core.Record — авторизованная запись.
//
// Возвращает: string — подпись для журнала.
func actorLabel(a *core.Record) string {
	if a == nil {
		return ""
	}
	if email := a.Email(); email != "" {
		return truncRunes(email, 255)
	}
	return truncRunes(a.Id, 32)
}

// auditWriteRow пишет одну строку в журнал без привязки к запросу —
// серверный путь записи (журнал действий, фаервол). Исполнитель может
// быть nil — тогда строка помечается «гость». Ошибка журнала никогда
// не роняет основную операцию: это подпись, а не часть прав — сбой
// записывается в лог сервера.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - actor: *core.Record — исполнитель (может быть nil);
//   - onBehalf: string — «от чьего имени» (пусто, если маски нет);
//   - session: string — ид сессии (грант), в которой сделано действие
//     (пусто у гостей и серверных строк);
//   - action: string — имя действия, напр. "records.update";
//   - detail: map[string]any — произвольные подробности (может быть nil).
func auditWriteRow(app core.App, actor *core.Record, onBehalf, session, action string, detail map[string]any) {
	col, err := app.FindCollectionByNameOrId("seed_audit")
	if err != nil {
		log.Printf("[seed] audit skip (no collection): %s", action)
		return
	}
	rec := core.NewRecord(col)
	if actor != nil {
		rec.Set("actor_id", actor.Id)
		rec.Set("actor_kind", actorKind(actor))
		rec.Set("actor_label", actorLabel(actor))
	} else {
		rec.Set("actor_kind", "guest")
	}
	if onBehalf != "" {
		rec.Set("on_behalf_of", onBehalf)
	}
	if session != "" {
		rec.Set("session", truncRunes(session, 64))
	}
	rec.Set("action", truncRunes(action, 64))
	if detail != nil {
		rec.Set("detail", detail)
	}
	if err := app.Save(rec); err != nil {
		log.Printf("[seed] audit write failed (%s): %v", action, err)
	}
}

// auditWriteConsole пишет строку журнала о действии, выполненном
// консолью сервера (без HTTP и токенов). Актёр помечается видом
// «консоль», чтобы такие строки отличались и от гостей, и от серверных
// событий; источник дополнительно фиксируется в деталях («by»).
// Ошибка журнала никогда не прерывает само действие.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - action: string — имя действия («user.ban», «gateway.set», …);
//   - detail: map[string]any — детали действия (дополняются «by»).
func auditWriteConsole(app core.App, action string, detail map[string]any) {
	col, err := app.FindCollectionByNameOrId("seed_audit")
	if err != nil {
		log.Printf("[seed] audit skip (no collection): %s", action)
		return
	}
	rec := core.NewRecord(col)
	rec.Set("actor_kind", "console")
	rec.Set("actor_label", "console")
	rec.Set("action", truncRunes(action, 64))
	if detail == nil {
		detail = map[string]any{}
	}
	detail["by"] = "console"
	rec.Set("detail", detail)
	if err := app.Save(rec); err != nil {
		log.Printf("[seed] audit write failed (%s): %s", action, err)
	}
}

// resolveAuditSession выясняет сессию текущего запроса: у обычных
// юзеров и маски — по куке (кука маски несёт маска-сессию), у
// суперюзера — по маркеру носимого токена. Возвращает также «от чьего
// имени» для маски.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: string — ид сессии (грант) или "";
// string — «от чьего имени» или "".
func resolveAuditSession(e *core.RequestEvent) (string, string) {
	if sess := currentSessionByCookie(e); sess != nil {
		return asStr(sess.Get("grant_id")), asStr(sess.Get("on_behalf_of"))
	}
	if e.Auth != nil && e.Auth.IsSuperuser() {
		if sess := superuserSessionByToken(e.App, bearerToken(e)); sess != nil {
			return asStr(sess.Get("grant_id")), ""
		}
	}
	return "", ""
}

// auditLogAs пишет одну строку в журнал с явно указанным исполнителем.
// Исполнитель может быть nil — тогда строка помечается «гость» (так
// пишутся события входа: до выпуска токена записи авторизации ещё нет).
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса (кука маски, хранилище);
//   - actor: *core.Record — исполнитель (может быть nil);
//   - action: string — имя действия, напр. "records.update";
//   - detail: map[string]any — произвольные подробности (может быть nil).
func auditLogAs(e *core.RequestEvent, actor *core.Record, action string, detail map[string]any) {
	if e == nil {
		return
	}
	session, onBehalf := resolveAuditSession(e)
	auditWriteRow(e.App, actor, onBehalf, session, action, detail)
}

// auditLog пишет строку в журнал; исполнитель — текущая авторизация
// запроса (может отсутствовать у гостевых запросов).
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса;
//   - action: string — имя действия;
//   - detail: map[string]any — подробности (может быть nil).
func auditLog(e *core.RequestEvent, action string, detail map[string]any) {
	if e == nil {
		return
	}
	auditLogAs(e, e.Auth, action, detail)
}

// auditSkipCollection сообщает, нужно ли пропускать коллекцию в
// сквозном аудите записей. Пропускается сам журнал (иначе правка
// журнала суперюзером порождала бы строки о самой себе) и служебные
// таблицы PocketBase, кроме `_superusers`: правки операторских
// аккаунтов через панель тоже должны быть видны в журнале.
//
// Параметры:
//   - name: string — имя коллекции.
//
// Возвращает: bool — пропускать ли коллекцию.
func auditSkipCollection(name string) bool {
	if name == "seed_audit" {
		return true
	}
	return strings.HasPrefix(name, "_") && name != "_superusers"
}

// changedFieldNames собирает имена полей, чьё значение отличается между
// двумя состояниями записи (ид и автодаты не учитываются: `updated_at`
// двигается на каждой правке и содержательной информацией не является).
//
// Параметры:
//   - orig: *core.Record — состояние до изменения;
//   - rec: *core.Record — состояние после изменения.
//
// Возвращает: []string — имена изменённых полей (может быть пустым).
func changedFieldNames(orig, rec *core.Record) []string {
	var out []string
	for _, f := range rec.Collection().Fields {
		name := f.GetName()
		if name == core.FieldNameId {
			continue
		}
		if _, isAuto := f.(*core.AutodateField); isAuto {
			continue
		}
		if !reflect.DeepEqual(orig.Get(name), rec.Get(name)) {
			out = append(out, name)
		}
	}
	return out
}

// protectAuditCollection делает журнал неизменяемым через REST для ВСЕХ,
// включая суперюзера и панель: создание, правка и удаление строк
// отклоняются (403). Журнал — приложение к истории: пишет в него только
// сервер (сквозной хук и события входа), а стирает только фоновая
// очистка по истечении срока хранения. Обычные правила коллекций тут не
// помогают (для суперюзера правил нет), поэтому отказ ставится в самих
// обработчиках запросов.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func protectAuditCollection(app core.App) {
	block := func(e *core.RecordRequestEvent) error {
		return seedErr(e.RequestEvent, 403, "audit_immutable")
	}
	app.OnRecordCreateRequest("seed_audit").BindFunc(block)
	app.OnRecordUpdateRequest("seed_audit").BindFunc(block)
	app.OnRecordDeleteRequest("seed_audit").BindFunc(block)

	// Чтение журнала: суперюзер (правил для него нет) и роль «admin»
	// (её пускает правило коллекции). Правило — фильтр, а не заслон:
	// прочим оно вернуло бы пустой список, поэтому не-администраторам
	// ставится жёсткий отказ.
	gate := func(e *core.RecordRequestEvent) error {
		if !seedAdmin(e.Auth) {
			return seedErr(e.RequestEvent, 403, "forbidden")
		}
		return e.Next()
	}
	app.OnRecordsListRequest("seed_audit").BindFunc(func(e *core.RecordsListRequestEvent) error {
		if !seedAdmin(e.Auth) {
			return seedErr(e.RequestEvent, 403, "forbidden")
		}
		return e.Next()
	})
	app.OnRecordViewRequest("seed_audit").BindFunc(gate)
}

// installAuditHooks подключает сквозной аудит записей через REST:
// создание, изменение и удаление в ЛЮБОЙ коллекции любым действующим
// лицом — обычным юзером, модератором, админом, суперюзером из панели
// и даже гостем, если правила коллекции ему что-то разрешают.
// Логируются только состоявшиеся операции: обработчик обёрнут вокруг
// цепочки, и строка пишется после успешного сохранения. Отказы (403,
// ошибки валидации) в строки не попадают. Если действие выполнено под
// маской, строка несёт «от чьего имени».
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func installAuditHooks(app core.App) {
	app.OnRecordCreateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if auditSkipCollection(e.Collection.Name) {
			return e.Next()
		}
		err := e.Next()
		if err == nil {
			auditLog(e.RequestEvent, "records.create", map[string]any{
				"collection": e.Collection.Name, "id": e.Record.Id,
			})
		}
		return err
	})

	app.OnRecordUpdateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if auditSkipCollection(e.Collection.Name) {
			return e.Next()
		}
		// Состояние «до» читается ДО сохранения (после — уже не отличить).
		orig, _ := e.App.FindRecordById(e.Collection.Name, e.Record.Id)
		err := e.Next()
		if err == nil {
			detail := map[string]any{"collection": e.Collection.Name, "id": e.Record.Id}
			if orig != nil {
				detail["fields"] = changedFieldNames(orig, e.Record)
			}
			auditLog(e.RequestEvent, "records.update", detail)
		}
		return err
	})

	app.OnRecordDeleteRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if auditSkipCollection(e.Collection.Name) {
			return e.Next()
		}
		err := e.Next()
		if err == nil {
			auditLog(e.RequestEvent, "records.delete", map[string]any{
				"collection": e.Collection.Name, "id": e.Record.Id,
			})
		}
		return err
	})
}

// rulesSnapshot снимает состояние правил доступа коллекции для
// последующего сравнения (указатели разыменовываются в строки;
// отсутствующее правило — пустая строка с отдельной меткой, чтобы
// отличать «правила нет» от «правило пустое» = публичное).
//
// Параметры:
//   - c: *core.Collection — коллекция.
//
// Возвращает: map[string]string — снимок правил по именам.
func rulesSnapshot(c *core.Collection) map[string]string {
	out := map[string]string{}
	for name, rule := range map[string]*string{
		"listRule":   c.ListRule,
		"viewRule":   c.ViewRule,
		"createRule": c.CreateRule,
		"updateRule": c.UpdateRule,
		"deleteRule": c.DeleteRule,
	} {
		if rule == nil {
			out[name] = "\x00nil"
		} else {
			out[name] = *rule
		}
	}
	return out
}

// fieldNames собирает имена полей коллекции.
//
// Параметры:
//   - c: *core.Collection — коллекция.
//
// Возвращает: map[string]bool — множество имён полей.
func fieldNames(c *core.Collection) map[string]bool {
	out := make(map[string]bool, len(c.Fields))
	for _, f := range c.Fields {
		out[f.GetName()] = true
	}
	return out
}

// installCollectionAuditHooks подключает журнал к операциям с самими
// коллекциями: создание, правка (включая изменения правил доступа и
// набора полей из панели) и удаление. Это покрытие «служебных» правок
// панели, которые не проходят через обычный список записей.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func installCollectionAuditHooks(app core.App) {
	app.OnCollectionCreateRequest().BindFunc(func(e *core.CollectionRequestEvent) error {
		err := e.Next()
		if err == nil && e.Collection != nil {
			auditLog(e.RequestEvent, "collections.create", map[string]any{
				"collection": e.Collection.Name, "id": e.Collection.Id,
			})
		}
		return err
	})

	app.OnCollectionUpdateRequest().BindFunc(func(e *core.CollectionRequestEvent) error {
		var origRules map[string]string
		var origFields map[string]bool
		if e.Collection != nil {
			// Состояние «до» читается из базы ДО сохранения.
			if orig, err := e.App.FindCollectionByNameOrId(e.Collection.Name); err == nil {
				origRules = rulesSnapshot(orig)
				origFields = fieldNames(orig)
			}
		}
		err := e.Next()
		if err == nil && e.Collection != nil {
			detail := map[string]any{"collection": e.Collection.Name, "id": e.Collection.Id}
			if origRules != nil {
				var changed []string
				for name, before := range origRules {
					after := rulesSnapshot(e.Collection)[name]
					if before != after {
						changed = append(changed, name)
					}
				}
				sort.Strings(changed)
				detail["rules"] = changed
			}
			if origFields != nil {
				nowFields := fieldNames(e.Collection)
				var added, removed []string
				for name := range nowFields {
					if !origFields[name] {
						added = append(added, name)
					}
				}
				for name := range origFields {
					if !nowFields[name] {
						removed = append(removed, name)
					}
				}
				sort.Strings(added)
				sort.Strings(removed)
				if len(added) > 0 {
					detail["fields_added"] = added
				}
				if len(removed) > 0 {
					detail["fields_removed"] = removed
				}
			}
			auditLog(e.RequestEvent, "collections.update", detail)
		}
		return err
	})

	app.OnCollectionDeleteRequest().BindFunc(func(e *core.CollectionRequestEvent) error {
		name, id := "", ""
		if e.Collection != nil {
			name, id = e.Collection.Name, e.Collection.Id
		}
		err := e.Next()
		if err == nil {
			auditLog(e.RequestEvent, "collections.delete", map[string]any{
				"collection": name, "id": id,
			})
		}
		return err
	})
}

// installStockAuthAuditHooks закрывает штатные точки входа
// PocketBase для коллекции `users`: пароль, одноразовый код, OAuth2 и
// обновление токена. Основной вход юзеров — гейтвей (эц25519), но
// штатные эндпоинты тоже существуют и наблюдаются как все: успех,
// неудача и продление токена пишутся в журнал.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func installStockAuthAuditHooks(app core.App) {
	app.OnRecordAuthWithPasswordRequest("users").BindFunc(func(e *core.RecordAuthWithPasswordRequestEvent) error {
		err := e.Next()
		if err != nil {
			auditLogAs(e.RequestEvent, nil, "auth.api_login_failed", map[string]any{
				"collection": "users", "identity": truncRunes(e.Identity, 255),
				"method": "password", "ip_masked": maskIP(e.RealIP()),
			})
			return err
		}
		auditLog(e.RequestEvent, "auth.api_login", map[string]any{
			"collection": "users", "method": "password", "ip_masked": maskIP(e.RealIP()),
		})
		return nil
	})

	app.OnRecordAuthWithOTPRequest("users").BindFunc(func(e *core.RecordAuthWithOTPRequestEvent) error {
		err := e.Next()
		if err != nil {
			auditLogAs(e.RequestEvent, nil, "auth.api_login_failed", map[string]any{
				"collection": "users", "method": "otp", "ip_masked": maskIP(e.RealIP()),
			})
			return err
		}
		auditLog(e.RequestEvent, "auth.api_login", map[string]any{
			"collection": "users", "method": "otp", "ip_masked": maskIP(e.RealIP()),
		})
		return nil
	})

	app.OnRecordAuthWithOAuth2Request("users").BindFunc(func(e *core.RecordAuthWithOAuth2RequestEvent) error {
		err := e.Next()
		if err != nil {
			auditLogAs(e.RequestEvent, nil, "auth.api_login_failed", map[string]any{
				"collection": "users", "method": "oauth2",
				"provider": e.ProviderName, "ip_masked": maskIP(e.RealIP()),
			})
			return err
		}
		auditLog(e.RequestEvent, "auth.api_login", map[string]any{
			"collection": "users", "method": "oauth2",
			"provider": e.ProviderName, "ip_masked": maskIP(e.RealIP()),
		})
		return nil
	})

	// Штатное продление токена в обход гейтвея — тоже наблюдаемо.
	app.OnRecordAuthRefreshRequest("users").BindFunc(func(e *core.RecordAuthRefreshRequestEvent) error {
		err := e.Next()
		if err == nil {
			auditLog(e.RequestEvent, "auth.api_refresh", map[string]any{
				"collection": "users", "ip_masked": maskIP(e.RealIP()),
			})
		}
		return err
	})
}
