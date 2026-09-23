package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/types"
)

// ============================================================ SafeQuery
//
// SafeQuery — обёртка над FindRecordsByFilter, которая ВСЕГДА добавляет
// фильтр мягкого удаления. Вторая такая же точка — курсорный слой
// (CursorRecords): не-суперюзеру удалённые записи не выдаёт и он.
//
// Права:
//   - суперюзер — видит всё, включая удалённые записи;
//   - обычный пользователь — видит только неудалённые.
//
// Семантика метки удаления:
//   - поле называется `deleted_at` (DateField);
//   - запись жива    ⇔ значение пустое ('' в SQLite; NULL допускается как
//     защита от ручных правок);
//   - запись удалена ⇔ непустая дата.
//
// Все фильтры пишутся на языке PB (fexpr: `&&`, `||`, `= null`), НЕ на SQL.

// softDeleteWhitelist — реестр коллекций с мягким удалением.
// Только перечисленные здесь коллекции получают поле `deleted_at`,
// перехватчик DELETE и автофильтрацию в SafeQuery. Коллекции вне списка
// считаются обычными — для них фильтр не добавляется.
//
// Состав НЕ описывается вручную: он производный от единого реестра
// схемы (schema_registry.go) — коллекции с пометкой SoftDelete. Тесты
// могут временно добавлять сюда свои коллекции (см. withNotes).
var softDeleteWhitelist = buildSoftDeleteWhitelist()

// buildSoftDeleteWhitelist собирает реестр мягкого удаления из реестра
// схемы: все коллекции с пометкой SoftDelete.
//
// Возвращает: map[string]bool — имя коллекции → поддержка мягкого
// удаления.
func buildSoftDeleteWhitelist() map[string]bool {
	m := make(map[string]bool)
	for i := range seedSchema {
		if seedSchema[i].SoftDelete {
			m[seedSchema[i].Name] = true
		}
	}
	return m
}

// softDeleteOwnerField — поле-владелец в коллекции, используемое при
// проверке прав на восстановление (значение — имя поля, например "user").
// Если для коллекции поле не задано, обычный пользователь не может
// восстанавливать её записи вовсе (запрет по умолчанию).
var softDeleteOwnerField = map[string]string{
	"seed_sessions": "user",
}

// isSoftDeleted сообщает, помечена ли запись как удалённая.
//
// Параметры:
//   - rec: *core.Record — запись (допускается nil).
//
// Возвращает:
//   - bool — true, если `deleted_at` содержит непустую дату.
//
// Понимает все варианты значения поля: types.DateTime, time.Time, строку.
// Это единая точка проверки «запись удалена» для всего проекта.
func isSoftDeleted(rec *core.Record) bool {
	if rec == nil {
		return false
	}
	switch v := rec.Get("deleted_at").(type) {
	case types.DateTime:
		return !v.IsZero()
	case time.Time:
		return !v.IsZero()
	case string:
		return v != ""
	case nil:
		return false
	default:
		return false
	}
}

// deletedAtTime возвращает момент удаления записи.
//
// Параметры:
//   - rec: *core.Record — запись с полем `deleted_at`.
//
// Возвращает:
//   - time.Time — время удаления (нулевое, если запись не удалена);
//   - bool — удалена ли запись вообще.
//
// Используется для 30-секундного окна самостоятельного восстановления.
// Нераспознаваемое непустое значение трактуется как удаление (закрытая
// модель отказов).
func deletedAtTime(rec *core.Record) (time.Time, bool) {
	switch v := rec.Get("deleted_at").(type) {
	case types.DateTime:
		if v.IsZero() {
			return time.Time{}, false
		}
		return v.Time(), true
	case time.Time:
		if v.IsZero() {
			return time.Time{}, false
		}
		return v, true
	case string:
		if v == "" {
			return time.Time{}, false
		}
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			if t, err = time.Parse(time.RFC3339, v); err != nil {
				if t, err = time.Parse(types.DefaultDateLayout, v); err != nil {
					return time.Time{}, true // мусор считаем удалением (закрытая модель)
				}
			}
		}
		return t, true
	default:
		return time.Time{}, false
	}
}

// SafeQueryBuilder — конструктор запроса с автоматическим фильтром
// мягкого удаления. Создаётся функцией SafeQuery, методы цепочки
// возвращают сам билдер.
type SafeQueryBuilder struct {
	app            core.App
	isSuperuser    bool
	collection     string
	filter         string
	sort           string
	limit          int
	params         dbx.Params
	includeDeleted bool
}

// SafeQuery создаёт билдер запроса к коллекции.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - isSuperuser: bool — если true, удалённые записи не скрываются;
//   - collection: string — имя коллекции (например, "seed_sessions").
//
// Возвращает: *SafeQueryBuilder — цепочка .Where().Sort().Limit().Find().
//
// Пример:
//
//	records, err := SafeQuery(e.App, e.Auth.IsSuperuser(), "seed_sessions").
//	    Where("user = {:uid}", dbx.Params{"uid": e.Auth.Id}).
//	    Sort("-created_at").
//	    Limit(50).
//	    Find()
func SafeQuery(app core.App, isSuperuser bool, collection string) *SafeQueryBuilder {
	return &SafeQueryBuilder{
		app:         app,
		isSuperuser: isSuperuser,
		collection:  collection,
		limit:       50,
		params:      dbx.Params{},
	}
}

// Where задаёт fexpr-фильтр запроса (вызывать один раз).
//
// Параметры:
//   - filter: string — выражение фильтра, напр. "user = {:uid}";
//   - params: ...dbx.Params — подставляемые значения ({:имя}).
//
// Возвращает: *SafeQueryBuilder — тот же билдер для цепочки.
func (q *SafeQueryBuilder) Where(filter string, params ...dbx.Params) *SafeQueryBuilder {
	q.filter = filter
	for _, p := range params {
		for k, v := range p {
			q.params[k] = v
		}
	}
	return q
}

// Sort задаёт сортировку результата.
//
// Параметры:
//   - sort: string — поле и направление, напр. "-created_at" (по убыванию).
//
// Возвращает: *SafeQueryBuilder — тот же билдер для цепочки.
func (q *SafeQueryBuilder) Sort(sort string) *SafeQueryBuilder {
	q.sort = sort
	return q
}

// Limit задаёт максимальное число записей (по умолчанию 50).
//
// Параметры:
//   - limit: int — количество записей.
//
// Возвращает: *SafeQueryBuilder — тот же билдер для цепочки.
func (q *SafeQueryBuilder) Limit(limit int) *SafeQueryBuilder {
	q.limit = limit
	return q
}

// IncludeDeleted разрешает видеть удалённые записи. Доступно ТОЛЬКО
// суперюзеру: на обычном пользователе метод паникует (защита от
// случайной выдачи удалённого).
//
// Возвращает: *SafeQueryBuilder — тот же билдер для цепочки.
func (q *SafeQueryBuilder) IncludeDeleted() *SafeQueryBuilder {
	if !q.isSuperuser {
		panic("IncludeDeleted() только для superuser")
	}
	q.includeDeleted = true
	return q
}

// buildFilter собирает итоговый фильтр: к пользовательскому условию
// для не-администратора автоматически дописывается условие
// «запись не удалена» на языке fexpr.
//
// Возвращает: string — готовый фильтр для FindRecordsByFilter.
func (q *SafeQueryBuilder) buildFilter() string {
	f := q.filter
	// Автоматический фильтр мягкого удаления для не-админов.
	if !q.includeDeleted && !q.isSuperuser && softDeleteWhitelist[q.collection] {
		sd := `(deleted_at = null || deleted_at = "")`
		if f == "" {
			return sd
		}
		return "(" + f + ") && " + sd
	}
	return f
}

// Find выполняет SELECT и возвращает записи.
//
// Возвращает:
//   - []*core.Record — найденные записи (пустой срез, если ничего нет);
//   - error — ошибка выполнения запроса.
func (q *SafeQueryBuilder) Find() ([]*core.Record, error) {
	return q.app.FindRecordsByFilter(
		q.collection, q.buildFilter(), q.sort, q.limit, 0, q.params,
	)
}

// Count выполняет SELECT COUNT(*) и возвращает количество подходящих
// записей. Реализован сырым SQL: коллекция и фильтр попадают сюда
// только из кода, никогда из пользовательского ввода.
//
// Возвращает:
//   - int — число записей;
//   - error — ошибка выполнения запроса.
func (q *SafeQueryBuilder) Count() (int, error) {
	var count int
	query := "SELECT count(*) FROM " + q.collection
	if f := q.buildFilter(); f != "" {
		query += " WHERE " + f
	}
	err := q.app.DB().NewQuery(query).Bind(q.params).Row(&count)
	return count, err
}

// ============================================================ Мягкое удаление (хуки)

// softDeleteExpiry — срок хранения мягко удалённых записей до
// физической очистки сборщиком мусора (30 дней).
const softDeleteExpiry = 30 * 24 * time.Hour

// softDeleteUndoWindow — время, в течение которого владелец может сам
// восстановить запись без администратора (отсчёт от `deleted_at`).
const softDeleteUndoWindow = 30 * time.Second

// ctxKeyHardDelete — ключ контекста, включающий физическое удаление
// в обход перехватчика мягкого удаления.
type ctxKeyHardDelete struct{}

// withHardDelete помечает контекст: следующее удаление должно
// выполниться физически.
//
// Параметры:
//   - ctx: context.Context — исходный контекст.
//
// Возвращает: context.Context — контекст с флагом физического удаления.
func withHardDelete(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyHardDelete{}, true)
}

// isHardDelete проверяет, стоит ли в контексте флаг физического удаления.
//
// Параметры:
//   - ctx: context.Context — контекст операции удаления.
//
// Возвращает: bool — true, если удаление должно быть физическим.
func isHardDelete(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyHardDelete{}).(bool)
	return v
}

// softDeleteHook возвращает перехватчик события удаления для одной
// коллекции: ставит `deleted_at = now()` и отменяет физическое удаление.
// Если в контексте стоит флаг withHardDelete или запись уже удалена —
// пропускает операцию к реальному DELETE (путь админ-чистки и GC).
// Для seed_sessions дополнительно выставляется `revoked = true`.
//
// Параметры:
//   - colName: string — имя коллекции, для которой создаётся хук.
//
// Возвращает: обработчик события *core.RecordEvent (формат, который
// принимает app.OnRecordDelete(colName).BindFunc).
func softDeleteHook(colName string) func(*core.RecordEvent) error {
	return func(e *core.RecordEvent) error {
		// Путь физического удаления (админ-чистка).
		if isHardDelete(e.Context) {
			return e.Next()
		}
		// Уже мягко удалена: разрешаем физическое удаление (сборщик
		// мусора или повторный админский DELETE).
		if isSoftDeleted(e.Record) {
			return e.Next()
		}
		// Мягкое удаление: ставим метку и отменяем физический DELETE.
		e.Record.Set("deleted_at", time.Now().UTC().Format(time.RFC3339Nano))
		if colName == "seed_sessions" {
			e.Record.Set("revoked", true)
		}
		if err := e.App.UnsafeWithoutHooks().SaveNoValidate(e.Record); err != nil {
			log.Printf("[seed] ERROR: soft delete %s/%s: %v", colName, e.Record.Id, err)
			return err
		}
		log.Printf("[seed] soft deleted %s/%s", colName, e.Record.Id)
		return nil // отменяем физическое удаление
	}
}

// installSoftDeleteHooks регистрирует перехватчики мягкого удаления
// для всех коллекций из реестра. Вызывается один раз при старте.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func installSoftDeleteHooks(app core.App) {
	for col := range softDeleteWhitelist {
		app.OnRecordDelete(col).BindFunc(softDeleteHook(col))
	}
	log.Printf("[seed] soft delete hooks installed for %d collections", len(softDeleteWhitelist))
}

// softDeleteGC физически удаляет записи, мягко удалённые более 30 дней
// назад. Живые записи не затрагиваются: условие явно исключает пустые
// значения `deleted_at`. Запускается сборщиком мусора по таймеру.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func softDeleteGC(app core.App) {
	cutoff := time.Now().Add(-softDeleteExpiry).UTC().Format(time.RFC3339Nano)
	for col := range softDeleteWhitelist {
		result, err := app.NonconcurrentDB().NewQuery(
			"DELETE FROM " + col + " WHERE deleted_at IS NOT NULL AND deleted_at != '' AND deleted_at < {:cutoff}",
		).Bind(dbx.Params{"cutoff": cutoff}).Execute()
		if err != nil {
			log.Printf("[seed] ERROR: soft delete gc %s: %v", col, err)
			continue
		}
		n, _ := result.RowsAffected()
		if n > 0 {
			log.Printf("[seed] soft delete gc: %s purged %d rows", col, n)
		}
	}
}

// ============================================================ Физическое удаление

// HardDeleteRecords физически удаляет записи в обход мягкого удаления.
// Доступно только суперюзеру (проверяет вызывающий эндпоинт).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - collection: string — имя коллекции (должна быть в реестре мягкого
//     удаления, иначе ошибка);
//   - ids: []string — идентификаторы записей.
//
// Возвращает:
//   - int — сколько записей реально удалено;
//   - error — ошибка (например, коллекция не поддерживает мягкое удаление).
func HardDeleteRecords(app core.App, collection string, ids []string) (int, error) {
	if !softDeleteWhitelist[collection] {
		return 0, fmt.Errorf("collection %s does not support soft delete", collection)
	}
	n := 0
	ctx := withHardDelete(context.Background())
	for _, id := range ids {
		rec, err := app.FindRecordById(collection, id)
		if err != nil {
			continue // пропускаем несуществующие
		}
		if err := app.DeleteWithContext(ctx, rec); err != nil {
			log.Printf("[seed] hard delete %s/%s failed: %v", collection, id, err)
			continue
		}
		n++
	}
	return n, nil
}

// ============================================================ Восстановление

// RestoreRecords восстанавливает мягко удалённые записи, очищая
// поле `deleted_at`.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - collection: string — имя коллекции (должна быть в реестре);
//   - ids: []string — идентификаторы записей;
//   - authID: string — id пользователя, выполняющего восстановление;
//   - isSuperuser: bool — суперюзер восстанавливает без ограничений.
//
// Возвращает:
//   - int — сколько записей восстановлено;
//   - error — ошибка (коллекция вне реестра мягкого удаления).
//
// Правила: обычный пользователь восстанавливает только СВОИ записи
// (поле-владелец из реестра) и только в течение 30 секунд от момента
// удаления (`deleted_at`). Коллекция без известного поля-владельца
// обычным пользователям недоступна (запрет по умолчанию). Отметка
// `revoked` у сессий при восстановлении не снимается — требуется
// повторный вход.
func RestoreRecords(app core.App, collection string, ids []string, authID string, isSuperuser bool) (int, error) {
	if !softDeleteWhitelist[collection] {
		return 0, fmt.Errorf("collection %s does not support soft delete", collection)
	}
	ownerField, knownOwner := softDeleteOwnerField[collection]
	n := 0
	for _, id := range ids {
		rec, err := app.FindRecordById(collection, id)
		if err != nil {
			continue
		}
		deletedAt, deleted := deletedAtTime(rec)
		if !deleted {
			continue // не удалена
		}
		if !isSuperuser {
			// Чужие записи восстанавливать нельзя.
			if !knownOwner || asStr(rec.Get(ownerField)) != authID {
				continue
			}
			// Окно самостоятельного восстановления считается от deleted_at.
			if time.Since(deletedAt) > softDeleteUndoWindow {
				continue // слишком поздно, нужен администратор
			}
		}
		rec.Set("deleted_at", "")
		// Отметку revoked не снимаем — пользователь входит заново.
		if err := app.SaveNoValidate(rec); err != nil {
			log.Printf("[seed] restore %s/%s failed: %v", collection, id, err)
			continue
		}
		n++
	}
	return n, nil
}

// ============================================================ Анализ ссылок (impact)

// ReferenceInfo описывает одну ссылающуюся таблицу: имя коллекции,
// имя поля-связи и количество ссылающихся записей.
type ReferenceInfo struct {
	Collection string `json:"collection"`
	Field      string `json:"field"`
	Count      int    `json:"count"`
}

// ImpactReport — результат анализа «кто ссылается на запись»:
// цель, список ссылок и суммарное число зависимых записей.
type ImpactReport struct {
	Target     string          `json:"target"`
	References []ReferenceInfo `json:"references"`
	Total      int             `json:"total"`
}

// FindRecordImpact возвращает список коллекций и число записей,
// ссылающихся на указанную запись (для оценки последствий удаления).
// Имена таблиц и полей берутся из метаданных PocketBase, значение
// передаётся связанным параметром — инъекция исключена.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - collectionName: string — коллекция целевой записи;
//   - recordId: string — идентификатор записи.
//
// Возвращает:
//   - *ImpactReport — отчёт о зависимостях;
//   - error — коллекция не найдена или ошибка метаданных.
func FindRecordImpact(app core.App, collectionName, recordId string) (*ImpactReport, error) {
	col, err := app.FindCachedCollectionByNameOrId(collectionName)
	if err != nil {
		return nil, err
	}
	refs, err := app.FindCachedCollectionReferences(col)
	if err != nil {
		return nil, err
	}
	report := &ImpactReport{Target: collectionName + "/" + recordId}
	for refCol, fields := range refs {
		for _, field := range fields {
			var count int
			err := app.DB().NewQuery(
				"SELECT count(*) FROM " + refCol.Name + " WHERE " + field.GetName() + " = {:id}",
			).Bind(dbx.Params{"id": recordId}).Row(&count)
			if err != nil {
				continue
			}
			if count > 0 {
				report.References = append(report.References, ReferenceInfo{
					Collection: refCol.Name,
					Field:      field.GetName(),
					Count:      count,
				})
				report.Total += count
			}
		}
	}
	return report, nil
}

// ============================================================ GDPR-стирание

// EraseUser выполняет GDPR-стирание пользователя в одной транзакции:
// сессии и персональные настройки удаляются физически, строка
// пользователя анонимизируется (почта заменяется на служебную, пароль
// перевыпускается случайным) и помечается `deleted_at`.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - userId: string — идентификатор пользователя.
//
// Возвращает: error — ошибка транзакции (пользователь не найден и т.п.).
func EraseUser(app core.App, userId string) error {
	return app.RunInTransaction(func(txApp core.App) error {
		// 1. Физически удаляем сессии пользователя.
		_, _ = txApp.NonconcurrentDB().NewQuery(
			"DELETE FROM seed_sessions WHERE user = {:uid}",
		).Bind(dbx.Params{"uid": userId}).Execute()

		// 2. Физически удаляем персональные настройки пользователя.
		_, _ = txApp.NonconcurrentDB().NewQuery(
			"DELETE FROM seed_settings WHERE user = {:uid}",
		).Bind(dbx.Params{"uid": userId}).Execute()

		// 3. Анонимизируем пользователя: строка остаётся (целостность
		// связей), персональные данные стёрты, факт стирания помечен.
		user, err := txApp.FindRecordById("users", userId)
		if err != nil {
			return err
		}
		user.Set("email", "erased-"+userId[:8]+"@anon.invalid")
		user.Set("password", security.RandomString(48))
		user.Set("banned", false)
		user.Set("ban_reason", "")
		user.Set("banned_until", "")
		user.Set("deleted_at", nowISO())
		if err := txApp.SaveNoValidate(user); err != nil {
			return err
		}

		log.Printf("[seed] GDPR erasure completed: user %s", userId)
		return nil
	})
}

// ============================================================ HTTP-эндпоинты администрирования

// seedHardDelete — POST /api/seed/hard-delete.
// Физическое удаление записей в обход мягкого удаления. Только администратор (суперюзер или роль "admin").
//
// Тело запроса: {collection: string, ids: []string}
// Ответ 200: {ok: true, deleted: int}
// Ошибки: 403 (не суперюзер), 400 (пустое тело / коллекция вне реестра).
func seedHardDelete(e *core.RequestEvent) error {
	if !seedAdmin(e.Auth) {
		return seedErr(e, 403, "forbidden")
	}
	var b struct {
		Collection string   `json:"collection"`
		IDs        []string `json:"ids"`
	}
	_ = e.BindBody(&b)
	if b.Collection == "" || len(b.IDs) == 0 {
		return seedErr(e, 400, "bad_request")
	}
	n, err := HardDeleteRecords(e.App, b.Collection, b.IDs)
	if err != nil {
		return seedErr(e, 400, err.Error())
	}
	auditLog(e, "records.hard_delete", map[string]any{"collection": b.Collection, "ids": b.IDs, "deleted": n})
	return e.JSON(200, map[string]any{"ok": true, "deleted": n})
}

// seedRestore — POST /api/seed/restore.
// Восстановление мягко удалённых записей. Суперюзер — любые записи;
// обычный пользователь — только свои и только в течение 30 секунд от
// `deleted_at` (см. RestoreRecords).
//
// Тело запроса: {collection: string, ids: []string}
// Ответ 200: {ok: true, restored: int}
// Ошибки: 401 (нет токена), 400 (пустое тело / коллекция вне реестра).
func seedRestore(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	var b struct {
		Collection string   `json:"collection"`
		IDs        []string `json:"ids"`
	}
	_ = e.BindBody(&b)
	if b.Collection == "" || len(b.IDs) == 0 {
		return seedErr(e, 400, "bad_request")
	}
	n, err := RestoreRecords(e.App, b.Collection, b.IDs, e.Auth.Id, seedAdmin(e.Auth))
	if err != nil {
		return seedErr(e, 400, err.Error())
	}
	// Журнал ведёт слежку за всеми: и админское восстановление, и
	// самостоятельный возврат своей записи в 30-секундное окно.
	if n > 0 {
		auditLog(e, "records.restore", map[string]any{"collection": b.Collection, "ids": b.IDs, "restored": n})
	}
	return e.JSON(200, map[string]any{"ok": true, "restored": n})
}

// seedImpact — GET /api/seed/impact?collection=<имя>&id=<id записи>.
// Отчёт «кто ссылается на запись» перед удалением. Только администратор (суперюзер или роль "admin").
//
// Ответ 200: *ImpactReport {target, references[], total}
// Ошибки: 403 (не суперюзер), 400 (нет параметров / коллекция не найдена).
func seedImpact(e *core.RequestEvent) error {
	if !seedAdmin(e.Auth) {
		return seedErr(e, 403, "forbidden")
	}
	collection := e.Request.URL.Query().Get("collection")
	id := e.Request.URL.Query().Get("id")
	if collection == "" || id == "" {
		return seedErr(e, 400, "bad_request")
	}
	report, err := FindRecordImpact(e.App, collection, id)
	if err != nil {
		return seedErr(e, 400, err.Error())
	}
	return e.JSON(200, report)
}

// seedErase — POST /api/seed/erase.
// GDPR-стирание пользователя (см. EraseUser). Только администратор (суперюзер или роль "admin").
//
// Тело запроса: {user_id: string}
// Ответ 200: {ok: true}
// Ошибки: 403 (не суперюзер), 400 (нет user_id), 500 (ошибка стирания).
func seedErase(e *core.RequestEvent) error {
	if !seedAdmin(e.Auth) {
		return seedErr(e, 403, "forbidden")
	}
	var b struct {
		UserID string `json:"user_id"`
	}
	_ = e.BindBody(&b)
	if b.UserID == "" {
		return seedErr(e, 400, "bad_request")
	}
	if err := EraseUser(e.App, b.UserID); err != nil {
		return seedErr(e, 500, "erase_failed")
	}
	auditLog(e, "users.erase", map[string]any{"user_id": b.UserID})
	return e.JSON(200, map[string]any{"ok": true})
}

// seedDeletedParamAllow — белый список параметров /api/seed/deleted
// ("collection" проверяется отдельно). Неизвестный параметр — 400.
var seedDeletedParamAllow = map[string]bool{
	"limit":  true,
	"cursor": true,
	"sort":   true,
}

// seedDeletedSortAllow — колонки, разрешённые для сортировки списка
// надгробий (каждая — с префиксом "-" для убывания).
var seedDeletedSortAllow = map[string]bool{
	"deleted_at": true,
	"created_at": true,
	"updated_at": true,
}

// parseSeedDeletedSort разбирает параметр sort списка надгробий по
// белому списку колонок.
//
// Параметры:
//   - sort: string — значение ?sort= ("" → по умолчанию -deleted_at).
//
// Возвращает:
//   - []CursorSort — план сортировки;
//   - error — errCursorPlan при недопустимой колонке.
func parseSeedDeletedSort(sort string) ([]CursorSort, error) {
	if sort == "" {
		sort = "-deleted_at"
	}
	tokens := strings.Split(sort, ",")
	if len(tokens) > 2 {
		return nil, fmt.Errorf("%w: не больше 2 колонок", errCursorPlan)
	}
	out := make([]CursorSort, 0, len(tokens))
	seen := make(map[string]bool, len(tokens))
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		desc := strings.HasPrefix(tok, "-")
		name := strings.TrimLeft(tok, "-+")
		if !seedDeletedSortAllow[name] {
			return nil, fmt.Errorf("%w: %q", errCursorPlan, name)
		}
		if seen[name] {
			return nil, fmt.Errorf("%w: дубль %q", errCursorPlan, name)
		}
		seen[name] = true
		out = append(out, CursorSort{Column: name, Desc: desc})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: пусто", errCursorPlan)
	}
	return out, nil
}

// seedDeleted — GET /api/seed/deleted?collection=<имя>: список мягко
// удалённых записей коллекции с курсорной пагинацией. Только администратор (суперюзер или роль "admin").
// Формат ответа прежний (массив минимальных объектов); курсор
// следующей страницы — заголовок X-Next-Cursor.
//
// Параметры запроса (все необязательные; неизвестные — 400):
//   - collection: имя коллекции из реестра мягкого удаления (обязателен
//     по смыслу, его отсутствие — 400);
//   - limit: 1..200 (по умолчанию 50);
//   - cursor: курсор из X-Next-Cursor предыдущего ответа;
//   - sort: deleted_at | created_at | updated_at, "-" — по убыванию
//     (по умолчанию -deleted_at); разграничитель id дописывается сам.
//
// Ответ 200: [{id, deleted_at, created_at, updated_at}, ...]
// Ошибки: 403 (не суперюзер), 400 (коллекция вне реестра, параметры,
// курсор), 500 (хранилище).
func seedDeleted(e *core.RequestEvent) error {
	if !seedAdmin(e.Auth) {
		return seedErr(e, 403, "forbidden")
	}
	q := e.Request.URL.Query()
	collection := q.Get("collection")
	if collection == "" || !softDeleteWhitelist[collection] {
		return seedErr(e, 400, "bad_collection")
	}
	for key := range q {
		if key != "collection" && !seedDeletedParamAllow[key] {
			return seedErr(e, 400, "unknown_param")
		}
	}
	limit := 50
	if ls := q.Get("limit"); ls != "" {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 || n > 200 {
			return seedErr(e, 400, "bad_limit")
		}
		limit = n
	}
	sorts, err := parseSeedDeletedSort(q.Get("sort"))
	if err != nil {
		return seedErr(e, 400, "bad_sort")
	}
	requestInfo, err := e.RequestInfo()
	if err != nil {
		return seedErr(e, 500, "request_info_failed")
	}
	col, err := e.App.FindCollectionByNameOrId(collection)
	if err != nil {
		return seedErr(e, 500, "store_failed")
	}
	res, err := CursorRecords(e.App, col, requestInfo, false,
		`deleted_at != null && deleted_at != ""`, nil, sorts, q.Get("cursor"), limit)
	if err != nil {
		if errors.Is(err, errCursorValue) || errors.Is(err, errCursorPlan) ||
			errors.Is(err, errCursorLimit) {
			return seedErr(e, 400, "bad_cursor")
		}
		return seedErr(e, 500, "store_failed")
	}
	out := make([]map[string]any, 0, len(res.Records))
	for _, r := range res.Records {
		out = append(out, map[string]any{
			"id":         r.Id,
			"deleted_at": r.Get("deleted_at"),
			"created_at": r.Get("created_at"),
			"updated_at": r.Get("updated_at"),
		})
	}
	if res.NextCursor != "" {
		e.Response.Header().Set("X-Next-Cursor", res.NextCursor)
	}
	return e.JSON(200, out)
}

// ============================================================ Помощники схемы БД

// softDeleteField возвращает описание поля `deleted_at` (дата)
// для добавления в коллекцию.
//
// Возвращает: *core.DateField — поле с именем "deleted_at".
func softDeleteField() *core.DateField {
	return &core.DateField{Name: "deleted_at"}
}

// renameField переименовывает поле существующей коллекции. Используется
// при миграции развёрнутых баз: PocketBase переименовывает колонку
// таблицы по внутреннему id поля при сохранении коллекции, данные
// сохраняются. Если старого поля нет или новое уже существует —
// операция пропускается (идемпотентность).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - colName: string — имя коллекции;
//   - oldName: string — текущее имя поля;
//   - newName: string — новое имя поля.
//
// Возвращает:
//   - bool — было ли поле переименовано;
//   - error — коллекция не найдена или ошибка сохранения.
func renameField(app core.App, colName, oldName, newName string) (bool, error) {
	col, err := app.FindCollectionByNameOrId(colName)
	if err != nil {
		return false, err
	}
	old := col.Fields.GetByName(oldName)
	if old == nil || col.Fields.GetByName(newName) != nil {
		return false, nil // нечего мигрировать
	}
	old.SetName(newName)
	if err := app.Save(col); err != nil {
		return false, err
	}
	log.Printf("[seed] field renamed: %s.%s -> %s", colName, oldName, newName)
	return true, nil
}

// Примечание: поле `deleted_at`, его легаси-переименование
// (`deleted` → `deleted_at`) и индексы фильтрации удалённых записей
// объявлены в едином реестре схемы (schema_registry.go) и
// подтверждаются при каждом старте в syncSeedSchema.
