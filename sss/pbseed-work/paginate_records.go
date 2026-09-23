package main

// paginate_records.go — курсорная пагинация записей коллекций (слой 2)
// и HTTP-обработчики (слой 3).
//
// Слой 2 повторяет путь штатного списка записей (правила коллекции,
// клиентский фильтр на языке fexpr через core.NewRecordFieldResolver,
// скрытие мягко удалённых), но вместо OFFSET использует курсорное ядро
// из paginate.go.
//
// Обработчики:
//   - recordsCursor  — GET /api/collections/{collection}/records/cursor
//     (соседний к штатному списку; права и язык фильтра — штатные);
//   - seedSessions   — GET /api/seed/sessions (свои сессии; белый
//     список параметров, курсор в заголовке X-Next-Cursor).

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/search"
)

// cursorRecordsDefaultLimit — размер страницы по умолчанию для
// курсорного эндпоинта штатных коллекций.
const cursorRecordsDefaultLimit = 30

// cursorSortFieldAllowed сообщает, годится ли поле коллекции как
// колонка курсорной сортировки. Разрешены скалярные типы, чьё
// значение в записи совпадает с хранимым в БД представлением;
// отношение — только одиночное (списки значений не годятся).
//
// Параметры:
//   - f: core.Field — поле коллекции.
//
// Возвращает: bool — можно ли сортировать по этому полю курсором.
func cursorSortFieldAllowed(f core.Field) bool {
	switch t := f.(type) {
	case *core.TextField, *core.EmailField, *core.URLField,
		*core.DateField, *core.AutodateField, *core.NumberField, *core.BoolField:
		return true
	case *core.RelationField:
		return t.MaxSelect == 1
	default:
		return false
	}
}

// validateRecordsSorts проверяет план сортировки по полям коллекции:
// колонка существует (или это "id") и тип поля поддерживается; скрытые
// поля доступны только суперюзеру (как в штатном списке).
//
// Параметры:
//   - collection: *core.Collection — коллекция;
//   - sorts: []CursorSort — план сортировки;
//   - superuser: bool — запрос от суперюзера.
//
// Возвращает: error — errCursorPlan при нарушении, иначе nil.
func validateRecordsSorts(collection *core.Collection, sorts []CursorSort, superuser bool) error {
	if err := validateSortPlan(sorts); err != nil {
		return err
	}
	for _, s := range sorts {
		if s.Column == core.FieldNameId {
			continue
		}
		f := collection.Fields.GetByName(s.Column)
		if f == nil {
			return fmt.Errorf("%w: нет колонки %q", errCursorPlan, s.Column)
		}
		if !cursorSortFieldAllowed(f) {
			return fmt.Errorf("%w: тип поля %q не поддерживает курсор", errCursorPlan, s.Column)
		}
		if f.GetHidden() && !superuser {
			return fmt.Errorf("%w: скрытое поле %q", errCursorPlan, s.Column)
		}
	}
	return nil
}

// cursorRecordValue извлекает значение колонки курса из записи в том
// виде, в каком оно хранится в БД (для корректного сравнения при
// повторной подстановке параметром).
//
// Параметры:
//   - rec: *core.Record — запись;
//   - collection: *core.Collection — коллекция записи;
//   - col: string — колонка плана сортировки.
//
// Возвращает:
//   - string — значение в формате хранения БД;
//   - error — errCursorNull, если значение отсутствует.
func cursorRecordValue(rec *core.Record, collection *core.Collection, col string) (string, error) {
	if col == core.FieldNameId {
		if rec.Id == "" {
			return "", fmt.Errorf("%w: id", errCursorNull)
		}
		return rec.Id, nil
	}
	f := collection.Fields.GetByName(col)
	switch f.(type) {
	case *core.BoolField:
		if rec.GetBool(col) {
			return "1", nil
		}
		return "0", nil
	case *core.DateField, *core.AutodateField:
		return rec.GetDateTime(col).String(), nil // "" для пустой даты
	}
	return rec.GetString(col), nil
}

// buildRecordsBase собирает базовый SELECT записей: правила коллекции,
// клиентский фильтр (язык штатного API), скрытие мягко удалённых.
// Курсор, сортировка и лимит НЕ добавляются — их накладывает вызывающий.
//
// Параметры:
//   - app: core.App — приложение;
//   - collection: *core.Collection — коллекция;
//   - requestInfo: *core.RequestInfo — контекст запроса (права);
//   - applyListRule: bool — применять ListRule (false для эндпоинтов,
//     которые сами управляют доступом, например /api/seed/sessions);
//   - filter: string — клиентский fexpr-фильтр (может быть "");
//   - filterParams: dbx.Params — параметры {:имя} фильтра.
//
// Возвращает:
//   - *dbx.SelectQuery — готовый базовый запрос;
//   - error — ошибка правил/фильтра (400 на уровне эндпоинта).
func buildRecordsBase(app core.App, collection *core.Collection,
	requestInfo *core.RequestInfo, applyListRule bool,
	filter string, filterParams dbx.Params) (*dbx.SelectQuery, error) {
	superuser := requestInfo.HasSuperuserAuth()
	query := app.RecordQuery(collection)
	resolver := core.NewRecordFieldResolver(app, collection, requestInfo, true)

	if applyListRule && !superuser && collection.ListRule != nil && *collection.ListRule != "" {
		expr, err := search.FilterData(*collection.ListRule).BuildExpr(resolver)
		if err != nil {
			return nil, err
		}
		query.AndWhere(expr)
	}

	// Скрытые поля доступны в фильтре только суперюзеру (как в штатном).
	resolver.SetAllowHiddenFields(superuser)

	if filter != "" {
		if len(filter) > search.MaxFilterLength {
			return nil, fmt.Errorf("%w: %d > %d", errFilterLength, len(filter), search.MaxFilterLength)
		}
		// Параметры {:имя} подставляются в выражение безопасно
		// (экранируются и кавычатся самим BuildExpr).
		expr, err := search.FilterData(filter).BuildExpr(resolver, filterParams)
		if err != nil {
			return nil, err
		}
		query.AndWhere(expr)
	}
	// Джойны, накопленные резолвером при разборе фильтра/правила.
	if err := resolver.UpdateQuery(query); err != nil {
		return nil, err
	}
	// Единый контракт мягкого удаления: не-суперюзер не видит удалённое.
	if !superuser && softDeleteWhitelist[collection.Name] {
		query.AndWhere(dbx.NewExp("([[" + collection.Name + ".deleted_at]] IS NULL OR [[" +
			collection.Name + ".deleted_at]] = '')"))
	}
	return query, nil
}

// CursorRecordsResult — итог курсорной выборки записей (слой 2).
//
// Поля:
//   - Records: []*core.Record — записи страницы;
//   - HasMore: bool — есть ли следующая страница;
//   - NextCursor: string — курсор следующей страницы ("" если нет).
type CursorRecordsResult struct {
	Records    []*core.Record
	HasMore    bool
	NextCursor string
}

// CursorRecords — слой 2: курсорная выборка записей коллекции с той
// же семантикой доступа, что у штатного списка. Если последняя колонка
// плана не "id", разграничитель "id" дописывается автоматически.
//
// Параметры:
//   - app: core.App — приложение;
//   - collection: *core.Collection — коллекция;
//   - requestInfo: *core.RequestInfo — контекст запроса (права);
//   - applyListRule: bool — применять ListRule коллекции;
//   - filter: string — клиентский fexpr-фильтр ("" — без фильтра);
//   - filterParams: dbx.Params — параметры {:имя} фильтра (может быть nil);
//   - sorts: []CursorSort — план сортировки (колонки самой коллекции);
//   - cursor: string — курсор предыдущей страницы ("" = первая);
//   - limit: int — размер страницы, 1..200.
//
// Возвращает:
//   - *CursorRecordsResult — записи, hasMore, следующий курсор;
//   - error — ошибки валидации (по ошибкам-маркерам → 400) либо SQL.
func CursorRecords(app core.App, collection *core.Collection,
	requestInfo *core.RequestInfo, applyListRule bool,
	filter string, filterParams dbx.Params,
	sorts []CursorSort, cursor string, limit int) (*CursorRecordsResult, error) {
	if limit <= 0 || limit > cursorMaxLimit {
		return nil, fmt.Errorf("%w: %d (нужно 1..%d)", errCursorLimit, limit, cursorMaxLimit)
	}
	superuser := requestInfo.HasSuperuserAuth()
	if err := validateRecordsSorts(collection, sorts, superuser); err != nil {
		return nil, err
	}
	// Разграничитель: последняя колонка плана обязана быть уникальной.
	if sorts[len(sorts)-1].Column != core.FieldNameId {
		sorts = append(append([]CursorSort{}, sorts...), CursorSort{Column: core.FieldNameId})
	}

	var values []string
	if cursor != "" {
		v, err := decodeCursor(cursor, len(sorts))
		if err != nil {
			return nil, err
		}
		values = v
	}

	query, err := buildRecordsBase(app, collection, requestInfo, applyListRule, filter, filterParams)
	if err != nil {
		return nil, err
	}

	suffix := nextSuffix()
	qualify := func(col string) string { return "[[" + collection.Name + "." + col + "]]" }
	pred, orders, params := cursorClause(sorts, values, suffix, qualify)
	if pred != "" {
		query.AndWhere(dbx.NewExp(pred, params))
	}
	query.AndOrderBy(orders...)
	query.Limit(int64(limit + 1))

	records := []*core.Record{}
	if err := query.All(&records); err != nil {
		return nil, err
	}

	res := &CursorRecordsResult{HasMore: len(records) > limit}
	if res.HasMore {
		records = records[:limit]
	}
	res.Records = records
	if res.HasMore && len(records) > 0 {
		last := records[len(records)-1]
		vals := make([]string, 0, len(sorts))
		for _, s := range sorts {
			v, err := cursorRecordValue(last, collection, s.Column)
			if err != nil {
				return nil, err
			}
			vals = append(vals, v)
		}
		res.NextCursor = encodeCursor(vals)
	}
	return res, nil
}

// countRecordsBase считает общее число записей по той же базе
// (правила + фильтр + мягкое удаление), БЕЗ курсорного предиката.
// Используется только при явном with_total=1 — на больших таблицах дорого.
//
// Параметры: те же, что у buildRecordsBase.
//
// Возвращает:
//   - int — число строк;
//   - error — ошибка SQL.
func countRecordsBase(app core.App, collection *core.Collection,
	requestInfo *core.RequestInfo, applyListRule bool,
	filter string, filterParams dbx.Params) (int, error) {
	base, err := buildRecordsBase(app, collection, requestInfo, applyListRule, filter, filterParams)
	if err != nil {
		return 0, err
	}
	built := base.Build()
	var count int
	err = app.ConcurrentDB().NewQuery("SELECT COUNT(*) FROM (" + built.SQL() + ") AS __cnt").
		Bind(built.Params()).Row(&count)
	return count, err
}

// ---------------------------------------------------- слой 3: эндпоинты

// parseRecordsSort разбирает параметр sort курсорного эндпоинта:
// список колонок через запятую, "-" — по убыванию. Макросы штатного
// API (вида @random) не поддерживаются — курсор требует колонок.
//
// Параметры:
//   - collection: *core.Collection — коллекция;
//   - sort: string — значение параметра ?sort= (может быть "");
//   - superuser: bool — запрос от суперюзера (скрытые поля).
//
// Возвращает:
//   - []CursorSort — план сортировки (по умолчанию: created, иначе id);
//   - error — errCursorPlan при недопустимом значении.
func parseRecordsSort(collection *core.Collection, sort string, superuser bool) ([]CursorSort, error) {
	if sort == "" {
		// Имя автодаты: штатные коллекции — "created", коллекции
		// pbseed — "created_at".
		for _, def := range []string{"created", "created_at"} {
			if collection.Fields.GetByName(def) != nil {
				return []CursorSort{{Column: def}}, nil
			}
		}
		return []CursorSort{{Column: core.FieldNameId}}, nil
	}
	tokens := strings.Split(sort, ",")
	if len(tokens) > 8 {
		return nil, fmt.Errorf("%w: не больше 8 колонок", errCursorPlan)
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
		if name == "" || strings.HasPrefix(name, "@") {
			return nil, fmt.Errorf("%w: %q", errCursorPlan, tok)
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			return nil, fmt.Errorf("%w: дубль %q", errCursorPlan, name)
		}
		seen[lower] = true
		out = append(out, CursorSort{Column: name, Desc: desc})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: пусто", errCursorPlan)
	}
	if err := validateRecordsSorts(collection, out, superuser); err != nil {
		return nil, err
	}
	return out, nil
}

// recordsCursor — GET /api/collections/{collection}/records/cursor.
// Курсорный режим штатного списка: те же правила коллекции и тот же
// язык ?filter=, но без OFFSET. Штатный /records не трогается.
//
// Параметры запроса:
//   - filter: fexpr-фильтр (язык штатного API, до 3500 символов);
//   - sort: колонки через запятую, "-" — по убыванию (по умолчанию
//     created; разграничитель id дописывается сам);
//   - limit: 1..200 (по умолчанию 30);
//   - cursor: курсор предыдущей страницы;
//   - with_total=1: добавить totalItems (отдельный COUNT, дорого).
//
// Ответ 200: {items, nextCursor|null, limit[, totalItems]}.
// Ошибки: 404 (нет коллекции), 403 (только для суперюзеров),
// 400 (лимит/сортировка/фильтр/курсор).
func recordsCursor(e *core.RequestEvent) error {
	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
	if err != nil || collection == nil {
		return e.NotFoundError("Missing collection context.", err)
	}
	requestInfo, err := e.RequestInfo()
	if err != nil {
		return e.BadRequestError("", err)
	}
	// Права штатного списка: без правила листает только суперюзер.
	if collection.ListRule == nil && !requestInfo.HasSuperuserAuth() {
		return e.ForbiddenError("Only superusers can perform this action.", nil)
	}
	// Журнал в курсорном режиме читают те же лица, что и штатно:
	// суперюзер и роль «admin» (правило — фильтр, а не заслон).
	if collection.Name == "seed_audit" && !seedAdmin(requestInfo.Auth) {
		return e.ForbiddenError("Only superusers can perform this action.", nil)
	}

	q := e.Request.URL.Query()
	limit := cursorRecordsDefaultLimit
	if ls := q.Get("limit"); ls != "" {
		limit, err = strconv.Atoi(ls)
		if err != nil || limit < 1 || limit > cursorMaxLimit {
			return e.BadRequestError("Invalid limit (нужно 1.."+strconv.Itoa(cursorMaxLimit)+").", nil)
		}
	}
	sorts, err := parseRecordsSort(collection, q.Get("sort"), requestInfo.HasSuperuserAuth())
	if err != nil {
		return e.BadRequestError(err.Error(), nil)
	}
	filter := q.Get("filter")
	cursor := q.Get("cursor")

	res, err := CursorRecords(e.App, collection, requestInfo, true, filter, nil, sorts, cursor, limit)
	if err != nil {
		if errors.Is(err, errCursorValue) || errors.Is(err, errCursorPlan) ||
			errors.Is(err, errCursorLimit) || errors.Is(err, errFilterLength) {
			return e.BadRequestError(err.Error(), nil)
		}
		return e.InternalServerError("Query failed.", err)
	}

	if err := apis.EnrichRecords(e, res.Records); err != nil {
		return e.InternalServerError("Failed to enrich records.", err)
	}

	resp := map[string]any{
		"items": res.Records,
		"limit": limit,
	}
	if res.NextCursor != "" {
		resp["nextCursor"] = res.NextCursor
	} else {
		resp["nextCursor"] = nil
	}
	if q.Get("with_total") == "1" {
		count, err := countRecordsBase(e.App, collection, requestInfo, true, filter, nil)
		if err != nil {
			return e.InternalServerError("Count failed.", err)
		}
		resp["totalItems"] = count
	}
	return e.JSON(http.StatusOK, resp)
}

// ----------------------------------------- обогащение штатного списка

// recordsListCursorHint — гибридный мостик офсет → курсор: дописывает в
// штатный ответ /api/collections/{c}/records заголовок X-Next-Cursor,
// по которому клиент может продолжить листание через курсорный режим
// (/records/cursor) с тем же фильтром и сортировкой. Сами данные и тело
// штатного ответа не меняются.
//
// Заголовок ставится только когда курсор можно построить корректно:
// сортировка задана явно и состоит из простых колонок коллекции
// (без макросов и вложенных путей), и есть признаки следующей
// страницы. Во всех остальных случаях запрос отрабатывает как раньше,
// просто без заголовка.
//
// Параметры:
//   - e: *core.RecordsListRequestEvent — событие штатного списка
//     (записи и результат уже выбраны штатным обработчиком).
//
// Возвращает: error — результат продолжения цепочки (e.Next()).
func recordsListCursorHint(e *core.RecordsListRequestEvent) error {
	if hint := calcListCursorHint(e); hint != "" {
		e.Response.Header().Set("X-Next-Cursor", hint)
	}
	return e.Next()
}

// calcListCursorHint считает значение курсора по последней записи
// текущей штатной страницы. Любое сомнение (макрос в сортировке,
// вложенное поле, скрытое поле у не-суперюзера, последняя страница) —
// пустая строка вместо ошибки: обогащение не должно ломать список.
//
// Параметры:
//   - e: *core.RecordsListRequestEvent — событие штатного списка.
//
// Возвращает: string — курсор либо "" (заголовок не ставить).
func calcListCursorHint(e *core.RecordsListRequestEvent) string {
	if len(e.Records) == 0 || e.Collection == nil {
		return ""
	}
	// Есть ли следующая страница. При штатном подсчёте итогов смотрим на
	// номера страниц; при skipTotal=1 (TotalItems < 0) — на полноту страницы.
	if e.Result != nil {
		if e.Result.TotalItems >= 0 {
			if e.Result.Page >= e.Result.TotalPages {
				return ""
			}
		} else if len(e.Records) < e.Result.PerPage {
			return ""
		}
	}
	// Без явной сортировки штатный список не гарантирует порядок —
	// курсор был бы неоднозначен.
	sortParam := e.Request.URL.Query().Get("sort")
	if sortParam == "" {
		return ""
	}
	tokens := strings.Split(sortParam, ",")
	if len(tokens) > 8 {
		return ""
	}
	sorts := make([]CursorSort, 0, len(tokens))
	seen := make(map[string]bool, len(tokens))
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return ""
		}
		desc := strings.HasPrefix(tok, "-")
		name := strings.TrimLeft(tok, "-+")
		// макросы (@random и т. п.) и мусор не годятся для курсора
		if name == "" || strings.HasPrefix(name, "@") || !cursorIdentRe.MatchString(name) {
			return ""
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			return ""
		}
		seen[lower] = true
		sorts = append(sorts, CursorSort{Column: name, Desc: desc})
	}
	if len(sorts) == 0 {
		return ""
	}
	superuser := e.Auth != nil && e.Auth.IsSuperuser()
	for _, s := range sorts {
		if s.Column == core.FieldNameId {
			continue
		}
		f := e.Collection.Fields.GetByName(s.Column)
		if f == nil || !cursorSortFieldAllowed(f) {
			return ""
		}
		if f.GetHidden() && !superuser {
			return ""
		}
	}
	// Разграничитель — как в курсорном режиме: последним дописывается id.
	if sorts[len(sorts)-1].Column != core.FieldNameId {
		sorts = append(sorts, CursorSort{Column: core.FieldNameId})
	}
	last := e.Records[len(e.Records)-1]
	vals := make([]string, 0, len(sorts))
	for _, s := range sorts {
		v, err := cursorRecordValue(last, e.Collection, s.Column)
		if err != nil {
			return ""
		}
		vals = append(vals, v)
	}
	return encodeCursor(vals)
}

// ------------------------------------------------- /api/seed/sessions

// seedSessionsParamAllow — белый список параметров /api/seed/sessions.
// Неизвестный параметр — 400 (запрет по умолчанию, план раздел 2.3).
var seedSessionsParamAllow = map[string]bool{
	"limit":          true,
	"cursor":         true,
	"sort":           true,
	"revoked":        true,
	"ip_country":     true,
	"created_from":   true,
	"created_to":     true,
	"last_seen_from": true,
	"last_seen_to":   true,
}

// seedSessionsSortAllow — колонки, разрешённые для сортировки списка
// своих сессий (каждая — с префиксом "-" для убывания).
// Разграничитель id дописывается пагинатором автоматически.
var seedSessionsSortAllow = map[string]bool{
	"created_at":  true,
	"updated_at":  true,
	"last_seen":   true,
	"expires":     true,
	"device_name": true,
	"ip_country":  true,
}

// parseSeedSessionsSort разбирает параметр sort эндпоинта сессий по
// белому списку колонок.
//
// Параметры:
//   - sort: string — значение ?sort= ("" → по умолчанию -created_at).
//
// Возвращает:
//   - []CursorSort — план сортировки;
//   - error — errCursorPlan при недопустимой колонке.
func parseSeedSessionsSort(sort string) ([]CursorSort, error) {
	if sort == "" {
		sort = "-created_at"
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
		if !seedSessionsSortAllow[name] {
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

// parseCursorDate проверяет значение диапазонного параметра: дата в
// одном из форматов (дата, дата+время, RFC3339). Сравнение в БД
// лексикографическое — форматы хранения это допускают.
//
// Параметры:
//   - v: string — значение параметра.
//
// Возвращает: error — если ни один формат не распознан.
func parseCursorDate(v string) error {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if _, err := time.Parse(layout, v); err == nil {
			return nil
		}
	}
	return fmt.Errorf("не дата: %q", v)
}

// seedSessions — GET /api/seed/sessions: список своих сессий с
// курсорной пагинацией (ответ совместим со старой версией: тот же
// массив объектов; курсор следующей страницы — заголовок
// X-Next-Cursor, присутствует только если страницы ещё есть).
//
// Параметры запроса (все необязательные; неизвестные — 400):
//   - limit: 1..100 (по умолчанию 50);
//   - cursor: курсор из X-Next-Cursor предыдущего ответа;
//   - sort: колонки через запятую из белого списка, "-" — по убыванию
//     (по умолчанию -created_at);
//   - revoked: "true"/"false" — только отозванные/активные;
//   - ip_country: двухбуквенный код страны;
//   - created_from/created_to: диапазон created_at;
//   - last_seen_from/last_seen_to: диапазон last_seen.
//
// Ответ 200: массив объектов сессии (см. прежний контракт).
// Ошибки: 401 (нет входа), 400 (параметры/курсор), 500 (хранилище).
func seedSessions(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	q := e.Request.URL.Query()
	for key := range q {
		if !seedSessionsParamAllow[key] {
			return seedErr(e, 400, "unknown_param")
		}
	}

	limit := 50
	if ls := q.Get("limit"); ls != "" {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 || n > 100 {
			return seedErr(e, 400, "bad_limit")
		}
		limit = n
	}
	sorts, err := parseSeedSessionsSort(q.Get("sort"))
	if err != nil {
		return seedErr(e, 400, "bad_sort")
	}

	// Фильтр собирается параметризованным выражением; значения из
	// запроса попадают только в параметры, никогда в текст.
	filters := []string{"user = {:uid}"}
	params := dbx.Params{"uid": e.Auth.Id}

	if rv := q.Get("revoked"); rv != "" {
		switch rv {
		case "true":
			filters = append(filters, "revoked = true")
		case "false":
			filters = append(filters, "revoked = false")
		default:
			return seedErr(e, 400, "bad_revoked")
		}
	}
	if c := q.Get("ip_country"); c != "" {
		c = strings.ToUpper(c)
		if len(c) != 2 || c < "AA" || c > "ZZ" || !isLetters(c) {
			return seedErr(e, 400, "bad_ip_country")
		}
		filters = append(filters, "ip_country = {:ip_country}")
		params["ip_country"] = c
	}
	for _, def := range []struct{ param, col, op string }{
		{"created_from", "created_at", ">="},
		{"created_to", "created_at", "<="},
		{"last_seen_from", "last_seen", ">="},
		{"last_seen_to", "last_seen", "<="},
	} {
		v := q.Get(def.param)
		if v == "" {
			continue
		}
		if err := parseCursorDate(v); err != nil {
			return seedErr(e, 400, "bad_date")
		}
		filters = append(filters, def.col+" "+def.op+" {:"+def.param+"}")
		params[def.param] = v
	}

	requestInfo, err := e.RequestInfo()
	if err != nil {
		return seedErr(e, 500, "request_info_failed")
	}
	collection, err := e.App.FindCollectionByNameOrId("seed_sessions")
	if err != nil {
		return seedErr(e, 500, "store_failed")
	}
	res, err := CursorRecords(e.App, collection, requestInfo, false,
		strings.Join(filters, " && "), params, sorts, q.Get("cursor"), limit)
	if err != nil {
		if errors.Is(err, errCursorValue) || errors.Is(err, errCursorPlan) ||
			errors.Is(err, errCursorLimit) {
			return seedErr(e, 400, "bad_cursor")
		}
		return seedErr(e, 500, "store_failed")
	}

	curGrant := ""
	if parts := strings.SplitN(cookieVal(e, seedCookieName), ".", 2); len(parts) == 2 {
		curGrant = parts[0]
	}
	out := make([]map[string]any, 0, len(res.Records))
	for _, s := range res.Records {
		grant := asStr(s.Get("grant_id"))
		out = append(out, map[string]any{
			"session_id":  grant,
			"device_name": asStr(s.Get("device_name")),
			"ip_masked":   asStr(s.Get("ip_masked")),
			"country":     asStr(s.Get("ip_country")),
			"history":     getHistory(s),
			"current":     curGrant != "" && curGrant == grant,
			"revoked":     asBool(s.Get("revoked")),
			"last_seen":   asStr(s.Get("last_seen")),
			"created_at":  s.Get("created_at"),
			"updated_at":  s.Get("updated_at"),
			"expires":     asStr(s.Get("expires")),
		})
	}
	if res.NextCursor != "" {
		e.Response.Header().Set("X-Next-Cursor", res.NextCursor)
	}
	return e.JSON(http.StatusOK, out)
}

// isLetters сообщает, состоит ли строка только из латинских букв.
//
// Параметры:
//   - s: string — строка (непустая).
//
// Возвращает: bool — все байты в диапазоне A..Z/a..z.
func isLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
