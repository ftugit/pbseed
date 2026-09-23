package main

// paginate.go — курсорная (keyset) пагинация: универсальное ядро.
//
// Ядро листает ЛЮБОЙ базовый SELECT (одна таблица, JOIN, подзапросы,
// агрегаты) без OFFSET: базовый запрос оборачивается подзапросом,
// сверху накладывается курсорный предикат и детерминированный
// ORDER BY с уникальной последней колонкой.
//
// Контракт базового SELECT (нарушения отклоняются валидацией плана):
//   - все колонки плана сортировки присутствуют в выходных колонках;
//   - последняя колонка плана — уникальный разграничитель (обычно "id");
//   - нет дублей имён выходных колонок;
//   - у базового запроса нет собственного LIMIT;
//   - сортировка детерминирована (без random() и т. п.).
//
// Курсор — непрозрачная строка base64(json([значения колонок плана])).
// См. план: sss/pagination-design.md (разделы 2.1, 3).

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/pocketbase/dbx"
)

// cursorMaxLimit — жёсткий потолок размера страницы для всех слоёв
// пагинатора (защита от запросов с тысячами строк за раз).
const cursorMaxLimit = 200

// Ошибки пагинатора. Эндпоинты отображают их в 400 по errors.Is.
var (
	errCursorPlan   = errors.New("cursor: неверный план сортировки")
	errCursorValue  = errors.New("cursor: недопустимый курсор")
	errCursorLimit  = errors.New("cursor: недопустимый размер страницы")
	errCursorNull   = errors.New("cursor: NULL в колонке сортировки")
	errFilterLength = errors.New("cursor: фильтр длиннее допустимого")
)

// cursorIdentRe — допустимое имя колонки плана: простой идентификатор.
// Выражения не поддерживаются — их нужно алиасить в базовом SELECT.
var cursorIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// cursorParamSeq — счётчик для уникальных имён параметров курсора
// (защита от коллизий с параметрами базового запроса).
var cursorParamSeq atomic.Uint64

// CursorSort — одна колонка курсорной сортировки.
//
// Поля:
//   - Column: string — колонка, ПРИСУТСТВУЮЩАЯ в выходных колонках
//     базового запроса (простой идентификатор);
//   - Desc: bool — направление: true = по убыванию.
type CursorSort struct {
	Column string
	Desc   bool
}

// CursorPage — страница строк произвольного SELECT (слой 1).
//
// Поля:
//   - Rows: []dbx.NullStringMap — строки страницы (все значения —
//     строки, как вернул драйвер);
//   - HasMore: bool — есть ли следующая страница;
//   - NextCursor: string — курсор следующей страницы ("" если страниц
//     больше нет).
type CursorPage struct {
	Rows       []dbx.NullStringMap
	HasMore    bool
	NextCursor string
}

// encodeCursor кодирует значения колонок плана в непрозрачный курсор.
//
// Параметры:
//   - values: []string — значения последней строки страницы, по порядку
//     колонок плана сортировки.
//
// Возвращает: string — курсор (base64url от JSON-массива значений).
func encodeCursor(values []string) string {
	b, err := json.Marshal(values)
	if err != nil { // []string не может не сериализоваться
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor разбирает курсор и проверяет арность под план.
//
// Параметры:
//   - cursor: string — курсор предыдущей страницы;
//   - arity: int — число колонок в плане сортировки.
//
// Возвращает:
//   - []string — значения колонок по порядку плана;
//   - error — errCursorValue при повреждённом/чужом курсоре.
func decodeCursor(cursor string, arity int) ([]string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, fmt.Errorf("%w: не base64", errCursorValue)
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("%w: не список значений", errCursorValue)
	}
	if len(values) != arity {
		return nil, fmt.Errorf("%w: арность %d, план %d", errCursorValue, len(values), arity)
	}
	return values, nil
}

// validateSortPlan проверяет план курсорной сортировки: непустой,
// имена — простые идентификаторы, без дублей (регистронезависимо).
//
// Параметры:
//   - sorts: []CursorSort — план сортировки.
//
// Возвращает: error — errCursorPlan при нарушении, иначе nil.
func validateSortPlan(sorts []CursorSort) error {
	if len(sorts) == 0 {
		return fmt.Errorf("%w: план пуст", errCursorPlan)
	}
	seen := make(map[string]bool, len(sorts))
	for _, s := range sorts {
		if !cursorIdentRe.MatchString(s.Column) {
			return fmt.Errorf("%w: колонка %q", errCursorPlan, s.Column)
		}
		key := strings.ToLower(s.Column)
		if seen[key] {
			return fmt.Errorf("%w: дубль колонки %q", errCursorPlan, s.Column)
		}
		seen[key] = true
	}
	return nil
}

// cursorClause собирает курсорный предикат (OR-цепочка для смешанных
// направлений), фрагменты ORDER BY и параметры к ним.
//
// Параметры:
//   - sorts: []CursorSort — план сортировки;
//   - values: []string — значения курсора (nil для первой страницы);
//   - suffix: string — уникальный суффикс имён параметров;
//   - qualify: func(col string) string — способ записи колонки
//     (например, `__page."col"` или `[[таблица.колонка]]`).
//
// Возвращает:
//   - string — предикат ("" для первой страницы);
//   - []string — фрагменты ORDER BY по числу колонок плана;
//   - dbx.Params — параметры предиката.
//
// Вид предиката для плана (a↑, b↓, id↑) и курсора (v1, v2, vid):
//
//	(a > v1) OR (a = v1 AND b < v2) OR (a = v1 AND b = v2 AND id > vid)
func cursorClause(sorts []CursorSort, values []string, suffix string,
	qualify func(col string) string) (string, []string, dbx.Params) {
	orders := make([]string, len(sorts))
	for i, s := range sorts {
		dir := "ASC"
		if s.Desc {
			dir = "DESC"
		}
		orders[i] = qualify(s.Column) + " " + dir
	}
	if len(values) == 0 {
		return "", orders, dbx.Params{}
	}
	params := dbx.Params{}
	terms := make([]string, 0, len(sorts))
	for i := range sorts {
		parts := make([]string, 0, i+1)
		for j := 0; j < i; j++ {
			key := "__cur_" + strconv.Itoa(j) + "_" + suffix
			parts = append(parts, qualify(sorts[j].Column)+" = {:"+key+"}")
			params[key] = values[j]
		}
		op := ">"
		if sorts[i].Desc {
			op = "<"
		}
		key := "__cur_" + strconv.Itoa(i) + "_" + suffix
		parts = append(parts, qualify(sorts[i].Column)+" "+op+" {:"+key+"}")
		params[key] = values[i]
		terms = append(terms, "("+strings.Join(parts, " AND ")+")")
	}
	return "(" + strings.Join(terms, " OR ") + ")", orders, params
}

// nextSuffix выдаёт уникальный суффикс имён параметров для запроса.
//
// Возвращает: string — суффикс (цифры/буквы, уникален в процессе).
func nextSuffix() string {
	return strconv.FormatUint(cursorParamSeq.Add(1), 36)
}

// CursorQuery — слой 1: курсорная пагинация произвольного SELECT.
// Оборачивает базовый запрос подзапросом и одним запросом без OFFSET
// выбирает страницу (limit+1 строка ради hasMore).
//
// Параметры:
//   - db: dbx.Builder — подключение (например, app.DB());
//   - base: *dbx.SelectQuery — базовый SELECT БЕЗ собственного LIMIT;
//   - sorts: []CursorSort — план сортировки (последняя колонка —
//     уникальный разграничитель);
//   - cursor: string — курсор предыдущей страницы ("" = первая);
//   - limit: int — размер страницы, 1..200.
//
// Возвращает:
//   - *CursorPage — строки, hasMore, курсор следующей страницы;
//   - error — ошибки валидации плана/курсора/лимита либо ошибка SQL.
func CursorQuery(db dbx.Builder, base *dbx.SelectQuery,
	sorts []CursorSort, cursor string, limit int) (*CursorPage, error) {
	if limit <= 0 || limit > cursorMaxLimit {
		return nil, fmt.Errorf("%w: %d (нужно 1..%d)", errCursorLimit, limit, cursorMaxLimit)
	}
	if err := validateSortPlan(sorts); err != nil {
		return nil, err
	}
	var values []string
	if cursor != "" {
		v, err := decodeCursor(cursor, len(sorts))
		if err != nil {
			return nil, err
		}
		values = v
	}

	built := base.Build()
	suffix := nextSuffix()
	qualify := func(col string) string { return `__page."` + col + `"` }
	pred, orders, params := cursorClause(sorts, values, suffix, qualify)

	sql := "SELECT * FROM (" + built.SQL() + ") AS __page"
	if pred != "" {
		sql += " WHERE " + pred
	}
	sql += " ORDER BY " + strings.Join(orders, ", ")
	limitKey := "__cur_limit_" + suffix
	sql += " LIMIT {:" + limitKey + "}"
	for k, v := range built.Params() {
		params[k] = v
	}
	params[limitKey] = limit + 1

	rows := []dbx.NullStringMap{}
	if err := db.NewQuery(sql).Bind(params).All(&rows); err != nil {
		return nil, err
	}

	page := &CursorPage{HasMore: len(rows) > limit}
	if page.HasMore {
		rows = rows[:limit]
	}
	page.Rows = rows
	if page.HasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		vals := make([]string, 0, len(sorts))
		for _, s := range sorts {
			ns, ok := last[s.Column]
			if !ok || !ns.Valid {
				return nil, fmt.Errorf("%w: %s", errCursorNull, s.Column)
			}
			vals = append(vals, ns.String)
		}
		page.NextCursor = encodeCursor(vals)
	}
	return page, nil
}
