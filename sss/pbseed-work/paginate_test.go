package main

// Курсорная пагинация: регрессионные тесты всех трёх слоёв.
//
// Ядро (любой SELECT):
//   - TestCursorQueryAscPaging         — страницы, дубли значения сортировки
//   - TestCursorQueryMixedDirections   — смешанные направления (OR-цепочка)
//   - TestCursorQueryDesc              — чистое убывание
//   - TestCursorQueryBaseParams        — параметры базового запроса
//   - TestCursorQueryStableUnderInsert — вставка между страницами не ломает курсор
//   - TestCursorQueryNullSortColumn    — NULL в колонке плана — ошибка, не молчание
//   - TestCursorQueryValidation        — план/курсор/лимит отклоняются
//
// Коллекции (правила, мягкое удаление, фильтр с параметрами):
//   - TestCursorRecordsRulesAndSoftDelete
//   - TestCursorRecordsSessionsContinuation
//
// Эндпоинты:
//   - TestRecordsCursorEndpoint        — /api/collections/{c}/records/cursor
//   - TestSeedSessionsEndpointCursor   — /api/seed/sessions с курсором

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// ------------------------------------------------------------- ядро (слой 1)

// pgSeedRows — учебная таблица: дубли значения сортировки (n), две группы.
var pgSeedRows = [][4]any{
	{"i1", "a", 1, 5.0},
	{"i2", "a", 1, 4.0},
	{"i3", "b", 2, 3.0},
	{"i4", "a", 2, 2.5},
	{"i5", "b", 2, 2.5},
	{"i6", "a", 3, 1.0},
	{"i7", "b", 3, 0.5},
}

// mustPgTable создаёт и наполняет учебную таблицу pg_t.
func mustPgTable(t testing.TB, app core.App) {
	t.Helper()
	db := app.NonconcurrentDB()
	if _, err := db.NewQuery("DROP TABLE IF EXISTS pg_t").Execute(); err != nil {
		t.Fatalf("drop pg_t: %v", err)
	}
	if _, err := db.NewQuery(
		"CREATE TABLE pg_t (id TEXT PRIMARY KEY, grp TEXT, n INTEGER NOT NULL, price REAL NOT NULL)",
	).Execute(); err != nil {
		t.Fatalf("create pg_t: %v", err)
	}
	for _, r := range pgSeedRows {
		_, err := db.NewQuery(
			"INSERT INTO pg_t (id, grp, n, price) VALUES ({:id}, {:grp}, {:n}, {:price})",
		).Bind(dbx.Params{"id": r[0], "grp": r[1], "n": r[2], "price": r[3]}).Execute()
		if err != nil {
			t.Fatalf("insert %v: %v", r[0], err)
		}
	}
}

// walkCursor листает базовый запрос до конца и собирает колонку "id".
//
// Возвращает: все id по порядку и число страниц.
func walkCursor(t *testing.T, app core.App, base *dbx.SelectQuery,
	sorts []CursorSort, limit int) ([]string, int) {
	t.Helper()
	var ids []string
	pages := 0
	cursor := ""
	for {
		page, err := CursorQuery(app.DB(), base, sorts, cursor, limit)
		if err != nil {
			t.Fatalf("CursorQuery (страница %d): %v", pages+1, err)
		}
		pages++
		for _, r := range page.Rows {
			ids = append(ids, r["id"].String)
		}
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Fatalf("страница %d: hasMore=false, но курсор %q не пуст", pages, page.NextCursor)
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatalf("страница %d: hasMore=true, но курсор пуст", pages)
		}
		cursor = page.NextCursor
		if pages > 100 {
			t.Fatal("бесконечный цикл по курсору")
		}
	}
	return ids, pages
}

func TestCursorQueryAscPaging(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	mustPgTable(t, app)

	ids, pages := walkCursor(t, app, app.DB().Select("*").From("pg_t"),
		[]CursorSort{{Column: "n"}, {Column: "id"}}, 3)

	want := []string{"i1", "i2", "i3", "i4", "i5", "i6", "i7"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("порядок: %v, ждали %v", ids, want)
	}
	if pages != 3 { // 3+3+1
		t.Fatalf("страниц %d, ждали 3", pages)
	}
}

func TestCursorQueryMixedDirections(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	mustPgTable(t, app)

	// n по возрастанию, id по убыванию: внутри каждой группы n порядок
	// строк разворачивается. Проверяет OR-цепочечный предикат.
	ids, _ := walkCursor(t, app, app.DB().Select("*").From("pg_t"),
		[]CursorSort{{Column: "n"}, {Column: "id", Desc: true}}, 2)

	want := []string{"i2", "i1", "i5", "i4", "i3", "i7", "i6"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("порядок: %v, ждали %v", ids, want)
	}
}

func TestCursorQueryDesc(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	mustPgTable(t, app)

	ids, _ := walkCursor(t, app, app.DB().Select("*").From("pg_t"),
		[]CursorSort{{Column: "n", Desc: true}, {Column: "id"}}, 4)

	want := []string{"i6", "i7", "i3", "i4", "i5", "i1", "i2"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("порядок: %v, ждали %v", ids, want)
	}
}

func TestCursorQueryBaseParams(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	mustPgTable(t, app)

	// Базовый запрос с собственными параметрами — имена не должны
	// конфликтовать с параметрами курсора.
	base := app.DB().Select("*").From("pg_t").
		Where(dbx.NewExp("grp = {:g}", dbx.Params{"g": "a"}))

	ids, _ := walkCursor(t, app, base,
		[]CursorSort{{Column: "n"}, {Column: "id"}}, 2)

	want := []string{"i1", "i2", "i4", "i6"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("порядок: %v, ждали %v", ids, want)
	}
}

func TestCursorQueryStableUnderInsert(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	mustPgTable(t, app)

	base := func() *dbx.SelectQuery { return app.DB().Select("*").From("pg_t") }
	sorts := []CursorSort{{Column: "n"}, {Column: "id"}}

	page1, err := CursorQuery(app.DB(), base(), sorts, "", 2)
	if err != nil {
		t.Fatalf("первая страница: %v", err)
	}
	got := []string{page1.Rows[0]["id"].String, page1.Rows[1]["id"].String}
	if !reflect.DeepEqual(got, []string{"i1", "i2"}) {
		t.Fatalf("первая страница: %v", got)
	}

	// Между страницами вставляется строка РАНЬШЕ курсора — OFFSET бы
	// сдвинул выдачу, keyset обязан её пропустить.
	if _, err := app.NonconcurrentDB().NewQuery(
		"INSERT INTO pg_t (id, grp, n, price) VALUES ({:id}, {:grp}, {:n}, {:price})",
	).Bind(dbx.Params{"id": "i0", "grp": "a", "n": 0, "price": 9.0}).Execute(); err != nil {
		t.Fatalf("вставка i0: %v", err)
	}

	page2, err := CursorQuery(app.DB(), base(), sorts, page1.NextCursor, 2)
	if err != nil {
		t.Fatalf("вторая страница: %v", err)
	}
	got = []string{page2.Rows[0]["id"].String, page2.Rows[1]["id"].String}
	if !reflect.DeepEqual(got, []string{"i3", "i4"}) {
		t.Fatalf("вторая страница после вставки: %v, ждали [i3 i4]", got)
	}
}

func TestCursorQueryNullSortColumn(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	mustPgTable(t, app)
	if _, err := app.NonconcurrentDB().NewQuery(
		"INSERT INTO pg_t (id, grp, n, price) VALUES ({:id}, NULL, {:n}, {:price})",
	).Bind(dbx.Params{"id": "i8", "n": 9, "price": 9.0}).Execute(); err != nil {
		t.Fatalf("вставка i8: %v", err)
	}

	// grp NULL поднимается первым при ASC: курсор по нему построить
	// нельзя — пагинатор обязан отказать, а не выдать плывущие страницы.
	_, err := CursorQuery(app.DB(), app.DB().Select("*").From("pg_t"),
		[]CursorSort{{Column: "grp"}, {Column: "id"}}, "", 1)
	if !errors.Is(err, errCursorNull) {
		t.Fatalf("ждали errCursorNull, получили %v", err)
	}
}

func TestCursorQueryValidation(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	mustPgTable(t, app)
	base := app.DB().Select("*").From("pg_t")
	okSorts := []CursorSort{{Column: "n"}, {Column: "id"}}

	cases := []struct {
		name   string
		sorts  []CursorSort
		cursor string
		limit  int
		want   error
	}{
		{"пустой план", nil, "", 10, errCursorPlan},
		{"колонка не идентификатор", []CursorSort{{Column: "n; DROP TABLE pg_t"}}, "", 10, errCursorPlan},
		{"дубль колонки (регистр)", []CursorSort{{Column: "n"}, {Column: "N"}}, "", 10, errCursorPlan},
		{"лимит 0", okSorts, "", 0, errCursorLimit},
		{"лимит выше потолка", okSorts, "", cursorMaxLimit + 1, errCursorLimit},
		{"курсор не base64", okSorts, "!!!не-база64!!!", 10, errCursorValue},
		{"курсор чужой арности", okSorts, encodeCursor([]string{"только-одно"}), 10, errCursorValue},
		{"курсор не список", okSorts, "e30", 10, errCursorValue}, // base64("{}")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := CursorQuery(app.DB(), base, c.sorts, c.cursor, c.limit)
			if !errors.Is(err, c.want) {
				t.Fatalf("ждали %v, получили %v", c.want, err)
			}
		})
	}
}

// -------------------------------------------- коллекционный слой (слой 2)

func TestCursorRecordsRulesAndSoftDelete(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	withNotes(t, app)

	a := mustUser(t, app, "pg-a@seed.test")
	b := mustUser(t, app, "pg-b@seed.test")
	_ = mustNote(t, app, a.Id, "a-public", "public")
	_ = mustNote(t, app, a.Id, "a-private", "private")
	pubB := mustNote(t, app, b.Id, "b-public", "public")
	_ = mustNote(t, app, b.Id, "b-private", "private")
	notes := mustCollection(t, app, "notes")
	sorts := []CursorSort{{Column: "created_at"}} // автодаты pbseed

	titles := func(res *CursorRecordsResult) []string {
		out := make([]string, 0, len(res.Records))
		for _, r := range res.Records {
			out = append(out, asStr(r.Get("title")))
		}
		return out
	}

	// Пользователь видит своё + публичное, чужое приватное — нет.
	// Порядок внутри одинакового created_at решает разграничитель id,
	// поэтому сравниваем множество, а не последовательность.
	res, err := CursorRecords(app, notes, &core.RequestInfo{Auth: a},
		true, "", nil, sorts, "", 50)
	if err != nil {
		t.Fatalf("CursorRecords (пользователь): %v", err)
	}
	gotSet := map[string]bool{}
	for _, tt := range titles(res) {
		gotSet[tt] = true
	}
	if len(res.Records) != 3 || !gotSet["a-public"] || !gotSet["a-private"] || !gotSet["b-public"] {
		t.Fatalf("видимость пользователя: %v, ждали своё+публичное", titles(res))
	}
	if gotSet["b-private"] {
		t.Fatalf("чужое приватное %q должно быть скрыто правилами", "b-private")
	}

	// Суперюзер видит всё.
	su, _ := mustSuperuser(t, app)
	resSu, err := CursorRecords(app, notes, &core.RequestInfo{Auth: su},
		true, "", nil, sorts, "", 50)
	if err != nil {
		t.Fatalf("CursorRecords (суперюзер): %v", err)
	}
	if len(resSu.Records) != 4 {
		t.Fatalf("суперюзер: %d записей, ждали 4", len(resSu.Records))
	}

	// Мягкое удаление публичной записи: пользователю исчезает,
	// суперюзеру остаётся видна.
	if err := app.Delete(pubB); err != nil {
		t.Fatalf("мягкое удаление: %v", err)
	}
	res2, err := CursorRecords(app, notes, &core.RequestInfo{Auth: a},
		true, "", nil, sorts, "", 50)
	if err != nil {
		t.Fatalf("CursorRecords после удаления: %v", err)
	}
	for _, tt := range titles(res2) {
		if tt == "b-public" {
			t.Fatalf("удалённая запись видна пользователю: %v", titles(res2))
		}
	}
	if len(res2.Records) != 2 {
		t.Fatalf("после удаления у пользователя %d записей, ждали 2", len(res2.Records))
	}
	resSu2, err := CursorRecords(app, notes, &core.RequestInfo{Auth: su},
		true, "", nil, sorts, "", 50)
	if err != nil {
		t.Fatalf("CursorRecords суперюзера после удаления: %v", err)
	}
	if len(resSu2.Records) != 4 {
		t.Fatalf("суперюзер после удаления: %d записей, ждали 4", len(resSu2.Records))
	}

	// Фильтр с параметрами {:имя} и правилами одновременно.
	res3, err := CursorRecords(app, notes, &core.RequestInfo{Auth: a},
		true, `visibility = {:v}`, dbx.Params{"v": "private"}, sorts, "", 50)
	if err != nil {
		t.Fatalf("CursorRecords с фильтром: %v", err)
	}
	got := titles(res3)
	if len(got) != 1 || got[0] != "a-private" {
		t.Fatalf("фильтр приватных: %v, ждали [a-private]", got)
	}

	// Убывающая сортировка по тексту.
	res4, err := CursorRecords(app, notes, &core.RequestInfo{Auth: su},
		true, "", nil, []CursorSort{{Column: "title", Desc: true}}, "", 50)
	if err != nil {
		t.Fatalf("CursorRecords desc: %v", err)
	}
	got = titles(res4)
	if len(got) != 4 || got[0] != "b-public" || got[3] != "a-private" {
		t.Fatalf("убывающая сортировка: %v", got)
	}
}

func TestCursorRecordsSessionsContinuation(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	u := mustUser(t, app, "pg-s@seed.test")
	grants := map[string]bool{}
	for i := 0; i < 5; i++ {
		g, _ := mustSession(t, app, u.Id, "dev-"+string(rune('a'+i)))
		grants[g] = true
	}
	col := mustCollection(t, app, "seed_sessions")
	sorts := []CursorSort{{Column: "created_at", Desc: true}}

	var seen []string
	cursor := ""
	for {
		res, err := CursorRecords(app, col, &core.RequestInfo{Auth: u},
			false, "user = {:uid}", dbx.Params{"uid": u.Id}, sorts, cursor, 2)
		if err != nil {
			t.Fatalf("CursorRecords: %v", err)
		}
		for _, r := range res.Records {
			g := asStr(r.Get("grant_id"))
			if !grants[g] {
				t.Fatalf("чужая/неизвестная сессия в выдаче: %q", g)
			}
			seen = append(seen, g)
		}
		if !res.HasMore {
			break
		}
		if res.NextCursor == "" {
			t.Fatal("hasMore=true без курсора")
		}
		cursor = res.NextCursor
	}
	if len(seen) != len(grants) {
		t.Fatalf("собрано %d сессий из %d (дубли/потери?): %v", len(seen), len(grants), seen)
	}
	dup := map[string]bool{}
	for _, g := range seen {
		if dup[g] {
			t.Fatalf("дубль сессии %q при листании", g)
		}
		dup[g] = true
	}
}

// ------------------------------------------------------------ эндпоинты

func TestRecordsCursorEndpoint(t *testing.T) {
	t.Run("superuser paginates users", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			mustUser(t, app, "rc-a@seed.test")
			mustUser(t, app, "rc-b@seed.test")
			mustUser(t, app, "rc-c@seed.test")
			_, suTok := mustSuperuser(t, app)
			return tests.ApiScenario{
				Name:            "page 1 of users",
				Method:          http.MethodGet,
				URL:             "/api/collections/users/records/cursor?limit=2&sort=-created",
				Headers:         map[string]string{"Authorization": suTok},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"items"`, `"nextCursor"`},
				AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
					body, err := io.ReadAll(res.Body)
					if err != nil {
						t.Fatalf("чтение тела: %v", err)
					}
					var parsed struct {
						Items      []map[string]any `json:"items"`
						NextCursor *string          `json:"nextCursor"`
					}
					if err := json.Unmarshal(body, &parsed); err != nil {
						t.Fatalf("JSON ответа: %v (%s)", err, body)
					}
					if len(parsed.Items) != 2 {
						t.Fatalf("элементов %d, ждали 2", len(parsed.Items))
					}
					if parsed.NextCursor == nil || *parsed.NextCursor == "" {
						t.Fatal("nextCursor пуст при неполной выборке")
					}
				},
			}
		})
	})

	t.Run("guest sees empty users list", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			mustUser(t, app, "rc-g@seed.test")
			return tests.ApiScenario{
				Name:            "guest: rule yields nothing",
				Method:          http.MethodGet,
				URL:             "/api/collections/users/records/cursor",
				ExpectedStatus:  200,
				ExpectedContent: []string{`"items":[]`},
			}
		})
	})

	t.Run("guest forbidden on locked collection", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			return tests.ApiScenario{
				Name:            "ListRule nil = superusers only",
				Method:          http.MethodGet,
				URL:             "/api/collections/seed_sessions/records/cursor",
				ExpectedStatus:  403,
				ExpectedContent: []string{`"status":403`},
			}
		})
	})

	t.Run("user sees self only", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			a := mustUser(t, app, "rc-ua@seed.test")
			b := mustUser(t, app, "rc-ub@seed.test")
			_, cka := mustSession(t, app, a.Id, "a")
			return tests.ApiScenario{
				Name:               "self-scoped list",
				Method:             http.MethodGet,
				URL:                "/api/collections/users/records/cursor?limit=50",
				Headers:            map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + cka},
				ExpectedStatus:     200,
				ExpectedContent:    []string{`"` + a.Id + `"`},
				NotExpectedContent: []string{`"` + b.Id + `"`},
			}
		})
	})

	t.Run("validation errors", func(t *testing.T) {
		bad := []struct{ name, url string }{
			{"лимит 0", "?limit=0"},
			{"лимит выше потолка", "?limit=999"},
			{"неизвестная колонка сортировки", "?sort=нет_такой"},
			{"макрос в сортировке", "?sort=@random"},
			{"чужой курсор", "?cursor=zzz"},
		}
		for _, c := range bad {
			t.Run(c.name, func(t *testing.T) {
				runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
					mustUser(t, app, "rc-v@seed.test")
					_, suTok := mustSuperuser(t, app)
					return tests.ApiScenario{
						Method:          http.MethodGet,
						URL:             "/api/collections/users/records/cursor" + c.url,
						Headers:         map[string]string{"Authorization": suTok},
						ExpectedStatus:  400,
						ExpectedContent: []string{`"status":400`},
					}
				})
			})
		}
	})

	t.Run("hidden sort field forbidden for user", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			a := mustUser(t, app, "rc-h@seed.test")
			_, cka := mustSession(t, app, a.Id, "a")
			// tokenKey — скрытое поле users: сортировка по нему
			// разрешена только суперюзеру (как в штатном списке).
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/collections/users/records/cursor?sort=-tokenKey",
				Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + cka},
				ExpectedStatus:  400,
				ExpectedContent: []string{`"status":400`},
			}
		})
	})

	t.Run("filter and with_total", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			a := mustUser(t, app, "rc-fa@seed.test")
			mustUser(t, app, "rc-fb@seed.test")
			_, suTok := mustSuperuser(t, app)
			return tests.ApiScenario{
				Method:         http.MethodGet,
				URL:            "/api/collections/users/records/cursor?limit=1&with_total=1&filter=email%3D%22rc-fa%40seed.test%22",
				Headers:        map[string]string{"Authorization": suTok},
				ExpectedStatus: 200,
				ExpectedContent: []string{
					`"` + a.Id + `"`,
					`"totalItems":1`,
					`"nextCursor":null`,
				},
			}
		})
	})
}

func TestSeedSessionsEndpointCursor(t *testing.T) {
	t.Run("paged via X-Next-Cursor", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "sc-u@seed.test")
			g1, ck := mustSession(t, app, u.Id, "laptop")
			g2, _ := mustSession(t, app, u.Id, "phone")
			g3, _ := mustSession(t, app, u.Id, "tablet")
			return tests.ApiScenario{
				Name:            "limit=2 из 3 сессий",
				Method:          http.MethodGet,
				URL:             "/api/seed/sessions?limit=2",
				Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"session_id"`},
				AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
					body, _ := io.ReadAll(res.Body)
					var items []map[string]any
					if err := json.Unmarshal(body, &items); err != nil {
						t.Fatalf("JSON: %v", err)
					}
					if len(items) != 2 {
						t.Fatalf("сессий %d, ждали 2", len(items))
					}
					if res.Header.Get("X-Next-Cursor") == "" {
						t.Fatal("нет заголовка X-Next-Cursor при неполной выборке")
					}
					// на первой странице — две из трёх
					_ = g1
					_ = g2
					_ = g3
				},
			}
		})
	})

	t.Run("default response unchanged", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "sc-d@seed.test")
			g, ck := mustSession(t, app, u.Id, "laptop")
			return tests.ApiScenario{
				Method:         http.MethodGet,
				URL:            "/api/seed/sessions",
				Headers:        map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus: 200,
				ExpectedContent: []string{
					`"` + g + `"`,
					`"device_name":"laptop"`,
					`"created_at"`,
					`"current":true`,
				},
				AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
					if res.Header.Get("X-Next-Cursor") != "" {
						t.Fatal("одна страница не должна нести курсор")
					}
				},
			}
		})
	})

	t.Run("revoked filter", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "sc-r@seed.test")
			live, ck := mustSession(t, app, u.Id, "live")
			gone, _ := mustSession(t, app, u.Id, "gone")
			// отзываем вторую сессию напрямую в базе
			rec, err := app.FindFirstRecordByFilter("seed_sessions", "grant_id={:g}", dbx.Params{"g": gone})
			if err != nil {
				t.Fatalf("поиск сессии: %v", err)
			}
			rec.Set("revoked", true)
			if err := app.Save(rec); err != nil {
				t.Fatalf("отзыв: %v", err)
			}
			return tests.ApiScenario{
				Method:             http.MethodGet,
				URL:                "/api/seed/sessions?revoked=false",
				Headers:            map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus:     200,
				ExpectedContent:    []string{`"` + live + `"`},
				NotExpectedContent: []string{`"` + gone + `"`},
			}
		})
	})

	t.Run("bad params", func(t *testing.T) {
		bad := []struct{ name, url, want string }{
			{"неизвестный параметр", "?foo=1", `"error":"unknown_param"`},
			{"сортировка вне белого списка", "?sort=secret_hash", `"error":"bad_sort"`},
			{"лимит 0", "?limit=0", `"error":"bad_limit"`},
			{"лимит выше 100", "?limit=500", `"error":"bad_limit"`},
			{"мусор в дате", "?created_from=не-дата", `"error":"bad_date"`},
			{"мусор в стране", "?ip_country=12", `"error":"bad_ip_country"`},
			{"мусор в revoked", "?revoked=может-быть", `"error":"bad_revoked"`},
			{"битый курсор", "?cursor=!!!", `"error":"bad_cursor"`},
		}
		for _, c := range bad {
			t.Run(c.name, func(t *testing.T) {
				runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
					u := mustUser(t, app, "sc-b@seed.test")
					_, ck := mustSession(t, app, u.Id, "x")
					return tests.ApiScenario{
						Method:          http.MethodGet,
						URL:             "/api/seed/sessions" + c.url,
						Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
						ExpectedStatus:  400,
						ExpectedContent: []string{c.want},
					}
				})
			})
		}
	})
}

// ------------------- доп. пункты плана: индекс, надгробия, гибрид

// Пункт 1: индекс под горячий курсорный план (владелец + дата).
func TestSessionsUserCreatedIndex(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	var names []string
	err := app.NonconcurrentDB().NewQuery(
		"SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'seed_sessions'",
	).Column(&names)
	if err != nil {
		t.Fatalf("список индексов: %v", err)
	}
	for _, n := range names {
		if n == "idx_seed_sessions_user_created" {
			return
		}
	}
	t.Fatalf("нет индекса idx_seed_sessions_user_created, есть только %v", names)
}

// Пункт 2: список надгробий с курсором.
func TestSeedDeletedEndpointCursor(t *testing.T) {
	// Три удалённые сессии листаются по две; продолжение по курсору
	// из заголовка отдаёт остаток без повторов.
	t.Run("paged tombstones", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "del-u@seed.test")
			var ids []string
			for _, dev := range []string{"d1", "d2", "d3"} {
				g, _ := mustSession(t, app, u.Id, dev)
				rec, err := app.FindFirstRecordByFilter("seed_sessions", "grant_id={:g}", dbx.Params{"g": g})
				if err != nil {
					t.Fatalf("сессия %s: %v", dev, err)
				}
				if err := app.Delete(rec); err != nil {
					t.Fatalf("мягкое удаление %s: %v", dev, err)
				}
				ids = append(ids, rec.Id)
			}
			su, suTok := mustSuperuser(t, app)
			return tests.ApiScenario{
				Name:            "limit=2 из 3 надгробий",
				Method:          http.MethodGet,
				URL:             "/api/seed/deleted?collection=seed_sessions&limit=2",
				Headers:         map[string]string{"Authorization": suTok},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"deleted_at"`},
				AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
					body, _ := io.ReadAll(res.Body)
					var items []map[string]any
					if err := json.Unmarshal(body, &items); err != nil {
						t.Fatalf("JSON: %v", err)
					}
					if len(items) != 2 {
						t.Fatalf("надгробий %d, ждали 2", len(items))
					}
					cursor := res.Header.Get("X-Next-Cursor")
					if cursor == "" {
						t.Fatal("нет X-Next-Cursor при неполной выборке")
					}
					// Продолжение: строго остаток (одно надгробие), без повторов.
					col := mustCollection(t, app, "seed_sessions")
					res2, err := CursorRecords(app, col, &core.RequestInfo{Auth: su}, false,
						`deleted_at != null && deleted_at != ""`, nil,
						[]CursorSort{{Column: "deleted_at", Desc: true}}, cursor, 2)
					if err != nil {
						t.Fatalf("продолжение: %v", err)
					}
					if len(res2.Records) != 1 {
						t.Fatalf("на второй странице %d записей, ждали 1", len(res2.Records))
					}
					page1 := map[string]bool{}
					for _, it := range items {
						page1[it["id"].(string)] = true
					}
					if page1[res2.Records[0].Id] {
						t.Fatalf("повтор надгробия %s на второй странице", res2.Records[0].Id)
					}
				},
			}
		})
	})

	t.Run("bad params", func(t *testing.T) {
		bad := []struct{ name, url, want string }{
			{"неизвестный параметр", "&foo=1", `"error":"unknown_param"`},
			{"сортировка вне белого списка", "&sort=grant_id", `"error":"bad_sort"`},
			{"лимит 0", "&limit=0", `"error":"bad_limit"`},
			{"битый курсор", "&cursor=!!!", `"error":"bad_cursor"`},
		}
		for _, c := range bad {
			t.Run(c.name, func(t *testing.T) {
				runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
					_, suTok := mustSuperuser(t, app)
					return tests.ApiScenario{
						Method:          http.MethodGet,
						URL:             "/api/seed/deleted?collection=seed_sessions" + c.url,
						Headers:         map[string]string{"Authorization": suTok},
						ExpectedStatus:  400,
						ExpectedContent: []string{c.want},
					}
				})
			})
		}
	})
}

// Пункт 4: штатный /records несёт X-Next-Cursor для продолжения
// курсорным режимом (гибрид офсет → курсор).
func TestRecordsListCursorHint(t *testing.T) {
	// Пять пользователей с разнесёнными датами: порядок детерминирован
	// и в офсетном, и в курсорном режиме.
	seedUsers := func(t testing.TB, app *tests.TestApp) (*core.Record, string) {
		t.Helper()
		for i := 0; i < 5; i++ {
			u := mustUser(t, app, fmt.Sprintf("hint-%d@seed.test", i))
			ts := fmt.Sprintf("2026-09-01 10:%02d:00.000Z", i)
			_, err := app.NonconcurrentDB().NewQuery(
				"UPDATE users SET created = {:c} WHERE id = {:id}",
			).Bind(dbx.Params{"c": ts, "id": u.Id}).Execute()
			if err != nil {
				t.Fatalf("дата пользователя: %v", err)
			}
		}
		return mustSuperuser(t, app)
	}

	t.Run("header and exact continuation", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			su, suTok := seedUsers(t, app)
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/collections/users/records?perPage=2&sort=-created",
				Headers:         map[string]string{"Authorization": suTok},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"items"`},
				AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
					cursor := res.Header.Get("X-Next-Cursor")
					if cursor == "" {
						t.Fatal("нет X-Next-Cursor у штатного списка с сортировкой")
					}
					body, _ := io.ReadAll(res.Body)
					var parsed struct {
						Items []map[string]any `json:"items"`
					}
					if err := json.Unmarshal(body, &parsed); err != nil {
						t.Fatalf("JSON: %v", err)
					}
					if len(parsed.Items) != 2 {
						t.Fatalf("элементов %d, ждали 2", len(parsed.Items))
					}
					page1 := map[string]bool{}
					for _, it := range parsed.Items {
						page1[it["id"].(string)] = true
					}
					col := mustCollection(t, app, "users")
					res2, err := CursorRecords(app, col, &core.RequestInfo{Auth: su}, true,
						"", nil, []CursorSort{{Column: "created", Desc: true}}, cursor, 10)
					if err != nil {
						t.Fatalf("курсорное продолжение: %v", err)
					}
					// Фикстура тестов сама содержит пользователей, поэтому
					// остаток считаем от общего числа, а не от константы.
					var total int
					if err := app.NonconcurrentDB().NewQuery("SELECT COUNT(*) FROM users").Row(&total); err != nil {
						t.Fatalf("подсчёт пользователей: %v", err)
					}
					if len(res2.Records) != total-2 {
						t.Fatalf("в продолжении %d записей, ждали %d", len(res2.Records), total-2)
					}
					for _, r := range res2.Records {
						if page1[r.Id] {
							t.Fatalf("запись %s есть и на офсетной странице, и в продолжении", r.Id)
						}
					}
				},
			}
		})
	})

	t.Run("no header without sort", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			_, suTok := seedUsers(t, app)
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/collections/users/records?perPage=2",
				Headers:         map[string]string{"Authorization": suTok},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"items"`},
				AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
					if res.Header.Get("X-Next-Cursor") != "" {
						t.Fatal("без явной сортировки заголовок ставиться не должен")
					}
				},
			}
		})
	})

	t.Run("no header on last page", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			_, suTok := seedUsers(t, app)
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/collections/users/records?perPage=50&sort=-created",
				Headers:         map[string]string{"Authorization": suTok},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"items"`},
				AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
					if res.Header.Get("X-Next-Cursor") != "" {
						t.Fatal("на последней странице заголовок ставиться не должен")
					}
				},
			}
		})
	})
}
