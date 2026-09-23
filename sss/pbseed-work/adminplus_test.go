package main

// adminplus_test.go — «админ+» (первый админ по дате создания):
// защита от бана и смены роли, право повышать до «admin», выбор
// носителя звания и его переезд при выбытии.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// backdateCreated сдвигает стоковое поле `created` записи `users` в
// прошлое, чтобы порядок создания в фикстуре был детерминированным
// (вживую записи создаются в разные моменты, в тесте — в одну
// миллисекунду).
//
// Параметры:
//   - t: testing.TB — тест;
//   - app: core.App — приложение;
//   - id: string — запись users;
//   - ago: time.Duration — на сколько в прошлое сдвинуть.
func backdateCreated(t testing.TB, app core.App, id string, ago time.Duration) {
	t.Helper()
	v := time.Now().UTC().Add(-ago).Format("2006-01-02 15:04:05.000") + "Z"
	if _, err := app.NonconcurrentDB().NewQuery("UPDATE users SET created = {:c} WHERE id = {:id}").
		Bind(dbx.Params{"c": v, "id": id}).Execute(); err != nil {
		t.Fatalf("сдвиг created: %v", err)
	}
}

// adminPlusFixture создаёт «админа+» (самый ранний) и обычного
// ролевого админа; возвращает обоих.
//
// Параметры:
//   - t: testing.TB — тест;
//   - app: core.App — приложение;
//   - tag: string — суффикс почт фикстуры.
//
// Возвращает: *core.Record — «админ+»;
// *core.Record — второй админ.
func adminPlusFixture(t testing.TB, app core.App, tag string) (*core.Record, *core.Record) {
	t.Helper()
	plus := mustUser(t, app, "plus-"+tag+"@seed.test")
	plus.Set("role", seedRoleAdmin)
	if err := app.Save(plus); err != nil {
		t.Fatalf("сохранить админ+: %v", err)
	}
	backdateCreated(t, app, plus.Id, 2*time.Hour)
	adm := mustUser(t, app, "adm-"+tag+"@seed.test")
	adm.Set("role", seedRoleAdmin)
	if err := app.Save(adm); err != nil {
		t.Fatalf("сохранить админа: %v", err)
	}
	return plus, adm
}

// TestAdminPlusBanProtection — «админ+» нельзя забанить через REST
// никому, кроме суперюзера.
func TestAdminPlusBanProtection(t *testing.T) {
	t.Run("ролевой админ не банит админ+", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			plus, adm := adminPlusFixture(t, app, "ban")
			_, ck := mustSession(t, app, adm.Id, "dev")
			sc := tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + plus.Id,
				Headers:         map[string]string{"Authorization": mustToken(t, adm), "Cookie": "pb_seed=" + ck},
				Body:            strings.NewReader(`{"banned":true,"ban_reason":"попытка"}`),
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error"`, `"forbidden"`},
			}
			sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
				got, err := app.FindRecordById("users", plus.Id)
				if err != nil {
					t.Fatalf("чтение: %v", err)
				}
				if asBool(got.Get("banned")) {
					t.Errorf("бан админ+ сохранился, хотя запрос отказан")
				}
			}
			return sc
		})
	})

	t.Run("суперюзер банит админ+", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			plus, _ := adminPlusFixture(t, app, "ban-su")
			_, suTok := mustSuperuser(t, app)
			sc := tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + plus.Id,
				Headers:         map[string]string{"Authorization": suTok},
				Body:            strings.NewReader(`{"banned":true,"ban_reason":"решение владельца"}`),
				ExpectedStatus:  200,
				ExpectedContent: []string{`"banned":true`},
			}
			sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
				got, err := app.FindRecordById("users", plus.Id)
				if err != nil || !asBool(got.Get("banned")) {
					t.Errorf("бан суперюзером не сохранился: %v", err)
				}
			}
			return sc
		})
	})
}

// TestAdminPlusRoleProtected — роль «админ+» нельзя изменить через
// REST никому, кроме суперюзера (иначе бан обходился бы связкой
// «понизить, затем забанить»).
func TestAdminPlusRoleProtected(t *testing.T) {
	t.Run("ролевой админ не понижает админ+", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			plus, adm := adminPlusFixture(t, app, "demote")
			_, ck := mustSession(t, app, adm.Id, "dev")
			sc := tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + plus.Id,
				Headers:         map[string]string{"Authorization": mustToken(t, adm), "Cookie": "pb_seed=" + ck},
				Body:            strings.NewReader(`{"role":"user"}`),
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error"`, `"forbidden"`},
			}
			sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
				got, err := app.FindRecordById("users", plus.Id)
				if err != nil || asStr(got.Get("role")) != seedRoleAdmin {
					t.Errorf("роль админ+ изменилась: %v (%v)", asStr(got.Get("role")), err)
				}
			}
			return sc
		})
	})

	t.Run("суперюзер понижает админ+", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			plus, _ := adminPlusFixture(t, app, "demote-su")
			_, suTok := mustSuperuser(t, app)
			sc := tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + plus.Id,
				Headers:         map[string]string{"Authorization": suTok},
				Body:            strings.NewReader(`{"role":"user"}`),
				ExpectedStatus:  200,
				ExpectedContent: []string{`"role":"user"`},
			}
			sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
				got, err := app.FindRecordById("users", plus.Id)
				if err != nil || asStr(got.Get("role")) != seedRoleUser {
					t.Errorf("понижение суперюзером не сохранилось: %v (%v)", asStr(got.Get("role")), err)
				}
			}
			return sc
		})
	})
}

// TestAdminPlusPromotesAdmin — «админ+» (единственный из ролевых
// админов) может повышать до «admin».
func TestAdminPlusPromotesAdmin(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		plus, _ := adminPlusFixture(t, app, "promo")
		target := mustUser(t, app, "promo-target@seed.test")
		_, ck := mustSession(t, app, plus.Id, "dev")
		sc := tests.ApiScenario{
			Method:          http.MethodPatch,
			URL:             "/api/collections/users/records/" + target.Id,
			Headers:         map[string]string{"Authorization": mustToken(t, plus), "Cookie": "pb_seed=" + ck},
			Body:            strings.NewReader(`{"role":"admin"}`),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"role":"admin"`},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			got, err := app.FindRecordById("users", target.Id)
			if err != nil || asStr(got.Get("role")) != seedRoleAdmin {
				t.Errorf("назначение админа не сохранилось: %v (%v)", asStr(got.Get("role")), err)
			}
		}
		return sc
	})
}

// TestFirstAdminSelection — выбор «админ+»: самый ранний живой админ;
// при мягком удалении, понижении или стирании носителя звание переезжает
// к следующему по дате создания.
func TestFirstAdminSelection(t *testing.T) {
	app := newSeedTestApp(t)
	u1 := mustUser(t, app, "pick-1@seed.test")
	u2 := mustUser(t, app, "pick-2@seed.test")
	u3 := mustUser(t, app, "pick-3@seed.test")
	for i, u := range []*core.Record{u1, u2, u3} {
		u.Set("role", seedRoleAdmin)
		if err := app.Save(u); err != nil {
			t.Fatalf("роль %d: %v", i+1, err)
		}
		backdateCreated(t, app, u.Id, time.Duration(3-i)*time.Hour)
	}

	if got := firstAdminID(app); got != u1.Id {
		t.Fatalf("первый админ: %q, ждём %q", got, u1.Id)
	}
	if !isAdminPlus(app, u1) || isAdminPlus(app, u2) {
		t.Fatalf("isAdminPlus: u1=%v u2=%v", isAdminPlus(app, u1), isAdminPlus(app, u2))
	}

	// Мягкое удаление носителя — звание переезжает.
	u1.Set("deleted_at", time.Now().UTC().Format("2006-01-02 15:04:05.000")+"Z")
	if err := app.Save(u1); err != nil {
		t.Fatalf("мягкое удаление: %v", err)
	}
	if got := firstAdminID(app); got != u2.Id {
		t.Fatalf("после мягкого удаления: %q, ждём %q", got, u2.Id)
	}

	// Понижение носителя — звание переезжает.
	u2.Set("role", seedRoleUser)
	if err := app.Save(u2); err != nil {
		t.Fatalf("понижение: %v", err)
	}
	if got := firstAdminID(app); got != u3.Id {
		t.Fatalf("после понижения: %q, ждём %q", got, u3.Id)
	}

	// Админов не осталось — «админ+» нет.
	u3.Set("role", seedRoleUser)
	if err := app.Save(u3); err != nil {
		t.Fatalf("понижение последнего: %v", err)
	}
	if got := firstAdminID(app); got != "" {
		t.Fatalf("без админов: %q, ждём пусто", got)
	}
}
