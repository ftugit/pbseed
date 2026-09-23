package main

// role_test.go — роли пользователей сайта (user / moderator / admin).
//
// Роль — атрибут записи в таблице `users`, а не токен: права даёт
// колонка, которую читает правило коллекции и помощник seedAdmin.
// Проверяется: бэкфилл роли, консольное назначение, чтение пользователей
// по ролям, бан чужих записей админом, запрет самозаписи служебных
// полей, границы модератора (только чтение) и админские эндпоинты,
// доступные роли без суперюзера.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/tests"
)

// TestRoleBackfillOnBootstrap подтверждает, что записи без роли
// получают "user" на запуске (бэкфилл идемпотентен и не трогает
// назначенные роли).
func TestRoleBackfillOnBootstrap(t *testing.T) {
	app := newRegistryTestApp(t)

	plain := mustUser(t, app, "role-empty@seed.test") // роль не задана
	admin := mustUser(t, app, "role-kept@seed.test")
	admin.Set("role", seedRoleAdmin)
	if err := app.Save(admin); err != nil {
		t.Fatalf("save admin: %v", err)
	}

	if err := ensureSeedSchema(app); err != nil {
		t.Fatalf("re-bootstrap: %v", err)
	}

	got, err := app.FindRecordById("users", plain.Id)
	if err != nil {
		t.Fatalf("re-read plain: %v", err)
	}
	if asStr(got.Get("role")) != seedRoleUser {
		t.Errorf("empty role not backfilled: %q", asStr(got.Get("role")))
	}
	gotAdmin, err := app.FindRecordById("users", admin.Id)
	if err != nil {
		t.Fatalf("re-read admin: %v", err)
	}
	if asStr(gotAdmin.Get("role")) != seedRoleAdmin {
		t.Errorf("assigned role overwritten: %q", asStr(gotAdmin.Get("role")))
	}
}

// TestSetUserRoleConsole подтверждает консольное назначение роли:
// существующему юзеру роль обновляется, а для незнакомого ключа запись
// создаётся заранее.
func TestSetUserRoleConsole(t *testing.T) {
	app := newRegistryTestApp(t)

	key := strings.Repeat("5b", 32) // почта юзера = ключ@seed.local
	u := mustUser(t, app, key+"@seed.local")
	if err := setUserRole(app, key, seedRoleModerator); err != nil {
		t.Fatalf("setUserRole existing: %v", err)
	}
	got, err := app.FindRecordById("users", u.Id)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if asStr(got.Get("role")) != seedRoleModerator {
		t.Errorf("role not updated: %q", asStr(got.Get("role")))
	}

	freshKey := strings.Repeat("7a", 32)
	if err := setUserRole(app, freshKey, seedRoleAdmin); err != nil {
		t.Fatalf("setUserRole new: %v", err)
	}
	created, err := app.FindFirstRecordByData("users", "email", freshKey+"@seed.local")
	if err != nil || created == nil {
		t.Fatalf("pre-created record missing: %v", err)
	}
	if asStr(created.Get("role")) != seedRoleAdmin {
		t.Errorf("pre-created role: %q", asStr(created.Get("role")))
	}
}

// TestRoleReadsUsersByRule подтверждает ролевое правило чтения: обычный
// юзер видит только себя, модератор и админ — всех.
func TestRoleReadsUsersByRule(t *testing.T) {
	t.Run("moderator sees everyone", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			m := mustUser(t, app, "role-mod@seed.test")
			m.Set("role", seedRoleModerator)
			if err := app.Save(m); err != nil {
				t.Fatalf("save mod: %v", err)
			}
			x := mustUser(t, app, "role-x@seed.test")
			_, ck := mustSession(t, app, m.Id, "mod-device")
			return tests.ApiScenario{
				Method:         http.MethodGet,
				URL:            "/api/collections/users/records?perPage=100",
				Headers:        map[string]string{"Authorization": mustToken(t, m), "Cookie": "pb_seed=" + ck},
				ExpectedStatus: 200,
				ExpectedContent: []string{
					`"` + x.Id + `"`,
					`"` + m.Id + `"`,
				},
			}
		})
	})

	t.Run("plain user sees only self", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "role-plain@seed.test")
			other := mustUser(t, app, "role-other@seed.test")
			_, ck := mustSession(t, app, u.Id, "plain-device")
			return tests.ApiScenario{
				Method:             http.MethodGet,
				URL:                "/api/collections/users/records?perPage=100",
				Headers:            map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus:     200,
				ExpectedContent:    []string{`"totalItems":1`, `"` + u.Id + `"`},
				NotExpectedContent: []string{`"` + other.Id + `"`},
			}
		})
	})
}

// TestAdminRoleBansViaRest подтверждает, что админ по роли банит чужого
// юзера через штатный REST, но почту (открытый ключ) менять не может.
func TestAdminRoleBansViaRest(t *testing.T) {
	t.Run("ban another user", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			a := mustUser(t, app, "role-ban-admin@seed.test")
			a.Set("role", seedRoleAdmin)
			if err := app.Save(a); err != nil {
				t.Fatalf("save admin: %v", err)
			}
			b := mustUser(t, app, "role-ban-target@seed.test")
			_, ck := mustSession(t, app, a.Id, "admin-device")
			sc := tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + b.Id,
				Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + ck},
				Body:            strings.NewReader(`{"banned":true,"ban_reason":"нарушение"}`),
				ExpectedStatus:  200,
				ExpectedContent: []string{`"banned":true`},
			}
			sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
				got, err := app.FindRecordById("users", b.Id)
				if err != nil || !asBool(got.Get("banned")) {
					t.Errorf("ban not persisted: %v", err)
				}
			}
			return sc
		})
	})

	t.Run("email stays admin-protected", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			a := mustUser(t, app, "role-mail-admin@seed.test")
			a.Set("role", seedRoleAdmin)
			if err := app.Save(a); err != nil {
				t.Fatalf("save admin: %v", err)
			}
			b := mustUser(t, app, "role-mail-target@seed.test")
			_, ck := mustSession(t, app, a.Id, "admin-device")
			return tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + b.Id,
				Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + ck},
				Body:            strings.NewReader(`{"email":"stolen@seed.local"}`),
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error"`, `"forbidden"`},
			}
		})
	})
}

// TestUserCannotSelfPromote подтверждает, что обычный юзер не может
// назначить себе роль или снять бан — служебные поля охраняются.
func TestUserCannotSelfPromote(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "role-selfpromote@seed.test")
		_, ck := mustSession(t, app, u.Id, "device")
		return tests.ApiScenario{
			Method:          http.MethodPatch,
			URL:             "/api/collections/users/records/" + u.Id,
			Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
			Body:            strings.NewReader(`{"role":"admin"}`),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"error"`, `"forbidden"`},
		}
	})
}

// TestModeratorReadOnly подтверждает границы модератора: чужие записи
// он читает, но менять и удалять ничего не может.
func TestModeratorReadOnly(t *testing.T) {
	t.Run("hard-delete refused", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			m := mustUser(t, app, "role-mod-del@seed.test")
			m.Set("role", seedRoleModerator)
			if err := app.Save(m); err != nil {
				t.Fatalf("save mod: %v", err)
			}
			_, ck := mustSession(t, app, m.Id, "mod-device")
			return tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/api/seed/hard-delete",
				Headers:         map[string]string{"Authorization": mustToken(t, m), "Cookie": "pb_seed=" + ck},
				Body:            strings.NewReader(`{"collection":"seed_sessions","ids":["whateverid000000"]}`),
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error"`, `"forbidden"`},
			}
		})
	})

	t.Run("impersonate refused", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			m := mustUser(t, app, "role-mod-imp@seed.test")
			m.Set("role", seedRoleModerator)
			if err := app.Save(m); err != nil {
				t.Fatalf("save mod: %v", err)
			}
			target := mustUser(t, app, "role-mod-imp-target@seed.test")
			return tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/api/seed/impersonate",
				Headers:         map[string]string{"Authorization": mustToken(t, m)},
				Body:            strings.NewReader(`{"user_id":"` + target.Id + `"}`),
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error"`, `"forbidden"`},
			}
		})
	})
}

// TestAdminRoleModeration подтверждает, что роль "admin" без суперюзера
// даёт полный цикл модерации: список удалённых, жёсткое удаление,
// маска администратора.
func TestAdminRoleModeration(t *testing.T) {
	t.Run("hard-delete works", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			a := mustUser(t, app, "role-hd-admin@seed.test")
			a.Set("role", seedRoleAdmin)
			if err := app.Save(a); err != nil {
				t.Fatalf("save admin: %v", err)
			}
			grant, ck := mustSession(t, app, a.Id, "admin-device")
			sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", grant)
			if err != nil {
				t.Fatalf("find session: %v", err)
			}
			sc := tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/api/seed/hard-delete",
				Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + ck},
				Body:            strings.NewReader(`{"collection":"seed_sessions","ids":["` + sess.Id + `"]}`),
				ExpectedStatus:  200,
				ExpectedContent: []string{`"deleted":1`},
			}
			sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if _, err := app.FindFirstRecordByData("seed_sessions", "grant_id", grant); err == nil {
					t.Error("session survived hard delete")
				}
			}
			return sc
		})
	})

}

// TestAdminRoleSeesDeletedList подтверждает, что список мягко удалённых
// записей доступен роли "admin" без суперюзера.
func TestAdminRoleSeesDeletedList(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		a := mustUser(t, app, "role-del-admin@seed.test")
		a.Set("role", seedRoleAdmin)
		if err := app.Save(a); err != nil {
			t.Fatalf("save admin: %v", err)
		}
		_, ck := mustSession(t, app, a.Id, "admin-device")
		return tests.ApiScenario{
			Method:          http.MethodGet,
			URL:             "/api/seed/deleted?collection=seed_sessions",
			Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + ck},
			ExpectedStatus:  200,
			ExpectedContent: []string{`[]`},
		}
	})
}

// TestAdminRoleImpersonates подтверждает, что роль "admin" надевает
// маску модели B (кука не нужна — путь в белом списке мидлвейра, права
// решает обработчик): ответ помечен "masked", права остаются у админа.
func TestAdminRoleImpersonates(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		a := mustUser(t, app, "role-imp-admin@seed.test")
		a.Set("role", seedRoleAdmin)
		if err := app.Save(a); err != nil {
			t.Fatalf("save admin: %v", err)
		}
		target := mustUser(t, app, "role-imp-target@seed.test")
		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/impersonate",
			Headers:         map[string]string{"Authorization": mustToken(t, a)},
			Body:            strings.NewReader(`{"user_id":"` + target.Id + `"}`),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"masked":true`, `"masked_as":"` + target.Id + `"`},
		}
	})
}

// TestAdminCannotPromoteToAdmin — запрет плодить админов: админ по роли
// не может повысить до "admin" (это делают только консоль и суперюзер),
// но назначает "moderator".
func TestAdminCannotPromoteToAdmin(t *testing.T) {
	t.Run("admin cannot make admin", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			plus := mustUser(t, app, "role-promo-plus@seed.test")
			plus.Set("role", seedRoleAdmin)
			if err := app.Save(plus); err != nil {
				t.Fatalf("save admin+: %v", err)
			}
			backdateCreated(t, app, plus.Id, 2*time.Hour)
			a := mustUser(t, app, "role-promo-admin@seed.test")
			a.Set("role", seedRoleAdmin)
			if err := app.Save(a); err != nil {
				t.Fatalf("save admin: %v", err)
			}
			b := mustUser(t, app, "role-promo-target@seed.test")
			_, ck := mustSession(t, app, a.Id, "admin-device")
			return tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + b.Id,
				Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + ck},
				Body:            strings.NewReader(`{"role":"admin"}`),
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error"`, `"forbidden"`},
			}
		})
	})
	t.Run("admin can make moderator", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			plus := mustUser(t, app, "role-promo2-plus@seed.test")
			plus.Set("role", seedRoleAdmin)
			if err := app.Save(plus); err != nil {
				t.Fatalf("save admin+: %v", err)
			}
			backdateCreated(t, app, plus.Id, 2*time.Hour)
			a := mustUser(t, app, "role-promo2-admin@seed.test")
			a.Set("role", seedRoleAdmin)
			if err := app.Save(a); err != nil {
				t.Fatalf("save admin: %v", err)
			}
			b := mustUser(t, app, "role-promo2-target@seed.test")
			_, ck := mustSession(t, app, a.Id, "admin-device")
			sc := tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + b.Id,
				Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + ck},
				Body:            strings.NewReader(`{"role":"moderator"}`),
				ExpectedStatus:  200,
				ExpectedContent: []string{`"moderator"`},
			}
			sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
				got, err := app.FindRecordById("users", b.Id)
				if err != nil || asStr(got.Get("role")) != seedRoleModerator {
					t.Errorf("role not set to moderator: %v", err)
				}
			}
			return sc
		})
	})
	t.Run("superuser can make admin", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			_, suTok := mustSuperuser(t, app)
			b := mustUser(t, app, "role-promo3-target@seed.test")
			sc := tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + b.Id,
				Headers:         map[string]string{"Authorization": suTok},
				Body:            strings.NewReader(`{"role":"admin"}`),
				ExpectedStatus:  200,
				ExpectedContent: []string{`"role":"admin"`},
			}
			sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
				got, err := app.FindRecordById("users", b.Id)
				if err != nil || asStr(got.Get("role")) != seedRoleAdmin {
					t.Errorf("superuser failed to set admin: %v", err)
				}
			}
			return sc
		})
	})
}
