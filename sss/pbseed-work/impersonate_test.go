package main

// impersonate_test.go — маска администратора (модель B: маска = подпись).
//
// Маску надевает суперюзер или админ: права остаются у исполнителя
// (модель B), а сессия маски помечается зарезервированным именем
// "@administrator" и атрибуцией «от чьего имени». Зарезервированное
// пространство имён (префикс "@") обычным входам запрещено. Эти тесты
// проверяют: маску может надеть только администрация; сессия маски
// помечена зарезервированным именем; обычный вход с зарезервированным
// именем отклоняется; сессия маски видна в списке устройств; пустой
// user_id снимает маску. Многошаговые проверки прав исполнителя под
// маской — в maskb_test.go.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/tests"
)

// TestImpersonateBySuperuser подтверждает, что суперюзер надевает маску:
// ответ содержит токен и пометку, а для юзера создана сессия с
// зарезервированным именем.
func TestImpersonateBySuperuser(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "mask-target@seed.test")
		_, suTok := mustSuperuser(t, app)

		sc := tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/impersonate",
			Headers:         map[string]string{"Authorization": suTok},
			Body:            strings.NewReader(`{"user_id":"` + u.Id + `"}`),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"access"`, `"session_id"`, `"masked":true`, `"masked_as":"` + u.Id + `"`},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			// Маска суперюзера вешается на целевого юзера (суперюзера нет
			// в коллекции users) и помечена зарезервированным именем +
			// атрибуцией «от чьего имени».
			dn := rowStamp(t, app,
				"SELECT device_name FROM seed_sessions WHERE user = {:uid} ORDER BY created_at DESC LIMIT 1",
				dbx.Params{"uid": u.Id})
			if dn != seedAdminDeviceName {
				t.Errorf("impersonation session device_name=%q, want %q", dn, seedAdminDeviceName)
			}
			ob := rowStamp(t, app,
				"SELECT on_behalf_of FROM seed_sessions WHERE user = {:uid} ORDER BY created_at DESC LIMIT 1",
				dbx.Params{"uid": u.Id})
			if ob != u.Id {
				t.Errorf("mask session on_behalf_of=%q, want %q", ob, u.Id)
			}
			// Токен в ответе — токен ИСПОЛНИТЕЛЯ (суперюзера), а не юзера:
			// суперюзер сохраняет свои права (модель B).
			var body struct {
				MaskedAs string `json:"masked_as"`
			}
			_ = readJSON(t, res, &body)
			if body.MaskedAs != u.Id {
				t.Errorf("masked_as=%q, want %q", body.MaskedAs, u.Id)
			}
		}
		return sc
	})
}

// TestImpersonateRequiresSuperuser подтверждает, что обычный юзер не
// может надеть маску (403).
func TestImpersonateRequiresSuperuser(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "mask-attacker@seed.test")
		target := mustUser(t, app, "mask-victim@seed.test")

		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/impersonate",
			Headers:         map[string]string{"Authorization": mustToken(t, u)},
			Body:            strings.NewReader(`{"user_id":"` + target.Id + `"}`),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"error"`, `"forbidden"`},
		}
	})
}

// TestImpersonateGuestForbidden подтверждает, что гость без токена маску
// не наденет (403).
func TestImpersonateGuestForbidden(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		target := mustUser(t, app, "mask-guest-target@seed.test")
		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/impersonate",
			Body:            strings.NewReader(`{"user_id":"` + target.Id + `"}`),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"error"`, `"forbidden"`},
		}
	})
}

// TestImpersonateUnknownUser подтверждает 404 на несуществующего юзера.
func TestImpersonateUnknownUser(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		_, suTok := mustSuperuser(t, app)
		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/impersonate",
			Headers:         map[string]string{"Authorization": suTok},
			Body:            strings.NewReader(`{"user_id":"missinguserid00000"}`),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"error"`, `"no_user"`},
		}
	})
}

// TestImpersonateEmptyUserUnmasks подтверждает, что пустой user_id — это
// снятие маски (модель B): успешный идемпотентный ответ, даже если
// активной маски не было.
func TestImpersonateEmptyUserUnmasks(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		_, suTok := mustSuperuser(t, app)
		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/impersonate",
			Headers:         map[string]string{"Authorization": suTok},
			Body:            strings.NewReader(`{}`),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"ok":true`, `"unmasked":true`},
		}
	})
}

// TestLoginRejectsReservedDeviceName подтверждает, что обычный вход с
// зарезервированным именем (префикс "@") отклоняется — пространство
// служебных имён принадлежит серверу.
func TestLoginRejectsReservedDeviceName(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		pk := strings.Repeat("ab", 32)  // 64 hex-символа
		sig := strings.Repeat("cd", 64) // 128 hex-символов (формат)
		body := `{"public_key":"` + pk + `","signature":"` + sig +
			`","purpose":"register","nonce":"whatever","device_name":"@administrator"}`
		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/login",
			Body:            strings.NewReader(body),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"error"`, `"reserved_device_name"`},
		}
	})
}

// TestLoginRejectsAnyReservedPrefix подтверждает, что весь префикс "@"
// зарезервирован, а не только точное имя администратора.
func TestLoginRejectsAnyReservedPrefix(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		pk := strings.Repeat("ef", 32)
		sig := strings.Repeat("01", 64)
		body := `{"public_key":"` + pk + `","signature":"` + sig +
			`","purpose":"login","nonce":"whatever","device_name":"  @my-phone"}`
		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/login",
			Body:            strings.NewReader(body),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"error"`, `"reserved_device_name"`},
		}
	})
}

// TestAdminSessionVisibleInList подтверждает, что сессия с
// зарезервированным именем видна юзеру в списке устройств (маска
// прозрачна для владельца).
func TestAdminSessionVisibleInList(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "mask-visible@seed.test")
		_, ck := mustSession(t, app, u.Id, seedAdminDeviceName)

		return tests.ApiScenario{
			Method:          http.MethodGet,
			URL:             "/api/seed/sessions",
			Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"@administrator"`},
		}
	})
}
