package main

// schema_registry_test.go — проверки единого реестра схемы.
//
// Реестр (см. schema_registry.go) должен быть единственным источником
// истины для служебных коллекций: тесты подтверждают, что живой схеме
// соответствует именно он, дрейф правил служебных коллекций
// восстанавливается, дрейф пользователей — только логируется, а
// удалённое поле возвращается на место.

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/types"
)

// newRegistryTestApp поднимает тестовое приложение с применённым
// реестром схемы (без перехватчиков и маршрутов — они этим тестам не
// нужны).
//
// Параметры:
//   - t: testing.TB — контекст теста.
//
// Возвращает: *tests.TestApp — готовое приложение.
func newRegistryTestApp(t testing.TB) *tests.TestApp {
	t.Helper()
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatalf("new test app: %v", err)
	}
	if err := ensureSeedSchema(app); err != nil {
		t.Fatalf("ensureSeedSchema: %v", err)
	}
	return app
}

// captureLog перехватывает вывод стандартного логгера на время
// выполнения фукнции.
//
// Параметры:
//   - t: testing.TB — контекст теста.
//   - fn: func() — код, чей вывод лога перехватывается.
//
// Возвращает: string — весь записанный за это время лог.
func captureLog(t testing.TB, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	fn()
	return buf.String()
}

// TestSeedSchemaRegistryMatchesLive подтверждает, что реестр схемы и
// живые коллекции полностью совпадают: наборы полей, правила, индексы,
// состав реестра мягкого удаления.
func TestSeedSchemaRegistryMatchesLive(t *testing.T) {
	app := newRegistryTestApp(t)

	for _, entry := range seedSchema {
		col, err := app.FindCollectionByNameOrId(entry.Name)
		if err != nil {
			t.Fatalf("registry collection %s missing: %v", entry.Name, err)
		}
		expected := entry.Build(col.Id)
		for i := range expected.Fields {
			if col.Fields.GetByName(expected.Fields[i].GetName()) == nil {
				t.Errorf("collection %s: registry field %q missing in live schema",
					entry.Name, expected.Fields[i].GetName())
			}
		}
		if len(col.Indexes) != len(expected.Indexes) {
			t.Errorf("collection %s: index count live=%d registry=%d",
				entry.Name, len(col.Indexes), len(expected.Indexes))
		}
		for _, want := range expected.Indexes {
			found := false
			for _, got := range col.Indexes {
				if got == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("collection %s: index missing: %s", entry.Name, want)
			}
		}
	}

	// Реестр мягкого удаления — производный от реестра схемы.
	for _, entry := range seedSchema {
		if softDeleteWhitelist[entry.Name] != entry.SoftDelete {
			t.Errorf("softDeleteWhitelist[%s]=%v, registry SoftDelete=%v",
				entry.Name, softDeleteWhitelist[entry.Name], entry.SoftDelete)
		}
	}
}

// TestSyncSeedSchemaRestoresServiceRules подтверждает восстановление
// правил служебных коллекций: случайно открытый просмотр сессий
// закрывается обратно с записью в лог.
func TestSyncSeedSchemaRestoresServiceRules(t *testing.T) {
	app := newRegistryTestApp(t)

	sessions, err := app.FindCollectionByNameOrId("seed_sessions")
	if err != nil {
		t.Fatalf("find seed_sessions: %v", err)
	}
	sessions.ListRule = types.Pointer("") // дрейф: открытый просмотр
	if err := app.Save(sessions); err != nil {
		t.Fatalf("save drifted sessions: %v", err)
	}

	out := captureLog(t, func() {
		if err := syncSeedSchema(app); err != nil {
			t.Fatalf("syncSeedSchema: %v", err)
		}
	})

	got, err := app.FindCollectionByNameOrId("seed_sessions")
	if err != nil {
		t.Fatalf("re-find seed_sessions: %v", err)
	}
	if got.ListRule != nil {
		t.Fatalf("service ListRule not restored: %q", *got.ListRule)
	}
	if !strings.Contains(out, "restored from registry") {
		t.Errorf("expected restoration log, got: %q", out)
	}
}

// TestEnsureSeedSchemaUsersRulesAligned подтверждает, что дрейф правил
// коллекции пользователей исправляется автоматически: правила — часть
// продуктовой схемы (на них завязаны роли), поэтому на каждом запуске
// они приводятся к базовым с записью в лог.
func TestEnsureSeedSchemaUsersRulesAligned(t *testing.T) {
	app := newRegistryTestApp(t)

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatalf("find users: %v", err)
	}
	users.DeleteRule = types.Pointer("") // дрейф: открытое удаление
	users.ListRule = types.Pointer("")   // дрейф: открытый список
	if err := app.Save(users); err != nil {
		t.Fatalf("save drifted users: %v", err)
	}

	out := captureLog(t, func() {
		if err := ensureSeedSchema(app); err != nil {
			t.Fatalf("ensureSeedSchema: %v", err)
		}
	})

	got, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatalf("re-find users: %v", err)
	}
	if got.DeleteRule == nil || *got.DeleteRule != usersSelfRule {
		t.Fatalf("users DeleteRule not aligned: %v", got.DeleteRule)
	}
	if got.ListRule == nil || *got.ListRule != usersStaffViewRule {
		t.Fatalf("users ListRule not aligned: %v", got.ListRule)
	}
	if !strings.Contains(out, "users rules aligned") {
		t.Errorf("expected alignment log, got: %q", out)
	}
}

// TestSyncSeedSchemaReaddsMissingField подтверждает, что удалённое
// поле возвращается синхронизацией (данные при этом не удаляются —
// добавление поля никогда не трогает строки).
func TestSyncSeedSchemaReaddsMissingField(t *testing.T) {
	app := newRegistryTestApp(t)

	sessions, err := app.FindCollectionByNameOrId("seed_sessions")
	if err != nil {
		t.Fatalf("find seed_sessions: %v", err)
	}
	sessions.Fields.RemoveByName("ip_country")
	if err := app.Save(sessions); err != nil {
		t.Fatalf("save fieldless sessions: %v", err)
	}

	if err := syncSeedSchema(app); err != nil {
		t.Fatalf("syncSeedSchema: %v", err)
	}

	got, err := app.FindCollectionByNameOrId("seed_sessions")
	if err != nil {
		t.Fatalf("re-find seed_sessions: %v", err)
	}
	if got.Fields.GetByName("ip_country") == nil {
		t.Fatal("ip_country was not re-added by sync")
	}
}

// TestSeedProxyHeadersFromEnv проверяет сев доверенного прокси:
// стандарт без окружения, список из переменной (с пробелами и пустыми
// элементами), пустая переменная и запрет перезаписи уже настроенной
// базы.
func TestSeedProxyHeadersFromEnv(t *testing.T) {
	app := newRegistryTestApp(t)
	if got := app.Settings().TrustedProxy.Headers; len(got) != 1 || got[0] != "X-Forwarded-For" {
		t.Fatalf("default headers: %v", got)
	}
	if app.Settings().TrustedProxy.UseLeftmostIP {
		t.Fatal("useLeftmostIP must stay off")
	}

	// Уже настроенный список окружение не перезаписывает.
	t.Setenv("PROXY_HEADERS", "X-Real-IP")
	if err := ensureSeedSettings(app); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	if got := app.Settings().TrustedProxy.Headers; len(got) != 1 || got[0] != "X-Forwarded-For" {
		t.Fatalf("configured headers overwritten: %v", got)
	}

	t.Setenv("PROXY_HEADERS", " CF-Connecting-IP , True-Client-IP ")
	app2 := newRegistryTestApp(t)
	if got := app2.Settings().TrustedProxy.Headers; len(got) != 2 ||
		got[0] != "CF-Connecting-IP" || got[1] != "True-Client-IP" {
		t.Fatalf("env headers: %v", got)
	}

	t.Setenv("PROXY_HEADERS", " , ")
	app3 := newRegistryTestApp(t)
	if got := app3.Settings().TrustedProxy.Headers; len(got) != 1 || got[0] != "X-Forwarded-For" {
		t.Fatalf("empty env must fall back to standard: %v", got)
	}
}
