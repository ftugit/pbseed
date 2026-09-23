package main

// Soft delete + authorization regression tests (2026-09-17 audit, updated
// after the fixes).
//
// History: the tests listed below were written RED against the pre-fix
// code and are the acceptance criteria for REPORT-2026-09-17.md. They are
// now GREEN and guard against regressions:
//
//   - TestSoftDeleteGCKeepsLiveRows      — S1: GC purged live rows (deleted='')
//   - TestSafeQueryUserSeesOwnLiveRows   — S2: `IS NULL` is not fexpr, endpoint 500ed
//   - TestSeedSessionsEndpointUserOwn    — same root cause, HTTP level
//   - TestSoftDeleteEndpointsGuards      — same root cause in /api/seed/deleted
//   - TestRestoreBySuperuser             — S6: RestoreRecords never restored
//   - TestRestoreDeniedCrossUser         — S4: no ownership check
//
// Added with the fixes:
//   - TestNotesNotInProduction           — notes is a test-only collection now
//   - TestRenewSameIPDoesNotBumpUpdatedAt— last_seen must not touch updated_at
//   - TestRenewIPChangeBumpsUpdatedAt    — data change DOES bump updated_at
//   - TestGeoOnLoginRecordsCountry       — GeoIP recorded on session creation
//   - TestGeoOnIPChangeRecordsCountry    — GeoIP recorded when IP changes
//   - TestRestoreWindowExpired           — 30s undo window counts from deleted_at
//   - TestEraseAnonymizesAndCleansUp     — R7: EraseUser stamps users.deleted_at
//   - TestFieldRenameMigration           — deployed-DB created/updated/deleted renames
//
// The `notes` collection no longer ships in production. Tests that need it
// call withNotes(app), which recreates the old production schema inside the
// test app only and registers it for soft delete.
//
// Note on the harness: PocketBase caches serve-time state per app
// instance, so one TestApp can answer exactly ONE ApiScenario (a second
// serve on the same app panics on duplicated routes). runWithApp builds a
// fresh seeded app per scenario.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/types"
)

// ---------------------------------------------------------------- harness

// newSeedTestApp boots a PB test app with the pbseed schema, hooks and
// routes wired exactly like main.go — minus startSeedGC, so no ticker can
// interfere with the assertions. It does NOT create `notes`: production
// has no notes collection.
func newSeedTestApp(t testing.TB) *tests.TestApp {
	t.Helper()
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatalf("new test app: %v", err)
	}
	// ensureSeedSchema применяет и реестр схемы (поля, индексы, правила
	// служебных коллекций), и базовые ролевые правила коллекции users
	// (фикстура идёт с запертыми правилами — они приводятся к базовым).
	if err := ensureSeedSchema(app); err != nil {
		t.Fatalf("ensureSeedSchema: %v", err)
	}
	installSoftDeleteHooks(app)
	protectUsersFields(app)
	installAuditHooks(app)
	installCollectionAuditHooks(app)
	installStockAuthAuditHooks(app)
	protectAuditCollection(app)
	installSuperuserSessions(app)
	installFirewallHooks(app)
	app.OnRecordsListRequest().BindFunc(recordsListCursorHint)
	// По умолчанию фаервол в общем каркасе выключен, чтобы не влиять на
	// существующие сьюты; тесты фаервола включают его сами (SEED_FIREWALL=1).
	t.Setenv("SEED_FIREWALL", "0")

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		se.Router.BindFunc(fwPanelMiddleware)
		se.Router.BindFunc(seedSessionMiddleware)
		se.Router.POST("/api/seed/challenge", seedChallenge)
		se.Router.POST("/api/seed/login", seedLogin)
		se.Router.POST("/api/seed/impersonate", seedImpersonate)
		se.Router.POST("/api/seed/renew", seedRenew)
		se.Router.POST("/api/seed/revoke", seedRevoke)
		se.Router.POST("/api/seed/logout", seedLogout)
		se.Router.POST("/api/seed/logout-all", seedLogoutAll)
		se.Router.GET("/api/seed/policy", seedPolicyGet)
		se.Router.POST("/api/seed/policy", seedPolicySet)
		se.Router.DELETE("/api/seed/policy", seedPolicyDelete)
		se.Router.GET("/api/seed/sessions", seedSessions)
		se.Router.GET("/api/collections/{collection}/records/cursor", recordsCursor)
		se.Router.POST("/api/seed/geo/update", seedGeoUpdate)
		se.Router.GET("/api/seed/geo/status", seedGeoStatus)
		se.Router.GET("/api/seed/geo/lookup", seedGeoLookup)
		se.Router.POST("/api/seed/hard-delete", seedHardDelete)
		se.Router.POST("/api/seed/restore", seedRestore)
		se.Router.GET("/api/seed/impact", seedImpact)
		se.Router.POST("/api/seed/erase", seedErase)
		se.Router.GET("/api/seed/deleted", seedDeleted)
		se.Router.GET("/api/seed/firewall/status", seedFirewallStatus)
		se.Router.POST("/api/seed/firewall/unlock", seedFirewallUnlock)
		se.Router.GET("/api/seed/gateway-config", seedGatewayConfigGet)
		se.Router.POST("/api/seed/gateway-config", seedGatewayConfigSet)
		se.Router.DELETE("/api/seed/gateway-config", seedGatewayConfigDelete)
		return se.Next()
	})
	return app
}

// withNotes recreates the old production `notes` collection inside a test
// app ONLY (the user requirement: notes must not exist in production; if
// it is needed for tests it exists only in tests). Registers it for soft
// delete and owner-scoped restore exactly like the pre-fix production
// wiring, and removes the registration again when the test ends.
func withNotes(t testing.TB, app core.App) {
	t.Helper()
	if _, err := app.FindCollectionByNameOrId("notes"); err == nil {
		t.Fatal("notes unexpectedly already exists")
	}
	col := core.NewBaseCollection("notes")
	readRule := `visibility = "public" || owner = @request.auth.id`
	col.ListRule = types.Pointer(readRule)
	col.ViewRule = types.Pointer(readRule)
	col.CreateRule = types.Pointer(`@request.auth.id != "" && @request.body.owner = @request.auth.id`)
	col.UpdateRule = types.Pointer(`owner = @request.auth.id`)
	col.DeleteRule = types.Pointer(`owner = @request.auth.id`)
	col.Fields.Add(
		&core.TextField{Name: "title", Max: 255},
		&core.RelationField{Name: "owner", CollectionId: mustCollection(t, app, "users").Id, MaxSelect: 1},
		&core.TextField{Name: "visibility", Max: 16},
	)
	autoDates(col)
	col.Fields.Add(softDeleteField())
	if err := app.Save(col); err != nil {
		t.Fatalf("create notes (test-only): %v", err)
	}
	softDeleteWhitelist["notes"] = true
	softDeleteOwnerField["notes"] = "owner"
	t.Cleanup(func() {
		delete(softDeleteWhitelist, "notes")
		delete(softDeleteOwnerField, "notes")
	})
	// installSoftDeleteHooks уже отработал без notes в мапе — навешиваем
	// тот же перехватчик вручную (продовый путь идентичен).
	app.OnRecordDelete("notes").BindFunc(softDeleteHook("notes"))
	app.OnRecordUpdateRequest("notes").BindFunc(testNotesOwnerGuard)
}

// testNotesOwnerGuard is the test-only version of the former production
// protectNotesOwner hook: ownership is immutable via the API, superuser
// bypass.
func testNotesOwnerGuard(e *core.RecordRequestEvent) error {
	if e.Auth != nil && e.Auth.IsSuperuser() {
		return e.Next()
	}
	orig, err := e.App.FindRecordById("notes", e.Record.Id)
	if err != nil || orig == nil {
		return e.Next() // let PB answer 404
	}
	if asStr(orig.Get("owner")) != asStr(e.Record.Get("owner")) {
		return seedErr(e.RequestEvent, 403, "forbidden")
	}
	return e.Next()
}

// runWithApp builds a fresh seeded app, lets `build` populate data and
// compose a scenario against it, then runs that single scenario.
func runWithApp(t *testing.T, build func(app *tests.TestApp) tests.ApiScenario) {
	t.Helper()
	app := newSeedTestApp(t)
	defer app.Cleanup()
	sc := build(app)
	sc.TestAppFactory = func(t testing.TB) *tests.TestApp { return app }
	sc.DisableTestAppCleanup = true
	sc.Test(t)
}

func mustCollection(t testing.TB, app core.App, name string) *core.Collection {
	t.Helper()
	col, err := app.FindCollectionByNameOrId(name)
	if err != nil {
		t.Fatalf("collection %s: %v", name, err)
	}
	return col
}

func mustUser(t testing.TB, app core.App, email string) *core.Record {
	t.Helper()
	u := core.NewRecord(mustCollection(t, app, "users"))
	u.Set("email", email)
	u.Set("password", "user-password-123")
	u.Set("emailVisibility", false)
	if err := app.Save(u); err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return u
}

func mustSuperuser(t testing.TB, app core.App) (*core.Record, string) {
	t.Helper()
	su := core.NewRecord(mustCollection(t, app, "_superusers"))
	su.Set("email", "root-"+security.RandomString(8)+"@seed.test")
	su.Set("password", "root-password-123")
	if err := app.Save(su); err != nil {
		t.Fatalf("create superuser: %v", err)
	}
	tok, err := su.NewAuthToken()
	if err != nil {
		t.Fatalf("superuser token: %v", err)
	}
	return su, tok
}

func mustToken(t testing.TB, u *core.Record) string {
	t.Helper()
	tok, err := u.NewAuthToken()
	if err != nil {
		t.Fatalf("user token: %v", err)
	}
	return tok
}

// mustSession creates a live seed session row the same way seedLogin does,
// returning the grant id and the pb_seed cookie value.
func mustSession(t testing.TB, app core.App, userID, device string) (string, string) {
	t.Helper()
	s := core.NewRecord(mustCollection(t, app, "seed_sessions"))
	grant := security.RandomString(24)
	secret := security.RandomString(32)
	s.Set("user", userID)
	s.Set("grant_id", grant)
	s.Set("secret_hash", security.SHA256(secret))
	s.Set("device_name", device)
	s.Set("ip_hash", "")
	s.Set("ip_masked", "")
	s.Set("ip_country", "")
	s.Set("history", []any{})
	s.Set("revoked", false)
	s.Set("last_seen", nowISO())
	s.Set("expires", time.Now().AddDate(0, 0, seedSessionDays).UTC().Format(time.RFC3339Nano))
	if err := app.Save(s); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return grant, grant + "." + secret
}

func mustNote(t testing.TB, app core.App, ownerID, title, visibility string) *core.Record {
	t.Helper()
	n := core.NewRecord(mustCollection(t, app, "notes"))
	n.Set("title", title)
	n.Set("owner", ownerID)
	n.Set("visibility", visibility)
	if err := app.Save(n); err != nil {
		t.Fatalf("create note %s: %v", title, err)
	}
	return n
}

// stampDeleted raw-SQL stamps deleted_at (bypasses hooks so the timestamp
// is under test control).
func stampDeleted(t testing.TB, app core.App, table, id string, when time.Time) {
	t.Helper()
	_, err := app.NonconcurrentDB().NewQuery(
		"UPDATE " + table + " SET deleted_at = {:d} WHERE id = {:id}",
	).Bind(dbx.Params{
		"d":  when.UTC().Format(time.RFC3339Nano),
		"id": id,
	}).Execute()
	if err != nil {
		t.Fatalf("stamp deleted_at: %v", err)
	}
}

// rowStamp reads a single text column of a single row (test helper).
func rowStamp(t testing.TB, app core.App, query string, params dbx.Params) string {
	t.Helper()
	var v string
	if err := app.DB().NewQuery(query).Bind(params).Row(&v); err != nil {
		t.Fatalf("rowStamp %s: %v", query, err)
	}
	return v
}

// readJSON разбирает тело HTTP-ответа в переданную структуру.
//
// Параметры:
//   - t: testing.TB — тест;
//   - res: *http.Response — ответ, тело которого читается;
//   - dst: any — указатель на структуру-приёмник.
//
// Возвращает: error — ошибка чтения или разбора.
func readJSON(t testing.TB, res *http.Response, dst any) error {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

// loadGeoFixture installs tests/fixtures/country-test.mmdb as the server's
// geo DB (203.0.113.5->US, 198.51.100.9->DE, 192.0.2.7->JP).
func loadGeoFixture(t testing.TB, app core.App) {
	t.Helper()
	dir := geoDir(app)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("geo dir: %v", err)
	}
	data, err := os.ReadFile(filepath.Join("tests", "fixtures", "country-test.mmdb"))
	if err != nil {
		t.Fatalf("geo fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "country.mmdb"), data, 0o644); err != nil {
		t.Fatalf("geo install: %v", err)
	}
	geoInit(app)
}

// ---------------------------------------------------------------- notes scope

// The production schema must not create `notes` (user requirement
// 2026-09-17). The old test-fixture-based checks live on via withNotes.
func TestNotesNotInProduction(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	if _, err := app.FindCollectionByNameOrId("notes"); err == nil {
		t.Errorf("notes collection must not exist in the production schema")
	}
}

// ---------------------------------------------------------------- S1: GC

// S1 (CRITICAL, was FAILING before the fix): softDeleteGC must only purge
// rows that are actually soft-deleted and older than the retention window.
func TestSoftDeleteGCKeepsLiveRows(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	u := mustUser(t, app, "gc-live@seed.test")
	g1, _ := mustSession(t, app, u.Id, "dev1")
	g2, _ := mustSession(t, app, u.Id, "dev2")

	softDeleteGC(app)

	if _, err := app.FindFirstRecordByData("seed_sessions", "grant_id", g1); err != nil {
		t.Errorf("live session %s purged by softDeleteGC", g1)
	}
	if _, err := app.FindFirstRecordByData("seed_sessions", "grant_id", g2); err != nil {
		t.Errorf("live session %s purged by softDeleteGC", g2)
	}
}

// S1 continued: stale soft-deleted rows are purged, fresh soft-deleted rows
// and live rows survive.
func TestSoftDeleteGCPurgesOnlyStaleDeleted(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	u := mustUser(t, app, "gc-stale@seed.test")
	liveGrant, _ := mustSession(t, app, u.Id, "live")

	stale := core.NewRecord(mustCollection(t, app, "seed_sessions"))
	stale.Set("user", u.Id)
	stale.Set("grant_id", "stale-grant")
	stale.Set("secret_hash", security.SHA256("x"))
	stale.Set("expires", time.Now().AddDate(0, 0, 30).UTC().Format(time.RFC3339Nano))
	if err := app.Save(stale); err != nil {
		t.Fatalf("create stale session: %v", err)
	}
	stampDeleted(t, app, "seed_sessions", stale.Id, time.Now().Add(-31*24*time.Hour))

	fresh := core.NewRecord(mustCollection(t, app, "seed_sessions"))
	fresh.Set("user", u.Id)
	fresh.Set("grant_id", "fresh-grant")
	fresh.Set("secret_hash", security.SHA256("y"))
	fresh.Set("expires", time.Now().AddDate(0, 0, 30).UTC().Format(time.RFC3339Nano))
	if err := app.Save(fresh); err != nil {
		t.Fatalf("create fresh session: %v", err)
	}
	stampDeleted(t, app, "seed_sessions", fresh.Id, time.Now().Add(-time.Hour))

	softDeleteGC(app)

	if _, err := app.FindFirstRecordByData("seed_sessions", "grant_id", "stale-grant"); err == nil {
		t.Errorf("stale soft-deleted session NOT purged")
	}
	if _, err := app.FindFirstRecordByData("seed_sessions", "grant_id", "fresh-grant"); err != nil {
		t.Errorf("fresh soft-deleted session purged too early: %v", err)
	}
	if _, err := app.FindFirstRecordByData("seed_sessions", "grant_id", liveGrant); err != nil {
		t.Errorf("live session purged by softDeleteGC")
	}
}

// ------------------------------------------------------- S2: SafeQuery

// S2 (HIGH, was FAILING): for a non-superuser SafeQuery must add a
// soft-delete filter that the PB filter parser actually accepts and return
// only the caller's live rows.
func TestSafeQueryUserSeesOwnLiveRows(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	u1 := mustUser(t, app, "sq-1@seed.test")
	u2 := mustUser(t, app, "sq-2@seed.test")
	liveGrant, _ := mustSession(t, app, u1.Id, "live")

	deleted := core.NewRecord(mustCollection(t, app, "seed_sessions"))
	deleted.Set("user", u1.Id)
	deleted.Set("grant_id", "deleted-grant")
	deleted.Set("secret_hash", security.SHA256("z"))
	deleted.Set("expires", time.Now().AddDate(0, 0, 30).UTC().Format(time.RFC3339Nano))
	if err := app.Save(deleted); err != nil {
		t.Fatalf("create deleted session: %v", err)
	}
	stampDeleted(t, app, "seed_sessions", deleted.Id, time.Now().Add(-time.Hour))

	mustSession(t, app, u2.Id, "other-user")

	rows, err := SafeQuery(app, false, "seed_sessions").
		Where("user = {:uid}", dbx.Params{"uid": u1.Id}).
		Find()
	if err != nil {
		t.Fatalf("SafeQuery for non-superuser failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 live own row, got %d", len(rows))
	}
	if asStr(rows[0].Get("grant_id")) != liveGrant {
		t.Errorf("wrong row returned: %v", rows[0].Get("grant_id"))
	}
}

// Superuser sees everything including soft-deleted (admin reads all).
func TestSafeQuerySuperuserSeesAllIncludingDeleted(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()

	u := mustUser(t, app, "sq-su@seed.test")
	mustSession(t, app, u.Id, "live-1")
	mustSession(t, app, u.Id, "live-2")

	deleted := core.NewRecord(mustCollection(t, app, "seed_sessions"))
	deleted.Set("user", u.Id)
	deleted.Set("grant_id", "su-deleted")
	deleted.Set("secret_hash", security.SHA256("z"))
	deleted.Set("expires", time.Now().AddDate(0, 0, 30).UTC().Format(time.RFC3339Nano))
	if err := app.Save(deleted); err != nil {
		t.Fatalf("create session: %v", err)
	}
	stampDeleted(t, app, "seed_sessions", deleted.Id, time.Now().Add(-time.Hour))

	rows, err := SafeQuery(app, true, "seed_sessions").IncludeDeleted().Find()
	if err != nil {
		t.Fatalf("SafeQuery for superuser failed: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("superuser should see all 3 sessions (incl. deleted), got %d", len(rows))
	}
}

// ------------------------------------------- HTTP: sessions endpoint

func TestSeedSessionsEndpointUserOwn(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "sess-u@seed.test")
		other := mustUser(t, app, "sess-o@seed.test")
		g1, ck1 := mustSession(t, app, u.Id, "laptop")
		g2, _ := mustSession(t, app, u.Id, "phone")
		gOther, _ := mustSession(t, app, other.Id, "intruder")

		// The user sees exactly their own live sessions — and the endpoint
		// must not 500 (S2).
		return tests.ApiScenario{
			Name:           "user sessions list",
			Method:         http.MethodGet,
			URL:            "/api/seed/sessions",
			Headers:        map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck1},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"` + g1 + `"`,
				`"` + g2 + `"`,
				`"created_at"`, // new timestamp contract
			},
			NotExpectedContent: []string{`"` + gOther + `"`},
		}
	})
}

func TestSeedSessionsEndpointSuperuser(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "sess-su@seed.test")
		mustSession(t, app, u.Id, "laptop")
		_, suTok := mustSuperuser(t, app)

		// Admin reaches the endpoint without a session cookie (superusers
		// bypass the middleware). The endpoint is self-scoped even for
		// admins — an admin has no seed sessions of their own here.
		return tests.ApiScenario{
			Name:            "superuser sessions list",
			Method:          http.MethodGet,
			URL:             "/api/seed/sessions",
			Headers:         map[string]string{"Authorization": suTok},
			ExpectedStatus:  200,
			ExpectedContent: []string{`[]`},
		}
	})
}

// ------------------------------------- access control: users collection

// Admin has the right to read all users; users cannot read each other.
func TestUsersIsolationAndAdminReadsAll(t *testing.T) {
	t.Run("A views B -> 404", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			a := mustUser(t, app, "iso-a@seed.test")
			b := mustUser(t, app, "iso-b@seed.test")
			_, cka := mustSession(t, app, a.Id, "a")
			return tests.ApiScenario{
				Method:         http.MethodGet,
				URL:            "/api/collections/users/records/" + b.Id,
				Headers:        map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + cka},
				ExpectedStatus: 404,
				ExpectedContent: []string{
					`"status":404`,
				},
			}
		})
	})

	t.Run("list -> self only", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			a := mustUser(t, app, "iso-a@seed.test")
			b := mustUser(t, app, "iso-b@seed.test")
			_, cka := mustSession(t, app, a.Id, "a")
			return tests.ApiScenario{
				Method:         http.MethodGet,
				URL:            "/api/collections/users/records?perPage=50",
				Headers:        map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + cka},
				ExpectedStatus: 200,
				ExpectedContent: []string{
					`"totalItems":1`,
					`"` + a.Id + `"`,
				},
				NotExpectedContent: []string{`"` + b.Id + `"`},
			}
		})
	})

	t.Run("superuser reads everyone", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			a := mustUser(t, app, "iso-a@seed.test")
			b := mustUser(t, app, "iso-b@seed.test")
			_, suTok := mustSuperuser(t, app)
			return tests.ApiScenario{
				Method:         http.MethodGet,
				URL:            "/api/collections/users/records?perPage=50",
				Headers:        map[string]string{"Authorization": suTok},
				ExpectedStatus: 200,
				ExpectedContent: []string{
					`"` + a.Id + `"`,
					`"` + b.Id + `"`,
				},
			}
		})
	})

	t.Run("guest reads nobody", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			mustUser(t, app, "iso-a@seed.test")
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/collections/users/records?perPage=50",
				ExpectedStatus:  200,
				ExpectedContent: []string{`"totalItems":0`},
			}
		})
	})
}

// ----------------------------------------- admin grant token protection

// Creating a superuser ("granting admin") requires a superuser token:
// guests and regular users are rejected.
func TestSuperuserGrantRequiresSuperuserToken(t *testing.T) {
	body := `{"email":"new-admin@seed.test","password":"new-admin-pass-1","passwordConfirm":"new-admin-pass-1"}`

	t.Run("guest -> denied", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			return tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/api/collections/_superusers/records",
				Body:            strings.NewReader(body),
				ExpectedStatus:  403,
				ExpectedContent: []string{`"status":403`},
			}
		})
	})

	t.Run("user token -> denied", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "grant-u@seed.test")
			_, ck := mustSession(t, app, u.Id, "d")
			return tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/api/collections/_superusers/records",
				Body:            strings.NewReader(body),
				Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus:  403,
				ExpectedContent: []string{`"status":403`},
			}
		})
	})

	t.Run("superuser token -> ok", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			_, suTok := mustSuperuser(t, app)
			return tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/api/collections/_superusers/records",
				Body:            strings.NewReader(body),
				Headers:         map[string]string{"Authorization": suTok},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"email":"new-admin@seed.test"`},
			}
		})
	})
}

// ------------------------------------------------- protected user fields

// A user cannot flip moderation/identity fields on their own record.
func TestProtectedUserFields(t *testing.T) {
	for _, body := range []string{
		`{"banned":true}`,
		`{"ban_reason":"self"}`,
		`{"banned_until":"2030-01-01T00:00:00Z"}`,
		`{"email":"hijack@seed.test"}`,
	} {
		t.Run("self PATCH "+body, func(t *testing.T) {
			runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
				u := mustUser(t, app, "prot-u@seed.test")
				_, ck := mustSession(t, app, u.Id, "d")
				return tests.ApiScenario{
					Method:          http.MethodPatch,
					URL:             "/api/collections/users/records/" + u.Id,
					Body:            strings.NewReader(body),
					Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
					ExpectedStatus:  403,
					ExpectedContent: []string{`"error":"forbidden"`},
				}
			})
		})
	}

	t.Run("non-protected field stays self-service", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "prot-u@seed.test")
			_, ck := mustSession(t, app, u.Id, "d")
			return tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/users/records/" + u.Id,
				Body:            strings.NewReader(`{"emailVisibility":true}`),
				Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"emailVisibility":true`},
			}
		})
	})
}

// ------------------------------------------------------- notes isolation

func TestNotesReadIsolationAndOwnerImmutability(t *testing.T) {
	t.Run("B sees public + own only", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			withNotes(t, app)
			a := mustUser(t, app, "notes-a@seed.test")
			b := mustUser(t, app, "notes-b@seed.test")
			_, ckb := mustSession(t, app, b.Id, "b")
			mustNote(t, app, a.Id, "a-pub", "public")
			mustNote(t, app, a.Id, "a-priv", "private")
			mustNote(t, app, b.Id, "b-priv", "private")
			return tests.ApiScenario{
				Method:         http.MethodGet,
				URL:            "/api/collections/notes/records?perPage=50",
				Headers:        map[string]string{"Authorization": mustToken(t, b), "Cookie": "pb_seed=" + ckb},
				ExpectedStatus: 200,
				ExpectedContent: []string{
					`"totalItems":2`,
					`"title":"a-pub"`,
					`"title":"b-priv"`,
				},
				NotExpectedContent: []string{`"title":"a-priv"`},
			}
		})
	})

	t.Run("B views A's private note -> 404", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			withNotes(t, app)
			a := mustUser(t, app, "notes-a@seed.test")
			b := mustUser(t, app, "notes-b@seed.test")
			_, ckb := mustSession(t, app, b.Id, "b")
			aPriv := mustNote(t, app, a.Id, "a-priv", "private")
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/collections/notes/records/" + aPriv.Id,
				Headers:         map[string]string{"Authorization": mustToken(t, b), "Cookie": "pb_seed=" + ckb},
				ExpectedStatus:  404,
				ExpectedContent: []string{`"status":404`},
			}
		})
	})

	t.Run("A views own private note -> 200", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			withNotes(t, app)
			a := mustUser(t, app, "notes-a@seed.test")
			_, cka := mustSession(t, app, a.Id, "a")
			aPriv := mustNote(t, app, a.Id, "a-priv", "private")
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/collections/notes/records/" + aPriv.Id,
				Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + cka},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"title":"a-priv"`},
			}
		})
	})

	t.Run("owner transfer blocked", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			withNotes(t, app)
			a := mustUser(t, app, "notes-a@seed.test")
			b := mustUser(t, app, "notes-b@seed.test")
			_, cka := mustSession(t, app, a.Id, "a")
			aPub := mustNote(t, app, a.Id, "a-pub", "public")
			return tests.ApiScenario{
				Method:          http.MethodPatch,
				URL:             "/api/collections/notes/records/" + aPub.Id,
				Body:            strings.NewReader(`{"owner":"` + b.Id + `"}`),
				Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + cka},
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error":"forbidden"`},
			}
		})
	})
}

// ------------------------------------------------------ soft-delete API

// S6 (HIGH, was FAILING): a superuser must be able to restore a
// soft-deleted record.
func TestRestoreBySuperuser(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		withNotes(t, app)
		u := mustUser(t, app, "rest-su@seed.test")
		_, suTok := mustSuperuser(t, app)
		n := mustNote(t, app, u.Id, "to-restore", "private")
		if err := app.Delete(n); err != nil { // hook turns this into a soft delete
			t.Fatalf("delete note: %v", err)
		}
		if _, err := app.FindRecordById("notes", n.Id); err != nil {
			t.Fatalf("note should be soft-deleted, not physically gone: %v", err)
		}
		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/restore",
			Body:            strings.NewReader(`{"collection":"notes","ids":["` + n.Id + `"]}`),
			Headers:         map[string]string{"Authorization": suTok},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"restored":1`},
		}
	})
}

// S4 (MEDIUM): restore must be owner-scoped for non-superusers.
func TestRestoreDeniedCrossUser(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		withNotes(t, app)
		a := mustUser(t, app, "rest-a@seed.test")
		b := mustUser(t, app, "rest-b@seed.test")
		_, ckb := mustSession(t, app, b.Id, "b")
		n := mustNote(t, app, a.Id, "a-deleted", "private")
		if err := app.Delete(n); err != nil {
			t.Fatalf("delete note: %v", err)
		}
		sc := tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/restore",
			Body:            strings.NewReader(`{"collection":"notes","ids":["` + n.Id + `"]}`),
			Headers:         map[string]string{"Authorization": mustToken(t, b), "Cookie": "pb_seed=" + ckb},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"restored":0`},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			deletedAt := rowStamp(t, app, "SELECT deleted_at FROM notes WHERE id = {:id}", dbx.Params{"id": n.Id})
			if deletedAt == "" {
				t.Errorf("cross-user restore cleared the deleted_at stamp")
			}
		}
		return sc
	})
}

// The owner CAN restore their own record within the undo window.
func TestRestoreOwnWithinWindow(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		withNotes(t, app)
		a := mustUser(t, app, "rest-own@seed.test")
		_, cka := mustSession(t, app, a.Id, "a")
		n := mustNote(t, app, a.Id, "mine-deleted", "private")
		if err := app.Delete(n); err != nil {
			t.Fatalf("delete note: %v", err)
		}
		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/restore",
			Body:            strings.NewReader(`{"collection":"notes","ids":["` + n.Id + `"]}`),
			Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + cka},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"restored":1`},
		}
	})
}

// The 30s undo window is measured from deleted_at (user requirement).
func TestRestoreWindowExpired(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		withNotes(t, app)
		a := mustUser(t, app, "rest-late@seed.test")
		_, cka := mustSession(t, app, a.Id, "a")
		n := mustNote(t, app, a.Id, "late-delete", "private")
		if err := app.Delete(n); err != nil {
			t.Fatalf("delete note: %v", err)
		}
		// Backdate deleted_at beyond the undo window.
		stampDeleted(t, app, "notes", n.Id, time.Now().Add(-softDeleteUndoWindow-time.Minute))
		return tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/restore",
			Body:            strings.NewReader(`{"collection":"notes","ids":["` + n.Id + `"]}`),
			Headers:         map[string]string{"Authorization": mustToken(t, a), "Cookie": "pb_seed=" + cka},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"restored":0`},
		}
	})
}

// Soft-deleted session restored by superuser: deleted_at cleared, but
// revoked stays — the user must log in again.
func TestRestoreSessionStaysRevoked(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "rest-sess@seed.test")
		_, suTok := mustSuperuser(t, app)
		g, _ := mustSession(t, app, u.Id, "restorable")
		sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", g)
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		if err := app.Delete(sess); err != nil { // soft delete hook
			t.Fatalf("delete session: %v", err)
		}
		sc := tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/restore",
			Body:            strings.NewReader(`{"collection":"seed_sessions","ids":["` + sess.Id + `"]}`),
			Headers:         map[string]string{"Authorization": suTok},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"restored":1`},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			deletedAt := rowStamp(t, app, "SELECT deleted_at FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
			if deletedAt != "" {
				t.Errorf("restored session still has deleted_at=%q", deletedAt)
			}
			revoked := rowStamp(t, app, "SELECT revoked FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
			if revoked != "1" {
				t.Errorf("restored session must stay revoked (revoked=%q)", revoked)
			}
		}
		return sc
	})
}

// Admin-only guards on the destructive/introspection endpoints.
func TestSoftDeleteEndpointsGuards(t *testing.T) {
	t.Run("user hard-delete -> 403", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			withNotes(t, app)
			u := mustUser(t, app, "guard-u@seed.test")
			_, ck := mustSession(t, app, u.Id, "d")
			n := mustNote(t, app, u.Id, "guard-note", "private")
			return tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/api/seed/hard-delete",
				Body:            strings.NewReader(`{"collection":"notes","ids":["` + n.Id + `"]}`),
				Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error":"forbidden"`},
			}
		})
	})

	t.Run("user impact -> 403", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "guard-u@seed.test")
			_, ck := mustSession(t, app, u.Id, "d")
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/seed/impact?collection=users&id=" + u.Id,
				Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error":"forbidden"`},
			}
		})
	})

	t.Run("user erase -> 403", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "guard-u@seed.test")
			_, ck := mustSession(t, app, u.Id, "d")
			return tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/api/seed/erase",
				Body:            strings.NewReader(`{"user_id":"` + u.Id + `"}`),
				Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error":"forbidden"`},
			}
		})
	})

	t.Run("user deleted list -> 403", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "guard-u@seed.test")
			_, ck := mustSession(t, app, u.Id, "d")
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/seed/deleted?collection=seed_sessions",
				Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
				ExpectedStatus:  403,
				ExpectedContent: []string{`"error":"forbidden"`},
			}
		})
	})

	// Superuser reaches /deleted (S2: used to 500 on the fexpr filter).
	t.Run("superuser deleted list -> 200", func(t *testing.T) {
		runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
			u := mustUser(t, app, "guard-su@seed.test")
			g, _ := mustSession(t, app, u.Id, "deleted-one")
			sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", g)
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			if err := app.Delete(sess); err != nil {
				t.Fatalf("soft delete session: %v", err)
			}
			_, suTok := mustSuperuser(t, app)
			return tests.ApiScenario{
				Method:          http.MethodGet,
				URL:             "/api/seed/deleted?collection=seed_sessions",
				Headers:         map[string]string{"Authorization": suTok},
				ExpectedStatus:  200,
				ExpectedContent: []string{`"` + sess.Id + `"`, `"deleted_at"`},
			}
		})
	})
}

// ------------------------------------------------------------- GDPR erase

func TestEraseAnonymizesAndCleansUp(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "erase-u@seed.test")
		mustSession(t, app, u.Id, "d1")
		mustSession(t, app, u.Id, "d2")
		_, suTok := mustSuperuser(t, app)
		sc := tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/erase",
			Body:            strings.NewReader(`{"user_id":"` + u.Id + `"}`),
			Headers:         map[string]string{"Authorization": suTok},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"ok":true`},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			rec, err := app.FindRecordById("users", u.Id)
			if err != nil {
				t.Errorf("erased user row should remain (anonymized): %v", err)
				return
			}
			if email := asStr(rec.Get("email")); !strings.HasPrefix(email, "erased-") {
				t.Errorf("email not anonymized: %q", email)
			}
			// R7 fix: the erasure must leave a stamp in users.deleted_at
			// (checked both via the record and the raw DB value).
			var sqlStamp string
			_ = app.DB().NewQuery("SELECT deleted_at FROM users WHERE id = {:id}").
				Bind(dbx.Params{"id": u.Id}).Row(&sqlStamp)
			if sqlStamp == "" || asStr(rec.Get("deleted_at")) == "" {
				t.Errorf("users.deleted_at not stamped by EraseUser (record=%q sql=%q)",
					asStr(rec.Get("deleted_at")), sqlStamp)
			}
			var n int
			_ = app.DB().NewQuery("SELECT count(*) FROM seed_sessions WHERE user = {:u}").
				Bind(dbx.Params{"u": u.Id}).Row(&n)
			if n != 0 {
				t.Errorf("sessions survive erasure: %d", n)
			}
		}
		return sc
	})
}

// ---------------------------------------------------------- session death

// A soft-deleted session must be rejected by the middleware (the hook also
// sets revoked=true; the middleware independently checks isSoftDeleted).
func TestSoftDeletedSessionRejected(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "dead-sess@seed.test")
		grant, ck := mustSession(t, app, u.Id, "dying")
		sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", grant)
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		if err := app.Delete(sess); err != nil { // soft delete hook
			t.Fatalf("delete session: %v", err)
		}
		return tests.ApiScenario{
			Method:          http.MethodGet,
			URL:             "/api/seed/sessions",
			Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"error":"session_revoked"`},
		}
	})
}

// ------------------------------------------ updated_at / last_seen split

// Activity alone (same IP renew) must NOT bump updated_at: last_seen is
// refreshed via a raw UPDATE that bypasses the autodate interceptor.
func TestRenewSameIPDoesNotBumpUpdatedAt(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "ts-same@seed.test")
		g, ck := mustSession(t, app, u.Id, "steady")
		sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", g)
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		// Pre-seed the stored IP with the socket IP the test server will
		// present (192.0.2.1), so the renew is a pure heartbeat.
		sess.Set("ip_hash", seedIPHash("192.0.2.1", g, seedIPKey()))
		sess.Set("ip_masked", "192.0.2.1")
		if err := app.Save(sess); err != nil {
			t.Fatalf("seed ip: %v", err)
		}
		beforeUpd := rowStamp(t, app, "SELECT updated_at FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
		beforeSeen := rowStamp(t, app, "SELECT last_seen FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
		time.Sleep(5 * time.Millisecond) // PB datetimes are ms-precise

		sc := tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/renew",
			Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"access"`},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			afterUpd := rowStamp(t, app, "SELECT updated_at FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
			afterSeen := rowStamp(t, app, "SELECT last_seen FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
			if afterUpd != beforeUpd {
				t.Errorf("last_seen-only renew bumped updated_at: %q -> %q", beforeUpd, afterUpd)
			}
			if afterSeen == beforeSeen {
				t.Errorf("last_seen not refreshed by renew")
			}
		}
		return sc
	})
}

// A real data change (IP moved) must bump updated_at, record the new
// masked IP and push an ip_changed history entry.
func TestRenewIPChangeBumpsUpdatedAt(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "ts-move@seed.test")
		g, ck := mustSession(t, app, u.Id, "roaming")
		sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", g)
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		adoptIP(sess, g, "203.0.113.5") // fixture: US
		if err := app.Save(sess); err != nil {
			t.Fatalf("seed ip: %v", err)
		}
		beforeUpd := rowStamp(t, app, "SELECT updated_at FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
		time.Sleep(5 * time.Millisecond)

		sc := tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/renew",
			Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"access"`},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			afterUpd := rowStamp(t, app, "SELECT updated_at FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
			if afterUpd == beforeUpd {
				t.Errorf("IP change did not bump updated_at")
			}
			history := rowStamp(t, app, "SELECT history FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
			if !strings.Contains(history, "ip_changed") {
				t.Errorf("no ip_changed entry in history: %s", history)
			}
			masked := rowStamp(t, app, "SELECT ip_masked FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
			if strings.HasPrefix(masked, "203.0.113") {
				t.Errorf("ip_masked not updated after IP change: %q", masked)
			}
		}
		return sc
	})
}

// TestKickOnIPChangePolicy — ветка кика: при включённой персональной
// политике смена адреса на продлении рвёт сессию (401 `ip_changed`),
// а в журнал ложится `auth.renew_failed` с причиной `ip_changed`.
// Живая проверка гоняла этот сценарий заголовком-адресом; синтетика
// до этого покрывала только ветку истории (без кика).
//
// Адрес сокета в каркасе всегда 127.0.0.1, поэтому «переезд» задаётся
// фикстура: сессия заранее получает чужой адрес, продление приходит
// с адресом сокета — этого достаточно для срабатывания защиты.
func TestKickOnIPChangePolicy(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		u := mustUser(t, app, "ts-kick@seed.test")
		g, ck := mustSession(t, app, u.Id, "roaming")
		sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", g)
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		adoptIP(sess, g, "203.0.113.9")
		if err := app.Save(sess); err != nil {
			t.Fatalf("seed ip: %v", err)
		}
		if err := policySetRow(app, seedPolicyKick, u.Id, true, false); err != nil {
			t.Fatalf("персональная политика кика: %v", err)
		}

		sc := tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/renew",
			Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"error"`, `"ip_changed"`},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			got, err := app.FindFirstRecordByData("seed_sessions", "grant_id", g)
			if err != nil || got == nil {
				t.Fatalf("сессия после кика: %v", err)
			}
			if !asBool(got.Get("revoked")) {
				t.Errorf("сессия не отозвана киком")
			}
			row := saFindLatest(t.(*testing.T), app, "auth.renew_failed")
			if row == nil || fwDetail(row)["reason"] != "ip_changed" {
				t.Errorf("нет строки renew_failed(ip_changed) в журнале")
			}
		}
		return sc
	})
}

// ----------------------------------------------------------- GeoIP writes

// Real end-to-end login (ed25519 signature over the challenge message):
// the session created at login must carry the client country.
func TestGeoOnLoginRecordsCountry(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		loadGeoFixture(t, app)

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519: %v", err)
		}
		pk := strings.ToLower(hex.EncodeToString(pub))
		nonce := security.RandomString(32)

		// Pre-create the challenge row (same shape as POST /api/seed/challenge).
		ch := core.NewRecord(mustCollection(t, app, "seed_challenges"))
		ch.Set("public_key", pk)
		ch.Set("nonce", nonce)
		ch.Set("purpose", "register")
		ch.Set("used", false)
		ch.Set("expires", time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339Nano))
		if err := app.Save(ch); err != nil {
			t.Fatalf("create challenge: %v", err)
		}

		msg := seedMsgPrefix + seedDomain() + ":register:" + pk + ":" + nonce
		sig := strings.ToLower(hex.EncodeToString(ed25519.Sign(priv, []byte(msg))))
		body := `{"public_key":"` + pk + `","signature":"` + sig +
			`","purpose":"register","nonce":"` + nonce + `","device_name":"geo-test"}`

		sc := tests.ApiScenario{
			Method:         http.MethodPost,
			URL:            "/api/seed/login",
			Body:           strings.NewReader(body),
			Headers:        map[string]string{"X-Forwarded-For": "203.0.113.5"}, // fixture: US
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"session_id"`,
				`"access"`,
			},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			cc := rowStamp(t, app, "SELECT ip_country FROM seed_sessions ORDER BY created_at DESC LIMIT 1", dbx.Params{})
			if cc != "US" {
				t.Errorf("GeoIP not recorded at session creation: ip_country=%q, want US", cc)
			}
			// timestamps present from the start (created_at/updated_at autodate)
			createdAt := rowStamp(t, app, "SELECT created_at FROM seed_sessions ORDER BY created_at DESC LIMIT 1", dbx.Params{})
			if createdAt == "" {
				t.Errorf("created_at empty on fresh session")
			}
		}
		return sc
	})
}

// When the IP changes, the new country must be written on the update.
func TestGeoOnIPChangeRecordsCountry(t *testing.T) {
	runWithApp(t, func(app *tests.TestApp) tests.ApiScenario {
		loadGeoFixture(t, app)
		u := mustUser(t, app, "geo-move@seed.test")
		g, ck := mustSession(t, app, u.Id, "traveler")
		sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", g)
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		adoptIP(sess, g, "203.0.113.5") // US
		if err := app.Save(sess); err != nil {
			t.Fatalf("seed ip: %v", err)
		}
		beforeUpd := rowStamp(t, app, "SELECT updated_at FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
		time.Sleep(5 * time.Millisecond)

		sc := tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             "/api/seed/renew",
			Headers:         map[string]string{"Authorization": mustToken(t, u), "Cookie": "pb_seed=" + ck, "X-Forwarded-For": "198.51.100.9"}, // fixture: DE
			ExpectedStatus:  200,
			ExpectedContent: []string{`"access"`},
		}
		sc.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
			cc := rowStamp(t, app, "SELECT ip_country FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
			if cc != "DE" {
				t.Errorf("GeoIP not refreshed on IP change: ip_country=%q, want DE", cc)
			}
			afterUpd := rowStamp(t, app, "SELECT updated_at FROM seed_sessions WHERE id = {:id}", dbx.Params{"id": sess.Id})
			if afterUpd == beforeUpd {
				t.Errorf("IP change did not bump updated_at")
			}
		}
		return sc
	})
}

// ------------------------------------------------- deployed-DB migration

// Deployed databases pre-2026-09-17 carry created/updated/deleted;
// renameField must migrate names by field id (PB renames the column).
func TestFieldRenameMigration(t *testing.T) {
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatalf("new test app: %v", err)
	}
	defer app.Cleanup()

	col := core.NewBaseCollection("mig_demo")
	col.Fields.Add(&core.TextField{Name: "title"})
	col.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	col.Fields.Add(&core.DateField{Name: "deleted"})
	if err := app.Save(col); err != nil {
		t.Fatalf("create mig_demo: %v", err)
	}
	rec := core.NewRecord(col)
	rec.Set("title", "migrating")
	if err := app.Save(rec); err != nil {
		t.Fatalf("create record: %v", err)
	}

	renamed, err := renameField(app, "mig_demo", "created", "created_at")
	if err != nil || !renamed {
		t.Fatalf("rename created->created_at: %v (%v)", renamed, err)
	}
	renamed, err = renameField(app, "mig_demo", "deleted", "deleted_at")
	if err != nil || !renamed {
		t.Fatalf("rename deleted->deleted_at: %v (%v)", renamed, err)
	}
	// Idempotent: nothing left to rename.
	renamed, err = renameField(app, "mig_demo", "created", "created_at")
	if err != nil || renamed {
		t.Errorf("second rename should be a no-op: %v (%v)", renamed, err)
	}

	col2 := mustCollection(t, app, "mig_demo")
	if col2.Fields.GetByName("created_at") == nil || col2.Fields.GetByName("deleted_at") == nil {
		t.Errorf("renamed fields missing from collection schema")
	}
	rec2, err := app.FindRecordById("mig_demo", rec.Id)
	if err != nil {
		t.Fatalf("record lost by rename: %v", err)
	}
	if asStr(rec2.Get("title")) != "migrating" || rec2.Get("created_at") == "" {
		t.Errorf("data lost by rename: title=%v created_at=%v", rec2.Get("title"), rec2.Get("created_at"))
	}
}
