package main

// auditlist_repro_test.go — регрессия на чтение журнала через штатный
// список: после серии записей (регистрация, правка себя, выход) список
// и фильтры «по исполнителю» / «по упоминанию» обязаны отвечать 200.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// TestAuditListReads повторяет живой сценарий: регистрация юзера,
// правка себя, выход, бан суперюзером — и затем чтение журнала
// списком: весь журнал, «что творил юзер» (по исполнителю) и «что
// творили у юзера» (по упоминанию).
func TestAuditListReads(t *testing.T) {
	app := newSeedTestApp(t)
	defer app.Cleanup()
	do := serveMux(t, app)
	_, suTok := mustSuperuser(t, app)
	hdr := map[string]string{"Authorization": suTok}

	access, ck, uid := edRegister(t, do)

	res, body := do(http.MethodPatch, "/api/collections/users/records/"+uid,
		map[string]string{"Authorization": access, "Cookie": seedCookieName + "=" + ck},
		`{"name":"Репро Имя"}`)
	if res.StatusCode != 200 {
		t.Fatalf("self update status=%d body=%s", res.StatusCode, body)
	}
	res, body = do(http.MethodPost, "/api/seed/logout",
		map[string]string{"Authorization": access, "Cookie": seedCookieName + "=" + ck}, `{}`)
	if res.StatusCode != 200 {
		t.Fatalf("logout status=%d body=%s", res.StatusCode, body)
	}
	// Бан суперюзером после выхода: в журнале появляется строка, где
	// юзер — объект (detail.id), а не исполнитель.
	res, body = do(http.MethodPatch, "/api/collections/users/records/"+uid,
		hdr, `{"banned":true}`)
	if res.StatusCode != 200 {
		t.Fatalf("ban status=%d body=%s", res.StatusCode, body)
	}

	q := func(filter string) string {
		v := url.Values{}
		v.Set("filter", filter)
		return "/api/collections/seed_audit/records?" + v.Encode()
	}
	list := func(u string) (int, []map[string]any) {
		res, body := do(http.MethodGet, u, hdr, "")
		var out struct {
			Items []map[string]any `json:"items"`
		}
		_ = json.Unmarshal([]byte(body), &out)
		return res.StatusCode, out.Items
	}

	urls := []string{
		"/api/collections/seed_audit/records?perPage=50",
		"/api/collections/seed_audit/records",
		"/api/collections/seed_audit/records?perPage=200&sort=-created_at",
		q(`actor_id="` + uid + `"`),
		q(`on_behalf_of="` + uid + `" || detail.id="` + uid + `"`),
	}
	for _, u := range urls {
		for i := 0; i < 5; i++ {
			if st, _ := list(u); st != 200 {
				t.Fatalf("audit list failed: iter=%d url=%s status=%d", i, u, st)
			}
		}
	}

	// «Что творил юзер»: исполнитель — сам юзер (регистрация, правка).
	_, items := list(q(`actor_id="` + uid + `"`))
	if len(items) == 0 {
		t.Fatalf("actor read: no rows for user %s", uid)
	}
	for _, it := range items {
		if it["actor_id"] != uid {
			t.Fatalf("actor read leaked foreign actor: %v", it["actor_id"])
		}
	}

	// «Что творили у юзера»: бан суперюзером обязан найтись по
	// упоминанию в `detail`.
	_, items = list(q(`on_behalf_of="` + uid + `" || detail.id="` + uid + `"`))
	banSeen := false
	for _, it := range items {
		if it["action"] == "records.update" && it["actor_kind"] == "superuser" {
			banSeen = true
		}
	}
	if !banSeen {
		t.Fatalf("mention read: superuser ban of %s not found (%d rows)", uid, len(items))
	}
}
