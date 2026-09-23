package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/pocketbase/pocketbase/core"
)

const (
	geoSource = "db-ip-country-lite"
	geoURLFmt = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"

	geoMaxCompressed = 128 << 20 // 128 MB download cap (real file: ~8 MB)
	geoMaxExpanded   = 512 << 20 // 512 MB gunzip-bomb guard
)

var (
	errGeoTooLarge = errors.New("geo file too large")
	rxGeoRelease   = regexp.MustCompile(`dbip-country-lite-(\d{4}-\d{2})`)
	rxCountryCode  = regexp.MustCompile(`^[A-Z]{2}$`)
)

// geoMeta describes the DB file on disk (persisted as meta.json).
type geoMeta struct {
	Source       string `json:"source"`
	URL          string `json:"url"`
	Release      string `json:"release"`
	DownloadedAt string `json:"downloaded_at"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	BuildEpoch   uint64 `json:"build_epoch,omitempty"`
}

type geoManager struct {
	mu      sync.RWMutex
	readers sync.WaitGroup // tracks active RLock holders for safe Close (N1+)
	reader  *maxminddb.Reader
	meta    *geoMeta
	running bool

	state      string // idle|downloading|ready|error
	percent    int
	downloaded int64
	total      int64
	jobURL     string
	jobErr     string
}

var geoMgr = &geoManager{state: "idle", total: -1}

func geoDir(app core.App) string { return filepath.Join(app.DataDir(), "geoip") }

// geoInit loads a previously downloaded DB (if any). Never fails the boot:
// without a DB every lookup quietly returns "".
func geoInit(app core.App) {
	dir := geoDir(app)
	_ = os.MkdirAll(dir, 0o755)
	_ = os.Remove(filepath.Join(dir, "country.mmdb.tmp")) // stale partial

	final := filepath.Join(dir, "country.mmdb")
	raw, _ := os.ReadFile(filepath.Join(dir, "meta.json"))
	var meta *geoMeta
	if len(raw) > 0 {
		var m geoMeta
		if json.Unmarshal(raw, &m) == nil {
			meta = &m
		}
	}
	st, err := os.Stat(final)
	if err != nil {
		return // no DB yet — stub mode
	}
	r, err := maxminddb.Open(final)
	if err != nil {
		log.Printf("[seed] ERROR: geo stored db unreadable (%v), re-run update", err)
		geoMgr.mu.Lock()
		geoMgr.meta, geoMgr.state, geoMgr.jobErr = meta, "error", "stored db unreadable, re-run update"
		geoMgr.mu.Unlock()
		return
	}
	if meta == nil || meta.Bytes != st.Size() {
		// meta.json missing or stale (crash between swap and meta write):
		// re-derive the minimum rather than distrust the file.
		meta = &geoMeta{Source: geoSource, Release: "unknown", Bytes: st.Size()}
	}
	geoMgr.mu.Lock()
	geoMgr.reader, geoMgr.meta, geoMgr.state = r, meta, "ready"
	geoMgr.percent = 100
	geoMgr.mu.Unlock()
	log.Printf("[seed] geo db loaded (release %s, %d bytes)", meta.Release, meta.Bytes)
}

// geoCountry resolves an IP to an ISO-3166 country code, "" when unknown.
// Non-public addresses never hit the DB; a missing/corrupt DB fails open.
func geoCountry(ipStr string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return ""
	}
	// N1: the read lock is held across BOTH lookups. Copying the pointer
	// and unlocking first races the updater's Close (munmap) — observed
	// as DATA RACE + SIGSEGV. The writer swaps under Lock and closes the
	// old reader only after every pre-swap RLock holder is gone.
	//
	// readers.Add BEFORE RLock: if finish() acquires Lock first, it sees
	// us in the WaitGroup and waits. If we acquire RLock first, finish()
	// blocks on Lock until we release.
	geoMgr.readers.Add(1)
	geoMgr.mu.RLock()
	defer geoMgr.mu.RUnlock()
	defer geoMgr.readers.Done()
	r := geoMgr.reader
	if r == nil {
		return ""
	}
	var cc string
	if err := r.Lookup(addr).DecodePath(&cc, "country", "iso_code"); err != nil || cc == "" {
		cc = ""
		_ = r.Lookup(addr).DecodePath(&cc, "country_code") // non-MaxMind schemas
	}
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if !rxCountryCode.MatchString(cc) {
		return ""
	}
	return cc
}

// --- updater ---------------------------------------------------------------

type countReader struct {
	r       io.Reader
	remain  int64
	onChunk func(int64)
	read    int64
}

func (c *countReader) Read(p []byte) (int, error) {
	if c.remain <= 0 {
		return 0, errGeoTooLarge
	}
	if int64(len(p)) > c.remain {
		p = p[:c.remain]
	}
	n, err := c.r.Read(p)
	if n > 0 {
		c.read += int64(n)
		c.remain -= int64(n)
		if c.onChunk != nil {
			c.onChunk(c.read)
		}
	}
	return n, err
}

func geoReleaseOf(url string) string {
	if m := rxGeoRelease.FindStringSubmatch(url); m != nil {
		return m[1]
	}
	return "custom"
}

func (g *geoManager) noteProgress(n int64) {
	g.mu.Lock()
	g.downloaded = n
	if g.total > 0 {
		g.percent = int(n * 100 / g.total)
		if g.percent > 100 {
			g.percent = 100
		}
	}
	g.mu.Unlock()
}

func (g *geoManager) finish(jobErr string, meta *geoMeta, r *maxminddb.Reader) {
	g.mu.Lock()
	old := g.reader
	if r != nil {
		g.reader, g.meta = r, meta
	}
	g.running = false
	if jobErr != "" {
		g.state, g.jobErr = "error", jobErr
	} else {
		g.state, g.jobErr, g.percent = "ready", "", 100
	}
	g.mu.Unlock()
	// Wait for every RLock holder that entered BEFORE the swap to finish
	// their Lookup. Only then is it safe to Close (munmap) the old reader.
	// New RLock holders after the swap see the new reader.
	g.readers.Wait()
	if old != nil && r != nil {
		old.Close()
	}
}

// startUpdate launches a background refresh. ok=false means one is already
// running (the API answers 409). An empty rawURL selects the default
// DB-IP monthly file (current month, previous month on 404).
func (g *geoManager) startUpdate(app core.App, rawURL string) (ok bool, urlUsed string) {
	g.mu.Lock()
	if g.running {
		g.mu.Unlock()
		return false, ""
	}
	g.running = true
	g.state, g.percent, g.downloaded, g.total, g.jobURL, g.jobErr =
		"downloading", 0, 0, -1, rawURL, ""
	g.mu.Unlock()
	go g.run(app, rawURL)
	if rawURL == "" {
		return true, "default(monthly db-ip release)"
	}
	return true, rawURL
}

var geoCGN = netip.MustParsePrefix("100.64.0.0/10")

// geoAllowPrivate permits loopback/private targets (tests/dev only).
func geoAllowPrivate() bool { return os.Getenv("SEED_GEO_ALLOW_PRIVATE") == "1" }

// geoIPAllowed is the SSRF gate (N2): global unicast only, minus private
// (Go calls IPv6 ULA "global unicast" — IsPrivate catches it) and minus CGN
// shared space (ditto).
func geoIPAllowed(ip netip.Addr) bool {
	if geoAllowPrivate() {
		return true
	}
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	return !geoCGN.Contains(ip)
}

// geoDialer resolves, filters every candidate, and dials the first allowed
// IP — pinning the dial kills DNS-rebinding TOCTOU between check and dial
// (TLS SNI and Host still come from the URL, so pinning is transparent).
func geoDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var blocked []string
	d := &net.Dialer{Timeout: 30 * time.Second}
	for _, ip := range ips {
		a, perr := netip.ParseAddr(ip.String())
		if perr != nil {
			blocked = append(blocked, ip.String())
			continue
		}
		a = a.Unmap()
		if !geoIPAllowed(a) {
			blocked = append(blocked, a.String())
			continue
		}
		return d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
	}
	return nil, fmt.Errorf("ssrf blocked: %s resolves to %v", host, blocked)
}

// N2: pinned dialing (SSRF gate on every hop, redirects included) +
// redirect cap. No env proxy (a proxy would dial for us, bypassing the
// gate). Custom URLs stay a feature — just fenced in.
var geoHTTP = &http.Client{
	Timeout: 10 * time.Minute,
	Transport: &http.Transport{
		DialContext:           geoDialer,
		ResponseHeaderTimeout: 60 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
			return errors.New("redirect to non-http(s) scheme blocked")
		}
		return nil
	},
}

func geoFetch(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pbseed/geoip-updater")
	return geoHTTP.Do(req)
}

func (g *geoManager) run(app core.App, rawURL string) {
	// N3: a panic here must fail the job, not the process.
	defer func() {
		if r := recover(); r != nil {
			g.finish(fmt.Sprintf("panic: %v", r), nil, nil)
		}
	}()
	fail := func(err string) { g.finish(err, nil, nil) }

	urls := []string{rawURL}
	if rawURL == "" {
		now := time.Now().UTC()
		urls = []string{
			time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01"),
			time.Date(now.Year(), now.Month()-1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01"),
		}
		for i, m := range urls {
			urls[i] = "https://download.db-ip.com/free/dbip-country-lite-" + m + ".mmdb.gz"
		}
	}
	var resp *http.Response
	var dlURL string
	for i, u := range urls {
		r, err := geoFetch(u)
		if err != nil {
			fail("fetch failed: " + err.Error())
			return
		}
		if r.StatusCode == http.StatusNotFound && rawURL == "" && i+1 < len(urls) {
			r.Body.Close() // current month not published yet — try previous
			continue
		}
		if r.StatusCode != http.StatusOK {
			r.Body.Close()
			fail("fetch failed: http " + r.Status)
			return
		}
		resp, dlURL = r, u
		break
	}
	if resp == nil {
		fail("fetch failed: no release found")
		return
	}
	defer resp.Body.Close()

	g.mu.Lock()
	g.total, g.jobURL = resp.ContentLength, dlURL
	g.mu.Unlock()

	dir := geoDir(app)
	tmp := filepath.Join(dir, "country.mmdb.tmp")
	final := filepath.Join(dir, "country.mmdb")
	_ = os.Remove(tmp)
	out, err := os.Create(tmp)
	if err != nil {
		fail("store failed: " + err.Error())
		return
	}
	wire := &countReader{r: resp.Body, remain: geoMaxCompressed + 1, onChunk: g.noteProgress}

	// Sniff: real releases are .gz, but accept a raw .mmdb too.
	head := make([]byte, 2)
	if _, err := io.ReadFull(wire, head); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		fail("fetch failed: empty body")
		return
	}
	stream := io.MultiReader(strings.NewReader(string(head)), wire)
	var src io.Reader = stream
	if head[0] == 0x1f && head[1] == 0x8b {
		gz, err := gzip.NewReader(stream)
		if err != nil {
			out.Close()
			_ = os.Remove(tmp)
			fail("bad gzip: " + err.Error())
			return
		}
		defer gz.Close()
		src = gz
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), &countReader{r: src, remain: geoMaxExpanded + 1})
	out.Close()
	if err != nil {
		_ = os.Remove(tmp)
		if errors.Is(err, errGeoTooLarge) {
			fail("file too large, rejected")
			return
		}
		fail("download failed: " + err.Error())
		return
	}

	// Validate before swapping: must open AND verify as a real MaxMind-DB.
	// Open alone only parses the metadata; Verify walks the whole tree
	// (~28 ms on the 8 MB release, monthly cost) — required for untrusted
	// input such as a custom update URL.
	probe, err := maxminddb.Open(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		fail("not a valid mmdb file: " + err.Error())
		return
	}
	buildEpoch := probe.Metadata.BuildEpoch
	if err := probe.Verify(); err != nil {
		probe.Close()
		_ = os.Remove(tmp)
		fail("db corrupt: " + err.Error())
		return
	}
	probe.Close()

	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		fail("store failed: " + err.Error())
		return
	}
	fresh, err := maxminddb.Open(final)
	if err != nil {
		fail("fresh db unreadable: " + err.Error())
		return
	}
	meta := &geoMeta{
		Source: geoSource, URL: dlURL, Release: geoReleaseOf(dlURL),
		DownloadedAt: time.Now().UTC().Format(time.RFC3339),
		SHA256:       hex.EncodeToString(h.Sum(nil)),
		Bytes: n, BuildEpoch: uint64(buildEpoch),
	}
	if raw, err := json.MarshalIndent(meta, "", "  "); err == nil {
		mf := filepath.Join(dir, "meta.json.tmp")
		if os.WriteFile(mf, raw, 0o644) == nil {
			_ = os.Rename(mf, filepath.Join(dir, "meta.json"))
		}
	}
	log.Printf("[seed] geo db updated (release %s, %d bytes, sha256 %s...)", meta.Release, n, meta.SHA256[:16])
	g.finish("", meta, fresh)
}

// --- endpoints (superuser only) --------------------------------------------

func seedGeoGuard(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	if !e.Auth.IsSuperuser() {
		return seedErr(e, 403, "forbidden")
	}
	return nil
}

// POST /api/seed/geo/update {url?} — start a background refresh.
// Empty url = default DB-IP monthly release (current, else previous month).
// A custom url must be http(s) and serve a .gz or raw .mmdb.
func seedGeoUpdate(e *core.RequestEvent) error {
	if err := seedGeoGuard(e); err != nil {
		return err
	}
	var b struct {
		URL string `json:"url"`
	}
	_ = e.BindBody(&b)
	rawURL := strings.TrimSpace(b.URL)
	if rawURL != "" {
		u, err := url.ParseRequestURI(rawURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return seedErr(e, 400, "bad_url")
		}
	}
	ok, used := geoMgr.startUpdate(e.App, rawURL)
	if !ok {
		return seedErr(e, 409, "busy")
	}
	return e.JSON(200, map[string]any{"ok": true, "started": true, "url": used})
}

// GET /api/seed/geo/status — refresh progress + loaded DB info.
func seedGeoStatus(e *core.RequestEvent) error {
	if err := seedGeoGuard(e); err != nil {
		return err
	}
	geoMgr.mu.RLock()
	defer geoMgr.mu.RUnlock()
	return e.JSON(200, map[string]any{
		"state": geoMgr.state, "percent": geoMgr.percent,
		"downloaded_bytes": geoMgr.downloaded, "total_bytes": geoMgr.total,
		"url": geoMgr.jobURL, "error": ifEmpty(geoMgr.jobErr), "db": geoMgr.meta,
	})
}

func ifEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// GET /api/seed/geo/lookup?ip= — diagnostic country lookup for the panel.
func seedGeoLookup(e *core.RequestEvent) error {
	if err := seedGeoGuard(e); err != nil {
		return err
	}
	ip := strings.TrimSpace(e.Request.URL.Query().Get("ip"))
	if _, err := netip.ParseAddr(ip); err != nil {
		return seedErr(e, 400, "bad_ip")
	}
	return e.JSON(200, map[string]any{"ip": ip, "country": geoCountry(ip)})
}
