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
	// geoSource — имя источника базы в метаданных.
	geoSource = "db-ip-country-lite"
	// geoURLFmt — шаблон адреса ежемесячного выпуска DB-IP (подставляется месяц вида 2026-09).
	geoURLFmt = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"

	// geoMaxCompressed — предел размера скачиваемого архива (реальный файл ~8 МБ).
	geoMaxCompressed = 128 << 20
	// geoMaxExpanded — предел распакованного размера (защита от gzip-бомб).
	geoMaxExpanded = 512 << 20
)

var (
	// errGeoTooLarge — файл превышает допустимый размер.
	errGeoTooLarge = errors.New("geo file too large")
	// rxGeoRelease — извлекает месяц выпуска (ГГГГ-ММ) из адреса файла.
	rxGeoRelease = regexp.MustCompile(`dbip-country-lite-(\d{4}-\d{2})`)
	// rxCountryCode — строгая проверка кода страны (две заглавные буквы).
	rxCountryCode = regexp.MustCompile(`^[A-Z]{2}$`)
)

// geoMeta — метаданные базы на диске (сохраняются в meta.json рядом с mmdb).
type geoMeta struct {
	Source       string `json:"source"`                // источник ("db-ip-country-lite")
	URL          string `json:"url"`                   // адрес, откуда скачан файл
	Release      string `json:"release"`               // выпуск ("2026-09" или "custom")
	DownloadedAt string `json:"downloaded_at"`         // время скачивания (RFC3339)
	SHA256       string `json:"sha256"`                // контрольная сумма распакованного файла
	Bytes        int64  `json:"bytes"`                 // размер распакованного файла
	BuildEpoch   uint64 `json:"build_epoch,omitempty"` // epoch сборки базы из её метаданных
}

// geoManager — менеджер геобазы: загрузка, атомарная подмена ридера,
// состояние фоновой задачи. Один экземпляр на процесс (см. geoMgr).
type geoManager struct {
	mu      sync.RWMutex
	reader  *maxminddb.Reader // активный ридер базы (nil = база не загружена)
	meta    *geoMeta          // метаданные активной базы
	running bool              // идёт ли фоновое обновление

	state      string // idle | downloading | ready | error
	percent    int    // прогресс скачивания 0–100
	downloaded int64  // скачано байт
	total      int64  // всего байт (-1 = неизвестно)
	jobURL     string // адрес текущей задачи
	jobErr     string // текст последней ошибки
}

// geoMgr — единственный экземпляр менеджера геобазы процесса.
var geoMgr = &geoManager{state: "idle", total: -1}

// geoDir возвращает каталог геобазы внутри каталога данных приложения.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: string — путь вида <pb_data>/geoip.
func geoDir(app core.App) string { return filepath.Join(app.DataDir(), "geoip") }

// geoInit загружает ранее скачанную геобазу при старте. Никогда не
// роняет запуск: без базы определение страны тихо возвращает "".
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func geoInit(app core.App) {
	dir := geoDir(app)
	_ = os.MkdirAll(dir, 0o755)
	_ = os.Remove(filepath.Join(dir, "country.mmdb.tmp")) // обрывок прошлой загрузки

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
		return // базы ещё нет — режим заглушки
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
		// meta.json отсутствует или устарел (краш между подменой файла и
		// записью метаданных): восстанавливаем минимальные метаданные.
		meta = &geoMeta{Source: geoSource, Release: "unknown", Bytes: st.Size()}
	}
	geoMgr.mu.Lock()
	geoMgr.reader, geoMgr.meta, geoMgr.state = r, meta, "ready"
	geoMgr.percent = 100
	geoMgr.mu.Unlock()
	log.Printf("[seed] geo db loaded (release %s, %d bytes)", meta.Release, meta.Bytes)
}

// geoCountry определяет страну по IP-адресу.
//
// Параметры:
//   - ipStr: string — IP-адрес (пробелы игнорируются).
//
// Возвращает: string — код страны ISO-3166 ("US", "DE") или "" если
// адрес неизвестен, приватный/локальный либо база не загружена.
//
// Открытая модель отказов: любая ошибка даёт "", сессии продолжают
// работать и без базы.
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
	// Блокировка чтения удерживается на ВСЁ время поиска. Сначала снять
	// блокировку, а потом искать нельзя: обновление закроет старый ридер
	// (munmap) под ногами — гонка данных и сегфолт. Обновляющая сторона
	// ждёт эксклюзивную блокировку и закрывает старый ридер только когда
	// все читатели закончили.
	geoMgr.mu.RLock()
	defer geoMgr.mu.RUnlock()
	r := geoMgr.reader
	if r == nil {
		return ""
	}
	var cc string
	if err := r.Lookup(addr).DecodePath(&cc, "country", "iso_code"); err != nil || cc == "" {
		cc = ""
		_ = r.Lookup(addr).DecodePath(&cc, "country_code") // несовместимые схемы баз
	}
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if !rxCountryCode.MatchString(cc) {
		return ""
	}
	return cc
}

// --- обновлятор ------------------------------------------------------------

// countReader — обёртка потока чтения: считает байты, сообщает прогресс
// и обрывает чтение сверх лимита (остановка злоупотреблений размером).
type countReader struct {
	r       io.Reader   // источник данных
	remain  int64       // сколько байт ещё разрешено прочитать
	onChunk func(int64) // вызов после каждой порции (всего прочитано)
	read    int64       // всего прочитано
}

// Read реализует io.Reader: читает не больше остатка, ведёт счётчик.
//
// Параметры:
//   - p: []byte — буфер для чтения.
//
// Возвращает: (int, error) — число прочитанных байт и ошибку
// (включая переполнение лимита).
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

// geoReleaseOf извлекает выпуск базы из адреса скачивания.
//
// Параметры:
//   - url: string — адрес файла.
//
// Возвращает: string — "ГГГГ-ММ" для официальных выпусков, иначе "custom".
func geoReleaseOf(url string) string {
	if m := rxGeoRelease.FindStringSubmatch(url); m != nil {
		return m[1]
	}
	return "custom"
}

// noteProgress обновляет счётчики прогресса скачивания под блокировкой.
//
// Параметры:
//   - n: int64 — сколько байт скачано всего.
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

// finish завершает фоновую задачу обновления и атомарно подменяет ридер.
// Эксклюзивная блокировка гарантирует, что ни одна горутина не находится
// внутри поиска по старому ридеру, поэтому его можно безопасно закрыть
// (munmap). Старая база закрывается только после успешной подмены.
//
// Параметры:
//   - jobErr: string — текст ошибки ("" при успехе);
//   - meta: *geoMeta — метаданные новой базы (при успехе);
//   - r: *maxminddb.Reader — ридер новой базы (при успехе).
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
	if old != nil && r != nil {
		old.Close()
	}
	g.mu.Unlock()
}

// startUpdate запускает фоновое обновление базы.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - rawURL: string — пользовательский адрес ("" = официальный
//     ежемесячный выпуск DB-IP: текущий месяц, при 404 — предыдущий).
//
// Возвращает:
//   - ok: bool — false, если обновление уже выполняется (эндпоинт
//     отвечает 409);
//   - urlUsed: string — адрес или описание источника для ответа.
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

// geoCGN — общее адресное пространство провайдеров (100.64.0.0/10),
// тоже закрыто для скачивания.
var geoCGN = netip.MustParsePrefix("100.64.0.0/10")

// geoAllowPrivate сообщает, разрешены ли локальные/приватные адреса для
// скачивания (переменная окружения, только для тестов и разработки).
//
// Возвращает: bool — true при SEED_GEO_ALLOW_PRIVATE=1.
func geoAllowPrivate() bool { return os.Getenv("SEED_GEO_ALLOW_PRIVATE") == "1" }

// geoIPAllowed — фильтр допустимых адресов при скачивании (защита от
// подмены запросов к внутренним сервисам): только глобальные публичные
// адреса, приватные сети и пространство провайдеров закрыты.
//
// Параметры:
//   - ip: netip.Addr — адрес для проверки.
//
// Возвращает: bool — разрешено ли соединение.
func geoIPAllowed(ip netip.Addr) bool {
	if geoAllowPrivate() {
		return true
	}
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	return !geoCGN.Contains(ip)
}

// geoDialer резолвит имя хоста, проверяет КАЖДЫЙ адрес-кандидат и
// соединяется с первым разрешённым. Проверка на уровне соединения
// исключает гонку «проверка резолва → соединение» (повторный резолв
// уже не выполняется), поэтому подмена адреса после проверки невозможна.
//
// Параметры:
//   - ctx: context.Context — контекст запроса;
//   - network: string — тип сети ("tcp");
//   - addr: string — адрес вида "хост:порт".
//
// Возвращает: (net.Conn, error) — установленное соединение либо ошибку
// блокировки.
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

// geoHTTP — HTTP-клиент обновлятора: соединение через фильтрующий
// dialer, не более 5 редиректов и только по http(s). Прокси из
// окружения не используется (прокси обошёл бы фильтр адресов).
// Свой адрес скачивания остаётся возможностью — но в защитном контуре.
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

// geoFetch выполняет GET-запрос с фирменным User-Agent.
//
// Параметры:
//   - url: string — адрес ресурса.
//
// Возвращает: (*http.Response, error) — ответ сервера (тело закрывает
// вызывающий) либо ошибку сети.
func geoFetch(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pbseed/geoip-updater")
	return geoHTTP.Do(req)
}

// run — тело фоновой задачи обновления: скачивает файл, распаковывает
// при необходимости, проверяет его как настоящую MaxMind-базу (открытие
// + обход всего дерева) и только затем атомарно подменяет активную базу.
// Паника внутри задачи завершает задачу ошибкой, а не процессом.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - rawURL: string — пользовательский адрес ("" = официальный выпуск).
func (g *geoManager) run(app core.App, rawURL string) {
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
			r.Body.Close() // текущий месяц ещё не опубликован — пробуем предыдущий
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

	// Определяем формат: официальные выпуски идут в .gz, но принимаем и чистый .mmdb.
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

	// Проверка до подмены: файл должен открыться И пройти полную проверку
	// дерева. Открытие читает только метаданные; Verify обходит всё дерево
	// (~28 мс на 8 МБ базе) — обязательно для недоверенных источников,
	// например пользовательского адреса обновления.
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
		Bytes:        n, BuildEpoch: uint64(buildEpoch),
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

// --- эндпоинты геобазы (только суперюзер) -----------------------------------

// seedGeoGuard — общая проверка доступа геоподсистемы: без токена — 401,
// не суперюзер — 403.
//
// Параметры:
//   - e: *core.RequestEvent — событие запроса.
//
// Возвращает: error — ответ-ошибка либо nil (доступ разрешён).
func seedGeoGuard(e *core.RequestEvent) error {
	if e.Auth == nil {
		return seedErr(e, 401, "auth_required")
	}
	if !e.Auth.IsSuperuser() {
		return seedErr(e, 403, "forbidden")
	}
	return nil
}

// seedGeoUpdate — POST /api/seed/geo/update. Запускает фоновое обновление
// геобазы. Только суперюзер.
//
// Тело запроса: {url?: string} — пустой url = официальный ежемесячный
// выпуск DB-IP (текущий месяц, при 404 предыдущий); свой адрес должен
// быть http(s) и отдавать .gz или чистый .mmdb.
// Ответ 200: {ok: true, started: true, url: string}
// Ошибки: 400 (неверный адрес), 401/403 (доступ), 409 (уже выполняется).
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
	auditLog(e, "geo.update", map[string]any{"url": used})
	return e.JSON(200, map[string]any{"ok": true, "started": true, "url": used})
}

// seedGeoStatus — GET /api/seed/geo/status. Прогресс обновления и
// сведения о загруженной базе. Только суперюзер.
//
// Ответ 200: {state: "idle"|"downloading"|"ready"|"error", percent: int,
// downloaded_bytes: int, total_bytes: int, url: string|null,
// error: string|null, db: geoMeta|null}
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

// ifEmpty превращает пустую строку в nil для аккуратного ответа в JSON.
//
// Параметры:
//   - s: string — исходная строка.
//
// Возвращает: any — nil при пустой строке, иначе саму строку.
func ifEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// seedGeoLookup — GET /api/seed/geo/lookup?ip=<адрес>. Диагностическое
// определение страны по загруженной базе (для админ-панели). Только суперюзер.
//
// Ответ 200: {ip: string, country: string} ("" если страна неизвестна)
// Ошибки: 400 (адрес не распознан), 401/403 (доступ).
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
