# SPEC — lib `paginate` (tanstack-start + jotai)

Статус: design утверждён по секциям 1–5 (2026-09-13). Спека собрана из подтверждённых секций + решения D1–D4.
Уровень протокола: full. Безопасный минимум (§8) и верификация (§7) не упрощаются.

## 1. Цель и рамки

Headless-библиотека постраничной загрузки данных для проекта на TanStack Start + jotai.
Живёт в демо-приложении в `src/lib/paginate/`; переносится в целевой проект копированием директории.

**Вне lib (граница ответственности, требование пользователя):** БД через пагинатор не подключается.
Данные попадают в пагинатор ТОЛЬКО через `adapter.loadPage/getInitial` (источник) и `storage.read`.
Политики доступа к реальной БД — задача уровня приложения-потребителя (см. §6, путь 1).

**В скоупе:** demo-приложение Start (SSR, tailwind 4) с двумя пагинаторами на одной странице; vitest-тесты lib и серверной логики демо; интеграционные curl-проверки SSR.

## 2. Требования (R) — трассировка к словам пользователя

| # | Требование |
|---|---|
| R1 | Подгрузка страниц: accumulate-режим копит страницы; single-режим показывает одну |
| R2 | UI строит потребитель (headless); lib даёт состояние, действия и блоки (Host/PageAnchor/EdgeSentinel) |
| R3 | Текущая страница трекается якорем у первого элемента страницы (IntersectionObserver) |
| R4 | Слои: источник (fetch «дай страницу») / адаптер (source+storage фасад) / хранилище (персист между сессиями) |
| R5 | Адаптер для SSR tanstack, где GET (URL ?page) — хранилище указателя страницы |
| R6 | Кнопки пагинатора НЕ читают storage: meta (totalPages/totalItems/hasNext) приходит в конверте ответа источника; storage при восстановлении лишь подкрашивает meta до первого fetch |
| R7 | Прыжок на незагруженную страницу → сброс: отображается только запрошенная; на загруженную → скролл к её якорю без fetch |
| R8 | Список — в собственном скролл-контейнере (Host); при загрузке «с нуля» скролл возвращается к началу |
| R9 | `name` у пагинатора: несколько экземпляров на одной странице (реестр, ключи storage, URL-параметры) |
| R10 | Пагинатор отдаёт хранилищу ПОЛНЫЙ snapshot; storage сам берёт нужное (default: page + totalItems) |
| R11 | Пагинатор URL не меняет: меняет page у себя и передаёт в adapter.persist; в GET-адаптере ?page следует за скроллом (replace-навигация — на стороне адаптера) |
| R12 | Источник без известного total → номерные кнопки (1,2,3…) не рендерятся, только стрелки |
| R13 | Append-загрузка: до прихода данных UI рисует скелетоны; число = числу карточек страницы от источника (pageSize; после первого ответа — items.length последнего) |
| R14 | viewState: `notReady` (нет данных при старте/React не готов) и `empty` (текущая страница без данных); пустой результат ПОДГРУЗКИ → ничего не менять. События: loaded / empty-page / append-empty / error (сервер упал, таймаут — Error из source как есть) / page-changed — для расширения (toast «сервер оффлайн» и т.п.) |
| R15 | Host = скролл-контейнер с name; компоненты внутри берут пагинатор из контекста без name; `goPage(5)` — только номер |
| R16 | Стек (свежий): Start 1.168.53, router 1.170.36, jotai 3.0.0, react 19.3, zod 4, tailwind 4.3 + @tailwindcss/vite, vitest 5, node ≥22.12 |
| R17 | Deny by default (§8.1): неизвестный `name` → throw; невалидный ввод на любом краю → отказ/безопасный дефолт, никогда «все данные» |

## 3. Архитектура

```
ПАГИНАТОР (ядро, jotai-атомы)  ← нормализованный PaginatorState →  АДАПТЕР (source+storage фасад)
  трекинг текущей страницы (якоря),                                    │ loadPage = source (единственный путь к данным)
  append-vs-replace, запрос данных,                                    │ persist  = storage.write / URL-navigate
  snapshot для UI, события                                             ▼
                                                                   STORAGE (memory / localStorage / GET-URL)
```

### 3.1 Финальные контракты (types.ts — одна дефиниция, импортят обе стороны)

```ts
export type MaybePromise<T> = T | Promise<T>

export type PageRequest = { page: number; pageSize: number }

export type PageResponse<T> = {
  items: T[]
  totalItems?: number
  totalPages?: number
  hasNext?: boolean
}

export type Source<T> = (req: PageRequest) => Promise<PageResponse<T>>

// Что storage может вернуть при восстановлении (валидируется zod на read):
export type RestorableState = {
  page: number
  pageSize: number
  totalItems: number | null
  totalPages: number | null
}

export type PaginatorState<T> = RestorableState & {
  name: string
  loadedPages: number[]             // отсортировано по возрастанию
  pages: Record<number, T[]>        // accumulate копит; single хранит одну
  status: 'init' | 'idle' | 'loading' | 'error'
  error: string | null
  skeletonCount: number | null      // R13: append-загрузка → число скелетонов; иначе null
  loadingDir: 1 | -1 | null         // куда вставлять скелетоны/данные (конец/начало)
  hasNext: boolean | null           // из meta источника; null = неизвестно
  reqId: number                     // внутренний счётчик гонок (в state → per-store, SSR-safe, D4)
}

export type AdapterInit<T> = {
  page: number
  pageSize?: number
  totalItems?: number | null
  totalPages?: number | null
  hasNext?: boolean | null
  preloaded?: Record<number, T[]>   // SSR: loader уже принёс — не рефетчить
}

export type PaginatorAdapter<T> = {
  getInitial(): MaybePromise<AdapterInit<T>>
  loadPage(req: PageRequest): Promise<PageResponse<T>>
  persist(state: PaginatorState<T>): MaybePromise<void>
  capabilities: { append: boolean }
}

export type PaginatorStorage = {
  read(name: string): MaybePromise<Partial<RestorableState> | null>
  write(name: string, snapshot: PaginatorState<unknown>): MaybePromise<void>
}

export type PaginatorConfig<T> =
  | { name: string; adapter: PaginatorAdapter<T> }
  | { name: string; source: Source<T>; pageSize?: number; append?: boolean; storage?: PaginatorStorage }

export type PaginatorEvent =
  | { type: 'loaded'; page: number; itemCount: number; via: 'init' | 'replace' | 'append' }
  | { type: 'empty-page'; page: number }
  | { type: 'append-empty'; page: number }
  | { type: 'error'; error: unknown; page: number | null; phase: 'init' | 'replace' | 'append' }
  | { type: 'page-changed'; page: number; via: 'anchor' | 'go' | 'url' | 'init' }

export type ViewState = 'notReady' | 'loading' | 'error' | 'empty' | 'ready'
```

### 3.2 Решения, принятые при финализации (уточняют утверждённые секции)

- **D1.** `onPage` убран из интерфейса адаптера (был в секции 3 rev.2): внешняя смена страницы приходит в ядро действием `onExternalPage(page)`; кто её доставляет — интеграция: `PaginatorHost` принимает проп `externalPage?: number` (roутер-нейтрально), `TanStackPaginatorHost` сам берёт её из search-состояния роутера. Адаптер остаётся фасадом данных/персиста.
- **D2.** TanStack-клей (useRouter → persist-навигация, useSearch → externalPage) изолирован в компоненте `TanStackPaginatorHost` (lib/react-tanstack.tsx). Generic `PaginatorHost` про роутер не знает.
- **D3.** В state нет поля `mode` (единственный источник — `capabilities.append`); добавлены `loadingDir`, `hasNext`, `reqId`.
- **D4.** Гард гонок — `reqId` внутри `PaginatorState` (значения живут в store), а не в модульном реестре: конкурентные SSR-запросы с общим per-request store-паттерном не отбрасывают ответы друг друга.

### 3.3 Семантика действий ядра (core.ts)

```
initPaginator(store, name)             // идемпотентно: status!=='init' → skip
  adapter.getInitial() → preloaded?
    да  → state := {page, pages: preloaded, loadedPages, meta}, status 'idle', page-changed(via:init), loaded(via:init)
    нет → fetch page (replace-путь)
  ошибка getInitial/fetch → status 'error', error-событие(phase:'init')

goToPage(store, name, n)               // кнопка/ссылка
  n ∈ loadedPages → page := n, page-changed(via:'go'), scrollDriver.toPage(n), persist
  иначе → page := n, persist, status 'loading' (skeletonCount null), fetch → REPLACE
          → scrollDriver.toTop(), loaded(via:'replace') | empty-page | error(phase:'replace')

loadMore(store, name, dir)             // сентинел; только capabilities.append
  гарды: status==='loading' → skip; canGo(dir, state)===false → skip
  target = dir>0 ? max(loadedPages)+1 : min(loadedPages)-1
  skeletonCount := pageSize (или items.length последнего ответа), loadingDir := dir, status 'loading'
  fetch → items.length===0 → «ничего не делать»: skeleton null, status 'idle', hasNext(dir>0):=false, append-empty
        → иначе APPEND: pages[target]=items, loadedPages+=target, meta refresh, skeleton null,
          status 'idle', loaded(via:'append'), persist
  ошибка → status 'error' (страницы целы), error(phase:'append')

reportAnchor(store, name, page)        // от AnchorTracker
  page !== state.page → page := page, page-changed(via:'anchor'), persist

onExternalPage(store, name, page)      // URL back/forward/ссылка (через Host externalPage)
  page === state.page → игнор (эхо-guard)
  page ∈ loadedPages → page := page, page-changed(via:'url'), scrollDriver.toPage(page)
  иначе → page := page, fetch → REPLACE → scrollDriver.toTop(), page-changed(via:'url')

retry = повтор последнего действия (goToPage/loadMore) — UI-решение, ядро хранит lastAction
```

REPLACE := `pages={n:items}`, `loadedPages=[n]`, meta из ответа, status 'idle', error null.
APPEND := дописывание страницы к коллекции.
Гонки: каждый fetch увеличивает `state.reqId`; резолв с устаревшим reqId отбрасывается целиком.
Reset (goToPage/onExternalPage-replace) во время in-flight loadMore → append-результат отбрасывается по reqId.
`// ponytail: устаревшие запросы отбрасываются, но не прерываются — AbortSignal в PageRequest, если source дорогой.`

persist-точки: goToPage, reportAnchor, loadMore-успех. НЕ персистим: init, onExternalPage (эхо), ошибки.
Ошибка persist → console.warn, состояние не ломается.

### 3.4 Derived-селекторы (чистые, pure.ts)

```
deriveMeta(resp, pageSize) → {totalItems, totalPages, hasNext}   // приоритет: totalPages > ceil(totalItems/pageSize) > hasNext; нет ничего → null'ы
flattenPages(state) → T[]                                        // loadedPages по порядку
viewState(state) → ViewState                                     // init→notReady; error→error; loading→loading; items пусто→empty; else ready
canGo(dir, state) → boolean                                      // +1: append && (hasNext ?? (totalPages!=null ? page<totalPages : loadedPages включает max и … )) — точная формула в T1.3
pickCurrentPage(visible: Set<number>, fallback: number) → number // visible пусто → fallback; иначе min(visible)
```

### 3.5 Хранилища (storage.ts)

- `memoryStorage` — Map; default.
- `localStorageStorage({ pick? })` — ключ `pag:<name>`; SSR-guard (`typeof window === 'undefined'` → read null / write no-op);
  `read` → JSON.parse + zod `restorableSchema.partial().safeParse` → мусор отбрасывается (default page=1);
  `write` — default берёт из snapshot `{page, totalItems}` (R10), кастомизируется `pick`.
- GET/URL — не storage-класс, а поведение tanstack-адаптера (R11).

### 3.6 Адаптеры

- `createLocalAdapter({source, storage=memoryStorage, pageSize=20, append=true, name})`:
  getInitial: `storage.read(name)` → `{page: r?.page ?? 1, totalItems: r?.totalItems ?? null, pageSize}`;
  persist: `storage.write(name, state)`; loadPage: source; capabilities: {append}.
- `createTanStackAdapter({name, source, pageSize=20, append=true, pageParam='page', getUrl?, setRouter?})`:
  getInitial: page из `getUrl()` через `pageSearchSchema(pageParam)` (сервер: `getRequest().url`; клиент: `window.location.search`) — одна zod-схема на роут и адаптер;
  persist: роутер привязан → `router.navigate({ search: prev => ({...prev, [pageParam]: state.page}), replace: true })`, значение не изменилось → no-op; не привязан (сервер) → no-op;
  привязку роутера делает `TanStackPaginatorHost` (D2).

### 3.7 Якоря, скролл, хост (anchors.ts, react.tsx)

- `PaginatorHost({name, className?, snapshot?, externalPage?, children})` — провайдер контекста + `<div ref={containerRef} className>` (overflow-y задаёт потребитель классом).
  - `snapshot` → `useHydrateAtoms([[stateAtom(name), snapshot]])` до первого чтения (SSR-гидрация без рефетча);
  - нет snapshot → init-effect (один раз, идемпотентно через status);
  - `externalPage` → effect: отличается от state.page → `onExternalPage` (D1);
  - регистрирует scrollDriver (toTop: `container.scrollTo({top:0})`; toPage: `anchorEl.scrollIntoView({block:'start'})` через rAF после commit) и AnchorTracker (IO root = container).
- `AnchorTracker` — ОДИН IntersectionObserver на пагинатор: observe/unobserve якорей и сентинелей;
  `rootMargin: '0px 0px -80% 0px'` (детект-зона — верхние 20% контейнера); ведёт `visible: Set<page>`;
  изменение → `pickCurrentPage` → `reportAnchor`. Сентинели (kind='sentinel') → при пересечении `loadMore(dir)` через гарды ядра.
  IO отсутствует (старый jsdom/SSR) → tracker не создаётся, ядро работает без якорей.
- `<PageAnchor page>` — обёртка первого элемента страницы (ref → tracker.observe). `<EdgeSentinel dir>` — маркер края.
- Контекст-хуки без name (R15): `usePaginatorState()`, `usePaginatorActions()` → `{goPage(n), loadMore(dir), retry()}`, `usePaginatorEvents(handler)`.
- Escape-hatch вне хоста: `usePaginator(name)`, `onPaginatorEvent(name, cb)`.
- Скелетоны: UI читает `skeletonCount`/`loadingDir` и рисует (R13); lib скелетонов не рендерит.

### 3.8 SSR-поток (routes/items.tsx демо)

```
validateSearch: pageSearchSchema('page')                  // zod .catch → deny-safe default 1
loader: store = createStore()                             // per-request
        products = await initServerPaginator('products', store)   // source = server fn (RPC на клиенте)
        gallery  = await initServerPaginator('gallery', store)
        return { paginators: { products, gallery } }      // Start дегидрирует автоматически
компонент: data = Route.useLoaderData()
        <TanStackPaginatorHost name="products" pageParam="page" snapshot={data.paginators.products} …>
loaderDeps — ПУСТЫЕ: смена ?page на клиенте loader НЕ перезапускает (нет RPC-шторма от скролла, verified-доки + интеграционный тест T6.2)
```

URL-эхо-цикл исключён: persist→navigate→search change→externalPage===state.page→игнор.
`// ponytail: persist на каждое якорное переключение без троттлинга — debounce, если Safari history rate-limit станет проблемой.`

### 3.9 Регистрация (registry.ts)

`definePaginator(config)` — модульная регистрация (app-code, один файл конфигурации, клиент и сервер импортят его же — «одна дефиниция, каждый потребитель»).
`getPaginator(name)` — ленивый экземпляр {adapter, atoms, emitter, lastAction}; **неизвестный name → throw** (R17).
Экземпляры stateless по данным (данные в store) → серверная конкурентность безопасна (D4).

## 4. File Structure

```
package.json  tsconfig.json  vite.config.ts  vitest.config.ts  scripts/env.sh
src/
  styles.css                     # @import "tailwindcss";
  router.tsx                     # createRouter (docs-verified)
  paginators.ts                  # definePaginator ×2 (products: tanstack-adapter+server fn; gallery: local+localStorage, unknown total)
  routes/__root.tsx              # shell + jotai Provider + HeadContent/Scripts
  routes/index.tsx               # ссылки на демо
  routes/items.tsx               # демо-роут: validateSearch, loader, UI (карточки/кнопки/скелетоны/стрелки, tailwind)
  server/db.ts                   # мок-«БД»: 97+43 элемента, только серверный модуль
  server/items-fn.ts             # createServerFn GET .validator(inputSchema).handler(queryItemsPage)
  lib/paginate/
    types.ts        # контракты (§3.1)
    pure.ts         # deriveMeta/flattenPages/viewState/canGo/pickCurrentPage
    events.ts       # эмиттер (on/emit/off)
    storage.ts      # memory/localStorage + restorableSchema (zod)
    registry.ts     # definePaginator/getPaginator (throw на unknown)
    core.ts         # stateAtom+derived, init/goToPage/loadMore/reportAnchor/onExternalPage, reqId-гард
    adapter-local.ts
    adapter-tanstack.ts   # + pageSearchSchema/parsePageFromUrl (одна схема URL)
    anchors.ts      # AnchorTracker + scrollDriver
    react.tsx       # PaginatorHost/context/хуки/PageAnchor/EdgeSentinel
    react-tanstack.tsx  # TanStackPaginatorHost (D2)
    index.ts        # публичный фасад
    *.test.ts       # тесты рядом (co-located)
test/mock-io.ts     # MockIntersectionObserver для jsdom-тестов
docs/…              # память проекта (§10)
```

Сплиты обоснованы: pure vs core (чистое vs эффекты/store), adapters (два runtime-края), react vs react-tanstack (generic vs框架-клей), storage (своя причина меняться — валидация/персист).

## 5. Тесты (стратегия)

- **unit/node** (без React): pure.ts, storage.ts (+bypass: мусор в localStorage), events, registry (unknown→throw), core.ts c fake-адаптером на vanilla `createStore` (init/goToPage/loadMore/races/append-vs-replace/errors/events/skeleton/externalPage), adapter-local (fake storage), adapter-tanstack (инжектированные getUrl/fake router: navigate-вызов, no-op без роутера, pageSearchSchema bypass).
- **jsdom + RTL + MockIntersectionObserver**: Host (контекст без name, snapshot-гидрация — первый рендер с данными, externalPage-эффект), PageAnchor→reportAnchor, EdgeSentinel-гарды, scroll-драйвер (стабы scrollTo/scrollIntoView).
- **integration**: `npm run build` exit 0; dev-сервер + curl: `/items?page=3` → SSR-HTML содержит айтемы страницы 3 (data-testid маркеры); `/items?page=abc` → страница 1 (deny-safe); loader-не-перезапускается на клиентский search-change — проверяется в preview (чек-лист) + отсутствием RPC в логах dev-сервера при скролле.
- Каждый не-trivial таск: RED (наблюдаем провал по правильной причине) → GREEN → verify (весь suite, pristine output). Регрессия ядра: PASS→revert→FAIL→restore→PASS на T2.5 (races) как representative.

## 6. Пути к данным и enforcement (§8.2)

| # | Путь | Enforcement | Тест |
|---|---|---|---|
| 1 | `src/server/db.ts` | Импортируется только серверными модулями (server fn); в клиентский бандл не попадает; in-memory — прямого доступа в обход приложения нет. **При подключении реальной БД потребителем: политика на слое данных (RLS/permissions) — отдельная задача + bypass-тест уровня БД (требование зафиксировано, в демо N/A)** | grep импортов db.ts (T6.3) |
| 2 | server fn (RPC) | `.validator(inputSchema)` zod на сервере: page int ≥1 (catch→отказ), pageSize int 1..100 (анти-DoS); невалидно → отказ, НЕ «все записи» (R17) | bypass: schema.parse({page:'x', pageSize:1e9}) → throws (T5.2) |
| 3 | URL `?page` (ручной ввод) | `pageSearchSchema` — одна zod-схема для validateSearch роута и getInitial адаптера; `.catch(1)` | curl `?page=abc` → page 1 (T6.2) + unit (T3.2) |
| 4 | localStorage snapshot (подделка в devtools) | `restorableSchema` на read: page int ≥1 catch→null→default 1; totalItems int ≥0 nullable; мусор → safe defaults | bypass: битый JSON + враждебные значения → defaults (T1.5) |
| 5 | jotai store / события / реестр | Внешнего пути нет; unknown name → throw (deny by default) | registry throw (T1.7) |

Дублирование enforcement (3 и 4 — одна схема на разные края) — НЕ DRY-нарушение (§8.2): разные края, разные атакующие.

## 7. Нефункциональное

- Никаких memo/useMemo/кэшей без замеров (§4.4); единственная «оптимизация» — derived-атомы jotai (штатный механизм гранулярности, не самописный кэш).
- `ponytail:`-маркеры: AbortSignal (T2.5), persist-троттлинг (§3.8).
- Данные snapshot должны быть JSON-сериализуемы (дегидрация Start) — ограничение типа `T extends Json` не вводим, документируем.
- Arena: node_modules и /tmp не персистят → `scripts/env.sh` идемпотентно поднимает node 22.23.2 и ставит зависимости одной командой; manifest полный.

## 8. Критерии приёмки (доказательства, §7)

1. `source scripts/env.sh && npx vitest run` — 0 fail, все поведения R1–R17 покрыты (матрица в плане).
2. `npx tsc --noEmit` — exit 0. `npm run build` — exit 0.
3. dev-сервер отвечает 200; curl-проверки §6 (пути 2,3) — вывод в отчёте.
4. Live preview: ручной чек-лист (скролл → ?page следует; якорь → подсветка кнопок; прыжок незагруженная → reset+scroll-top; загруженная → scroll к якорю; скелетоны при append; unknown total → только стрелки; localStorage-пагинатор переживает reload; события в консоли демо — toast-заглушка).
5. §6 self-review (Stage A/B) выполнен, находки применены.
6. JOURNAL/INVENTORY/research/план — финальные статусы в том же ходу.
