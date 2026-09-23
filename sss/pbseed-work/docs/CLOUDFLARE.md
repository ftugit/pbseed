# Cloudflare перед pbseed — план на будущее

**Статус: ОТЛОЖЕНО (15.09.2026).** Пока работаем без Cloudflare.
Документ фиксирует обсуждённое решение, чтобы вернуться позже.

## Цель

1. Защитить HTTP-поверхность (сам SQLite в volume из сети недоступен):
   API, админка `/_/`, abuse (DDoS, спам в `/api/seed/challenge` — там CPU
   и рост таблицы nonce).
2. Брать реальный IP и страну из заголовков Cloudflare.

## Строгий порядок доверия

**Сначала** доказать «запрос точно пришёл через Cloudflare»
(секрет/туннель), **только потом** доверять `CF-Connecting-IP` /
`CF-IPCountry` / XFF. Напрямую к origin любой может прислать их
поддельными:
- https://devsec-blog.com/2025/04/understanding-the-x-forwarded-for-http-header-security-risks-and-best-practices
- https://stackharbor.com/en/knowledge-base/cfops-real-client-ip-at-origin

## Ловушка: сокетный IP за Cloudflare

За CF (+ балансировщик Northflank) сокетный IP у ВСЕХ пользователей один.
Stage-1 IP-трекинг молча деградирует: кики перестают срабатывать, а при
смене IP балансировщика — массовый кик всех strict-сессий разом
(известный эффект: https://github.com/WITCodingClub/calendar-backend/pull/586).
Поэтому при переезде за CF клиентский IP обязательно брать из
`CF-Connecting-IP` (только после проверки секрета/туннеля!). XFF не
использовать — подделывается.

## Схема A — секретный заголовок (простая, 5 минут)

- Cloudflare: Transform Rule «HTTP Request Header Modification», действие
  **Set static** (перезапись безусловная — клиентскую подделку затирает).
- Приложение: сверка с секретом из env (256 бит, сравнение за константное
  время, в логи не писать, ротация через пару «старый/новый»).
- От проверки освободить только `/api/health` — иначе ляжет Northflank
  healthcheck (он ходит напрямую, без секрета).
- Ограничение: публичный Northflank-URL остаётся доступен, секрет —
  единственная стена (не подобрать, только украсть).

Почему не альтернативы:
- Проверка «запрос с IP-диапазонов Cloudflare» НЕ работает: пиром
  приложения является балансировщик Northflank, а не edge CF.
- mTLS Authenticated Origin Pulls НЕ дотягивается: TLS от Cloudflare
  терминирует LB Northflank.

## Схема B — Cloudflare Tunnel (сильная)

`cloudflared` отдельным сервисом в том же проекте, к pbseed — по
приватным портам Northflank (приватное межсервисное общение:
https://northflank.com/blog/connect-ai-built-app-private-apis-corporate-network).
Публичной поверхности у origin нет вообще; токен туннеля вместо секрета.
Zero Trust бесплатен, WebSocket/SSE пробрасываются.
Проверить в консоли: отключается ли публичный endpoint у сервиса
полностью; если нет — секрет из схемы A остаётся вторым рубежом.

## GeoIP и реальный IP от Cloudflare

- Страна: Managed Transform **«Add visitor location headers»**
  (Rules → Transform Rules → Managed Transforms, бесплатно):
  `CF-IPCountry` + `CF-Region-Code` / `CF-IPCity`
  (https://docs.umami.is/docs/enable-cloudflare-headers).
- Валидация на нашей стороне обязательна: страна `^[A-Z]{2}$`,
  `XX`/`T1` → fallback; IP — парсинг.
- Локальная DB-IP база остаётся fallback-цепочкой:
  секрет/туннель → CF-заголовки → локальный mmdb → `""`.
  Локалка, тесты и уход от CF продолжают работать; обновлять mmdb можно реже.

## Что ещё взять у Cloudflare (free)

- DDoS из коробки; базовый WAF.
- Rate limiting на `/api/seed/challenge` и `/api/seed/login`.
- Access или allowlist на `/_/` (вход суперюзера — самое чувствительное место).
- TLS Full Strict до Northflank + Always Use HTTPS.

## Порядок внедрения (когда решим)

1. DNS на CF (оранжевое облако) → origin = Northflank-URL; TLS Full Strict.
2. Managed Transform «Add visitor location headers» — вкл.
3. Transform Rule с секретным заголовком (A) — или туннель (B).
4. WAF/rate-limit на `/api/seed/*`, Access на `/_/*`.
5. Код приложения: проверка секрета → `CF-Connecting-IP` как client IP →
   `CF-IPCountry` как страна → fallback на mmdb; `/api/health` без секрета.

## Открытые решения

1. Схема A или B? (можно начать с A и переехать на B без смены кода —
   заголовки те же).
2. Fallback на локальную mmdb — рекомендовано «да».
3. Админку `/_/` закрывать через Access сразу или позже?
