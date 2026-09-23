package main

// schema_registry.go — ЕДИНАЯ ТОЧКА ПРАВДЫ схемы БД проекта.
//
// Каждая коллекция сервиса описана здесь целиком: поля, индексы,
// правила доступа, принадлежность к мягкому удалению. Из реестра на
// каждом старте схема доводится до желаемого состояния (декларативная
// модель «рендер», а не одноразовый инсталлер):
//
//   - отсутствующая коллекция создаётся;
//   - недостающие поля добавляются (только добавление, без потерь);
//   - правила СЛУЖЕБНЫХ коллекций (все, кроме «общих») сверяются с
//     реестром и восстанавливаются при дрейфе (запись в лог);
//   - правила ОБЩЕЙ коллекции пользователей не перезаписываются —
//     только предупреждение в лог (оператор мог настроить осознанно);
//   - индексы подтверждаются идемпотентно;
//   - легаси-переименование поля `deleted` → `deleted_at`.
//
// Порядок запуска: см. main.go (Bootstrap). Тесты инвариантов —
// schema_registry_test.go.

import (
	"log"
	"strings"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

// schemaEntry — одна коллекция в реестре схемы.
//
// Поля:
//   - Name: string — имя коллекции;
//   - Service: bool — служебная коллекция проекта: её правила на
//     каждом старте восстанавливаются из реестра (инвариант);
//     для «общих» коллекций (пользователи) правила только
//     проверяются предупреждением;
//   - SoftDelete: bool — коллекция с мягким удалением: поле
//     `deleted_at`, легаси-переименование `deleted` и регистрация в
//     реестре мягкого удаления;
//   - Build: func(usersId string) *core.Collection — конструктор
//     коллекции «с нуля»: поля, индексы, правила. Эталон для сверки.
type schemaEntry struct {
	Name       string
	Service    bool
	SoftDelete bool
	Build      func(usersId string) *core.Collection
}

// seedSchema — реестр коллекций проекта. Добавление новой таблицы =
// новая запись здесь (и доменное использование полей); другого места,
// где объявляется схема служебных коллекций, в проекте нет.
var seedSchema = []schemaEntry{
	{
		Name:    "seed_challenges",
		Service: true,
		Build: func(_ string) *core.Collection {
			c := core.NewBaseCollection("seed_challenges")
			c.Fields.Add(
				&core.TextField{Name: "public_key", Max: 64},
				&core.TextField{Name: "nonce", Max: 64},
				&core.TextField{Name: "purpose", Max: 16},
				&core.BoolField{Name: "used"},
				&core.TextField{Name: "expires", Max: 64},
			)
			autoDates(c)
			c.Indexes = types.JSONArray[string]{
				"CREATE UNIQUE INDEX idx_seed_challenges_nonce ON seed_challenges (nonce)",
			}
			return c
		},
	},
	{
		Name:    "seed_used",
		Service: true,
		Build: func(_ string) *core.Collection {
			c := core.NewBaseCollection("seed_used")
			c.Fields.Add(
				&core.TextField{Name: "nonce", Max: 64},
				&core.TextField{Name: "expires", Max: 64},
			)
			autoDates(c)
			c.Indexes = types.JSONArray[string]{
				"CREATE UNIQUE INDEX idx_seed_used_nonce ON seed_used (nonce)",
			}
			return c
		},
	},
	{
		Name:       "seed_sessions",
		Service:    true,
		SoftDelete: true,
		Build: func(usersId string) *core.Collection {
			c := core.NewBaseCollection("seed_sessions")
			c.Fields.Add(
				&core.RelationField{Name: "user", CollectionId: usersId, MaxSelect: 1},
				&core.TextField{Name: "grant_id", Max: 64},
				&core.TextField{Name: "secret_hash", Max: 128},
				&core.TextField{Name: "device_name", Max: 255},
				&core.TextField{Name: "ip_hash", Max: 128},
				&core.TextField{Name: "ip_masked", Max: 255},
				&core.TextField{Name: "ip_country", Max: 8},
				&core.JSONField{Name: "history"},
				&core.BoolField{Name: "revoked"},
				&core.TextField{Name: "last_seen", Max: 64},
				&core.TextField{Name: "expires", Max: 64},
				// Сессии суперюзера: строка принадлежит не записи `users`,
				// а записи `_superusers` (ид здесь), а привязка запросов —
				// по хэшу носимого токена (обновляется при refresh, поэтому
				// сессия не рвётся). У обычных сессий оба поля пусты.
				&core.TextField{Name: "superuser_id", Max: 32},
				&core.TextField{Name: "token_hash", Max: 128},
				// Модель B маски: сессия принадлежит самому исполнителю
				// (админ/суперюзер), а это поле указывает, от чьего имени
				// он действует. Пусто у обычных сессий.
				&core.RelationField{Name: "on_behalf_of", CollectionId: usersId, MaxSelect: 1},
			)
			autoDates(c)
			c.Fields.Add(softDeleteField())
			c.Indexes = types.JSONArray[string]{
				"CREATE UNIQUE INDEX idx_seed_sessions_grant ON seed_sessions (grant_id)",
				"CREATE INDEX idx_seed_sessions_user ON seed_sessions (user)",
				"CREATE INDEX idx_seed_sessions_user_created ON seed_sessions (user, created_at DESC)",
				"CREATE INDEX idx_seed_sessions_user_deleted_at ON seed_sessions (user, deleted_at)",
				"CREATE UNIQUE INDEX idx_seed_sessions_token ON seed_sessions (token_hash) WHERE token_hash != ''",
			}
			return c
		},
	},
	{
		Name:    "seed_settings",
		Service: true,
		Build: func(usersId string) *core.Collection {
			// Одна строка = одна настройка: пользователь пуст — глобальное
			// значение по умолчанию, задан — персональное переопределение.
			// Частичные уникальные индексы: в SQLite значения пустого
			// пользователя считаются разными, поэтому нужны два индекса.
			c := core.NewBaseCollection("seed_settings")
			c.Fields.Add(
				&core.TextField{Name: "key", Max: 64},
				&core.BoolField{Name: "value"},
				&core.RelationField{Name: "user", CollectionId: usersId, MaxSelect: 1},
				&core.BoolField{Name: "locked"},
			)
			autoDates(c)
			c.Indexes = types.JSONArray[string]{
				"CREATE UNIQUE INDEX idx_seed_settings_personal ON seed_settings (user, key) WHERE user IS NOT NULL",
				"CREATE UNIQUE INDEX idx_seed_settings_global ON seed_settings (key) WHERE user IS NULL",
			}
			return c
		},
	},
	{
		Name:    "seed_gateway",
		Service: true,
		Build: func(usersId string) *core.Collection {
			// Переопределения констант защиты гейтвея: одна строка = один
			// параметр. Строка существует, только если значение отличается
			// от стандартного (запись равного стандарту запрещена);
			// удаление строки возвращает параметр к константе/окружению.
			c := core.NewBaseCollection("seed_gateway")
			c.Fields.Add(
				&core.TextField{Name: "key", Max: 64},
				&core.TextField{Name: "value", Max: 32},
			)
			autoDates(c)
			c.Indexes = types.JSONArray[string]{
				"CREATE UNIQUE INDEX idx_seed_gateway_key ON seed_gateway (key)",
			}
			return c
		},
	},
	{
		Name:    "seed_audit",
		Service: true,
		Build: func(usersId string) *core.Collection {
			// Журнал действий администрации (модель B маски): кто сделал,
			// с каким уровнем и от чьего имени (если была надета маска).
			// Исполнителем может быть и суперюзер (его ид нет в users),
			// поэтому актёр — пара текстовых полей, а не связь.
			c := core.NewBaseCollection("seed_audit")
			c.Fields.Add(
				&core.TextField{Name: "actor_id", Max: 32},
				&core.TextField{Name: "actor_kind", Max: 16},
				&core.TextField{Name: "actor_label", Max: 255},
				&core.RelationField{Name: "on_behalf_of", CollectionId: usersId, MaxSelect: 1},
				&core.TextField{Name: "action", Max: 64},
				&core.JSONField{Name: "detail"},
				// Привязка к сессии: грант сессии из `seed_sessions`
				// (у суперюзера — его сессия по токену, у маски — маска-сессия).
				// Пусто у гостей и серверных строк без запроса.
				&core.TextField{Name: "session", Max: 64},
			)
			autoDates(c)
			// Чтение журнала: суперюзер (правил для него не существует) и
			// пользователи с ролью «admin». Запись запрещена всем без
			// исключения — см. protectAuditCollection.
			auditRead := types.Pointer(`@request.auth.role = "admin"`)
			c.ListRule = auditRead
			c.ViewRule = auditRead
			c.Indexes = types.JSONArray[string]{
				"CREATE INDEX idx_seed_audit_behalf ON seed_audit (on_behalf_of, created_at DESC)",
				"CREATE INDEX idx_seed_audit_action ON seed_audit (action, created_at DESC)",
				"CREATE INDEX idx_seed_audit_session ON seed_audit (session, created_at DESC)",
			}
			return c
		},
	},
	// Примечание: демо-коллекция записей в продакшене не создаётся —
	// она существует только в тестах (см. тесты мягкого удаления).
}

// registryEntry ищет коллекцию в реестре схемы по имени.
//
// Параметры:
//   - name: string — имя коллекции.
//
// Возвращает:
//   - *schemaEntry — запись реестра (или второй результат false).
func registryEntry(name string) (*schemaEntry, bool) {
	for i := range seedSchema {
		if seedSchema[i].Name == name {
			return &seedSchema[i], true
		}
	}
	return nil, false
}

// syncSeedSchema доводит схему служебных коллекций до состояния,
// описанного реестром: создаёт отсутствующие коллекции, добавляет
// недостающие поля, восстанавливает правила служебных коллекций,
// подтверждает индексы и выполняет легаси-переименование поля
// мягкого удаления. Идемпотентна: вызывается на каждом старте.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: error — ошибка схемы (запуск прерывается).
func syncSeedSchema(app core.App) error {
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		return err
	}
	for i := range seedSchema {
		entry := &seedSchema[i]
		existing, err := app.FindCollectionByNameOrId(entry.Name)
		if err != nil || existing == nil {
			if err := app.Save(entry.Build(users.Id)); err != nil {
				return err
			}
			log.Printf("[seed] collection created: %s", entry.Name)
			continue
		}
		// Легаси-миграция старых томов: поле «удалён» переехало в дату.
		if entry.SoftDelete {
			if _, err := renameField(app, entry.Name, "deleted", "deleted_at"); err != nil {
				return err
			}
		}
		if entry.Service {
			if err := reconcileRules(app, existing, entry); err != nil {
				return err
			}
		}
		if err := reconcileFields(app, existing, entry.Build(users.Id)); err != nil {
			return err
		}
	}
	return ensureRegistryIndexes(app)
}

// reconcileFields добавляет в существующую коллекцию поля, объявленные
// в реестре, но отсутствующие в базе (только добавление — существующие
// поля и данные не трогаются).
//
// Параметры:
//   - app: core.App — приложение;
//   - existing: *core.Collection — коллекция из базы;
//   - fresh: *core.Collection — эталон из реестра.
//
// Возвращает: error — ошибка сохранения.
func reconcileFields(app core.App, existing *core.Collection, fresh *core.Collection) error {
	var missing []core.Field
	for _, f := range fresh.Fields {
		name := f.GetName()
		if name == core.FieldNameId { // id управляется самим PocketBase
			continue
		}
		if existing.Fields.GetByName(name) == nil {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	existing.Fields.Add(missing...)
	if err := app.Save(existing); err != nil {
		return err
	}
	log.Printf("[seed] fields added (collection %s)", existing.Name)
	return nil
}

// rulePtrEqual сравнивает два указателя на правило (nil = доступ
// только суперюзерам, "" = публичный).
//
// Возвращает: bool — правила совпадают.
func rulePtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// reconcileRules сверяет правила служебной коллекции с эталоном
// реестра и восстанавливает их при дрейфе (с записью в лог). Правила
// служебных коллекций — инвариант: их незачем тюнинговать извне,
// доступ к данным идёт через эндпоинты сервиса.
//
// Параметры:
//   - app: core.App — приложение;
//   - existing: *core.Collection — коллекция из базы;
//   - entry: *schemaEntry — запись реестра.
//
// Возвращает: error — ошибка сохранения.
func reconcileRules(app core.App, existing *core.Collection, entry *schemaEntry) error {
	fresh := entry.Build("")
	if rulePtrEqual(existing.ListRule, fresh.ListRule) &&
		rulePtrEqual(existing.ViewRule, fresh.ViewRule) &&
		rulePtrEqual(existing.CreateRule, fresh.CreateRule) &&
		rulePtrEqual(existing.UpdateRule, fresh.UpdateRule) &&
		rulePtrEqual(existing.DeleteRule, fresh.DeleteRule) {
		return nil
	}
	existing.ListRule = fresh.ListRule
	existing.ViewRule = fresh.ViewRule
	existing.CreateRule = fresh.CreateRule
	existing.UpdateRule = fresh.UpdateRule
	existing.DeleteRule = fresh.DeleteRule
	if err := app.Save(existing); err != nil {
		return err
	}
	log.Printf("[seed] WARN: collection %s rules drifted, restored from registry", existing.Name)
	return nil
}

// idempotentIndexDDL превращает DDL индекса из реестра в идемпотентный
// («IF NOT EXISTS»), чтобы подтверждать индексы на каждом старте.
//
// Параметры:
//   - ddl: string — DDL вида CREATE [UNIQUE] INDEX ...
//
// Возвращает: string — тот же DDL с «IF NOT EXISTS».
func idempotentIndexDDL(ddl string) string {
	if strings.Contains(ddl, "IF NOT EXISTS") {
		return ddl
	}
	if strings.HasPrefix(ddl, "CREATE UNIQUE INDEX ") {
		return strings.Replace(ddl, "CREATE UNIQUE INDEX ", "CREATE UNIQUE INDEX IF NOT EXISTS ", 1)
	}
	return strings.Replace(ddl, "CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1)
}

// ensureRegistryIndexes подтверждает физическое существование всех
// индексов реестра (идемпотентно). Индексы, объявленные при создании
// коллекции, не воссоздаются после удаления — без них запуск падает
// громко: молчаливая незащищённость хуже простоя.
//
// Параметры:
//   - app: core.App — приложение.
//
// Возвращает: error — ошибка создания индекса.
func ensureRegistryIndexes(app core.App) error {
	for i := range seedSchema {
		fresh := seedSchema[i].Build("")
		for _, ddl := range fresh.Indexes {
			q := idempotentIndexDDL(ddl)
			if _, err := app.NonconcurrentDB().NewQuery(q).Execute(); err != nil {
				log.Printf("[seed] ERROR: index ensure failed: %v (%s)", err, q)
				return err
			}
		}
	}
	return nil
}

// Базовые правила коллекции пользователей — часть продуктовой схемы
// (учитывают роли): своё видит каждый, всех видят админ и модератор
// (чтение), менять других может админ. Правила применяются при старте
// автоматически с записью в лог: на них завязаны права ролей, дрейф
// здесь — поломка продукта, а не настройка оператора.

// usersStaffViewRule — чтение: своё + весь список для админа/модератора.
const usersStaffViewRule = `id = @request.auth.id || @request.auth.role = "admin" || @request.auth.role = "moderator"`

// usersAdminUpdateRule — изменение: своё + чужие записи для админа
// (служебные поля при этом охраняет protectUsersFields).
const usersAdminUpdateRule = `id = @request.auth.id || @request.auth.role = "admin"`

// usersSelfRule — удаление: только своё.
const usersSelfRule = `id = @request.auth.id`

// applyUsersRules приводит правила коллекции пользователей к базовым
// (ролевым). Идемпотентна: совпадающие правила не трогаются, дрейф
// исправляется с записью в лог.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func applyUsersRules(app core.App) {
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil || users == nil {
		return
	}
	wantList := types.Pointer(usersStaffViewRule)
	wantView := types.Pointer(usersStaffViewRule)
	wantUpdate := types.Pointer(usersAdminUpdateRule)
	wantDelete := types.Pointer(usersSelfRule)
	drift := !rulePtrEqual(users.ListRule, wantList) ||
		!rulePtrEqual(users.ViewRule, wantView) ||
		!rulePtrEqual(users.UpdateRule, wantUpdate) ||
		!rulePtrEqual(users.DeleteRule, wantDelete) ||
		users.CreateRule != nil
	if !drift {
		return
	}
	users.ListRule = wantList
	users.ViewRule = wantView
	users.UpdateRule = wantUpdate
	users.DeleteRule = wantDelete
	users.CreateRule = nil
	if err := app.Save(users); err != nil {
		log.Printf("[seed] ERROR: users role rules apply failed: %v", err)
		return
	}
	log.Printf("[seed] users rules aligned to role baseline (list/view: staff read; update: admin; delete: self)")
}
