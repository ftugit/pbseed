package main

import (
	"log"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/jsvm"
)

// main — точка входа приложения.
//
// Порядок работы:
//  1. Подключает необязательные JS-хуки (каталог pb_hooks рядом с
//     бинарником; авторизация вкомпилирована в бинарник, см. seed.go).
//  2. При старте (событие Bootstrap) готовит схему БД: коллекции и поля
//     аутентификации, поле и индексы мягкого удаления, загружает
//     геобазу, создаёт первого суперюзера из переменных окружения.
//  3. При поднятии HTTP (событие Serve) регистрирует все эндпоинты
//     /api/seed/* и промежуточный слой проверки сессий.
//
// Возвращаемых параметров нет; аварийное завершение — через log.Fatal.
func main() {
	app := pocketbase.New()

	// Консольные команды управления пользователями сайта (роли, баны,
	// сессии, стирание) — единственный способ назначить администратора
	// без входа на сайт.
	app.RootCmd.AddCommand(newUserCommand(app))
	// Консольные команды фаервола: единственный способ включить панель
	// после суточного отключения.
	app.RootCmd.AddCommand(newFirewallCommand(app))
	// Политики и настройки (таблица seed_settings).
	app.RootCmd.AddCommand(newPolicyCommand(app))
	app.RootCmd.AddCommand(newSettingsCommand(app))
	// Параметры гейтвея (переопределения в базе).
	app.RootCmd.AddCommand(newGatewayCommand(app))
	// Обслуживание: геобаза, схема, база данных, журнал действий.
	app.RootCmd.AddCommand(newGeoCommand(app))
	app.RootCmd.AddCommand(newCollectionsCommand(app))
	app.RootCmd.AddCommand(newDBCommand(app))
	app.RootCmd.AddCommand(newAuditCommand(app))

	// Необязательные JS-хуки (каталог pb_hooks рядом с исполняемым
	// файлом; слежение за файлами отключено для контейнеров). Сама
	// авторизация вкомпилирована (см. seed.go); jsvm нужен только для
	// будущих правок без пересборки.
	jsvm.MustRegister(app, jsvm.Config{
		HooksWatch:    false,
		HooksPoolSize: 5,
	})

	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		// Единая точка управления схемой: реестр коллекций, поля,
		// правила, индексы (включая индексы мягкого удаления),
		// настройки безопасности, первый админ.
		if err := ensureSeedSchema(e.App); err != nil {
			log.Printf("[seed] ERROR: schema bootstrap failed: %v", err)
			return err
		}
		installSoftDeleteHooks(e.App)
		installAutomationHooks(e.App)
		geoInit(e.App) // никогда не роняет старт (без базы работает заглушкой)
		log.Printf("[seed] auth ready (domain %s)", seedDomain())
		if !seedCookieSecure() {
			log.Printf("[seed] WARN: PB_COOKIE_INSECURE=1: session cookies without Secure flag (dev only!)")
		}
		if len(seedIPKey()) == 0 {
			log.Printf("[seed] WARN: SEED_IP_KEY unset: ip_hash is plain SHA256 (set a key for HMAC)")
		}
		ensureSuperuserFromEnv(e.App)
		return nil
	})

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		se.Router.BindFunc(fwPanelMiddleware) // фаервол: «/_/» закрыт при отключённой панели
		se.Router.BindFunc(seedSessionMiddleware)
		se.Router.POST("/api/seed/challenge", seedChallenge)
		se.Router.POST("/api/seed/login", seedLogin)
		se.Router.POST("/api/seed/renew", seedRenew)
		se.Router.POST("/api/seed/impersonate", seedImpersonate)
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
		// Административные эндпоинты мягкого удаления.
		se.Router.POST("/api/seed/hard-delete", seedHardDelete)
		se.Router.POST("/api/seed/restore", seedRestore)
		se.Router.GET("/api/seed/impact", seedImpact)
		se.Router.POST("/api/seed/erase", seedErase)
		se.Router.GET("/api/seed/deleted", seedDeleted)
		// Фаервол панели на журнале действий.
		se.Router.GET("/api/seed/firewall/status", seedFirewallStatus)
		se.Router.POST("/api/seed/firewall/unlock", seedFirewallUnlock)
		// Настройка защиты гейтвея (переопределения констант) — суперюзер.
		se.Router.GET("/api/seed/gateway-config", seedGatewayConfigGet)
		se.Router.POST("/api/seed/gateway-config", seedGatewayConfigSet)
		se.Router.DELETE("/api/seed/gateway-config", seedGatewayConfigDelete)
		startSeedGC(se.App) // фоновая очистка просроченных записей по таймеру
		return se.Next()
	})

	protectUsersFields(app)
	installAuditHooks(app)           // сквозной журнал действий записей (все роли)
	installCollectionAuditHooks(app) // журнал операций с коллекциями (правила из панели)
	installStockAuthAuditHooks(app)  // журнал штатных входов юзеров (пароль/ОТП/refresh)
	protectAuditCollection(app)      // журнал неизменяем через REST (все, включая суперюзера)
	installSuperuserSessions(app)    // настоящие сессии суперюзера (привязка журнала)
	installFirewallHooks(app)        // фаервол панели: неудачные входы суперюзера

	// Гибрид офсет → курсор: штатный /records дополнительно несёт
	// заголовок X-Next-Cursor для продолжения через /records/cursor.
	app.OnRecordsListRequest().BindFunc(recordsListCursorHint)

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
