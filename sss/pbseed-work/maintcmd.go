package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/spf13/cobra"
)

// maintcmd.go — консольные команды обслуживания: геобаза, диагностика
// схемы, база данных и чтение журнала действий.

// geoConsoleUpdate запускает обновление геобазы и печатает прогресс до
// завершения (консоль, в отличие от эндпоинта, ждёт результат).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - rawURL: string — необязательный адрес файла ("" = официальный выпуск).
//
// Возвращает: error — плохой адрес, занятость задачи или ошибка загрузки.
func geoConsoleUpdate(app core.App, rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL != "" {
		u, err := url.ParseRequestURI(rawURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("адрес должен быть http:// или https://")
		}
	}
	ok, used := geoMgr.startUpdate(app, rawURL)
	if !ok {
		return errors.New("обновление уже выполняется")
	}
	consoleAudit(app, "geo.update", map[string]any{"url": used})
	fmt.Printf("Обновление геобазы запущено: %s\n", used)
	for {
		time.Sleep(500 * time.Millisecond)
		geoMgr.mu.RLock()
		state, percent := geoMgr.state, geoMgr.percent
		jobErr := geoMgr.jobErr
		geoMgr.mu.RUnlock()
		switch state {
		case "downloading":
			fmt.Printf("\rСкачано: %d%%   ", percent)
		case "ready":
			fmt.Println("\rГеобаза готова.            ")
			geoPrintStatus(app)
			return nil
		case "error":
			return fmt.Errorf("обновление не удалось: %s", jobErr)
		}
	}
}

// geoPrintStatus печатает состояние геобазы и метаданные активной базы.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
func geoPrintStatus(app core.App) {
	_ = app
	geoMgr.mu.RLock()
	defer geoMgr.mu.RUnlock()
	fmt.Printf("Состояние: %s", geoMgr.state)
	if geoMgr.state == "downloading" {
		fmt.Printf(" (%d%%)", geoMgr.percent)
	}
	fmt.Println()
	if geoMgr.jobErr != "" {
		fmt.Printf("Последняя ошибка: %s\n", geoMgr.jobErr)
	}
	if m := geoMgr.meta; m != nil {
		fmt.Printf("База: %s, выпуск %s, скачана %s (%d байт, sha256 %s)\n",
			m.Source, m.Release, m.DownloadedAt, m.Bytes, m.SHA256)
	} else {
		fmt.Println("База не загружена.")
	}
}

// newGeoCommand собирает команду `geo` для консоли бинарника.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: *cobra.Command — готовая команда `geo`.
func newGeoCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:   "geo",
		Short: "GeoIP database: update, status and lookup",
	}

	updateCmd := &cobra.Command{
		Use:          "update [URL]",
		Short:        "Downloads and installs the GeoIP database (no URL = official release), prints progress",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return errors.New("нужен один адрес или ничего")
			}
			u := ""
			if len(args) == 1 {
				u = args[0]
			}
			return geoConsoleUpdate(app, u)
		},
	}

	statusCmd := &cobra.Command{
		Use:          "status",
		Short:        "Shows the GeoIP database state and metadata",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			geoPrintStatus(app)
			return nil
		},
	}

	lookupCmd := &cobra.Command{
		Use:          "lookup IP",
		Short:        "Resolves the country of an IP address by the loaded database",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: IP-адрес")
			}
			ip := strings.TrimSpace(args[0])
			if _, err := netip.ParseAddr(ip); err != nil {
				return errors.New("адрес не распознан")
			}
			country := geoCountry(ip)
			if country == "" {
				country = "(неизвестна)"
			}
			fmt.Printf("%s → %s\n", ip, country)
			return nil
		},
	}

	command.AddCommand(updateCmd, statusCmd, lookupCmd)
	return command
}

// newCollectionsCommand собирает команду `collections` — диагностика
// дрейфа схемы: реальный список коллекций с полями и правилами чтения.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: *cobra.Command — готовая команда `collections`.
func newCollectionsCommand(app core.App) *cobra.Command {
	listCmd := &cobra.Command{
		Use:          "list",
		Short:        "Lists collections with fields and list/view rules (schema drift check)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cols, err := app.FindAllCollections()
			if err != nil {
				return err
			}
			for _, c := range cols {
				names := make([]string, 0, len(c.Fields))
				for _, f := range c.Fields {
					names = append(names, f.GetName())
				}
				listRule, viewRule := "закрыто", "закрыто"
				if c.ListRule != nil {
					listRule = fmt.Sprintf("%q", *c.ListRule)
				}
				if c.ViewRule != nil {
					viewRule = fmt.Sprintf("%q", *c.ViewRule)
				}
				fmt.Printf("%s (%s)\n", c.Name, c.Type)
				fmt.Printf("  поля:  %s\n", strings.Join(names, ", "))
				fmt.Printf("  list:  %s\n  view:  %s\n", listRule, viewRule)
			}
			return nil
		},
	}
	command := &cobra.Command{
		Use:   "collections",
		Short: "Schema diagnostics",
	}
	command.AddCommand(listCmd)
	return command
}

// dbVacuumTo сжимает базу данных (полезно после массовых удалений).
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: error — ошибка выполнения.
func dbVacuumTo(app core.App) error {
	if _, err := app.NonconcurrentDB().NewQuery("VACUUM").Execute(); err != nil {
		return err
	}
	consoleAudit(app, "db.vacuum", nil)
	return nil
}

// dbBackupTo создаёт согласованную копию базы штатным механизмом
// SQLite «VACUUM INTO» (снимок под блокировкой записи, файл цел даже
// при работающем сервере).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - path: string — путь к файлу копии.
//
// Возвращает: error — ошибка пути или копирования.
func dbBackupTo(app core.App, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("укажите путь к файлу копии")
	}
	escaped := strings.ReplaceAll(path, "'", "''")
	if _, err := app.NonconcurrentDB().NewQuery("VACUUM INTO '" + escaped + "'").Execute(); err != nil {
		return err
	}
	consoleAudit(app, "db.backup", map[string]any{"path": path})
	return nil
}

// newDBCommand собирает команду `db` для консоли бинарника.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: *cobra.Command — готовая команда `db`.
func newDBCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:   "db",
		Short: "Database maintenance: vacuum and consistent backup",
	}

	vacuumCmd := &cobra.Command{
		Use:          "vacuum",
		Short:        "Reclaims space in the database file (VACUUM)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := dbVacuumTo(app); err != nil {
				return err
			}
			fmt.Println("База сжата (VACUUM).")
			return nil
		},
	}

	backupCmd := &cobra.Command{
		Use:          "backup PATH",
		Short:        "Creates a consistent copy of the database (SQLite VACUUM INTO)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: путь к файлу копии")
			}
			if err := dbBackupTo(app, args[0]); err != nil {
				return err
			}
			fmt.Printf("Согласованная копия записана: %s\n", args[0])
			return nil
		},
	}

	command.AddCommand(vacuumCmd, backupCmd)
	return command
}

// consoleAuditTail читает последние строки журнала действий с
// необязательными фильтрами по действию и пользователю-актёру.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - action: string — фильтр по действию ("" = все);
//   - userId: string — фильтр по актору ("" = все);
//   - limit: int — число строк.
//
// Возвращает: []*core.Record — строки журнала (свежие сверху);
// error — ошибка хранилища.
func consoleAuditTail(app core.App, action, userId string, limit int) ([]*core.Record, error) {
	filters := []string{"id != ''"}
	params := dbx.Params{}
	if action != "" {
		filters = append(filters, "action = {:action}")
		params["action"] = action
	}
	if userId != "" {
		filters = append(filters, "actor_id = {:actor}")
		params["actor"] = userId
	}
	return app.FindRecordsByFilter("seed_audit", strings.Join(filters, " && "),
		"-created_at", limit, 0, params)
}

// newAuditCommand собирает команду `audit` для консоли бинарника.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: *cobra.Command — готовая команда `audit`.
func newAuditCommand(app core.App) *cobra.Command {
	var tailFlags struct {
		action string
		user   string
		limit  int
	}
	tailCmd := &cobra.Command{
		Use:          "tail",
		Short:        "Shows the latest audit rows (filters: --action, --user)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tailFlags.limit <= 0 || tailFlags.limit > 500 {
				return errors.New("--limit должен быть от 1 до 500")
			}
			userId := ""
			if tailFlags.user != "" {
				pk, err := normPK(tailFlags.user)
				if err != nil {
					return err
				}
				u, err := findUserByPK(app, pk)
				if err != nil {
					return err
				}
				userId = u.Id
			}
			rows, err := consoleAuditTail(app, tailFlags.action, userId, tailFlags.limit)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Println("Строк журнала не найдено.")
				return nil
			}
			for _, r := range rows {
				actor := asStr(r.Get("actor_label"))
				if actor == "" {
					actor = asStr(r.Get("actor_kind"))
				}
				if actor == "" {
					actor = "—"
				}
				detail, _ := json.Marshal(fwDetail(r))
				fmt.Printf("%s  %-28s актёр=%s  детали=%s\n",
					asStr(r.Get("created_at")), asStr(r.Get("action")), actor, string(detail))
			}
			return nil
		},
	}
	tailCmd.Flags().StringVar(&tailFlags.action, "action", "", "фильтр по действию (например, user.ban)")
	tailCmd.Flags().StringVar(&tailFlags.user, "user", "", "фильтр по актору: открытый ключ пользователя")
	tailCmd.Flags().IntVar(&tailFlags.limit, "limit", 20, "число строк")

	command := &cobra.Command{
		Use:   "audit",
		Short: "Read the action journal from the console",
	}
	command.AddCommand(tailCmd)
	return command
}
