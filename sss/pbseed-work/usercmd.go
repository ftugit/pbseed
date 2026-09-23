package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/spf13/cobra"
)

// usercmd.go — консольное управление пользователями сайта.
//
// Консоль — офлайн-обёртка над уже существующей логикой: бан читается
// теми же функциями, что и при входе, стирание — тот же EraseUser,
// отзыв сессий — тот же запрос, что в /api/seed/logout-all. Второй
// реализации механик здесь нет.

// setUserRole устанавливает роль пользователю по его открытому ключу.
// Если владелец ключа ещё не регистрировался, запись создаётся заранее —
// при первом входе этим ключом человек сразу получит назначенную роль.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - pk: string — открытый ключ (64 шестнадцатеричных символа);
//   - role: string — новая роль (user, moderator или admin).
//
// Возвращает: error — ошибка хранилища или сохранения.
func setUserRole(app core.App, pk, role string) error {
	email := pk + "@seed.local"
	user, err := app.FindFirstRecordByData("users", "email", email)
	if err != nil || user == nil {
		// Ключ ещё не заходил — готовим запись до его первого входа.
		ucol, err2 := app.FindCollectionByNameOrId("users")
		if err2 != nil {
			return err2
		}
		user = core.NewRecord(ucol)
		user.Set("email", email)
		user.Set("password", security.RandomString(48))
		user.Set("emailVisibility", false)
	}
	user.Set("role", role)
	return app.Save(user)
}

// userSetBan банит пользователя: пустой срок означает бессрочный бан,
// заданный обязан быть датой в будущем (формат RFC3339). Бан начинает
// действовать немедленно — проверки входа и живых сессий читают эти же
// поля.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - pk: string — открытый ключ;
//   - reason: string — причина (может быть пустой);
//   - until: string — срок действия ("" = бессрочно).
//
// Возвращает: error — ошибка формата, поиска или хранилища.
func userSetBan(app core.App, pk, reason, until string) error {
	if until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err != nil {
			return fmt.Errorf("срок бана — дата в формате RFC3339: %w", err)
		}
		if !t.After(time.Now()) {
			return errors.New("срок бана должен быть в будущем")
		}
	}
	user, err := findUserByPK(app, pk)
	if err != nil {
		return err
	}
	user.Set("banned", true)
	user.Set("ban_reason", reason)
	user.Set("banned_until", until)
	if err := app.Save(user); err != nil {
		return err
	}
	consoleAudit(app, "user.ban", map[string]any{
		"public_key": pk, "reason": reason, "until": until,
	})
	return nil
}

// userClearBan снимает бан и стирает его причину и срок.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - pk: string — открытый ключ.
//
// Возвращает: error — ошибка поиска или хранилища.
func userClearBan(app core.App, pk string) error {
	user, err := findUserByPK(app, pk)
	if err != nil {
		return err
	}
	user.Set("banned", false)
	user.Set("ban_reason", "")
	user.Set("banned_until", "")
	if err := app.Save(user); err != nil {
		return err
	}
	consoleAudit(app, "user.unban", map[string]any{"public_key": pk})
	return nil
}

// userSoftDelete помечает пользователя удалённым (поле deleted_at) —
// запись остаётся в базе и может быть восстановлена штатным механизмом.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - pk: string — открытый ключ.
//
// Возвращает: error — ошибка поиска или хранилища.
func userSoftDelete(app core.App, pk string) error {
	user, err := findUserByPK(app, pk)
	if err != nil {
		return err
	}
	user.Set("deleted_at", nowISO())
	if err := app.Save(user); err != nil {
		return err
	}
	consoleAudit(app, "user.delete", map[string]any{"public_key": pk, "mode": "soft"})
	return nil
}

// userHardDelete физически удаляет запись пользователя вместе с его
// сессиями и настройками (одна транзакция, чтобы запись не оставила
// висячих связей). В отличие от EraseUser строка не анонимизируется,
// а исчезает целиком.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - pk: string — открытый ключ.
//
// Возвращает: error — ошибка поиска или транзакции.
func userHardDelete(app core.App, pk string) error {
	user, err := findUserByPK(app, pk)
	if err != nil {
		return err
	}
	err = app.RunInTransaction(func(txApp core.App) error {
		if _, err := txApp.NonconcurrentDB().NewQuery(
			"DELETE FROM seed_sessions WHERE user = {:uid}",
		).Bind(dbx.Params{"uid": user.Id}).Execute(); err != nil {
			return err
		}
		if _, err := txApp.NonconcurrentDB().NewQuery(
			"DELETE FROM seed_settings WHERE user = {:uid}",
		).Bind(dbx.Params{"uid": user.Id}).Execute(); err != nil {
			return err
		}
		// Коллекция `users` вне реестра мягкого удаления — удаление
		// физическое само по себе.
		return txApp.Delete(user)
	})
	if err != nil {
		return err
	}
	consoleAudit(app, "user.delete", map[string]any{"public_key": pk, "mode": "hard"})
	return nil
}

// userKillSessions отзывает сессии пользователя: одну по идентификатору
// (grant) или все живые одним запросом. Отозванные сессии не удаляются —
// они перестают приниматься продлением и проверкой куки.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - pk: string — открытый ключ;
//   - grant: string — идентификатор сессии (пусто при all);
//   - all: bool — отозвать все живые сессии.
//
// Возвращает: int — число отозванных сессий; error — ошибка поиска,
// аргументов или хранилища.
func userKillSessions(app core.App, pk, grant string, all bool) (int, error) {
	user, err := findUserByPK(app, pk)
	if err != nil {
		return 0, err
	}
	revoked := 0
	if all {
		// Один UPDATE вместо N сохранений — как в /api/seed/logout-all.
		result, err := app.NonconcurrentDB().NewQuery(
			"UPDATE seed_sessions SET revoked = 1, updated_at = {:now} WHERE user = {:uid} AND revoked = 0 AND (deleted_at IS NULL OR deleted_at = '')",
		).Bind(dbx.Params{"uid": user.Id, "now": nowISO()}).Execute()
		if err != nil {
			return 0, err
		}
		n, _ := result.RowsAffected()
		revoked = int(n)
	} else {
		sess, err := app.FindFirstRecordByData("seed_sessions", "grant_id", grant)
		if err != nil || sess == nil || asStr(sess.Get("user")) != user.Id {
			return 0, fmt.Errorf("сессия %q у этого пользователя не найдена", grant)
		}
		sess.Set("revoked", true)
		if err := app.Save(sess); err != nil {
			return 0, err
		}
		revoked = 1
	}
	consoleAudit(app, "session.kill", map[string]any{
		"public_key": pk, "grant": grant, "revoked": revoked,
	})
	return revoked, nil
}

// userList печатает список пользователей: ключ, роль, состояние бана и
// дату создания. Мягко удалённые не показываются.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - role: string — фильтр по роли ("" = все);
//   - bannedOnly: bool — только с флагом бана;
//   - limit: int — максимум строк.
//
// Возвращает: error — ошибка хранилища.
func userList(app core.App, role string, bannedOnly bool, limit int) error {
	q := SafeQuery(app, true, "users")
	if role != "" {
		q = q.Where("role = {:role}", dbx.Params{"role": role})
	}
	if bannedOnly {
		q = q.Where("banned = true")
	}
	recs, err := q.Sort("-created").Limit(limit).Find()
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Println("Пользователи не найдены.")
		return nil
	}
	for _, r := range recs {
		ban := "—"
		if userBanned(r) {
			if u := asStr(r.Get("banned_until")); u != "" {
				ban = "до " + u
			} else {
				ban = "бессрочно"
			}
			if reason := asStr(r.Get("ban_reason")); reason != "" {
				ban += " (" + reason + ")"
			}
		}
		fmt.Printf("%s  роль=%s  бан=%s  создан=%s\n",
			pkOfEmail(asStr(r.Get("email"))), asStr(r.Get("role")), ban, asStr(r.Get("created")))
	}
	fmt.Printf("Всего: %d (показано не более %d)\n", len(recs), limit)
	return nil
}

// userShow печатает запись пользователя целиком: роль, бан-поля,
// пометку удаления и число живых сессий.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - pk: string — открытый ключ.
//
// Возвращает: error — ошибка поиска или хранилища.
func userShow(app core.App, pk string) error {
	user, err := findUserByPK(app, pk)
	if err != nil {
		return err
	}
	sessions, err := SafeQuery(app, true, "seed_sessions").
		Where("user = {:uid}", dbx.Params{"uid": user.Id}).Count()
	if err != nil {
		return err
	}
	ban := "нет"
	if asBool(user.Get("banned")) {
		ban = "да"
		if u := asStr(user.Get("banned_until")); u != "" {
			ban += " до " + u
		} else {
			ban += " (бессрочно)"
		}
		if r := asStr(user.Get("ban_reason")); r != "" {
			ban += ", причина: " + r
		}
	}
	deleted := asStr(user.Get("deleted_at"))
	if deleted == "" {
		deleted = "—"
	}
	fmt.Printf("Ключ:       %s\n", pk)
	fmt.Printf("Роль:       %s\n", asStr(user.Get("role")))
	fmt.Printf("Бан:        %s\n", ban)
	fmt.Printf("Удалён:     %s\n", deleted)
	fmt.Printf("Сессий:     %d\n", sessions)
	fmt.Printf("Создан:     %s\n", asStr(user.Get("created")))
	fmt.Printf("Обновлён:   %s\n", asStr(user.Get("updated")))
	return nil
}

// userSessions печатает живые сессии пользователя (не более 50 —
// предел числа живых сессий действует и на сервере).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - pk: string — открытый ключ.
//
// Возвращает: error — ошибка поиска или хранилища.
func userSessions(app core.App, pk string) error {
	user, err := findUserByPK(app, pk)
	if err != nil {
		return err
	}
	recs, err := SafeQuery(app, true, "seed_sessions").
		Where("user = {:uid}", dbx.Params{"uid": user.Id}).
		Sort("-created_at").Limit(50).Find()
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Println("Сессий нет.")
		return nil
	}
	for _, s := range recs {
		addr := asStr(s.Get("ip_masked"))
		if addr == "" {
			addr = asStr(s.Get("ip_hash"))
			if len(addr) > 12 {
				addr = addr[:12] + "…"
			}
		}
		country := asStr(s.Get("ip_country"))
		if country == "" {
			country = "—"
		}
		revoked := ""
		if asBool(s.Get("revoked")) {
			revoked = "  [ОТОЗВАНА]"
		}
		fmt.Printf("%s  grant=%s  устройство=%q  адрес=%s  страна=%s  виден=%s%s\n",
			asStr(s.Get("created_at")), asStr(s.Get("grant_id")),
			asStr(s.Get("device_name")), addr, country,
			asStr(s.Get("last_seen")), revoked)
	}
	return nil
}

// newUserCommand собирает команду `user` для консоли бинарника.
//
// Параметры:
//   - app: core.App — приложение PocketBase (уже загружено каркасом).
//
// Возвращает: *cobra.Command — готовая команда `user`.
func newUserCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:   "user",
		Short: "Manage site users (roles, bans, sessions, erasure)",
	}

	roleCmd := &cobra.Command{
		Use:          "role PUBLIC_KEY ROLE",
		Example:      "user role f4a9c2...1e admin",
		Short:        "Sets the role (user|moderator|admin) of a site user by their public key",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return errors.New("нужны два аргумента: открытый ключ и роль (user|moderator|admin)")
			}
			pk := strings.ToLower(strings.TrimSpace(args[0]))
			if !rxHex64.MatchString(pk) {
				return errors.New("открытый ключ — это 64 шестнадцатеричных символа")
			}
			role := strings.ToLower(strings.TrimSpace(args[1]))
			if role != seedRoleUser && role != seedRoleModerator && role != seedRoleAdmin {
				return fmt.Errorf("неизвестная роль %q (ожидается user, moderator или admin)", args[1])
			}
			if err := setUserRole(app, pk, role); err != nil {
				return fmt.Errorf("не удалось сохранить роль: %w", err)
			}
			fmt.Printf("Роль %q установлена пользователю %s@seed.local\n", role, pk)
			return nil
		},
	}

	var listFlags struct {
		role   string
		banned bool
		limit  int
	}
	listCmd := &cobra.Command{
		Use:          "list",
		Short:        "Lists site users (key, role, ban, created)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if listFlags.limit <= 0 || listFlags.limit > 500 {
				return errors.New("--limit должен быть от 1 до 500")
			}
			return userList(app, listFlags.role, listFlags.banned, listFlags.limit)
		},
	}
	listCmd.Flags().StringVar(&listFlags.role, "role", "", "фильтр по роли (user|moderator|admin)")
	listCmd.Flags().BoolVar(&listFlags.banned, "banned", false, "только забаненные (по флагу)")
	listCmd.Flags().IntVar(&listFlags.limit, "limit", 100, "максимум строк")

	showCmd := &cobra.Command{
		Use:          "show PUBLIC_KEY",
		Short:        "Shows the full record of a site user",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: открытый ключ")
			}
			pk, err := normPK(args[0])
			if err != nil {
				return err
			}
			return userShow(app, pk)
		},
	}

	var banFlags struct {
		reason string
		until  string
	}
	banCmd := &cobra.Command{
		Use:          "ban PUBLIC_KEY",
		Short:        "Bans a site user (--until in RFC3339, empty = permanent)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: открытый ключ")
			}
			pk, err := normPK(args[0])
			if err != nil {
				return err
			}
			if err := userSetBan(app, pk, banFlags.reason, banFlags.until); err != nil {
				return err
			}
			if banFlags.until == "" {
				fmt.Printf("Пользователь %s забанен бессрочно.\n", pk)
			} else {
				fmt.Printf("Пользователь %s забанен до %s.\n", pk, banFlags.until)
			}
			return nil
		},
	}
	banCmd.Flags().StringVar(&banFlags.reason, "reason", "", "причина бана")
	banCmd.Flags().StringVar(&banFlags.until, "until", "", "срок бана в формате RFC3339 (пусто = бессрочно)")

	unbanCmd := &cobra.Command{
		Use:          "unban PUBLIC_KEY",
		Short:        "Removes the ban (and its reason/deadline) from a site user",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: открытый ключ")
			}
			pk, err := normPK(args[0])
			if err != nil {
				return err
			}
			if err := userClearBan(app, pk); err != nil {
				return err
			}
			fmt.Printf("Бан снят с пользователя %s.\n", pk)
			return nil
		},
	}

	var delFlags struct {
		consoleFlags
		hard bool
	}
	deleteCmd := &cobra.Command{
		Use:          "delete PUBLIC_KEY",
		Short:        "Deletes a site user (soft by default, --hard = physically)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: открытый ключ")
			}
			pk, err := normPK(args[0])
			if err != nil {
				return err
			}
			mode := "мягкое удаление (запись останется и может быть восстановлена)"
			if delFlags.hard {
				mode = "ФИЗИЧЕСКОЕ удаление записи без восстановления"
			}
			ok, err := consoleProceed(&delFlags.consoleFlags, fmt.Sprintf("Пользователь %s: %s", pk, mode))
			if err != nil || !ok {
				return err
			}
			if delFlags.hard {
				err = userHardDelete(app, pk)
			} else {
				err = userSoftDelete(app, pk)
			}
			if err != nil {
				return err
			}
			fmt.Printf("Готово: пользователь %s удалён (%s).\n", pk, mode)
			return nil
		},
	}
	deleteCmd.Flags().BoolVar(&delFlags.hard, "hard", false, "физическое удаление (вместо мягкого)")
	addConsoleFlags(deleteCmd, &delFlags.consoleFlags)

	sessionsCmd := &cobra.Command{
		Use:          "sessions PUBLIC_KEY",
		Short:        "Lists the live sessions of a site user",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: открытый ключ")
			}
			pk, err := normPK(args[0])
			if err != nil {
				return err
			}
			return userSessions(app, pk)
		},
	}

	var killFlags struct {
		consoleFlags
		all   bool
		grant string
	}
	killCmd := &cobra.Command{
		Use:          "kill PUBLIC_KEY",
		Short:        "Revokes sessions of a site user (--all or --grant ID)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: открытый ключ")
			}
			if killFlags.all == (killFlags.grant != "") {
				return errors.New("укажите ровно одно: --all или --grant ИДЕНТИФИКАТОР")
			}
			pk, err := normPK(args[0])
			if err != nil {
				return err
			}
			what := "все живые сессии"
			if !killFlags.all {
				what = "сессия " + killFlags.grant
			}
			ok, err := consoleProceed(&killFlags.consoleFlags, fmt.Sprintf("Отозвать %s пользователя %s", what, pk))
			if err != nil || !ok {
				return err
			}
			n, err := userKillSessions(app, pk, killFlags.grant, killFlags.all)
			if err != nil {
				return err
			}
			fmt.Printf("Отозвано сессий: %d.\n", n)
			return nil
		},
	}
	killCmd.Flags().BoolVar(&killFlags.all, "all", false, "отозвать все живые сессии")
	killCmd.Flags().StringVar(&killFlags.grant, "grant", "", "идентификатор одной сессии")
	addConsoleFlags(killCmd, &killFlags.consoleFlags)

	var eraseFlags consoleFlags
	eraseCmd := &cobra.Command{
		Use:          "erase PUBLIC_KEY",
		Short:        "GDPR erasure: anonymizes the user and wipes their sessions and settings",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: открытый ключ")
			}
			pk, err := normPK(args[0])
			if err != nil {
				return err
			}
			user, err := findUserByPK(app, pk)
			if err != nil {
				return err
			}
			ok, err := consoleProceed(&eraseFlags,
				fmt.Sprintf("GDPR-стирание пользователя %s (анонимизация записи, удаление сессий и настроек, без восстановления)", pk))
			if err != nil || !ok {
				return err
			}
			if err := EraseUser(app, user.Id); err != nil {
				return err
			}
			consoleAudit(app, "user.erase", map[string]any{"public_key": pk})
			fmt.Printf("Стирание завершено: %s.\n", pk)
			return nil
		},
	}
	addConsoleFlags(eraseCmd, &eraseFlags)

	command.AddCommand(roleCmd, listCmd, showCmd, banCmd, unbanCmd, deleteCmd, sessionsCmd, killCmd, eraseCmd)
	return command
}
