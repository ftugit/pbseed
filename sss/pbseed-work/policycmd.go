package main

import (
	"errors"
	"fmt"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/spf13/cobra"
)

// policycmd.go — консольное управление политиками (таблица
// `seed_settings`): глобальные и персональные строки, замки.
// Консоль не ограничена замками — границу доверия задаёт сам хост.

// policyEffective сообщает действующее значение политики и источник:
// персональная строка → глобальная строка → ложь по умолчанию.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - key: string — ключ политики;
//   - userId: string — id пользователя ("" = глобальный взгляд).
//
// Возвращает: bool — действующее значение;
// string — источник («персональная», «глобальная» или «по умолчанию»).
func policyEffective(app core.App, key, userId string) (bool, string) {
	if userId != "" {
		if r := findSetting(app, key, userId); r != nil {
			return asBool(r.Get("value")), "персональная"
		}
	}
	if r := findSetting(app, key, ""); r != nil {
		return asBool(r.Get("value")), "глобальная"
	}
	return false, "по умолчанию"
}

// policySetRow записывает строку политики (глобальную или персональную):
// существующая строка обновляется, отсутствующая создаётся. Замок
// ставится только на глобальную строку.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - key: string — ключ политики;
//   - userId: string — id пользователя ("" = глобальная строка);
//   - value: bool — значение;
//   - lock: bool — поставить замок (только для глобальной).
//
// Возвращает: error — ошибка аргументов или хранилища.
func policySetRow(app core.App, key, userId string, value, lock bool) error {
	if lock && userId != "" {
		return errors.New("замок ставится только на глобальную строку")
	}
	row := findSetting(app, key, userId)
	if row == nil {
		col, err := app.FindCollectionByNameOrId("seed_settings")
		if err != nil {
			return err
		}
		row = core.NewRecord(col)
		row.Set("key", key)
		if userId != "" {
			row.Set("user", userId)
		}
	}
	row.Set("value", value)
	if userId == "" {
		row.Set("locked", lock)
	}
	if err := app.Save(row); err != nil {
		return err
	}
	consoleAudit(app, "policy.set", map[string]any{
		"key": key, "value": value, "user_id": userId, "locked": lock,
	})
	return nil
}

// policyDeleteRow удаляет строку политики (откат к вышестоящему
// значению). Отсутствие строки не считается ошибкой.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - key: string — ключ политики;
//   - userId: string — id пользователя ("" = глобальная строка).
//
// Возвращает: bool — была ли строка; error — ошибка хранилища.
func policyDeleteRow(app core.App, key, userId string) (bool, error) {
	row := findSetting(app, key, userId)
	if row == nil {
		return false, nil
	}
	if err := app.Delete(row); err != nil {
		return false, err
	}
	consoleAudit(app, "policy.delete", map[string]any{"key": key, "user_id": userId})
	return true, nil
}

// settingsListRows читает строки настроек: все или только
// персональные строки одного пользователя.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - userId: string — id пользователя ("" = все строки).
//
// Возвращает: []*core.Record — строки; error — ошибка хранилища.
func settingsListRows(app core.App, userId string) ([]*core.Record, error) {
	q := SafeQuery(app, true, "seed_settings")
	if userId != "" {
		q = q.Where("user = {:uid}", dbx.Params{"uid": userId})
	}
	return q.Sort("key").Find()
}

// newPolicyCommand собирает команду `policy` для консоли бинарника.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: *cobra.Command — готовая команда `policy`.
func newPolicyCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:   "policy",
		Short: "Manage policy rows (seed_settings): get/set/delete, global or per-user",
	}

	var getFlags struct{ user string }
	getCmd := &cobra.Command{
		Use:          "get KEY",
		Short:        "Shows the effective policy value and its source",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: ключ политики")
			}
			userId := ""
			if getFlags.user != "" {
				pk, err := normPK(getFlags.user)
				if err != nil {
					return err
				}
				u, err := findUserByPK(app, pk)
				if err != nil {
					return err
				}
				userId = u.Id
			}
			value, source := policyEffective(app, args[0], userId)
			fmt.Printf("Политика %q: %v (источник: %s)\n", args[0], value, source)
			return nil
		},
	}
	getCmd.Flags().StringVar(&getFlags.user, "user", "", "открытый ключ пользователя (иначе глобальный взгляд)")

	var setFlags struct {
		user  string
		value string
		lock  bool
	}
	setCmd := &cobra.Command{
		Use:          "set KEY",
		Short:        "Writes a global (--lock available) or per-user (--user) policy row",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: ключ политики")
			}
			var value bool
			switch setFlags.value {
			case "true":
				value = true
			case "false":
				value = false
			default:
				return errors.New("--value принимает только true или false")
			}
			userId := ""
			if setFlags.user != "" {
				pk, err := normPK(setFlags.user)
				if err != nil {
					return err
				}
				u, err := findUserByPK(app, pk)
				if err != nil {
					return err
				}
				userId = u.Id
			}
			if err := policySetRow(app, args[0], userId, value, setFlags.lock); err != nil {
				return err
			}
			scope := "глобальная"
			if userId != "" {
				scope = "персональная (" + setFlags.user + ")"
			}
			fmt.Printf("Политика %q = %v записана (%s).\n", args[0], value, scope)
			return nil
		},
	}
	setCmd.Flags().StringVar(&setFlags.user, "user", "", "открытый ключ пользователя (персональная строка)")
	setCmd.Flags().StringVar(&setFlags.value, "value", "", "значение: true или false")
	setCmd.Flags().BoolVar(&setFlags.lock, "lock", false, "замок на глобальную строку (запрет персональных переопределений)")

	var delFlags struct{ user string }
	delCmd := &cobra.Command{
		Use:          "delete KEY",
		Short:        "Deletes a policy row (rollback to the upper-level value)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: ключ политики")
			}
			userId := ""
			if delFlags.user != "" {
				pk, err := normPK(delFlags.user)
				if err != nil {
					return err
				}
				u, err := findUserByPK(app, pk)
				if err != nil {
					return err
				}
				userId = u.Id
			}
			existed, err := policyDeleteRow(app, args[0], userId)
			if err != nil {
				return err
			}
			if !existed {
				fmt.Println("Строка не найдена — удалять нечего.")
				return nil
			}
			fmt.Printf("Строка политики %q удалена.\n", args[0])
			return nil
		},
	}
	delCmd.Flags().StringVar(&delFlags.user, "user", "", "открытый ключ пользователя (персональная строка)")

	command.AddCommand(getCmd, setCmd, delCmd)
	return command
}

// newSettingsCommand собирает команду `settings` (просмотр строк
// настроек) для консоли бинарника.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: *cobra.Command — готовая команда `settings`.
func newSettingsCommand(app core.App) *cobra.Command {
	var listFlags struct{ user string }
	listCmd := &cobra.Command{
		Use:          "list",
		Short:        "Lists policy rows (all, or per-user with --user)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			userId := ""
			if listFlags.user != "" {
				pk, err := normPK(listFlags.user)
				if err != nil {
					return err
				}
				u, err := findUserByPK(app, pk)
				if err != nil {
					return err
				}
				userId = u.Id
			}
			rows, err := settingsListRows(app, userId)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Println("Строк настроек нет.")
				return nil
			}
			for _, r := range rows {
				scope := "глобальная"
				if asStr(r.Get("user")) != "" {
					scope = "личная (пользователь " + asStr(r.Get("user")) + ")"
				}
				lock := ""
				if asBool(r.Get("locked")) {
					lock = "  [ЗАМОК]"
				}
				fmt.Printf("%s = %v  %s%s\n", asStr(r.Get("key")), asBool(r.Get("value")), scope, lock)
			}
			return nil
		},
	}
	listCmd.Flags().StringVar(&listFlags.user, "user", "", "открытый ключ пользователя (только его строки)")

	command := &cobra.Command{
		Use:   "settings",
		Short: "Inspect settings rows (seed_settings)",
	}
	command.AddCommand(listCmd)
	return command
}
