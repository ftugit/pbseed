package main

import (
	"errors"
	"fmt"

	"github.com/pocketbase/pocketbase/core"
	"github.com/spf13/cobra"
)

// gatewaycmd.go — офлайн-управление параметрами гейтвея (таблица
// `seed_gateway`): те же операции, что эндпоинт
// /api/seed/gateway-config, но без HTTP и токенов. Запись равная
// стандарту отклоняется — база хранит только отличия.

// gatewaySetParam записывает переопределение параметра и помечает
// действие в журнале.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - key: string — имя параметра;
//   - value: string — новое значение (нормализуется).
//
// Возвращает: string — записанное каноническое значение;
// error — неизвестный ключ, плохое значение, совпадение со стандартом
// или ошибка хранилища.
func gatewaySetParam(app core.App, key, value string) (string, error) {
	written, err := settingsSet(app, key, value)
	if err != nil {
		return "", err
	}
	consoleAudit(app, "gateway.set", map[string]any{"key": key, "value": written})
	// Предохранитель «автонастройка» действует и на консольном пути
	// записи (см. autotuneRegPerDay): консоль минует и REST-хуки, и
	// эндпоинт, поэтому вызывается здесь тем же телом.
	autotuneRegPerDay(app)
	return written, nil
}

// gatewayResetParam удаляет переопределение параметра (возврат к
// окружению/константе) и помечает действие в журнале.
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - key: string — имя параметра.
//
// Возвращает: bool — существовало ли переопределение;
// error — неизвестный ключ или ошибка хранилища.
func gatewayResetParam(app core.App, key string) (bool, error) {
	deleted, err := settingsDelete(app, key)
	if err != nil {
		return false, err
	}
	if deleted {
		consoleAudit(app, "gateway.reset", map[string]any{"key": key})
	}
	return deleted, nil
}

// newGatewayCommand собирает команду `gateway` для консоли бинарника.
//
// Параметры:
//   - app: core.App — приложение PocketBase.
//
// Возвращает: *cobra.Command — готовая команда `gateway`.
func newGatewayCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:   "gateway",
		Short: "Manage gateway parameters (seed_gateway overrides)",
	}

	listCmd := &cobra.Command{
		Use:          "list",
		Short:        "Shows every gateway parameter: effective value, source and standard",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, p := range gwParams {
				value, source := gwResolve(app, p)
				fmt.Printf("%-14s %-4s = %-6s  источник: %s  стандарт: %s  окружение: %s\n",
					p.Key, p.Kind, value, source, p.Def, p.Env)
			}
			return nil
		},
	}

	var setFlags struct{ value string }
	setCmd := &cobra.Command{
		Use:          "set PARAM",
		Short:        "Overrides a gateway parameter in the database (value must differ from the standard)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: имя параметра")
			}
			if setFlags.value == "" {
				return errors.New("укажите --value")
			}
			written, err := gatewaySetParam(app, args[0], setFlags.value)
			if err != nil {
				return err
			}
			fmt.Printf("Параметр %q = %s записан в базу.\n", args[0], written)
			return nil
		},
	}
	setCmd.Flags().StringVar(&setFlags.value, "value", "", "новое значение параметра")

	resetCmd := &cobra.Command{
		Use:          "reset PARAM",
		Short:        "Removes the database override (parameter falls back to env/standard)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("нужен один аргумент: имя параметра")
			}
			deleted, err := gatewayResetParam(app, args[0])
			if err != nil {
				return err
			}
			if !deleted {
				fmt.Printf("Переопределения %q в базе не было.\n", args[0])
				return nil
			}
			fmt.Printf("Переопределение %q удалено (параметр вернулся к окружению/стандарту).\n", args[0])
			return nil
		},
	}

	command.AddCommand(listCmd, setCmd, resetCmd)
	return command
}
