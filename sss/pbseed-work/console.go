package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/pocketbase/pocketbase/core"
	"github.com/spf13/cobra"
)

// console.go — общие механизмы консольных команд: подтверждение,
// «прогон без изменений» и поиск пользователя по открытому ключу.
//
// Граница доверия консоли — сам хост: кто запускает бинарник, тот
// суперюзер. Паролей и ролей внутри консоли нет; каждое действие
// помечается в журнале как выполненное консолью (поле «by»).

// consoleFlags — флаги, общие для разрушительных команд.
type consoleFlags struct {
	yes    bool // выполнить без подтверждения
	dryRun bool // показать действие, ничего не менять
}

// addConsoleFlags подключает к команде флаги -y/--yes и --dry-run.
//
// Параметры:
//   - cmd: *cobra.Command — команда;
//   - f: *consoleFlags — структура для значений флагов.
func addConsoleFlags(cmd *cobra.Command, f *consoleFlags) {
	cmd.Flags().BoolVarP(&f.yes, "yes", "y", false, "выполнить без подтверждения")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "показать, что было бы сделано, и ничего не менять")
}

// consoleProceed решает, выполнять ли действие: в режиме --dry-run
// печатает его и отказывается; без -y спрашивает подтверждение на
// стандартном вводе (закрытый ввод трактуется как отказ).
//
// Параметры:
//   - f: *consoleFlags — флаги команды;
//   - summary: string — человекочитаемое описание действия.
//
// Возвращает: bool — выполнять ли действие; error — ошибка ввода.
func consoleProceed(f *consoleFlags, summary string) (bool, error) {
	if f.dryRun {
		fmt.Printf("[dry-run] %s\n", summary)
		return false, nil
	}
	if f.yes {
		return true, nil
	}
	fmt.Printf("%s. Выполнить? [y/N] ", summary)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if line == "" && err != nil {
		return false, nil // ввод закрыт — считаем отказом
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes" || answer == "д" || answer == "да", nil
}

// validatePK проверяет формат открытого ключа.
//
// Параметры:
//   - pk: string — кандидат в открытые ключи.
//
// Возвращает: error — если это не 64 шестнадцатеричных символа.
func validatePK(pk string) error {
	if !rxHex64.MatchString(pk) {
		return errors.New("открытый ключ — это 64 шестнадцатеричных символа")
	}
	return nil
}

// normPK приводит открытый ключ к каноническому виду (нижний регистр,
// без пробелов) и проверяет формат.
//
// Параметры:
//   - raw: string — ключ в произвольном регистре.
//
// Возвращает: string — канонический ключ; error — ошибка формата.
func normPK(raw string) (string, error) {
	pk := strings.ToLower(strings.TrimSpace(raw))
	if err := validatePK(pk); err != nil {
		return "", err
	}
	return pk, nil
}

// findUserByPK находит пользователя по открытому ключу
// (почта записи — ключ@seed.local).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - pk: string — открытый ключ (канонический вид).
//
// Возвращает: *core.Record — запись пользователя;
// error — если записи нет.
func findUserByPK(app core.App, pk string) (*core.Record, error) {
	user, err := app.FindFirstRecordByData("users", "email", pk+"@seed.local")
	if err != nil || user == nil {
		return nil, fmt.Errorf("пользователь с ключом %s не найден", pk)
	}
	return user, nil
}

// pkOfEmail извлекает открытый ключ из почты (часть до @).
//
// Параметры:
//   - email: string — почта вида «ключ@домен».
//
// Возвращает: string — открытый ключ (или почту целиком, если @ нет).
func pkOfEmail(email string) string {
	if i := strings.Index(email, "@"); i > 0 {
		return email[:i]
	}
	return email
}

// consoleAudit пишет строку журнала о действии консоли (актёр — сама
// консоль, источник дополнительно помечается в деталях).
//
// Параметры:
//   - app: core.App — приложение PocketBase;
//   - action: string — имя действия («user.ban», «policy.set», …);
//   - detail: map[string]any — детали действия (дополняются «by»).
func consoleAudit(app core.App, action string, detail map[string]any) {
	auditWriteConsole(app, action, detail)
}
