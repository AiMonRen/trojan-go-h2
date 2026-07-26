package actions

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/voidluo/trojan-go/cmd/trojan/menu"
)

// getStdin 获取用户输入
func getStdin(promptCN, promptEN string) string {
	prompt := promptCN
	if menu.CurrentLang == menu.EN {
		prompt = promptEN
	}
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	s, _ := reader.ReadString('\n')
	return strings.TrimSpace(s)
}
