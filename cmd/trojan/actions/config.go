package actions

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/voidluo/trojan-go/internal/secretfile"
)

// ShowConfig 展示当前配置文件内容
func ShowConfig() {
	paths := []string{"config.yaml", "config.yml", "config.json", "/etc/trojan-go/config.yaml", "/etc/trojan-go/config.json"}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			fmt.Printf("[ 当前配置文件: %s ]\n\n", p)
			fmt.Println(string(data))
			return
		}
	}
	fmt.Println("\033[33m未找到配置文件，请在运行目录或 /etc/trojan-go/ 中放置 config.yaml 或 config.json。\033[0m")
}

// ToggleWebSocket 开关配置中的 WebSocket 传输选项
func ToggleWebSocket() {
	paths := []string{"config.yaml", "config.yml", "/etc/trojan-go/config.yaml"}
	var targetPath string
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			targetPath = p
			break
		}
	}
	if targetPath == "" {
		fmt.Println("\033[31m未找到活动的 YAML 配置文件，无法修改 WebSocket 状态。\033[0m")
		return
	}

	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("\033[31m解析配置文件失败: %v\033[0m\n", err)
		return
	}

	wsVal, ok := cfg["websocket"]
	if !ok {
		wsVal = make(map[string]any)
		cfg["websocket"] = wsVal
	}

	var ws map[string]any
	if wsMap, ok := wsVal.(map[string]any); ok {
		ws = wsMap
	} else if wsAny, ok2 := wsVal.(map[any]any); ok2 {
		ws = make(map[string]any)
		for k, v := range wsAny {
			if ks, ok3 := k.(string); ok3 {
				ws[ks] = v
			}
		}
		cfg["websocket"] = ws
	} else {
		fmt.Println("\033[31m配置文件中的 websocket 节点格式不正确。\033[0m")
		return
	}

	enabled, _ := ws["enabled"].(bool)
	nextState := !enabled

	newContent, err := modifyYamlField(string(data), "websocket", "enabled", nextState)
	if err != nil {
		fmt.Printf("\033[31m生成配置文件失败: %v\033[0m\n", err)
		return
	}

	// S-03: config.yaml holds proxy passwords and API keys. Writing it with a
	// hardcoded 0644 was a one-way permission downgrade from the 0600 the
	// installer sets, making it world-readable on the host. WriteAtomic
	// preserves the existing mode (defaulting to 0600) and swaps the file in
	// with a rename so a crash cannot leave a truncated config behind.
	if err := secretfile.WriteAtomic(targetPath, []byte(newContent)); err != nil {
		fmt.Printf("\033[31m写入配置文件失败: %v\033[0m\n", err)
		return
	}

	stateStr := "已禁用 (Disabled)"
	if nextState {
		stateStr = "已启用 (Enabled)"
	}
	fmt.Printf("\033[32m✓ WebSocket 伪装已成功切换为: %s\033[0m\n", stateStr)

	// 提示是否重启服务
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("是否立刻重启 trojan-go 服务以应用配置？(y/n, 默认 n): ")
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(ans)
	if ans == "y" || ans == "Y" {
		fmt.Println("正在重启 trojan-go 服务...")
		cmd := exec.Command("systemctl", "restart", "trojan-go")
		if err := cmd.Run(); err != nil {
			fmt.Printf("\033[31m重启服务失败: %v，请手动运行 sudo systemctl restart trojan-go\033[0m\n", err)
		} else {
			fmt.Println("\033[32m✓ 服务已成功重启！\033[0m")
		}
	}
}

// modifyYamlField 在不破坏排版和注释的前提下，修改指定 parent 节下的 key 字段值
func modifyYamlField(content, parentKey, key string, value any) (string, error) {
	lines := strings.Split(content, "\n")
	var newLines []string
	inParent := false
	modified := false

	valStr := fmt.Sprintf("%v", value)
	if s, ok := value.(string); ok {
		if !strings.HasPrefix(s, "\"") {
			valStr = fmt.Sprintf("\"%s\"", s)
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, parentKey+":") {
			inParent = true
			newLines = append(newLines, line)
			continue
		}

		if inParent {
			if len(line) > 0 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(trimmed, "#") {
				inParent = false
			} else if strings.HasPrefix(trimmed, key+":") && !modified {
				parts := strings.SplitN(line, ":", 2)
				leadingSpace := parts[0]

				lineComment := ""
				if len(parts) > 1 && strings.Contains(parts[1], "#") {
					cParts := strings.SplitN(parts[1], "#", 2)
					lineComment = " #" + cParts[1]
				}

				line = fmt.Sprintf("%s: %s%s", leadingSpace, valStr, strings.TrimRight(lineComment, "\r\n"))
				modified = true
			}
		}

		newLines = append(newLines, line)
	}

	return strings.Join(newLines, "\n"), nil
}
