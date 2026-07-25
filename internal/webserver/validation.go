package webserver

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"
	"unicode/utf8"
)

// L-02: shared field validators so the create and update paths cannot drift.
// Every value validated here eventually reaches a generated client
// configuration, a systemd unit or a shell-free exec argument list, so the
// rules reject control characters and over-long values rather than relying on
// downstream escaping alone.

const (
	maxNodeNameLen = 128
	maxHostnameLen = 253
	maxWSPathLen   = 512
	maxUsernameLen = 64
)

// hasControlChars reports whether s contains C0/C1 control characters, DEL, or
// Unicode line/paragraph separators.
func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
			return true
		}
	}
	return false
}

// validateNodeAddress accepts either a literal IP address or a syntactically
// valid DNS hostname. It intentionally does not resolve anything.
func validateNodeAddress(address string) error {
	if address == "" {
		return errors.New("节点地址不能为空")
	}
	if address != strings.TrimSpace(address) {
		return errors.New("节点地址不能包含首尾空白字符")
	}
	if hasControlChars(address) {
		return errors.New("节点地址包含非法控制字符")
	}
	if len(address) > maxHostnameLen {
		return fmt.Errorf("节点地址不能超过 %d 个字符", maxHostnameLen)
	}
	// Bracketless IPv6 and IPv4 literals are both accepted; a bracketed form is
	// unwrapped first because callers may paste it from a URL.
	candidate := strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
	if net.ParseIP(candidate) != nil {
		return nil
	}
	if err := validateHostname(address); err != nil {
		return fmt.Errorf("节点地址必须是合法的 IP 或域名: %w", err)
	}
	return nil
}

// validateHostname checks DNS label syntax (RFC 1123 with the common
// leading-digit relaxation).
func validateHostname(host string) error {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return errors.New("域名为空")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return errors.New("域名包含空标签")
		}
		if len(label) > 63 {
			return errors.New("域名标签超过 63 个字符")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("域名标签不能以连字符开头或结尾")
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
			if !isAlphaNum && ch != '-' && ch != '_' {
				return fmt.Errorf("域名包含非法字符 %q", string(ch))
			}
		}
	}
	return nil
}

// validateSNI applies hostname rules to a TLS SNI value. An empty SNI means
// "derive it from the address" and is accepted by callers before this runs.
func validateSNI(sni string) error {
	if sni == "" {
		return nil
	}
	if sni != strings.TrimSpace(sni) {
		return errors.New("SNI 不能包含首尾空白字符")
	}
	if hasControlChars(sni) {
		return errors.New("SNI 包含非法控制字符")
	}
	if len(sni) > maxHostnameLen {
		return fmt.Errorf("SNI 不能超过 %d 个字符", maxHostnameLen)
	}
	if net.ParseIP(sni) != nil {
		// An IP literal is a valid TLS server_name only in unusual setups, but
		// it is not a syntax error and some deployments rely on it.
		return nil
	}
	if err := validateHostname(sni); err != nil {
		return fmt.Errorf("SNI 格式无效: %w", err)
	}
	return nil
}

// validateWSPath checks a WebSocket path. An empty value means "use the
// default" and is handled by the caller.
func validateWSPath(path string) error {
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "/") {
		return errors.New("WebSocket 路径必须以 / 开头")
	}
	if hasControlChars(path) {
		return errors.New("WebSocket 路径包含非法控制字符")
	}
	if len(path) > maxWSPathLen {
		return fmt.Errorf("WebSocket 路径不能超过 %d 个字符", maxWSPathLen)
	}
	if strings.ContainsAny(path, " \t") {
		return errors.New("WebSocket 路径不能包含空格或制表符")
	}
	if strings.ContainsAny(path, "?#") {
		return errors.New("WebSocket 路径不能包含查询串或片段标识")
	}
	return nil
}

// validateNodeName checks a display name. Names end up in the generated Clash
// document and in the web UI, so control characters are rejected even though
// yamlScalar would escape them.
func validateNodeName(name string) error {
	if name == "" {
		return errors.New("节点名称不能为空")
	}
	if hasControlChars(name) {
		return errors.New("节点名称包含非法控制字符")
	}
	if !utf8.ValidString(name) {
		return errors.New("节点名称必须是合法的 UTF-8 文本")
	}
	if utf8.RuneCountInString(name) > maxNodeNameLen {
		return fmt.Errorf("节点名称不能超过 %d 个字符", maxNodeNameLen)
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("节点名称不能只包含空白字符")
	}
	return nil
}

// validateUsername checks a proxy account name. The name is used in
// subscription filenames and share links, so it is restricted to printable
// non-space characters.
func validateUsername(username string) error {
	if username == "" {
		return errors.New("用户名不能为空")
	}
	if !utf8.ValidString(username) {
		return errors.New("用户名必须是合法的 UTF-8 文本")
	}
	if utf8.RuneCountInString(username) > maxUsernameLen {
		return fmt.Errorf("用户名不能超过 %d 个字符", maxUsernameLen)
	}
	if hasControlChars(username) {
		return errors.New("用户名包含非法控制字符")
	}
	for _, r := range username {
		if unicode.IsSpace(r) {
			return errors.New("用户名不能包含空白字符")
		}
		if strings.ContainsRune(`/\:*?"<>|`, r) {
			return fmt.Errorf("用户名不能包含字符 %q", string(r))
		}
	}
	return nil
}

// validateQuota enforces the documented quota contract: -1 means unlimited and
// any other negative value is rejected. Shared by the user create/update
// handlers and the standalone quota endpoint so they cannot disagree.
func validateQuota(quota int64) error {
	if quota < -1 {
		return errors.New("配额必须为 -1（不限）或不小于 0 的字节数")
	}
	return nil
}
