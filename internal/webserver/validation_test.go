package webserver

import (
	"strings"
	"testing"
)

// L-02 regression coverage for the shared field validators.

func TestValidateNodeAddress(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"example.com.",
		"xn--fiqs8s.example",
		"node-1.example.com",
		"under_score.example.com",
		"1.2.3.4",
		"203.0.113.7",
		"2001:db8::1",
		"[2001:db8::1]",
		"a" + strings.Repeat("b", 62) + ".com",
	}
	for _, addr := range valid {
		if err := validateNodeAddress(addr); err != nil {
			t.Errorf("validateNodeAddress(%q) = %v, want nil", addr, err)
		}
	}

	invalid := []string{
		"",
		" example.com",
		"example.com ",
		"exa mple.com",
		"example..com",
		"-example.com",
		"example-.com",
		"exam;ple.com",
		"http://example.com",
		"example.com/path",
		"example.com:443",
		"host\x00name",
		"host\nname",
		"host\rname",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63),
		"a" + strings.Repeat("b", 63) + ".com",
	}
	for _, addr := range invalid {
		if err := validateNodeAddress(addr); err == nil {
			t.Errorf("validateNodeAddress(%q) = nil, want error", addr)
		}
	}
}

func TestValidateSNI(t *testing.T) {
	for _, sni := range []string{"", "example.com", "1.2.3.4", "2001:db8::1"} {
		if err := validateSNI(sni); err != nil {
			t.Errorf("validateSNI(%q) = %v, want nil", sni, err)
		}
	}
	for _, sni := range []string{
		" example.com", "example.com ", "bad host", "sni\x00", "sni\r\n",
		strings.Repeat("a", 300), "-bad.example.com",
	} {
		if err := validateSNI(sni); err == nil {
			t.Errorf("validateSNI(%q) = nil, want error", sni)
		}
	}
}

func TestValidateWSPath(t *testing.T) {
	for _, path := range []string{"", "/", "/trojan-go", "/a/b/c", "/%E4%B8%AD"} {
		if err := validateWSPath(path); err != nil {
			t.Errorf("validateWSPath(%q) = %v, want nil", path, err)
		}
	}
	for _, path := range []string{
		"trojan-go",       // missing leading slash
		"/with space",     // space
		"/with\ttab",      // tab
		"/path?query=1",   // query string
		"/path#fragment",  // fragment
		"/path\x00",       // NUL
		"/path\nInjected", // newline injection
		"/" + strings.Repeat("a", maxWSPathLen),
	} {
		if err := validateWSPath(path); err == nil {
			t.Errorf("validateWSPath(%q) = nil, want error", path)
		}
	}
}

func TestValidateNodeName(t *testing.T) {
	for _, name := range []string{"hk", "🇭🇰 香港 01", "node (backup)", strings.Repeat("名", maxNodeNameLen)} {
		if err := validateNodeName(name); err != nil {
			t.Errorf("validateNodeName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{
		"",
		"   ",
		"name\x00",
		"name\nsecond",
		"name\u2028",
		strings.Repeat("名", maxNodeNameLen+1),
	} {
		if err := validateNodeName(name); err == nil {
			t.Errorf("validateNodeName(%q) = nil, want error", name)
		}
	}
}

// TestValidateNodeNameRejectsHTMLMetaChars covers S-01: the node name reaches
// the admin UI, so HTML metacharacters must be refused at the API boundary in
// addition to the front-end escaping.
func TestValidateNodeNameRejectsHTMLMetaChars(t *testing.T) {
	for _, name := range []string{
		`<img src=x onerror=alert(1)>`,
		`<script>alert(1)</script>`,
		`" onfocus=alert(1) autofocus x="`,
		`hk' or '1`,
		`a&b`,
		`node<`,
		`node>`,
	} {
		if err := validateNodeName(name); err == nil {
			t.Errorf("validateNodeName(%q) = nil, want error", name)
		}
	}
}

func TestValidateUsername(t *testing.T) {
	for _, name := range []string{"alice", "用户1", "a.b-c_d", strings.Repeat("u", maxUsernameLen)} {
		if err := validateUsername(name); err != nil {
			t.Errorf("validateUsername(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{
		"",
		"has space",
		"has\ttab",
		"has\nnewline",
		"nul\x00",
		"slash/name",
		`back\slash`,
		"colon:name",
		"star*name",
		"quest?name",
		`quote"name`,
		"lt<name",
		"gt>name",
		"pipe|name",
		strings.Repeat("u", maxUsernameLen+1),
	} {
		if err := validateUsername(name); err == nil {
			t.Errorf("validateUsername(%q) = nil, want error", name)
		}
	}
}

func TestValidateQuota(t *testing.T) {
	for _, q := range []int64{-1, 0, 1, 1 << 40} {
		if err := validateQuota(q); err != nil {
			t.Errorf("validateQuota(%d) = %v, want nil", q, err)
		}
	}
	for _, q := range []int64{-2, -100, -1 << 40} {
		if err := validateQuota(q); err == nil {
			t.Errorf("validateQuota(%d) = nil, want error", q)
		}
	}
}
