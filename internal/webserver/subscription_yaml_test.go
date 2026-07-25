package webserver

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/voidluo/trojan-go/internal/database"
	"gopkg.in/yaml.v3"
)

// TestYamlScalarRoundTripsHostileValues covers M-09: every dynamic value that
// reaches the hand-written subscription template must survive a YAML round trip
// as the exact same Go string, including type-coercion traps (numbers, bools,
// null forms), whitespace traps (tabs, leading/trailing spaces, CRLF) and
// structural injection attempts.
func TestYamlScalarRoundTripsHostileValues(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"plain ascii", "hk-node"},
		{"unicode name", "🇭🇰 香港节点"},

		// Number-like values must stay strings.
		{"integer", "443"},
		{"leading zero", "0443"},
		{"hex", "0x1f"},
		{"octal", "0o17"},
		{"underscored", "1_000"},
		{"float", "3.14"},
		{"exponent", "1e5"},
		{"infinity", ".inf"},
		{"not a number", ".nan"},
		{"sexagesimal", "1:30:00"},
		{"date", "2026-07-25"},
		{"negative", "-1"},

		// Boolean and null forms in every YAML 1.1 spelling.
		{"true", "true"}, {"True", "True"}, {"TRUE", "TRUE"},
		{"false", "false"}, {"False", "False"},
		{"yes", "yes"}, {"Yes", "Yes"}, {"YES", "YES"},
		{"no", "no"}, {"No", "No"},
		{"on", "on"}, {"On", "On"},
		{"off", "off"}, {"OFF", "OFF"},
		{"y", "y"}, {"n", "n"},
		{"null word", "null"}, {"Null word", "Null"}, {"NULL word", "NULL"},
		{"tilde", "~"},
		{"prefix of bool", "truely"},
		{"prefix of null", "nullish"},

		// Whitespace traps.
		{"leading space", " leading"},
		{"trailing space", "trailing "},
		{"only spaces", "   "},
		{"tab", "with\ttab"},
		{"leading tab", "\tleading-tab"},
		{"newline", "line1\nline2"},
		{"crlf", "line1\r\nline2"},
		{"lone cr", "line1\rline2"},
		{"trailing newline", "value\n"},

		// Structural / indicator characters.
		{"colon space", "key: value"},
		{"hash comment", "value # comment"},
		{"dash prefix", "- item"},
		{"question prefix", "? key"},
		{"flow mapping", "{a: b}"},
		{"flow sequence", "[a, b]"},
		{"anchor", "&anchor"},
		{"alias", "*alias"},
		{"tag", "!!python/object"},
		{"directive", "%YAML 1.2"},
		{"block scalar", "|-"},
		{"folded scalar", ">-"},
		{"double quote", `say "hi"`},
		{"single quote", "it's"},
		{"backslash", `C:\path\to`},
		{"backtick", "`cmd`"},
		{"at sign", "@reserved"},
		{"document end", "..."},
		{"document start", "---"},

		// Injection attempts against the surrounding template.
		{"break out of proxies", "x\n  - name: injected\n    type: trojan"},
		{"append key", "x\nskip-cert-verify: true"},
		{"nul byte", "a\x00b"},
		{"control chars", "a\x01\x02\x1fb"},
		{"del", "a\x7fb"},
		{"unicode line separator", "a\u2028b"},
		{"bom", "\ufeffvalue"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := yamlScalar(tc.value)
			if strings.ContainsAny(encoded, "\n\r") {
				t.Fatalf("encoded scalar must stay on one line, got %q", encoded)
			}

			// Must round-trip through a realistic single-key document.
			var holder struct {
				V string `yaml:"v"`
			}
			doc := "v: " + encoded + "\n"
			if err := yaml.Unmarshal([]byte(doc), &holder); err != nil {
				t.Fatalf("re-parse %q failed: %v", doc, err)
			}
			if holder.V != tc.value {
				t.Fatalf("round trip mismatch:\n  input:   %q\n  encoded: %s\n  decoded: %q",
					tc.value, encoded, holder.V)
			}
			if !yamlScalarRoundTrips(tc.value) {
				t.Fatalf("yamlScalarRoundTrips reported failure for %q", tc.value)
			}

			// Must also round-trip nested inside a sequence, which is how node
			// names are emitted in proxy-groups.
			var seq struct {
				Items []string `yaml:"items"`
			}
			nested := "items:\n  - " + encoded + "\n"
			if err := yaml.Unmarshal([]byte(nested), &seq); err != nil {
				t.Fatalf("re-parse nested %q failed: %v", nested, err)
			}
			if len(seq.Items) != 1 || seq.Items[0] != tc.value {
				t.Fatalf("nested round trip mismatch for %q: %#v", tc.value, seq.Items)
			}
		})
	}
}

// TestGeneratedSubscriptionParsesWithHostileNodeFields proves the whole
// document survives reverse parsing when node metadata carries hostile values.
func TestGeneratedSubscriptionParsesWithHostileNodeFields(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "subscription.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}

	user := database.User{Username: "hostile", Password: "pw: #not-a-comment\ttab", Hash: "hash", Quota: -1}
	nodes := []database.Node{
		{Name: "true", Address: "443", Port: 443, SNI: "~"},
		{Name: "x\n  - name: injected", Address: "a\x00b", Port: 8443, SNI: "0x1f"},
		{Name: "  padded  ", Address: "node.example.com", Port: 9443, WSEnabled: true, WSPath: "/#frag: yes"},
	}

	config := generateClashConfigMultiNode(db, user, nodes, "gw.example.com", 443, true, "/ws: #x")

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(config), &parsed); err != nil {
		t.Fatalf("generated subscription is not valid YAML: %v\n%s", err, config)
	}
	proxies, ok := parsed["proxies"].([]any)
	if !ok {
		t.Fatalf("proxies section missing or wrong type: %T", parsed["proxies"])
	}
	// Main node plus the three worker nodes; no injected extra entries.
	if len(proxies) != 4 {
		t.Fatalf("expected 4 proxies (1 main + 3 nodes), got %d", len(proxies))
	}
	for _, entry := range proxies {
		proxy, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("proxy entry has unexpected type %T", entry)
		}
		if _, isString := proxy["name"].(string); !isString {
			t.Fatalf("proxy name must decode as a string, got %T (%v)", proxy["name"], proxy["name"])
		}
		if _, isString := proxy["server"].(string); !isString {
			t.Fatalf("proxy server must decode as a string, got %T (%v)", proxy["server"], proxy["server"])
		}
		if pwd, isString := proxy["password"].(string); !isString || pwd != user.Password {
			t.Fatalf("password must decode back to the original string, got %T (%v)", proxy["password"], proxy["password"])
		}
	}
}

// TestGeneratedSubscriptionFallsBackOnBrokenCustomRules verifies that an
// operator-supplied rules fragment that breaks YAML does not produce an
// unparsable subscription: the generator drops the fragment and falls back to
// the built-in defaults.
func TestGeneratedSubscriptionFallsBackOnBrokenCustomRules(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "subscription.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	broken := "  - GEOIP,CN,🎯 全球直连\n\tbad-indent: [unclosed"
	if err := db.Save(&database.Config{Key: "clash_rules", Value: broken}).Error; err != nil {
		t.Fatalf("store broken rules: %v", err)
	}

	user := database.User{Username: "fallback", Password: "pw", Hash: "hash", Quota: -1}
	config := generateClashConfigMultiNode(db, user, nil, "gw.example.com", 443, false, "")

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(config), &parsed); err != nil {
		t.Fatalf("fallback subscription must still be valid YAML: %v\n%s", err, config)
	}
	if strings.Contains(config, "bad-indent") {
		t.Fatal("broken operator fragment must not be emitted")
	}
	if _, ok := parsed["rules"]; !ok {
		t.Fatal("fallback subscription must contain the built-in rules section")
	}
}
