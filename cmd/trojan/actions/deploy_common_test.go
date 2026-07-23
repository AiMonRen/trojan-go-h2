package actions

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentUnitContentsPreservesRoleSpecificDescriptions(t *testing.T) {
	deployPath := "/etc/trojan-go"
	tests := []struct {
		name             string
		role             deploymentRole
		hysteriaEnabled  bool
		proxyDescription string
		webDescription   string
		h2Description    string
	}{
		{
			name:             "master without Hysteria2",
			role:             deploymentMaster,
			proxyDescription: "Description=Trojan-Go Proxy Service",
			webDescription:   "Description=Trojan-Go Web Management Service",
		},
		{
			name:             "worker with Hysteria2",
			role:             deploymentWorker,
			hysteriaEnabled:  true,
			proxyDescription: "Description=Trojan-Go Worker Proxy Service",
			webDescription:   "Description=Trojan-Go Worker Web Management Service",
			h2Description:    "Description=Hysteria2 QUIC/UDP Server (Worker)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			units := deploymentUnitContents(tt.role, deployPath, tt.hysteriaEnabled)
			if got := units["trojan-go.service"]; !strings.Contains(got, tt.proxyDescription) {
				t.Fatalf("proxy unit missing role description %q:\n%s", tt.proxyDescription, got)
			}
			if got := units["trojan-go.service"]; !strings.Contains(got, "ExecStart=/usr/bin/trojan-go -config "+filepath.Join(deployPath, "config.yaml")) {
				t.Fatalf("proxy unit has unexpected config path:\n%s", got)
			}
			if got := units["trojan-web.service"]; !strings.Contains(got, tt.webDescription) {
				t.Fatalf("web unit missing role description %q:\n%s", tt.webDescription, got)
			}
			if got := units["trojan-web.service"]; !strings.Contains(got, "ExecStart=/usr/bin/trojan-go web -config "+filepath.Join(deployPath, "web_config.yaml")) {
				t.Fatalf("web unit has unexpected config path:\n%s", got)
			}
			if tt.hysteriaEnabled {
				got, ok := units["hysteria.service"]
				if !ok || !strings.Contains(got, tt.h2Description) {
					t.Fatalf("Hysteria2 unit missing role description %q:\n%s", tt.h2Description, got)
				}
				if !strings.Contains(got, "ExecStart=/usr/local/bin/hysteria server -c "+filepath.Join(deployPath, "hysteria.yaml")) {
					t.Fatalf("Hysteria2 unit has unexpected config path:\n%s", got)
				}
			} else if _, ok := units["hysteria.service"]; ok {
				t.Fatal("Hysteria2 disabled deployment must not create a hysteria unit")
			}
		})
	}
}

func TestDeploymentServiceNamesPreservesDependencyOrder(t *testing.T) {
	if got, want := deploymentServiceNames(false), []string{"trojan-web", "trojan-go"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("services without Hysteria2 = %v, want %v", got, want)
	}
	if got, want := deploymentServiceNames(true), []string{"trojan-web", "trojan-go", "hysteria"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("services with Hysteria2 = %v, want %v", got, want)
	}
}
