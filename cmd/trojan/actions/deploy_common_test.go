package actions

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentUnitContentsPreservesServiceBoundaries(t *testing.T) {
	deployPath := "/etc/trojan-go"
	master := deploymentUnitContents(deploymentMaster, deployPath, true)
	for _, name := range []string{"admin-service.service", "control-service.service", "trojan-data-plane.service", "gateway-service.service", "hysteria.service"} {
		if _, ok := master[name]; !ok {
			t.Fatalf("master missing %s", name)
		}
	}
	if got := master["admin-service.service"]; !strings.Contains(got, "admin-service -config "+filepath.Join(deployPath, "web_config.yaml")+" -listen 127.0.0.1:8081") {
		t.Fatalf("admin unit has unexpected command:\n%s", got)
	}
	if got := master["control-service.service"]; !strings.Contains(got, "control-service -listen 127.0.0.1:8082 -admin 127.0.0.1:8081") || !strings.Contains(got, "Requires=admin-service.service") {
		t.Fatalf("control unit has unexpected dependency or command:\n%s", got)
	}
	if got := master["trojan-data-plane.service"]; !strings.Contains(got, "ExecStart=/usr/bin/trojan-go -config "+filepath.Join(deployPath, "config.yaml")) {
		t.Fatalf("data-plane unit has unexpected command:\n%s", got)
	}
	if got := master["gateway-service.service"]; !strings.Contains(got, "gateway-service -config "+filepath.Join(deployPath, "gateway.yaml")) || !strings.Contains(got, "Requires=admin-service.service control-service.service trojan-data-plane.service") {
		t.Fatalf("gateway unit has unexpected dependency or command:\n%s", got)
	}
	if got := master["hysteria.service"]; !strings.Contains(got, "Requires=control-service.service") {
		t.Fatalf("Hysteria2 must depend on control-service:\n%s", got)
	}

	worker := deploymentUnitContents(deploymentWorker, deployPath, false)
	if _, ok := worker["admin-service.service"]; ok {
		t.Fatal("worker must not create admin-service")
	}
	for _, name := range []string{"control-service.service", "trojan-data-plane.service", "gateway-service.service"} {
		if _, ok := worker[name]; !ok {
			t.Fatalf("worker missing %s", name)
		}
	}
	if got := worker["control-service.service"]; !strings.Contains(got, "control-service -worker -config "+filepath.Join(deployPath, "web_config.yaml")+" -listen 127.0.0.1:8082") {
		t.Fatalf("worker control unit has unexpected command:\n%s", got)
	}
	if got := worker["gateway-service.service"]; strings.Contains(got, "admin-service.service") || !strings.Contains(got, "Requires=control-service.service trojan-data-plane.service") {
		t.Fatalf("worker gateway has unexpected dependencies:\n%s", got)
	}
}

func TestDeploymentServiceNamesPreservesDependencyOrder(t *testing.T) {
	if got, want := deploymentServiceNames(deploymentMaster, false), []string{"admin-service", "control-service", "trojan-data-plane", "gateway-service"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("master services = %v, want %v", got, want)
	}
	if got, want := deploymentServiceNames(deploymentWorker, true), []string{"control-service", "trojan-data-plane", "gateway-service", "hysteria"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("worker services = %v, want %v", got, want)
	}
}
