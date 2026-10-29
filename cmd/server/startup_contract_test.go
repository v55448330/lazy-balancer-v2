package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRunMain_healthcheckBypassesServiceStartup(t *testing.T) {
	serveCalled := false
	code := runMain(
		[]string{"lazy-balancer", "--healthcheck", "-config", "/missing/config.yaml"},
		func() int { return 1 },
		func() error {
			serveCalled = true
			return nil
		},
	)
	if code != 1 {
		t.Fatalf("exit=%d, want healthcheck exit 1", code)
	}
	if serveCalled {
		t.Fatal("healthcheck entered normal startup: flag/config/DB path must not run")
	}
}

func TestRunMain_nonHealthcheckUsesNormalStartup(t *testing.T) {
	serveCalled := false
	code := runMain(
		[]string{"lazy-balancer", "-config", "--healthcheck"},
		func() int {
			t.Fatal("non-leading --healthcheck must not enter probe mode")
			return 1
		},
		func() error {
			serveCalled = true
			return nil
		},
	)
	if code != 0 || !serveCalled {
		t.Fatalf("exit=%d serveCalled=%v, want normal startup exactly once", code, serveCalled)
	}
}

const dockerHealthcheckTimeout = 5 * time.Second

func TestHealthcheckTimeout_twoAttemptsFitDockerBudget(t *testing.T) {
	if budget := 2 * healthcheckTimeout; budget >= dockerHealthcheckTimeout {
		t.Fatalf("HTTPS+HTTP budget=%v, must be less than Docker timeout %v", budget, dockerHealthcheckTimeout)
	}
}

func TestContainerStartup_usesTiniAndExecHealthcheck(t *testing.T) {
	root := repoRootForVersionTest(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	healthcheck := regexp.MustCompile(`(?m)^HEALTHCHECK\s+([^\n]*\\\n\s+CMD\s+(\[[^\n]+\]))\s*$`).FindSubmatch(dockerfile)
	if healthcheck == nil {
		t.Fatal("Dockerfile HEALTHCHECK must use a multiline exec-form CMD array")
	}
	for _, option := range []string{"--interval=30s", "--timeout=5s", "--start-period=90s", "--retries=3"} {
		if !strings.Contains(string(healthcheck[1]), option) {
			t.Errorf("Dockerfile HEALTHCHECK missing %s", option)
		}
	}
	var probeCommand []string
	if err := json.Unmarshal(healthcheck[2], &probeCommand); err != nil {
		t.Fatalf("decode HEALTHCHECK exec array: %v", err)
	}
	if want := []string{"/usr/local/bin/lazy-balancer", "--healthcheck"}; !reflect.DeepEqual(probeCommand, want) {
		t.Fatalf("HEALTHCHECK command=%v, want %v", probeCommand, want)
	}

	entrypoint := regexp.MustCompile(`(?m)^ENTRYPOINT\s+(\[[^\n]+\])\s*$`).FindSubmatch(dockerfile)
	if entrypoint == nil {
		t.Fatal("Dockerfile ENTRYPOINT must use exec form")
	}
	var entrypointCommand []string
	if err := json.Unmarshal(entrypoint[1], &entrypointCommand); err != nil {
		t.Fatalf("decode ENTRYPOINT exec array: %v", err)
	}
	if want := []string{"/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"}; !reflect.DeepEqual(entrypointCommand, want) {
		t.Fatalf("ENTRYPOINT=%v, want tini followed by entrypoint script %v", entrypointCommand, want)
	}

	compose, err := os.ReadFile(filepath.Join(root, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	common := regexp.MustCompile(`(?ms)^x-common-healthcheck:.*?^services:`).Find(compose)
	if common == nil {
		t.Fatal("docker-compose.yml missing x-common-healthcheck anchor")
	}
	for _, declaration := range []string{
		`test: ["CMD", "/usr/local/bin/lazy-balancer", "--healthcheck"]`,
		"interval: 30s",
		"timeout: 5s",
		"retries: 3",
		"start_period: 90s",
	} {
		if !strings.Contains(string(common), declaration) {
			t.Errorf("compose common healthcheck missing %q", declaration)
		}
	}
}
