package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
)

func TestRestartRequiredHandler_shutsDownHTTPServer(t *testing.T) {
	// Given
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: http.NewServeMux()}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	quit := make(chan os.Signal, 1)
	restart, requestRestart := newRestartSignal()
	services.SetRestartRequiredHandler(requestRestart)
	t.Cleanup(func() { services.SetRestartRequiredHandler(nil) })

	// When
	requestRestart()
	requestRestart()
	serverErr := waitForServerStop(server, serverStopSignals{quit: quit, restart: restart, serverErrors: serverErrors})

	// Then
	if serverErr != nil {
		t.Fatalf("wait for server stop: %v", serverErr)
	}
	if err := <-serverErrors; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serve error=%v, want http.ErrServerClosed", err)
	}
}

func TestMain_exitsNonZero_whenHTTPListenFails(t *testing.T) {
	// Given
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	// caddy_admin_url 必须指向死端口：缺省会落到 config.go 的默认
	// http://localhost:2019——helper 的 ApplyConfigOnStartup 会把零规则配置
	// 应用到本机真实运行的 Caddy（host 网络共享 loopback），静默清空其路由。
	configJSON := fmt.Sprintf(`{"port":%d,"data_dir":%q,"static_dir":%q,"metrics_interval":5,"caddy_admin_url":"http://127.0.0.1:1"}`, port, filepath.Join(tempDir, "data"), tempDir)
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestMainHelperProcess")
	command.Env = append(os.Environ(), "LAZY_BALANCER_MAIN_HELPER=1", "LAZY_BALANCER_TEST_CONFIG="+configPath)

	// When
	output, err := command.CombinedOutput()

	// Then
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() == 0 {
		t.Fatalf("process error=%v output=%q, want non-zero exit", err, output)
	}
	if !strings.Contains(string(output), "HTTP server stopped unexpectedly") {
		t.Fatalf("output=%q, want startup failure log", output)
	}
}

func TestMainHelperProcess(t *testing.T) {
	if os.Getenv("LAZY_BALANCER_MAIN_HELPER") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{os.Args[0], "-config", os.Getenv("LAZY_BALANCER_TEST_CONFIG")}
	main()
	os.Exit(0)
}
