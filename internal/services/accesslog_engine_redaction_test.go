package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const accessLogEngineProbeKey = "lb_sk_engine_probe_secret_value"

// accessLogEngineConfig 构造最小可跑的访问日志配置：一个静态响应路由 + 一个
// 只由该 encoder 决定的访问日志写文件。返回 JSON 字节。
func accessLogEngineConfig(t *testing.T, listenAddr, logPath string, encoder map[string]interface{}) []byte {
	t.Helper()
	config := map[string]interface{}{
		"admin": map[string]interface{}{"disabled": true},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []string{listenAddr},
						"routes": []interface{}{
							map[string]interface{}{
								"handle": []interface{}{
									map[string]interface{}{"handler": "static_response", "body": "ok", "status_code": 200},
								},
								"terminal": true,
							},
						},
						"logs": map[string]interface{}{"default_logger_name": "access"},
					},
				},
			},
		},
		"logging": map[string]interface{}{
			"logs": map[string]interface{}{
				"access": map[string]interface{}{
					"writer":  map[string]interface{}{"output": "file", "filename": logPath},
					"encoder": encoder,
					"include": []string{"http.log.access.access"},
				},
			},
		},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal engine config: %v", err)
	}
	return raw
}

// runAccessLogEngineProbe 用真实 Caddy 跑一份配置，发一条带 X-API-Key 的请求，
// 返回访问日志正文（日志正文为空即夹具失效，直接判红）。
func runAccessLogEngineProbe(t *testing.T, binary string, encoder map[string]interface{}) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	listenAddr := listener.Addr().String()
	_ = listener.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	configPath := filepath.Join(dir, "caddy.json")
	if err := os.WriteFile(configPath, accessLogEngineConfig(t, listenAddr, logPath, encoder), 0o600); err != nil {
		t.Fatalf("write engine config: %v", err)
	}

	cmd := exec.Command(binary, "run", "--config", configPath, "--adapter", "json")
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	stopped := make(chan struct{})
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-stopped
		if t.Failed() {
			t.Logf("caddy output:\n%s", output.String())
		}
	})
	go func() { _ = cmd.Wait(); close(stopped) }()

	readyDeadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", listenAddr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(readyDeadline) {
			t.Fatalf("caddy 未在 10s 内监听 %s\n%s", listenAddr, output.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	request, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/probe", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("X-API-Key", accessLogEngineProbeKey)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("probe request: %v\n%s", err, output.String())
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("probe status=%d body=%s", response.StatusCode, body)
	}

	logDeadline := time.Now().Add(10 * time.Second)
	for {
		content, err := os.ReadFile(logPath)
		if err == nil && strings.Contains(string(content), "http.log.access") {
			return string(content)
		}
		if time.Now().After(logDeadline) {
			t.Fatalf("访问日志在 10s 内没有写入访问记录（夹具失效）\n%s", output.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// 生效级验收：真实 Caddy 引擎加载渲染层的 encoder 后，携带 X-API-Key 的请求
// 不得在访问日志里留下 Key 明文。跳过条件与环境里没有项目定制 caddy 二进制
// 一致（与 caddy_engine_acceptance_test.go 同口径）。
func TestAccessLogEncoder_realEngineDropsAPIKey(t *testing.T) {
	binary := caddyBinaryForAcceptance(t)

	t.Run("rendered_encoder_redacts", func(t *testing.T) {
		log := runAccessLogEngineProbe(t, binary, buildAccessLogEncoder(true, ""))
		if strings.Contains(log, accessLogEngineProbeKey) {
			t.Fatalf("访问日志泄漏 API Key 明文:\n%s", log)
		}
		// 正向控制：数据面确实经过该路由且日志确实是被脱敏后的访问日志
		// （而不是空日志或别的 logger）。
		if !strings.Contains(log, "http.log.access.access") && !strings.Contains(log, `"logger":"http.log.access`) {
			t.Fatalf("访问日志缺少访问记录标识（夹具失效）:\n%s", log)
		}
	})

	// 意义性控制（red 形态）：只有字面量拼写（旧实现）时引擎精确匹配不命中，
	// 明文必然落盘。本子用例证明上面的断言有牙——若将来有人把路径改回手写
	// 字面量，第一个子用例会真实失败，而不是永远绿。
	t.Run("legacy_literal_spelling_leaks", func(t *testing.T) {
		legacy := map[string]interface{}{
			"format": "filter",
			"wrap":   map[string]interface{}{"format": "json"},
			"fields": map[string]interface{}{
				"request>headers>X-API-Key": map[string]interface{}{"filter": "delete"},
			},
		}
		log := runAccessLogEngineProbe(t, binary, legacy)
		if !strings.Contains(log, accessLogEngineProbeKey) {
			t.Fatalf("字面量拼写的删除规则竟然命中了（引擎语义变化，需重审脱敏键形态）:\n%s", log)
		}
	})
}

// sanity: 配置构造本身必须是引擎可接受的 JSON（无二进制环境下仍能钉住形状）。
func TestAccessLogEngineConfig_isJSONObject(t *testing.T) {
	raw := accessLogEngineConfig(t, "127.0.0.1:18080", "/tmp/access.log", buildAccessLogEncoder(true, ""))
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("engine config is not valid JSON: %v", err)
	}
	logging, _ := decoded["logging"].(map[string]interface{})
	logs, _ := logging["logs"].(map[string]interface{})
	entry, _ := logs["access"].(map[string]interface{})
	encoder, _ := entry["encoder"].(map[string]interface{})
	fields, _ := encoder["fields"].(map[string]interface{})
	if _, ok := fields["request>headers>X-Api-Key"]; !ok {
		t.Fatalf("engine config 未携带规范化脱敏键: %s", fmt.Sprint(fields))
	}
}
