package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/accesslog"
)

// apiKeyRedactionPath 必须等于引擎实际看到的头键路径（http.Header 的规范化
// 键名）——写死字面量的副本就是脱敏空转的根因，故此处从单源派生。
var apiKeyRedactionPath = accesslog.APIKeyHeaderPath()

func encoderFields(t *testing.T, encoder map[string]interface{}) map[string]interface{} {
	t.Helper()
	if got := encoder["format"]; got != "filter" {
		t.Fatalf("access log encoder format=%v, want filter（X-API-Key 脱敏必须经 filter）", got)
	}
	wrap, _ := encoder["wrap"].(map[string]interface{})
	if wrap["format"] != "json" {
		t.Fatalf("access log encoder wrap=%v, want json", encoder["wrap"])
	}
	fields, ok := encoder["fields"].(map[string]interface{})
	if !ok {
		t.Fatalf("access log encoder fields=%v, want map", encoder["fields"])
	}
	return fields
}

// JSON、以及用户格式里的 rename 行三种形态都不得让 API Key 明文落日志。
func TestBuildAccessLogEncoder_redactsAPIKeyInEverySupportedShape(t *testing.T) {
	cases := []struct {
		name   string
		json   bool
		format string
	}{
		{"custom-empty-format", true, ""},
		{"native-json-toggle", false, ""},
		{"custom-format-without-line", true, "request>remote_ip -> src"},
		{"custom-format-renames-api-key", true, "request>headers>X-API-Key -> apikey"},
		{"native-json-with-format-ignored", false, "request>remote_ip -> src"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := encoderFields(t, buildAccessLogEncoder(tc.json, tc.format))
			rule, ok := fields[apiKeyRedactionPath].(map[string]interface{})
			if !ok {
				t.Fatalf("fields 缺少 %s 脱敏行: %v", apiKeyRedactionPath, fields)
			}
			if rule["filter"] != "delete" {
				t.Fatalf("%s 动作=%v, want delete（rename/缺失都会泄漏 API Key）", apiKeyRedactionPath, rule["filter"])
			}
		})
	}
}

// 用户自定义格式仍须完整生效（脱敏行是叠加而非替换）。
func TestBuildAccessLogEncoder_keepsUserFormatAlongsideRedaction(t *testing.T) {
	fields := encoderFields(t, buildAccessLogEncoder(true, "request>remote_ip -> src\nmsg -> delete"))
	if got, ok := fields["request>remote_ip"].(map[string]interface{}); !ok || got["filter"] != "rename" || got["name"] != "src" {
		t.Fatalf("用户 rename 行丢失: %v", fields)
	}
	if got, ok := fields["msg"].(map[string]interface{}); !ok || got["filter"] != "delete" {
		t.Fatalf("用户 delete 行丢失: %v", fields)
	}
}

// 渲染链端到端：规则日志（复用同一 encoder）与全局开关 false 形态都必须
// 携带脱敏行——单测 encoder 之外，钉住 generateCaddyConfigFromStore 的接线。
func TestGenerateCaddyConfig_ruleLogsAlwaysRedactAPIKey(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_logredact", false)
	if _, err := database.Exec(`UPDATE lb_rules SET log_enabled=1 WHERE caddy_id='lb_logredact'`); err != nil {
		t.Fatalf("enable rule log: %v", err)
	}
	for _, jsonToggle := range []int{0, 1} {
		if _, err := database.Exec(`UPDATE global_config SET access_log_json=?, access_log_format='' WHERE id=1`, jsonToggle); err != nil {
			t.Fatalf("set log toggle: %v", err)
		}
		cfg := generateCaddyConfigFromStore(database)
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		logging, _ := cfg["logging"].(map[string]interface{})
		logs, _ := logging["logs"].(map[string]interface{})
		entry, ok := logs["rule_lb_logredact"].(map[string]interface{})
		if !ok {
			t.Fatalf("规则日志条目缺失（access_log_json=%d）: %s", jsonToggle, raw)
		}
		encoder, ok := entry["encoder"].(map[string]interface{})
		if !ok {
			t.Fatalf("规则日志 encoder 缺失: %s", raw)
		}
		if _, ok := encoderFields(t, encoder)[apiKeyRedactionPath]; !ok {
			t.Fatalf("access_log_json=%d 时规则日志缺少 X-API-Key 脱敏: %s", jsonToggle, raw)
		}
	}
}

// 同族宽口径：全局日志集合里任何 http.log.access 消费者都必须是 filter 编码器
// （未来新增访问日志条目不得绕过脱敏）。
func TestGenerateCaddyConfig_noAccessLogConsumerUsesBareJSONEncoder(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_logscan", false)
	if _, err := database.Exec(`UPDATE lb_rules SET log_enabled=1 WHERE caddy_id='lb_logscan'`); err != nil {
		t.Fatalf("enable rule log: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET access_log_json=0 WHERE id=1`); err != nil {
		t.Fatalf("set toggle: %v", err)
	}
	cfg := generateCaddyConfigFromStore(database)
	raw, _ := json.Marshal(cfg)
	logging, ok := cfg["logging"].(map[string]interface{})
	if !ok {
		t.Fatalf("logging 缺失: %s", raw)
	}
	logs, ok := logging["logs"].(map[string]interface{})
	if !ok {
		t.Fatalf("logging.logs 缺失: %s", raw)
	}
	accessEntries := 0
	for name, value := range logs {
		entry, ok := value.(map[string]interface{})
		if !ok {
			t.Fatalf("日志条目 %s 类型=%T: %s", name, value, raw)
		}
		includes, ok := entry["include"].([]string)
		if !ok {
			continue // 非访问日志条目（如服务器运行日志）形态合法
		}
		isAccess := false
		for _, inc := range includes {
			if strings.HasPrefix(inc, "http.log.access") {
				isAccess = true
			}
		}
		if !isAccess {
			continue
		}
		accessEntries++
		encoder, ok := entry["encoder"].(map[string]interface{})
		if !ok {
			t.Fatalf("访问日志条目 %s 缺少 encoder: %s", name, raw)
		}
		if encoder["format"] != "filter" {
			t.Fatalf("访问日志条目 %s 使用 %v 编码器（无删除通道）: %s", name, encoder["format"], raw)
		}
	}
	// 正向控制：条目（或其 include）整体消失时循环零命中，不得视为通过。
	if accessEntries == 0 {
		t.Fatalf("未找到任何 http.log.access 消费者（守卫扫描面为空）: %s", raw)
	}
}
