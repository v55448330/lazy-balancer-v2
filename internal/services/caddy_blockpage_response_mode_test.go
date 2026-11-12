package services

import (
	"encoding/json"
	"testing"
)

// 策略级响应方式（auto|html|json）与默认 JSON 派生：
//   - json 模式必须只发 JSON 变体（不依赖请求头），供 API 客户端强制拿到 JSON；
//   - html 模式必须只发 HTML 主档；
//   - auto 保持按请求头分流（3 条 JSON matcher + 1 条 HTML 兜底）；
//   - 未自定义 json_content 时从页面 <title> 派生消息，且不再携带 code 字段
//     （HTTP status 已是标准语义）。
func TestBlockPageResponseModeAndDerivedJSON(t *testing.T) {
	base := map[string]interface{}{"host": []string{"example.com"}}
	content := `<html><head><title>Too Many Requests</title></head><body>slow down</body></html>`

	htmlRoutes := buildDualBlockPageRoutes(base, content, "", "text/html; charset=utf-8", 429, nil, "html")
	if len(htmlRoutes) != 1 {
		t.Fatalf("html 模式应只有 1 条路由，got %d", len(htmlRoutes))
	}
	htmlBody := htmlRoutes[0]["handle"].([]interface{})[0].(map[string]interface{})["body"]
	if htmlBody != content {
		t.Fatalf("html 模式应返回页面原文，got %v", htmlBody)
	}

	jsonRoutes := buildDualBlockPageRoutes(base, content, "", "text/html; charset=utf-8", 429, nil, "json")
	if len(jsonRoutes) != 1 {
		t.Fatalf("json 模式应只有 1 条路由，got %d", len(jsonRoutes))
	}
	handler := jsonRoutes[0]["handle"].([]interface{})[0].(map[string]interface{})
	body := handler["body"].(string)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("json 模式响应体必须是合法 JSON，got %q: %v", body, err)
	}
	if parsed["message"] != "Too Many Requests" {
		t.Fatalf("默认 JSON 消息应派生自 <title>，got %v", parsed["message"])
	}
	if _, hasCode := parsed["code"]; hasCode {
		t.Fatalf("默认 JSON 不应携带 code（HTTP status 已表达），got %q", body)
	}
	headers := handler["headers"].(map[string]interface{})
	if got := headers["Content-Type"].([]string)[0]; got != "application/json; charset=utf-8" {
		t.Fatalf("json 模式 Content-Type=%q", got)
	}

	autoRoutes := buildDualBlockPageRoutes(base, content, "", "text/html; charset=utf-8", 403, nil, "auto")
	if len(autoRoutes) != 4 {
		t.Fatalf("auto 模式应为 3 条 JSON matcher + 1 条 HTML，got %d", len(autoRoutes))
	}
}

// 真实内置页标题含前缀/破折号时同样必须成功派生（防止取标题逻辑对复杂
// HTML 静默回退到通用文案）。
func TestDefaultBlockPageJSONMessage_complexTitle(t *testing.T) {
	content := `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Too Many Requests — Lazy Balancer</title></head><body>x</body></html>`
	got := defaultBlockPageJSONMessage(content)
	want := `{"message":"Too Many Requests — Lazy Balancer"}`
	if got != want {
		t.Fatalf("derived=%q, want %q", got, want)
	}
}

// 自定义 JSON 必须原样优先，不得被派生逻辑覆盖。
func TestBlockPageResponseModeKeepsCustomJSON(t *testing.T) {
	base := map[string]interface{}{"host": []string{"example.com"}}
	custom := `{"error":"blocked"}`
	routes := buildDualBlockPageRoutes(base, "<html><title>x</title></html>", custom, "text/html; charset=utf-8", 403, nil, "json")
	body := routes[0]["handle"].([]interface{})[0].(map[string]interface{})["body"].(string)
	if body != custom {
		t.Fatalf("自定义 JSON 必须优先，got %q", body)
	}
}
