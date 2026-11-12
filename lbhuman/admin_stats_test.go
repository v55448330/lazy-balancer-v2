package lbhuman

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// CC「封禁」响应选项退役（2026-11-13 用户裁定）：CC 统一走挑战页，真正的封禁
// 由自动封禁管线（挑战发放/失败达阈值）承载。stats 端点不再返回 bans 计数。
func TestServeHumanStats_noBansField(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/lb/human/stats", nil)
	if err := serveHumanStats(rec, req); err != nil {
		t.Fatalf("serveHumanStats: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if _, ok := payload["bans"]; ok {
		t.Fatalf("bans 字段已退役，不得再返回: %s", rec.Body.String())
	}
	for _, key := range []string{"challenges", "passes", "fails"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("缺少保留字段 %s: %s", key, rec.Body.String())
		}
	}
}
