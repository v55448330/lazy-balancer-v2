package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// IP 名单详情的每个条目携带来源位 automatic（服务端按自动封禁判据单源派生）：
// 封禁控制台「来源」列不得再由前端拿备注字面量去猜——自动条目的备注早已
// 升级为具体触发原因（突刺/累犯·…/人机验证失败…），字面量判据会把绝大多数
// 自动封禁条目显示成「手动」。
func TestGetIPList_entriesCarryAutomaticSource(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	entries := `[{"value":"198.51.100.1","remark":"突刺"},` +
		`{"value":"198.51.100.2","remark":"累犯·人机验证失败"},` +
		`{"value":"198.51.100.3","remark":"自动封禁"},` +
		`{"value":"198.51.100.4","remark":"手动封禁"},` +
		`{"value":"198.51.100.5","remark":"事件处置"},` +
		`{"value":"198.51.100.6","remark":"运维手工备注"}]`
	id := seedIPListRow(t, "detail-source-list", entries)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/ip-lists/:id", (&Handlers{}).GetIPList)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/security/ip-lists/%d", id), nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}

	var payload struct {
		Data struct {
			Entries []struct {
				Value     string `json:"value"`
				Automatic *bool  `json:"automatic"`
			} `json:"entries"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := map[string]bool{
		"198.51.100.1": true,  // 触发原因词表
		"198.51.100.2": true,  // 累犯前缀 + 原因词表
		"198.51.100.3": true,  // 存量占位符
		"198.51.100.4": false, // 手动封禁
		"198.51.100.5": false, // 事件处置
		"198.51.100.6": false, // 自定义备注
	}
	if len(payload.Data.Entries) != len(want) {
		t.Fatalf("entries=%d want %d", len(payload.Data.Entries), len(want))
	}
	for _, entry := range payload.Data.Entries {
		if entry.Automatic == nil {
			t.Fatalf("条目 %s 缺少 automatic 来源位", entry.Value)
		}
		if *entry.Automatic != want[entry.Value] {
			t.Fatalf("条目 %s automatic=%v want %v", entry.Value, *entry.Automatic, want[entry.Value])
		}
	}
}
