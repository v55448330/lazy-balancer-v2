package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// CL44-3（第 44 轮审计）：从节点 /cluster/service-control 是未认证机器端点，
// 非法动作原文（含换行/控制字符、超长）此前直接落审计详情——必须经
// registerAuditField 清洗（去控制字符、截断 128B）后再拼接。
func TestCL44_3_ClusterServiceControl_sanitizesAuditActionField(t *testing.T) {
	setupClusterServiceControlDB(t)
	_, router := newSlaveTestHandler(&config.Config{})
	// Given：含换行/控制字符且超长的非法动作（动作校验先于票据校验，直接落审计）
	action := strings.Repeat("A", 200) + "\r\n\t\x00\x1b"

	// When
	response := postServiceControl(router, action, "any-ticket")

	// Then：拒绝且审计详情无控制字符、动作段 ≤128B
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	details := auditDetailsServiceControlRows(t)
	if len(details) == 0 {
		t.Fatal("no service-control audit recorded")
	}
	detail := details[len(details)-1]
	for _, r := range detail {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("audit detail contains control character %U: %q", r, detail)
		}
	}
	if got := strings.Count(detail, "A"); got > 128 {
		t.Fatalf("audit detail action field As=%d, want <=128（截断）: %q", got, detail)
	}
}

// CL44-4（第 44 轮审计）：从节点管理面强制 HTTPS/反代重定向时，未跟随的 3xx
// 空 body 此前落进 JSON 解析报「unexpected end of JSON input」——须在读 body
// 前给可行动指引（访问地址改 https:// 或修正反代），与集群同步 3xx 分支同契约。
func TestCL44_4_callClusterServiceControl_returnsActionableErrorOnRedirect(t *testing.T) {
	setupClusterServiceControlDB(t)
	// Given：从端 301 跨主机重定向，空 body
	slave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://slave-elsewhere.example.com/api/v1/cluster/service-control")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	t.Cleanup(slave.Close)
	handler := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}}

	// When
	_, err := handler.callClusterServiceControl(context.Background(), slave.URL, models.ClusterServiceActionStopCaddy, "ticket-x")

	// Then：含 https 指引的重定向错误，而非 JSON 解析错误
	if err == nil || !strings.Contains(err.Error(), "https://") || !strings.Contains(err.Error(), "重定向") {
		t.Fatalf("error=%v, want 含 https 指引的重定向错误", err)
	}
}
