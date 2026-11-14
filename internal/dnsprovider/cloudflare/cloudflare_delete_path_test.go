package cloudflare

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// 记录 ID 直接拼进 DELETE URL 路径：点段（"." / ".."）经 HTTP 客户端/服务端
// 路径归一化会把删除请求落到 zone 集合端点（DELETE /zones/{id}/dns_records），
// 账本条目可能来自集群快照/旧版本写入，必须 fail-visible 拒绝。
func TestDeleteRecord_rejectsDotSegments(t *testing.T) {
	s := newCloudflareTestServer(t)
	p := newCloudflareTestProvider(t, "cf-token", s)
	for _, recordID := range []string{".", ".."} {
		err := p.deleteRecord(context.Background(), "z1", recordID)
		if err == nil || !strings.Contains(err.Error(), "非法记录 ID") {
			t.Fatalf("recordID=%q 未被拒绝: %v", recordID, err)
		}
	}
	for _, entry := range s.log() {
		if entry.method == http.MethodDelete {
			t.Fatalf("点段 ID 不得构造删除请求: %+v", entry)
		}
	}
	// 回归形状：合法 ID 照常删除（404 幂等语义不变）。
	if err := p.deleteRecord(context.Background(), "z1", "rec-ok"); err != nil {
		t.Fatalf("合法 ID 删除失败: %v", err)
	}
}
