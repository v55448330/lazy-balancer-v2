package handlers

// CL40-C1-5(第 40 轮):切换从节点的出口 IP 探测失败(回退 127.0.0.1)时,
// 切换审计必须追加点名——否则注册的访问地址是坏值而无任何运维可见性。

import (
	"strings"
	"testing"
)

func TestSwitchToSlaveAuditDetail_outboundIPFallbackNoted(t *testing.T) {
	detail := switchToSlaveAuditDetail("https://master.example.com", false)
	if !strings.Contains(detail, "出口 IP 探测失败") || !strings.Contains(detail, "127.0.0.1") {
		t.Fatalf("fallback must be named in audit detail, got %q", detail)
	}
	detailOK := switchToSlaveAuditDetail("https://master.example.com", true)
	if strings.Contains(detailOK, "出口 IP 探测失败") {
		t.Fatalf("successful probe must not add fallback note, got %q", detailOK)
	}
}
