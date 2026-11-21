package handlers

// 切换从节点的出口 IP 探测失败时,切换审计必须追加点名——上报地址留空、
// 由主节点按注册来源地址落库，运维需要一条可见说明去确认访问地址。

import (
	"strings"
	"testing"
)

func TestSwitchToSlaveAuditDetail_outboundIPFallbackNoted(t *testing.T) {
	detail := switchToSlaveAuditDetail("https://master.example.com", false, 0, "")
	if !strings.Contains(detail, "出口 IP 探测失败") || !strings.Contains(detail, "注册来源地址") {
		t.Fatalf("fallback must be named in audit detail, got %q", detail)
	}
	detailOK := switchToSlaveAuditDetail("https://master.example.com", true, 0, "")
	if strings.Contains(detailOK, "出口 IP 探测失败") {
		t.Fatalf("successful probe must not add fallback note, got %q", detailOK)
	}
}
