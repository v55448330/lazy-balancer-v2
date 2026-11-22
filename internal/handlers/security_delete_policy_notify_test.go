package handlers

// 删除安全策略的通知事件必须携带策略名：名称读取此前排在两条 DELETE 之后，
// 行已不存在 → 事件恒回落「#id」，用户看到的通知与审计失去可读标识。

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

func TestDeleteSecurityPolicy_notifyEventCarriesPolicyName(t *testing.T) {
	withIsolatedGlobal(t)
	setupSecurityPolicyTestDB(t)
	h := newFakeCaddyHandlers(t)
	oldPublish := notifyPublish
	var events []notify.Event
	notifyPublish = func(evt notify.Event) { events = append(events, evt) }
	t.Cleanup(func() { notifyPublish = oldPublish })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.DELETE("/security/policies/:id", h.DeleteSecurityPolicy)

	res, err := db.DB.Exec(`INSERT INTO security_policies (name) VALUES ('待删策略')`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	recorder := deleteRequest(t, router, fmt.Sprintf("/security/policies/%d", id))
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var found bool
	for _, evt := range events {
		if evt.Type != notify.EvtPolicyChanged {
			continue
		}
		found = true
		if got := evt.Fields["3"]; got != "待删策略" {
			t.Fatalf("事件策略名=%q, want 待删策略（名称须在删除前读取）", got)
		}
	}
	if !found {
		t.Fatalf("未发布 %s 事件: %v", notify.EvtPolicyChanged, events)
	}
}

// 源序钉测：名称读取必须先于两条 DELETE。行为测试在文件库 WAL 下会因
// db.DB 连接池读到「未提交删除」的旧快照而偶然通过——只有源序能钉住不依赖
// 快照隔离的正确实现（共享缓存/单连接形态下后置读恒空）。
func TestDeleteSecurityPolicy_readsPolicyNameBeforeDeletes(t *testing.T) {
	source, err := os.ReadFile("security.go")
	if err != nil {
		t.Fatalf("read security.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func (h *Handlers) DeleteSecurityPolicy(")
	if start < 0 {
		t.Fatal("DeleteSecurityPolicy 未找到")
	}
	body := text[start:]
	if next := strings.Index(body[1:], "\nfunc "); next >= 0 {
		body = body[:next+1]
	}
	nameRead := strings.Index(body, "SELECT COALESCE(name,'')")
	deletePolicy := strings.Index(body, "DELETE FROM security_policies")
	deleteBindings := strings.Index(body, "DELETE FROM security_policy_bindings")
	if nameRead < 0 || deletePolicy < 0 || deleteBindings < 0 {
		t.Fatalf("缺少名称读取或 DELETE 语句（name=%d policy=%d bindings=%d）", nameRead, deletePolicy, deleteBindings)
	}
	if nameRead > deletePolicy || nameRead > deleteBindings {
		t.Fatalf("名称读取位置=%d 必须在两条 DELETE（policy=%d bindings=%d）之前", nameRead, deletePolicy, deleteBindings)
	}
}
