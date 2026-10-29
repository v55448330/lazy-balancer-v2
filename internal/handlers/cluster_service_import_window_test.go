package handlers

import (
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// 导入窗口内的 Caddy 启停必须 409 fast-fail：导入会话自 begin 到 close() 全程
// 持 caddyOpMu，无门时主节点票据调用 60s 超时判失败、从节点锁释放后仍执行，
// 双向审计相反且终态不可知。窗口外同一票据走原路径（不可达 admin → 500），
// 证明门只收敛窗口内形态。
func TestClusterServiceControl_caddyAction409DuringImportWindow(t *testing.T) {
	setupClusterServiceControlDB(t)
	const clusterToken = "lb_cluster_ctl-import-window"
	seedControlNode(t, clusterToken, nil)
	ticket := issueControlTicketOnTestDB(t, 21, clusterToken, models.ClusterServiceActionStartCaddy)
	becomeSlave(t, 21, clusterToken)
	// admin 指向不可达地址：若门失效走到执行层，结果是 500 而非 409（钉住
	// 「门先于取锁」——不真持锁，避免回归形态退化为测试死锁）。
	_, router := newSlaveTestHandler(&config.Config{CaddyAdminURL: "http://127.0.0.1:1"})

	closeWindow := beginImportWindowForTest(t)
	busy := postServiceControl(router, models.ClusterServiceActionStartCaddy, ticket)
	closeWindow()

	if busy.Code != http.StatusConflict {
		t.Fatalf("导入窗口内 status=%d body=%s, want 409", busy.Code, busy.Body.String())
	}
	if !strings.Contains(busy.Body.String(), "配置导入进行中") {
		t.Fatalf("body=%s, want 409 文案点名配置导入进行中", busy.Body.String())
	}

	free := postServiceControl(router, models.ClusterServiceActionStartCaddy, ticket)
	if free.Code != http.StatusInternalServerError {
		t.Fatalf("窗口外 status=%d body=%s, want 500（票据有效、admin 不可达）", free.Code, free.Body.String())
	}
}
