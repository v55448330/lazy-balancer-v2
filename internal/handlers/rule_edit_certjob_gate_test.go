package handlers

// 规则编辑的证书任务守卫（ruleEditBlockingCertJobStatuses）行为钉：
// 状态集由 db.CertJobStatuses 单源派生，此前是写死的
// NOT IN ('issued','failed','disabled')——把「无 worker 在跑」的 waiting_ca
// （CA 冷却可达 1–3 小时）与 downloaded（部署退避，材料已在库）一起拦下，
// 冷却期改个名称也 409 死等；反向把 queued 误并入放行集又会让保存路径
// 重复入队（needJob/入队分支以「不存在非终态任务」为前提）。
// 两个方向此前都没有经 PUT /rules/:id 的行为钉。

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 单源断言：放行集与阻塞集的方向（HTTP 行为钉之外的就近门）。
func TestRuleEditBlockingCertJobStatuses_direction(t *testing.T) {
	blocking := ruleEditBlockingCertJobStatuses()
	for _, status := range []string{"queued", "pending"} {
		if !slices.Contains(blocking, status) {
			t.Errorf("%s 必须在阻塞集（worker 即将/可能取走，放行会重复入队）；got %v", status, blocking)
		}
	}
	for _, status := range []string{"issued", "failed", "disabled", "waiting_ca", "downloaded"} {
		if slices.Contains(blocking, status) {
			t.Errorf("%s 不得在阻塞集（放行侧：终态或长窗口无 worker）；got %v", status, blocking)
		}
	}
	// 派生闭合：阻塞集 ∪ 放行集 = 全域状态（新增状态默认阻塞，不得漏项）。
	nonBlocking := []string{"issued", "failed", "disabled", "waiting_ca", "downloaded"}
	if got := len(blocking) + len(nonBlocking); got != len(db.CertJobStatuses()) {
		t.Fatalf("阻塞+放行=%d, want %d（状态枚举漂移）", got, len(db.CertJobStatuses()))
	}
}

// 行为钉：waiting_ca/downloaded 的规则可保存（200），queued 仍 409。
func TestUpdateRule_saveGuard_certJobStatusMatrix(t *testing.T) {
	cases := []struct {
		name     string
		status   string
		wantCode int
	}{
		{"waiting_ca 放行（CA 冷却期改名称不得死等）", "waiting_ca", http.StatusOK},
		{"downloaded 放行（部署退避，材料已在库）", "downloaded", http.StatusOK},
		{"queued 仍阻塞（避免同一规则重复入队）", "queued", http.StatusConflict},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(services.SetCertDirForTest(t.TempDir()))
			caddyID := fmt.Sprintf("lb_saveguard_%d", index)
			domain := fmt.Sprintf("saveguard%d.example.test", index)
			harness := newUpdateAuditRuleHandlers(t, caddyID, 0, false)
			seedACMEManualSwitchFixture(t, caddyID, domain, tc.status)
			// 放行分支会走保存路径的证书任务收敛（读/写队列状态），与同族
			// 用例一致地启动一个空实现的队列。
			services.ResetCAQueueManagerForTest()
			services.InitCAQueueManager(func() error { return nil }, t.TempDir())
			services.GetCAQueueManager().Start()
			t.Cleanup(services.ResetCAQueueManagerForTest)

			// 只改名称：不触发 ACME 脱离/禁用路径，直达主 UPDATE 的守卫谓词。
			response := putUpdateRule(t, harness, caddyID, `{"name":"after"}`)

			if response.Code != tc.wantCode {
				t.Fatalf("status=%d body=%s, want %d（cert_jobs.status=%s）",
					response.Code, response.Body.String(), tc.wantCode, tc.status)
			}
			if tc.wantCode == http.StatusConflict {
				var tlsSource string
				if err := db.DB.QueryRow("SELECT tls_source FROM lb_rules WHERE caddy_id=?", caddyID).Scan(&tlsSource); err != nil {
					t.Fatalf("read rule: %v", err)
				}
				if tlsSource != "acme_dns" {
					t.Fatalf("tls_source=%q, want acme_dns（409 早退必须回滚）", tlsSource)
				}
			}
		})
	}
}
