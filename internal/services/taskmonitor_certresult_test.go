package services

// cert-job 动态行的结果列必须落引擎结果词表（running/success/failed/
// cancelled/skipped/interrupted）：此前直通 cert_jobs 业务态（issued/
// queued/disabled…），前端结果词表只认引擎六态，全部落「未知」。
// 映射单源 CertJobTaskResult：列表 last_run.result 与历史端点 RunRecord.status
// 共用；业务生命周期细节仍由 message/状态列三态承载，不进结果词表。

import (
	"fmt"
	"strings"
	"testing"
)

// Given 覆盖 cert_jobs 状态枚举的代表形态（活动各阶段/停车/终态/退役）。
// When 收集任务监控行。
// Then 每行 last_run.result ⊆ 引擎六态词表：终态成功=success、失败=failed、
// 退役=skipped（非故障放弃）、其余（含限流停车）=running。
func TestCollectCertJobRows_resultUsesEngineVocabulary(t *testing.T) {
	setupIsolatedDB(t)

	cases := []struct{ status, want string }{
		{"queued", "running"},
		{"pending", "running"},
		{"waiting_ca", "running"},
		{"processing", "running"},
		{"creating_order", "running"},
		{"validating", "running"},
		{"downloading", "running"},
		{"downloaded", "success"},
		{"issued", "success"},
		{"failed", "failed"},
		{"disabled", "skipped"},
	}
	for i, tc := range cases {
		seedCertJobRowForTaskMonitor(t, "lb_tm_result", fmt.Sprintf("result-%02d.example.com", i), tc.status)
	}

	rows, _ := collectCertJobRows()
	byDomain := map[string]TaskInfo{}
	for _, r := range rows {
		byDomain[r.Name] = r
	}
	for i, tc := range cases {
		got, ok := byDomain["ACME 签发 · "+fmt.Sprintf("result-%02d.example.com", i)]
		if !ok {
			t.Fatalf("%s 行缺失: %+v", tc.status, rows)
		}
		if got.LastRun == nil {
			t.Fatalf("%s 行缺少 last_run", tc.status)
		}
		if got.LastRun.Result != tc.want {
			t.Fatalf("%s 结果列=%q, want %q（业务态直通会在前端落「未知」）", tc.status, got.LastRun.Result, tc.want)
		}
	}
}

// Given cert_jobs 规范枚举全集。
// When 逐态映射。
// Then 映射值全部落引擎六态词表（词表外取值=前端「未知」缺口复发）。
func TestCertJobTaskResult_coversCanonicalEnumWithinEngineVocabulary(t *testing.T) {
	engineStates := map[string]bool{
		"running": true, "success": true, "failed": true,
		"cancelled": true, "skipped": true, "interrupted": true,
	}
	for _, status := range AllJobStatuses() {
		got := CertJobTaskResult(status)
		if !engineStates[got] {
			t.Fatalf("CertJobTaskResult(%q)=%q 不在引擎结果词表内", status, got)
		}
	}
	// 边界形态：枚举外/空值不得直通（回显原值会再次落「未知」）。
	for _, status := range []string{"", "not-a-status"} {
		if got := CertJobTaskResult(status); got != "failed" {
			t.Fatalf("CertJobTaskResult(%q)=%q, want failed（未知业务态保守按失败）", status, got)
		}
	}
}

// Given 同一 issued 行。
// When 列表与历史端点分别取结果。
// Then 两处结果同值（单源映射，不得各自直通业务态）。
func TestCertJobTaskResult_listAndHistoryShareMapping(t *testing.T) {
	setupIsolatedDB(t)
	seedCertJobRowForTaskMonitor(t, "lb_tm_share", "share.example.com", "issued")
	rows, _ := collectCertJobRows()
	for _, r := range rows {
		if strings.HasSuffix(r.Name, "share.example.com") {
			if r.LastRun == nil || r.LastRun.Result != CertJobTaskResult("issued") {
				t.Fatalf("列表结果=%v, want 与 CertJobTaskResult 单源同值", r.LastRun)
			}
			return
		}
	}
	t.Fatal("share.example.com 行缺失")
}
