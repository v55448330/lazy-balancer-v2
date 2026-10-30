package services

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 执行时间口径（2026-10-30 裁定）：cert-job 动态行无独立运行轮次——任务监控
// 行的执行时间 = updated_at（最近状态变更），开始/结束同值、耗时 0；语义注明
// 随行 Description 下发（任务名 hover tooltip）。历史端点
// （handlers.certJobRunHistory）仍按 started=created_at/finished=updated_at
// 呈现完整区间（CertJobRunTimes 单源不动），两处语义差异是裁定口径不是漂移。
func TestCollectCertJobRows_runTimesUseUpdatedAt(t *testing.T) {
	setupIsolatedDB(t)
	const createdAt = "2020-01-01 08:00:00"
	const updatedAt = "2030-06-01 12:34:56"
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,created_at,updated_at)
		VALUES ('lb_tm_runtime','runtime.example.com','failed','CA 签发失败: boom',?,?)`, createdAt, updatedAt); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}

	rows, _ := collectCertJobRows()
	if len(rows) != 1 {
		t.Fatalf("cert 行数=%d, want 1", len(rows))
	}
	lr := rows[0].LastRun
	if lr == nil {
		t.Fatal("cert 行缺少 LastRun")
	}
	_, wantFinished, _ := CertJobRunTimes(createdAt, updatedAt)
	if wantFinished == "" {
		t.Fatal("CertJobRunTimes 未能解析 updated_at（夹具失效）")
	}
	if lr.StartedAt != wantFinished || lr.FinishedAt != wantFinished {
		t.Fatalf("执行时间 started=%q finished=%q, want 均=%q（updated_at）", lr.StartedAt, lr.FinishedAt, wantFinished)
	}
	if lr.DurationMs != 0 {
		t.Fatalf("耗时=%dms, want 0（动态行无独立运行轮次，时长无意义）", lr.DurationMs)
	}
	if !strings.Contains(rows[0].Description, "updated_at") {
		t.Fatalf("Description=%q, want 注明执行时间语义（最近状态变更 updated_at）", rows[0].Description)
	}
}

// 24h 成功/失败按当前 status（issued=成功、failed=失败）与 updated_at 窗内判定：
// 终态事件口径每行 ≤1；超窗行显示但不计数，非终态行不计数。
func TestCollectCertJobRows_terminal24hCounts(t *testing.T) {
	setupIsolatedDB(t)
	seed := func(ruleID, domain, status, offset string) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,updated_at)
			VALUES (?,?,?,datetime('now',`+offset+`))`, ruleID, domain, status); err != nil {
			t.Fatalf("seed %s: %v", ruleID, err)
		}
	}
	seed("lb_tm_ok2h", "ok2h.example.com", "issued", "'-2 hours'")
	seed("lb_tm_bad2h", "bad2h.example.com", "failed", "'-2 hours'")
	seed("lb_tm_ok30h", "ok30h.example.com", "issued", "'-30 hours'")
	seed("lb_tm_run2h", "run2h.example.com", "validating", "'-2 hours'")

	rows, _ := collectCertJobRows()
	byDomain := map[string]TaskInfo{}
	for _, r := range rows {
		byDomain[strings.TrimPrefix(r.Name, "ACME 签发 · ")] = r
	}
	cases := []struct {
		domain          string
		wantSucc, wantF int
	}{
		{"ok2h.example.com", 1, 0},
		{"bad2h.example.com", 0, 1},
		{"ok30h.example.com", 0, 0},
		{"run2h.example.com", 0, 0},
	}
	for _, tc := range cases {
		row, ok := byDomain[tc.domain]
		if !ok {
			t.Fatalf("行 %s 缺失: %+v", tc.domain, byDomain)
		}
		if row.Success24h != tc.wantSucc || row.Fail24h != tc.wantF {
			t.Fatalf("%s 24h=%d/%d, want %d/%d（当前 status + updated_at 窗内）",
				tc.domain, row.Success24h, row.Fail24h, tc.wantSucc, tc.wantF)
		}
	}
}
