package services

import (
	"context"
	"database/sql"
	"strconv"
	"testing"
	"time"
)

// 自动重签时间抖动固定向量表（2026-10-30 裁定）：jitter = FNV-1a32(rule_id) % 21600
// （0–6h，确定性）。前端镜像实现在 web/src/utils/certJobExpiry.ts
// certRenewalJitterSeconds，两侧持有同一份字面量向量（certJobExpiry.spec.ts）——
// 任一侧算法/模数漂移即两侧向量表同时红，跨栈口径永不静默分叉。
//
// 扫描入队判定（expires_at − 窗口 − jitter ≤ now）落在 certificates.go 的
// CheckExpiration/scanRenewalCandidates——该文件本轮归并行批次的 ACME 失败语义
// 代理（Main 协调），抖动门与对应扫描用例在其收尾后挂回；本文件只覆盖纯函数。
func TestCertRenewalJitterSeconds_vectors(t *testing.T) {
	cases := []struct {
		ruleID string
		want   int64
	}{
		{"", 1861},
		{"lb_tm_queued", 3393},
		{"web-frontend", 13088},
		{"规则-中文", 20819},
		{"rule-1", 7281},
		{"cluster-node-2", 15507},
		{"lb_restore_deploy_backoff", 15367},
	}
	for _, tc := range cases {
		if got := CertRenewalJitterSeconds(tc.ruleID); got != tc.want {
			t.Fatalf("CertRenewalJitterSeconds(%q)=%d, want %d（跨栈固定向量）", tc.ruleID, got, tc.want)
		}
	}
}

// 抖动值域 [0, 6h)：模数漂移（如误用 32 位原值）会在此暴露。
func TestCertRenewalJitterSeconds_bounds(t *testing.T) {
	for i := range 64 {
		ruleID := "rule-" + strconv.Itoa(i)
		got := CertRenewalJitterSeconds(ruleID)
		if got < 0 || got >= certRenewalJitterWindowSeconds {
			t.Fatalf("jitter(%q)=%d 越界 [0,%d)", ruleID, got, certRenewalJitterWindowSeconds)
		}
	}
}

// seedJitterGateJob 播种「有 expires_at、无证书材料」的 issued 行：无材料使
// 逐规则证书选择不命中，行落到 scanRenewalCandidates 的逐行 expires_at 闸门
// （有材料的行由 PEM 分支按实际寿命窗口判定，不入本闸门）。
func seedJitterGateJob(t *testing.T, database interface {
	Exec(string, ...any) (sql.Result, error)
}, ruleID, domain string, expiresAt time.Time) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?, 'jitter', ?, 'http', 8080, 1, 1, 'acme_dns')`, ruleID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at) VALUES (?, ?, 'issued', ?)`,
		ruleID, domain, expiresAt.UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatalf("seed job: %v", err)
	}
}

// 扫描侧抖动闸门（2026-10-30 裁定）：入队判据 = expires_at − renewalDays −
// jitter(rule_id) ≤ now，不足则本轮跳过。规则 rule-1 的抖动为 7281s（固定向量，
// <4h，保证用例边界都落在「窗口+6h」预筛可达范围内）。预筛按「窗口+抖动上界」
// 放宽、逐行闸门按各规则抖动收敛——两条在旧窗口外、新放宽区间内的行走向相反
// 结果，共同钉住「放宽准入 + 逐行闸门」的配合：早于自身抖动槽的行跳过，晚于
// 自身抖动槽的行入队（旧行为对这两行完全无感知）。
func TestCheckExpiration_renewalJitterGatesEnqueue(t *testing.T) {
	const window = 30 * 24 * time.Hour
	const jitter = int64(7281) // rule-1 固定向量

	cases := []struct {
		name      string
		extra     time.Duration // expires_at = now + 窗口 + extra
		wantRenew bool
	}{
		// 既有窗口内：无论抖动多大都照常入队（回归形状——不得破坏原口径）。
		{"legacy window interior", -time.Hour, true},
		// 放宽预筛准入后的两行：同一规则、同在旧窗口外、仅差 2 分钟，结果相反。
		// 抖动把入队时刻提前到「到期 − 窗口 − jitter」：早于自身抖动槽 60s 的行
		// 已到期（入队），晚于自身抖动槽 60s 的行未到（本轮跳过，下轮扫描进入）。
		{"within jitter offset (past own slot)", time.Duration(jitter-60) * time.Second, true},
		{"within jitter offset (before own slot)", time.Duration(jitter+60) * time.Second, false},
		// 抖动上界之外：SQL 预筛直接排除（行为与旧窗口外一致）。
		{"beyond jitter window", 7 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			setRenewalDays(t, database, 30)
			seedJitterGateJob(t, database, "rule-1", "jitter.example.com", time.Now().Add(window+tc.extra))

			jobs, _, err := (&CertificateService{}).CheckExpiration(context.Background())
			if err != nil {
				t.Fatalf("check expiration: %v", err)
			}
			if got := len(jobs) == 1; got != tc.wantRenew {
				t.Fatalf("candidates=%d, want renew=%v（expires_at=now+窗口%+v）", len(jobs), tc.wantRenew, tc.extra)
			}
		})
	}
}
