package services

import (
	"fmt"
	"testing"
)

// 任务监控状态列词表=引擎执行语义三态（2026-10-22 用户裁定，取代旧「排队中/
// 已禁用」扩展值）：cert_jobs 的业务生命周期态（issued/waiting_ca/disabled…）
// 绝不进入任务状态列——活动工作项=运行中、终态成功=空闲、终态失败=失败、退役行=空闲
// （「已禁用」由业务文本承载）。
func TestCollectCertJobRows_statusColumnThreeStates(t *testing.T) {
	setupIsolatedDB(t)

	// Given 覆盖 cert_jobs 状态枚举的代表形态（活动各阶段/停车/终态/退役）。
	cases := []struct{ status, want string }{
		{"queued", "running"},
		{"pending", "running"},
		{"waiting_ca", "running"}, // 限流停车仍是未完成工作项；停车语义归业务文本，不得冒充第三态
		{"processing", "running"},
		{"creating_order", "running"},
		{"validating", "running"},
		{"downloading", "running"},
		{"downloaded", "idle"},
		{"issued", "idle"},
		{"failed", "failed"},
		{"disabled", "idle"},
	}
	for i, tc := range cases {
		seedCertJobRowForTaskMonitor(t, "lb_tm_vocab", fmt.Sprintf("vocab-%02d.example.com", i), tc.status)
	}

	// When 收集任务监控行。
	rows, _ := collectCertJobRows()
	byDomain := map[string]TaskInfo{}
	for _, r := range rows {
		byDomain[r.Name] = r
	}

	// Then 每行业务态按三态映射，且全表词表 ⊆ {idle,running,failed}。
	for i, tc := range cases {
		got, ok := byDomain["ACME 签发 · "+fmt.Sprintf("vocab-%02d.example.com", i)]
		if !ok {
			t.Fatalf("%s 行缺失: %+v", tc.status, rows)
		}
		if string(got.Status) != tc.want {
			t.Fatalf("%s 状态列=%s, want %s", tc.status, got.Status, tc.want)
		}
	}
	for _, r := range rows {
		if r.Status != TaskStatusRunning && r.Status != TaskStatusIdle && r.Status != TaskStatusFailed {
			t.Fatalf("状态列出现三态外取值 %q（行 %s）——业务生命周期态不得进入状态列", r.Status, r.Name)
		}
	}
}
