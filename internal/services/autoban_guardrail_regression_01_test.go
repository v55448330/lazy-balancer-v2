package services

// 对直读配置显式校验（库值唯一真相铁律：无效值拒绝执行+显性报错，禁止
// 静默兜底）。threshold<=0 会让「count>=threshold」把全量候选收进名单；
// duration 非法时 autobanDurations 查表得 0 被当「永久」——候选全部落为
// 永久封禁条目；window<=0 让窗口计算失真。三者都必须在执行前拦下。

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// feedAndRun 前置：预置名单+喂一个候选 IP 进计数器+配置六列，跑一轮 Run。
func feedAndRun(t *testing.T, threshold, windowMin int, duration, scope string, dryRun bool) error {
	t.Helper()
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, threshold, windowMin, duration, scope, dryRun)
	// system=1 名单名唯一（部分唯一索引），内置预置行由 DB 初始化
	// 播种——这里按幂等语义复用，不再插入第二行。
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_ip_lists (name, entries, system) VALUES (?, '[]', 1)`, AutobanPresetListName); err != nil {
		t.Fatalf("seed preset list: %v", err)
	}
	// 2026-10-30 阶段 3 口径后非数值 token 不再计数，候选前置喂 CRS 形态 id。
	autobanObserveEvent("203.0.113.5", "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		return err
	}
	return nil
}

func TestRunAutobanCycle_invalidConfigRefusesExecution(t *testing.T) {
	tests := []struct {
		name       string
		threshold  int
		windowMin  int
		duration   string
		scope      string
		wantSubstr string
	}{
		{"threshold=0 拒绝执行", 0, 5, "1h", "all", "阈值须在 1-10000 之间"},
		{"window=0 拒绝执行", 100, 0, "1h", "all", "统计窗口须在 1-60 分钟之间"},
		{"duration 非法拒绝执行（不得落永久封禁）", 1, 5, "bogus", "all", "封禁时长取值无效"},
		{"scope 非法拒绝执行", 1, 5, "1h", "bogus", "统计口径取值无效"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := feedAndRun(t, tt.threshold, tt.windowMin, tt.duration, tt.scope, false)
			if err == nil {
				t.Fatal("无效配置必须拒绝执行（返回错误），得到 nil")
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("err=%v, want contain %q", err, tt.wantSubstr)
			}
			// 名单零写入：候选不得以任何形态（含永久条目）落库
			entries, _, err := AutobanListEntries()
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("拒绝执行的轮次不得写名单，entries=%+v", entries)
			}
		})
	}
}

// 回归形状：合法配置照常执行（护栏不得误伤正常轮）。
func TestRunAutobanCycle_validConfigStillExecutes(t *testing.T) {
	if err := feedAndRun(t, 1, 5, "24h", "all", false); err != nil {
		t.Fatalf("合法配置不得被护栏拦截: %v", err)
	}
	entries, _, err := AutobanListEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Value != "203.0.113.5" {
		t.Fatalf("entries=%+v, want 1 auto entry for 203.0.113.5", entries)
	}
	// 有时长枚举时条目必须带 expires_at（24h）——非永久形态
	if entries[0].ExpiresAt == "" {
		t.Fatal("24h 封禁条目必须带 expires_at")
	}
}
