package taskengine

// 24h 分小时桶聚合（任务监控图表重构，2026-10-11 用户裁定方案 A）：
// 时间序列替代任务名柱状图——高频任务不再压制其他任务，且新增时间分布信息。
// 口径：配置时区墙面小时（engineNowStr 同基准，与 task_runs 存储串一致）。
//
// 桶键构造期望随生产侧改为墙面小时
// （time.Date 日历分量取整），并补时区形状三枚举
//   - 整小时偏移（+08:00 固定）——生产行为不变（回归形状）
//   - 非整小时偏移（+05:30）——Truncate(1h) 纪元取整会产出 :30 桶键，
//     与 strftime('%H:00:00') 墙面键永不相交 → 24 桶全零（原缺陷形状）
//   - DST 时区（Europe/Berlin）——桶键与 WHERE 界同锚点做绝对时长加减：
//     键位恒与 strftime 对齐；fall-back 重复墙时合并到后桶（计数不丢）、
//     spring-forward 消失墙时无行可落（无计数损失）

import (
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // 内嵌 tzdata：DST 形状用例不依赖宿主 zoneinfo（不得静默 skip）

	"lazy-balancer-v2/internal/db"
)

// runHourlySeriesShape 在指定时区下钉三断言：①24 桶键全为墙面小时
// （分钟=0，strftime 口径）；②首/末桶锚点（绝对时长加减）；③计数落桶。
func runHourlySeriesShape(t *testing.T, loc *time.Location) {
	t.Helper()
	old := engineLocPtr()
	SetLocation(loc)
	t.Cleanup(func() { SetLocation(old) })

	e := newTestEngine(t)
	now := time.Now().In(loc)
	// 期望锚点=墙面小时（修复后的生产口径；Truncate 在非整小时
	// 偏移时区下会产出 :30 分钟分量）
	curHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, loc)
	mk := func(h time.Time, status string) {
		if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, operator, status, started_at) VALUES ('t-x','t','auto','',?,?)`,
			status, h.Format("2006-01-02 15:04:05")); err != nil {
			t.Fatal(err)
		}
	}
	// 本小时 2 成功 1 失败；3 小时前 1 失败；25 小时前 1 成功（出窗不计）
	mk(curHour, "success")
	mk(curHour.Add(10*time.Minute), "success")
	mk(curHour.Add(20*time.Minute), "failed")
	mk(curHour.Add(-3*time.Hour), "failed")
	mk(curHour.Add(-25*time.Hour), "success")

	series := e.Stats24hHourlySeries()
	if len(series) != 24 {
		t.Fatalf("桶数=%d, want 24（now-23h..now 逐小时）", len(series))
	}
	// 桶键必须为墙面小时（分钟=0）——非整小时偏移时区下纪元 Truncate 产出
	// :30 键时，本断言与下方计数断言同时失守。
	for i, b := range series {
		if !strings.HasSuffix(b.Hour, ":00:00") {
			t.Fatalf("桶 %d=%s 非墙面小时键（分钟分量非 0，strftime 键永不相交）", i, b.Hour)
		}
	}
	// 首桶=now-23h，逐小时递增，末桶=当前小时
	first, _ := time.ParseInLocation("2006-01-02 15:04:05", series[0].Hour, loc)
	last, _ := time.ParseInLocation("2006-01-02 15:04:05", series[23].Hour, loc)
	if !first.Equal(curHour.Add(-23 * time.Hour)) {
		t.Fatalf("首桶=%s, want %s", series[0].Hour, curHour.Add(-23*time.Hour).Format("2006-01-02 15:04:05"))
	}
	if !last.Equal(curHour) {
		t.Fatalf("末桶=%s, want 当前小时 %s", series[23].Hour, curHour.Format("2006-01-02 15:04:05"))
	}
	// 计数落桶正确（行键由 strftime 产出——与桶键相交即对齐）
	if series[23].Success != 2 || series[23].Failed != 1 {
		t.Fatalf("本小时桶=%+v, want 2 成功 1 失败", series[23])
	}
	if series[20].Failed != 1 || series[20].Success != 0 {
		t.Fatalf("3 小时前桶=%+v, want 1 失败 0 成功", series[20])
	}
	// 空桶零填
	if series[21].Success != 0 || series[21].Failed != 0 {
		t.Fatalf("空桶=%+v, want 零填", series[21])
	}
}

func TestEngine_Stats24hHourlySeries(t *testing.T) {
	t.Run("整小时偏移时区", func(t *testing.T) {
		runHourlySeriesShape(t, time.FixedZone("CST", 8*3600))
	})
	t.Run("非整小时偏移时区(+05:30)", func(t *testing.T) {
		runHourlySeriesShape(t, time.FixedZone("IST", 5*3600+30*60))
	})
	t.Run("DST时区", func(t *testing.T) {
		berlin, err := time.LoadLocation("Europe/Berlin")
		if err != nil {
			t.Fatalf("加载 Europe/Berlin 失败（time/tzdata 已内嵌）: %v", err)
		}
		runHourlySeriesShape(t, berlin)
	})
}
