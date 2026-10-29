package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 发现 ①（2026-10-03 用户裁定核实后全修）：m 单位漏乘 60——30m
// 窗口被算成 30s，桶宽钳位 1s，升序 LIMIT 720 保留最旧桶，静默丢弃最近数据。
// 双手写解析收敛为 parseMetricsInterval 单源，本测试改靶
// 并扩为 modifier/seconds 双输出一致性钉（分桶粒度=窗口秒数/720 必须
// 对应 SQL modifier，单源后编译期保证）。

func TestParseMetricsInterval_modifierSecondsAgreement(t *testing.T) {
	cases := []struct {
		in           string
		wantModifier string
		wantSeconds  int64
	}{
		{"30m", "-30 minutes", 1800},
		{"10080m", "-10080 minutes", 604800},
		{"10081m", "-10080 minutes", 604800}, // F9：分钟上限 7×24×60 钳位
		{"2h", "-2 hours", 7200},
		{"168h", "-168 hours", 604800},
		{"169h", "-168 hours", 604800}, // F9：小时上限 7×24 钳位
		{"7d", "-7 days", 604800},
		{"8d", "-7 days", 604800}, // F9：天上限 7 钳位
		{"", "-1 hours", 3600},
		{"garbage", "-1 hours", 3600},
		{"10x", "-1 hours", 3600},
		{" 6H ", "-6 hours", 21600}, // 大小写/空白归一
		// 非正值（Atoi 可解析的负数与 0）回退默认窗口——不得拼出
		// 非法/零长 modifier 或负桶宽。
		{"-5h", "-1 hours", 3600},
		{"-1d", "-1 hours", 3600},
		{"-30m", "-1 hours", 3600},
		{"0h", "-1 hours", 3600},
		{"0d", "-1 hours", 3600},
		{"0m", "-1 hours", 3600},
	}
	for _, c := range cases {
		modifier, seconds := parseMetricsInterval(c.in)
		if modifier != c.wantModifier || seconds != c.wantSeconds {
			t.Errorf("parseMetricsInterval(%q)=(%q,%d), want (%q,%d)（modifier 与窗口秒数同源同上限）", c.in, modifier, seconds, c.wantModifier, c.wantSeconds)
		}
	}
}

// 端到端形状：30m 窗口 1500 行（2s 间隔，最新行贴近 now）→ 分桶后必须
// 覆盖到最近（最新桶时间戳在 60s 内）——今日返回最旧 720 桶（RED）。
func TestGetMetricsHistory_miniteWindowKeepsRecentData(t *testing.T) {
	newMetricsTestDatabase(t)
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/metrics/history", h.GetMetricsHistory)
	for i := 0; i < 1500; i++ {
		ts := time.Now().UTC().Add(-time.Duration(i*2) * time.Second).Format("2006-01-02 15:04:05")
		if _, err := db.MetricsDB.Exec(
			`INSERT INTO metrics_history (rule_id, timestamp, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out)
			 VALUES (NULL, ?, ?, ?, 0, 0, 0, 0, 0)`, ts, 1500-i, 1500-i); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/history?interval=30m", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			Timestamp time.Time `json:"timestamp"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) == 0 || len(resp.Data) > 720 {
		t.Fatalf("rows=%d, want 1..720", len(resp.Data))
	}
	last := resp.Data[len(resp.Data)-1].Timestamp
	if time.Since(last) > 60*time.Second {
		t.Fatalf("最新桶 %v 距 now %v——30m 窗口不得静默丢弃最近数据（最旧 720 桶形态）", last, time.Since(last))
	}
	// 窗口覆盖门：桶宽向下取整（1800/720=2）会只覆盖 1440s，最旧段静默缺失
	// 20%。上取整（3s）后最旧桶起点必须落在 now-30m 的一个桶宽内。
	windowStart := time.Now().UTC().Add(-30 * time.Minute)
	if delta := resp.Data[0].Timestamp.Sub(windowStart); delta < -5*time.Second || delta > 5*time.Second {
		t.Fatalf("最旧桶 %v 距窗口起点 %v 偏差 %v——非 720 整除窗口必须覆盖全程", resp.Data[0].Timestamp, windowStart, delta)
	}
}

// 24h/7d 整除窗口（720×bucket 恰等于窗长）的覆盖契约：最旧数据桶起点必须
// 落在「窗口起点+首样本间隔」的一个桶宽内（24h=120s、7d=840s），最新桶不得
// 被升序 LIMIT 截掉。窗口起点恰对齐桶界时窗口内桶数=720+1，LIMIT 720 恒截
// 掉最旧的部分桶——覆盖起点最多再偏 1 个桶宽（见 metricsHistoryBuckets
// 注释）；本断言按该契约放行两种对齐形态，同时钉死「桶宽向下取整丢最旧段」
// 与「升序 LIMIT 只留最旧 720 桶」两类真实回归（旧 30m 用例只覆盖分钟窗口）。
func TestGetMetricsHistory_dayWeekWindowsKeepOldestBucketWithinOneBucketWidth(t *testing.T) {
	for _, tc := range []struct {
		interval     string
		window       time.Duration
		bucketWidth  time.Duration
		seedInterval time.Duration
	}{
		{"24h", 24 * time.Hour, 120 * time.Second, 15 * time.Minute},
		{"7d", 7 * 24 * time.Hour, 840 * time.Second, 30 * time.Minute},
	} {
		t.Run(tc.interval, func(t *testing.T) {
			newMetricsTestDatabase(t)
			h := &Handlers{}
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.GET("/api/v1/metrics/history", h.GetMetricsHistory)
			now := time.Now().UTC()
			for ts := now.Add(-tc.window).Add(tc.seedInterval); ts.Before(now); ts = ts.Add(tc.seedInterval) {
				if _, err := db.MetricsDB.Exec(
					`INSERT INTO metrics_history (rule_id, timestamp, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out)
					 VALUES ('oldest-rule', ?, 1, 1, 0, 0, 0, 0, 0)`, ts.Format("2006-01-02 15:04:05")); err != nil {
					t.Fatalf("seed row: %v", err)
				}
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/history?rule_id=oldest-rule&interval="+tc.interval, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var resp struct {
				Data []struct {
					Timestamp time.Time `json:"timestamp"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if len(resp.Data) == 0 || len(resp.Data) > metricsHistoryBuckets {
				t.Fatalf("rows=%d, want 1..%d", len(resp.Data), metricsHistoryBuckets)
			}
			windowStart := now.Add(-tc.window)
			// 最旧数据桶起点=floor(首样本/桶宽)×桶宽 ∈ (窗口起点+首样本间隔-桶宽,
			// 窗口起点+首样本间隔]；对齐退化再让 1 个桶宽（最旧部分桶被截）。
			delta := resp.Data[0].Timestamp.Sub(windowStart)
			if delta <= 0 || delta > tc.seedInterval+tc.bucketWidth {
				t.Fatalf("最旧桶 %v 距窗口起点 %v 偏差 %v——覆盖起点必须=最旧数据桶起点（对齐退化至多+1 桶宽 %s）", resp.Data[0].Timestamp, windowStart, delta, tc.bucketWidth)
			}
			// 最新端也不得截断（升序输出取最旧 720 桶的旧形态）。
			if newest := now.Sub(resp.Data[len(resp.Data)-1].Timestamp); newest > tc.seedInterval+tc.bucketWidth {
				t.Fatalf("最新桶距 now %v——升序 LIMIT 不得丢弃最近数据", newest)
			}
		})
	}
}
