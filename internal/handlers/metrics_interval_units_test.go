package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// Review66-Head 发现 ①（2026-10-03 用户裁定核实后全修）：m 单位漏乘 60——30m
// 窗口被算成 30s，桶宽钳位 1s，升序 LIMIT 720 保留最旧桶，静默丢弃最近数据。
// SYS-R1（第 69 轮）：双手写解析收敛为 parseMetricsInterval 单源，本测试改靶
// 并扩为 modifier/seconds 双输出一致性钉（U8a-P4-1 分桶粒度=窗口秒数/720 必须
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
	_ = fmt.Sprint()
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
}
