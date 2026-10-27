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

// GET /metrics/history 密集单规则指标必须分桶（≤720），每桶取 timestamp
// 最大且同刻 id 最大的行；响应保持既有 Data 数组契约。
func TestGetMetricsHistory_bucketsDenseRowsToCap(t *testing.T) {
	newMetricsTestDatabase(t)
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/metrics/history", h.GetMetricsHistory)

	const bucketSeconds int64 = 5
	type sample struct {
		id        int64
		timestamp time.Time
		requests  int64
	}
	samples := make([]sample, 0, 1501)
	seed := func(timestamp time.Time, requests int64) {
		t.Helper()
		result, err := db.MetricsDB.Exec(
			`INSERT INTO metrics_history (rule_id, timestamp, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out)
			 VALUES ('dense-rule', ?, ?, ?, 0, 0, 0, 0, 0)`,
			timestamp.Format("2006-01-02 15:04:05"), requests, requests)
		if err != nil {
			t.Fatalf("seed timestamp=%s: %v", timestamp, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("seed id: %v", err)
		}
		samples = append(samples, sample{id: id, timestamp: timestamp, requests: requests})
	}

	// Given：1h 内 1500 行（2s 间隔），另在已有时间戳补一条更高 id 行。
	base := time.Now().UTC().Add(-3000 * time.Second).Truncate(time.Duration(bucketSeconds) * time.Second)
	for i := range 1500 {
		seed(base.Add(time.Duration(i*2)*time.Second), int64(i*10+1))
	}
	seed(base.Add(1500*time.Second), 900001)

	// 独立按契约计算每个桶应选中的样本：先比 timestamp，再比 id。
	expected := map[int64]sample{}
	rowsAtTimestamp := map[int64]int{}
	for _, candidate := range samples {
		bucketStart := candidate.timestamp.Unix() / bucketSeconds * bucketSeconds
		current, ok := expected[bucketStart]
		if !ok || candidate.timestamp.After(current.timestamp) ||
			(candidate.timestamp.Equal(current.timestamp) && candidate.id > current.id) {
			expected[bucketStart] = candidate
		}
		rowsAtTimestamp[candidate.timestamp.Unix()]++
	}
	if len(expected) < 2 {
		t.Fatalf("测试夹具仅覆盖 %d 个桶，want >=2", len(expected))
	}
	hasSameTimestampRows := false
	for _, count := range rowsAtTimestamp {
		hasSameTimestampRows = hasSameTimestampRows || count > 1
	}
	if !hasSameTimestampRows {
		t.Fatal("测试夹具缺少同 timestamp 双行（id 决胜门失效）")
	}

	// When
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/history?interval=1h&rule_id=dense-rule", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			Timestamp     time.Time `json:"timestamp"`
			RequestsTotal int64     `json:"requests_total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Then：桶数受限且逐桶精确等于末行样本，不是仅检查非空/数量。
	if len(resp.Data) > metricsHistoryBuckets {
		t.Fatalf("metrics history rows=%d, want ≤%d（密集窗必须分桶）", len(resp.Data), metricsHistoryBuckets)
	}
	if len(resp.Data) != len(expected) {
		t.Fatalf("metrics history rows=%d, want %d（每个有样本桶恰好一行）", len(resp.Data), len(expected))
	}
	seen := map[int64]bool{}
	for _, row := range resp.Data {
		bucketStart := row.Timestamp.Unix()
		want, ok := expected[bucketStart]
		if !ok {
			t.Fatalf("返回意外桶 %s", row.Timestamp)
		}
		if seen[bucketStart] {
			t.Fatalf("桶 %s 返回重复行", row.Timestamp)
		}
		seen[bucketStart] = true
		if row.RequestsTotal != want.requests {
			t.Errorf("桶 %s requests_total=%d, want %d（timestamp 最大且同刻 id 最大行）", row.Timestamp, row.RequestsTotal, want.requests)
		}
	}
}

// GET /rules/:caddy_id/metrics-history 披露桶宽，并按每桶末行采样；
// 少量独立种子同时覆盖 timestamp 决胜与同刻 id 决胜。
func TestGetRuleMetricsHistory_bucketWidthAndLastSample(t *testing.T) {
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('dense-rule', 'dense', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	const bucketSeconds int64 = 5
	base := time.Now().UTC().Add(-30 * time.Second).Truncate(time.Duration(bucketSeconds) * time.Second)
	seeds := []struct {
		offset   time.Duration
		requests int64
	}{
		{1 * time.Second, 100},
		{2 * time.Second, 101}, // 第一桶 timestamp 较大，应选此行。
		{7 * time.Second, 200},
		{7 * time.Second, 201}, // 第二桶 timestamp 相同，id 较大，应选此行。
	}
	for _, seed := range seeds {
		timestamp := base.Add(seed.offset)
		if _, err := db.MetricsDB.Exec(
			`INSERT INTO metrics_history (rule_id, timestamp, requests_total, requests_2xx)
			 VALUES ('dense-rule', ?, ?, ?)`,
			timestamp.Format("2006-01-02 15:04:05"), seed.requests, seed.requests); err != nil {
			t.Fatalf("seed timestamp=%s: %v", timestamp, err)
		}
	}

	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/metrics-history", h.GetRuleMetricsHistory)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rules/dense-rule/metrics-history?range=1h", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			BucketIntervalSeconds int `json:"bucket_interval_seconds"`
			Rows                  []struct {
				Timestamp     string `json:"timestamp"`
				RequestsTotal int64  `json:"requests_total"`
			} `json:"rows"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.BucketIntervalSeconds != int(bucketSeconds) {
		t.Fatalf("bucket_interval_seconds=%d, want %d", resp.Data.BucketIntervalSeconds, bucketSeconds)
	}
	if len(resp.Data.Rows) != 2 {
		t.Fatalf("rows=%d, want 2（两个有样本桶）body=%s", len(resp.Data.Rows), rec.Body.String())
	}
	for i, want := range []struct {
		timestamp string
		requests  int64
	}{
		{base.Format("2006-01-02 15:04:05"), 101},
		{base.Add(5 * time.Second).Format("2006-01-02 15:04:05"), 201},
	} {
		row := resp.Data.Rows[i]
		if row.Timestamp != want.timestamp || row.RequestsTotal != want.requests {
			t.Errorf("row[%d]={timestamp:%q requests_total:%d}, want {%q %d}（末行及同刻 id 决胜）",
				i, row.Timestamp, row.RequestsTotal, want.timestamp, want.requests)
		}
	}
}
