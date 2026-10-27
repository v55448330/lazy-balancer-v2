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

// GET /metrics/history 的**全局分支**（无 rule_id，rule_id IS NULL 行）取值语义此前
// 无任何断言：per_ts 先按 timestamp 求和，再每桶取「末行样本」。两条语义都可被
// 静默改坏（SUM→MAX、ORDER BY DESC→ASC）而测试全绿：
//   - 同 timestamp 多行 → 返回其和（MAX 会少算）；
//   - 同一桶内多个 timestamp → 返回最后一条时间戳的行（累计口径），不是桶内求和、
//     也不是最早那条（ASC 会取错）。
//
// 桶宽取 interval=24h（120s/桶），使两个夹具桶稳定隔离。
func TestGetMetricsHistory_globalBranchSumsPerTimestampAndTakesLastSample(t *testing.T) {
	// 两个语义各自独立夹具（互不干扰），interval=1h → 5s 桶。
	seedAndRead := func(t *testing.T, rows func(seed func(time.Time, int64, int64))) map[int64][2]int64 {
		t.Helper()
		newMetricsTestDatabase(t)
		h := &Handlers{}
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/api/v1/metrics/history", h.GetMetricsHistory)
		rows(func(timestamp time.Time, requestsTotal, requests2xx int64) {
			if _, err := db.MetricsDB.Exec(
				`INSERT INTO metrics_history (rule_id, timestamp, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out)
				 VALUES (NULL, ?, ?, ?, 0, 0, 0, 0, 0)`,
				timestamp.Format("2006-01-02 15:04:05"), requestsTotal, requests2xx,
			); err != nil {
				t.Fatalf("seed global row: %v", err)
			}
		})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/history?interval=1h", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data []struct {
				Timestamp     time.Time `json:"timestamp"`
				RequestsTotal int64     `json:"requests_total"`
				Status2xx     int64     `json:"status_2xx"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.Data) == 0 {
			t.Fatalf("全局分支返回空: %s", rec.Body.String())
		}
		out := map[int64][2]int64{}
		for _, row := range resp.Data {
			out[row.Timestamp.Unix()] = [2]int64{row.RequestsTotal, row.Status2xx}
		}
		return out
	}

	// 语义 A：同一 timestamp 多行 → 该桶返回求和（SUM→MAX 会红）。
	t.Run("sums_rows_sharing_timestamp", func(t *testing.T) {
		at := time.Now().UTC().Add(-300 * time.Second).Truncate(5 * time.Second)
		got := seedAndRead(t, func(seed func(time.Time, int64, int64)) {
			seed(at, 5, 1)
			seed(at, 7, 2)
		})
		if len(got) != 1 {
			t.Fatalf("buckets=%v, want 1（同一 timestamp 的两行属于同一桶）", got)
		}
		for _, value := range got {
			if value[0] != 12 || value[1] != 3 {
				t.Fatalf("requests_total=%d 2xx=%d, want 12/3（同 timestamp 多行必须求和，不是取最大）", value[0], value[1])
			}
		}
	})

	// 语义 B：同一桶内多个 timestamp → 返回最后一条样本（DESC→ASC 会红）。
	t.Run("takes_last_sample_within_bucket", func(t *testing.T) {
		base := time.Now().UTC().Add(-300 * time.Second).Truncate(5 * time.Second)
		got := seedAndRead(t, func(seed func(time.Time, int64, int64)) {
			seed(base, 100, 10)
			seed(base.Add(2*time.Second), 200, 40)
		})
		if len(got) != 1 {
			t.Fatalf("buckets=%v, want 1（5s 桶内两个 timestamp 同行）", got)
		}
		for _, value := range got {
			if value[0] != 200 || value[1] != 40 {
				t.Fatalf("requests_total=%d 2xx=%d, want 200/40（桶内取最后一条 timestamp 的样本，既非最早行也非桶内求和）", value[0], value[1])
			}
		}
	})
}
