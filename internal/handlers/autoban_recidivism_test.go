package handlers

// 自动封禁累犯记录端点钉（面板「累犯升级」统计的下钻弹框数据源）：
//   GET    /security/autoban/recidivism 全员可读；按 offense_count 降序、
//          identity 升序；空表序列化为 []（不是 null）。
//   DELETE /security/autoban/recidivism 重置全部累犯历史（无条件清空，
//          幂等——重复调用保持空表并返回成功）；主节点门在 handler 内；
//          显式审计「重置」；不影响已生效封禁条目（重置只清历史记账）。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func newAutobanRecidivismRouter(t *testing.T) *gin.Engine {
	t.Helper()
	router := newAutobanTestEnv(t)
	router.GET("/security/autoban/recidivism", (&Handlers{}).GetAutobanRecidivism)
	router.DELETE("/security/autoban/recidivism", (&Handlers{}).ResetAutobanRecidivism)
	return router
}

func seedRecidivismTestRows(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES
		('45.33.32.10', 2, '2026-11-14 09:00:00', '24h'),
		('2606:4700:abcd:1234::', 3, '2026-11-15 10:00:00', 'permanent'),
		('45.33.32.11', 2, '2026-11-13 08:00:00', '24h'),
		('198.51.100.7', 1, '2026-11-12 07:00:00', '1h')`); err != nil {
		t.Fatalf("seed recidivism: %v", err)
	}
}

type recidivismDocRow struct {
	Identity          string `json:"identity"`
	OffenseCount      int    `json:"offense_count"`
	LastBanAt         string `json:"last_ban_at"`
	EscalatedDuration string `json:"escalated_duration"`
}

// Given 累犯表四行（计数 3/2/2/1，含并列）。
// When GET /security/autoban/recidivism。
// Then 200 信封；四列逐行齐备；offense_count 降序、identity 升序（并列按身份）。
func TestAutobanRecidivism_getListsRowsOrdered(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)

	rec := getRequest(t, router, "/security/autoban/recidivism")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Records []recidivismDocRow `json:"records"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v body=%s", err, rec.Body.String())
	}
	if resp.Code != 0 {
		t.Fatalf("code=%d body=%s", resp.Code, rec.Body.String())
	}
	want := []recidivismDocRow{
		{Identity: "2606:4700:abcd:1234::", OffenseCount: 3, LastBanAt: "2026-11-15 10:00:00", EscalatedDuration: "permanent"},
		{Identity: "45.33.32.10", OffenseCount: 2, LastBanAt: "2026-11-14 09:00:00", EscalatedDuration: "24h"},
		{Identity: "45.33.32.11", OffenseCount: 2, LastBanAt: "2026-11-13 08:00:00", EscalatedDuration: "24h"},
		{Identity: "198.51.100.7", OffenseCount: 1, LastBanAt: "2026-11-12 07:00:00", EscalatedDuration: "1h"},
	}
	if len(resp.Data.Records) != len(want) {
		t.Fatalf("records=%+v, want %d rows", resp.Data.Records, len(want))
	}
	for i, w := range want {
		if resp.Data.Records[i] != w {
			t.Fatalf("row[%d]=%+v, want %+v（offense_count 降序 + identity 升序）", i, resp.Data.Records[i], w)
		}
	}
}

// Given 空累犯表。
// When GET。
// Then records 必须是 []（字节级判定——契约是数组，null 会让前端 .map 崩）。
func TestAutobanRecidivism_getEmptySerializesAsArray(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	rec := getRequest(t, router, "/security/autoban/recidivism")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"records":[]`) {
		t.Fatalf("empty records must serialize as [], body=%s", rec.Body.String())
	}
}

// Given 累犯表有行 + 自动封禁名单有生效条目。
// When DELETE /security/autoban/recidivism。
// Then 200；表清空；审计「重置」留痕；封禁条目不受影响（重置只清历史记账）。
func TestAutobanRecidivism_resetClearsHistoryAndAudits(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)
	seedAutobanListEntries(t, `[{"value":"45.33.32.10","remark":"auto","expires_at":"2099-01-01 00:00:00"}]`)

	rec := deleteRequest(t, router, "/security/autoban/recidivism")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&n); err != nil {
		t.Fatalf("count recidivism: %v", err)
	}
	if n != 0 {
		t.Fatalf("reset must clear all rows, got %d", n)
	}
	if got := countAuditRows(t, "重置", "累犯记录"); got != 1 {
		t.Fatalf("audit rows=%d, want 1（重置/累犯记录）", got)
	}
	entries := readAutobanListEntries(t, autobanPresetID(t))
	if len(entries) != 1 || entries[0].Value != "45.33.32.10" {
		t.Fatalf("reset must not touch ban list entries, got %+v", entries)
	}
}

// Given 空表（或已重置过一次）。
// When 重复 DELETE。
// Then 幂等：仍 200、表恒空（无条件清空语义，与 unbind 同族）。
func TestAutobanRecidivism_resetIdempotentOnEmpty(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	for i := range 2 {
		rec := deleteRequest(t, router, "/security/autoban/recidivism")
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d status=%d body=%s", i+1, rec.Code, rec.Body.String())
		}
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&n); err != nil {
		t.Fatalf("count recidivism: %v", err)
	}
	if n != 0 {
		t.Fatalf("table must stay empty, got %d", n)
	}
}

// Given 文档示例与实现。
// When 对照 GET 响应顶层键与行键。
// Then 示例键集与 handler 事实一致（records/四列），不漂移。
func TestAutobanRecidivism_docExampleMatchesImplementation(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)
	rec := getRequest(t, router, "/security/autoban/recidivism")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp models.APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	payload, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data must be object, got %T", resp.Data)
	}
	if _, ok := payload["records"]; !ok {
		t.Fatalf("data keys=%v, want records", payload)
	}
	example := docResponseExample(t, "GET /security/autoban/recidivism")
	if _, ok := example["records"]; !ok {
		t.Fatalf("doc example keys=%v, want records", example)
	}
	rows, ok := example["records"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatalf("doc example records must be non-empty array, got %v", example["records"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("doc example row must be object, got %T", rows[0])
	}
	for _, key := range []string{"identity", "offense_count", "last_ban_at", "escalated_duration"} {
		if _, ok := row[key]; !ok {
			t.Fatalf("doc example row lacks %s: %v", key, row)
		}
	}
}
