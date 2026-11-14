package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// GetSecurityOverview 在 MetricsDB==nil 时必须返回
// 空面板 200 而非 nil 解引用 panic——对齐家族口径
// （ListSecurityEvents / GetIPEventCount / GetRuleStageStats 同口径）。
func TestGetSecurityOverview_metricsDBNilReturnsEmptyPanel(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_crs_version (id, version, update_status) VALUES (1, 'v4.99.0', 'success')`); err != nil {
		t.Fatalf("seed crs version: %v", err)
	}

	saved := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = saved })

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                     `json:"code"`
		Data models.SecurityOverview `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.TodayBlocked != 0 || resp.Data.TodayDetected != 0 || len(resp.Data.Trend) != 0 {
		t.Fatalf("空面板应为零值: %+v", resp.Data)
	}
	if resp.Data.CRSVersion != "v4.99.0" || resp.Data.UpdateStatus != "success" {
		t.Fatalf("MetricsDB=nil 不得跳过主库 CRS 状态: %+v", resp.Data)
	}
}

func TestGetSecurityOverview_metricsDBNilPropagatesMainDBFailure(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	if _, err := db.DB.Exec(`DROP TABLE security_policies`); err != nil {
		t.Fatalf("drop policies: %v", err)
	}
	saved := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = saved })

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("主库查询失败必须 500，不得返回零面板: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
