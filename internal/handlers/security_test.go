package handlers

import (
	"encoding/json"

	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// SLB9-6(第 9 轮审计):GetCRSInfo/GetIP2RegionInfo 对齐 SC-11——仅行缺失
// (ErrNoRows)合法回落默认值,真实 DB 故障 500 可见(此前一律吞为默认)。
func TestGetCRSInfo_dbFailureReturns500(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 换坏库:关掉真库换一个无表库使查询报错(非 ErrNoRows)
	bad, err := sql.Open("sqlite", t.TempDir()+"/bad.db")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	oldDB := db.DB
	db.DB = bad
	t.Cleanup(func() { db.DB = oldDB })
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.GetCRSInfo(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("CRS status=%d, want 500 on real DB failure", w.Code)
	}
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	h.GetIP2RegionInfo(c2)
	if w2.Code != http.StatusInternalServerError {
		t.Fatalf("IP2Region status=%d, want 500 on real DB failure", w2.Code)
	}
}

// IP 弹框增强(第 20 轮批准):近 30 天该 IP 事件计数——索引范围 COUNT。
func TestGetIPEventCount(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 种子:2 条 30 天内 + 1 条 40 天前(metrics 库)
	db.MetricsDB.Exec(`INSERT INTO security_events (event_time,action,client_ip,rule_caddy_id) VALUES
		(datetime('now','-1 day'),'blocked','1.2.3.4','r1'),
		(datetime('now','-2 day'),'logged','1.2.3.4','r1'),
		(datetime('now','-40 day'),'blocked','1.2.3.4','r1'),
		(datetime('now','-1 day'),'blocked','5.6.7.8','r1')`)
	router := gin.New()
	router.GET("/security/events/count", h.GetIPEventCount)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/events/count?ip=1.2.3.4", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Count int `json:"count"`
		} `json:"data"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.Count != 2 {
		t.Fatalf("count=%d, want 2 (30-day window excludes 40-day-old)", resp.Data.Count)
	}

	// 无事件 IP
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/security/events/count?ip=9.9.9.9", nil)
	router.ServeHTTP(rec2, req2)
	json.Unmarshal(rec2.Body.Bytes(), &resp)
	if resp.Data.Count != 0 {
		t.Fatalf("empty ip count=%d, want 0", resp.Data.Count)
	}

	// F7:边界形状——缺 ip 400 / days 超限 clamp 365 / days 非数字回落 30 / days=0 回落 30
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/security/events/count", nil))
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("missing ip: status=%d, want 400", rec3.Code)
	}
	rec4 := httptest.NewRecorder()
	router.ServeHTTP(rec4, httptest.NewRequest(http.MethodGet, "/security/events/count?ip=1.2.3.4&days=99999", nil))
	if rec4.Code != http.StatusOK {
		t.Fatalf("oversized days: status=%d, want 200 (clamped)", rec4.Code)
	}
	rec5 := httptest.NewRecorder()
	router.ServeHTTP(rec5, httptest.NewRequest(http.MethodGet, "/security/events/count?ip=1.2.3.4&days=abc", nil))
	if rec5.Code != http.StatusOK {
		t.Fatalf("non-numeric days: status=%d, want 200 (fallback 30)", rec5.Code)
	}
	rec6 := httptest.NewRecorder()
	router.ServeHTTP(rec6, httptest.NewRequest(http.MethodGet, "/security/events/count?ip=1.2.3.4&days=0", nil))
	if rec6.Code != http.StatusOK {
		t.Fatalf("days=0: status=%d, want 200 (fallback 30)", rec6.Code)
	}
}
