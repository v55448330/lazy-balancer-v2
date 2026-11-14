package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func setupIP2RegionHandlerTest(t *testing.T) {
	t.Helper()
	setupSecurityPolicyTestDB(t)
	services.ResetIP2RegionUpdateManagerForTest()
	services.InitIP2RegionUpdateManager(func() error { return nil })
	t.Cleanup(services.ResetIP2RegionUpdateManagerForTest)
}

// TestGetIP2RegionInfo_returnsStoredState verifies the info endpoint reads
// version/auto_update/update_status from the DB.
func TestGetIP2RegionInfo_returnsStoredState(t *testing.T) {
	// Given a seeded ip2region version row
	setupIP2RegionHandlerTest(t)
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET version='commit-abc', update_status='success' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{}
	router := newIP2RegionRouter(h)

	// When the info endpoint is fetched
	recorder := getRequest(t, router, "/security/ip2region")

	// Then it carries the stored fields
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Version      string `json:"version"`
			UpdateStatus string `json:"update_status"`
			AutoUpdate   bool   `json:"auto_update"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Data.Version != "commit-abc" {
		t.Fatalf("version=%q, want commit-abc", resp.Data.Version)
	}
	if resp.Data.UpdateStatus != "success" {
		t.Fatalf("update_status=%q, want success", resp.Data.UpdateStatus)
	}
}

// v6 三列查询与 v4 同口径：真实 DB 故障（非缺行）必须 500，不得吞错把存储
// 故障伪装成「v6 从未更新」的正常展示态。
func TestGetIP2RegionInfo_v6QueryFailureReturns500(t *testing.T) {
	setupIP2RegionHandlerTest(t)
	// 真实故障注入：把版本表重建为缺 v6 列的旧形态——v4 七列查询照常成功，
	// v6 三列查询报 no such column（非 ErrNoRows）。
	if _, err := db.DB.Exec(`DROP TABLE security_ip2region_version;
		CREATE TABLE security_ip2region_version (
			id INTEGER PRIMARY KEY,
			version TEXT NOT NULL,
			updated_at DATETIME DEFAULT (datetime('now')),
			auto_update BOOLEAN DEFAULT 1,
			update_status TEXT DEFAULT 'idle',
			message TEXT DEFAULT '',
			trigger TEXT DEFAULT '',
			last_checked DATETIME,
			next_update DATETIME
		);
		INSERT INTO security_ip2region_version (id, version, auto_update) VALUES (1, 'v4-ok', 1)`); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{}
	router := newIP2RegionRouter(h)

	recorder := getRequest(t, router, "/security/ip2region")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（v6 查询真实故障不得吞错回 200）", recorder.Code, recorder.Body.String())
	}
}

// TestUpdateIP2RegionAutoUpdate_togglesFlag verifies the admin PUT toggles auto_update.
func TestUpdateIP2RegionAutoUpdate_togglesFlag(t *testing.T) {
	// Given a fresh version row with auto update off
	setupIP2RegionHandlerTest(t)
	h := &Handlers{}
	router := newIP2RegionRouter(h)

	// When auto update is enabled
	recorder := putJSON(t, router, "/security/ip2region/auto-update", map[string]any{"auto_update": true})

	// Then the flag is persisted and the info endpoint echoes it
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var autoUpdate bool
	if err := db.DB.QueryRow("SELECT auto_update FROM security_ip2region_version WHERE id=1").Scan(&autoUpdate); err != nil {
		t.Fatal(err)
	}
	if !autoUpdate {
		t.Fatal("auto_update should be true after PUT")
	}
	autoUpdateInfo := func() bool {
		info := getRequest(t, router, "/security/ip2region")
		if info.Code != http.StatusOK {
			t.Fatalf("info status=%d body=%s", info.Code, info.Body.String())
		}
		var resp struct {
			Data struct {
				AutoUpdate bool `json:"auto_update"`
			} `json:"data"`
		}
		if err := json.Unmarshal(info.Body.Bytes(), &resp); err != nil {
			t.Fatalf("parse info response: %v", err)
		}
		return resp.Data.AutoUpdate
	}
	if !autoUpdateInfo() {
		t.Fatal("GET /security/ip2region auto_update=false after enabling, want true（回读必须与库值一致）")
	}

	// And 关闭后库与回读同口径为 false（只测开启方向会漏掉「恒 true」的漂移）
	recorder = putJSON(t, router, "/security/ip2region/auto-update", map[string]any{"auto_update": false})
	if recorder.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.QueryRow("SELECT auto_update FROM security_ip2region_version WHERE id=1").Scan(&autoUpdate); err != nil {
		t.Fatal(err)
	}
	if autoUpdate {
		t.Fatal("auto_update should be false after disabling")
	}
	if autoUpdateInfo() {
		t.Fatal("GET /security/ip2region auto_update=true after disabling, want false")
	}
}

func newIP2RegionRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/ip2region", h.GetIP2RegionInfo)
	router.PUT("/security/ip2region/auto-update", h.UpdateIP2RegionAutoUpdate)
	router.POST("/security/ip2region/update", h.StartIP2RegionUpdate)
	router.GET("/security/ip2region/update/status", h.GetIP2RegionUpdateStatus)
	router.GET("/security/ip2region/update/logs", h.GetIP2RegionUpdateLogs)
	return router
}
