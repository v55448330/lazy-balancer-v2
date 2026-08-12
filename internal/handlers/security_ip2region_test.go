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

// TestUpdateIP2RegionAutoUpdate_togglesFlag verifies the admin PUT toggles auto_update.
func TestUpdateIP2RegionAutoUpdate_togglesFlag(t *testing.T) {
	// Given a fresh version row with auto update off
	setupIP2RegionHandlerTest(t)
	h := &Handlers{}
	router := newIP2RegionRouter(h)

	// When auto update is enabled
	recorder := putJSON(t, router, "/security/ip2region/auto-update", map[string]any{"auto_update": true})

	// Then the flag is persisted
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
