package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// testHandlers 由 newBackupTestHandlers 注入。
var testHandlers *Handlers

func newThreatTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	testHandlers = newBackupTestHandlers(t)
	oldDir := services.ThreatDataDir
	services.ThreatDataDir = t.TempDir()
	t.Cleanup(func() { services.ThreatDataDir = oldDir })
	services.ResetThreatUpdateManagerForTest()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/threat-lib", testHandlers.GetThreatLib)
	router.PUT("/security/threat-lib/:id/flags", testHandlers.UpdateThreatSourceFlags)
	router.POST("/security/threat-lib/update", testHandlers.StartThreatLibUpdate)
	router.GET("/security/threat-lib/:id/entries", testHandlers.GetThreatSourceEntries)
	router.GET("/security/threat-lib/:id/export", testHandlers.ExportThreatSource)
	return router
}

func TestThreatLib_getListsSourcesWithMergedCount(t *testing.T) {
	// Given
	router := newThreatTestRouter(t)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=100, apply_enabled=1 WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=50, apply_enabled=0 WHERE name='firehol_l1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=25, apply_enabled=1 WHERE name='et_compromised'`); err != nil {
		t.Fatal(err)
	}

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/threat-lib", nil))

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Data struct {
			Sources []struct {
				Name          string `json:"name"`
				DisplayName   string `json:"display_name"`
				URL           string `json:"url"`
				UpdateEnabled bool   `json:"update_enabled"`
				ApplyEnabled  bool   `json:"apply_enabled"`
				EntryCount    int    `json:"entry_count"`
				Version       string `json:"version"`
				UpdateStatus  string `json:"update_status"`
			} `json:"sources"`
			MergedApplyCount int `json:"merged_apply_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Sources) != 3 {
		t.Fatalf("sources=%d, want 3", len(payload.Data.Sources))
	}
	if payload.Data.MergedApplyCount != 125 {
		t.Fatalf("merged_apply_count=%d, want 125（仅 apply_enabled 源合计）", payload.Data.MergedApplyCount)
	}
}

func TestThreatLib_flagsOnlyToggleTwoFields(t *testing.T) {
	// Given
	router := newThreatTestRouter(t)
	var id int
	var origURL string
	if err := db.DB.QueryRow(`SELECT id, url FROM security_threat_sources WHERE name='ustc'`).Scan(&id, &origURL); err != nil {
		t.Fatal(err)
	}

	// When：携带伪造 url/name（必须被忽略）+ 合法双开关
	body := `{"update_enabled":false,"apply_enabled":false,"url":"https://evil.example/x","name":"forged"}`
	req := httptest.NewRequest(http.MethodPut, "/security/threat-lib/"+strconv.Itoa(id)+"/flags", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var updateEnabled, applyEnabled bool
	var url, name string
	if err := db.DB.QueryRow(`SELECT update_enabled, apply_enabled, url, name FROM security_threat_sources WHERE id=?`, id).
		Scan(&updateEnabled, &applyEnabled, &url, &name); err != nil {
		t.Fatal(err)
	}
	if updateEnabled || applyEnabled {
		t.Fatalf("开关未生效: update=%v apply=%v", updateEnabled, applyEnabled)
	}
	if url != origURL || name != "ustc" {
		t.Fatalf("伪造字段被写入: url=%q name=%q", url, name)
	}
}

func TestThreatLib_updateAcceptedAndDuplicate409(t *testing.T) {
	// Given：源指向快速本地桩（避免真网下载）
	router := newThreatTestRouter(t)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.1\n"))
	}))
	t.Cleanup(stub.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=?`, stub.URL); err != nil {
		t.Fatal(err)
	}

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/security/threat-lib/update", nil))

	// Then：受理
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 受理", resp.Code, resp.Body.String())
	}
	// 等待任务收尾后断言三源行 success（真实顺序执行实证）
	deadline := time.Now().Add(10 * time.Second)
	for services.GetThreatUpdateManager().IsRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if services.GetThreatUpdateManager().IsRunning() {
		t.Fatal("更新任务 10s 未结束")
	}
	for _, name := range []string{"ustc", "firehol_l1", "et_compromised"} {
		var status string
		var count int
		if err := db.DB.QueryRow(`SELECT update_status, entry_count FROM security_threat_sources WHERE name=?`, name).Scan(&status, &count); err != nil {
			t.Fatal(err)
		}
		if status != "success" || count != 1 {
			t.Fatalf("源 %s=(%s,%d), want (success,1)", name, status, count)
		}
	}
}

func TestThreatLib_updateSlaveRejected403(t *testing.T) {
	// Given 从节点
	router := newThreatTestRouter(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/security/threat-lib/update", nil))

	// Then
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", resp.Code)
	}
}

func TestThreatLib_entriesPaginationAndMissing404(t *testing.T) {
	// Given：ustc 源有 3 条文件；firehol 无文件
	router := newThreatTestRouter(t)
	var ustcID, fireholID int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE name='ustc'`).Scan(&ustcID); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE name='firehol_l1'`).Scan(&fireholID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(services.ThreatDataDir, "ustc.txt"), []byte("203.0.113.1\n203.0.113.2\n203.0.113.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When/Then：分页
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/threat-lib/"+strconv.Itoa(ustcID)+"/entries?page=1&size=2", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Data struct {
			Total   int      `json:"total"`
			Page    int      `json:"page"`
			Size    int      `json:"size"`
			Entries []string `json:"entries"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.Total != 3 || len(payload.Data.Entries) != 2 || payload.Data.Entries[0] != "203.0.113.1" {
		t.Fatalf("分页=%+v, want total=3 首页两条", payload.Data)
	}
	// 文件缺失 → 404
	resp2 := httptest.NewRecorder()
	router.ServeHTTP(resp2, httptest.NewRequest(http.MethodGet, "/security/threat-lib/"+strconv.Itoa(fireholID)+"/entries", nil))
	if resp2.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404（无已下载数据）", resp2.Code)
	}
}

func TestThreatLib_exportStreamsFile(t *testing.T) {
	// Given
	router := newThreatTestRouter(t)
	var ustcID int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE name='ustc'`).Scan(&ustcID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(services.ThreatDataDir, "ustc.txt"), []byte("203.0.113.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/threat-lib/"+strconv.Itoa(ustcID)+"/export", nil))

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if ct := resp.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type=%q, want text/plain", ct)
	}
	if cd := resp.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, "threat-ustc-") {
		t.Fatalf("Content-Disposition=%q", cd)
	}
	if resp.Body.String() != "203.0.113.1\n" {
		t.Fatalf("body=%q", resp.Body.String())
	}
}
