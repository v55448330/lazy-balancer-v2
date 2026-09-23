package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 威胁情报库管理面（v2.3.2 名单化重构）：列表+开关+手动更新+状态/日志端点。
func newThreatTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	testHandlers := newBackupTestHandlers(t)
	services.ResetThreatUpdateManagerForTest()
	// 更新日志目录默认 /app/logs（容器路径）——测试指向临时目录
	t.Cleanup(services.SetUpdateLogDirForTest(t.TempDir()))
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/threat-lib", testHandlers.GetThreatLib)
	router.PUT("/security/threat-lib/:id/flags", testHandlers.UpdateThreatSourceFlags)
	router.POST("/security/threat-lib/update", testHandlers.StartThreatLibUpdate)
	router.PUT("/security/threat-lib/auto-update", testHandlers.UpdateThreatAutoUpdate)
	router.GET("/security/threat-lib/update/status", testHandlers.GetThreatLibUpdateStatus)
	router.GET("/security/threat-lib/update/logs", testHandlers.GetThreatLibUpdateLogs)
	return router
}

func TestThreatLib_getListsSourcesWithTotal(t *testing.T) {
	// Given
	router := newThreatTestRouter(t)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=100 WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=25 WHERE name='et_compromised'`); err != nil {
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
				EntryCount    int    `json:"entry_count"`
				Version       string `json:"version"`
				UpdateStatus  string `json:"update_status"`
				ListID        int    `json:"list_id"`
			} `json:"sources"`
			TotalEntries int `json:"total_entries"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Sources) != 3 {
		t.Fatalf("sources=%d, want 3", len(payload.Data.Sources))
	}
	if payload.Data.TotalEntries != 125 {
		t.Fatalf("total_entries=%d, want 125", payload.Data.TotalEntries)
	}
	for _, s := range payload.Data.Sources {
		if s.ListID == 0 {
			t.Fatalf("源 %s 的 list_id=0, want 内置名单行 id", s.Name)
		}
	}
}

func TestThreatLib_flagsOnlyToggleUpdateEnabled(t *testing.T) {
	// Given
	router := newThreatTestRouter(t)
	var id int
	var origURL string
	if err := db.DB.QueryRow(`SELECT id, url FROM security_threat_sources WHERE name='ustc'`).Scan(&id, &origURL); err != nil {
		t.Fatal(err)
	}

	// When：携带伪造 url/name（必须被忽略）
	body := `{"update_enabled":false,"url":"https://evil.example/x","name":"forged"}`
	req := httptest.NewRequest(http.MethodPut, "/security/threat-lib/"+strconv.Itoa(id)+"/flags", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var updateEnabled bool
	var url, name string
	if err := db.DB.QueryRow(`SELECT update_enabled, url, name FROM security_threat_sources WHERE id=?`, id).
		Scan(&updateEnabled, &url, &name); err != nil {
		t.Fatal(err)
	}
	if updateEnabled {
		t.Fatal("开关未生效")
	}
	if url != origURL || name != "ustc" {
		t.Fatalf("伪造字段被写入: url=%q name=%q", url, name)
	}
}

func TestThreatLib_updateAcceptedWithStatusAndLogs(t *testing.T) {
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
	// 等待任务收尾后断言三源行 success + 名单行有内容 + 状态/日志端点可读
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
	// 状态端点
	statusResp := httptest.NewRecorder()
	router.ServeHTTP(statusResp, httptest.NewRequest(http.MethodGet, "/security/threat-lib/update/status", nil))
	if statusResp.Code != http.StatusOK || !strings.Contains(statusResp.Body.String(), `"outcome":"success"`) {
		t.Fatalf("status 端点: %d %s", statusResp.Code, statusResp.Body.String())
	}
	// 日志端点
	logsResp := httptest.NewRecorder()
	router.ServeHTTP(logsResp, httptest.NewRequest(http.MethodGet, "/security/threat-lib/update/logs", nil))
	body := logsResp.Body.String()
	if logsResp.Code != http.StatusOK || !strings.Contains(body, "ustc") {
		t.Fatalf("logs 端点: %d %s", logsResp.Code, body)
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

// 任务级总开关端点：写入 global_config.threat_auto_update 并经 GET 回读。
func TestThreatLib_autoUpdateMasterSwitch(t *testing.T) {
	router := newThreatTestRouter(t)

	// 默认开（迁移默认值）
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/threat-lib", nil))
	if !strings.Contains(resp.Body.String(), `"auto_update":true`) {
		t.Fatalf("默认应 auto_update=true: %s", resp.Body.String()[:200])
	}

	// 关闭 → 写库 + 回读 false
	req := httptest.NewRequest(http.MethodPut, "/security/threat-lib/auto-update", strings.NewReader(`{"auto_update":false}`))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/threat-lib", nil))
	if !strings.Contains(resp.Body.String(), `"auto_update":false`) {
		t.Fatalf("关闭后回读应 false: %s", resp.Body.String()[:200])
	}
}
