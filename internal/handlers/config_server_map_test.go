package handlers

// 大屏本站坐标配置面（v3 规格第 3 项：面板设置里的公网坐标，缺省用地图视觉
// 中心）——node-local 列（Ruling：站点地理位置是节点属性，随集群同步会让从节点
// 的信标被主节点坐标覆盖，故不入 cluster_snapshot/cluster_apply 与
// cluster_version 触发器 OF 列表；先例：auto_backup_last_run 同族）。
// 写侧范围校验（纬度 ±90 / 经度 ±180），0,0=未设置（前端回退视觉中心）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

func newServerMapConfigRouter(t *testing.T) *gin.Engine {
	t.Helper()
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	router.GET("/config", handler.GetConfig)
	return router
}

func putConfigJSON(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func readServerMapCoords(t *testing.T, router *gin.Engine) (float64, float64) {
	t.Helper()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /config status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data models.GlobalConfig `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return payload.Data.ServerMapLat, payload.Data.ServerMapLon
}

func TestPutConfig_serverMapCoordsPersistAndOmissionKeepsValue(t *testing.T) {
	// Given: 全新配置（0,0=未设置 → 前端回退地图视觉中心）
	router := newServerMapConfigRouter(t)
	if lat, lon := readServerMapCoords(t, router); lat != 0 || lon != 0 {
		t.Fatalf("初始坐标=(%v,%v), want (0,0) 未设置", lat, lon)
	}

	// When: 提交本站坐标
	if response := putConfigJSON(t, router, `{"server_map_lat":31.23,"server_map_lon":121.47}`); response.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", response.Code, response.Body.String())
	}

	// Then: 回读同级值（写侧入库 + 读侧直读，非兜底常量）
	if lat, lon := readServerMapCoords(t, router); lat != 31.23 || lon != 121.47 {
		t.Fatalf("回读坐标=(%v,%v), want (31.23,121.47)", lat, lon)
	}

	// 省略字段（只改日志级别）→ 坐标保持现值（COALESCE 语义）
	if response := putConfigJSON(t, router, `{"log_level":"warn"}`); response.Code != http.StatusOK {
		t.Fatalf("PUT omit status=%d body=%s", response.Code, response.Body.String())
	}
	if lat, lon := readServerMapCoords(t, router); lat != 31.23 || lon != 121.47 {
		t.Fatalf("省略提交后坐标=(%v,%v), want 保持 (31.23,121.47)", lat, lon)
	}
}

func TestPutConfig_serverMapCoordsRangeValidation(t *testing.T) {
	// Given: 已设置坐标
	router := newServerMapConfigRouter(t)
	if response := putConfigJSON(t, router, `{"server_map_lat":31.23,"server_map_lon":121.47}`); response.Code != http.StatusOK {
		t.Fatalf("seed PUT status=%d", response.Code)
	}

	// When/Then: 越界坐标 400 且不改库值（fail-visible，不静默钳位）
	for _, body := range []string{
		`{"server_map_lat":91}`,
		`{"server_map_lat":-90.5}`,
		`{"server_map_lon":181}`,
		`{"server_map_lon":-180.5}`,
	} {
		response := putConfigJSON(t, router, body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s, want 400", body, response.Code, response.Body.String())
		}
	}
	if lat, lon := readServerMapCoords(t, router); lat != 31.23 || lon != 121.47 {
		t.Fatalf("越界提交后坐标被改写=(%v,%v), want 保持 (31.23,121.47)", lat, lon)
	}

	// 边界值合法（±90 / ±180）
	for _, body := range []string{
		`{"server_map_lat":90,"server_map_lon":180}`,
		`{"server_map_lat":-90,"server_map_lon":-180}`,
	} {
		if response := putConfigJSON(t, router, body); response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s, want 200（边界值合法）", body, response.Code, response.Body.String())
		}
	}
	if lat, lon := readServerMapCoords(t, router); lat != -90 || lon != -180 {
		t.Fatalf("边界提交后坐标=(%v,%v), want (-90,-180)", lat, lon)
	}
}

func TestServerMapCoords_areNodeLocalNotClusterSynced(t *testing.T) {
	// Given: 大屏本站坐标为 node-local 列（先例 auto_backup_last_run）——
	// 集群同步会让从节点信标被主节点坐标覆盖；备份仍随 global_config 通用
	// 表导出（同节点还原语义正确）。
	// When/Then: 列不在集群应用 UPDATE 列单，也不在 cluster_version 触发器
	// OF 列表中（源码级绊线：新增同步列时必须显式决策并更新本测试）。
	for _, check := range []struct {
		file   string
		target string
	}{
		{"../services/cluster_apply.go", "server_map_lat"},
		{"../services/cluster_snapshot.go", "server_map_lat"},
		{"../middleware/cluster_version.go", "server_map_lat"},
	} {
		content, err := os.ReadFile(check.file)
		if err != nil {
			t.Fatalf("read %s: %v", check.file, err)
		}
		if strings.Contains(string(content), check.target) {
			t.Errorf("%s 出现 %s——本站坐标应为 node-local（决策依据见本测试注释），若确需集群同步请移除本绊线并说明", check.file, check.target)
		}
	}
}
