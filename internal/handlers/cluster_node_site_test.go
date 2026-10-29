package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func newClusterNodeSiteRouter(t *testing.T) *gin.Engine {
	t.Helper()
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/cluster/nodes/:id/site", handler.UpdateClusterNodeSiteCoordinates)
	return router
}

func seedClusterNodeSite(t *testing.T, isMaster bool) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=?, cluster_version=7 WHERE id=1`, isMaster); err != nil {
		t.Fatalf("seed global role: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,is_approved) VALUES (2,'edge-a','slave','10.0.0.2',8000,1)`); err != nil {
		t.Fatalf("seed node: %v", err)
	}
}

func putClusterNodeSite(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/cluster/nodes/2/site", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func readClusterNodeSite(t *testing.T) (float64, float64, int) {
	t.Helper()
	var lat, lon float64
	var version int
	if err := db.DB.QueryRow(`SELECT server_map_lat, server_map_lon FROM nodes WHERE id=2`).Scan(&lat, &lon); err != nil {
		t.Fatalf("read node site: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	return lat, lon, version
}

func TestUpdateClusterNodeSiteCoordinates_updatesNodeAndBumpsVersion(t *testing.T) {
	// Given: 主节点与一个从节点
	router := newClusterNodeSiteRouter(t)
	seedClusterNodeSite(t, true)

	// When: 主节点为该从节点配置站点坐标
	if response := putClusterNodeSite(t, router, `{"server_map_lat":31.23,"server_map_lon":121.47}`); response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	// Then: 仅该节点坐标变化，并 bump 集群版本触发同步
	lat, lon, version := readClusterNodeSite(t)
	if lat != 31.23 || lon != 121.47 {
		t.Fatalf("node site=(%v,%v), want (31.23,121.47)", lat, lon)
	}
	if version != 8 {
		t.Fatalf("cluster_version=%d, want 8", version)
	}
}

func TestUpdateClusterNodeSiteCoordinates_validationAndMasterGate(t *testing.T) {
	// Given: 主节点，已有坐标
	router := newClusterNodeSiteRouter(t)
	seedClusterNodeSite(t, true)
	if response := putClusterNodeSite(t, router, `{"server_map_lat":10,"server_map_lon":20}`); response.Code != http.StatusOK {
		t.Fatalf("seed status=%d", response.Code)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET cluster_version=7 WHERE id=1`); err != nil {
		t.Fatalf("reset version: %v", err)
	}

	// When/Then: 缺键/越界/类型错误 400 且不写库
	for _, body := range []string{
		`{}`,
		`{"server_map_lat":31.23}`,
		`{"server_map_lon":121.47}`,
		`{"server_map_lat":91,"server_map_lon":121.47}`,
		`{"server_map_lat":31.23,"server_map_lon":181}`,
		`{"server_map_lat":"north","server_map_lon":121.47}`,
	} {
		if response := putClusterNodeSite(t, router, body); response.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s, want 400", body, response.Code, response.Body.String())
		}
	}
	if lat, lon, version := readClusterNodeSite(t); lat != 10 || lon != 20 || version != 7 {
		t.Fatalf("invalid writes changed node=(%v,%v) version=%d, want unchanged (10,20)/7", lat, lon, version)
	}

	// 从节点调用 → 主节点门拒绝
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if response := putClusterNodeSite(t, router, `{"server_map_lat":1,"server_map_lon":2}`); response.Code != http.StatusForbidden {
		t.Fatalf("slave status=%d body=%s, want 403", response.Code, response.Body.String())
	}
}

// 编号非法失败面的审计段落形态：nodeLabel 槽放「节点 <原始值>」（与访问地址
// 端点同形）、原因槽放结论、结果码 invalid_request——旧写法把整句塞进
// nodeLabel 槽且 reason 槽重复同一句，段落错位导致按段落检索失配。
func TestUpdateClusterNodeSiteCoordinates_invalidIDAuditShape(t *testing.T) {
	router := newClusterNodeSiteRouter(t)
	seedClusterNodeSite(t, true)

	request := httptest.NewRequest(http.MethodPut, "/cluster/nodes/abc/site", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}

	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='集群节点' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("编号非法失败面必须留痕: %v", err)
	}
	// 结果段经 AuditResultPart 渲染：invalid_request → 「结果：请求格式错误」。
	if want := "节点 abc；节点编号无效；结果：请求格式错误"; detail != want {
		t.Fatalf("audit detail=%q, want %q", detail, want)
	}
}

// 非法 access_url 是客户端可修正的输入错误，必须 400 并回可行动文案——
// 此前落默认 500「更新地址节点失败」。
func TestUpdateClusterNodeAccessURL_invalidURLIs400(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/cluster/nodes/:id/access-url", h.UpdateClusterNodeAccessURL)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/cluster/nodes/1/access-url",
		strings.NewReader(`{"access_url":"http://user:pass@10.0.0.2:8000/?q=1"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（非法访问地址是输入错误）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "访问地址") {
		t.Fatalf("body=%s, want 访问地址相关文案（不得落 500 通用失败）", rec.Body.String())
	}
}
