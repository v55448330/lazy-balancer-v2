package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 服务层 ErrNotMasterNode → 403 必须与 requireMaster 门同源携带
// X-LB-Error-Code: master_required——从端 Pull 的错误分类依赖该头
// （cluster_sync.go），服务层降级竞态 403 此前不设头造成错误形状分叉。
func TestClusterNodeAction_forbiddenCarriesMasterRequiredErrorCode(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// 直接以桩操作驱动 clusterNodeAction 的错误映射分支（降级竞态在 HTTP 层
	// 无法确定性复现，这里钉住映射形状本身）。
	router.POST("/cluster/nodes/:id/demoted", func(c *gin.Context) {
		handler.clusterNodeAction(c, "审批", func(int) error { return services.ErrNotMasterNode })
	})
	router.POST("/cluster/nodes/:id/missing", func(c *gin.Context) {
		handler.clusterNodeAction(c, "审批", func(int) error { return services.ErrNodeNotFound })
	})

	// 目标形状：服务层 ErrNotMasterNode → 403 + X-LB-Error-Code。
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/cluster/nodes/2/demoted", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("demoted status=%d body=%s, want 403", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-LB-Error-Code"); got != masterRequiredErrorCode {
		t.Fatalf("X-LB-Error-Code=%q, want %q（与 requireMaster 门同形状）", got, masterRequiredErrorCode)
	}

	// 回归形状：ErrNodeNotFound → 404 且不携带主节点错误码。
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/2/missing", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing status=%d body=%s, want 404", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-LB-Error-Code"); got != "" {
		t.Fatalf("404 response unexpectedly carries X-LB-Error-Code=%q", got)
	}
}

// （同族收敛）：requireMaster 门路径本身已带头——钉住从节点直连
// 节点写端点的 403 形状，防回归。
func TestUpdateClusterNodeSiteCoordinates_slaveGateCarriesErrorCode(t *testing.T) {
	router := newClusterNodeSiteRouter(t)
	seedClusterNodeSite(t, false)
	response := putClusterNodeSite(t, router, `{"server_map_lat":1,"server_map_lon":2}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("slave status=%d body=%s, want 403", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-LB-Error-Code"); got != masterRequiredErrorCode {
		t.Fatalf("X-LB-Error-Code=%q, want %q", got, masterRequiredErrorCode)
	}
}

// 哨兵同源的真实核对：原用例断言
// errors.Is(sentinel, sentinel) 恒真——零实现耦合，给「防未来误用
// errors.New 平行实现」的注释承诺提供不了任何保护。改为驱动服务层真实
// 拒绝：从节点上的节点写操作必须返回同一个 ErrNotMasterNode 哨兵，且该
// 错误经 clusterNodeAction 映射为 403 + X-LB-Error-Code（服务层若改回平行
// 实现，handler 的 errors.Is 分类会静默失效 → 403 变 500）。
func TestClusterNodeAction_forbiddenMappingUsesSentinel(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.clusterService = services.NewClusterService(db.DB, t.TempDir())
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// 角色复位走 t.Cleanup（不是「断言之后」的一行）：断言失败即 t.Fatalf 终止，
	// 后面的复位不会执行，后续用例会以从节点身份启动（-shuffle 下随机红）。
	t.Cleanup(func() {
		_, _ = db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`)
	})
	// 服务层真实拒绝：SQL 级角色条件命中 0 行 → 复核角色 → ErrNotMasterNode。
	serviceErr := h.clusterService.ApproveNode(context.Background(), 1, time.Now())
	if !errors.Is(serviceErr, services.ErrNotMasterNode) {
		t.Fatalf("服务层错误=%v, want services.ErrNotMasterNode（不得使用平行哨兵）", serviceErr)
	}
	// 恢复主节点角色：让 requireMaster 门放行，从而真正走到服务层错误映射分支
	// （否则 403 只来自角色门，测不到哨兵分类）。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/nodes/:id/sentinel", func(c *gin.Context) {
		h.clusterNodeAction(c, "审批", func(int) error { return serviceErr })
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/cluster/nodes/1/sentinel", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403（哨兵必须经 errors.Is 分类）", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-LB-Error-Code"); got != masterRequiredErrorCode {
		t.Fatalf("X-LB-Error-Code=%q, want %q", got, masterRequiredErrorCode)
	}
}
