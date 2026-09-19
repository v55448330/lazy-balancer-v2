package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// CL43-1(第 43 轮):生成登录票据的目标节点不存在属客户端寻址错误——与同族
// ErrNodeNotFound→404 口径对齐(cluster_registration.go:151-153、
// cluster_service.go:71-72、cluster_sync.go:135-136),此前误映射 409。
func TestGenerateClusterLoginTicket_nodeNotFoundReturns404(t *testing.T) {
	// Given:主节点 + OIDC 会话(豁免两道 MFA 门) + 不存在的节点 999
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	h := &Handlers{clusterService: services.NewClusterService(db.DB, nil, "")}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/nodes/:id/login-ticket", func(c *gin.Context) {
		c.Set("auth_method", "oidc")
		h.GenerateClusterLoginTicket(c)
	})

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/cluster/nodes/999/login-ticket", nil)
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%q, want 404", response.Code, response.Body.String())
	}
}
