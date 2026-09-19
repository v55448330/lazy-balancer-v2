package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
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

// 用户反馈(第 44 轮后):「生成登录票据」审计只写「节点 %d」,与服务控制事件
// (cluster_service.go 「节点 %d（%s）」)不对称——补节点名,便于定位目标节点。
func TestGenerateClusterLoginTicket_auditCarriesNodeName(t *testing.T) {
	// Given:主节点 + OIDC 会话 + 在线已审批节点 7(name=slave-01)
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	key := sha256.Sum256([]byte("lb_cluster_audit-node-name"))
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash,last_seen) VALUES (7,'slave-01','10.0.0.7',8000,'online',1,?,datetime('now'))`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{clusterService: services.NewClusterService(db.DB, nil, "")}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/nodes/:id/login-ticket", func(c *gin.Context) {
		c.Set("auth_method", "oidc")
		h.GenerateClusterLoginTicket(c)
	})

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/cluster/nodes/7/login-ticket", nil)
	router.ServeHTTP(response, request)

	// Then:200 且审计详情带节点名(与服务控制事件同格式「节点 7（slave-01）」)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q, want 200", response.Code, response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE resource='登录票据' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if !strings.Contains(detail, "节点 7（slave-01）") {
		t.Fatalf("audit detail=%q, want 含「节点 7（slave-01）」", detail)
	}
}
