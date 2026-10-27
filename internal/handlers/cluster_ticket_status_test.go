package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 生成登录票据的目标节点不存在属客户端寻址错误——与同族
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
	h := &Handlers{clusterService: services.NewClusterService(db.DB, "")}
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

// 已批准但集群令牌尚未交付（批准后从节点还没轮询注册状态回传哈希）的节点
// 存在且被信任，只是暂不可签发：必须 409「令牌待交付」而不是 404「节点
// 不存在」。旧实现把 approved ∧ keyHash=="" 与「未批准/不存在」同归
// ErrNodeNotFound→404，排障方向被引向「节点是否被删除」。
func TestGenerateClusterLoginTicket_tokenPendingReturns409(t *testing.T) {
	// Given：主节点 + OIDC 会话 + 已批准但令牌为空的节点 8
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash,last_seen) VALUES (8,'tokenless','10.0.0.8',8000,'online',1,'',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{clusterService: services.NewClusterService(db.DB, "")}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/nodes/:id/login-ticket", func(c *gin.Context) {
		c.Set("auth_method", "oidc")
		h.GenerateClusterLoginTicket(c)
	})

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/cluster/nodes/8/login-ticket", nil))

	// Then：409 + 单源文案（与离线语义区分）
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%q, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), services.ErrNodeTokenPending.Error()) {
		t.Fatalf("body=%q, want 含 %q", response.Body.String(), services.ErrNodeTokenPending.Error())
	}
}

// 用户反馈(后):「生成登录票据」审计只写「节点 %d」,与服务控制事件
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
	h := &Handlers{clusterService: services.NewClusterService(db.DB, "")}
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

// 登录票据的 MFA 三态门（端点级）：未启用 → 403 引导绑定；读状态失败 →
// 500 fail-closed（不得放行发票）；已启用但无近期验证 → 428 step-up；
// 已启用且验证窗口内 → 通过 MFA 门（落到节点不存在的 404，证明未提前短路）。
func TestGenerateClusterLoginTicket_mfaThreeStateGates(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled) VALUES (1,'alice','hash','admin',1,0)`); err != nil {
		t.Fatal(err)
	}
	h.clusterService = services.NewClusterService(db.DB, "")
	gin.SetMode(gin.TestMode)
	routerWith := func(mfaTs any) *gin.Engine {
		router := gin.New()
		router.POST("/cluster/nodes/:id/login-ticket", func(c *gin.Context) {
			c.Set("user_id", 1)
			c.Set("username", "alice")
			c.Set("auth_method", "password")
			c.Set("auth_type", "jwt")
			if mfaTs != nil {
				c.Set("mfa_ts", mfaTs)
			}
			h.GenerateClusterLoginTicket(c)
		})
		return router
	}
	call := func(mfaTs any) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		routerWith(mfaTs).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/cluster/nodes/999/login-ticket", nil))
		return rec
	}

	// 未启用 MFA → 403 引导
	if rec := call(nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "需先启用 MFA") {
		t.Fatalf("未启用 MFA status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}

	// 已启用但本轮未验证 → 428 step-up
	if _, err := db.DB.Exec(`UPDATE users SET mfa_enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if rec := call(nil); rec.Code != http.StatusPreconditionRequired || !strings.Contains(rec.Body.String(), "MFA_STEP_UP_REQUIRED") {
		t.Fatalf("缺 mfa_ts status=%d body=%s, want 428 step-up", rec.Code, rec.Body.String())
	}

	// 已启用且 60s 内验证过 → MFA 门放行（节点不存在 → 404）
	if rec := call(float64(time.Now().Unix())); rec.Code != http.StatusNotFound {
		t.Fatalf("有效 mfa_ts status=%d body=%s, want 404（MFA 门应放行）", rec.Code, rec.Body.String())
	}

	// 读 MFA 状态失败 → 500 fail-closed（无法证明已启用=拒绝）
	if _, err := db.DB.Exec(`DROP TABLE users`); err != nil {
		t.Fatal(err)
	}
	if rec := call(nil); rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "读取 MFA 状态失败") {
		t.Fatalf("MFA 读失败 status=%d body=%s, want 500 fail-closed", rec.Code, rec.Body.String())
	}
}
