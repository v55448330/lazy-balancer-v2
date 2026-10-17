package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// L02-03：重复 ip:port 注册命中已批准节点时必须点名被覆盖的节点（响应 + 审计），
// 首次注册保持无覆盖语义。
func TestRegisterClusterNode_duplicateApprovedNodeNamesOverwrittenNode(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)

	register := func(token, name string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"token":%q,"name":%q,"ip_address":"10.0.0.5","port":9000}`, token, name)
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
		h.RegisterClusterNode(ctx)
		return recorder
	}
	newToken := func() string {
		t.Helper()
		token, _, err := h.clusterService.GenerateRegisterToken(context.Background(), 1, time.Now())
		if err != nil {
			t.Fatalf("generate register token: %v", err)
		}
		return token
	}

	first := register(newToken(), "first-name")
	if first.Code != http.StatusOK {
		t.Fatalf("first registration status=%d body=%s", first.Code, first.Body.String())
	}
	if strings.Contains(first.Body.String(), "已覆盖节点") {
		t.Fatalf("first registration must not report overwrite: %s", first.Body.String())
	}
	var firstPayload struct {
		Data models.ClusterRegistration `json:"data"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstPayload); err != nil {
		t.Fatalf("decode first response: %v", err)
	}
	if err := h.clusterService.ApproveNode(context.Background(), firstPayload.Data.RegistrationID); err != nil {
		t.Fatalf("approve node: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE nodes SET name='original-name' WHERE id=?", firstPayload.Data.RegistrationID); err != nil {
		t.Fatal(err)
	}

	second := register(newToken(), "second-name")
	if second.Code != http.StatusOK {
		t.Fatalf("duplicate registration status=%d body=%s", second.Code, second.Body.String())
	}
	want := fmt.Sprintf("已覆盖节点 #%d（original-name）", firstPayload.Data.RegistrationID)
	if !strings.Contains(second.Body.String(), want) {
		t.Fatalf("duplicate response=%s, want %q", second.Body.String(), want)
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action='注册' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("query registration audit: %v", err)
	}
	if !strings.Contains(detail, want) {
		t.Fatalf("registration audit detail=%q, want %q", detail, want)
	}
}

// L02-04：已批准但从未上报/已离线 → 409 可行动文案；未批准 → 404。
func TestGenerateClusterLoginTicket_offlineNodeReturns409(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	hash := sha256.Sum256([]byte("lb_cluster_offline-handler"))
	hexHash := hex.EncodeToString(hash[:])
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,is_approved,cluster_token_hash,last_seen) VALUES (7,'never-reported','10.0.0.7',8000,1,?,NULL)`, hexHash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,is_approved,cluster_token_hash,last_seen) VALUES (9,'not-approved','10.0.0.9',8000,0,?,datetime('now'))`, hexHash); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{clusterService: services.NewClusterService(db.DB, "")}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/nodes/:id/login-ticket", func(c *gin.Context) {
		c.Set("auth_method", "oidc")
		h.GenerateClusterLoginTicket(c)
	})

	offline := httptest.NewRecorder()
	router.ServeHTTP(offline, httptest.NewRequest(http.MethodPost, "/cluster/nodes/7/login-ticket", nil))
	if offline.Code != http.StatusConflict {
		t.Fatalf("offline node status=%d body=%s, want 409", offline.Code, offline.Body.String())
	}
	if !strings.Contains(offline.Body.String(), "尚未上报") && !strings.Contains(offline.Body.String(), "离线") {
		t.Fatalf("offline node body=%s, want actionable offline wording", offline.Body.String())
	}

	unapproved := httptest.NewRecorder()
	router.ServeHTTP(unapproved, httptest.NewRequest(http.MethodPost, "/cluster/nodes/9/login-ticket", nil))
	if unapproved.Code != http.StatusNotFound {
		t.Fatalf("unapproved node status=%d body=%s, want 404", unapproved.Code, unapproved.Body.String())
	}
}
