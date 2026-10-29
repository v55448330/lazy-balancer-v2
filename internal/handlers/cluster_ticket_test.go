package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// TicketLogin 的 500 分支（DB/内部故障）曾复用「登录
// 票据无效或已过期」凭证文案——审计侧已区分 database_error，响应面缺失让
// 运维误判为票据问题并反复重取票据。钉：DB 故障 → 500 + 独立文案；401
// 凭证分支文案不变。
func TestTicketLogin_databaseErrorUsesRetryMessage(t *testing.T) {
	h := newBackupTestHandlers(t)
	const clusterToken = "lb_cluster_a87"
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0, cluster_token=?, registration_id=7 WHERE id=1`, clusterToken); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (id, username, password_hash, role, is_enabled) VALUES (1,'alice','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
	// 构造合法票据（HMAC 键=sha256(cluster_token)），随后删表制造 DB 故障：
	// 票据验签/用户校验通过，消费票据语句失败 → 非 ErrInvalidLoginTicket 的 500。
	claims, err := json.Marshal(map[string]any{
		"user_id": 1, "username": "alice", "node_id": 7, "jti": "jti-a87",
		"expires_at": time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte(clusterToken))
	payload := base64.RawURLEncoding.EncodeToString(claims)
	mac := hmac.New(sha256.New, key[:])
	// 服务层对 base64 载荷串（parts[0]）签名，而非原始 JSON 字节。
	_, _ = mac.Write([]byte(payload))
	ticket := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if _, err := db.DB.Exec(`DROP TABLE used_login_tickets`); err != nil {
		t.Fatalf("drop used_login_tickets: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/ticket-login", h.TicketLogin)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/ticket-login", strings.NewReader(`{"ticket":"`+ticket+`"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "登录票据无效或已过期") {
		t.Fatalf("body=%s, DB 故障不得归因为票据无效", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "校验失败") {
		t.Fatalf("body=%s, want 独立故障文案（校验失败，请稍后重试）", response.Body.String())
	}
	var reason string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='登录失败' AND resource='登录票据' ORDER BY id DESC LIMIT 1`).Scan(&reason); err != nil {
		t.Fatalf("query ticket failure audit: %v", err)
	}
	if !strings.Contains(reason, "数据库错误") {
		t.Fatalf("audit detail=%q, want 数据库错误（database_error 的落库形态）", reason)
	}
}

func TestRecordTicketLoginFailureAuditsSanitizedReasons(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	gin.SetMode(gin.TestMode)
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("POST", "/api/v1/auth/ticket-login", nil)
	reasons := []string{"invalid_request", "invalid_signature", "expired", "replay", "user_unavailable", "database_error"}
	for _, reason := range reasons {
		recordTicketLoginFailure(context, "alice", reason)
	}
	rows, err := db.AuditDB.Query("SELECT detail FROM audit_log WHERE resource='登录票据' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		got = append(got, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(reasons) {
		t.Fatalf("ticket failure audit count=%d, want %d: %v", len(got), len(reasons), got)
	}
	// 断言单一来源映射：每条落库详情必须等于「结果：<映射文案>」，且映射
	// 不得回退为原始英文码——漏映射会让审计面出现内部标识（此前的
	// 「详情不含 ticket 常量」恒真：票据原文从不进入该函数）。
	for i, reason := range reasons {
		text := services.AuditResultText(reason)
		if text == reason {
			t.Fatalf("审计结果码 %q 缺少中文映射（落库将暴露内部标识）", reason)
		}
		if want := "结果：" + text; got[i] != want {
			t.Fatalf("audit detail[%d]=%q, want %q", i, got[i], want)
		}
	}
}

// 端点级取证边界：提交的票据原文不得进入审计详情（审计只记归因文案）。
func TestTicketLogin_auditDoesNotLeakSubmittedTicket(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0, cluster_token='lb_cluster_leak_test' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/ticket-login", h.TicketLogin)
	const ticket = "leaky-secret-ticket-zzz"
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/ticket-login", strings.NewReader(`{"ticket":"`+ticket+`"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", response.Code, response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='登录失败' AND resource='登录票据' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("query ticket failure audit: %v", err)
	}
	if strings.Contains(detail, ticket) {
		t.Fatalf("audit detail leaked submitted ticket: %q", detail)
	}
	if !strings.Contains(detail, "登录票据") {
		t.Fatalf("audit detail=%q, want 归因文案", detail)
	}
}

func TestTicketLogin_preservesTicketSessionAuthMethod(t *testing.T) {
	for _, tc := range []struct {
		name       string
		authMethod string
		want       any
	}{
		{name: "local password origin on mixed identity row", authMethod: "", want: nil},
		{name: "OIDC origin", authMethod: "oidc", want: "oidc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			h.cfg.JWTSecret = "test-secret"
			seedUserAuditTest(t, 3, "alice", "admin", true)
			if _, err := db.DB.Exec(`UPDATE users SET auth_provider='oidc',mfa_enabled=1 WHERE id=3`); err != nil {
				t.Fatal(err)
			}
			clusterToken := "lb_cluster_ticket-auth-method"
			key := sha256.Sum256([]byte(clusterToken))
			if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash,last_seen)
				VALUES (7,'slave','10.0.0.7',8000,'online',1,?,datetime('now'))`, hex.EncodeToString(key[:])); err != nil {
				t.Fatal(err)
			}
			masterRouter := gin.New()
			masterRouter.POST("/cluster/nodes/:id/login-ticket", func(c *gin.Context) {
				c.Set("user_id", 3)
				c.Set("username", "alice")
				c.Set("role", "admin")
				c.Set("auth_type", "jwt")
				c.Set("mfa_ts", float64(time.Now().Unix()))
				if tc.authMethod != "" {
					c.Set("auth_method", tc.authMethod)
				}
				h.GenerateClusterLoginTicket(c)
			})
			issued := httptest.NewRecorder()
			masterRouter.ServeHTTP(issued, httptest.NewRequest(http.MethodPost, "/cluster/nodes/7/login-ticket", nil))
			if issued.Code != http.StatusOK {
				t.Fatalf("issue status=%d body=%s, want 200", issued.Code, issued.Body.String())
			}
			var ticket struct {
				Ticket string `json:"ticket"`
			}
			if err := json.Unmarshal(issued.Body.Bytes(), &ticket); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0, cluster_token=?, registration_id=7 WHERE id=1`, clusterToken); err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.POST("/auth/ticket-login", h.TicketLogin)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/auth/ticket-login", strings.NewReader(`{"ticket":"`+ticket.Ticket+`"}`))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
			}
			var body struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			parsed, err := jwt.Parse(body.Token, func(token *jwt.Token) (any, error) { return []byte("test-secret"), nil })
			if err != nil || !parsed.Valid {
				t.Fatalf("parse ticket session: %v", err)
			}
			claims := parsed.Claims.(jwt.MapClaims)
			if got := claims["auth_method"]; got != tc.want {
				t.Fatalf("auth_method=%v, want %v", got, tc.want)
			}
		})
	}
}
