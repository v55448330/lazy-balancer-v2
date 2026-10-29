package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 集群写端点的失败面必须留痕/映射正确：
//   - 非法 access_url 是客户端可修正输入 → 400（此前落 500，从端包成 502 误判
//     主节点故障）；
//   - 审批/拒绝/删除失败（404/409/5xx）此前零审计（中间件对 explicit 路由无条件
//     早退），现由 auditFailure 单点留痕。

func TestClusterRegistrationHandler_invalidAccessURLMapped400(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := `{"token":"whatever","name":"slave-a","ip_address":"10.0.0.9","port":9000,"access_url":"ftp://evil.example"}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.RemoteAddr = "10.0.0.9:5555"

	h.RegisterClusterNode(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（非法访问地址属客户端输入）", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "访问地址无效") {
		t.Fatalf("响应必须直指访问地址，got %s", recorder.Body.String())
	}
}

func TestClusterNodeAction_failureLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/999999/approve", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "999999"}}

	h.ApproveClusterNode(ctx)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
	var detail string
	err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='审批' AND resource='集群节点' ORDER BY id DESC LIMIT 1`).Scan(&detail)
	if err != nil {
		t.Fatalf("失败分支必须留痕（审计行缺失）: %v", err)
	}
	if !strings.Contains(detail, "失败") {
		t.Fatalf("审计详情必须标明失败，got %q", detail)
	}
	if !strings.Contains(detail, fmt.Sprintf("节点 %d", 999999)) {
		t.Fatalf("审计详情必须点名节点，got %q", detail)
	}
}

func TestClusterNodeAction_invalidIDLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/abc/approve", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "abc"}}

	h.ApproveClusterNode(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='审批' AND detail LIKE '%失败%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("非法编号失败面审计行数=%d, want 1", count)
	}
}

// 站点坐标端点是 Explicit 路由：审计中间件对其失败面无条件早退，handler 必须
// 逐条补记（与 clusterNodeAction 的 auditFailure 同构）。
func TestUpdateClusterNodeSiteCoordinates_failureLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/nodes/999999/site", strings.NewReader(`{"server_map_lat":1.5,"server_map_lon":2.5}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "999999"}}

	h.UpdateClusterNodeSiteCoordinates(ctx)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='集群节点' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("站点坐标失败面必须留痕（审计行缺失）: %v", err)
	}
	if !strings.Contains(detail, "节点 999999") || !strings.Contains(detail, "失败") {
		t.Fatalf("审计详情必须点名节点并标明失败，got %q", detail)
	}
}

func TestUpdateClusterNodeSiteCoordinates_invalidCoordinatesAudited(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/nodes/1/site", strings.NewReader(`{"server_map_lat":999,"server_map_lon":2.5}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}

	h.UpdateClusterNodeSiteCoordinates(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='更新' AND resource='集群节点' AND detail LIKE '%请求格式错误%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("越界坐标失败面审计行数=%d, want 1", count)
	}
}

// 登录票据端点的失败面此前零审计：MFA 未启用/step-up 缺失/节点离线/DB 故障
// 在操作审计页不可回溯，只剩 stdout clusterError 日志。
func TestGenerateClusterLoginTicket_mfaDisabledLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled) VALUES (1,'admin','x','admin',1,0)"); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/1/login-ticket", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	ctx.Set("user_id", 1)

	h.GenerateClusterLoginTicket(ctx)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403（未启用 MFA）", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='生成失败' AND resource='登录票据' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("票据签发失败面必须留痕（审计行缺失）: %v", err)
	}
	if !strings.Contains(detail, "未启用 MFA") {
		t.Fatalf("审计详情必须点明失败原因，got %q", detail)
	}
}

// step-up 缺失（MFA 已启用但 10 分钟内未验证）此前同样零审计：428 属客户端
// 可自愈分支，但仍需可追溯。
func TestGenerateClusterLoginTicket_missingStepUpLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled) VALUES (1,'admin','x','admin',1,1)"); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/1/login-ticket", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	ctx.Set("user_id", 1)
	ctx.Set("auth_type", "jwt")
	ctx.Set("auth_method", "password")

	h.GenerateClusterLoginTicket(ctx)

	if recorder.Code != http.StatusPreconditionRequired {
		t.Fatalf("status=%d body=%s, want 428（step-up 未完成）", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='生成失败' AND resource='登录票据' AND detail LIKE '%step-up%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("step-up 缺失失败面审计行数=%d, want 1", count)
	}
}

// 注册端点的请求绑定失败此前零审计，与同 handler 其余失败面（无效令牌/非法名/
// 缺地址/非法地址）不一致。
func TestRegisterClusterNode_bindFailureLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(`{"name":`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.RemoteAddr = "10.0.0.9:5555"

	h.RegisterClusterNode(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='注册失败' AND resource='集群节点' AND detail='注册请求格式错误'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("绑定失败审计行数=%d, want 1", count)
	}
}

// 访问地址端点同样是 Explicit 路由：请求体绑定失败此前零审计（同族站点坐标
// 端点已补），探测/前端旧缓存提交在操作审计页不可回溯。
func TestUpdateClusterNodeAccessURL_bindFailureLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/nodes/7/access-url", strings.NewReader(`{"access_url":123}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "7"}}

	h.UpdateClusterNodeAccessURL(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新地址' AND resource='集群节点' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("访问地址绑定失败面必须留痕（审计行缺失）: %v", err)
	}
	if !strings.Contains(detail, "节点 7") || !strings.Contains(detail, "访问地址格式错误") {
		t.Fatalf("审计详情必须点名节点与失败原因，got %q", detail)
	}
}

// 单节点指纹清除的编号非法分支此前零审计：同函数其余失败面（无钉/失败/
// 成功）均有留痕，仅 400 早退分支空白。
func TestForgetClusterNodePin_invalidIDLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/abc/forget-pin", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "abc"}}

	h.ForgetClusterNodePin(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='清除失败' AND resource='证书指纹' AND detail LIKE '%节点编号无效（abc）%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("编号非法失败面审计行数=%d, want 1", count)
	}
}

// 集群模式/设置两条 explicit 写端点的业务拒绝面必须留痕：审计策略对
// explicit 路由不代记 4xx（含权限语义的 403），handler 是唯一留痕点。
// 同端点内此前只有部分失败面有审计，形成「部分可复盘」的方言。
func TestSetClusterMode_rejectionsLeaveAuditTrail(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		nodeName   string
		wantStatus int
		wantDetail string
	}{
		{
			name:       "invalid body",
			body:       `{"mode":1}`,
			wantStatus: http.StatusBadRequest,
			wantDetail: "集群模式参数无效",
		},
		{
			name:       "master mode rejected",
			body:       `{"mode":"master","master_url":"https://master.example","register_token":"t"}`,
			wantStatus: http.StatusBadRequest,
			wantDetail: "请使用提升接口切换为主节点",
		},
		{
			name:       "empty master url",
			body:       `{"mode":"slave","master_url":"","register_token":""}`,
			wantStatus: http.StatusBadRequest,
			wantDetail: "主节点地址和注册令牌不能为空",
		},
		{
			name:       "node name normalizes to empty",
			body:       `{"mode":"slave","master_url":"https://master.example","register_token":"t"}`,
			nodeName:   "   ",
			wantStatus: http.StatusBadRequest,
			wantDetail: "节点名不能为空",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			h.cfg.NodeName = test.nodeName
			h.syncService = services.NewSyncService(db.DB, h.cfg, nil)
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.POST("/cluster/mode", h.SetClusterMode)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/cluster/mode", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), test.wantStatus)
			}
			var action, detail string
			if err := db.AuditDB.QueryRow(`SELECT action, detail FROM audit_log WHERE resource='集群模式' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); err != nil {
				t.Fatalf("拒绝面必须留痕（审计行缺失）: %v", err)
			}
			if action != "切换失败" {
				t.Fatalf("audit action=%q, want 切换失败", action)
			}
			if !strings.Contains(detail, test.wantDetail) {
				t.Fatalf("audit detail=%q, want 含 %q", detail, test.wantDetail)
			}
		})
	}
}

// UpdateClusterSettings 的四个失败面（参数 400、服务层 400、从节点只读 403、
// 内部故障 500）此前零审计——从节点误操作与越权探测最需要可追溯。
func TestUpdateClusterSettings_failuresLeaveAuditTrail(t *testing.T) {
	t.Run("invalid body", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/settings", strings.NewReader(`{"sync_interval":"bad"}`))
		ctx.Request.Header.Set("Content-Type", "application/json")

		h.UpdateClusterSettings(ctx)

		assertClusterSettingsFailureAudit(t, recorder, http.StatusBadRequest)
	})
	t.Run("invalid interval", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/settings", strings.NewReader(`{"sync_interval":5}`))
		ctx.Request.Header.Set("Content-Type", "application/json")

		h.UpdateClusterSettings(ctx)

		assertClusterSettingsFailureAudit(t, recorder, http.StatusBadRequest)
	})
	t.Run("slave read only", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Fatalf("demote node: %v", err)
		}
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/settings", strings.NewReader(`{"sync_rules":true}`))
		ctx.Request.Header.Set("Content-Type", "application/json")

		h.UpdateClusterSettings(ctx)

		assertClusterSettingsFailureAudit(t, recorder, http.StatusForbidden)
	})
	t.Run("internal failure", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		// 角色查询失败 → 500（IsMaster 走独立句柄，不污染包级 db.DB）。
		h.clusterService = services.NewClusterService(closedTestDB(t), "")
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/settings", strings.NewReader(`{"sync_rules":true}`))
		ctx.Request.Header.Set("Content-Type", "application/json")

		h.UpdateClusterSettings(ctx)

		assertClusterSettingsFailureAudit(t, recorder, http.StatusInternalServerError)
	})
}

func assertClusterSettingsFailureAudit(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if recorder.Code != wantStatus {
		t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), wantStatus)
	}
	var action, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, detail FROM audit_log WHERE resource='集群设置' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); err != nil {
		t.Fatalf("失败面必须留痕（审计行缺失）: %v", err)
	}
	if action != "更新失败" {
		t.Fatalf("audit action=%q, want 更新失败", action)
	}
	if strings.TrimSpace(detail) == "" {
		t.Fatal("审计详情不得为空")
	}
}

func closedTestDB(t *testing.T) *sql.DB {
	t.Helper()
	closed, err := sql.Open("sqlite", t.TempDir()+"/closed.db")
	if err != nil {
		t.Fatalf("open closed-handle database: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close handle: %v", err)
	}
	return closed
}

// 装配缺失（clusterService/syncService 未注入）的 503 出口同属拒绝面：
// explicit 路由中间件对 5xx 不代记，handler 必须留痕——此前角色端点的
// 装配缺失出口直接 clusterError 返回，审计页对「集群操作为何点不动」零记录。
func TestClusterWriteEndpoints_assemblyMissing503LeavesAuditTrail(t *testing.T) {
	t.Run("SetClusterMode syncService missing", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/mode", strings.NewReader(`{"mode":"slave","master_url":"https://master.example","register_token":"t"}`))
		ctx.Request.Header.Set("Content-Type", "application/json")

		h.SetClusterMode(ctx)

		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d body=%s, want 503", recorder.Code, recorder.Body.String())
		}
		assertClusterFailureAuditRow(t, "集群模式", "切换失败", "同步服务未初始化", "服务不可用")
	})
	t.Run("PromoteClusterNode syncService missing", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/promote", nil)

		h.PromoteClusterNode(ctx)

		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d body=%s, want 503", recorder.Code, recorder.Body.String())
		}
		assertClusterFailureAuditRow(t, "集群模式", "提升失败", "同步服务未初始化", "服务不可用")
	})
	t.Run("UpdateClusterSettings clusterService missing", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		h.clusterService = nil
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/settings", strings.NewReader(`{"sync_rules":true}`))
		ctx.Request.Header.Set("Content-Type", "application/json")

		h.UpdateClusterSettings(ctx)

		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d body=%s, want 503", recorder.Code, recorder.Body.String())
		}
		assertClusterFailureAuditRow(t, "集群设置", "更新失败", "集群服务未初始化", "服务不可用")
	})
}

func assertClusterFailureAuditRow(t *testing.T, resource, action, detailPart, resultPart string) {
	t.Helper()
	var gotAction, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, detail FROM audit_log WHERE resource=? ORDER BY id DESC LIMIT 1`, resource).Scan(&gotAction, &detail); err != nil {
		t.Fatalf("装配缺失失败面必须留痕（审计行缺失）: %v", err)
	}
	if gotAction != action {
		t.Fatalf("audit action=%q, want %q", gotAction, action)
	}
	if !strings.Contains(detail, detailPart) || !strings.Contains(detail, "结果："+resultPart) {
		t.Fatalf("audit detail=%q, want 含 %q 与 结果：%s", detail, detailPart, resultPart)
	}
}
