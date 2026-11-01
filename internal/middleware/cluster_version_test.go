package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// synchronizedWriteClassificationCase 是 isSynchronizedWrite 分类矩阵的一条用例。
type synchronizedWriteClassificationCase struct {
	method string
	path   string
	want   bool
}

// synchronizedWriteClassificationCases 是同步写分类回归矩阵：快照内容写路径
// true，只读/纯代理 false。生产 users 写路径清单必须被本矩阵全覆盖——反向
// 覆盖断言见 TestIsSynchronizedWrite_coversProductionUsersWritePaths。
var synchronizedWriteClassificationCases = []synchronizedWriteClassificationCase{
	{"PUT", "/api/v1/config", true},
	{"POST", "/api/v1/config/preview", false},
	{"PUT", "/api/v1/caddy/config", true},
	{"POST", "/api/v1/rules", true},
	{"POST", "/api/v1/rules/cert-info", false},
	{"PATCH", "/api/v1/users/me", true},
	{"DELETE", "/api/v1/api-keys/:id", true},
	{"POST", "/api/v1/cluster/mode", false},
	{"PUT", "/api/v1/cluster/settings", true},
	{"PUT", "/api/v1/admin-tls", true},
	{"POST", "/api/v1/admin-tls/inspect", false},
	{"POST", "/api/v1/config/import", true},
	{"POST", "/api/v1/config/import/v1", true},
	{"POST", "/api/v1/config/import/validate", false},
	// 还原经 importConfigBackupCore 重写 lb_rules/
	// upstreams 等全部同步表,必须与 /config/import 同口径 fail-closed;
	// run/delete 仅写 auto_backups 本地簿记表(非同步表),不放行。
	{"POST", "/api/v1/auto-backup/:id/restore", true},
	{"POST", "/api/v1/auto-backup/7/restore", true},
	{"POST", "/api/v1/auto-backup/run", false},
	{"DELETE", "/api/v1/auto-backup/:id", false},
	{"POST", "/api/v1/certificates/issue", true},
	{"POST", "/api/v1/certificates/jobs/:id/retry", true},
	{"DELETE", "/api/v1/certificates/jobs/:id", true},
	{"POST", "/api/v1/certificates/jobs/current", false},
	{"POST", "/api/v1/certificates/parse", false},
	{"GET", "/api/v1/certificates/jobs/:id", false},
	{"PUT", "/api/v1/ca-providers/:id", true},
	// test 端点在 ZeroSSL 缺 EAB 时写
	// ca_providers.credentials（同步表），与 PUT 同口径 fail-closed。
	{"POST", "/api/v1/ca-providers/:id/test", true},
	{"POST", "/api/v1/ca-providers/7/test", true},
	{"POST", "/api/v1/certificate-configs", true},
	{"PUT", "/api/v1/certificate-configs/:id", true},
	{"DELETE", "/api/v1/certificate-configs/:id", true},
	{"POST", "/api/v1/certificate-configs/test", false},
	{"POST", "/api/v1/certificate-configs/:id/test", false},
	{"POST", "/api/v1/security/policies", true},
	{"PUT", "/api/v1/security/policies/:id", true},
	{"DELETE", "/api/v1/security/policies/:id", true},
	{"PUT", "/api/v1/settings/auto-backup", true},
	{"PUT", "/api/v1/settings/oidc", true},
	{"DELETE", "/api/v1/settings/oidc", true},
	{"POST", "/api/v1/security/policies/:id/bind", true},
	{"DELETE", "/api/v1/security/policies/:id/bind/:caddy_id", true},
	{"POST", "/api/v1/security/custom-rules", true},
	{"PUT", "/api/v1/security/custom-rules/:id", true},
	{"DELETE", "/api/v1/security/custom-rules/:id", true},
	{"POST", "/api/v1/security/block-pages", true},
	{"PUT", "/api/v1/security/block-pages/:id", true},
	{"DELETE", "/api/v1/security/block-pages/:id", true},
	{"PUT", "/api/v1/security/crs/auto-update", true},
	{"POST", "/api/v1/security/crs/update", true},
	// 手动任务触发可写版本表；整路由 fail-closed，避免在中间件维护
	// 第二份任务 ID/同步写清单。其他任务操作不据此捕获。
	{"POST", "/api/v1/system/tasks/:id/trigger", true},
	{"POST", "/api/v1/system/tasks/:id/toggle", false},
	// 大屏流量采集租约是 Caddy admin 的纯代理
	//（内存租约，不写任何同步表）——不得按 security 前缀误分类为
	// 同步写（触发器降级态会把它误伤成 500）。
	{"POST", "/api/v1/security/overview/threat-screen/collector", false},
	{"DELETE", "/api/v1/security/overview/threat-screen/collector", false},
	{"GET", "/api/v1/security/policies", false},
	{"GET", "/api/v1/security/custom-rules", false},
	// 登录锁传播：密码登录与 MFA 验证步均写
	// users 同步列（失败置锁 login_locked_until/成功清零解锁），触发器
	// 不可用时须与 setup/OIDC 开户同口径 fail-closed。
	{"POST", "/api/v1/auth/login", true},
	{"POST", "/api/v1/auth/mfa/verify", true},
	// 初始化管理员 / OIDC JIT 开户 / MFA 三段状态变更同样写 users
	// 同步列——生产单源清单里的每条都必须在此留 true 用例（反向覆盖
	// 断言见 TestIsSynchronizedWrite_coversProductionUsersWritePaths）。
	{"POST", "/api/v1/auth/setup", true},
	{"GET", "/api/v1/auth/oidc/callback", true},
	{"POST", "/api/v1/auth/mfa/activate", true},
	{"POST", "/api/v1/auth/mfa/disable", true},
	{"POST", "/api/v1/auth/mfa/recovery-codes", true},
	// 反例：只写 pending/记账列（永不 bump），按前缀捕获会误伤 MFA 登录/step-up。
	{"POST", "/api/v1/auth/mfa/setup", false},
	{"POST", "/api/v1/auth/mfa/verify-step", false},
	// 票据登录不写 users 同步列（失败仅记审计）——不误伤从节点登录
	// 可用性；GET 形态同样不入。
	{"POST", "/api/v1/auth/ticket-login", false},
	{"GET", "/api/v1/auth/login", false},
}

func TestIsSynchronizedWrite_classifies_only_snapshot_content_mutations(t *testing.T) {
	for _, test := range synchronizedWriteClassificationCases {
		if got := isSynchronizedWrite(test.method, test.path); got != test.want {
			t.Errorf("isSynchronizedWrite(%s %s)=%v, want %v", test.method, test.path, got, test.want)
		}
	}
}

// 反向覆盖：生产清单是唯一事实源，分类矩阵必须为其中每条写路径留 true 用例。
// 新增 users 写路径时若忘了扩展矩阵，本断言直接失败（生产 ⊆ 测试覆盖），
// 不会出现「清单加了、分类行为没人验」的静默漂移。
func TestIsSynchronizedWrite_coversProductionUsersWritePaths(t *testing.T) {
	covered := make(map[string]bool, len(synchronizedWriteClassificationCases))
	for _, test := range synchronizedWriteClassificationCases {
		if test.want {
			covered[test.method+" "+test.path] = true
		}
	}
	for _, path := range usersTableWritePostPaths {
		if !covered[http.MethodPost+" "+path] {
			t.Errorf("生产 users 写路径 POST %s 未出现在同步写分类矩阵", path)
		}
	}
	if !covered[http.MethodGet+" "+usersTableWriteOIDCCallbackPath] {
		t.Errorf("生产 users 写路径 GET %s 未出现在同步写分类矩阵", usersTableWriteOIDCCallbackPath)
	}
}

// 名称如实反映覆盖面——中间件不开启事务（无 BeginTx），
// 版本递增由 users/lb_rules 等表上的语句级触发器完成；本测试只证明「同步写
// 单语句即 bump」，不证明多语句 handler 的原子性（见
// TestClusterVersionMiddleware_statementLevelAtomicityWithoutExplicitTx）。
func TestClusterVersionMiddleware_bumps_on_synchronized_statement(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	gin.SetMode(gin.TestMode)
	requestContext, cancel := context.WithCancel(context.Background())
	router := gin.New()
	router.Use(clusterVersionMiddleware(database))
	router.POST("/api/v1/rules", func(c *gin.Context) {
		if _, err := database.ExecContext(c.Request.Context(), `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_version', 'version', 'http', 8080)`); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		cancel()
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil).WithContext(requestContext)
	recorder := httptest.NewRecorder()

	// When
	router.ServeHTTP(recorder, request)

	// Then
	var version int
	if err := database.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if recorder.Code != http.StatusNoContent || version != 1 {
		t.Fatalf("response=%d version=%d, want 204 and 1", recorder.Code, version)
	}
}

// 回滚来自 SQLite 触发器 ABORT 的**语句级**原子性——
// 不是中间件事务。多语句 handler 若不显式事务，前序语句会保留提交。
func TestClusterVersionMiddleware_statement_rolls_back_when_version_bump_fails(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(clusterVersionMiddleware(database))
	if _, err := database.Exec(`CREATE TRIGGER reject_cluster_version BEFORE UPDATE OF cluster_version ON global_config
		BEGIN SELECT RAISE(ABORT, 'cluster version unavailable'); END`); err != nil {
		t.Fatalf("install failing bump trigger: %v", err)
	}
	router.POST("/api/v1/rules", func(c *gin.Context) {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_rollback', 'rollback', 'http', 8080)`); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "save failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"saved": true})
	})
	recorder := httptest.NewRecorder()

	// When
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	// Then
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("response status=%d body=%q, want 500", recorder.Code, recorder.Body.String())
	}
	var count, version int
	if err := database.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_rollback'").Scan(&count); err != nil {
		t.Fatalf("count rolled back rules: %v", err)
	}
	if err := database.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if count != 0 || version != 0 {
		t.Fatalf("rule count=%d version=%d, want both unchanged", count, version)
	}
}

// 契约显式化——中间件只做「同步写分类 + 触发器可用性」门，不包裹
// 业务事务。多语句 handler 未显式 BEGIN 时，前序语句（非同步表）保留提交，
// 同步语句因 bump 失败单独 ABORT。需要整体原子性的 handler 必须自建事务。
func TestClusterVersionMiddleware_statementLevelAtomicityWithoutExplicitTx(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(clusterVersionMiddleware(database))
	if _, err := database.Exec(`CREATE TRIGGER reject_cluster_version BEFORE UPDATE OF cluster_version ON global_config
		BEGIN SELECT RAISE(ABORT, 'cluster version unavailable'); END`); err != nil {
		t.Fatalf("install failing bump trigger: %v", err)
	}
	router.POST("/api/v1/rules", func(c *gin.Context) {
		// 语句 1：非同步表（revoked_jti）——不触发 cluster_version。
		if _, err := database.Exec(`INSERT INTO revoked_jti (jti_hash, expires_at) VALUES ('atomicity-probe','2099-01-01T00:00:00Z')`); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		// 语句 2：同步写——版本 bump 失败 → 仅本语句 ABORT。
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_atomicity','atomicity','http',8081)`); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()

	// When
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	// Then：同步写回滚但前序语句保留——handler 需自建事务才能整体回滚。
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", recorder.Code)
	}
	var probe, rules int
	if err := database.QueryRow("SELECT COUNT(*) FROM revoked_jti WHERE jti_hash='atomicity-probe'").Scan(&probe); err != nil {
		t.Fatalf("count probe row: %v", err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_atomicity'").Scan(&rules); err != nil {
		t.Fatalf("count synchronized rule: %v", err)
	}
	if probe != 1 || rules != 0 {
		t.Fatalf("probe=%d rules=%d, want first statement persisted and synchronized statement rolled back", probe, rules)
	}
}

// 触发器安装失败时中间件必须按 {code,message} APIResponse 契约返回
// 500（此前是英文 gin.H{"error":...}，脱离 API 契约且未中文化）。
func TestClusterVersionMiddleware_rejects_with_api_response_when_trigger_install_fails(t *testing.T) {
	// Given：触发器安装失败（已关闭的连接让首次 Exec 报错）
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = database.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if err := db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	// 夹具复位走单源 restoreTestDBHandles（含 SetDB）。句柄自检用已关闭库的
	// 指针身份做非平凡断言：db.Close 内部 SetDB(nil)，只赋值包级变量的旧写法
	// 会让 db.GetDB() 停在 nil，与 db.DB 分叉（两条读取路径读到不同库）。
	restoreTestDBHandles(database, oldMetricsDB, oldAuditDB)
	if db.DB != database || db.GetDB() != database {
		t.Fatalf("夹具复位未回填原子句柄：db.DB=%p db.GetDB()=%p want %p", db.DB, db.GetDB(), database)
	}
	// 再复位到用例开始前的环境（后续只在 router 内使用已关闭的 database）。
	restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	if db.DB != oldDB || db.GetDB() != oldDB {
		t.Fatalf("复位到用例前环境失败：db.DB=%p db.GetDB()=%p want %p", db.DB, db.GetDB(), oldDB)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(clusterVersionMiddleware(database))
	router.POST("/api/v1/rules", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	router.POST("/api/v1/system/tasks/:id/trigger", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	// When
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	// Then：500 + APIResponse 契约体
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("response status=%d body=%q, want 500", recorder.Code, recorder.Body.String())
	}
	var resp models.APIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal body %q: %v", recorder.Body.String(), err)
	}
	if resp.Code != 500 || resp.Message != "集群版本触发器不可用" {
		t.Fatalf("body={code:%d message:%q}, want {code:500 message:集群版本触发器不可用}", resp.Code, resp.Message)
	}

	triggerRecorder := httptest.NewRecorder()
	router.ServeHTTP(triggerRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/system/tasks/crs/trigger", nil))
	if triggerRecorder.Code != http.StatusInternalServerError {
		t.Fatalf("task trigger response status=%d body=%q, want fail-closed 500", triggerRecorder.Code, triggerRecorder.Body.String())
	}
}

func TestClusterVersionTriggers_bump_for_snapshot_insert_update_delete(t *testing.T) {
	tests := []struct {
		name       string
		seed       string
		insert     string
		insertArgs []any
		update     string
		delete     string
	}{
		{name: "lb_rules", insert: `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('matrix_rule','rule','http',8080)`, update: `UPDATE lb_rules SET name='updated' WHERE caddy_id='matrix_rule'`, delete: `DELETE FROM lb_rules WHERE caddy_id='matrix_rule'`},
		{name: "upstreams", seed: `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('matrix_parent','parent','http',8080)`, insert: `INSERT INTO upstreams (rule_id,host,port) VALUES ('matrix_parent','127.0.0.1',80)`, update: `UPDATE upstreams SET host='127.0.0.2' WHERE rule_id='matrix_parent'`, delete: `DELETE FROM upstreams WHERE rule_id='matrix_parent'`},
		{name: "path_rules", seed: `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('matrix_parent','parent','http',8080)`, insert: `INSERT INTO path_rules (rule_id,path) VALUES ('matrix_parent','/old')`, update: `UPDATE path_rules SET path='/new' WHERE rule_id='matrix_parent'`, delete: `DELETE FROM path_rules WHERE rule_id='matrix_parent'`},
		{name: "users", insert: `INSERT INTO users (username,password_hash) VALUES ('matrix_user','hash')`, update: `UPDATE users SET display_name='updated' WHERE username='matrix_user'`, delete: `DELETE FROM users WHERE username='matrix_user'`},
		{name: "api_keys", seed: `INSERT INTO users (username,password_hash) VALUES ('matrix_owner','hash')`, insert: `INSERT INTO api_keys (name,key_hash,key_prefix,created_by) VALUES ('matrix_key','hash','prefix',1)`, update: `UPDATE api_keys SET name='updated' WHERE key_prefix='prefix'`, delete: `DELETE FROM api_keys WHERE key_prefix='prefix'`},
		{name: "cert_jobs", insert: `INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('matrix_rule','example.com','failed',?,?,datetime('now','+30 days'))`, update: `UPDATE cert_jobs SET expires_at=datetime('now','+60 days') WHERE rule_id='matrix_rule'`, delete: `DELETE FROM cert_jobs WHERE rule_id='matrix_rule'`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			database := newClusterVersionTestDB(t)
			if test.name == "cert_jobs" {
				certPEM, keyPEM := clusterVersionCertificatePair(t)
				test.insertArgs = []any{certPEM, keyPEM}
			}
			if test.seed != "" {
				if _, err := database.Exec(test.seed); err != nil {
					t.Fatalf("seed dependency: %v", err)
				}
			}
			if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=100 WHERE id=1"); err != nil {
				t.Fatalf("seed cluster version: %v", err)
			}
			if err := InstallClusterVersionTriggers(database); err != nil {
				t.Fatalf("install triggers: %v", err)
			}
			if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
				t.Fatalf("reset cluster version: %v", err)
			}

			operations := []struct {
				name      string
				statement string
				args      []any
				version   int
			}{
				{name: "insert", statement: test.insert, args: test.insertArgs, version: 1},
				{name: "update", statement: test.update, version: 2},
				{name: "delete", statement: test.delete, version: 3},
			}
			for _, operation := range operations {
				// When
				if _, err := database.Exec(operation.statement, operation.args...); err != nil {
					t.Fatalf("%s row: %v", operation.name, err)
				}

				// Then
				if got := clusterVersion(t, database); got != operation.version {
					t.Fatalf("version after %s=%d, want %d", operation.name, got, operation.version)
				}
			}
		})
	}
}

func TestClusterVersionTriggers_bump_for_security_tables(t *testing.T) {
	tests := []struct {
		name   string
		insert string
		update string
		delete string
	}{
		{name: "security_policies",
			insert: `INSERT INTO security_policies (id,name,mode) VALUES (7,'matrix policy','blocking')`,
			update: `UPDATE security_policies SET ip_acl_mode='deny',ip_acl_list='["10.0.0.0/8"]' WHERE id=7`,
			delete: `DELETE FROM security_policies WHERE id=7`},
		{name: "security_policy_bindings",
			insert: `INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_matrix',7)`,
			update: `UPDATE security_policy_bindings SET policy_id=8 WHERE rule_caddy_id='lb_matrix'`,
			delete: `DELETE FROM security_policy_bindings WHERE rule_caddy_id='lb_matrix'`},
		{name: "security_custom_rules",
			insert: `INSERT INTO security_custom_rules (id,name,conditions) VALUES (7,'matrix rule','[]')`,
			update: `UPDATE security_custom_rules SET score=10 WHERE id=7`,
			delete: `DELETE FROM security_custom_rules WHERE id=7`},
		{name: "security_block_pages",
			insert: `INSERT INTO security_block_pages (id,name,content) VALUES (7,'matrix page','<html>blocked</html>')`,
			update: `UPDATE security_block_pages SET content='<html>v2</html>' WHERE id=7`,
			delete: `DELETE FROM security_block_pages WHERE id=7`},
		// UPDATE 用例写语义列（version）：update_status/message 等运行态簿记列
		// 已按「值真实变化」守卫排除出 bump 判定（见
		// TestClusterVersionTrigger_runtimeBookkeepingExcluded）。
		{name: "security_crs_version",
			insert: `INSERT INTO security_crs_version (id,version) VALUES (1,'v4.14.0')`,
			update: `UPDATE security_crs_version SET version='v4.15.0' WHERE id=1`,
			delete: `DELETE FROM security_crs_version WHERE id=1`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			database := newClusterVersionTestDB(t)
			if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=100 WHERE id=1"); err != nil {
				t.Fatalf("seed cluster version: %v", err)
			}
			if err := InstallClusterVersionTriggers(database); err != nil {
				t.Fatalf("install triggers: %v", err)
			}
			for _, operation := range []string{"insert", "update", "delete"} {
				triggerName := "cluster_version_" + test.name + "_" + operation
				var count int
				if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?", triggerName).Scan(&count); err != nil {
					t.Fatalf("query trigger %s: %v", triggerName, err)
				}
				if count != 1 {
					t.Fatalf("trigger %s missing from sqlite_master", triggerName)
				}
			}
			if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
				t.Fatalf("reset cluster version: %v", err)
			}

			operations := []struct {
				name      string
				statement string
				version   int
			}{
				{name: "insert", statement: test.insert, version: 1},
				{name: "update", statement: test.update, version: 2},
				{name: "delete", statement: test.delete, version: 3},
			}
			for _, operation := range operations {
				// When
				if _, err := database.Exec(operation.statement); err != nil {
					t.Fatalf("%s row: %v", operation.name, err)
				}

				// Then
				if got := clusterVersion(t, database); got != operation.version {
					t.Fatalf("version after %s=%d, want %d", operation.name, got, operation.version)
				}
			}
		})
	}
}

func TestClusterVersionTriggers_coverEverySecurityPolicySchemaColumn(t *testing.T) {
	// Given：真实 schema 与触发器；逐列 UPDATE OF 行为是比手写清单更可靠的契约。
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (id,name) VALUES (7,'trigger parity');
		UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	rows, err := database.Query(`SELECT name FROM pragma_table_info('security_policies') ORDER BY cid`)
	if err != nil {
		t.Fatal(err)
	}
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		columns = append(columns, column)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(columns) == 0 {
		t.Fatal("no security_policies columns discovered")
	}

	// When / Then：每列单独出现在 UPDATE 列清单，版本必须恰好递增一次。
	for index, column := range columns {
		quoted := strings.ReplaceAll(column, `"`, `""`)
		statement := fmt.Sprintf(`UPDATE security_policies SET "%s"="%s" WHERE id=7`, quoted, quoted)
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("update column %s: %v", column, err)
		}
		if got := clusterVersion(t, database); got != index+1 {
			t.Errorf("version after updating %s=%d, want %d（触发器 OF 漏列）", column, got, index+1)
		}
	}
}

func TestClusterVersionTriggers_bumpForCrawlerExemptionColumns(t *testing.T) {
	// Given：真实触发器与预热快照缓存。
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode) VALUES (7,'crawler trigger','blocking');
		UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	cluster := services.NewClusterService(database, "")
	if _, _, err := cluster.Snapshot(context.Background(), 0, "", ""); err != nil {
		t.Fatalf("warm snapshot: %v", err)
	}

	// When：每次只改一个爬虫豁免列（不夹带 updated_at 等其他 OF 列）。
	if _, err := database.Exec(`UPDATE security_policies SET geoip_crawler_exempt=1 WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	// Then：开关本身必须使版本失效。
	if got := clusterVersion(t, database); got != 1 {
		t.Errorf("version after crawler exempt update=%d, want 1", got)
	}
	if _, err := database.Exec(`UPDATE security_policies SET geoip_crawler_engines='["googlebot"]' WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 2 {
		t.Errorf("version after crawler engines update=%d, want 2", got)
	}

	// And：版本失效后的快照必须带出新值，而非命中预热缓存。
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot after crawler updates: %v", err)
	}
	var policies []map[string]interface{}
	if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0]["geoip_crawler_exempt"] != float64(1) || policies[0]["geoip_crawler_engines"] != `["googlebot"]` {
		t.Errorf("snapshot crawler values=%+v, want exempt=1 engines=[googlebot]", policies)
	}

	// 回归形状：从节点本地写不得 bump 主端版本链。
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1;
		UPDATE security_policies SET geoip_crawler_exempt=0 WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 2 {
		t.Errorf("version after slave-local update=%d, want unchanged 2", got)
	}
}

func TestClusterVersionTriggers_bumpForIPListSystemColumn(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_ip_lists (id,name,entries,system) VALUES (77,'system toggle','[]',0);
		UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When：只改快照已携带的 system 列。
	if _, err := database.Exec(`UPDATE security_ip_lists SET system=1 WHERE id=77`); err != nil {
		t.Fatal(err)
	}

	// Then
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after system update=%d, want 1", got)
	}
	// 回归形状：普通快照列仍正常 bump。
	if _, err := database.Exec(`UPDATE security_ip_lists SET entries='["203.0.113.1"]' WHERE id=77`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 2 {
		t.Fatalf("version after entries update=%d, want 2", got)
	}
}

func TestClusterVersionTriggers_doNotBumpForAPIKeyLastUsed(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO users (username,password_hash) VALUES ('last_used_owner','hash')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by) VALUES ('last_used','hash','prefix',1)`); err != nil {
		t.Fatalf("seed API key: %v", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER cluster_version_api_keys_update AFTER UPDATE ON api_keys
		BEGIN UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1; END`); err != nil {
		t.Fatalf("install legacy trigger: %v", err)
	}
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("replace triggers: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=100 WHERE id=1"); err != nil {
		t.Fatalf("seed cluster version: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("reset cluster version: %v", err)
	}

	// When
	if _, err := database.Exec(`UPDATE api_keys SET last_used=CURRENT_TIMESTAMP WHERE key_prefix='prefix'`); err != nil {
		t.Fatalf("update last_used: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after last_used update=%d, want 0", got)
	}
}

func TestClusterVersionTriggersBumpForAPIKeyRestrictions(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash) VALUES (1,'owner','hash'); INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by) VALUES (1,'key','hash','prefix',1)`); err != nil {
		t.Fatal(err)
	}
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE api_keys SET mcp_enabled=1,read_only=1,mcp_ip_whitelist='["192.0.2.0/24"]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after API key restriction update=%d, want 1", got)
	}
}

func TestClusterVersionTriggers_bumpForUserPasswordVersion(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,password_version) VALUES (1,'alice','hash',0)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec("UPDATE users SET password_version=1,password_changed_at=CURRENT_TIMESTAMP WHERE id=1"); err != nil {
		t.Fatalf("change password version: %v", err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after password change=%d, want 1", got)
	}
}

func TestClusterPasswordVersionSync_rejects_old_JWT(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (1,'alice','hash','admin',1,0)`); err != nil {
		t.Fatalf("seed slave user: %v", err)
	}
	const clusterToken = "cluster-token"
	snapshot := models.ClusterSnapshot{Version: 1, SchemaVersion: services.CurrentSnapshotSchema, MinReaderVersion: services.CurrentSnapshotSchema, Users: []models.ClusterUser{{ID: 1, Username: "alice", PasswordHash: "new-hash", Role: "admin", IsEnabled: true, PasswordVersion: 1}}, ACME: &models.ClusterACMEState{CAProviders: []models.CAProvider{}, CertificateConfigs: []models.CertificateConfig{}, DNSOwnership: json.RawMessage(`{"version":1,"records":[]}`)}}
	canonicalSnapshot := snapshot
	canonicalSnapshot.Fingerprint = ""
	canonicalSnapshot.Signature = ""
	canonicalSnapshot.CanonicalPayload = nil
	payload, err := json.Marshal(canonicalSnapshot)
	if err != nil {
		t.Fatalf("marshal canonical snapshot: %v", err)
	}
	fingerprint := sha256.Sum256(payload)
	snapshot.Fingerprint = hex.EncodeToString(fingerprint[:])
	snapshot.CanonicalPayload = payload
	mac := hmac.New(sha256.New, []byte(clusterToken))
	_, _ = mac.Write(payload)
	snapshot.Signature = hex.EncodeToString(mac.Sum(nil))
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"data": snapshot})
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0,master_url=?,cluster_token=? WHERE id=1", master.URL, clusterToken); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	cfg := &config.Config{JWTSecret: "jwt-secret", CaddyAdminURL: caddy.URL}
	if _, err := services.NewSyncService(database, cfg, services.NewCaddyService(caddy.URL)).Pull(context.Background()); err != nil {
		t.Fatalf("sync changed password version: %v", err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": float64(1), "username": "alice", "pwd_ver": float64(0), "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("sign old JWT: %v", err)
	}
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.GET("/protected", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("old JWT status=%d body=%q, want 401", response.Code, response.Body.String())
	}
}

func TestClusterVersionTriggers_doNotBumpForCertificateProgress(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain) VALUES ('progress_rule','example.com')`); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=100 WHERE id=1"); err != nil {
		t.Fatalf("seed cluster version: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("reset cluster version: %v", err)
	}

	// When
	if _, err := database.Exec(`UPDATE cert_jobs SET status='processing', message='working', updated_at=CURRENT_TIMESTAMP WHERE rule_id='progress_rule'`); err != nil {
		t.Fatalf("update certificate progress: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after certificate progress update=%d, want 0", got)
	}
}

func TestClusterVersionTriggers_refreshCachedSnapshotWhenCertificateEntersAndLeavesIssued(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	certPEM, keyPEM := clusterVersionCertificatePair(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, domain, enable_tls, tls_source, enabled) VALUES ('status_rule', 'status rule', 'http', 443, 'example.com', 1, 'acme_dns', 1)`); err != nil {
		t.Fatalf("seed enabled ACME rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('status_rule','example.com','downloaded',?,?,datetime('now','+60 days'))`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed downloaded certificate: %v", err)
	}
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	cluster := services.NewClusterService(database, "")
	downloadedSnapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("build downloaded snapshot: %v", err)
	}
	if len(downloadedSnapshot.Certs) != 1 || downloadedSnapshot.Certs[0].RuleID != "status_rule" {
		t.Fatalf("downloaded snapshot certificates=%+v, want status_rule", downloadedSnapshot.Certs)
	}

	// When
	if _, err := database.Exec("UPDATE cert_jobs SET status='issued' WHERE rule_id='status_rule'"); err != nil {
		t.Fatalf("mark certificate issued: %v", err)
	}
	issuedSnapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("build issued snapshot: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after issued=%d, want 0 (status-only, 历史问题)", got)
	}
	if len(issuedSnapshot.Certs) != 1 || issuedSnapshot.Certs[0].RuleID != "status_rule" {
		t.Fatalf("issued snapshot certificates=%+v, want status_rule", issuedSnapshot.Certs)
	}

	// When
	if _, err := database.Exec("UPDATE cert_jobs SET status='disabled' WHERE rule_id='status_rule'"); err != nil {
		t.Fatalf("disable certificate: %v", err)
	}
	disabledSnapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("build disabled snapshot: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after disabled=%d, want 1 (disabled exception, 历史问题)", got)
	}
	if len(disabledSnapshot.Certs) != 0 {
		t.Fatalf("disabled snapshot certificates=%+v, want none", disabledSnapshot.Certs)
	}
}

func TestClusterVersionTriggers_bumpForTimestampOnlyUpdates(t *testing.T) {
	// created_at/updated_at 属于快照 payload（cluster_snapshot.go 的 rules 与
	// ACME 证书候选节），时间戳单列更新也必须递增 cluster_version，否则指纹漂移。
	t.Run("lb_rules", func(t *testing.T) {
		database := newClusterVersionTestDB(t)
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('stamp_rule','rule','http',8080)`); err != nil {
			t.Fatalf("seed rule: %v", err)
		}
		if err := InstallClusterVersionTriggers(database); err != nil {
			t.Fatalf("install triggers: %v", err)
		}
		if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
			t.Fatalf("seed master: %v", err)
		}

		if _, err := database.Exec(`UPDATE lb_rules SET updated_at=datetime('now') WHERE caddy_id='stamp_rule'`); err != nil {
			t.Fatalf("update rule timestamp: %v", err)
		}
		if got := clusterVersion(t, database); got != 1 {
			t.Fatalf("version after rule updated_at=%d, want 1", got)
		}
	})

	t.Run("cert_jobs member", func(t *testing.T) {
		database := newClusterVersionTestDB(t)
		certPEM, keyPEM := clusterVersionCertificatePair(t)
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('stamp_cert','example.com','issued',?,?,datetime('now','+30 days'))`, certPEM, keyPEM); err != nil {
			t.Fatalf("seed issued job: %v", err)
		}
		if err := InstallClusterVersionTriggers(database); err != nil {
			t.Fatalf("install triggers: %v", err)
		}
		if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
			t.Fatalf("seed master: %v", err)
		}

		if _, err := database.Exec(`UPDATE cert_jobs SET updated_at=datetime('now') WHERE rule_id='stamp_cert'`); err != nil {
			t.Fatalf("update job timestamp: %v", err)
		}
		// updated_at 是簿记列——单列更新不再 bump
		// ( 旧语义已改:簿记抖动不再触发全集群重放)
		if got := clusterVersion(t, database); got != 0 {
			t.Fatalf("version after member cert updated_at=%d, want 0 (bookkeeping column, 历史问题)", got)
		}
	})

	t.Run("cert_jobs non-member", func(t *testing.T) {
		database := newClusterVersionTestDB(t)
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('stamp_progress','example.com','processing')`); err != nil {
			t.Fatalf("seed progress job: %v", err)
		}
		if err := InstallClusterVersionTriggers(database); err != nil {
			t.Fatalf("install triggers: %v", err)
		}
		if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
			t.Fatalf("seed master: %v", err)
		}

		if _, err := database.Exec(`UPDATE cert_jobs SET updated_at=datetime('now') WHERE rule_id='stamp_progress'`); err != nil {
			t.Fatalf("update job timestamp: %v", err)
		}
		if got := clusterVersion(t, database); got != 0 {
			t.Fatalf("version after non-member cert updated_at=%d, want 0", got)
		}
	})
}

func clusterVersionCertificatePair(t *testing.T) (string, string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	pair := server.TLS.Certificates[0]
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatalf("marshal test certificate key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func TestClusterVersionTriggers_doNotBumpForGlobalSyncMetadata(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=100 WHERE id=1"); err != nil {
		t.Fatalf("seed cluster version: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("reset cluster version: %v", err)
	}

	// When
	if _, err := database.Exec("UPDATE global_config SET last_sync=CURRENT_TIMESTAMP WHERE id=1"); err != nil {
		t.Fatalf("update sync metadata: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after sync metadata update=%d, want 0", got)
	}
}

func newClusterVersionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	return database
}

func clusterVersion(t *testing.T, database *sql.DB) int {
	t.Helper()
	var version int
	if err := database.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	return version
}

// CL-新1:security_crs_version/security_ip2region_version 的
// last_checked 列是读路径指标(页面浏览即写),必须从触发器 OF 列表排除——
// 否则 CRS 页面浏览触发 cluster_version+1 → 快照 304 门失效 → 全量下发 +
// 各从节点强制 Caddy 重载。
func TestClusterVersionTrigger_lastCheckedExcluded(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	// 种子行 + 版本重置
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_crs_version (id, version) VALUES (1, '4.28.0')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	readV := func() int64 {
		var v int64
		if err := database.QueryRow("SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	base := readV()

	// 写 last_checked(模拟页面浏览的 RefreshLatestAsync)
	if _, err := database.Exec("UPDATE security_crs_version SET last_checked=datetime('now') WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if v := readV(); v != base {
		t.Errorf("last_checked-only update bumped cluster_version %d→%d, want unchanged (excluded from OF list)", base, v)
	}

	// 写业务列(版本变更)仍应 bump
	if _, err := database.Exec("UPDATE security_crs_version SET version='4.29.0-test' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if v := readV(); v != base+1 {
		t.Errorf("version update should bump cluster_version to %d, got %d", base+1, v)
	}
}

// 规则库版本表的运行态簿记列不参与 bump 判定——生产常态轮只写这些列
// （每轮开始标记 + 「已是最新版本」终态 + 失败/取消终态），若照常 bump，
// 默认排程下 CRS/IP2Region 每日各两轮常态检查即让 cluster_version 逐轮 +1，
// 全部从节点 304 门失效并拉取整包快照重写两表。语义列（version/updated_at/
// auto_update/排程）值真实变化照常 bump。
func TestClusterVersionTrigger_runtimeBookkeepingExcluded(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	for _, seed := range []string{
		`INSERT OR IGNORE INTO security_crs_version (id, version) VALUES (1, '4.28.0')`,
		`INSERT OR IGNORE INTO security_ip2region_version (id, version) VALUES (1, 'v3.17.0')`,
	} {
		if _, err := database.Exec(seed); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	runtimeWrites := []struct{ name, stmt string }{
		{"crs 每轮开始", `UPDATE security_crs_version SET trigger='schedule', started_at=datetime('now'), last_checked=datetime('now'), finished_at=NULL WHERE id=1`},
		{"crs 已是最新", `UPDATE security_crs_version SET update_status='success', message='已是最新版本', finished_at=datetime('now'), next_update='2026-10-24 04:00:00' WHERE id=1`},
		{"crs 失败终态", `UPDATE security_crs_version SET update_status='failed', message='下载失败', finished_at=datetime('now'), next_update='2026-10-24 04:00:00' WHERE id=1`},
		{"ip2region 每轮开始", `UPDATE security_ip2region_version SET trigger='schedule', started_at=datetime('now'), last_checked=datetime('now'), finished_at=NULL WHERE id=1`},
		{"ip2region 已是最新", `UPDATE security_ip2region_version SET update_status='success', message='已是最新版本', finished_at=datetime('now'), next_update='2026-10-24 04:00:00' WHERE id=1`},
		{"ip2region 取消终态", `UPDATE security_ip2region_version SET update_status='cancelled', message='已取消', finished_at=datetime('now') WHERE id=1`},
	}
	for _, write := range runtimeWrites {
		if _, err := database.Exec(write.stmt); err != nil {
			t.Fatalf("%s: %v", write.name, err)
		}
		if got := clusterVersion(t, database); got != 0 {
			t.Fatalf("%s 写入后 cluster_version=%d, want 0（运行态簿记列不得 bump）", write.name, got)
		}
	}

	semanticWrites := []struct{ name, stmt string }{
		{"crs 版本变化", `UPDATE security_crs_version SET version='4.29.0', updated_at=datetime('now') WHERE id=1`},
		{"ip2region 自动更新开关", `UPDATE security_ip2region_version SET auto_update=0 WHERE id=1`},
		{"ip2region 版本变化", `UPDATE security_ip2region_version SET version='v3.18.0' WHERE id=1`},
	}
	for i, write := range semanticWrites {
		if _, err := database.Exec(write.stmt); err != nil {
			t.Fatalf("%s: %v", write.name, err)
		}
		if got := clusterVersion(t, database); got != i+1 {
			t.Fatalf("%s 写入后 cluster_version=%d, want %d（语义列变化须 bump）", write.name, got, i+1)
		}
	}
}

// v6 开关与 v6 库版本是语义列：主端切换/安装必须 bump cluster_version 让从端
// 304 门失效（从端渲染门只读 v6_enabled，快照列/apply 通道已建全；触发面若被
// 运行态清单排除，主从 xdb_v6_path 渲染分叉无限期不收敛——主端 IPv6 精确
// 解析、从端按「海外」哨兵拦截/放行）。v6_updated_at/v6_update_status/
// v6_message 仍是每轮任务簿记，保持运行态豁免（「已是最新」轮不 bump）；
// 同值重复写（重试/重放）不 bump（值变化守卫）。
func TestClusterVersionTrigger_v6EnabledToggleBumps(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_ip2region_version (id, version, v6_enabled, v6_version) VALUES (1, 'v3.17.0', 0, 'v3.17.0')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	// 语义形状：切换 v6 开关（真实值变化）必须 bump。
	if _, err := database.Exec(`UPDATE security_ip2region_version SET v6_enabled=1, v6_updated_at=datetime('now') WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("v6 开关切换后 cluster_version=%d, want 1（语义列变化必须 bump，从端 304 门依赖）", got)
	}

	// 回归形状（防过宽）：v6 更新任务「已是最新」轮只写运行态三列 → 不 bump。
	if _, err := database.Exec(`UPDATE security_ip2region_version SET v6_updated_at=datetime('now'), v6_update_status='success', v6_message='已是最新版本' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("v6 运行态簿记写入后 cluster_version=%d, want 1（每轮例行检查不得 bump）", got)
	}

	// v6 库版本安装（真实语义变化）随行 bump。
	if _, err := database.Exec(`UPDATE security_ip2region_version SET v6_version='v3.18.0', v6_updated_at=datetime('now') WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 2 {
		t.Fatalf("v6 版本安装后 cluster_version=%d, want 2（库版本是语义列）", got)
	}

	// 同值重复写不 bump：开关值未变、仅 updated_at（运行态）变。
	if _, err := database.Exec(`UPDATE security_ip2region_version SET v6_enabled=1, v6_updated_at=datetime('now') WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 2 {
		t.Fatalf("v6 开关同值写后 cluster_version=%d, want 2（值变化守卫防同值抖动）", got)
	}
}

// 三规则库排程列入集群同步——版本表 schedule_days/
// schedule_time 与 global_config 威胁库三列（threat_auto_update/threat_schedule_days/
// threat_schedule_time）自身入触发器 OF 列表：排程写入即 bump cluster_version，
// 从端经 304 失效收敛。（生产排程保存同语句还写 next_update——本测试刻意只写
// 排程列，钉排程列自身的 OF 成员资格，而非搭车 next_update 的偶然 bump。）
func TestClusterVersionTrigger_ruleLibScheduleBumps(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_crs_version (id, version) VALUES (1, '4.28.0')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_ip2region_version (id, version) VALUES (1, 'v3.17.0')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name string
		stmt string
	}{
		{"crs 排程列", `UPDATE security_crs_version SET schedule_days='2', schedule_time='04:30' WHERE id=1`},
		{"ip2region 排程列", `UPDATE security_ip2region_version SET schedule_days='1,3,5', schedule_time='23:15' WHERE id=1`},
		{"威胁库排程列", `UPDATE global_config SET threat_schedule_days='7', threat_schedule_time='05:00' WHERE id=1`},
		{"威胁库总开关", `UPDATE global_config SET threat_auto_update=0 WHERE id=1`},
		{"爬虫排程列", `UPDATE global_config SET crawler_schedule_days='6', crawler_schedule_time='06:00' WHERE id=1`},
		{"爬虫总开关", `UPDATE global_config SET crawler_auto_update=0 WHERE id=1`},
	}
	for i, step := range steps {
		if _, err := database.Exec(step.stmt); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if got := clusterVersion(t, database); got != i+1 {
			t.Fatalf("%s 写入后 cluster_version=%d, want %d（排程列须入 OF 触发 bump）", step.name, got, i+1)
		}
	}
}

// branding_json 入 OF 列表(2026-09-11):主节点镜像写入 bump cluster_version,
// 使快照缓存失效、变更流向从节点。
func TestClusterVersionTrigger_brandingJSONBumps(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET branding_json='{"app_name":"X"}' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Errorf("branding_json update should bump cluster_version to 1, got %d", got)
	}
	// 从节点写不 bump(WHEN 守卫)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET branding_json='{"app_name":"Y"}' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Errorf("slave write must not bump, got %d", got)
	}
}

// 登录热路径同值写 login_locked_until(NULL→NULL、
// CASE 保值)不得 bump——SQLite OF 触发器按 SET 列出现即触发,此前每次成功
// 登录/失败尝试都引发全集群快照重放+从节点强制 Caddy 重载;真实置锁/解锁
// 过渡仍须 bump。
func TestClusterVersionTrigger_loginHotPathNoBump(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	// 每条种子的 error 必须显式检查：schema 漂移（列改名/删表）时静默失败
	// 会让后续「版本不涨」断言变成空转（误报成 bump 语义问题）。
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,login_failed_attempts,login_locked_until) VALUES (1,'u','h','admin',1,0,NULL)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed global_config: %v", err)
	}

	// 成功登录路径:同值 NULL→NULL 写
	if _, err := database.Exec(`UPDATE users SET login_failed_attempts=0, login_locked_until=NULL WHERE id=1`); err != nil {
		t.Fatalf("same-value write: %v", err)
	}
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("same-value NULL write bumped version to %d, want 0 (登录热路径)", got)
	}

	// 失败计数路径:CASE 保值(未达阈值)
	if _, err := database.Exec(`UPDATE users SET login_failed_attempts=COALESCE(login_failed_attempts,0)+1, login_locked_until=CASE WHEN COALESCE(login_failed_attempts,0)+1>=5 THEN datetime('now','+10 minutes') ELSE login_locked_until END WHERE id=1`); err != nil {
		t.Fatalf("case-preserving write: %v", err)
	}
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("CASE same-value write bumped version to %d, want 0", got)
	}

	// 真实置锁:值变化 → bump
	if _, err := database.Exec(`UPDATE users SET login_locked_until=datetime('now','+10 minutes') WHERE id=1`); err != nil {
		t.Fatalf("lock write: %v", err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("real lock transition should bump to 1, got %d", got)
	}

	// 真实解锁 → bump
	if _, err := database.Exec(`UPDATE users SET login_locked_until=NULL WHERE id=1`); err != nil {
		t.Fatalf("unlock write: %v", err)
	}
	if got := clusterVersion(t, database); got != 2 {
		t.Fatalf("unlock should bump to 2, got %d", got)
	}
}

// 自动备份六设置列入 global_config 触发器 OF 列表——
// 主端保存设置 bump cluster_version,从端经 304 失效收敛;auto_backup_last_run
// 为节点本地运行态(调度器每次备份推进),必须排除在 OF 列表外,否则每次备份
// 引发全集群快照重放。
func TestClusterVersionTrigger_autoBackupSettingsBumpLastRunExcluded(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	for i, stmt := range []string{
		"UPDATE global_config SET auto_backup_enabled=1 WHERE id=1",
		"UPDATE global_config SET auto_backup_frequency='weekly' WHERE id=1",
		"UPDATE global_config SET auto_backup_time='04:30' WHERE id=1",
		"UPDATE global_config SET auto_backup_day=3 WHERE id=1",
		"UPDATE global_config SET auto_backup_keep=5 WHERE id=1",
		`UPDATE global_config SET auto_backup_sections='["users"]' WHERE id=1`,
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatal(err)
		}
		if got := clusterVersion(t, database); got != i+1 {
			t.Fatalf("%q should bump cluster_version to %d, got %d", stmt, i+1, got)
		}
	}
	// last_run 推进不得 bump(调度器每次备份都写)
	if _, err := database.Exec("UPDATE global_config SET auto_backup_last_run='2026-09-19T03:00:00+08:00' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 6 {
		t.Fatalf("auto_backup_last_run update must not bump, got %d", got)
	}
	// 从端写入不 bump(WHEN is_master 守卫)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET auto_backup_keep=9 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 6 {
		t.Fatalf("slave write must not bump, got %d", got)
	}
}

// lb_rules 触发器 OF 清单补阶段拦截页 4 列——
// block_page_stage1_id/status、block_page_stage3_id/status 是同步面列
// (cluster_snapshot.go dump 与 cluster_apply.go 重放均携带),此前不在 OF
// 清单:UpdateRule 指针逐列拼装与 BatchRuleBlockPages 单事务 4 列 UPDATE
// 不 bump cluster_version,快照缓存持续命中旧指纹,阶段页变更经 304 门
// 永不传播到从节点。
func TestClusterVersionTrigger_bumpsOnStagePageColumns(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_stage_of','stage-of','http',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	// 目标形状:仅写阶段页 4 列(batch-block-pages 单事务 UPDATE 形态)必须 bump
	if _, err := database.Exec(`UPDATE lb_rules SET block_page_stage1_id=7, block_page_stage1_status=403, block_page_stage3_id=8, block_page_stage3_status=503 WHERE caddy_id='lb_stage_of'`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("stage page columns update should bump cluster_version to 1, got %d", got)
	}

	// 目标形状:单列写(UpdateRule 指针逐列拼装形态)同样 bump
	if _, err := database.Exec(`UPDATE lb_rules SET block_page_stage3_status=404 WHERE caddy_id='lb_stage_of'`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 2 {
		t.Fatalf("single stage page column update should bump cluster_version to 2, got %d", got)
	}

	// 回归形状:既有 OF 列赋值仍 bump
	if _, err := database.Exec(`UPDATE lb_rules SET description='of-bumped' WHERE caddy_id='lb_stage_of'`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 3 {
		t.Fatalf("existing OF column update should bump cluster_version to 3, got %d", got)
	}

	// 非 OF 列不 bump(OF 语义既有行为):lb_rules 无 last_login 类簿记列,
	// 唯一非 OF 列是 id——仅 SET id 不得触发版本 bump。
	if _, err := database.Exec(`UPDATE lb_rules SET id=id WHERE caddy_id='lb_stage_of'`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 3 {
		t.Fatalf("non-OF column (id) update must not bump, got %d", got)
	}
}

// security_policies 触发器 OF 清单补 policy_type/
// trust_detection——两列是同步面列(快照 dump/apply 携带,从端渲染消费
// stage0 直通与 id:3 并集),此前不在 OF 清单:UpdateSecurityPolicy 仅提交
// 类型或检测开关、或缺省提交触发合并后重推断回写时不 bump,阶段 0 类型与
// 信任语义变更经 304 门滞留主节点。
func TestClusterVersionTrigger_bumpsOnPolicyTypeColumns(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES ('of-typed','blocking','stage3',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,ip_whitelist,ip_whitelist_enabled,policy_type,trust_detection,enabled) VALUES ('of-trust','off','["198.51.100.7"]',1,'stage0',0,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	// 目标形状:仅写 policy_type(显式类型提交/重推断回写形态)必须 bump
	if _, err := database.Exec(`UPDATE security_policies SET policy_type='stage2' WHERE name='of-typed'`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("policy_type update should bump cluster_version to 1, got %d", got)
	}

	// 目标形状:仅写 trust_detection(阶段 0 检测开关形态)必须 bump
	if _, err := database.Exec(`UPDATE security_policies SET trust_detection=1 WHERE name='of-trust'`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 2 {
		t.Fatalf("trust_detection update should bump cluster_version to 2, got %d", got)
	}

	// 回归形状:既有 OF 列赋值仍 bump
	if _, err := database.Exec(`UPDATE security_policies SET mode='detection' WHERE name='of-typed'`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 3 {
		t.Fatalf("existing OF column update should bump cluster_version to 3, got %d", got)
	}
}

// 受信代理四列（trusted_proxy_enabled/ranges/headers/strict）入
// global_config UPDATE 触发器 OF 列表（防御对齐）——主端保存受信代理设置
// 须即 bump cluster_version 随快照下发；不在 OF 内则稳态变更永不传播。
func TestClusterVersionTriggers_bumpForTrustedProxyColumns(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='["203.0.113.0/24"]', trusted_proxy_headers='["CF-Connecting-IP","X-Forwarded-For"]', trusted_proxy_strict=0 WHERE id=1`); err != nil {
		t.Fatalf("update trusted proxy columns: %v", err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after trusted proxy update=%d, want 1", got)
	}

	// 受信代理引用列（trusted_proxy_range_refs）同入 OF——主端改引用名单
	// 须即 bump 版本随快照下发（引用的名单本体在 security 节同步）。
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[1,2]' WHERE id=1`); err != nil {
		t.Fatalf("update trusted proxy range refs: %v", err)
	}
	if got := clusterVersion(t, database); got != 2 {
		t.Fatalf("version after trusted_proxy_range_refs update=%d, want 2", got)
	}
}

// Given loginRateBuckets 已满 1024 桶（容量上限）。
// When clusterRateLimit 命中新 IP（曾建桶无检查——分布式攻击可推满
// 共享 map 使登录限流对新源 fail-open）。
// Then LRU 淘汰最久未命中桶为新 IP 建桶：请求照常记账（起不再放行
// 不计数），map 规模保持上限。
func TestClusterRateLimitRespectsBucketCap(t *testing.T) {
	withIsolatedRateLimitBuckets(t)
	now := time.Now()
	loginRateBuckets.Lock()
	for i := range rateLimitBucketCapacity {
		bucket := &loginRateBucket{until: now.Add(time.Minute), count: 1}
		bucket.lastUsed.Store(now.Add(time.Duration(i) * time.Millisecond).UnixNano())
		loginRateBuckets.entries[fmt.Sprintf("cap-%d", i)] = bucket
	}
	loginRateBuckets.Unlock()
	h := clusterRateLimit("test", 30, "测试限流")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/cluster/service-control", nil)
	c.Request.RemoteAddr = "203.0.113.77:1234"
	h(c) // 不 panic
	loginRateBuckets.Lock()
	bucket, exists := loginRateBuckets.entries["203.0.113.77|test"]
	_, oldestEvicted := loginRateBuckets.entries["cap-0"]
	size := len(loginRateBuckets.entries)
	loginRateBuckets.Unlock()
	if !exists {
		t.Fatal("容量满时必须 LRU 淘汰建桶——跳过建桶=新来源本分钟零限流（fail-open）")
	}
	if bucket.count != 1 {
		t.Fatalf("新桶计数=%d，want 1（请求必须被真实记账）", bucket.count)
	}
	if oldestEvicted {
		t.Fatal("LRU 淘汰应移除最久未命中的桶（cap-0）")
	}
	if size > rateLimitBucketCapacity {
		t.Fatalf("桶表越界：%d > %d", size, rateLimitBucketCapacity)
	}
}

// threat 源的 consecutive_failures 是纯运行态失败计数
// （failSourceRow 每次失败独立 UPDATE +1），必须与 last_checked 同法从 UPDATE
// OF 触发列排除——否则源持续不可达期间每轮失败写都 bump cluster_version，
// 快照 304 门失效、全集群重放。
func TestClusterVersionTrigger_threatConsecutiveFailuresExcluded(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_threat_sources (id, name) VALUES (1, 'ustc')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	readV := func() int64 {
		var v int64
		if err := database.QueryRow("SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	base := readV()

	// 写失败计数（failSourceRow 形态：独立 UPDATE consecutive_failures+1）
	if _, err := database.Exec("UPDATE security_threat_sources SET consecutive_failures=consecutive_failures+1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if v := readV(); v != base {
		t.Errorf("consecutive_failures-only update bumped cluster_version %d→%d, want unchanged (excluded from OF list)", base, v)
	}

	// 回归形状：真实同步列（版本）仍 bump
	if _, err := database.Exec("UPDATE security_threat_sources SET version='20261003' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if v := readV(); v != base+1 {
		t.Errorf("version update should bump cluster_version to %d, got %d", base+1, v)
	}
}

// 规则面三表新列 OF 钉测试——lb_rules.health_check_host、
// upstreams.origin_domain、path_rules.upstream_path/response_* 均为快照同步面列
// （主端导出 SELECT 与从端 INSERT 均携带），OF 漏列则单列 UPDATE 不 bump
// cluster_version → 快照缓存恒命中旧指纹 → 从端 304 循环，该列稳态永不传播
// 每步只写目标单列，钉该列自身的 OF 成员资格。
// NTLM 两列（lb_rules.ntlm_compatible/
// upstream_force_http1，快照同步面列）补入 steps——900 字符单行 OF 清单无
// 绊线，未来重构丢列会让 NTLM 切换在从节点稳态永不传播（基线钉测试：列
// 已在 OF 内，钉既有正确行为）。
func TestClusterVersionTriggers_bumpForRuleSurfaceNewColumns(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_newcol','newcol','http',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_newcol','127.0.0.1',9000,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_newcol',0,'prefix','/api')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name string
		stmt string
	}{
		{"lb_rules.ntlm_compatible", `UPDATE lb_rules SET ntlm_compatible=1 WHERE caddy_id='lb_newcol'`},
		{"lb_rules.upstream_force_http1", `UPDATE lb_rules SET upstream_force_http1=1 WHERE caddy_id='lb_newcol'`},
		{"upstreams.origin_domain", `UPDATE upstreams SET origin_domain='origin.example.test' WHERE rule_id='lb_newcol'`},
		{"path_rules.upstream_path", `UPDATE path_rules SET upstream_path='/v2' WHERE rule_id='lb_newcol'`},
		{"path_rules.response_mode", `UPDATE path_rules SET response_mode='static' WHERE rule_id='lb_newcol'`},
		{"path_rules.response_status", `UPDATE path_rules SET response_status=201 WHERE rule_id='lb_newcol'`},
		{"path_rules.response_body", `UPDATE path_rules SET response_body='pong' WHERE rule_id='lb_newcol'`},
		{"path_rules.response_content_type", `UPDATE path_rules SET response_content_type='text/plain' WHERE rule_id='lb_newcol'`},
		{"path_rules.redirect_to", `UPDATE path_rules SET redirect_to='https://example.test/landing' WHERE rule_id='lb_newcol'`},
	}
	for i, step := range steps {
		if _, err := database.Exec(step.stmt); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if got := clusterVersion(t, database); got != i+1 {
			t.Fatalf("%s 单列 UPDATE 后 cluster_version=%d, want %d（新列须入 OF 触发 bump）", step.name, got, i+1)
		}
	}
}

// 威胁/爬虫源表的运行态簿记列（status/message/started_at/
// finished_at）每轮例行更新都会写，UPDATE OF 只要列在 SET 即触发。改为语义列
// 值变化守卫后：源持续不可达的失败轮、例行 running→success 的纯簿记变化不再
// bump（304 门保持有效），数据/开关类语义列变化照常 bump。
func TestClusterVersionTrigger_sourceRuntimeColumnsDoNotBump(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_threat_sources (id, name) VALUES (1, 'ustc')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_crawler_sources (id, name) VALUES (1, 'crawler')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	readV := func() int64 {
		var v int64
		if err := database.QueryRow("SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	base := readV()

	runtimeUpdates := []string{
		"UPDATE security_threat_sources SET update_status='running', started_at=datetime('now') WHERE id=1",
		"UPDATE security_threat_sources SET update_status='failed', message='timeout', finished_at=datetime('now') WHERE id=1",
		"UPDATE security_threat_sources SET last_checked=datetime('now'), next_update=datetime('now','+1 day'), trigger='schedule' WHERE id=1",
		"UPDATE security_crawler_sources SET update_status='running', started_at=datetime('now') WHERE id=1",
		"UPDATE security_crawler_sources SET update_status='failed', message='timeout', finished_at=datetime('now') WHERE id=1",
	}
	for _, stmt := range runtimeUpdates {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
		if v := readV(); v != base {
			t.Fatalf("runtime-only update bumped cluster_version %d→%d, want unchanged: %s", base, v, stmt)
		}
	}

	semanticUpdates := []string{
		"UPDATE security_threat_sources SET entry_count=42 WHERE id=1",
		"UPDATE security_crawler_sources SET version='20261020' WHERE id=1",
	}
	want := base
	for _, stmt := range semanticUpdates {
		want++
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
		if v := readV(); v != want {
			t.Fatalf("semantic update should bump cluster_version to %d, got %d: %s", want, v, stmt)
		}
	}
}
