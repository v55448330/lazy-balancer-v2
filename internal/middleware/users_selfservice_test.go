package middleware

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
)

func TestAdminOrSelfParam_allowsSelfAndAdminOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name   string
		role   string
		actor  int
		target string
		want   int
	}{
		{"non-admin self", "user", 5, "5", http.StatusOK},
		{"non-admin other", "user", 5, "6", http.StatusForbidden},
		{"admin other", "admin", 1, "6", http.StatusOK},
		{"invalid id", "user", 5, "abc", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPut, "/users/"+tc.target, nil)
			c.Params = gin.Params{{Key: "id", Value: tc.target}}
			c.Set("role", tc.role)
			c.Set("user_id", tc.actor)

			adminOrSelfParam()(c)
			got := rec.Code
			if got == 0 {
				got = http.StatusOK
			}
			if got != tc.want {
				t.Fatalf("status=%d body=%s, want %d", got, rec.Body.String(), tc.want)
			}
		})
	}
}

// 脏角色值（admin/user 之外的取值——旧备份、直接改库可产生）不得绕过自助锁：
// 守卫链按「非管理员 = role != 'admin'」判定、handler 自助锁必须同口径，
// 否则 role='viewer' 的用户可把自己改成 admin。
func TestSelfServiceUserWrite_dirtyRoleCannotEscalate(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (5,'viewer','x','viewer',1)"); err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	h := handlers.NewHandlers(handlers.Dependencies{})

	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		// 模拟 jwtAuth 从库读到的角色（脏值原样入链）与身份
		c.Set("role", "viewer")
		c.Set("user_id", 5)
	})
	engine.PUT("/api/v1/users/:id", readOnlyGuard(db.DB), adminOrSelfParam(), h.UpdateUser)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/v1/users/5", strings.NewReader(`{"role":"admin"}`))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(rec, request)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("dirty-role self escalation: status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
	var role string
	if err := db.DB.QueryRow("SELECT role FROM users WHERE id=5").Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "viewer" {
		t.Fatalf("role=%q, want viewer（自助锁不得被脏角色值绕过）", role)
	}
}

// 只读门侧同口径：脏角色值的写请求（非自助面）必须 403，不得落进「管理员」分支。
func TestReadOnlyGuard_dirtyRoleDenied(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})

	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		c.Set("role", "viewer")
		c.Set("user_id", 5)
	})
	engine.PUT("/api/v1/rules/:id", readOnlyGuard(db.DB), noContent)

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/rules/lb_1", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("dirty-role non-self write: status=%d, want 403", rec.Code)
	}
}

// user_id 类型归一单源：string 形态（MCP 内部转发/测试直连）不得让 actor 归零。
func TestAdminOrSelfParam_stringUserIDForm(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/users/7", nil)
	c.Params = gin.Params{{Key: "id", Value: "7"}}
	c.Set("role", "user")
	c.Set("user_id", "7")
	adminOrSelfParam()(c)
	if rec.Code != 0 && rec.Code != http.StatusOK {
		t.Fatalf("string user_id 形态: status=%d body=%s, want 放行", rec.Code, rec.Body.String())
	}

	if !isSelfServiceUserWrite(func() *gin.Context {
		r := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(r)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/api/v1/users/7", nil)
		ctx.Set("user_id", "7")
		return ctx
	}()) {
		t.Fatal("isSelfServiceUserWrite 应识别 string 形态的本人请求")
	}
}

// 夹具自检：db.Close 内部会 SetDB(nil)，夹具只还原包级变量会让
// db.GetDB()（后台刷新循环等原子句柄消费方）与 db.DB（守卫装配期捕获）分叉
// ——复位序列必须显式 SetDB 回填（单源 restoreTestDBHandles）。
func TestDatabaseHandleParityAfterFixtureRestore(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	var previous *sql.DB
	t.Cleanup(func() {
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
		if previous != nil {
			_ = previous.Close()
		}
	})

	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	previous = db.GetDB()
	if previous == nil {
		t.Fatal("Initialize 后原子句柄不应为 nil")
	}
	// 夹具语境：进入用例前已有库，用例再 Initialize 换库
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("re-initialize database: %v", err)
	}
	_ = db.Close()
	if got := db.GetDB(); got != nil {
		t.Fatal("Close 后原子句柄应为 nil（夹具必须显式回填）")
	}
	restoreTestDBHandles(previous, oldMetricsDB, oldAuditDB)
	if got := db.GetDB(); got != db.DB || got != previous {
		t.Fatal("复位后 db.GetDB() 必须与被还原的包级句柄同源")
	}
}

// 自助写的方法约束必须显式：PUT /users/<own> 与
// POST /users/<own>/reset-password 之外的方法一律不算自助——不再依赖「当前
// 没有对应路由」的隐式前提（新增路由即把别的语义误判成自助写）。
func TestIsSelfServiceUserWrite_methodConstrained(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPut, "/api/v1/users/7", true},
		{http.MethodPost, "/api/v1/users/7/reset-password", true},
		{http.MethodPost, "/api/v1/users/7", false},
		{http.MethodDelete, "/api/v1/users/7", false},
		{http.MethodPatch, "/api/v1/users/7", false},
		{http.MethodPost, "/api/v1/users/7/other", false},
		{http.MethodGet, "/api/v1/users/7/reset-password", false},
		{http.MethodPut, "/api/v1/users/8", false},
		{http.MethodPut, "/api/v1/users/me", false},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(recorder)
			context.Request = httptest.NewRequest(tc.method, tc.path, nil)
			context.Set("user_id", 7)
			if got := isSelfServiceUserWrite(context); got != tc.want {
				t.Fatalf("isSelfServiceUserWrite(%s %s)=%v, want %v", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

// 两个守卫必须共用同一 actor/target 判定：路由参数形态与只读门的原始路径
// 形态虽然入口不同，对同一自助请求不得给出相反结论。
func TestSelfServiceUserWrite_matchesAdminOrSelfParam(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name   string
		method string
		path   string
		target string
		actor  any
	}{
		{"update self", http.MethodPut, "/api/v1/users/7", "7", 7},
		{"reset self", http.MethodPost, "/api/v1/users/7/reset-password", "7", 7},
		{"update other", http.MethodPut, "/api/v1/users/8", "8", 7},
		{"reset other", http.MethodPost, "/api/v1/users/8/reset-password", "8", 7},
		{"missing actor", http.MethodPut, "/api/v1/users/7", "7", 0},
		{"invalid target", http.MethodPut, "/api/v1/users/abc", "abc", 7},
		{"non-positive target", http.MethodPut, "/api/v1/users/0", "0", 7},
		{"string actor", http.MethodPut, "/api/v1/users/7", "7", "7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(recorder)
			context.Request = httptest.NewRequest(tc.method, tc.path, nil)
			context.Params = gin.Params{{Key: "id", Value: tc.target}}
			context.Set("role", "user")
			context.Set("user_id", tc.actor)

			readOnlyDecision := isSelfServiceUserWrite(context)
			adminOrSelfParam()(context)
			adminDecision := !context.IsAborted()
			if readOnlyDecision != adminDecision {
				t.Fatalf("guard parity: isSelfServiceUserWrite=%v adminOrSelfParam=%v", readOnlyDecision, adminDecision)
			}
		})
	}
}
