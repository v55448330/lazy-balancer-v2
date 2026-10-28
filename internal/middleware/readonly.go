package middleware

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func readOnlyGuard(database *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		routePath := c.FullPath()
		if routePath == "" {
			routePath = path
		}
		// 写方法判定收敛至包级 writeMethods
		// （middleware.go）——与原 switch 四形态同义集合。
		if !writeMethods[c.Request.Method] {
			c.Next()
			return
		}
		if services.IsReadOnlyWriteRoute(c.Request.Method, routePath) {
			c.Next()
			return
		}
		// 角色读取单源（COALESCE 兜底语义在 services.RoleOf 内；读失败
		// 仍按 500 fail-closed，与写闸原语义一致）。
		isMaster, err := services.RoleOf(c.Request.Context(), database)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "节点角色查询失败"})
			return
		}
		if !isMaster {
			// 从节点仅放行集群管理与认证路径
			if isReadOnlyGuardWhitelisted(path) {
				c.Next()
				return
			}
			recordAuthenticationRejection(c, "slave_write_denied")
			c.AbortWithStatusJSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "从节点只读，请在主节点操作"})
			return
		}
		if c.GetString("role") != "admin" {
			// 主节点非管理员仅放行自管理（个人资料、自己的 API 密钥、
			// 用户管理页的本人编辑/重置密码——后者为重置语义，无当前密码）。
			if isSelfServicePath(path) || isSelfServiceUserWrite(c) {
				c.Next()
				return
			}
			recordAuthenticationRejection(c, "non_admin_write_denied")
			c.AbortWithStatusJSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "非管理员用户只读"})
			return
		}
		c.Next()
	}
}

func isReadOnlyGuardWhitelisted(path string) bool {
	// verify-step 入白名单——MFA 写守卫开启的
	// 从节点 JWT 用户此前 428(需验码)↔403(verify-step 被只读拒)互封,
	// promote/forget-pins 补救通道不可达;verify-step 仅写非同步簿记列
	// (users 触发器 OF 列表不含 mfa_last_timestep),从节点本地执行无
	// 同步副作用,与 /auth/logout 同理放行。
	// login 公开路由、logout 挂 v1 级，当前均不经
	// 本守卫（仅 admin/business 组级）——两条目为挪组防御（若日后路由
	// 挪入组级，白名单仍须放行，对齐 middleware.go mfaStepUpGuard 同款
	// 防御性豁免）。
	return path == "/api/v1/auth/login" ||
		path == "/api/v1/auth/logout" ||
		path == "/api/v1/auth/mfa/verify-step" ||
		// 原「path == /api/v1/cluster 精确匹配」已删——
		// 生产路由面无精确注册（全部经 /cluster/ 前缀分支覆盖），永假死分支。
		strings.HasPrefix(path, "/api/v1/cluster/")
}

// isSelfServicePath 是主节点上非管理员用户可自助维护资源的路径
// isSelfServiceUserWrite 报告当前写请求是否为「用户管理页本人行」操作：
// PUT /api/v1/users/<自己的 id> 或 POST /api/v1/users/<自己的 id>/reset-password。
// 方法必须显式限定——不能只依赖「当前没有 POST/DELETE /api/v1/users/<id> 路由」
// 这条隐式前提（新增自助/管理路由时会把别的语义误判成自助写）。
// 只接受数字 id，不接受 :id 模板——工具可见性枚举（按路由模板）不会因此把
// update_user 暴露给非管理员。
func isSelfServiceUserWrite(c *gin.Context) bool {
	path := strings.TrimPrefix(c.Request.URL.Path, "/api/v1/users/")
	if path == c.Request.URL.Path {
		// 前缀不匹配（TrimPrefix 原样返回）：不是用户资源路径。
		return false
	}
	if i := strings.IndexByte(path, '/'); i >= 0 {
		if path[i:] != "/reset-password" || c.Request.Method != http.MethodPost {
			return false
		}
		path = path[:i]
	} else if c.Request.Method != http.MethodPut {
		return false
	}
	_, self := selfServiceUserTarget(c, path)
	return self
}

func isSelfServicePath(path string) bool {
	return path == "/api/v1/users/me" ||
		path == "/api/v1/users/me/api-keys" ||
		strings.HasPrefix(path, "/api/v1/users/me/api-keys/") ||
		// MFA 自助端点（setup/activate/disable/recovery-codes/
		// verify-step）——仅操作调用者本人第二因子，与 /users/me 同属自助维护，
		// 此前漏白名单致非 admin 用户 403（UI 却对全体展示卡片）。
		strings.HasPrefix(path, "/api/v1/auth/mfa/") ||
		// logout 属自助语义。当前路由注册于 v1 组
		// 不经本守卫(行为已正确),此处收录为防御性对齐——未来若挪入
		// business 组,非管理员登出不因守卫误拒(与从节点白名单 :69 同理)。
		path == "/api/v1/auth/logout"
}
