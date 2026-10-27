package middleware

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func clusterTokenAuth(database *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("X-Cluster-Token")
		if token == "" {
			token = bearerToken(c.GetHeader("Authorization"))
		}
		nodeID, err := services.AuthenticateClusterToken(c.Request.Context(), database, token)
		if err != nil {
			if errors.Is(err, services.ErrInvalidClusterAuth) {
				// 机器凭据枚举尝试必须留审计痕迹——此前
				// 只计入内存限流桶，进程重启即清零，事件响应与取证零线索。
				recordAuthenticationRejection(c, "cluster_token_invalid")
				// 机器可读错误码：从节点 Pull 据此区分「本服务撤销令牌」（终止）
				// 与前置代理/身份网关的 401（可重试自愈）。
				c.Header("X-LB-Error-Code", services.ClusterTokenInvalidErrorCode)
				c.AbortWithStatusJSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "集群凭证无效"})
			} else {
				services.Logf("error", "cluster token authentication failed: %v", err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "集群凭证校验失败"})
			}
			return
		}
		c.Set("cluster_node_id", nodeID)
		c.Set("cluster_token", token)
		c.Next()
	}
}

func registrationAuth(database *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "注册编号无效"})
			return
		}
		secret := c.GetHeader("X-Registration-Secret")
		if secret == "" {
			secret = bearerToken(c.GetHeader("Authorization"))
		}
		if err := services.AuthenticateRegistrationSecret(c.Request.Context(), database, nodeID, secret); err != nil {
			if errors.Is(err, services.ErrInvalidClusterAuth) {
				// 注册密钥枚举同样留痕（reason/path/ip 一分钟去重）。
				recordAuthenticationRejection(c, "registration_secret_invalid")
				c.AbortWithStatusJSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "注册凭证无效"})
			} else {
				services.Logf("error", "cluster registration authentication failed: %v", err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "注册凭证校验失败"})
			}
			return
		}
		c.Set("registration_secret", secret)
		c.Next()
	}
}

func bearerToken(authorization string) string {
	token, found := strings.CutPrefix(authorization, "Bearer ")
	if !found || token == "" {
		return ""
	}
	return token
}
