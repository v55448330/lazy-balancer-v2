package middleware

import (
	"database/sql"
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
			token = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		}
		nodeID, err := services.AuthenticateClusterToken(c.Request.Context(), database, token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "集群凭证无效"})
			return
		}
		c.Set("cluster_node_id", nodeID)
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
			secret = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		}
		if err := services.AuthenticateRegistrationSecret(c.Request.Context(), database, nodeID, secret); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "注册凭证无效"})
			return
		}
		c.Set("registration_secret", secret)
		c.Next()
	}
}
