package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) requireMaster(c *gin.Context) bool {
	isMaster, err := h.clusterService.IsMaster(c.Request.Context())
	if err != nil {
		clusterError(c, http.StatusInternalServerError, "读取节点模式失败", err)
		return false
	}
	if !isMaster {
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", nil)
		return false
	}
	return true
}

func clusterError(c *gin.Context, status int, message string, err error) {
	if err != nil {
		log.Printf("cluster request failed: %v", err)
	}
	c.JSON(status, models.APIResponse{Code: status, Message: message})
}
