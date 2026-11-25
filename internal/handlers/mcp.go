package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) GetMCPTools(c *gin.Context) {
	c.JSON(http.StatusOK, models.APIResponse{
		Code:    0,
		Message: apimsg.T("common.querySucceeded"), MessageKey: "common.querySucceeded",
		Data: mcpserver.ListToolSpecs(),
	})
}

func (h *Handlers) GetMCPOpsPlaybook(c *gin.Context) {
	c.Header("Content-Disposition", `attachment; filename="lazy-balancer-mcp-ops-playbook.md"`)
	c.Data(http.StatusOK, "text/markdown; charset=utf-8", []byte(mcpserver.OpsPlaybook()))
}
