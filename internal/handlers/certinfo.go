package handlers

import (
	"net/http"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// GetRuleCertInfo returns parsed certificate information for a single rule.
func (h *Handlers) GetRuleCertInfo(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	info := services.GetRuleCertInfo(caddyID)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

// GetRulesCertInfo returns parsed certificate information for multiple rules in one call.
func (h *Handlers) GetRulesCertInfo(c *gin.Context) {
	var req models.CertInfoBatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request: " + err.Error()})
		return
	}

	if len(req.CaddyIDs) == 0 {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]*models.RuleCertInfo{}})
		return
	}

	// Limit batch size to prevent abuse
	if len(req.CaddyIDs) > 200 {
		req.CaddyIDs = req.CaddyIDs[:200]
	}

	result := services.GetRulesCertInfo(req.CaddyIDs)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}
