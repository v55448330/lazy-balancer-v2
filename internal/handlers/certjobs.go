package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) ListCertJobs(c *gin.Context) {
	ruleID := c.Query("rule_id")
	query := "SELECT id, rule_id, domain, status, message, expires_at, created_at, updated_at FROM cert_jobs"
	var args []interface{}
	if ruleID != "" {
		query += " WHERE rule_id = ?"
		args = append(args, ruleID)
	}
	query += " ORDER BY created_at DESC"

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query cert jobs"})
		return
	}
	defer rows.Close()

	var jobs []models.CertJob
	for rows.Next() {
		var j models.CertJob
		if err := rows.Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message,
			&j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt,
		); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: jobs})
}

func (h *Handlers) RetryCertJob(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot retry jobs on slave node"})
		return
	}

	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("UPDATE cert_jobs SET status='issuing', message='重新签发', updated_at=datetime('now') WHERE id=?", id)
	h.applyCaddyConfig()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Retry triggered"})
}

func (h *Handlers) DeleteCertJob(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot delete jobs on slave node"})
		return
	}

	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("DELETE FROM cert_jobs WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Job deleted"})
}

func (h *Handlers) GetCertJob(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var j models.CertJob
	err := db.DB.QueryRow("SELECT id, rule_id, domain, status, message, expires_at, created_at, updated_at FROM cert_jobs WHERE id=?", id).
		Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message, &j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get job"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: j})
}
