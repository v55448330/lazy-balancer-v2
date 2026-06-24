package handlers

import (
	"database/sql"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) GetMetricsOverview(c *gin.Context) {
	overview := h.metricsService.GetOverview()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: overview})
}


func (h *Handlers) GetRuleMetrics(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var totalRequests, requests2xx, requests3xx, requests4xx, requests5xx int64
	var bytesIn, bytesOut int64

	db.DB.QueryRow(`
		SELECT COALESCE(SUM(requests_total), 0), COALESCE(SUM(requests_2xx), 0),
		       COALESCE(SUM(requests_3xx), 0), COALESCE(SUM(requests_4xx), 0),
		       COALESCE(SUM(requests_5xx), 0), COALESCE(SUM(bytes_in), 0),
		       COALESCE(SUM(bytes_out), 0)
		FROM metrics_history 
		WHERE rule_id = ? AND timestamp > datetime('now', '-1 hour')
	`, caddyID).Scan(&totalRequests, &requests2xx, &requests3xx, &requests4xx, &requests5xx, &bytesIn, &bytesOut)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"total_requests": totalRequests,
		"status_2xx":     requests2xx,
		"status_3xx":     requests3xx,
		"status_4xx":     requests4xx,
		"status_5xx":     requests5xx,
		"bytes_in":       bytesIn,
		"bytes_out":      bytesOut,
	}})
}


func (h *Handlers) GetMetricsHistory(c *gin.Context) {
	ruleID := c.Query("rule_id")
	interval := c.DefaultQuery("interval", "1h")

	var rows *sql.Rows
	var err error

	if ruleID != "" {
		rows, err = db.DB.Query(`
			SELECT timestamp, requests_total, requests_2xx, requests_3xx, 
			       requests_4xx, requests_5xx, bytes_in, bytes_out
			FROM metrics_history 
			WHERE rule_id = ? AND timestamp > datetime('now', '-'+?)
			ORDER BY timestamp
		`, ruleID, interval)
	} else {
		rows, err = db.DB.Query(`
			SELECT timestamp, SUM(requests_total), SUM(requests_2xx), SUM(requests_3xx), 
			       SUM(requests_4xx), SUM(requests_5xx), SUM(bytes_in), SUM(bytes_out)
			FROM metrics_history 
			WHERE timestamp > datetime('now', '-'+?)
			GROUP BY timestamp
			ORDER BY timestamp
		`, interval)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	type MetricRow struct {
		Timestamp     time.Time `json:"timestamp"`
		RequestsTotal int64     `json:"requests_total"`
		Status2xx     int64     `json:"status_2xx"`
		Status3xx     int64     `json:"status_3xx"`
		Status4xx     int64     `json:"status_4xx"`
		Status5xx     int64     `json:"status_5xx"`
		BytesIn       int64     `json:"bytes_in"`
		BytesOut      int64     `json:"bytes_out"`
	}

	var metrics []MetricRow
	for rows.Next() {
		var m MetricRow
		rows.Scan(&m.Timestamp, &m.RequestsTotal, &m.Status2xx, &m.Status3xx,
			&m.Status4xx, &m.Status5xx, &m.BytesIn, &m.BytesOut)
		metrics = append(metrics, m)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}


func (h *Handlers) GetCaddyMetrics(c *gin.Context) {
	resp, err := http.Get(h.cfg.CaddyAdminURL + "/metrics")
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: models.CaddyMetrics{}})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	metrics := parsePrometheusMetrics(string(body))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}


func (h *Handlers) GetHostMetrics(c *gin.Context) {
	resp, err := http.Get(h.cfg.CaddyAdminURL + "/metrics")
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: []models.HostMetrics{}})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	metrics := parseHostMetrics(string(body))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

