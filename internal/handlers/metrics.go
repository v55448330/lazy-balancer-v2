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
	ruleID := c.Param("caddy_id")

	var rule models.LbRule
	err := db.DB.QueryRow(`SELECT domain, listen_port, protocol, enable_tls FROM lb_rules WHERE caddy_id = ?`, ruleID).Scan(
		&rule.Domain, &rule.ListenPort, &rule.Protocol, &rule.EnableTLS)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}

	if rule.Protocol == "tcp" {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: emptyRuleMetrics()})
		return
	}

	resp, err := http.Get(h.cfg.CaddyAdminURL + "/metrics")
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: emptyRuleMetrics()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	metrics := parseRuleMetricsFromPrometheus(string(body), rule.Domain, rule.ListenPort, rule.Protocol, rule.EnableTLS)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
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

