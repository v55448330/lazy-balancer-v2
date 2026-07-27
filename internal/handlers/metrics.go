package handlers

import (
	"database/sql"
	"io"
	"lazy-balancer-v2/internal/services"
	"net/http"
	"strconv"
	"strings"
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

	resp, err := http.Get(h.cfg.CaddyAdminURL + "/metrics")
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: emptyRuleMetrics()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var metrics gin.H
	if rule.Protocol == "tcp" {
		upstreams, err := loadRuleUpstreams(ruleID)
		if err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: emptyRuleMetrics()})
			return
		}
		metrics = parseTCPRuleMetricsFromPrometheus(string(body), upstreams)
	} else {
		metrics = parseRuleMetricsFromPrometheus(string(body), rule.Domain, rule.ListenPort, rule.Protocol, rule.EnableTLS)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

// metricsIntervalModifier converts shorthand intervals (1h/6h/24h/7d/30d or
// "<n>h"/"<n>d") into a SQLite datetime modifier; unknown values fall back to
// one hour. SQLite has no "1h" syntax and arithmetic concatenation yields NULL.
func metricsIntervalModifier(interval string) string {
	interval = strings.TrimSpace(strings.ToLower(interval))
	if interval == "" {
		return "-1 hours"
	}
	unit := interval[len(interval)-1:]
	n := strings.TrimSuffix(interval, unit)
	if _, err := strconv.Atoi(n); err != nil {
		return "-1 hours"
	}
	switch unit {
	case "h":
		return "-" + n + " hours"
	case "d":
		return "-" + n + " days"
	case "m":
		return "-" + n + " months"
	default:
		return "-1 hours"
	}
}

// GetRuleMetricsHistory returns cumulative history rows for one HTTP rule
// within the requested range (1h/6h/24h/7d). TCP rules have no per-rule
// traffic counters from caddy-l4 and return an empty list with a note.
func (h *Handlers) GetRuleMetricsHistory(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	var protocol string
	if err := db.DB.QueryRow("SELECT COALESCE(protocol,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&protocol); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	if protocol != "http" {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"protocol": protocol, "supported": false, "rows": []any{}}})
		return
	}
	modifier := metricsIntervalModifier(c.DefaultQuery("range", "24h"))
	rows, err := db.MetricsDB.Query(`
		SELECT timestamp, requests_total, requests_2xx, requests_3xx,
		       requests_4xx, requests_5xx, bytes_in, bytes_out
		FROM metrics_history
		WHERE rule_id = ? AND timestamp > datetime('now', ?)
		ORDER BY timestamp
	`, caddyID, modifier)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取历史指标失败: " + err.Error()})
		return
	}
	defer rows.Close()
	type row struct {
		Timestamp string `json:"timestamp"`
		Requests  int64  `json:"requests_total"`
		Status2xx int64  `json:"requests_2xx"`
		Status3xx int64  `json:"requests_3xx"`
		Status4xx int64  `json:"requests_4xx"`
		Status5xx int64  `json:"requests_5xx"`
		BytesIn   int64  `json:"bytes_in"`
		BytesOut  int64  `json:"bytes_out"`
	}
	result := []row{}
	for rows.Next() {
		var r row
		var ts time.Time
		if err := rows.Scan(&ts, &r.Requests, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx, &r.BytesIn, &r.BytesOut); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取历史指标失败: " + err.Error()})
			return
		}
		r.Timestamp = ts.In(services.CurrentLocation()).Format("2006-01-02 15:04:05")
		result = append(result, r)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"protocol": protocol, "supported": true, "rows": result}})
}

func (h *Handlers) GetMetricsHistory(c *gin.Context) {
	ruleID := c.Query("rule_id")
	interval := metricsIntervalModifier(c.DefaultQuery("interval", "1h"))

	var rows *sql.Rows
	var err error

	if ruleID != "" {
		rows, err = db.MetricsDB.Query(`
			SELECT timestamp, requests_total, requests_2xx, requests_3xx, 
			       requests_4xx, requests_5xx, bytes_in, bytes_out
			FROM metrics_history 
			WHERE rule_id = ? AND timestamp > datetime('now', ?)
			ORDER BY timestamp
		`, ruleID, interval)
	} else {
		rows, err = db.MetricsDB.Query(`
			SELECT timestamp, SUM(requests_total), SUM(requests_2xx), SUM(requests_3xx), 
			       SUM(requests_4xx), SUM(requests_5xx), SUM(bytes_in), SUM(bytes_out)
			FROM metrics_history 
			WHERE rule_id IS NULL AND timestamp > datetime('now', ?)
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
		if err := rows.Scan(&m.Timestamp, &m.RequestsTotal, &m.Status2xx, &m.Status3xx,
			&m.Status4xx, &m.Status5xx, &m.BytesIn, &m.BytesOut); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取指标历史失败: " + err.Error()})
			return
		}
		metrics = append(metrics, m)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取指标历史失败: " + err.Error()})
		return
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

func loadRuleUpstreams(ruleID string) ([]models.Upstream, error) {
	rows, err := db.DB.Query(`
		SELECT id, rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol, dns_server, max_connections
		FROM upstreams WHERE rule_id = ? AND enabled = 1
	`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var upstreams []models.Upstream
	for rows.Next() {
		var u models.Upstream
		if err := rows.Scan(&u.ID, &u.RuleID, &u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.DnsServer, &u.MaxConnections); err != nil {
			continue
		}
		upstreams = append(upstreams, u)
	}
	return upstreams, nil
}
