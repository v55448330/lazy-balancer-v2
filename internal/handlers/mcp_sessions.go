package handlers

// MCP 会话可见性与调用统计 REST（通知中心）：会话列表（管理员全量，?mine=1
// 仅本人）、强制断开（管理动作，显式审计留痕）、工具调用统计聚合。
// 在线口径与投递 Daemon 清理同源：last_seen 30 分钟内=在线（表内即在线）。

import (
	"fmt"
	"lazy-balancer-v2/internal/services"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
)

// mcpSessionDTO 会话行（Main 契约形状）：username/key_name 由 JOIN 取展示名，
// 缺失（用户/Key 已删）回空串。
type mcpSessionDTO struct {
	SessionID string `json:"session_id"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	KeyID     int64  `json:"key_id"`
	KeyName   string `json:"key_name"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Online    bool   `json:"online"`
}

// ListMCPSessions GET /security/mcp-sessions——管理员全量；?mine=1 仅本人
// （管理员自查口径）。按最近活动倒序。
func (h *Handlers) ListMCPSessions(c *gin.Context) {
	query := `SELECT s.session_id, s.user_id, COALESCE(u.username,''), s.api_key_id, COALESCE(k.name,''),
		s.ip, COALESCE(s.user_agent,''), s.first_seen, s.last_seen,
		(s.last_seen >= datetime('now', '-30 minutes'))
		FROM mcp_sessions s
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN api_keys k ON k.id = s.api_key_id`
	args := []any{}
	if !isAdminRequest(c) || c.Query("mine") == "1" {
		query += ` WHERE s.user_id=?`
		args = append(args, contextUserID(c))
	}
	query += ` ORDER BY s.last_seen DESC, s.session_id`
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		writeInternalErrorKey(c, http.StatusInternalServerError, "apikey.mcpSessionsLoadFailed", err)
		return
	}
	defer rows.Close()
	out := make([]mcpSessionDTO, 0, 4)
	for rows.Next() {
		var r mcpSessionDTO
		var online int
		if err := rows.Scan(&r.SessionID, &r.UserID, &r.Username, &r.KeyID, &r.KeyName,
			&r.IP, &r.UserAgent, &r.FirstSeen, &r.LastSeen, &online); err != nil {
			continue
		}
		r.Online = online != 0
		out = append(out, r)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"sessions": out}})
}

// DisconnectMCPSession POST /security/mcp-sessions/:id/disconnect——强制断开：
// 删会话行 + MCP 层终止（后续请求 404）+ 注销推送注册；显式审计留痕（路由
// 分类 AuditPolicyExplicit，中间件不再记通用行）。
func (h *Handlers) DisconnectMCPSession(c *gin.Context) {
	sessionID := c.Param("id")
	var ownerUserID, ownerKeyID int64
	if err := db.DB.QueryRow(`SELECT user_id, api_key_id FROM mcp_sessions WHERE session_id=?`, sessionID).
		Scan(&ownerUserID, &ownerKeyID); err != nil {
		c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "apikey.mcpSessionNotFound"))
		return
	}
	if _, err := mcpserver.DisconnectSession(sessionID); err != nil {
		writeInternalErrorKey(c, http.StatusInternalServerError, "apikey.mcpSessionDisconnectFailed", err)
		return
	}
	recordAudit(c, "断开", "MCP 会话",
		services.AuditRawDetail("会话 "+sessionID+"（用户 #"+strconv.FormatInt(ownerUserID, 10)+
			"，Key #"+strconv.FormatInt(ownerKeyID, 10)+"）强制断开") /* audit-detail raw */)
	notify.Publish(notify.Event{Type: notify.EvtMCPDisconnected, Fields: map[string]string{"1": c.GetString("username"), "2": fmt.Sprintf("会话 #%s", c.Param("id"))}})
	c.JSON(http.StatusOK, apimsg.Envelope(c, 0, "apikey.mcpSessionDisconnected"))
}

// mcpToolCallsDTO TOP 工具行。
type mcpToolCallsDTO struct {
	Tool  string `json:"tool"`
	Calls int64  `json:"calls"`
}

// mcpTrendPointDTO 趋势点（date=YYYY-MM-DD 本机时区）。
type mcpTrendPointDTO struct {
	Date  string `json:"date"`
	Calls int64  `json:"calls"`
}

// GetMCPStats GET /notification/mcp/stats——今日调用/在线会话数/今日错误率/
// TOP 工具（今日，前 5）/近 7 天调用趋势（含今日，无调用日补零）。
func (h *Handlers) GetMCPStats(c *gin.Context) {
	today := time.Now().Format("2006-01-02")
	var todayCalls, totalErrors int64
	if err := db.DB.QueryRow(`SELECT COALESCE(SUM(calls),0), COALESCE(SUM(errors),0)
		FROM mcp_tool_stats WHERE date=?`, today).Scan(&todayCalls, &totalErrors); err != nil {
		writeInternalErrorKey(c, http.StatusInternalServerError, "apikey.mcpStatsLoadFailed", err)
		return
	}
	errorRate := 0.0
	if todayCalls > 0 {
		errorRate = float64(totalErrors) / float64(todayCalls)
	}
	var activeSessions int64
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM mcp_sessions
		WHERE last_seen >= datetime('now', '-30 minutes')`).Scan(&activeSessions); err != nil {
		writeInternalErrorKey(c, http.StatusInternalServerError, "apikey.mcpStatsLoadFailed", err)
		return
	}
	topRows, err := db.DB.Query(`SELECT tool, SUM(calls) FROM mcp_tool_stats
		WHERE date=? GROUP BY tool ORDER BY SUM(calls) DESC LIMIT 5`, today)
	if err != nil {
		writeInternalErrorKey(c, http.StatusInternalServerError, "apikey.mcpStatsLoadFailed", err)
		return
	}
	defer topRows.Close()
	topTools := make([]mcpToolCallsDTO, 0, 5)
	for topRows.Next() {
		var item mcpToolCallsDTO
		if err := topRows.Scan(&item.Tool, &item.Calls); err == nil {
			topTools = append(topTools, item)
		}
	}

	// 近 7 天趋势：先取库内有数的日期，再按日历补零——缺数日呈现 0 而非缺口。
	weekStart := time.Now().AddDate(0, 0, -6).Format("2006-01-02")
	trendRows, err := db.DB.Query(`SELECT date, SUM(calls) FROM mcp_tool_stats
		WHERE date>=? GROUP BY date`, weekStart)
	if err != nil {
		writeInternalErrorKey(c, http.StatusInternalServerError, "apikey.mcpStatsLoadFailed", err)
		return
	}
	defer trendRows.Close()
	byDate := map[string]int64{}
	for trendRows.Next() {
		var date string
		var calls int64
		if err := trendRows.Scan(&date, &calls); err == nil {
			byDate[date] = calls
		}
	}
	trend := make([]mcpTrendPointDTO, 0, 7)
	for i := 6; i >= 0; i-- {
		date := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		trend = append(trend, mcpTrendPointDTO{Date: date, Calls: byDate[date]})
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"today_calls":     todayCalls,
		"active_sessions": activeSessions,
		"error_rate":      errorRate,
		"top_tools":       topTools,
		"trend":           trend,
	}})
}
