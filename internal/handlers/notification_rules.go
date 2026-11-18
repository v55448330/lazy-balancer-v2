package handlers

// 通知规则聚合视图（notification rules）：把分散在 subscriptions（事件订阅）、
// channels（通道）、daily（日报配置）中的配置聚合为用户可理解的「规则」。
//
// 一条规则 = 触发条件 + 接收通道 + 消息模板 + 启用状态
//   - 事件规则：{trigger: "event", events: [...], min_level, channels: [...], body_template}
//   - 日报规则：{trigger: "daily", send_time, items, channels: [...], formats}
//
// 底层存储不变——聚合视图在读取时 JOIN，写入时拆解回原表。

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
)

// NotificationRule 聚合规则视图（前端消费的唯一形态）。
type NotificationRule struct {
	ID           string            `json:"id"`            // 规则标识（event:<type> 或 daily）
	Trigger      string            `json:"trigger"`       // event | daily
	Title        string            `json:"title"`         // 显示名
	Events       []string          `json:"events"`        // 事件类型列表（event 规则）
	MinLevel     string            `json:"min_level"`     // 最低级别
	SendTime     string            `json:"send_time"`     // 日报投递时间
	Items        []string          `json:"items"`         // 日报包含项目
	Formats      map[string]string `json:"formats"`       // 日报 per-channel 格式
	Channels     []RuleChannel     `json:"channels"`      // 接收通道
	BodyTemplate string            `json:"body_template"` // 事件级消息模板
	Enabled      bool              `json:"enabled"`
	Subscribed   bool              `json:"subscribed"` // 事件是否已订阅
}

// RuleChannel 规则关联的通道摘要。
type RuleChannel struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

// GetNotificationRules GET /notification/rules——聚合当前用户的全部通知规则。
func (h *Handlers) GetNotificationRules(c *gin.Context) {
	uid := contextUserID(c)
	// 管理员可指定 user_id 查看其他用户配置（隐私：target 脱敏在列表层处理）
	if isAdminRequest(c) {
		if q := c.Query("user_id"); q != "" {
			if v, err := strconv.ParseInt(q, 10, 64); err == nil && v > 0 {
				uid = v
			}
		}
	}

	// 1. 读取用户全部通道
	chRows, err := db.DB.Query(`SELECT id, type, name FROM notification_channels
		WHERE user_id=? AND enabled=1 ORDER BY id`, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
		return
	}
	var allChannels []RuleChannel
	for chRows.Next() {
		var ch RuleChannel
		if chRows.Scan(&ch.ID, &ch.Type, &ch.Name) == nil {
			allChannels = append(allChannels, ch)
		}
	}
	chRows.Close()

	rules := make([]NotificationRule, 0)

	// 2. 事件目录 → 事件规则
	catalog := notify.CatalogExport()
	subRows, err := db.DB.Query(`SELECT event_type, COALESCE(min_level,''), COALESCE(body_template,'')
		FROM notification_subscriptions WHERE user_id=?`, uid)
	subsByEvent := map[string][2]string{} // event → {min_level, body_template}
	if err == nil {
		for subRows.Next() {
			var ev, ml, bt string
			if subRows.Scan(&ev, &ml, &bt) == nil {
				subsByEvent[ev] = [2]string{ml, bt}
			}
		}
		subRows.Close()
	}

	// 按目录分组（同类事件合并为一条规则）
	groupMap := map[string][]notify.CatalogItem{}
	for _, e := range catalog {
		groupMap[e.Group] = append(groupMap[e.Group], e)
	}
	for group, entries := range groupMap {
		rule := NotificationRule{
			ID:       "group:" + group,
			Trigger:  "event",
			Title:    group,
			Channels: allChannels, // 当前模型：订阅后发到全部启用通道
			Enabled:  true,
		}
		hasSub := false
		for _, e := range entries {
			rule.Events = append(rule.Events, e.ID)
			if sub, ok := subsByEvent[e.ID]; ok {
				hasSub = true
				rule.MinLevel = sub[0]
				if sub[1] != "" {
					rule.BodyTemplate = sub[1]
				}
			}
		}
		rule.Subscribed = hasSub
		if !hasSub {
			// 未订阅组：显示但标记为未激活
			rule.Enabled = false
		}
		rules = append(rules, rule)
	}

	// 3. 日报规则
	dailyCfg, err := notify.GetDailyConfig(uid)
	if err == nil && dailyCfg.Enabled {
		rules = append(rules, NotificationRule{
			ID:       "daily",
			Trigger:  "daily",
			Title:    "每日摘要",
			SendTime: dailyCfg.SendTime,
			Items:    dailyCfg.Items,
			Formats:  dailyCfg.Formats,
			Channels: allChannels,
			Enabled:  dailyCfg.Enabled,
		})
	}

	// 排序：已启用在前，日报在末
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Enabled != rules[j].Enabled {
			return rules[i].Enabled
		}
		return rules[i].Trigger < rules[j].Trigger
	})

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"rules":       rules,
		"channels":    allChannels, // 供「添加规则」向导选择通道
		"catalog":     catalog,     // 事件目录（供向导选择触发条件）
		"daily_items": dailyItemsForWizard(),
	}})
}

// UpdateNotificationRule POST /notification/rules/:id——部分更新单条规则。
// 拆解写回底层表（subscriptions / notification_daily）。缺省键=不动既有值：
// 模板保存不得误启用已停用规则、级别调整不得清空模板。
func (h *Handlers) UpdateNotificationRule(c *gin.Context) {
	uid := contextUserID(c)
	ruleID := c.Param("id")

	var req struct {
		Enabled      *bool             `json:"enabled"`
		MinLevel     *string           `json:"min_level"`
		BodyTemplate *string           `json:"body_template"`
		SendTime     string            `json:"send_time"`
		Items        []string          `json:"items"`
		Formats      map[string]string `json:"formats"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	switch {
	case ruleID == "daily":
		// 更新日报配置
		cfg, err := notify.GetDailyConfig(uid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取日报配置失败", err)})
			return
		}
		if req.Enabled != nil {
			cfg.Enabled = *req.Enabled
		}
		if req.SendTime != "" {
			cfg.SendTime = req.SendTime
		}
		if len(req.Items) > 0 {
			cfg.Items = req.Items
		}
		if req.Formats != nil {
			cfg.Formats = req.Formats
		}
		if err := notify.SaveDailyConfig(cfg); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存日报配置失败", err)})
			return
		}

	case len(ruleID) > 6 && ruleID[:6] == "group:":
		// 更新事件组订阅：对该组全部事件设置/删除订阅行
		group := ruleID[6:]
		catalog := notify.CatalogExport()
		var eventIDs []string
		for _, e := range catalog {
			if e.Group == group {
				eventIDs = append(eventIDs, e.ID)
			}
		}
		if len(eventIDs) == 0 {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.Tf(c, "k_1d8f5b94", group), MessageKey: "k_1d8f5b94"})
			return
		}
		for _, ev := range eventIDs {
			if req.Enabled != nil && !*req.Enabled {
				// 显式停用=取消订阅（删行）
				if _, err := db.DB.Exec(`DELETE FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, ev); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("取消订阅失败", err)})
					return
				}
				continue
			}
			// 部分更新：先读既有行，缺省键沿用现值；无行且未显式启用=不动。
			var curLevel, curTpl string
			err := db.DB.QueryRow(`SELECT COALESCE(min_level,''), COALESCE(body_template,'') FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, ev).Scan(&curLevel, &curTpl)
			if err != nil {
				if req.Enabled == nil || !*req.Enabled {
					continue // 未订阅且未要求启用：不建行
				}
				curLevel, curTpl = "info", ""
			}
			if req.MinLevel != nil {
				curLevel = *req.MinLevel
			}
			if req.BodyTemplate != nil {
				curTpl = *req.BodyTemplate
			}
			if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template)
				VALUES (?,?,?,?)
				ON CONFLICT(user_id, event_type) DO UPDATE SET min_level=excluded.min_level, body_template=excluded.body_template`,
				uid, ev, curLevel, curTpl); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存订阅失败", err)})
				return
			}
		}

	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.Tf(c, "k_53f42807", ruleID), MessageKey: "k_53f42807"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// dailyItemsForWizard 日报可选项（向导选择包含项目）。
func dailyItemsForWizard() []gin.H {
	items := make([]gin.H, 0, len(notify.DailyItemIDs))
	for _, id := range notify.DailyItemIDs {
		items = append(items, gin.H{"id": id, "label": notify.DailyItemLabels[id]})
	}
	return items
}

// GetAdminNotificationOverview GET /notification/admin/overview——管理员视角：
// 通知统计+通道类型分布+用户列表。?user_id=X 时统计收窄到该用户（概览筛选器），
// 缺省=全平台汇总。
func (h *Handlers) GetAdminNotificationOverview(c *gin.Context) {
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "admin only"})
		return
	}
	// 统计口径：可选 user_id 收窄（与投递趋势筛选器同语义）
	scope := ""
	scopeArgs := []any{}
	if q := c.Query("user_id"); q != "" {
		if v, err := strconv.ParseInt(q, 10, 64); err == nil && v > 0 {
			scope = " WHERE user_id=?"
			scopeArgs = append(scopeArgs, v)
		}
	}
	var totalChannels, totalRules, totalDeliveries, sentDeliveries int
	chQuery := `SELECT COUNT(*) FROM notification_channels WHERE enabled=1`
	if scope != "" {
		chQuery += ` AND user_id=?`
	}
	_ = db.DB.QueryRow(chQuery, scopeArgs...).Scan(&totalChannels)
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions`+scope, scopeArgs...).Scan(&totalRules)
	dlQuery := `SELECT COUNT(*) FROM notification_deliveries` + scope
	_ = db.MetricsDB.QueryRow(dlQuery, scopeArgs...).Scan(&totalDeliveries)
	sentQuery := `SELECT COUNT(*) FROM notification_deliveries WHERE status='sent'`
	if scope != "" {
		sentQuery += ` AND user_id=?`
	}
	_ = db.MetricsDB.QueryRow(sentQuery, scopeArgs...).Scan(&sentDeliveries)
	rate := float64(0)
	if totalDeliveries > 0 {
		rate = float64(sentDeliveries) / float64(totalDeliveries)
	}

	// 通道类型分布（启用通道；概览饼图数据源）
	type typeCount struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	}
	byType := make([]typeCount, 0, 4)
	tcQuery := `SELECT type, COUNT(*) FROM notification_channels WHERE enabled=1`
	if scope != "" {
		tcQuery += ` AND user_id=?`
	}
	tcQuery += ` GROUP BY type ORDER BY type`
	if tcRows, err := db.DB.Query(tcQuery, scopeArgs...); err == nil {
		for tcRows.Next() {
			var tc typeCount
			if tcRows.Scan(&tc.Type, &tc.Count) == nil {
				byType = append(byType, tc)
			}
		}
		tcRows.Close()
	}

	// 用户列表（供筛选器）
	type userBrief struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}
	var users []userBrief
	rows, err := db.DB.Query(`SELECT id, username FROM users ORDER BY id`)
	if err == nil {
		for rows.Next() {
			var u userBrief
			if rows.Scan(&u.ID, &u.Username) == nil {
				users = append(users, u)
			}
		}
		rows.Close()
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"stats":           gin.H{"channels": totalChannels, "rules": totalRules, "deliveries": totalDeliveries, "success_rate": rate},
		"channel_by_type": byType,
		"users":           users,
	}})
}

// GetDeliveryTrend GET /notification/delivery-trend——7天投递趋势（按日计数+成功率）。
// 管理员可 ?user_id=X 查看指定用户；默认当前用户。
func (h *Handlers) GetDeliveryTrend(c *gin.Context) {
	uid := contextUserID(c)
	if isAdminRequest(c) {
		if q := c.Query("user_id"); q != "" {
			if v, err := strconv.ParseInt(q, 10, 64); err == nil && v > 0 {
				uid = v
			}
		}
	}
	type dayStat struct {
		Date  string  `json:"date"`
		Total int     `json:"total"`
		Sent  int     `json:"sent"`
		Rate  float64 `json:"rate"`
	}
	out := make([]dayStat, 0, 7)
	for i := 6; i >= 0; i-- {
		day := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var total, sent int
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE user_id=? AND substr(created_at,1,10)=?`, uid, day).Scan(&total)
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE user_id=? AND substr(created_at,1,10)=? AND status='sent'`, uid, day).Scan(&sent)
		rate := float64(0)
		if total > 0 {
			rate = float64(sent) / float64(total)
		}
		out = append(out, dayStat{Date: day, Total: total, Sent: sent, Rate: rate})
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"trend": out}})
}
