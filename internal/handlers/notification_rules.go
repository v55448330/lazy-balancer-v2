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

// UpdateNotificationRule PUT /notification/rules/:id——更新单条规则。
// 拆解写回底层表（subscriptions / notification_daily）。
func (h *Handlers) UpdateNotificationRule(c *gin.Context) {
	uid := contextUserID(c)
	ruleID := c.Param("id")

	var req struct {
		Enabled      bool              `json:"enabled"`
		MinLevel     string            `json:"min_level"`
		BodyTemplate string            `json:"body_template"`
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
		cfg.Enabled = req.Enabled
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
			if !req.Enabled {
				// 取消订阅
				if _, err := db.DB.Exec(`DELETE FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, ev); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("取消订阅失败", err)})
					return
				}
			} else {
				// 设置/更新订阅
				if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template)
					VALUES (?,?,?,?)
					ON CONFLICT(user_id, event_type) DO UPDATE SET min_level=excluded.min_level, body_template=excluded.body_template`,
					uid, ev, req.MinLevel, req.BodyTemplate); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存订阅失败", err)})
					return
				}
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
// 全平台通知统计+指定用户的通道/规则（user_id 参数可选，空=全平台汇总）。
func (h *Handlers) GetAdminNotificationOverview(c *gin.Context) {
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "admin only"})
		return
	}
	// 全平台统计
	var totalChannels, totalRules, totalDeliveries, sentDeliveries int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_channels WHERE enabled=1`).Scan(&totalChannels)
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions`).Scan(&totalRules)
	_ = db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries`).Scan(&totalDeliveries)
	_ = db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE status='sent'`).Scan(&sentDeliveries)
	rate := float64(0)
	if totalDeliveries > 0 {
		rate = float64(sentDeliveries) / float64(totalDeliveries)
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
		"stats": gin.H{"channels": totalChannels, "rules": totalRules, "deliveries": totalDeliveries, "success_rate": rate},
		"users": users,
	}})
}
