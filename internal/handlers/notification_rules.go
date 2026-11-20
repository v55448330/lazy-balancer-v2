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
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// NotificationRule 聚合规则视图（前端消费的唯一形态）。
type NotificationRule struct {
	ID               string            `json:"id"`                // 规则标识（group:<组> 或 daily）
	Trigger          string            `json:"trigger"`           // event | daily
	Title            string            `json:"title"`             // 显示名
	Events           []string          `json:"events"`            // 事件类型列表（event 规则）
	EventTitles      map[string]string `json:"event_titles"`      // 事件 ID → 用户可读标题（禁止裸键展示）
	EventLevels      map[string]string `json:"event_levels"`      // 事件 ID → 目录默认级别（info/warn/critical，标签配色）
	MinLevel         string            `json:"min_level"`         // 最低级别
	SendTime         string            `json:"send_time"`         // 日报投递时间
	Items            []string          `json:"items"`             // 日报包含项目
	Formats          map[string]string `json:"formats"`           // 日报 per-channel 格式
	Channels         []RuleChannel     `json:"channels"`          // 接收通道（订阅选定；空选择=全部启用通道）
	ChannelIDs       []int64           `json:"channel_ids"`       // 显式选定的通道 ID（空=全部）
	ChannelTemplates map[string]string `json:"channel_templates"` // 通道 ID → 事件×通道模板
	BodyTemplate     string            `json:"body_template"`     // 事件级消息模板
	Enabled          bool              `json:"enabled"`
	Subscribed       bool              `json:"subscribed"` // 事件是否已订阅
}

// RuleChannel 规则关联的通道摘要。
type RuleChannel struct {
	ID         int64  `json:"id"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	LastTestOK bool   `json:"last_test_ok"`
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
	chRows, err := db.DB.Query(`SELECT id, type, name, COALESCE(last_test_ok,0) FROM notification_channels
		WHERE user_id=? AND enabled=1 ORDER BY id`, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
		return
	}
	var allChannels []RuleChannel
	for chRows.Next() {
		var ch RuleChannel
		if chRows.Scan(&ch.ID, &ch.Type, &ch.Name, &ch.LastTestOK) == nil {
			allChannels = append(allChannels, ch)
		}
	}
	chRows.Close()

	rules := make([]NotificationRule, 0)

	// 2. 事件目录 → 事件规则
	catalog := notify.CatalogExport()
	subRows, err := db.DB.Query(`SELECT event_type, COALESCE(min_level,''), COALESCE(body_template,''),
		COALESCE(channel_ids,''), COALESCE(channel_templates,'')
		FROM notification_subscriptions WHERE user_id=?`, uid)
	type subState struct{ level, tpl, ids, tpls string }
	subsByEvent := map[string]subState{}
	if err == nil {
		for subRows.Next() {
			var ev string
			var s subState
			if subRows.Scan(&ev, &s.level, &s.tpl, &s.ids, &s.tpls) == nil {
				subsByEvent[ev] = s
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
			ID:          "group:" + group,
			Trigger:     "event",
			Title:       group,
			EventTitles: map[string]string{},
			EventLevels: map[string]string{},
			Enabled:     true,
		}
		hasSub := false
		for _, e := range entries {
			rule.Events = append(rule.Events, e.ID)
			rule.EventTitles[e.ID] = e.Title
			rule.EventLevels[e.ID] = string(e.Level)
			if sub, ok := subsByEvent[e.ID]; ok {
				hasSub = true
				rule.MinLevel = sub.level
				if sub.tpl != "" {
					rule.BodyTemplate = sub.tpl
				}
				// 通道选择/每通道模板：组内取首个非空配置（组级 UI 单一口径）。
				// '[]' 显式空选须保留（不投递语义）——用 nil 判定而非 len。
				if rule.ChannelIDs == nil && sub.ids != "" {
					var ids []int64
					if json.Unmarshal([]byte(sub.ids), &ids) == nil {
						if ids == nil {
							ids = []int64{}
						}
						rule.ChannelIDs = ids
					}
				}
				if len(rule.ChannelTemplates) == 0 && sub.tpls != "" {
					var m map[string]string
					if json.Unmarshal([]byte(sub.tpls), &m) == nil {
						rule.ChannelTemplates = m
					}
				}
			}
		}
		// 接收通道三态：nil=全部启用通道（缺省）；[]=不投递（显式空选）；
		// 非空=仅选定通道。
		if rule.ChannelIDs != nil {
			idSet := map[int64]bool{}
			for _, id := range rule.ChannelIDs {
				idSet[id] = true
			}
			for _, ch := range allChannels {
				if idSet[ch.ID] {
					rule.Channels = append(rule.Channels, ch)
				}
			}
		} else {
			rule.Channels = allChannels
		}
		rule.Subscribed = hasSub
		if !hasSub {
			// 未订阅组：显示但标记为未激活
			rule.Enabled = false
		}
		rules = append(rules, rule)
	}

	// 3. 日报规则（恒呈现：停用态也显示卡片，允许重新启用与配置；
	// GetDailyConfig 无行返回默认启用配置，err 仅 DB 故障时非 nil）
	dailyCfg, err := notify.GetDailyConfig(uid)
	if err == nil {
		// 日报目标通道= sys.daily_report 订阅行 channel_ids 三态（与事件规则同口径）。
		var dailyIDs string
		_ = db.DB.QueryRow(`SELECT COALESCE(channel_ids,'') FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, notify.EvtDailyReport).Scan(&dailyIDs)
		var chIDs []int64
		if dailyIDs != "" {
			_ = json.Unmarshal([]byte(dailyIDs), &chIDs)
		}
		rules = append(rules, NotificationRule{
			ID:         "daily",
			Trigger:    "daily",
			Title:      "每日摘要",
			SendTime:   dailyCfg.SendTime,
			Items:      dailyCfg.Items,
			Formats:    dailyCfg.Formats,
			Channels:   allChannels,
			ChannelIDs: chIDs,
			Enabled:    dailyCfg.Enabled,
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
	// 管理员代管他人配置：?user_id=X 时写回该用户（与 GET 视角同口径；
	// 非管理员忽略该参数恒本人）。此前写侧恒 contextUserID——管理员在
	// 他人视角保存会静默写到自己名下（浏览器实测抓出的归属缺陷）。
	if isAdminRequest(c) {
		if q := c.Query("user_id"); q != "" {
			if v, err := strconv.ParseInt(q, 10, 64); err == nil && v > 0 {
				uid = v
			}
		}
	}
	ruleID := c.Param("id")

	var req struct {
		Enabled          *bool             `json:"enabled"`
		Events           *[]string         `json:"events"` // 组内事件选择（inline 编辑；未选=取消订阅）
		MinLevel         *string           `json:"min_level"`
		BodyTemplate     *string           `json:"body_template"`
		ChannelIDs       *[]int64          `json:"channel_ids"`       // 显式通道选择（空数组=全部启用通道）
		ChannelTemplates map[string]string `json:"channel_templates"` // 通道 ID → 事件×通道模板
		SendTime         string            `json:"send_time"`
		Items            []string          `json:"items"`
		Formats          map[string]string `json:"formats"`
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
		// 日报目标通道落 sys.daily_report 订阅行（deliverOne 消费三态）。
		if req.ChannelIDs != nil {
			b, _ := json.Marshal(*req.ChannelIDs)
			if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template, channel_ids, channel_templates)
				VALUES (?,?,?,?,?,?)
				ON CONFLICT(user_id, event_type) DO UPDATE SET channel_ids=excluded.channel_ids`,
				uid, notify.EvtDailyReport, "info", "", string(b), ""); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存日报目标通道失败", err)})
				return
			}
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
			// inline 事件选择：未选=取消订阅（删行）；选中=确保订阅行存在。
			wantOn := req.Enabled != nil && *req.Enabled
			if req.Events != nil {
				selected := false
				for _, s := range *req.Events {
					if s == ev {
						selected = true
						break
					}
				}
				if !selected {
					if _, err := db.DB.Exec(`DELETE FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, ev); err != nil {
						c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("取消订阅失败", err)})
						return
					}
					continue
				}
				wantOn = true
			} else if req.Enabled != nil && !*req.Enabled {
				// 显式停用=取消订阅（删行）
				if _, err := db.DB.Exec(`DELETE FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, ev); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("取消订阅失败", err)})
					return
				}
				continue
			}
			// 部分更新：先读既有行，缺省键沿用现值；无行且未要求启用=不动。
			var curLevel, curTpl, curIDs, curTpls string
			err := db.DB.QueryRow(`SELECT COALESCE(min_level,''), COALESCE(body_template,''),
				COALESCE(channel_ids,''), COALESCE(channel_templates,'') FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, ev).Scan(&curLevel, &curTpl, &curIDs, &curTpls)
			if err != nil {
				if !wantOn {
					continue // 未订阅且未要求启用：不建行
				}
				curLevel, curTpl, curIDs, curTpls = "info", "", "", ""
			}
			if req.MinLevel != nil {
				curLevel = *req.MinLevel
			}
			if req.BodyTemplate != nil {
				curTpl = *req.BodyTemplate
			}
			if req.ChannelIDs != nil {
				// 显式空数组='[]'=不投递任何通道（用户裁定）；非空=仅选定通道。
				// 缺省键（nil）才沿用现值；'' 缺省态=全部启用通道（默认订阅）。
				b, _ := json.Marshal(*req.ChannelIDs)
				curIDs = string(b)
			}
			if req.ChannelTemplates != nil {
				// 剔除空值键后整体覆盖（所见即所存）
				clean := map[string]string{}
				for k, v := range req.ChannelTemplates {
					if v != "" {
						clean[k] = v
					}
				}
				if len(clean) > 0 {
					b, _ := json.Marshal(clean)
					curTpls = string(b)
				} else {
					curTpls = ""
				}
			}
			if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template, channel_ids, channel_templates)
				VALUES (?,?,?,?,?,?)
				ON CONFLICT(user_id, event_type) DO UPDATE SET min_level=excluded.min_level, body_template=excluded.body_template,
				channel_ids=excluded.channel_ids, channel_templates=excluded.channel_templates`,
				uid, ev, curLevel, curTpl, curIDs, curTpls); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存订阅失败", err)})
				return
			}
		}

	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.Tf(c, "k_53f42807", ruleID), MessageKey: "k_53f42807"})
		return
	}

	// 审计留痕（Explicit：规则名+结果；管理员代管注明目标用户）。
	ruleTitle := "每日摘要"
	if strings.HasPrefix(ruleID, "group:") {
		ruleTitle = ruleID[6:]
	}
	proxy := ""
	if uid != contextUserID(c) {
		proxy = "管理员代管用户 " + strconv.FormatInt(uid, 10)
	}
	recordAudit(c, "修改", "通知规则", services.FormatAuditDetail(proxy, "规则「"+ruleTitle+"」", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// TestNotificationRule POST /notification/rules/:id/test——按规则选定通道+
// 每通道模板渲染测试消息，落投递行（【测试】标记）走真实投递管线。
// 管理员 ?user_id 代管视角同写侧。结果见投递记录（用户裁定：测试必须留痕）。
func (h *Handlers) TestNotificationRule(c *gin.Context) {
	uid := contextUserID(c)
	if isAdminRequest(c) {
		if q := c.Query("user_id"); q != "" {
			if v, err := strconv.ParseInt(q, 10, 64); err == nil && v > 0 {
				uid = v
			}
		}
	}
	ruleID := c.Param("id")
	if len(ruleID) < 7 || ruleID[:6] != "group:" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.Tf(c, "k_53f42807", ruleID), MessageKey: "k_53f42807"})
		return
	}
	group := ruleID[6:]
	// 取组内首个事件作为测试消息事件形态（模板占位符 {{event}} 渲染源）
	eventType := ""
	for _, e := range notify.CatalogExport() {
		if e.Group == group {
			eventType = e.ID
			break
		}
	}
	if eventType == "" {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.Tf(c, "k_1d8f5b94", group), MessageKey: "k_1d8f5b94"})
		return
	}
	proxy := ""
	if uid != contextUserID(c) {
		proxy = "管理员代管用户 " + strconv.FormatInt(uid, 10)
	}
	if err := notify.EnqueueTestDelivery(uid, eventType); err != nil {
		recordAudit(c, "测试", "通知规则", services.FormatAuditDetail(proxy, "规则「"+group+"」", services.AuditResultPart("failed")))
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: err.Error()})
		return
	}
	recordAudit(c, "测试", "通知规则", services.FormatAuditDetail(proxy, "规则「"+group+"」", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_75aeb7a0"), MessageKey: "k_75aeb7a0"})
}

// TestNotificationDaily POST /notification/daily/test——当前用户日报测试发送
// （每日摘要卡「测试发送」；与定时日报同管线，结果见投递记录）。
func (h *Handlers) TestNotificationDaily(c *gin.Context) {
	uid := contextUserID(c)
	if err := notify.DeliverDailyForUser(uid, time.Now()); err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_165a4c01"), MessageKey: "k_165a4c01"})
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
	// 投递统计读主库（notification_deliveries 在主库，非指标库）；
	// 成功口径=sent+partial（partial=部分通道成功）。
	dlQuery := `SELECT COUNT(*) FROM notification_deliveries` + scope
	_ = db.DB.QueryRow(dlQuery, scopeArgs...).Scan(&totalDeliveries)
	sentQuery := `SELECT COUNT(*) FROM notification_deliveries WHERE status IN ('sent','partial')`
	if scope != "" {
		sentQuery += ` AND user_id=?`
	}
	_ = db.DB.QueryRow(sentQuery, scopeArgs...).Scan(&sentDeliveries)
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
		// created_at 以 UTC 落库（evt.Time.UTC()/datetime('now')），日桶须同用 UTC，
		// 否则本地时区午夜窗口（如 UTC+8 00:00-08:00）会漏计当日投递。
		day := time.Now().UTC().AddDate(0, 0, -i).Format("2006-01-02")
		var total, sent int
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE user_id=? AND substr(created_at,1,10)=?`, uid, day).Scan(&total)
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE user_id=? AND substr(created_at,1,10)=? AND status IN ('sent','partial')`, uid, day).Scan(&sent)
		rate := float64(0)
		if total > 0 {
			rate = float64(sent) / float64(total)
		}
		out = append(out, dayStat{Date: day, Total: total, Sent: sent, Rate: rate})
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"trend": out}})
}

// GetDeliveryStats GET /notification/delivery-stats——投递分布统计（概览图表数据源）。
// 口径：notification_delivery_channels 每通道结果行（7 天窗口）。管理员=全平台
// （概览不区分用户），普通用户=本人。返回：
//   - by_channel：每通道投递量+成功率（通道名 JOIN，已删通道以「通道 #id」兜底）
//   - by_type：每通道类型投递量+成功率
//   - by_event：每事件类型投递量（TOP 10，标题经目录映射）
func (h *Handlers) GetDeliveryStats(c *gin.Context) {
	scope, args := "", []any{}
	if !isAdminRequest(c) {
		scope = " WHERE user_id=?"
		args = append(args, contextUserID(c))
	}
	window := "created_at >= datetime('now', '-7 days')"
	where := window
	if scope != "" {
		where = window + " AND user_id=?"
	}

	type chanStat struct {
		ChannelID int64   `json:"channel_id"`
		Name      string  `json:"name"`
		Type      string  `json:"type"`
		Total     int     `json:"total"`
		Sent      int     `json:"sent"`
		Rate      float64 `json:"rate"`
	}
	byChannel := make([]chanStat, 0)
	q := `SELECT channel_id, channel_type, COUNT(*), SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END)
		FROM notification_delivery_channels WHERE ` + where + ` GROUP BY channel_id, channel_type ORDER BY COUNT(*) DESC`
	if rows, err := db.DB.Query(q, args...); err == nil {
		for rows.Next() {
			var s chanStat
			if rows.Scan(&s.ChannelID, &s.Type, &s.Total, &s.Sent) == nil {
				if s.Total > 0 {
					s.Rate = float64(s.Sent) / float64(s.Total)
				}
				s.Name = "通道 #" + strconv.FormatInt(s.ChannelID, 10)
				var name string
				if db.DB.QueryRow(`SELECT name FROM notification_channels WHERE id=?`, s.ChannelID).Scan(&name) == nil {
					s.Name = name
				}
				byChannel = append(byChannel, s)
			}
		}
		rows.Close()
	}

	type typeStat struct {
		Type  string  `json:"type"`
		Total int     `json:"total"`
		Sent  int     `json:"sent"`
		Rate  float64 `json:"rate"`
	}
	byType := make([]typeStat, 0, 4)
	q = `SELECT channel_type, COUNT(*), SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END)
		FROM notification_delivery_channels WHERE ` + where + ` GROUP BY channel_type ORDER BY COUNT(*) DESC`
	if rows, err := db.DB.Query(q, args...); err == nil {
		for rows.Next() {
			var s typeStat
			if rows.Scan(&s.Type, &s.Total, &s.Sent) == nil {
				if s.Total > 0 {
					s.Rate = float64(s.Sent) / float64(s.Total)
				}
				byType = append(byType, s)
			}
		}
		rows.Close()
	}

	type eventStat struct {
		EventType string `json:"event_type"`
		Title     string `json:"title"`
		Total     int    `json:"total"`
	}
	byEvent := make([]eventStat, 0, 10)
	titles := map[string]string{}
	for _, e := range notify.CatalogExport() {
		titles[e.ID] = e.Title
	}
	q = `SELECT event_type, COUNT(*) FROM notification_delivery_channels WHERE ` + where +
		` GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 10`
	if rows, err := db.DB.Query(q, args...); err == nil {
		for rows.Next() {
			var s eventStat
			if rows.Scan(&s.EventType, &s.Total) == nil {
				s.Title = s.EventType
				if t, ok := titles[s.EventType]; ok {
					s.Title = t
				}
				byEvent = append(byEvent, s)
			}
		}
		rows.Close()
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"by_channel": byChannel,
		"by_type":    byType,
		"by_event":   byEvent,
	}})
}
