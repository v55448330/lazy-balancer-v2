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
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	Events           []string          `json:"events"`            // 已启用订阅的事件子集（组内全量选项=event_titles 键集）
	EventTitles      map[string]string `json:"event_titles"`      // 事件 ID → 用户可读标题（禁止裸键展示）
	EventLevels      map[string]string `json:"event_levels"`      // 事件 ID → 目录默认级别（info/warn/critical，标签配色）
	MinLevel         string            `json:"min_level"`         // 最低级别
	SendTime         string            `json:"send_time"`         // 日报投递时间
	Items            []string          `json:"items"`             // 日报包含项目
	Formats          map[string]string `json:"formats"`           // 日报 per-channel 格式
	Channels         []RuleChannel     `json:"channels"`          // 接收通道：缺省=全部启用通道；空=显式不投递
	ChannelIDs       []int64           `json:"channel_ids"`       // 显式选定通道：缺省=全部启用；空数组=显式不投递
	ChannelTemplates map[string]string `json:"channel_templates"` // 通道 ID → 事件×通道模板
	BodyTemplate     string            `json:"body_template"`     // 事件级消息模板
	UpdatedAt        string            `json:"updated_at"`        // 最近更新（UTC 存储）
	UpdatedBy        int64             `json:"updated_by"`        // 更新者用户 ID
	UpdatedByName    string            `json:"updated_by_name"`   // 更新者显示名
	Enabled          bool              `json:"enabled"`
	Subscribed       bool              `json:"subscribed"` // 事件是否已订阅
}

// RuleChannel 规则关联的通道摘要。
type RuleChannel struct {
	ID           int64  `json:"id"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	LastTestOK   bool   `json:"last_test_ok"`
	SessionReady bool   `json:"session_ready"` // wx 会话上下文就绪（在线≠就绪；失效=会话待刷新）
}

// sanitizeRuleChannelIDs 规则保存时的通道就绪清洗（2026-11-22 用户裁定）：
// 剔除已停用/不存在的通道、「已知测试失败」（last_test_at 非空且
// last_test_ok=0——从未测试保留，未测≠失败）与「微信会话未就绪」（会话
// 待刷新）的通道——失效通道自动取消选择，不再允许发送；重新绑定/测试通过
// 后用户可再选。返回保序子集；显式空数组语义由调用方保留（'[]' 不经过此处）。
func sanitizeRuleChannelIDs(database interface{ QueryRow(string, ...any) *sql.Row }, userID int64, ids []int64) []int64 {
	if len(ids) == 0 {
		return ids
	}
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		var typ, target, lastTestAt string
		var enabled, testOK int
		err := database.QueryRow(`SELECT type, COALESCE(target,''), COALESCE(enabled,1),
			COALESCE(last_test_at,''), COALESCE(last_test_ok,0)
			FROM notification_channels WHERE id=? AND user_id=?`, id, userID).Scan(&typ, &target, &enabled, &lastTestAt, &testOK)
		if err != nil || enabled == 0 {
			continue
		}
		if lastTestAt != "" && testOK == 0 {
			continue
		}
		if typ == "wx_clawbot" && !notify.WxSessionReady(target) {
			continue
		}
		out = append(out, id)
	}
	return out
}

// ruleChannelsForIDs 按显式通道选择过滤启用通道（保 allChannels 顺序）。
// 返回非 nil 切片：显式空选序列化为 []（=显式不投递），不得回落全部通道。
func ruleChannelsForIDs(all []RuleChannel, ids []int64) []RuleChannel {
	idSet := make(map[int64]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	out := make([]RuleChannel, 0, len(ids))
	for _, ch := range all {
		if idSet[ch.ID] {
			out = append(out, ch)
		}
	}
	return out
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
	chRows, err := db.DB.Query(`SELECT id, type, name, COALESCE(last_test_ok,0), COALESCE(target,'') FROM notification_channels
		WHERE user_id=? AND enabled=1 ORDER BY id`, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
		return
	}
	var allChannels []RuleChannel
	for chRows.Next() {
		var ch RuleChannel
		var target string
		if err := chRows.Scan(&ch.ID, &ch.Type, &ch.Name, &ch.LastTestOK, &target); err != nil {
			chRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
			return
		}
		if ch.Type == "wx_clawbot" {
			ch.SessionReady = notify.WxSessionReady(target)
		}
		allChannels = append(allChannels, ch)
	}
	if err := chRows.Err(); err != nil {
		chRows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
		return
	}
	chRows.Close()

	rules := make([]NotificationRule, 0)

	// 2. 事件目录 → 事件规则
	catalog := notify.CatalogExport()
	subRows, err := db.DB.Query(`SELECT event_type, COALESCE(min_level,''), COALESCE(body_template,''),
		COALESCE(channel_ids,''), COALESCE(channel_templates,''), COALESCE(updated_at,''), COALESCE(updated_by,0), COALESCE(enabled,1)
		FROM notification_subscriptions WHERE user_id=?`, uid)
	if err != nil {
		// 聚合读失败必须 500：静默降级为空规则会让「已停用/已配置」在 UI 上
		// 看起来像未配置，用户保存后反而覆盖真实配置。
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
		return
	}
	type subState struct {
		level, tpl, ids, tpls string
		updatedAt             string
		updatedBy             int64
		enabled               int
	}
	subsByEvent := map[string]subState{}
	for subRows.Next() {
		var ev string
		var s subState
		if err := subRows.Scan(&ev, &s.level, &s.tpl, &s.ids, &s.tpls, &s.updatedAt, &s.updatedBy, &s.enabled); err != nil {
			subRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
			return
		}
		subsByEvent[ev] = s
	}
	if err := subRows.Err(); err != nil {
		subRows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
		return
	}
	subRows.Close()

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
			Events:      []string{},
			EventTitles: map[string]string{},
			EventLevels: map[string]string{},
			Enabled:     true,
		}
		hasSub := false
		hasEnabled := false
		for _, e := range entries {
			// 选项源=组内全量事件（EventTitles/EventLevels 键集），Events 仅
			// 承载「已启用订阅」子集（前端复选回显口径）。
			rule.EventTitles[e.ID] = e.Title
			rule.EventLevels[e.ID] = string(e.Level)
			if sub, ok := subsByEvent[e.ID]; ok {
				hasSub = true
				// 组级「更新时间/更新人」=组内最近一次订阅变更（停用行同样记录）。
				if sub.updatedAt > rule.UpdatedAt {
					rule.UpdatedAt = sub.updatedAt
					rule.UpdatedBy = sub.updatedBy
				}
				if sub.enabled == 0 {
					continue // 停用行：不参与启用/通道/级别聚合，但更新信息保留
				}
				hasEnabled = true
				rule.Events = append(rule.Events, e.ID)
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
			rule.Channels = ruleChannelsForIDs(allChannels, rule.ChannelIDs)
		} else {
			rule.Channels = allChannels
		}
		rule.Subscribed = hasSub
		// 启用态=存在启用行；无行或全停用=未激活（更新信息仍保留）。
		rule.Enabled = hasEnabled
		rules = append(rules, rule)
	}

	// 3. 日报规则（恒呈现：停用态也显示卡片，允许重新启用与配置；
	// GetDailyConfig 无行返回默认启用配置，err 仅 DB 故障时非 nil——DB 故障
	// 必须 500，静默丢卡片同样属于聚合读失真
	dailyCfg, err := notify.GetDailyConfig(uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取日报配置失败", err)})
		return
	}
	{
		// 日报目标通道= sys.daily_report 订阅行 channel_ids 三态（与事件规则同口径）。
		// 无行=缺省（全部启用通道）；DB 故障/列损坏必须 500——静默降级会把
		// 「显式空选=不投递」误显示为全部通道（同族）。
		var dailyIDs, dailyAt string
		var dailyBy int64
		err := db.DB.QueryRow(`SELECT COALESCE(channel_ids,''), COALESCE(updated_at,''), COALESCE(updated_by,0) FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, notify.EvtDailyReport).Scan(&dailyIDs, &dailyAt, &dailyBy)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
			return
		}
		var chIDs []int64
		if dailyIDs != "" {
			if err := json.Unmarshal([]byte(dailyIDs), &chIDs); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知规则失败", err)})
				return
			}
		}
		// 接收通道三态与事件规则同口径：nil=全部启用通道（缺省）；
		// []=不投递；非空=仅选定通道（真实投递面由 daemon 按 channel_ids 消费）。
		dailyChannels := allChannels
		if chIDs != nil {
			dailyChannels = ruleChannelsForIDs(allChannels, chIDs)
		}
		rules = append(rules, NotificationRule{
			ID:         "daily",
			Trigger:    "daily",
			Title:      "每日摘要",
			SendTime:   dailyCfg.SendTime,
			Items:      dailyCfg.Items,
			Formats:    dailyCfg.Formats,
			Channels:   dailyChannels,
			ChannelIDs: chIDs,
			UpdatedAt:  dailyAt,
			UpdatedBy:  dailyBy,
			Enabled:    dailyCfg.Enabled,
		})
	}

	// 更新者显示名（id→display_name/username），供前端「更新用户」列。
	if rows, err := db.DB.Query(`SELECT id, COALESCE(display_name,''), username FROM users`); err == nil {
		nameByID := map[int64]string{}
		for rows.Next() {
			var id int64
			var dn, un string
			if rows.Scan(&id, &dn, &un) == nil {
				if dn != "" {
					nameByID[id] = dn
				} else {
					nameByID[id] = un
				}
			}
		}
		rows.Close()
		for i := range rules {
			if rules[i].UpdatedBy > 0 {
				rules[i].UpdatedByName = nameByID[rules[i].UpdatedBy]
			}
		}
	}

	// 固定顺序（catalog 声明序），不随启停/保存变化：此前按 Enabled+Trigger 排序，
	// 同 trigger 的事件组比较恒 false 且来源是 Go map 遍历 → 每次请求顺序随机，
	// 任何配置修改触发刷新都会导致表格行重排。日报恒末位。
	groupRank := map[string]int{}
	for i, e := range catalog {
		if _, ok := groupRank[e.Group]; !ok {
			groupRank[e.Group] = i
		}
	}
	rankOf := func(r NotificationRule) int {
		if r.Trigger == "daily" {
			return 1 << 30
		}
		if len(r.ID) > 6 && r.ID[:6] == "group:" {
			if v, ok := groupRank[r.ID[6:]]; ok {
				return v
			}
		}
		return 1 << 29
	}
	sort.SliceStable(rules, func(i, j int) bool { return rankOf(rules[i]) < rankOf(rules[j]) })

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"rules":       rules,
		"channels":    allChannels, // 供「添加规则」向导选择通道
		"catalog":     catalog,     // 事件目录（供向导选择触发条件）
		"daily_items": dailyItemsForWizard(),
		// 大模块分组（2026-11-21 裁定：日报配置按模块选择）
		"daily_modules": notify.DailyModules(),
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
	actor := contextUserID(c) // 操作者（管理员代管时=管理员本人）

	var req struct {
		Enabled          *bool             `json:"enabled"`
		Events           *[]string         `json:"events"` // 组内事件选择（inline 编辑；未选=取消订阅）
		MinLevel         *string           `json:"min_level"`
		BodyTemplate     *string           `json:"body_template"`
		ChannelIDs       *[]int64          `json:"channel_ids"`       // 显式通道选择：缺省=沿用既有；空数组=显式不投递
		ChannelTemplates map[string]string `json:"channel_templates"` // 通道 ID → 事件×通道模板
		SendTime         string            `json:"send_time"`
		Items            []string          `json:"items"`
		Formats          map[string]string `json:"formats"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	switch {
	case ruleID == "daily":
		// 与独立日报端点同一白名单/格式口径（此前本端点直接落库：任意
		// send_time/items 可覆盖真实日报配置）。
		if req.SendTime != "" && !validateDailySendTime(c, req.SendTime) {
			return
		}
		if !validateDailyItems(c, req.Items) {
			return
		}
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
		// 通道选择先过就绪清洗再落任何写：400 必须整请求拒绝（不得先写
		// daily 配置再报通道错）。非空选择清洗为空=400；显式空数组=不投递，合法。
		var selectedChannelIDs []int64
		if req.ChannelIDs != nil {
			ids := *req.ChannelIDs
			if len(ids) > 0 {
				ids = sanitizeRuleChannelIDs(db.DB, uid, ids)
				if len(ids) == 0 {
					c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, msgNotifyChannelSelectionUnavailable), MessageKey: msgNotifyChannelSelectionUnavailable})
					return
				}
			}
			selectedChannelIDs = ids
		}
		// 日报配置与目标通道订阅行同事务：任一失败整体回滚，不得留下
		// 「保存失败但时间/项目已改、通道选择仍旧」的半写状态。
		tx, err := db.DB.BeginTx(c.Request.Context(), nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存日报配置失败", err)})
			return
		}
		defer tx.Rollback()
		if err := notify.SaveDailyConfigTx(c.Request.Context(), tx, cfg); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存日报配置失败", err)})
			return
		}
		// 日报目标通道落 sys.daily_report 订阅行（deliverOne 消费三态）；
		// 同时记录更新者/时间（items/send_time 变更亦刷新）。
		if req.ChannelIDs != nil {
			b, _ := json.Marshal(selectedChannelIDs)
			if _, err := tx.ExecContext(c.Request.Context(), `INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template, channel_ids, channel_templates, enabled, updated_at, updated_by)
				VALUES (?,?,?,?,?,?,1,datetime('now'),?)
				ON CONFLICT(user_id, event_type) DO UPDATE SET channel_ids=excluded.channel_ids, enabled=1, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
				uid, notify.EvtDailyReport, "info", "", string(b), "", actor); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存日报目标通道失败", err)})
				return
			}
		} else if _, err := tx.ExecContext(c.Request.Context(), `UPDATE notification_subscriptions SET updated_at=datetime('now'), updated_by=? WHERE user_id=? AND event_type=?`, actor, uid, notify.EvtDailyReport); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("记录日报更新时间失败", err)})
			return
		}
		if err := tx.Commit(); err != nil {
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
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.Tf(c, "k_9be13c70", group), MessageKey: "k_9be13c70"})
			return
		}
		// 级别白名单与订阅矩阵端点同源（validSubLevel）：此前原样落库，
		// min_level:"urgent" 会让 levelRank=0 变成最宽松下限（静默放行全部级别）。
		if req.MinLevel != nil && !validSubLevel(*req.MinLevel) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_3ae60346"), MessageKey: "k_3ae60346"})
			return
		}
		// 规则级「事件×通道模板」保存门（与派发渲染同门）：webhook 必须是可
		// 解析的 JSON 载荷模板、机器人/邮件模板长度受限。放在事务前——400 不
		// 触碰任何行。
		if req.ChannelTemplates != nil {
			clean := make(map[string]string, len(req.ChannelTemplates))
			for k, v := range req.ChannelTemplates {
				if v != "" {
					clean[k] = v
				}
			}
			if err := validateRuleChannelTemplates(db.DB, uid, clean); err != nil {
				var rv *ruleTemplateValidationError
				if errors.As(err, &rv) {
					c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, rv.key), MessageKey: rv.key})
					return
				}
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("校验规则模板失败", err)})
				return
			}
		}
		// 组写入包单事务：任一事件行失败不得留下半组订阅（此前逐条 Exec，
		// 失败中止时前半组已落库，UI 与投递口径分叉）。
		tx, err := db.DB.BeginTx(c.Request.Context(), nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存订阅失败", err)})
			return
		}
		defer tx.Rollback()
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
					// 取消选择=停用行（保留更新者/时间，不删行；无行时补建
					// opt-out 行，否则默认订阅兜底让取消静默失效）。
					if err := disableSubscriptionRow(tx, uid, ev, actor); err != nil {
						c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("取消订阅失败", err)})
						return
					}
					continue
				}
				wantOn = true
			} else if req.Enabled != nil && !*req.Enabled {
				// 显式停用=停用行（保留更新者/时间，不删行；投递侧按 enabled=0
				// 过滤；无行时同样补建，否则默认订阅继续投递）。
				if err := disableSubscriptionRow(tx, uid, ev, actor); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("取消订阅失败", err)})
					return
				}
				continue
			}
			// 部分更新：先读既有行，缺省键沿用现值；无行且未要求启用=不动。
			// 读错误必须区分 ErrNoRows（无行=按默认值建行）与真实故障：
			// 此前一律当无行用默认值覆盖，DB 故障窄窗会清掉真实配置。
			var curLevel, curTpl, curIDs, curTpls string
			curEnabled := 0
			rowExisted := true
			err := tx.QueryRow(`SELECT COALESCE(min_level,''), COALESCE(body_template,''),
				COALESCE(channel_ids,''), COALESCE(channel_templates,''), COALESCE(enabled,1) FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, ev).Scan(&curLevel, &curTpl, &curIDs, &curTpls, &curEnabled)
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取订阅失败", err)})
					return
				}
				if !wantOn {
					continue // 未订阅且未要求启用：不建行
				}
				curLevel, curTpl, curIDs, curTpls = "info", "", "", ""
				curEnabled = 1
				rowExisted = false
			}
			// 部分更新（仅模板/级别）不得误启用已停用行；显式启用/选中才置 1。
			if wantOn {
				curEnabled = 1
			}
			// 组级 min_level 只作为「新订阅事件的起始门槛」：已有行保留逐事件
			// 级别（组内事件可在订阅矩阵逐条配置，组保存不得用单一值回写全部）。
			if req.MinLevel != nil && (!rowExisted || strings.TrimSpace(curLevel) == "") {
				curLevel = *req.MinLevel
			}
			if req.BodyTemplate != nil {
				curTpl = *req.BodyTemplate
			}
			if req.ChannelIDs != nil {
				// 显式空数组='[]'=不投递任何通道（用户裁定）；非空=仅选定通道。
				// 缺省键（nil）才沿用现值；'' 缺省态=全部启用通道（默认订阅）。
				// 非空选择过就绪清洗：失效通道不落库（会话待刷新=发送被派发侧跳过）；
				// 清洗后为空=400（不得静默落 "[]" 变成显式不投递）。
				ids := *req.ChannelIDs
				if len(ids) > 0 {
					ids = sanitizeRuleChannelIDs(tx, uid, ids)
					if len(ids) == 0 {
						c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, msgNotifyChannelSelectionUnavailable), MessageKey: msgNotifyChannelSelectionUnavailable})
						return
					}
				}
				b, _ := json.Marshal(ids)
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
			if _, err := tx.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template, channel_ids, channel_templates, enabled, updated_at, updated_by)
				VALUES (?,?,?,?,?,?,?,datetime('now'),?)
				ON CONFLICT(user_id, event_type) DO UPDATE SET min_level=excluded.min_level, body_template=excluded.body_template,
				channel_ids=excluded.channel_ids, channel_templates=excluded.channel_templates, enabled=excluded.enabled,
				updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
				uid, ev, curLevel, curTpl, curIDs, curTpls, curEnabled, actor); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存订阅失败", err)})
				return
			}
		}
		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存订阅失败", err)})
			return
		}

	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.Tf(c, "k_958958af", ruleID), MessageKey: "k_958958af"})
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
	notify.Publish(notify.Event{Type: notify.EvtNotifyRuleChanged, Fields: map[string]string{"1": c.GetString("username"), "2": "更新", "3": ruleTitle}})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// requireNotifyMaster 通知测试发送的主节点门：从节点不存在
// pending 消费方（投递 Daemon 仅主节点运行），放行=API 成功但消息永不投递的
// 假成功。角色读脱离客户端生命周期（与 requireMasterNode 同口径：请求 ctx
// 已取消不得误报成角色查询失败），查询失败响亮 500。
func requireNotifyMaster(c *gin.Context) bool {
	if db.DB == nil {
		clusterError(c, http.StatusInternalServerError, "节点角色查询失败", nil)
		return false
	}
	roleCtx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 2*time.Second)
	isMaster, err := services.RoleOf(roleCtx, db.DB)
	cancel()
	return requireMasterResult(c, isMaster, err, masterGateOptions{
		queryFailure: "节点角色查询失败",
		forbidden:    "通知配置仅主节点生效，请在主节点操作",
	})
}

// TestNotificationRule POST /notification/rules/:id/test——按规则选定通道+
// 每通道模板渲染测试消息，落投递行（【测试】标记）走真实投递管线。
// 管理员 ?user_id 代管视角同写侧。结果见投递记录（用户裁定：测试必须留痕）。
func (h *Handlers) TestNotificationRule(c *gin.Context) {
	if !requireNotifyMaster(c) {
		return
	}
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.Tf(c, "k_958958af", ruleID), MessageKey: "k_958958af"})
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
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.Tf(c, "k_9be13c70", group), MessageKey: "k_9be13c70"})
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
	if !requireNotifyMaster(c) {
		return
	}
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
	if err := db.DB.QueryRow(chQuery, scopeArgs...).Scan(&totalChannels); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知统计失败", err)})
		return
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions`+scope, scopeArgs...).Scan(&totalRules); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知统计失败", err)})
		return
	}
	// 投递统计读主库（notification_deliveries 在主库，非指标库）；
	// 成功口径=sent+partial（partial=部分通道成功）。
	dlQuery := `SELECT COUNT(*) FROM notification_deliveries` + scope
	if err := db.DB.QueryRow(dlQuery, scopeArgs...).Scan(&totalDeliveries); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知统计失败", err)})
		return
	}
	sentQuery := `SELECT COUNT(*) FROM notification_deliveries WHERE status IN ('sent','partial')`
	if scope != "" {
		sentQuery += ` AND user_id=?`
	}
	if err := db.DB.QueryRow(sentQuery, scopeArgs...).Scan(&sentDeliveries); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知统计失败", err)})
		return
	}
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
	tcRows, err := db.DB.Query(tcQuery, scopeArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通道类型分布失败", err)})
		return
	}
	for tcRows.Next() {
		var tc typeCount
		if err := tcRows.Scan(&tc.Type, &tc.Count); err != nil {
			tcRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通道类型分布失败", err)})
			return
		}
		byType = append(byType, tc)
	}
	if err := tcRows.Err(); err != nil {
		tcRows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通道类型分布失败", err)})
		return
	}
	tcRows.Close()

	// 用户列表（供筛选器）
	type userBrief struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}
	var users []userBrief
	rows, err := db.DB.Query(`SELECT id, username FROM users ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询用户列表失败", err)})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var u userBrief
		if err := rows.Scan(&u.ID, &u.Username); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询用户列表失败", err)})
			return
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询用户列表失败", err)})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"stats":           gin.H{"channels": totalChannels, "rules": totalRules, "deliveries": totalDeliveries, "success_rate": rate},
		"channel_by_type": byType,
		"users":           users,
	}})
}

// GetDeliveryTrend GET /notification/delivery-trend——7天投递趋势（按日计数+成功率）。
// 普通用户=本人；管理员默认全平台（与概览统计卡一致），可 ?user_id=X 下钻指定用户。
func (h *Handlers) GetDeliveryTrend(c *gin.Context) {
	uid := contextUserID(c)
	scope, args := " AND user_id=?", []any{uid}
	if isAdminRequest(c) {
		if q := c.Query("user_id"); q != "" {
			if v, err := strconv.ParseInt(q, 10, 64); err == nil && v > 0 {
				uid = v
				args = []any{uid}
			}
		} else {
			// 概览页的管理员口径=全平台（与 admin/overview、delivery-stats 一致）；
			// 显式 ?user_id 仍可下钻单用户。
			scope, args = "", nil
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
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE substr(created_at,1,10)=?`+scope,
			append([]any{day}, args...)...).Scan(&total); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递趋势失败", err)})
			return
		}
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE substr(created_at,1,10)=? AND status IN ('sent','partial')`+scope,
			append([]any{day}, args...)...).Scan(&sent); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递趋势失败", err)})
			return
		}
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
	rows, err := db.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
		return
	}
	for rows.Next() {
		var s chanStat
		if err := rows.Scan(&s.ChannelID, &s.Type, &s.Total, &s.Sent); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
			return
		}
		if s.Total > 0 {
			s.Rate = float64(s.Sent) / float64(s.Total)
		}
		s.Name = "通道 #" + strconv.FormatInt(s.ChannelID, 10)
		var name string
		if err := db.DB.QueryRow(`SELECT name FROM notification_channels WHERE id=?`, s.ChannelID).Scan(&name); err == nil {
			s.Name = name
		} else if !errors.Is(err, sql.ErrNoRows) {
			// 行已删（通道 #id 兜底）之外一律 500：DB 故障静默兜底会把
			// 「读不到名称」伪装成已删通道。
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
			return
		}
		byChannel = append(byChannel, s)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
		return
	}
	rows.Close()

	type typeStat struct {
		Type  string  `json:"type"`
		Total int     `json:"total"`
		Sent  int     `json:"sent"`
		Rate  float64 `json:"rate"`
	}
	byType := make([]typeStat, 0, 4)
	q = `SELECT channel_type, COUNT(*), SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END)
		FROM notification_delivery_channels WHERE ` + where + ` GROUP BY channel_type ORDER BY COUNT(*) DESC`
	rows, err = db.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
		return
	}
	for rows.Next() {
		var s typeStat
		if err := rows.Scan(&s.Type, &s.Total, &s.Sent); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
			return
		}
		if s.Total > 0 {
			s.Rate = float64(s.Sent) / float64(s.Total)
		}
		byType = append(byType, s)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
		return
	}
	rows.Close()

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
	rows, err = db.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
		return
	}
	for rows.Next() {
		var s eventStat
		if err := rows.Scan(&s.EventType, &s.Total); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
			return
		}
		s.Title = s.EventType
		if t, ok := titles[s.EventType]; ok {
			s.Title = t
		}
		byEvent = append(byEvent, s)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询投递分布失败", err)})
		return
	}
	rows.Close()

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"by_channel": byChannel,
		"by_type":    byType,
		"by_event":   byEvent,
	}})
}
