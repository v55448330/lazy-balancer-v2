package notify

// 投递 Daemon 主循环（taskengine notification-delivery Run 体）。
// 每个 tick：①扫描 pending 批次→按用户启用通道展开→逐通道发送（重试 1 次）
// ②MCP 会话超时清理。（无通道健康探测：本循环不含 ping 端点逻辑。）

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	deliveryTickInterval = 10 * time.Second
	deliveryBatchSize    = 50
)

// RunDeliveryLoop 投递主循环（rc.Ctx 取消=引擎停止/角色门停）。
func RunDeliveryLoop(ctx context.Context) error { //scope-exempt: daemon-run-body-loop
	ctx = withTaskID(ctx, "notification-delivery")
	taskLogf(ctx, "delivery", "通知投递任务启动（pending 扫描+失败重试+MCP 会话清理）")
	requeueStalePending()
	t := time.NewTicker(deliveryTickInterval) //scope-exempt: daemon-run-body-loop
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			processPendingBatch(ctx)
			cleanupExpiredMCPSessions(ctx)
		case <-deliveryWakeCh:
			// 重发唤醒：立即补扫 pending（tick 兜底仍保留）。
			processPendingBatch(ctx)
		}
	}
}

// processPendingBatch 一批 pending：逐行取用户启用通道并发送。
// 单行多通道：全部成功 sent；有成功有失败 partial；全部失败重试 1 次后
// failed；无启用通道的行直接 dead（无处投递，留痕可见）。
func processPendingBatch(ctx context.Context) {
	batch, err := pendingDeliveries(deliveryBatchSize)
	if err != nil {
		taskLogWarn(ctx, "delivery", "notify pending 扫描失败: %v", err)
		return
	}
	for _, d := range batch {
		if ctx.Err() != nil {
			return
		}
		deliverOne(ctx, d.ID, d.UserID, Message{
			EventType: d.EventType, Level: d.Level, Title: d.Title, Body: d.Body, Node: d.Node,
		})
	}
}

// deliverOne 单行投递：展开订阅选定通道→failed_only 重发过滤（retry_channel_ids
// 非空时仅发指定通道，消费后清空）→逐通道发送（失败重试 1 次）→每通道结果落
// notification_delivery_channels（概览分布统计事实源）→主表状态收口
// （全成功 sent / 部分失败 partial / 全失败 failed）。
func deliverOne(ctx context.Context, id, userID int64, msg Message) {
	retryIDs := deliveryRetryChannelIDs(id)
	// 日报模板变量：把载荷 values 注入 msg.Fields，供内容模板 {{requests}} 等替换。
	if msg.EventType == EvtDailyReport {
		msg.Fields = DailyFieldsFromBody(msg.Body)
	}
	channels, err := channelsForUser(userID)
	if err != nil {
		taskLogWarn(ctx, "delivery", "notify 通道查询失败（delivery=%d）: %v", id, err)
		return
	}
	// 订阅通道选择三态：无订阅行/缺省=全部启用通道（默认订阅语义）；
	// '[]' 显式空选=不投递任何通道（用户裁定：全不选=不订阅）；
	// 非空数组=仅发选定通道。
	sel := subscriptionChannelSelectionFor(userID, msg.EventType)
	if sel.explicitEmpty {
		clearDeliveryRetryChannels(id)
		markDelivery(id, "dead", true, "规则未选择接收通道（不投递）")
		return
	}
	if len(sel.ids) > 0 {
		filtered := channels[:0]
		for _, ch := range channels {
			if sel.ids[ch.ChannelID] {
				filtered = append(filtered, ch)
			}
		}
		channels = filtered
	}
	if len(retryIDs) > 0 {
		filtered := channels[:0]
		for _, ch := range channels {
			if retryIDs[ch.ChannelID] {
				filtered = append(filtered, ch)
			}
		}
		channels = filtered
		clearDeliveryRetryChannels(id)
	}
	if len(channels) == 0 {
		if len(retryIDs) > 0 {
			markDelivery(id, "dead", true, "重发通道均不可用（已删除或停用）")
			return
		}
		markDelivery(id, "dead", true, "无启用的通知通道")
		return
	}
	errs, sentAny := sendToChannels(ctx, id, userID, channels, sel.templates, msg)
	if sentAny {
		if len(errs) > 0 {
			reason := "部分通道失败: " + strings.Join(errs, "; ")
			markDelivery(id, "partial", true, reason)
			taskLogf(ctx, "delivery", "投递 %d 部分成功（user=%d event=%s）%s", id, userID, msg.EventType, reason)
			return
		}
		markDelivery(id, "sent", true, "")
		taskLogf(ctx, "delivery", "投递 %d 已发送（user=%d event=%s）", id, userID, msg.EventType)
		return
	}
	markDelivery(id, "failed", true, strings.Join(errs, "; "))
	taskLogWarn(ctx, "delivery", "投递 %d 失败（user=%d event=%s）: %s", id, userID, msg.EventType, strings.Join(errs, "; "))
}

// sendToChannelConcurrency 逐通道发送的有界并发度：单条投递行的通道数通常
// 个位数，串行会让一个慢通道（SMTP 握手/远端超时）拖住整批；上限 3 防止
// 突发批量把出站连接打爆。
const sendToChannelConcurrency = 3

// sendToChannels 逐通道渲染+发送（失败重试 1 次）+结果落行。deliverOne 与
// 规则测试共用：模板优先级链=事件×通道模板 > 事件级模板 > 通道样式 > 默认。
// deliveryID=0 时不落结果行（测试发送不污染投递统计）。
// 并发：≤sendToChannelConcurrency 个通道并行发送（慢通道不阻塞其余通道），
// 结果按通道序收集后统一落行——落库仍在单 goroutine，保持既有语义与顺序。
// wxSessionReadyForDelivery 微信会话就绪判定（测试可覆写）。会话待刷新
// （iLink 上下文过期/从未建立）时不再尝试发送——见 sendToChannels 守卫。
var wxSessionReadyForDelivery = WxSessionReady

type channelSendResult struct {
	errMsg string // 非空=该通道失败（含跳过原因）
	sent   bool
	durMs  int64
}

// wxChannelCredentialsConfigured 微信通道凭据是否齐备（receiver 与 bot 键/
// 登录令牌都来自 target 或全局凭据）。未配置与会话过期要给出不同的跳过文案。
func wxChannelCredentialsConfigured(targetJSON string) bool {
	var cfg struct {
		Receiver string `json:"receiver"`
	}
	_ = json.Unmarshal([]byte(targetJSON), &cfg)
	if strings.TrimSpace(cfg.Receiver) == "" {
		return false
	}
	return wxTargetBotKey(targetJSON) != ""
}

// sendOneChannel 单通道发送（含重试 1 次与就绪门），不落库。
func sendOneChannel(ctx context.Context, ch deliveryTarget, channelTpl, eventTpl string, msg Message) channelSendResult {
	// 通道就绪门（2026-11-22 用户裁定）：微信会话失效后不再允许发送，
	// 跳过并留可见原因（投递记录可见），直到重新绑定且会话就绪。未配置
	// 凭据与会话过期是两种用户动作，文案必须区分。
	if ch.Type == "wx_clawbot" && !wxSessionReadyForDelivery(ch.Target) {
		if !wxChannelCredentialsConfigured(ch.Target) {
			return channelSendResult{errMsg: "微信凭据未配置（receiver/登录令牌为空）；请重新扫码登录并在通道配置中重新绑定"}
		}
		return channelSendResult{errMsg: "微信会话未就绪（会话待刷新，已跳过发送）；请让该微信先给机器人发消息重建会话，或重新扫码绑定"}
	}
	chMsg := msg
	if msg.EventType != EvtDailyReport {
		// 通道名后缀只服务事件消息（同事件多通道时区分来源）；日报标题固定
		// 「每日日报」，追加通道名对用户无意义。
		chName := ch.Name
		if chName == "" {
			chName = ch.Type
		}
		chMsg.Title = msg.Title + "（" + chName + "）"
	}
	isChannelTemplate := channelTpl != ""
	if channelTpl == "" {
		channelTpl = eventTpl
	}
	if channelTpl != "" && msg.EventType != EvtDailyReport {
		now := time.Now()
		switch {
		case isChannelTemplate && ch.Type == "webhook":
			// 规则级 webhook 模板=用户声明的 JSON 载荷：按 JSON 口径渲染占位符
			//（值 JSON 编码；兼容裹引号的旧预置），TemplateFormat 让 sender 直接
			// 把它作为 POST 体。
			chMsg.Body = renderStyleTemplateJSON(channelTpl, msg, now)
			chMsg.TemplateApplied, chMsg.TemplateFormat = true, "json"
		case isChannelTemplate && ch.Type == "email":
			// 规则级邮件模板的格式由内容决定（后端无规则级格式字段）：含 HTML 标签
			// → 值 HTML 转义后按 text/html 发送；纯文本模板 → 文本渲染后按
			// text/plain 原文发送（换行保留，保存门前落库的纯文本模板不变形）。
			chMsg.Body = renderStyleTemplate(channelTpl, msg, now)
			chMsg.TemplateApplied = true
			if ruleTemplateIsHTML(channelTpl) {
				chMsg.Body = renderStyleTemplateHTML(channelTpl, msg, now)
				chMsg.TemplateFormat = "html"
			}
		default:
			// 事件级模板（所有通道共用的文本版式）与机器人模板：文本渲染。
			// 全量布局已渲染：通道样式模板不得再套（双渲染根因修复）。
			chMsg.Body = renderStyleTemplate(channelTpl, msg, now)
			chMsg.TemplateApplied = true
		}
	}
	// 传 chMsg 保留事件模板渲染结果（非日报原样透传 chMsg.Body）；
	// 此前传 msg 会把事件模板渲染覆盖回目录原始正文（事件模板不生效根因）。
	// ContentFormat=实际渲染格式：邮件通道据此决定 Content-Type。
	chStyle := ParseChannelStyle(ch.StyleConfig)
	// 日报渲染模式显式开关（2026-11-22）：模块拼装=该通道正文模板保留
	// 但不生效（dailyTemplatesSuppressed），走 items 分节渲染。
	if msg.EventType == EvtDailyReport && chStyle.DailyModuleModeEffective() {
		chMsg.DailyModuleMode = true
	}
	chMsg.Body, chMsg.ContentFormat = renderDailyForChannelFormat(chMsg, ch.Type, chStyle.DailyFormat)
	styledTarget := MergeStyleIntoTarget(ch.Target, ch.StyleConfig)
	sendStart := time.Now()
	sendErr := sendToChannel(ctx, ch.Type, styledTarget, chMsg)
	if sendErr != nil {
		sendErr = sendToChannel(ctx, ch.Type, styledTarget, chMsg)
	}
	durMs := time.Since(sendStart).Milliseconds()
	if sendErr != nil {
		return channelSendResult{errMsg: sendErr.Error(), durMs: durMs}
	}
	return channelSendResult{sent: true, durMs: durMs}
}

func sendToChannels(ctx context.Context, deliveryID, userID int64, channels []deliveryTarget, channelTpls map[int64]string, msg Message) ([]string, bool) {
	// 事件级模板（同一 user×event 对所有通道相同）：提升到循环外，避免逐通道
	// 重复查库。
	eventTpl := subscriptionTemplateFor(userID, msg.EventType)

	results := make([]channelSendResult, len(channels))
	sem := make(chan struct{}, sendToChannelConcurrency)
	var wg sync.WaitGroup
	for i := range channels {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = sendOneChannel(ctx, channels[i], channelTpls[channels[i].ChannelID], eventTpl, msg)
		}(i)
	}
	wg.Wait()

	var errs []string
	sentAny := false
	for i, ch := range channels {
		// 落库在收集阶段串行完成：SQLite 单写者，避免并发写锁竞争。
		r := results[i]
		if r.errMsg != "" {
			errs = append(errs, ch.Type+": "+r.errMsg)
			if deliveryID > 0 {
				recordChannelResult(ctx, deliveryID, userID, ch, msg.EventType, "failed", r.errMsg, r.durMs)
			}
			continue
		}
		sentAny = true
		if deliveryID > 0 {
			recordChannelResult(ctx, deliveryID, userID, ch, msg.EventType, "sent", "", r.durMs)
		}
	}
	return errs, sentAny
}

// EnqueueTestDelivery 规则测试发送（导出：handlers 通知规则「测试」按钮）：
// 以目录模板+样例参数渲染真实事件形态消息，落 pending 投递行（标题带
// 【测试】标记、is_test=1）并唤醒投递循环——与真实投递同管线：订阅通道选择、
// 每通道模板渲染、每通道结果落行、投递记录可见（用户裁定：测试消息必须留痕）。
func EnqueueTestDelivery(userID int64, eventType string) error {
	entry, ok := catalogByID(eventType)
	if !ok {
		return errors.New("事件不在目录: " + eventType)
	}
	sel := subscriptionChannelSelectionFor(userID, eventType)
	if sel.explicitEmpty {
		return errors.New("规则未选择接收通道")
	}
	channels, err := channelsForUser(userID)
	if err != nil {
		return err
	}
	if len(sel.ids) > 0 {
		n := 0
		for _, ch := range channels {
			if sel.ids[ch.ChannelID] {
				n++
			}
		}
		if n == 0 {
			return errors.New("选定的接收通道均未启用")
		}
	} else if len(channels) == 0 {
		return errors.New("无启用的通知通道")
	}
	// 样例参数：目录模板参数序契约的通用占位（真实形态可读）
	// Node 必须带（用户裁定 2026-11-22）：模板来源区「所属节点」行在测试
	// 消息里此前恒空——与真实事件形态分叉，测试失真。
	// 参数序契约最多 7 位（sec.blocked_aggregate 的 TOP 路径）：少填第 7 位
	// 会让测试消息渲染成 %!s(MISSING)，与真实事件形态失真。
	sample := Event{Type: eventType, Level: entry.Level, Node: MasterNodeLabel(), Fields: map[string]string{
		"1": "example.com", "2": "示例详情", "3": "样例来源", "4": "3", "5": "样例", "6": "样例", "7": "样例",
	}}
	title := "【测试】" + renderTitle(entry, sample)
	body := renderBody(entry, sample)
	_, err = db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, is_test, created_at, node)
		VALUES (?,?,?,?,?, 'pending', 0, 1, ?, ?)`,
		userID, eventType, string(entry.Level), title, body,
		time.Now().UTC().Format("2006-01-02 15:04:05"), sample.Node)
	if err != nil {
		return err
	}
	select {
	case deliveryWakeCh <- struct{}{}:
	default:
	}
	return nil
}

// RecordChannelTestDelivery 通道「测试」留痕（用户裁定：投递记录须记录所有
// 外发消息，含通道测试）。同步落 delivery 行（is_test=1，status=sent/failed）
// + 每通道结果行，与真实投递同表同口径，投递记录可见。
func RecordChannelTestDelivery(userID, channelID int64, typ, name string, ok bool, errMsg string) error {
	status := "sent"
	if !ok {
		status = "failed"
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	// sent_at 只在成功时写（与 markDelivery 同口径）：失败测试行不得带
	// 「已发送时刻」，否则投递记录把失败通道显示成已发送。
	var sentAt any
	if ok {
		sentAt = now
	}
	res, err := db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, is_test, created_at, sent_at)
		VALUES (?,?,?,?,?,?,1,1,?,?)`,
		userID, "channel.test", "info", "【测试】通道「"+name+"」",
		"通道连通性测试消息", status, now, sentAt)
	if err != nil {
		return err
	}
	deliveryID, _ := res.LastInsertId()
	_, err = db.DB.Exec(`INSERT INTO notification_delivery_channels
		(delivery_id, user_id, channel_id, channel_name, channel_type, event_type, status, error, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		deliveryID, userID, channelID, name, typ, "channel.test", status, errMsg, now)
	return err
}

// DeliverDailyForUser 单用户日报测试发送（导出：每日摘要卡「测试发送」）：
// 与定时日报同管线（数据载荷落 pending → 派发侧按通道格式渲染），is_test=1
// 区分定时全员日报（is_test=0）。
func DeliverDailyForUser(userID int64, now time.Time) error {
	cfg, err := GetDailyConfig(userID)
	if err != nil {
		return err
	}
	data, err := CollectDailyData(context.Background(), now)
	if err != nil {
		return err
	}
	if err := deliverDaily(userID, cfg, data, now, true); err != nil {
		return err
	}
	select {
	case deliveryWakeCh <- struct{}{}:
	default:
	}
	return nil
}

// recordChannelResult 每通道投递结果落行（统计事实源；落库失败仅告警不阻断投递）。
// channel_name 快照落行——通道删除后投递记录仍显示通道名（不回退「通道 #id」）。
func recordChannelResult(ctx context.Context, deliveryID, userID int64, ch deliveryTarget, eventType, status, errMsg string, durMs int64) {
	_, err := db.DB.Exec(`INSERT INTO notification_delivery_channels
		(delivery_id, user_id, channel_id, channel_name, channel_type, event_type, status, error, duration_ms, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		deliveryID, userID, ch.ChannelID, ch.Name, ch.Type, eventType, status, errMsg, durMs,
		time.Now().UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		taskLogWarn(ctx, "delivery", "notify 通道结果落库失败（delivery=%d channel=%d）: %v", deliveryID, ch.ChannelID, err)
	}
}

// cleanupExpiredMCPSessions 30 分钟无活动的 MCP 会话标记离线（删除行——
// 在线 Agent 页=表内即在线）。
func cleanupExpiredMCPSessions(ctx context.Context) {
	if _, err := db.DB.Exec(`DELETE FROM mcp_sessions WHERE last_seen < datetime('now', '-30 minutes')`); err != nil {
		taskLogWarn(ctx, "delivery", "notify MCP 会话清理失败: %v", err)
	}
}

// subscriptionTemplateFor 事件级消息模板（notification_subscriptions.body_template；
// 优先于通道模板——投递 Daemon 的 renderStyleTemplate 同占位符集）。
func subscriptionTemplateFor(userID int64, eventType string) string {
	var tpl string
	_ = db.DB.QueryRow(`SELECT COALESCE(body_template,'') FROM notification_subscriptions
		WHERE user_id=? AND event_type=?`, userID, eventType).Scan(&tpl)
	return tpl
}

// subscriptionChannelSelectionsFor 批量版本（dispatch 热路径）：一次
// `event_type=? AND user_id IN (…)` 查询替代逐用户单查（N+1）。缺行用户
// 不出现在返回 map 中，调用方按零值（=默认订阅语义）处理。
func subscriptionChannelSelectionsFor(eventType string, userIDs []int64) map[int64]channelSelection {
	out := make(map[int64]channelSelection, len(userIDs))
	if len(userIDs) == 0 || db.DB == nil {
		return out
	}
	ph := make([]string, len(userIDs))
	args := make([]any, 0, len(userIDs)+1)
	args = append(args, eventType)
	for i, uid := range userIDs {
		ph[i] = "?"
		args = append(args, uid)
	}
	rows, err := db.DB.Query(`SELECT user_id, COALESCE(channel_ids,''), COALESCE(channel_templates,'')
		FROM notification_subscriptions WHERE event_type=? AND user_id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var uid int64
		var idsRaw, tplRaw string
		if err := rows.Scan(&uid, &idsRaw, &tplRaw); err != nil {
			continue
		}
		sel := channelSelection{ids: map[int64]bool{}, templates: map[int64]string{}}
		if idsRaw != "" {
			var ids []int64
			if json.Unmarshal([]byte(idsRaw), &ids) == nil {
				if len(ids) == 0 {
					sel.explicitEmpty = true
				}
				for _, id := range ids {
					sel.ids[id] = true
				}
			}
		}
		if tplRaw != "" {
			var m map[string]string
			if json.Unmarshal([]byte(tplRaw), &m) == nil {
				for k, v := range m {
					if id, err := strconv.ParseInt(k, 10, 64); err == nil && v != "" {
						sel.templates[id] = v
					}
				}
			}
		}
		out[uid] = sel
	}
	return out
}

// channelSelection 订阅的通道选择三态：explicitEmpty=显式 '[]'（不投递）；
// ids 非空=仅选定通道；两者皆否=全部启用通道（默认订阅语义）。
type channelSelection struct {
	ids           map[int64]bool
	templates     map[int64]string
	explicitEmpty bool
}

// subscriptionChannelSelectionFor 读订阅通道选择+每通道模板（坏 JSON=零值兜底，
// 派发路径不可因配置损坏中断投递）。
func subscriptionChannelSelectionFor(userID int64, eventType string) channelSelection {
	out := channelSelection{ids: map[int64]bool{}, templates: map[int64]string{}}
	var idsRaw, tplRaw string
	_ = db.DB.QueryRow(`SELECT COALESCE(channel_ids,''), COALESCE(channel_templates,'') FROM notification_subscriptions
		WHERE user_id=? AND event_type=?`, userID, eventType).Scan(&idsRaw, &tplRaw)
	if idsRaw != "" {
		var ids []int64
		if json.Unmarshal([]byte(idsRaw), &ids) == nil {
			if len(ids) == 0 {
				out.explicitEmpty = true // 显式空数组=不投递（区别于缺省空串=全部）
			}
			for _, id := range ids {
				out.ids[id] = true
			}
		}
	}
	if tplRaw != "" {
		var m map[string]string
		if json.Unmarshal([]byte(tplRaw), &m) == nil {
			for k, v := range m {
				if id, err := strconv.ParseInt(k, 10, 64); err == nil && v != "" {
					out.templates[id] = v
				}
			}
		}
	}
	return out
}
