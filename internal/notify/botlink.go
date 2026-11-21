package notify

// bot 连接器骨架（QQ/微信共用）：鉴权/心跳/重连状态机单源，协议编解码由
// 两个连接器分实现。形态=出站长连（免公网）：Daemon Run 内循环——配置缺失
// 即退出（EnabledFn 同口径）；断线指数退避重连；收到 C2C/私聊「绑定测试」
// → 匹配弹框绑定会话确认（建通道交弹框保存）；通道掉线触发 notify_channel_down 告警
// （走其它还活着的通道，自监控闭环）。

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// botLinkState 连接状态（通知中心页状态点数据源）。
type botLinkState struct {
	mu         sync.Mutex
	connected  bool
	downActive bool // 曾发布掉线告警且未恢复——仅真实 outage 后的上线才发恢复事件
	lastChange time.Time
	lastErr    string
}

func (s *botLinkState) set(connected bool, err string) {
	down, up := s.apply(connected, err)
	if down {
		// 通道掉线自监控：经其它还活着的通道告警（Publish→delivery；
		// 若投递通道同样依赖本连接，sender 会返回离线错误并留痕，不会死循环阻塞）。
		Publish(Event{
			Type: EvtNotifyChannelDown, Level: LevelWarn,
			Title: "通知通道离线", Body: err,
		})
	}
	if up {
		// 离线→在线恢复沿：与掉线成对，告知受众通道已恢复。
		Publish(Event{
			Type: EvtNotifyChannelRecovered, Level: LevelInfo,
			Title: "通知通道恢复", Body: "连接已恢复，通知投递正常",
		})
	}
}

// apply 更新连接态并返回「在线→离线」/「离线→在线」沿（不发布告警）。重连期间
// 逐次失败不重复发布（退避重连每分钟可多次事件，逐次发布会刷屏）。
func (s *botLinkState) apply(connected bool, err string) (down, up bool) {
	s.mu.Lock()
	down = s.connected && !connected
	up = !s.connected && connected && s.downActive
	if down {
		s.downActive = true
	}
	if !s.connected && connected {
		s.downActive = false
	}
	s.connected = connected
	s.lastChange = time.Now()
	s.lastErr = err
	s.mu.Unlock()
	return down, up
}

// botLinkRegistry per-bot 连接态登记表（多机器人入站会话各持其态）。
// first=首 bot（枚举首元素=全局凭据 bot）：无参状态查询保持单 bot 兼容。
// worker spawn 时 register、回收时 unregister；任务停止 stopAll 统一置离线。
type botLinkRegistry struct {
	mu    sync.Mutex
	links map[string]*botLinkState
	first string
}

// register 取 bot 状态（缺则创建；不改首 bot，首 bot 由 setFirst 显式指定）。
func (r *botLinkRegistry) register(botID string) *botLinkState {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.links == nil {
		r.links = map[string]*botLinkState{}
	}
	s := r.links[botID]
	if s == nil {
		s = &botLinkState{}
		r.links[botID] = s
	}
	return s
}

func (r *botLinkRegistry) unregister(botID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.links, botID)
}

// setFirst 指定首 bot（supervisor 每轮对账置为枚举首元素）。
func (r *botLinkRegistry) setFirst(botID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.first = botID
}

// status 查 bot 在线态：botID 空=首 bot；未登记 bot=离线（零值）。
func (r *botLinkRegistry) status(botID string) (bool, string, time.Time) {
	r.mu.Lock()
	id := botID
	if id == "" {
		id = r.first
	}
	s := r.links[id]
	r.mu.Unlock()
	if s == nil {
		return false, "", time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected, s.lastErr, s.lastChange
}

// stopAll 任务停止收尾：在线 bot 统一置离线，并**聚合发布一次**掉线告警
// （而非每 bot 一次）。该事件默认订阅=全部启用通道，逐 bot 发布会使 N 个
// 在线 bot × N 个订阅通道=每通道收 N 次（用户实测重启每通道收 2 次根因）。
// 已离线 bot 保留其具体 lastErr（如「登录态过期，需重新扫码」）供排障，不被
// 泛化停止原因覆盖。计划内回收（凭据轮换/删通道）不经此路径——worker 退出
// 不置离线，由 unregister 收口，无假告警。先快照再释锁——Publish→sender 可能
// 回调 status，持锁会死锁。
func (r *botLinkRegistry) stopAll(err string) {
	r.mu.Lock()
	states := make([]*botLinkState, 0, len(r.links))
	for _, s := range r.links {
		states = append(states, s)
	}
	r.mu.Unlock()
	anyDown := false
	for _, s := range states {
		s.mu.Lock()
		online := s.connected
		s.mu.Unlock()
		// 仅在线 bot 置离线：已离线 bot 保留其具体 lastErr（登录态过期等）
		// 供排障，不被泛化停止原因覆盖。
		if online {
			if down, _ := s.apply(false, err); down {
				anyDown = true
			}
		}
	}
	if anyDown {
		Publish(Event{
			Type: EvtNotifyChannelDown, Level: LevelWarn,
			Title: "通知通道离线", Body: err,
		})
	}
}

// botReconcileInterval bot 枚举对账周期：新钉住通道的 bot 在此窗口内上线。
// 取短周期（1s）兜底唤醒时序竞态——钉住唤醒先于通道落库（handler 先算
// target 后 INSERT）或唤醒信号合并丢弃时，对账仍在秒级捕获新凭据；
// 凭据变更/钉住唤醒（qqWakeCh/wxWakeCh）命中时立即对账，不等周期。
const botReconcileInterval = 1 * time.Second

// botBackoff 断线重连退避（1s→2s→…→60s 封顶）。
func botBackoff(attempt int) time.Duration {
	d := time.Second
	for i := 1; i < attempt && d < time.Minute; i++ {
		d *= 2
	}
	return d
}

var errBotNotConnected = errors.New("bot 连接未建立")

// quoteJSON 字符串转 JSON 字面量（绑定 target 组装用）。
func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// formatBotText 长连通道（QQ/微信）文本形态：标题+换行+正文（正文空则仅标题）。
func formatBotText(msg Message) string {
	var b strings.Builder
	b.WriteString(msg.Title)
	if strings.TrimSpace(msg.Body) != "" {
		b.WriteString("\n" + msg.Body)
	}
	// 日报渲染底座已含品牌+时间署名，避免重复；事件消息附加署名。
	if msg.EventType != EvtDailyReport {
		b.WriteString("\n\n" + brandFooter(msg.Time))
	}
	return b.String()
}

// brandFooter 消息署名（品牌+时间），统一附加于机器人文本/邮件。
func brandFooter(ts time.Time) string {
	if ts.IsZero() {
		ts = time.Now()
	}
	return fmt.Sprintf("—— %s · %s", BrandName(), ts.Format("2006-01-02 15:04"))
}

// formatBotTextWithTemplate 通道内容模板渲染（style_config.content_template；
// 占位符 {{title}}/{{body}}/{{level}}/{{event}}/{{time}}，缺省回退 formatBotText）。
func formatBotTextWithTemplate(tpl string, msg Message, ts time.Time) string {
	if strings.TrimSpace(tpl) == "" {
		return formatBotText(msg)
	}
	event := msg.EventType
	if event == "" {
		event = "notification"
	}
	pairs := []string{
		"{{title}}", msg.Title,
		"{{body}}", msg.Body,
		"{{level}}", msg.Level,
		"{{event}}", event,
		"{{event_title}}", eventDisplayTitle(msg.EventType),
		"{{node}}", msg.Node,
		"{{time}}", ts.Format("2006-01-02 15:04"),
		"{{brand}}", BrandName(),
	}
	// 日报变量（{{date}}/{{requests}}/{{nodes_summary}}/…）：值来自日报载荷
	// （deliverOne 注入 msg.Fields）。2026-11-22 用户裁定「模块选择与自定义
	// 模板二选一」——模板模式下令牌全量可放置，不再限定 7 个变量子集。
	// 非日报消息 Fields 无这些键不替换（事件模板不受影响）。
	if msg.EventType == EvtDailyReport {
		for _, k := range dailyFieldKeys(msg.Fields, botReservedPlaceholders) {
			pairs = append(pairs, "{{"+k+"}}", msg.Fields[k])
		}
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
}

// ChannelLinkStatus 通道实时连接态（qq/wx 常驻入站会话 per-bot 在线态；
// webhook/email 无长连=none）。target 钉住凭据优先，回退全局首 bot。
func ChannelLinkStatus(typ, targetJSON string) (bool, string) {
	switch typ {
	case "qq":
		botID := qqTargetBotID(targetJSON)
		if botID == "" {
			return false, "none"
		}
		c, _, _ := QQLinkStatusFor(botID)
		return c, linkStateWord(c)
	case "wx_clawbot":
		key := wxTargetBotKey(targetJSON)
		if key == "" {
			return false, "none"
		}
		c, _, _ := WxLinkStatusFor(key)
		return c, linkStateWord(c)
	}
	return false, "none"
}

func linkStateWord(connected bool) string {
	if connected {
		return "online"
	}
	return "offline"
}
