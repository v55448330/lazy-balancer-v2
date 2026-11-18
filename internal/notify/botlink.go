package notify

// bot 连接器骨架（QQ/微信共用）：鉴权/心跳/重连状态机单源，协议编解码由
// 两个连接器分实现。形态=出站长连（免公网）：Daemon Run 内循环——配置缺失
// 即退出（EnabledFn 同口径）；断线指数退避重连；收到 C2C/私聊「绑定 XXX」
// 指令 → openid/wxid↔user 绑定；通道掉线触发 notify_channel_down 告警
// （走其它还活着的通道，自监控闭环）。

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// botLinkState 连接状态（通知中心页状态点数据源）。
type botLinkState struct {
	mu         sync.Mutex
	connected  bool
	lastChange time.Time
	lastErr    string
}

func (s *botLinkState) set(connected bool, err string) {
	s.mu.Lock()
	// 仅「在线→离线」沿触发掉线告警：重连期间的逐次失败不再重复发布
	// （退避重连每分钟可产生多次事件，逐次发布会刷屏）。
	transition := s.connected && !connected
	s.connected = connected
	s.lastChange = time.Now()
	s.lastErr = err
	s.mu.Unlock()
	if transition {
		// 通道掉线自监控：经其它还活着的通道告警（Publish→delivery；
		// 若投递通道同样依赖本连接，sender 会返回离线错误并留痕，不会死循环阻塞）。
		Publish(Event{
			Type: EvtNotifyChannelDown, Level: LevelWarn,
			Title: "通知通道离线", Body: err,
		})
	}
}

// botBackoff 断线重连退避（1s→2s→…→60s 封顶）。
func botBackoff(attempt int) time.Duration {
	d := time.Second
	for i := 1; i < attempt && d < time.Minute; i++ {
		d *= 2
	}
	return d
}

var errBotNotConnected = errors.New("bot 连接未建立")

// bindBotChannel bot 连接器共用的绑定码落库：qq_bind_codes 校验有效期 →
// 通道 target（externalID 的 JSON 字面量）upsert 到 notification_channels →
// 消费绑定码 → 回执。typ/targetJSON 各连接器传入（qq={"openid":...}，
// wx_clawbot={"receiver":...}）。reply 的失败由调用方自行留痕。
func bindBotChannel(code, externalID, typ, name, targetJSON string, reply func(string)) {
	if code == "" || externalID == "" || db.DB == nil {
		return
	}
	var userID int64
	err := db.DB.QueryRow(`SELECT user_id FROM qq_bind_codes WHERE code=? AND expires_at>datetime('now')`, code).Scan(&userID)
	if err != nil {
		reply("绑定码无效或已过期，请在面板重新生成")
		return
	}
	var channelID int64
	err = db.DB.QueryRow(`SELECT id FROM notification_channels WHERE user_id=? AND type=? AND target=?`,
		userID, typ, targetJSON).Scan(&channelID)
	if err != nil {
		_, err = db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, enabled, created_at, updated_at)
			VALUES (?, ?, ?, ?, 1, datetime('now'), datetime('now'))`, userID, typ, name, targetJSON)
		if err != nil {
			reply("绑定失败：通道写入异常，请稍后重试")
			return
		}
	} else if _, err = db.DB.Exec(`UPDATE notification_channels SET enabled=1, updated_at=datetime('now') WHERE id=?`, channelID); err != nil {
		reply("绑定失败：通道更新异常，请稍后重试")
		return
	}
	_, _ = db.DB.Exec(`DELETE FROM qq_bind_codes WHERE code=?`, code)
	reply("绑定成功")
}

// quoteJSON 字符串转 JSON 字面量（绑定 target 组装用）。
func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// formatBotText 长连通道（QQ/微信）文本形态：标题+换行+正文（正文空则仅标题）。
func formatBotText(msg Message) string {
	if strings.TrimSpace(msg.Body) == "" {
		return msg.Title
	}
	return msg.Title + "\n" + msg.Body
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
	r := strings.NewReplacer(
		"{{title}}", msg.Title,
		"{{body}}", msg.Body,
		"{{level}}", msg.Level,
		"{{event}}", event,
		"{{time}}", ts.Format("2006-01-02 15:04"),
	)
	return r.Replace(tpl)
}
