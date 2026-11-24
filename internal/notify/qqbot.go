package notify

// QQ 官方机器人连接 Daemon（WebSocket 出站，免公网）：
//   AppID+Secret → getAppAccessToken → wss 事件网关（op:2 Identify/op:1 心跳/
//   op:6 Resume）→ C2C_MESSAGE_CREATE 处理「绑定测试」会话确认指令。
// 发消息走官方 REST（/v2/users/{openid}/messages，被动回复带 msg_id 免额度；
// 主动消息受官方额度频控——QQ 通道默认只订 critical）。
// access_token 经包级单例 qqTokens 按 appid 隔离缓存；入站会话 per-bot 维护
// （全局凭据+各通道钉住凭据枚举去重，各持独立 WS/在线态/日志），出站=通道
// target 钉住凭据，多机器人互不顶掉；过期自动刷新。
//
// 协议细节以 QQ 机器人开放平台文档为准（q.qq.com）；本文件为连接生命周期+
// 通道适配器，协议帧编解码在 qqbot_session.go。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// QQBotConfigured 全局凭据（AppID+Secret）已配置。
func QQBotConfigured() bool {
	appid, secret, ok := qqBotCredentials()
	return ok && appid != "" && secret != ""
}

// QQAnyBotConfigured 任一 bot 凭据可枚举（全局或通道钉住）——daemon Run 包装
// 门判据：pinned-only 形态（全局未配置、仅通道带凭据）入站亦可启动。
func QQAnyBotConfigured() bool {
	return len(qqEnumerateBots()) > 0
}

// qqBotCredentials 读全局凭据（notify_settings KV：notify.qq_appid/
// notify.qq_secret，单源 settings.go 键常量）。
func qqBotCredentials() (appid, secret string, ok bool) {
	kv := GetSettings(KeyQQAppID, KeyQQSecret)
	appid, secret = kv[KeyQQAppID], kv[KeyQQSecret]
	return appid, secret, appid != "" && secret != ""
}

// qqResolveCred 出站凭据解析：target 钉住凭据优先（多机器人各用所属 bot）；
// 缺失回退全局凭据（存量通道行为不变）。
func qqResolveCred(appid, secret string) (string, string) {
	if appid != "" && secret != "" {
		return appid, secret
	}
	gAppID, gSecret, _ := qqBotCredentials()
	return gAppID, gSecret
}

// qqBotCred 单个 bot 的凭据（入站会话鉴权源）。
type qqBotCred struct {
	AppID  string
	Secret string
}

// qqEnumerateBots 枚举 distinct bots：全局首 bot + 各通道钉住凭据，按 appid
// 去重（全局优先）。序=全局在前、通道按 id 升序（首元素=首 bot，无参在线态
// 兼容锚点）。缺凭据/坏 JSON 的 target 跳过。
func qqEnumerateBots() []qqBotCred {
	var bots []qqBotCred
	seen := map[string]bool{}
	add := func(appid, secret string) {
		if appid == "" || secret == "" || seen[appid] {
			return
		}
		seen[appid] = true
		bots = append(bots, qqBotCred{AppID: appid, Secret: secret})
	}
	if appid, secret, ok := qqBotCredentials(); ok {
		add(appid, secret)
	}
	if db.DB != nil {
		rows, err := db.DB.Query(`SELECT target FROM notification_channels WHERE type='qq' ORDER BY id`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var target string
				if rows.Scan(&target) != nil {
					continue
				}
				var cfg struct {
					AppID  string `json:"appid"`
					Secret string `json:"secret"`
				}
				if json.Unmarshal([]byte(target), &cfg) == nil {
					add(cfg.AppID, cfg.Secret)
				}
			}
		}
	}
	// 待绑定凭据：新 appid 一律追加（连接测试到确认前的提前建连死锁靠它破）；
	// 同名 appid 只在绑定会话 confirmed 后才覆盖——未确认就覆盖会让在线全局
	// bot 被重建会话（凭据变更→worker 回收重启），扫码期间入站断流。
	for _, p := range pendingBindQQCreds() {
		b := p.cred
		replaced := false
		for i := range bots {
			if bots[i].AppID == b.AppID {
				if p.confirmed {
					bots[i].Secret = b.Secret
				}
				replaced = true
				break
			}
		}
		if !replaced {
			bots = append(bots, b)
		}
	}
	return bots
}

// qqLinks per-bot 连接态登记表（通知中心页状态点数据源）。
var qqLinks botLinkRegistry

// QQLinkStatus 通道连接状态（REST 只读）=首 bot（全局凭据 bot，单 bot 时代
// 兼容口径）；多机器人按 bot 查询用 QQLinkStatusFor。
func QQLinkStatus() (bool, string, time.Time) {
	return qqLinks.status("")
}

// QQLinkStatusFor 查指定 bot（appid）入站会话在线态；空=首 bot；未登记 bot=离线。
func QQLinkStatusFor(botID string) (bool, string, time.Time) {
	return qqLinks.status(botID)
}

// qqTargetBotID 解析 target 所属 bot（钉住优先/全局回退后的 appid；空=首 bot）。
// Send/Test 闸门按 target 查对应 bot 的入站在线态（各 bot 会话独立）。
func qqTargetBotID(targetJSON string) string {
	var cfg struct {
		AppID  string `json:"appid"`
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal([]byte(targetJSON), &cfg)
	appid, _ := qqResolveCred(cfg.AppID, cfg.Secret)
	return appid
}

// qqSender QQ 通道适配器：发送/测试均走官方 REST（token 经单例复用）。
type qqSender struct{}

func (qqSender) Send(ctx context.Context, targetJSON string, msg Message) error {
	// 任务即服务（用户裁定）：出站发送闸门=统一任务引擎的真实运行态
	// （IsRunning 探针），停止常驻任务=无法处理发送，直接失败不静默滞留。
	// 链接态仅作未装配探针时的回退与 UI 展示，不作发送权威。
	connected, lastErr, _ := QQLinkStatusFor(qqTargetBotID(targetJSON))
	if !botServiceRunning("qq-bot-connection", connected) {
		if lastErr != "" {
			return fmt.Errorf("QQ 机器人服务未运行: %s", lastErr)
		}
		return errors.New("QQ 机器人服务未运行（连接任务已停止或凭据未配置）")
	}
	// 模板键经样式解析（含存量日报模板归一）：日报用 daily_content_template，
	// 事件用 content_template。
	style := ParseChannelStyle(targetJSON)
	contentTemplate := style.ContentTemplate
	if msg.EventType == EvtDailyReport {
		contentTemplate = style.DailyContentTemplate
	}
	text := renderBotMessage(contentTemplate, msg, time.Now(), "qq")
	// QQ 官方支持 markdown（msg_type=2）；缺省即 markdown 富文本，显式 text 才纯文本。
	if style.MsgType == "text" {
		return SendQQC2C(ctx, targetJSON, text)
	}
	return SendQQC2CMarkdown(ctx, targetJSON, text)
}

// Test 所属 bot 连接离线时返回明确错误（面板「测试」按钮的语义：连接不在位即不可发）。
func (qqSender) Test(ctx context.Context, targetJSON string) error {
	connected, lastErr, _ := QQLinkStatusFor(qqTargetBotID(targetJSON))
	if !botServiceRunning("qq-bot-connection", connected) {
		if lastErr != "" {
			return fmt.Errorf("QQ 机器人连接离线: %s", lastErr)
		}
		return errors.New("QQ 机器人连接离线（连接任务未运行或凭据未配置）")
	}
	return SendQQC2C(ctx, targetJSON, formatBotText(testNotificationMessageFor("QQ 机器人")))
}

// SendQQC2C 发 QQ 单聊文本（投递 Daemon 通道适配器调用）。
// ChannelTarget JSON 形如 {"openid":"...","appid":"...","secret":"..."}
// （appid/secret 为绑定/保存时钉住的 bot 凭据，缺省回退全局）；错误全部返回。
func SendQQC2C(ctx context.Context, targetJSON, text string) error {
	var cfg struct {
		OpenID string `json:"openid"`
		AppID  string `json:"appid"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil {
		return fmt.Errorf("QQ 通道目标解析失败: %w", err)
	}
	if cfg.OpenID == "" {
		return errors.New("QQ 通道目标缺少 openid（请先在 QQ 内发送绑定指令完成绑定）")
	}
	appid, secret := qqResolveCred(cfg.AppID, cfg.Secret)
	return sendQQRESTMessage(ctx, cfg.OpenID, text, appid, secret)
}

// SendQQC2CMarkdown 发 QQ 单聊 markdown 富文本（msg_type=2；机器人需具备
// markdown 权限，失败留痕）。target 凭据解析同 SendQQC2C。
func SendQQC2CMarkdown(ctx context.Context, targetJSON, md string) error {
	var cfg struct {
		OpenID string `json:"openid"`
		AppID  string `json:"appid"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil {
		return fmt.Errorf("QQ 通道目标解析失败: %w", err)
	}
	if cfg.OpenID == "" {
		return errors.New("QQ 通道目标缺少 openid（请先在 QQ 内发送绑定指令完成绑定）")
	}
	appid, secret := qqResolveCred(cfg.AppID, cfg.Secret)
	return sendQQRESTMarkdown(ctx, cfg.OpenID, md, appid, secret)
}

// qqWakeCh 凭据变更唤醒信号（SaveQQBotCredentials 落库后投递；非阻塞，
// 循环未运行时弃置——下轮启动自然读新凭据）。
var qqWakeCh = make(chan struct{}, 1)

// qqBotWorker 单 bot 入站会话句柄（supervisor 独占 cancel/done；reset=凭据
// 轮换信号，缓冲 1 非阻塞投递）。
type qqBotWorker struct {
	cred   qqBotCred
	cancel context.CancelFunc
	done   chan struct{}
	reset  chan struct{}
}

// RunQQBotConnection 连接 supervisor：枚举 distinct bots（全局+通道钉住），
// 每 bot 一个独立入站会话 goroutine（WaitGroup 同步收口，ctx 取消全停），
// per-bot 退避重连/Resume 续传/在线态/日志（bot=appid）。周期对账让新钉住
// 通道的 bot 上线；凭据变更（qqWakeCh）立即对账并重置各 bot 会话态重连，
// 不等退避。
func RunQQBotConnection(ctx context.Context) error { //scope-exempt: daemon-run-body-loop
	ctx = withTaskID(ctx, "qq-bot-connection")
	// 清洁停止必须置离线：否则 per-bot 态残留 connected=true，Send/Test 门被
	// 污染成假在线（停止后仍放行的实测根因）。任何退出路径统一收尾。
	defer qqLinks.stopAll("连接任务已停止")
	bots := qqEnumerateBots()
	// 0 bot 不退出：常驻等待绑定/保存新增凭据（wake/周期对账上线）。早退会使
	// 首绑 bot 无 supervisor 对账→连接测试永卡（用户实测 QQ 客户端卡连接中根因）。
	var wg sync.WaitGroup
	defer wg.Wait() // Run 同步等待全部 bot 会话 goroutine 收口（引擎形态②子协程）
	workers := map[string]*qqBotWorker{}
	reconcile := func() {
		bots := qqEnumerateBots()
		desired := map[string]qqBotCred{}
		for _, b := range bots {
			desired[b.AppID] = b
		}
		// 回收：不再枚举到的 bot / 凭据变更（取消+等待收口+注销登记）。
		for id, w := range workers {
			b, ok := desired[id]
			if ok && b == w.cred {
				continue
			}
			w.cancel()
			<-w.done
			qqLinks.unregister(id)
			delete(workers, id)
			if ok {
				taskLogf(ctx, "connect", "QQ 机器人凭据更新（bot=%s），重建入站会话", id)
			} else {
				taskLogf(ctx, "connect", "QQ 机器人移除（bot=%s），关闭入站会话", id)
			}
		}
		// 新增 bot：独立会话 goroutine（各自鉴权/心跳/重连，互不干扰）。
		for _, b := range bots {
			if _, ok := workers[b.AppID]; ok {
				continue
			}
			wctx, cancel := context.WithCancel(ctx)
			w := &qqBotWorker{cred: b, cancel: cancel, done: make(chan struct{}), reset: make(chan struct{}, 1)}
			workers[b.AppID] = w
			link := qqLinks.register(b.AppID)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer close(w.done)
				qqBotWorkerRun(wctx, b, link, w.reset)
			}()
			taskLogf(ctx, "connect", "QQ 机器人入站会话启动（bot=%s，开始鉴权建连）", b.AppID)
		}
		if len(bots) > 0 {
			qqLinks.setFirst(bots[0].AppID)
		}
	}
	reconcile()
	ids := make([]string, 0, len(bots))
	for _, b := range bots {
		ids = append(ids, b.AppID)
	}
	taskLogf(ctx, "connect", "QQ 机器人连接任务启动（%d 个 bot：%s）", len(bots), strings.Join(ids, ", "))
	for {
		select {
		case <-ctx.Done():
			for _, w := range workers {
				w.cancel()
			}
			return nil
		case <-qqWakeCh:
			// 凭据已落库：立即对账（增删/重建变更 bot）并重置各 bot 会话态，
			// 不等退避周期。
			reconcile()
			for _, w := range workers {
				select {
				case w.reset <- struct{}{}:
				default:
				}
			}
			taskLogf(ctx, "connect", "QQ 凭据变更，已对账 bot 会话并重置会话态立即重连")
		case <-time.After(botReconcileInterval):
			reconcile()
		}
	}
}

// qqBotWorkerRun 单 bot 入站会话循环：鉴权→ws→收发→断线退避重连。
// Resume 断线续传：会话态（sessionID/seq）per-bot 跨重连持有，服务端请求重连
// （op:7）或闪断时优先 Resume 补拉遗漏事件；会话失效（op:9）回退重新
// Identify。长时间在线后重连退避计数归零（长期运行不受历史断连拖累）。
// reset 信号（凭据轮换）作废会话态立即重连，不等退避。
// pendingQQSecretFor 返回活跃绑定会话携带的同 appid 新 secret（未确认也可用）。
func pendingQQSecretFor(appid string) (string, bool) {
	bindSessionMu.Lock()
	defer bindSessionMu.Unlock()
	for _, s := range bindSessions {
		if s.Type == "qq" && s.BotKey == appid && s.BotSecret != "" {
			return s.BotSecret, true
		}
	}
	return "", false
}

// qqCredentialFallback 旧 secret 鉴权失效时切到同 appid 的待绑定新 secret。
// 只在 100016/invalid appid or secret 时触发，不改变未失效在线 bot 的凭据。
func qqCredentialFallback(cred qqBotCred, err error) (qqBotCred, bool) {
	if err == nil {
		return cred, false
	}
	msg := err.Error()
	if !strings.Contains(msg, "invalid appid or secret") && !strings.Contains(msg, "100016") {
		return cred, false
	}
	secret, ok := pendingQQSecretFor(cred.AppID)
	if !ok || secret == "" || secret == cred.Secret {
		return cred, false
	}
	qqTokens.invalidateAppID(cred.AppID)
	cred.Secret = secret
	return cred, true
}

func qqBotWorkerRun(ctx context.Context, cred qqBotCred, link *botLinkState, reset <-chan struct{}) {
	// 退出不置离线：计划内回收（凭据轮换/删通道）由 supervisor unregister 收口，
	// 不产生在线→离线沿（防虚假掉线告警）；清洁停止由 stopAll 统一置离线。
	resume := &qqResumeState{}
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}
		started := time.Now()
		err := qqBotSession(ctx, cred, link, resume)
		if ctx.Err() != nil {
			return
		}
		// 重绑同 appid：旧 secret 可能已被官方轮换失效；待绑定会话里的新
		// secret 未确认也要用于连接测试，否则「连接测试→发绑定测试→确认」
		// 与「确认才切新 secret」互为死锁（QQ 客户端卡连接中）。
		if next, ok := qqCredentialFallback(cred, err); ok {
			cred = next
			resume.reset()
			attempt = 0
			link.set(false, fmt.Sprintf("bot=%s 旧凭据失效，切换待绑定凭据重连", cred.AppID))
			taskLogf(ctx, "connect", "QQ 旧凭据鉴权失效（bot=%s），切换本次扫码的待绑定凭据立即重连", cred.AppID)
			continue
		}
		link.set(false, fmt.Sprintf("bot=%s 连接断开: %v", cred.AppID, err))
		if time.Since(started) > 5*time.Minute {
			attempt = 0
		}
		attempt++
		taskLogWarn(ctx, "connect", "QQ 机器人连接断开（bot=%s 第 %d 次，%v 后重连）: %v", cred.AppID, attempt, botBackoff(attempt), err)
		select {
		case <-ctx.Done():
			return
		case <-reset:
			// 凭据已轮换：旧会话态作废，立即以新凭据重新 Identify。
			resume.reset()
			attempt = 0
			taskLogf(ctx, "connect", "QQ 凭据已轮换（bot=%s），重置会话态立即重连", cred.AppID)
		case <-time.After(botBackoff(attempt)):
		}
	}
}

func init() { RegisterSender("qq", qqSender{}) }
