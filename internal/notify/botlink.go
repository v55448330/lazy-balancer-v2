package notify

// bot 连接器骨架（QQ/微信共用）：鉴权/心跳/重连状态机单源，协议编解码由
// 两个连接器分实现。形态=出站长连（免公网）：Daemon Run 内循环——配置缺失
// 即退出（EnabledFn 同口径）；断线指数退避重连；收到 C2C/私聊「绑定 XXX」
// 指令 → openid/wxid↔user 绑定；通道掉线触发 notify_channel_down 告警
// （走其它还活着的通道，自监控闭环）。

import (
	"errors"
	"sync"
	"time"
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
	s.connected = connected
	s.lastChange = time.Now()
	s.lastErr = err
	s.mu.Unlock()
	if !connected {
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
