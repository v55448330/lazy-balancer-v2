package services

import (
	"strings"
	"sync"
)

// TCP 拦截提示（2026-11-06 用户裁定）：无配置项，全部 L4 断连路由
// （deny/blacklist/allow/geoip）的 lb_l4_sec 载荷恒发射 block_notice，
// 断连前向客户端写入一行提示文本；透传形态（trust_detect/allow_sample）
// 不发射。文案 = "Connection blocked by " + branding app_name；品牌空/未
// 注入回退 "Lazy Balancer v2"。
//
// 注入点：handlers.SyncDefaultLandingText（boot + GetBranding 幂等同步，
// 与 SetDefaultLandingBody 同一注入面）——渲染期零磁盘 IO（内存快照）；
// 文案在渲染期烘焙进 Caddy 配置，请求路径仅一次 write。
//
// 字符约束：剥离控制字符（含 CRLF——写入期由 handler 统一追加 \r\n），
// 256 字节 rune 边界钳制（防截断半个 UTF-8 序列产生乱码）。

const (
	tcpBlockNoticeFallbackBrand = "Lazy Balancer v2"
	tcpBlockNoticeMaxBytes      = 256
)

var (
	tcpBlockNoticeMu       sync.RWMutex
	tcpBlockNoticeBrandVal string
)

// SetTCPBlockNoticeBrand 注入 branding.json 的 app_name（已加载内存快照值，
// 允许为空串=回退默认品牌）。与 SetDefaultLandingBody 同款进程内单源。
func SetTCPBlockNoticeBrand(name string) {
	tcpBlockNoticeMu.Lock()
	tcpBlockNoticeBrandVal = name
	tcpBlockNoticeMu.Unlock()
}

// tcpBlockNoticeText 返回当前生效文案（剥离控制字符 + 256 字节钳制后恒非空）。
func tcpBlockNoticeText() string {
	tcpBlockNoticeMu.RLock()
	brand := tcpBlockNoticeBrandVal
	tcpBlockNoticeMu.RUnlock()
	return buildTCPBlockNotice(brand)
}

// buildTCPBlockNotice 是文案单源纯函数（测试直测）。
func buildTCPBlockNotice(appName string) string {
	brand := strings.TrimSpace(appName)
	if brand == "" {
		brand = tcpBlockNoticeFallbackBrand
	}
	text := "Connection blocked by " + brand
	return clampTCPNotice(text)
}

// clampTCPNotice 剥离控制字符并按 rune 边界钳制到 tcpBlockNoticeMaxBytes。
func clampTCPNotice(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r < 0x20 || r == 0x7F {
			continue
		}
		if b.Len()+len(string(r)) > tcpBlockNoticeMaxBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// applyTCPBlockNotice 把提示写入断连路由的 lb_l4_sec 载荷（l4SecCloseRoute
// 专用；透传路由不经此处）。文案为渲染期内存派生值，恒非空。
func applyTCPBlockNotice(handler map[string]interface{}) {
	if notice := tcpBlockNoticeText(); notice != "" {
		handler["block_notice"] = notice
	}
}
