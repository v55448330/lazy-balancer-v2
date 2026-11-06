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
// 注入点：handlers.SyncDefaultLandingText（boot + GetBranding 幂等同步）
// 与 services.MaterializeBranding（备份导入/从端 applySnapshot/自愈三入口
// 的落盘单源，与 landing 成对注入）——两处同口径幂等；渲染期零磁盘 IO
// （内存快照）；文案在渲染期烘焙进 Caddy 配置，请求路径仅一次 write。
//
// 字符约束：剥离控制字符（C0+DEL+C1 区 U+0080-009F 与行/段分隔符
// U+2028/U+2029；含 CRLF——写入期由 handler 统一追加 \r\n），
// 256 字节 rune 边界钳制（防截断半个 UTF-8 序列产生乱码）。

const (
	tcpBlockNoticeFallbackBrand = "Lazy Balancer v2"
	tcpBlockNoticeMaxBytes      = 256
	// tcpNoticeBrandDefault 与 handlers.defaultBranding.AppName 逐字锚定
	// （loadBrandingConfig 对空 app_name 的填充值）——handlers 反向 import
	// 成环无法复用，与 emptyBrandingTemplate 同款锚定纪律：handlers 侧
	// 默认值增减须双侧同步。该默认形态在 TCP 提示侧视为「未配置」。
	tcpNoticeBrandDefault = "Lazy Balancer"
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

// TCPBlockNoticeBrand 返回当前注入的品牌原始值（空=回退默认品牌）；
// 测试与诊断读数用。
func TCPBlockNoticeBrand() string {
	tcpBlockNoticeMu.RLock()
	defer tcpBlockNoticeMu.RUnlock()
	return tcpBlockNoticeBrandVal
}

// normalizeTCPNoticeBrand 与 handlers.SyncDefaultLandingText 同款归一口径：
// 空串或 handlers 默认品牌视为未配置→返回空串，渲染期回退裁定默认文案；
// 用户显式配置原样透传。两处注入面共用本单源语义（handlers 侧经
// loadBrandingConfig 已把空值填充为 tcpNoticeBrandDefault，归一结果一致）。
func normalizeTCPNoticeBrand(name string) string {
	if name == "" || name == tcpNoticeBrandDefault {
		return ""
	}
	return name
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
// 口径=C0 区 + DEL + C1 区（U+0080-009F，含 NEL/CSI 等 8 位控制兼容形态）+
// Unicode 行/段分隔符（U+2028/U+2029——日志/终端按行切分语义，写入期只追
// 加一次 \r\n，文案内不得再夹带行界）。与 caddyl4sec validateBlockNotice
// 同口径（独立模块不能 import services，两侧逐字同步，改动必须成对）。
func clampTCPNotice(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) || r == 0x2028 || r == 0x2029 {
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
