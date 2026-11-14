package services

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 人机验证配置装配（阶段 3，2026-11-12）：
//   - 策略级：模式/方式/有效期/豁免（human_verify_* 列）
//   - CC 检测阈值：global_config（自动封禁同族），渲染期一次读取
//   - cookie 签名密钥：global_config.human_secret 惰性生成（32 字节 hex）

// CCConfig 自动封禁 CC 检测配置（global_config 同族）。CC「封禁」响应退役
// （2026-11-13）：CC 统一走挑战页，封禁由自动封禁管线承载。
type CCConfig struct {
	Enabled         bool `json:"enabled"`
	RPSLimit        int  `json:"rps_limit"`
	WindowSec       int  `json:"window_sec"`
	Ratio4xx        int  `json:"ratio_4xx"`
	SessionAnomaly  bool `json:"session_anomaly"`
	SessionUAThresh int  `json:"session_ua_threshold"`
}

// loadCCConfig CC 检测配置=策略合并（2026-11-12 用户裁定：阈值在策略配置，
// 自动封禁引用策略——全局不再持有阈值，消除双份配置）。取首个启用 CC 检测的
// 策略的阈值（多条启用策略时按绑定序首条；与 humanPolicyMerged 同优先级）。
func loadCCConfig(policies []*models.SecurityPolicy) CCConfig {
	cfg := CCConfig{RPSLimit: 40, WindowSec: 10, Ratio4xx: 70, SessionUAThresh: 5}
	for _, p := range policies {
		if p == nil || !p.CCDetectEnabled {
			continue
		}
		cfg.Enabled = true
		cfg.RPSLimit = p.CCRPSLimit
		cfg.WindowSec = p.CCRPSWindow
		cfg.Ratio4xx = p.CC4xxRatio
		cfg.SessionAnomaly = p.CCSessionAnomaly
		cfg.SessionUAThresh = p.CCSessionUAThreshold
		return cfg
	}
	return cfg
}

// humanSecret cookie 签名密钥（惰性生成+缓存；global_config.human_secret）。
var (
	humanSecretMu    sync.Mutex
	humanSecretCache string
)

// resetHumanSecretCache 集群 apply 写入新密钥后调用：强制下次渲染重新读取，
// 使从节点与主端共用同一 cookie 签名密钥。
func resetHumanSecretCache() {
	humanSecretMu.Lock()
	humanSecretCache = ""
	humanSecretMu.Unlock()
}

// getHumanSecret 读取/惰性生成 cookie 签名密钥。
func getHumanSecret() string {
	humanSecretMu.Lock()
	defer humanSecretMu.Unlock()
	if humanSecretCache != "" {
		return humanSecretCache
	}
	if db.DB == nil {
		return ""
	}
	var secret string
	if err := db.DB.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&secret); err != nil {
		return ""
	}
	if secret == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return ""
		}
		secret = hex.EncodeToString(raw)
		_, _ = db.DB.Exec(`UPDATE global_config SET human_secret=? WHERE id=1`, secret)
	}
	humanSecretCache = secret
	return secret
}

// humanTopPolicy 选取最高优先级的人机验证策略：force > auto（首个 force
// 优先；无 force 时首个 auto）。merged 配置与挑战页选取共用本判定——
// 绑定序在前的 auto 策略不得遮蔽 force 策略（页与 mode 分叉）。
// 无任何 force/auto 策略时返回 nil。
func humanTopPolicy(policies []*models.SecurityPolicy) *models.SecurityPolicy {
	var top *models.SecurityPolicy
	for _, p := range policies {
		if p == nil {
			continue
		}
		if p.HumanVerifyMode == "force" {
			if top == nil || top.HumanVerifyMode != "force" {
				top = p
			}
		} else if p.HumanVerifyMode == "auto" && top == nil {
			top = p
		}
	}
	return top
}

// humanPolicyMerged 合并策略人机验证配置：force > auto 优先级（任一 force 策略
// 即 force）；方式/有效期/豁免取最高优先级策略的值，豁免路径/IP 取并集。
func humanPolicyMerged(policies []*models.SecurityPolicy) (mode, typ string, ttl int, exemptPaths []string) {
	mode = "off"
	top := humanTopPolicy(policies)
	if top != nil {
		mode = top.HumanVerifyMode
	}
	if top == nil {
		return
	}
	typ = top.HumanVerifyType
	if typ == "" {
		typ = "slider"
	}
	ttl = top.HumanVerifyTTL
	if ttl <= 0 {
		ttl = 30
	}
	// 豁免面只保留路径前缀：IP 级放行唯一入口=阶段 0 信任名单（命中跳过整条
	// 安全链），单列一种"只跳挑战"的 IP 豁免面会与信任名单形成两套口径
	// （2026-11-12 用户裁定退役 human_exempt_ips）。
	pathSet := map[string]struct{}{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		var paths []string
		_ = json.Unmarshal(p.HumanExemptPaths, &paths)
		for _, v := range paths {
			if v != "" {
				pathSet[v] = struct{}{}
			}
		}
	}
	for v := range pathSet {
		exemptPaths = append(exemptPaths, v)
	}
	// map 迭代序不确定 → 渲染字节漂移会让 errSameConfig 同字节短路失效，
	// autoban 投影热路径回退全量重载；排序后同配置渲染恒同字节。
	sort.Strings(exemptPaths)
	return
}

// 内置人机验证页 id（2026-11-13 用户裁定：滑块/JS 各一页，命名统一）：
// 策略未显式配挑战页时，按验证方式选对应内置页——JS 用 JS 页，否则用滑块页。
const (
	builtinHumanVerifyPageID   = 9005 // 滑块人机验证页面
	builtinHumanJSVerifyPageID = 9006 // JS 人机验证页面
)

// humanChallengeEnabled 判断策略链是否启用人机挑战（force/auto 任一，CC 检测
// 开关不是门：始终验证同样需要拦截页）。
func humanChallengeEnabled(policies []*models.SecurityPolicy) bool {
	mode, _, _, _ := humanPolicyMerged(policies)
	return mode != "off"
}

// humanChallengeFallbackPage 返回人机挑战的默认内置页内容（按验证方式选页）；
// 非挑战或页面缺失时返回空（调用方回退 lbhuman 内置生成页）。
func humanChallengeFallbackPage(ctx *securityPolicyContext, policies []*models.SecurityPolicy) (string, string) {
	if ctx == nil || !humanChallengeEnabled(policies) {
		return "", ""
	}
	_, typ, _, _ := humanPolicyMerged(policies)
	pageID := builtinHumanVerifyPageID
	if typ == "js" {
		pageID = builtinHumanJSVerifyPageID
	}
	return ctx.blockPageByID[pageID], ctx.blockPageTypeByID[pageID]
}

// buildHumanHandler 阶段 3 人机验证 handler 渲染：有任一策略启用人机验证
// （mode != off）即注入；CC 检测阈值随配置下发（auto 模式插件内判定）。
// CC「封禁」响应退役（2026-11-13）：不再下发 cc_response/ban_*。challengePage
// 变参只消费首元素（挑战页 HTML）；后续元素（历史调用方携带的页内容类型）
// 有意忽略——挑战页响应恒 text/html 契约，内容类型不参与渲染。
func buildHumanHandler(ruleCaddyID string, policies []*models.SecurityPolicy, challengePage ...string) map[string]interface{} {
	mode, typ, ttl, exemptPaths := humanPolicyMerged(policies)
	if mode == "off" {
		return nil
	}
	secret := getHumanSecret()
	if secret == "" {
		Logf("warn", "人机验证：cookie 签名密钥不可用，规则 %s 跳过 lb_human 渲染（检查 global_config.human_secret）", ruleCaddyID)
		return nil
	}
	cc := loadCCConfig(policies)
	challengeHTML := ""
	if len(challengePage) > 0 {
		challengeHTML = challengePage[0]
	}
	return map[string]interface{}{
		"handler":             "lb_human",
		"mode":                mode,
		"type":                typ,
		"ttl":                 ttl,
		"secret":              secret,
		"cc_enabled":          cc.Enabled,
		"cc_rps_limit":        cc.RPSLimit,
		"cc_window_sec":       cc.WindowSec,
		"cc_4xx_ratio":        cc.Ratio4xx,
		"cc_session":          cc.SessionAnomaly,
		"cc_session_ua":       cc.SessionUAThresh,
		"challenge_page_html": challengeHTML,
		"exempt_paths":        exemptPaths,
		"rule_id":             ruleCaddyID,
	}
}
