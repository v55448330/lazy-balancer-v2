package services

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 人机验证配置装配（阶段 3，2026-11-12）：
//   - 策略级：模式/方式/有效期/豁免（human_verify_* 列）
//   - CC 检测阈值：global_config（自动封禁同族），渲染期一次读取
//   - cookie 签名密钥：global_config.human_secret 惰性生成（32 字节 hex）

// CCConfig 自动封禁 CC 检测配置（global_config 同族）。
type CCConfig struct {
	Enabled         bool   `json:"enabled"`
	RPSLimit        int    `json:"rps_limit"`
	WindowSec       int    `json:"window_sec"`
	Ratio4xx        int    `json:"ratio_4xx"`
	SessionAnomaly  bool   `json:"session_anomaly"`
	SessionUAThresh int    `json:"session_ua_threshold"`
	Response        string `json:"response"` // verify | ban
}

// loadCCConfig CC 检测配置=策略合并（2026-11-12 用户裁定：阈值在策略配置，
// 自动封禁引用策略——全局不再持有阈值，消除双份配置）。取首个启用 CC 检测的
// 策略的阈值（多条启用策略时按绑定序首条；与 humanPolicyMerged 同优先级）。
func loadCCConfig(policies []*models.SecurityPolicy) CCConfig {
	cfg := CCConfig{RPSLimit: 40, WindowSec: 10, Ratio4xx: 70, SessionUAThresh: 5, Response: "verify"}
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
		if strings.EqualFold(strings.TrimSpace(p.CCResponse), "ban") {
			cfg.Response = "ban"
		} else {
			cfg.Response = "verify"
		}
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

// humanPolicyMerged 合并策略人机验证配置：force > auto 优先级（任一 force 策略
// 即 force）；方式/有效期/豁免取最高优先级策略的值，豁免路径/IP 取并集。
func humanPolicyMerged(policies []*models.SecurityPolicy) (mode, typ string, ttl int, exemptPaths []string) {
	mode = "off"
	var top *models.SecurityPolicy
	for _, p := range policies {
		if p == nil {
			continue
		}
		if p.HumanVerifyMode == "force" {
			if mode != "force" {
				top = p
			}
			mode = "force"
		} else if p.HumanVerifyMode == "auto" && mode == "off" {
			mode = "auto"
			top = p
		}
		if top == nil && p.HumanVerifyMode != "off" {
			top = p
		}
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
	return
}

// buildHumanHandler 阶段 3 人机验证 handler 渲染：有任一策略启用人机验证
// （mode != off）即注入；CC 检测阈值随配置下发（auto 模式插件内判定）。
func buildHumanHandler(ruleCaddyID string, policies []*models.SecurityPolicy, banPage ...string) map[string]interface{} {
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
	banStatus := 0
	for _, p := range policies {
		if p != nil && p.CCDetectEnabled && p.BlockStatusCode > 0 {
			banStatus = p.BlockStatusCode
			break
		}
	}
	banHTML, banType := "", ""
	challengeHTML := ""
	if len(banPage) > 0 {
		challengeHTML = banPage[0]
		banHTML = strings.ReplaceAll(banPage[0], "{{human_verify_widget}}", "")
	}
	if len(banPage) > 1 {
		banType = banPage[1]
	}
	return map[string]interface{}{
		"handler":             "lb_human",
		"mode":                mode,
		"type":                typ,
		"ttl":                 ttl,
		"secret":              getHumanSecret(),
		"cc_enabled":          cc.Enabled,
		"cc_rps_limit":        cc.RPSLimit,
		"cc_window_sec":       cc.WindowSec,
		"cc_4xx_ratio":        cc.Ratio4xx,
		"cc_session":          cc.SessionAnomaly,
		"cc_session_ua":       cc.SessionUAThresh,
		"cc_response":         cc.Response,
		"ban_status_code":     banStatus,
		"ban_page_html":       banHTML,
		"ban_page_type":       banType,
		"challenge_page_html": challengeHTML,
		"exempt_paths":        exemptPaths,
		"rule_id":             ruleCaddyID,
	}
}
