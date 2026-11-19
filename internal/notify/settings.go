package notify

// 通知中心管理设置 KV 存取（notify_settings 表：key/value；键清单见键常量）。
// 写入入口=handlers 通知设置端点（管理员）；读取方=本包连接器/聚合器与
// handlers 设置聚合。

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"lazy-balancer-v2/internal/db"
)

// 设置键（notify_settings.key）。secret 类值仅落库，REST 响应只回「已配置」布尔。
const (
	KeySMTPHost         = "notify.smtp_host"
	KeySMTPPort         = "notify.smtp_port"
	KeySMTPUser         = "notify.smtp_user"
	KeySMTPPass         = "notify.smtp_pass"
	KeySMTPFrom         = "notify.smtp_from"
	KeySMTPTLS          = "notify.smtp_tls"      // TLS 启用（缺省启用；"0"=明文 SMTP）
	KeySMTPInsecure     = "notify.smtp_insecure" // 忽略证书校验（"1"=跳过，自签证书场景）
	KeyQQAppID          = "notify.qq_appid"
	KeyQQSecret         = "notify.qq_secret"
	KeyMCPEnabled       = "notify.mcp_enabled"
	KeyAPIEnabled       = "notify.api_enabled" // REST API 密钥接入全局开关（与 MCP 对称；缺省启用）
	KeyAttackWarnAt     = "notify.attack_warn_at"
	KeyAttackCriticalAt = "notify.attack_critical_at"
	KeyWxBotCred        = "notify.wx_bot_cred" // 微信扫码登录态（连接器域写入）
	// SMTP OAuth2（XOAUTH2，Outlook/Office365 设备码流；公共客户端无 secret）
	KeySMTPOAuthTenant       = "notify.smtp_oauth_tenant"
	KeySMTPOAuthClientID     = "notify.smtp_oauth_client_id"
	KeySMTPOAuthRefreshToken = "notify.smtp_oauth_refresh_token" // 敏感（静态加密）
	KeySMTPOAuthScope        = "notify.smtp_oauth_scope"
)

// GetSetting 取单键值（未配置/库不可用返回空串）。
func GetSetting(key string) string {
	if db.DB == nil {
		return ""
	}
	var v string
	if err := db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, key).Scan(&v); err != nil {
		return ""
	}
	return openSecretSetting(key, v)
}

// openSecretSetting 敏感键解密（遗留明文透传）；解密失败留痕并返回空串
// （视为未配置，不崩溃；fail-loud 经 WARN 日志 + 发送侧认证失败暴露）。
func openSecretSetting(key, stored string) string {
	if !isSecretSettingKey(key) {
		return stored
	}
	plain, err := OpenSecret(stored)
	if err != nil {
		log.Printf("WARN: notify 凭据 %s 解密失败（视为未配置）: %v", key, err)
		return ""
	}
	return plain
}

// GetSettings 批量取键值（返回存在的键；库不可用返回空映射）。
func GetSettings(keys ...string) map[string]string {
	out := map[string]string{}
	if db.DB == nil || len(keys) == 0 {
		return out
	}
	rows, err := db.DB.Query(`SELECT key, value FROM notify_settings WHERE key IN (`+placeholders(len(keys))+`)`, toArgs(keys)...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		out[k] = openSecretSetting(k, v)
	}
	return out
}

// SetSettings 批量写入（事务 UPSERT；空串=清除配置）。
func SetSettings(kv map[string]string) error {
	if db.DB == nil {
		return errors.New("数据库不可用")
	}
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range kv {
		if isSecretSettingKey(k) {
			sealed, err := SealSecret(v)
			if err != nil {
				return fmt.Errorf("凭据 %s 加密失败: %w", k, err)
			}
			v = sealed
		}
		if _, err := tx.Exec(`INSERT INTO notify_settings (key, value) VALUES (?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func placeholders(n int) string {
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('?')
	}
	return b.String()
}

func toArgs(keys []string) []any {
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

// MCPEnabled MCP 推送通道全局开关（notify.mcp_enabled，'1'=开）。
func MCPEnabled() bool { return GetSetting(KeyMCPEnabled) == "1" }

// APIEnabled REST API 密钥接入全局开关（notify.api_enabled，'1'=开；
// 缺行/读失败按启用——与 MCPEnabled 同语义，停用只影响 API Key 认证的
// REST 请求，JWT 面板会话不受影响）。
func APIEnabled() bool {
	v := GetSetting(KeyAPIEnabled)
	return v == "" || v == "1"
}

// BlockedThresholds 拦截聚合升级阈值（滚动窗口累计 ≥warn→warn、
// ≥critical→critical）。设置缺省/非法（非正数或 critical≤warn）回落内置
// 默认——阈值失效不得让告警静默消失或全部升级。
func BlockedThresholds() (warnAt, criticalAt int) {
	warnAt, criticalAt = blockedWarnAt, blockedCriticalAt
	m := GetSettings(KeyAttackWarnAt, KeyAttackCriticalAt)
	if w, err := strconv.Atoi(m[KeyAttackWarnAt]); err == nil && w > 0 {
		warnAt = w
	}
	if c, err := strconv.Atoi(m[KeyAttackCriticalAt]); err == nil && c > 0 {
		criticalAt = c
	}
	if criticalAt <= warnAt {
		return blockedWarnAt, blockedCriticalAt
	}
	return warnAt, criticalAt
}
