package notify

// QQ 扫码绑定凭据的落库/读取（notify_settings 单源：notify.qq_appid /
// notify.qq_secret ——连接 Daemon 鉴权与投递发送共用）。
// 通知通道 target 的 openid 绑定由 bindBotChannel 侧维护（channels 表）。

import (
	"lazy-balancer-v2/internal/db"
)

// SaveQQBotCredentials 绑定完成后的凭据落库（供 qq-bot-connection Daemon 鉴权）。
// 落库即作废 token 缓存并唤醒连接循环——换绑场景旧 token/旧会话态立即
// 失效重鉴权，不等退避周期（实测：换绑后 Invalid Session 死循环根因修复）。
func SaveQQBotCredentials(appID, appSecret string) error {
	_, err := db.DB.Exec(`INSERT INTO notify_settings (key, value) VALUES ('notify.qq_appid', ?), ('notify.qq_secret', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, appID, appSecret)
	if err == nil {
		qqTokens.invalidate()
		select {
		case qqWakeCh <- struct{}{}:
		default:
		}
	}
	return err
}

// QQBotCredentialsPair 读取绑定下发的凭据（空=未绑定/未配置）。
func QQBotCredentialsPair() (appID, appSecret string, ok bool) {
	if db.DB == nil {
		return "", "", false
	}
	_ = db.DB.QueryRow(`SELECT COALESCE((SELECT value FROM notify_settings WHERE key='notify.qq_appid'),''),
		COALESCE((SELECT value FROM notify_settings WHERE key='notify.qq_secret'),'')`).Scan(&appID, &appSecret)
	return appID, appSecret, appID != "" && appSecret != ""
}

// ClearQQBotCredentials 删除凭据（解绑/重置）。
func ClearQQBotCredentials() error {
	_, err := db.DB.Exec(`DELETE FROM notify_settings WHERE key IN ('notify.qq_appid','notify.qq_secret')`)
	return err
}
