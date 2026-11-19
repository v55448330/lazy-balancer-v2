package notify

// QQ 扫码绑定凭据的落库/读取（notify_settings 单源：notify.qq_appid /
// notify.qq_secret ——入站连接 Daemon 鉴权单源=首个 bot）。多机器人出站
// 凭据经通道 target 钉住（各用所属 bot），全局仅首 bot、后续绑定不覆盖。
// 通知通道 target 的 openid 绑定由 bindBotChannel 侧维护（channels 表）。

import (
	"lazy-balancer-v2/internal/db"
)

// SaveQQBotCredentials 凭据无条件落库（供 qq-bot-connection Daemon 鉴权）。
// 落库即作废 token 缓存并唤醒连接循环——旧 token/旧会话态立即失效重鉴权，
// 不等退避周期。绑定流程经 SaveQQBotCredentialsIfAbsent 调用（仅全局未配
// 置时写入，防多机器人互覆）；本函数保留无条件形态供凭据管理侧重置使用。
func SaveQQBotCredentials(appID, appSecret string) error {
	// 经 SetSettings 统一入口：qq_secret 静态加密落库（qq_appid 标识符明文）。
	if err := SetSettings(map[string]string{KeyQQAppID: appID, KeyQQSecret: appSecret}); err != nil {
		return err
	}
	qqTokens.invalidate()
	select {
	case qqWakeCh <- struct{}{}:
	default:
	}
	return nil
}

// SaveQQBotCredentialsIfAbsent 仅全局未配置时落库（多机器人根因修复）：
// 首个 bot 凭据供入站 WS 鉴权；后续绑定不覆盖全局——否则连接 Daemon 用
// 新凭据重连致老 bot 掉线。后续 bot 凭据经通道 target 钉住（保存通道时）。
// 返回 written=本次是否实际写入全局。
func SaveQQBotCredentialsIfAbsent(appID, appSecret string) (written bool, err error) {
	if _, _, ok := QQBotCredentialsPair(); ok {
		return false, nil
	}
	if err := SaveQQBotCredentials(appID, appSecret); err != nil {
		return false, err
	}
	return true, nil
}

// QQBotCredentialsPair 读取绑定下发的凭据（空=未绑定/未配置）。
func QQBotCredentialsPair() (appID, appSecret string, ok bool) {
	// 经 GetSettings 统一入口：qq_secret 解密读取（遗留明文透传）。
	kv := GetSettings(KeyQQAppID, KeyQQSecret)
	appID, appSecret = kv[KeyQQAppID], kv[KeyQQSecret]
	return appID, appSecret, appID != "" && appSecret != ""
}

// ClearQQBotCredentials 删除凭据（解绑/重置）。
func ClearQQBotCredentials() error {
	_, err := db.DB.Exec(`DELETE FROM notify_settings WHERE key IN ('notify.qq_appid','notify.qq_secret')`)
	return err
}
