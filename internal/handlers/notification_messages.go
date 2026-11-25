package handlers

// 通知中心 REST 的响应键（词条在 internal/i18n/catalog_manual.go 登记 zh/en 成对）。
// apimsg.T/Tf 调用点必须用键字面量——call-site 槽数对账钉测按字面量取键；本文件的常量
// 只给 MessageKey 赋值共用。

// 日报配置校验、日报手动触发的管理员门、QQ 扫码绑定、微信扫码登录。
const (
	msgDailySendTimeInvalid  = "notify.dailySendTimeInvalid"
	msgDailyItemUnknown      = "notify.dailyItemUnknown"
	msgDailyTriggerForbidden = "notify.dailyTriggerForbidden"
	// 规则通道选择被就绪门清洗为空（非空选择全部失效）——400 固定文案。
	msgNotifyChannelSelectionUnavailable = "notify.selectedChannelsAllUnavailable"
	msgQQTaskCreateFailed                = "notify.qqBindTaskCreateFailed"
	msgQQPollFailed                      = "notify.qqBindPollFailed"
	msgWxQRStartFailed                   = "notify.wxLoginStartFailed"
	msgWxQRPollFailed                    = "notify.wxLoginPollFailed"
)
