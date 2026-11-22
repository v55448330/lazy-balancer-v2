package handlers

// 通知中心 REST 的响应键单源（词条在 internal/i18n/catalog_manual.go 注册
// zh/en 成对；apimsg.Tf 调用点必须用键字面量——call-site 槽数对账钉测要求）。
// T(c, key) 的键同样字面量化；本文件只留 P/T 常量给 MessageKey 赋值共用。

// 日报/扫码绑定响应键（catalog_manual.go 注册）。
const (
	msgDailySendTimeInvalid  = "k_f9986707"
	msgDailyItemUnknown      = "k_d1a39d14"
	msgDailyTriggerForbidden = "k_4b8e3591"
	// 规则通道选择被就绪门清洗为空（非空选择全部失效）——400 固定文案。
	msgNotifyChannelSelectionUnavailable = "k_6287f2db"
	msgQQTaskCreateFailed                = "k_413b63ec"
	msgQQPollFailed                      = "k_27469cbd"
	msgWxQRStartFailed                   = "k_94d8f73b"
	msgWxQRPollFailed                    = "k_403c12fe"
)
