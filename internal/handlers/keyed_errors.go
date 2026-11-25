package handlers

// 键化的错误装配器：把「固定文案 + 服务端留痕」的既有装配点（internalError / serverErrMsg /
// clusterError / failAutoBackupAccess）迁到「稳定键 + 中文母本 + 模板参数」，日志与审计口径
// 逐字保留——迁移不得以丢失留痕为代价。
//
// 5xx 固定文案不随请求语言变化（与 internalError 同口径）：message 取键的中文母本，前端据
// message_key + message_params 按界面语言渲染。参数经变参传入，实参只求值一次。

import (
	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/i18n"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// internalErrorKeyed 是 internalError 的键化形态：tag 非空时日志带域标签；cause 非空才写日志
// （err==nil 表示调用方已就地留痕，不重复写）。
func internalErrorKeyed(tag string, status int, key string, cause error, args ...any) models.APIResponse {
	if cause != nil {
		message := i18n.T(i18n.ZH, key)
		if tag != "" {
			services.Logf("error", "%s: %s: %v", tag, message, cause)
		} else {
			services.Logf("error", "%s: %v", message, cause)
		}
	}
	return apimsg.Envelope(nil, status, key, args...)
}

// securityErrKeyed 是 serverErrMsg 的键化形态（域标签「安全处理器」，与 internalError 同源）。
func securityErrKeyed(status int, key string, cause error, args ...any) models.APIResponse {
	return internalErrorKeyed("安全处理器", status, key, cause, args...)
}

// clusterErrorKeyedResponse 是 clusterError 的键化形态：日志口径保持
// "cluster request failed: <err>"（只有 cause 非空才写）。
func clusterErrorKeyedResponse(status int, key string, cause error, args ...any) models.APIResponse {
	if cause != nil {
		services.Logf("error", "cluster request failed: %v", cause)
	}
	return apimsg.Envelope(nil, status, key, args...)
}

// failAutoBackupAccessKeyed 是 failAutoBackupAccess 的键化形态：审计明细（动作 + 对象 + 中文
// 母本）、日志级别与日志正文口径逐字保留。
func failAutoBackupAccessKeyed(c *gin.Context, verb, subject, key string, status int, cause error, args ...any) {
	auditAutoBackupAccessFailure(c, verb, subject, i18n.T(i18n.ZH, key), status, cause)
	c.JSON(status, apimsg.Envelope(nil, status, key, args...))
}
