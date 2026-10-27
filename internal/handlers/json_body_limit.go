package handlers

import (
	"fmt"
	"net/http"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// configuredRequestBodyBytes 读取全局配置 request_body_max_size_mb 作为请求体
// 上限（2026-09-19 用户裁定「统一遵循请求体大小配置项
// 限制」）。读侧：0/缺列/读失败/越界均回退 128MB；写侧：值型 1-1024，0 被
// 400 拒绝（见 handlers/caddy.go UpdateConfig 校验与 db_truth_write_gate_test）。
// 两侧口径不同——0 不是合法的「默认 128」写值，回退只发生在读侧。
func configuredRequestBodyBytes() int64 {
	mb := globalConfigInt("request_body_max_size_mb", 128)
	if mb < 1 || mb > maxRequestBodySizeMB {
		// 带外改库/旧备份越界值：回退默认必须留痕（读失败已有
		// LogConfigReadFailure；此前越界静默回退——所有受本上限约束的端点悄悄
		// 变成 128MB 且零信号，与「库值唯一真相/fail-visible」取向相悖）。
		// 按状态转换去重（面板轮询不刷屏），值恢复合法即补「已恢复」。
		services.LogConfigReadFailure("request-body-max-size-out-of-range",
			fmt.Errorf("request_body_max_size_mb=%d 越界（合法 1-%d），按 128MB 继续", mb, maxRequestBodySizeMB))
		mb = 128
	} else {
		services.LogConfigReadRecovered("request-body-max-size-out-of-range")
	}
	return mb * 1024 * 1024
}

// guardConfiguredJSONBody 与 guardAuthJSONBody 同构：ContentLength 预检 413 +
// MaxBytesReader 包装（chunked/未知长度读中途掐断走 binding 400 分支）。
// 上限取「请求体大小」配置项，供未设独立上限的写/读探测端点统一使用；
// 返回 false 时调用方立即 return。
func guardConfiguredJSONBody(c *gin.Context) bool {
	limit := configuredRequestBodyBytes()
	if c.Request.ContentLength > limit {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
	return true
}
