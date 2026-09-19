package handlers

import (
	"net/http"

	"lazy-balancer-v2/internal/models"

	"github.com/gin-gonic/gin"
)

// configuredRequestBodyBytes 读取全局配置 request_body_max_size_mb 作为请求体
// 上限（APIMCP41-2，第 41 轮审计，2026-09-19 用户裁定「统一遵循请求体大小配置项
// 限制」）。0/缺列/读失败/越界均回退 128MB（与配置项写侧 0=默认 128、0-4096
// 边界同口径，见 handlers/caddy.go UpdateConfig 校验）。
func configuredRequestBodyBytes() int64 {
	mb := globalConfigInt("request_body_max_size_mb", 128)
	if mb < 1 || mb > 4096 {
		mb = 128
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
