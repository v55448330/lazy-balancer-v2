// Package middleware — i18n 语言协商中间件与 handler 侧取用。
package middleware

import (
	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/i18n"
)

// i18nMiddleware 语言协商:Accept-Language → 上下文 + Content-Language 响应头。
func i18nMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		lang := i18n.Negotiate(c.GetHeader("Accept-Language"))
		c.Set(i18n.CtxLangKey, lang)
		c.Header("Content-Language", lang)
		c.Next()
	}
}

// Lang 取当前请求语言(默认 zh)。兼容薄封装,新代码建议直接 i18n.FromCtx。
func Lang(c *gin.Context) string { return i18n.FromCtx(c) }
