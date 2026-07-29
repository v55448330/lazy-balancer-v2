package middleware

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

func clusterVersionMiddleware(database *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isSynchronizedWrite(c.Request.Method, c.FullPath()) {
			c.Next()
			return
		}
		originalWriter := c.Writer
		bufferedWriter := &clusterVersionResponseWriter{ResponseWriter: originalWriter}
		c.Writer = bufferedWriter
		c.Next()
		if bufferedWriter.Status() >= http.StatusBadRequest {
			bufferedWriter.flush(c, originalWriter)
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 2*time.Second)
		defer cancel()
		var isMaster bool
		if err := database.QueryRowContext(ctx, "SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
			writeClusterVersionError(c, originalWriter, err)
			return
		}
		if !isMaster {
			bufferedWriter.flush(c, originalWriter)
			return
		}
		if err := services.BumpClusterVersion(ctx, database); err != nil {
			writeClusterVersionError(c, originalWriter, err)
			return
		}
		bufferedWriter.flush(c, originalWriter)
	}
}

type clusterVersionResponseWriter struct {
	gin.ResponseWriter
	body   bytes.Buffer
	status int
}

func (w *clusterVersionResponseWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}

func (w *clusterVersionResponseWriter) WriteHeaderNow() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
}

func (w *clusterVersionResponseWriter) Write(data []byte) (int, error) {
	w.WriteHeaderNow()
	return w.body.Write(data)
}

func (w *clusterVersionResponseWriter) WriteString(data string) (int, error) {
	w.WriteHeaderNow()
	return w.body.WriteString(data)
}

func (w *clusterVersionResponseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *clusterVersionResponseWriter) Size() int     { return w.body.Len() }
func (w *clusterVersionResponseWriter) Written() bool { return w.status != 0 }
func (w *clusterVersionResponseWriter) Flush()        { w.WriteHeaderNow() }

func (w *clusterVersionResponseWriter) flush(c *gin.Context, original gin.ResponseWriter) {
	c.Writer = original
	original.WriteHeader(w.Status())
	if w.body.Len() == 0 {
		return
	}
	if _, err := original.Write(w.body.Bytes()); err != nil {
		_ = c.Error(err)
	}
}

func writeClusterVersionError(c *gin.Context, original gin.ResponseWriter, err error) {
	c.Writer = original
	original.Header().Del("Content-Length")
	c.Error(err)
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "cluster version update failed"})
}

func isSynchronizedWrite(method, path string) bool {
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return false
	}
	if method == http.MethodPut && (path == "/api/v1/config" || path == "/api/v1/caddy/config") {
		return true
	}
	if path == "/api/v1/rules/cert-info" {
		return false
	}
	for _, prefix := range []string{"/api/v1/rules", "/api/v1/users", "/api/v1/api-keys"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
