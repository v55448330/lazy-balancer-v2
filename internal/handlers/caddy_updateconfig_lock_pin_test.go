package handlers

// 基线钉：审计判定「UpdateConfig 是配置/
// 规则/安全写族中唯一不持 caddyOpMu 的 Caddy 写者」——亲验不成立：
// UpdateConfig 在请求体校验后、全部业务逻辑前即取锁（函数体内
// `h.caddyOpMu.Lock()` + `defer h.caddyOpMu.Unlock()`，defer 覆盖函数全程）。
// 本钉测试以 caddy_test.go 生命周期探针同款模式锁行为：预持 caddyOpMu 期间
// UpdateConfig 必须阻塞，释放后完成——证明取锁在位。
// 基线钉测试（钉既有正确行为），按豁免 RED，判定变更披露见修复报告。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type updateConfigSignalingBody struct {
	io.Reader
	once    sync.Once
	entered chan struct{}
}

func (body *updateConfigSignalingBody) Read(p []byte) (int, error) {
	body.once.Do(func() { close(body.entered) })
	return body.Reader.Read(p)
}

func (body *updateConfigSignalingBody) Close() error { return nil }

// Given caddyOpMu 被预持（模拟并发的规则/安全写临界区）。
// When UpdateConfig 处理请求（生产方法=PUT）。
// Then 必须阻塞至锁释放（取锁点=请求校验后函数顶部），释放后完成并 200。
func TestUpdateConfig_holds_rule_operation_lock(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)

	h.caddyOpMu.Lock()
	done := make(chan int, 1)
	entered := make(chan struct{})
	go func() {
		response := httptest.NewRecorder()
		body := &updateConfigSignalingBody{Reader: strings.NewReader(`{"timezone":"Asia/Shanghai"}`), entered: entered}
		request := httptest.NewRequest(http.MethodPut, "/config", body)
		router.ServeHTTP(response, request)
		done <- response.Code
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		h.caddyOpMu.Unlock()
		t.Fatal("请求未进入 body 读取阶段——正向屏障失效")
	}
	select {
	case code := <-done:
		h.caddyOpMu.Unlock()
		t.Fatalf("UpdateConfig 在 caddyOpMu 被预持期间完成（status=%d）——写路径未持锁", code)
	case <-time.After(300 * time.Millisecond):
	}
	h.caddyOpMu.Unlock()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("锁释放后 UpdateConfig status=%d, want 200", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("锁释放后 UpdateConfig 10s 内未完成")
	}
}
