package notify

// wx 会话上下文持久化回归（复用 notify_settings KV，无新表）：内存清空后经
// KV 恢复（扛重启）；per-bot per-receiver 隔离（多通道共存）；值静态加密落库；
// WxSessionReady 据此判定可主动发送。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func clearWxContextMemory() {
	wxCtxMu.Lock()
	wxContextTokens = map[string]map[string]string{}
	wxCtxMu.Unlock()
}

func TestWxContextTokenPersistenceAndIsolation(t *testing.T) {
	newNotifyConnectorDB(t)
	t.Cleanup(clearWxContextMemory)

	// Given 两 bot 各自接收者的会话上下文
	cacheWxContextToken("BOT_A", "user1", "ctx-A1")
	cacheWxContextToken("BOT_B", "user1", "ctx-B1")
	if wxContextTokenFor("BOT_A", "user1") != "ctx-A1" {
		t.Fatalf("内存命中失败")
	}
	// 密文落库（复用 KV + 静态加密）
	var stored string
	_ = db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, wxContextKey("BOT_A", "user1")).Scan(&stored)
	if !strings.HasPrefix(stored, "enc:v1:") || strings.Contains(stored, "ctx-A1") {
		t.Errorf("会话上下文应密文落库, got %q", stored)
	}

	// When 清空内存（模拟面板重启）
	clearWxContextMemory()
	// Then 经 KV 恢复，且 per-bot 隔离
	if got := wxContextTokenFor("BOT_A", "user1"); got != "ctx-A1" {
		t.Errorf("重启后 BOT_A/user1 应恢复 ctx-A1, got %q", got)
	}
	if got := wxContextTokenFor("BOT_B", "user1"); got != "ctx-B1" {
		t.Errorf("多通道隔离：BOT_B/user1 应 ctx-B1, got %q", got)
	}
	if got := wxContextTokenFor("BOT_A", "user2"); got != "" {
		t.Errorf("未缓存接收者应空, got %q", got)
	}

	// WxSessionReady：就绪/未就绪
	readyTarget := `{"receiver":"user1","account_id":"BOT_A","token":"T_A"}`
	if !WxSessionReady(readyTarget) {
		t.Errorf("有会话上下文的接收者应就绪")
	}
	if WxSessionReady(`{"receiver":"user2","account_id":"BOT_A","token":"T_A"}`) {
		t.Errorf("无会话上下文的接收者应未就绪")
	}
	if WxSessionReady(`{"account_id":"BOT_A","token":"T_A"}`) {
		t.Errorf("缺 receiver 应未就绪")
	}
}

func TestPruneWxContextTokens(t *testing.T) {
	newNotifyConnectorDB(t)
	t.Cleanup(clearWxContextMemory)
	cacheWxContextToken("BOT_A", "u1", "ctx-fresh")
	if err := SetSettings(map[string]string{wxContextKey("BOT_B", "u2"): "legacy-no-ts"}); err != nil {
		t.Fatalf("播种遗留值: %v", err)
	}
	clearWxContextMemory()
	n, err := PruneWxContextTokens(time.Hour)
	if err != nil {
		t.Fatalf("PruneWxContextTokens: %v", err)
	}
	if n != 1 {
		t.Errorf("应清理 1 条遗留上下文, got %d", n)
	}
	if wxContextTokenFor("BOT_A", "u1") != "ctx-fresh" {
		t.Errorf("新鲜上下文应保留")
	}
	if wxContextTokenFor("BOT_B", "u2") != "" {
		t.Errorf("遗留上下文应被清理")
	}
}
