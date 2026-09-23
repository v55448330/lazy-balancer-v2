package caddygeoip

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"lazy-balancer-v2/wafiplist"
)

// @ipListFast 经 caddygeoip 链接锚点注册后，在本模块（Caddy 插件编译单元）
// 内可被 coraza 编译并真实拦截——端到端冒烟（详细语义测试在 wafiplist 模块）。
func TestIPListFast_registeredAndBlocks(t *testing.T) {
	// Given：白名单内的名单文件
	dir := t.TempDir()
	old := wafiplist.AllowedPathPrefix
	wafiplist.AllowedPathPrefix = dir + string(filepath.Separator)
	t.Cleanup(func() { wafiplist.AllowedPathPrefix = old })
	path := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(path, []byte("203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When：@ipListFast 规则编译 + 两个事务（命中/未命中）
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
		"SecRuleEngine On\nSecRule REMOTE_ADDR \"@ipListFast " + path + "\" \"id:1,phase:1,deny,status:403\"\n"))
	if err != nil {
		t.Fatalf("coraza must accept @ipListFast directives: %v", err)
	}
	blocked := func(ip string) bool {
		tx := waf.NewTransaction()
		defer func() { _ = tx.Close() }()
		tx.ProcessConnection(ip, 12345, "127.0.0.1", 443)
		tx.ProcessURI("/", "GET", "HTTP/1.1")
		return tx.ProcessRequestHeaders() != nil
	}

	// Then
	if !blocked("203.0.113.9") {
		t.Fatal("名单内 IP 必须被拦截")
	}
	if blocked("203.0.114.9") {
		t.Fatal("名单外 IP 不得被拦截")
	}
}
