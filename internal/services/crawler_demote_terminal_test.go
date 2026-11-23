package services

// 下载期间节点被降级：源行已置 running，中止分支必须写终态（旧实现直接
// return ErrTaskSkipped，行长期停在「运行中」）。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func TestCrawlerUpdate_demoteDuringDownloadMarksSourceSkipped(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 把角色翻成从节点后取消本轮并掐断连接（模拟下载中途 demote +
		// 请求失败，保证进入「下载错误 + ctx 取消」分支）。
		if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Errorf("flip role: %v", err)
		}
		cancel()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("response writer 不支持 hijack")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	}))
	t.Cleanup(ts.Close)

	if err := ensureCrawlerSources(); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}

	err := GetCrawlerUpdateManager().RunUpdate(ctx, taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	if err != nil && !errors.Is(err, taskengine.ErrTaskSkipped) && !errors.Is(err, context.Canceled) {
		t.Logf("RunUpdate 返回 %v（降级中止允许 skipped/取消形态）", err)
	}

	var status, message string
	if err := db.DB.QueryRow(`SELECT update_status, COALESCE(message,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status == "running" {
		t.Fatalf("降级中止后源行仍停在 running（message=%q）", message)
	}
	if status != "skipped" {
		t.Fatalf("源状态=%q, want skipped（message=%q）", status, message)
	}
}
