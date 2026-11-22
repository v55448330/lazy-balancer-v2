package notify

// live 即时上报也携带客户端幂等键（batch_id 全覆盖），且
// live 失败转 spool 重传复用同一键——主节点按 batch_id 去重可抗「已处理但
// 响应丢失」的重复投递。（去重窗口本身是主节点进程内 512 批次 FIFO，见
// handlers/cluster_events_report.go 与 apidocs 端点说明。）

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClusterForward_liveReportCarriesBatchID(t *testing.T) {
	flushClusterForwardQueue(t)
	var mu sync.Mutex
	var gotBody ClusterEventReport
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body ClusterEventReport
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		gotBody, hits = body, hits+1
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-live")
	_ = newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Time: time.Unix(1700000000, 42), Fields: map[string]string{"1": "node-x", "2": "d"}})

	waitNotifyCond(t, "live 上报到达", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return hits == 1
	})
	mu.Lock()
	defer mu.Unlock()
	if gotBody.BatchID == "" {
		t.Fatal("live 上报 batch_id 为空（无幂等键 → 主节点无法去重重试）")
	}
	if gotBody.Spooled {
		t.Fatal("live 上报不应标记 spooled")
	}
}

func TestClusterForward_spoolReusesLiveBatchID(t *testing.T) {
	flushClusterForwardQueue(t)
	dir := t.TempDir()
	overrideForwardSpoolDir(t, dir)
	var failing atomic.Bool
	failing.Store(true)
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var report ClusterEventReport
		_ = json.Unmarshal(raw, &report)
		mu.Lock()
		seen = append(seen, report.BatchID)
		mu.Unlock()
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-spool")
	_ = newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Time: time.Unix(1700000001, 7), Fields: map[string]string{"1": "node-y", "2": "d"}})

	// 异步转发失败后落 spool：等文件出现再断言同键。
	var entries []os.DirEntry
	waitNotifyCond(t, "失败事件落 spool", func() bool {
		entries = spoolJSONFiles(dir)
		return len(entries) == 1
	})
	raw, err := os.ReadFile(dir + "/" + entries[0].Name())
	if err != nil {
		t.Fatal(err)
	}
	var spooled ClusterEventReport
	if err := json.Unmarshal(raw, &spooled); err != nil {
		t.Fatal(err)
	}
	if spooled.BatchID == "" {
		t.Fatal("spool 载荷 batch_id 为空")
	}
	mu.Lock()
	if len(seen) != 1 || seen[0] != spooled.BatchID {
		t.Fatalf("live 上报键=%v，spool 键=%q（必须复用同一键，否则重传被当新事件重复投递）", seen, spooled.BatchID)
	}
	mu.Unlock()

	failing.Store(false)
	DrainClusterForwardSpool(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("重传次数=%d，want 2（live + 一次 spool 重传）", len(seen))
	}
	if seen[1] != spooled.BatchID {
		t.Fatalf("spool 重传键=%q，want %q", seen[1], spooled.BatchID)
	}
}
