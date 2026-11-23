package caddygeoip

// 快照 TTL 到期后的并发重读必须 singleflight：旧实现每个请求各自读 4MiB
// 文件并解析 360 引擎全量段。

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCrawlerIPRangeSnapshot_concurrentReloadIsSingleFlight(t *testing.T) {
	oldFile := crawlerIPListFile
	oldRead := crawlerReadBoundedFile
	t.Cleanup(func() {
		crawlerIPListFile = oldFile
		crawlerReadBoundedFile = oldRead
		resetCrawlerIPRangeCacheForTest()
	})
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	payload := `{"so360spider":["42.236.9.0/24"],"googlebot":["66.249.66.0/24"]}`
	if err := os.WriteFile(crawlerIPListFile, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	resetCrawlerIPRangeCacheForTest()

	var reads atomic.Int64
	crawlerReadBoundedFile = func(path string, limit int64) ([]byte, os.FileInfo, error) {
		reads.Add(1)
		// 放大读盘窗口：并发读者若各自读盘会全部落入本窗口。
		time.Sleep(50 * time.Millisecond)
		return oldRead(path, limit)
	}

	const goroutines = 8
	var wg sync.WaitGroup
	results := make([]*crawlerIPRangeSnapshot, goroutines)
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = loadCrawlerIPRangeSnapshot()
		}(i)
	}
	close(start)
	wg.Wait()

	if got := reads.Load(); got != 1 {
		t.Fatalf("并发首载读盘 %d 次, want 1（TTL 到期重读必须 singleflight）", got)
	}
	for i, snap := range results {
		if snap == nil || !snap.ok {
			t.Fatalf("goroutine %d 未拿到可用快照: %+v", i, snap)
		}
	}
}
