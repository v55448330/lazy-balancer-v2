package services

// 队列 provider 快照归一：0 值（max_concurrent=0 / min_interval_ms=0）只能由
// 带外改库、旧版本备份还原或混版本运行产生（写侧 UpdateCAProvider 归一），
// 但一旦落到运行期队列缓存，闸门（running >= MaxConcurrent）会永久关闭该 CA
// 的派发。归一的唯一出口是 loadCAProvider，本文件钉住两个消费面：
//  1. 加载出口本身归一；
//  2. enqueueLocked 复用已有队列时刷新的快照同样归一：只归一 tick/refresh 的
//     重载分支而放过复用入口时，复用会写入未归一快照并同步版本号，使后续重载
//     分支永不纠偏。

import (
	"context"
	"fmt"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func seedCAProviderBounds(t *testing.T, id, maxConcurrent, minIntervalMS int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO ca_providers
		(id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES (?,?,?,?,?,?,?,1)`,
		id, fmt.Sprintf("provider-%d", id), "letsencrypt", "https://acme.invalid/directory", "{}", maxConcurrent, minIntervalMS); err != nil {
		t.Fatalf("seed ca provider %d: %v", id, err)
	}
}

// Given 库内 max_concurrent=0、min_interval_ms=0（带外边角）。
// When 队列加载该 provider。
// Then 返回的快照必须已归一为 (1,2000)——未归一会让该 CA 的派发闸门恒关闭。
func TestLoadCAProvider_normalizesNonPositiveBounds(t *testing.T) {
	useCertSweepTickTestEnv(t)
	seedCAProviderBounds(t, 7, 0, 0)

	provider, err := loadCAProvider(7)
	if err != nil {
		t.Fatalf("load ca provider: %v", err)
	}
	if provider.MaxConcurrent != 1 || provider.MinIntervalMS != 2000 {
		t.Fatalf("provider bounds=(%d,%d), want (1,2000)", provider.MaxConcurrent, provider.MinIntervalMS)
	}
}

// Given 运行期已存在该 provider 的队列（快照为正常值）。
// When 库内该行被带外改成 (0,0) 后再次入队（enqueueLocked 复用队列分支）。
// Then 复用分支刷新的快照同样归一，闸门不被 0 值关死、节流不静默失效。
func TestEnqueueLocked_reusedQueueSnapshotIsNormalized(t *testing.T) {
	useCertSweepTickTestEnv(t)
	seedCAProviderBounds(t, 8, 0, 0)

	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(ResetCAQueueManagerForTest)
	qm := GetCAQueueManager()
	qm.Start()

	// 预置队列模拟「运行期已有队列」：enqueueLocked 走 else 分支，把本次加载的
	// provider 直接写入快照。执行体置空——测试只断言快照归一，不发起真实签发
	//（自建泵已退役，无 loop 可启；断言全为同步读）。
	q := newCAQueue(models.CAProvider{ID: 8, Name: "provider-8", Provider: "letsencrypt", MaxConcurrent: 5, MinIntervalMS: 2000}, func() error { return nil }, t.TempDir())
	q.executeFn = func(context.Context, queueItem, models.CAProvider) error { return nil }
	qm.mu.Lock()
	qm.queues[8] = q
	qm.mu.Unlock()

	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_norm','norm','http','norm.example.com',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_norm','norm.example.com','queued',8)`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	_, changed, err := qm.EnqueueIfActive(8, int(jobID), "lb_norm", "norm.example.com", func() (int, bool, error) {
		return int(jobID), true, nil
	})
	if err != nil || !changed {
		t.Fatalf("enqueue=(changed=%v, err=%v), want queued", changed, err)
	}

	q.mu.Lock()
	snapshot := q.provider
	q.mu.Unlock()
	if snapshot.MaxConcurrent != 1 || snapshot.MinIntervalMS != 2000 {
		t.Fatalf("reused queue snapshot=(%d,%d), want (1,2000)", snapshot.MaxConcurrent, snapshot.MinIntervalMS)
	}
}
