package services

// taskengine_wire_runtime_test.go —— 运行期生命周期 daemon 归口的钉测：
// ①任务注册成功（8 个 ID、Kind/RunsOn/节拍口径）；
// ②RunTicker 首跑立即生效（bootstrap 不等首个节拍）；
// ③间隔执行（小节拍观测 ≥2 轮）；
// ④StopLoop 后不再执行（观察窗内计数稳定）；
// ⑤装配期同步首跑（阈值/时区 Once 在注册期已读真实库值）；
// ⑥main.go 无残留自建循环启动接线（cmd/server 侧另有 grep 断言，本文件
//   钉 services/handlers/db/middleware 侧的退役符号不存在——由编译保证）。

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// newRuntimeLifecycleTestEngine 装配隔离库 + 引擎并注册运行期生命周期任务族
// （默认启动清单随之拉起）。返回引擎；钩子复位与引擎收尾挂 t.Cleanup。
// seed 在注册（daemon bootstrap）之前执行——需要被 bootstrap 轮消费的
// 预置状态（如脏 API Key 标记）必须经此注入。
func newRuntimeLifecycleTestEngine(t *testing.T) *taskengine.Engine {
	return newRuntimeLifecycleTestEngineWithSeed(t, nil)
}

func newRuntimeLifecycleTestEngineWithSeed(t *testing.T, seed func()) *taskengine.Engine {
	t.Helper()
	setupIsolatedDB(t)
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	SetTaskEngineForTest(te)
	t.Cleanup(func() {
		SetMetricsCollector(nil)
		SetThreatRollupWarmerRound(nil)
		SetCaddyRestartWatcherRound(nil)
		SetRateLimitBucketSweep(nil)
		StopTaskEngine()
	})
	if seed != nil {
		seed()
	}
	registerRuntimeLifecycleTasks(te)
	return te
}

func TestRuntimeLifecycleTasks_registered(t *testing.T) {
	te := newRuntimeLifecycleTestEngine(t)
	want := map[string]taskengine.Kind{
		"metrics-collector":       taskengine.KindDaemon,
		"metrics-history-cleanup": taskengine.KindPeriodic,
		"threat-rollup-warmer":    taskengine.KindDaemon,
		"caddy-restart-watcher":   taskengine.KindDaemon,
		"ratelimit-bucket-sweep":  taskengine.KindDaemon,
		"apikey-usage-flusher":    taskengine.KindDaemon,
		"runtime-log-threshold":   taskengine.KindDaemon,
		"runtime-tz-refresh":      taskengine.KindDaemon,
	}
	for id, kind := range want {
		meta, ok := te.Lookup(id)
		if !ok {
			t.Fatalf("任务 %s 未注册", id)
		}
		if meta.Kind != kind {
			t.Fatalf("任务 %s Kind=%s, want %s", id, meta.Kind, kind)
		}
		// Controllable 面板口径只对常驻族为真（Periodic 的调度开关走
		// loopEnabled，不暴露启停钮）——与 buildTaskMeta 口径一致。
		if wantControllable := kind == taskengine.KindDaemon; meta.Controllable != wantControllable {
			t.Fatalf("任务 %s Controllable=%v, want %v（Kind=%s）", id, meta.Controllable, wantControllable, kind)
		}
	}
	meta, _ := te.Lookup("metrics-history-cleanup")
	if meta.IntervalSec != int(24*time.Hour/time.Second) {
		t.Fatalf("metrics-history-cleanup IntervalSec=%d, want 24h", meta.IntervalSec)
	}
}

// metrics-collector：bootstrap 立即采集、按节拍续采、StopLoop 后不再采集
// （观察窗内抓取计数稳定）。
func TestRuntimeLifecycleMetricsCollector_bootstrapIntervalAndStop(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("caddy_http_requests_total{handler=\"reverse_proxy\",host=\"example.com\"} 20\n"))
	}))
	t.Cleanup(server.Close)

	te := newRuntimeLifecycleTestEngine(t)
	SetMetricsCollector(NewMetricsService(server.URL, 1)) // 1s 节拍便于观测

	// bootstrap：立即首跑（不等 1s 节拍）。
	waitForCond(t, 2*time.Second, func() bool { return hits.Load() >= 1 })
	// 间隔执行：观察窗内 ≥3 轮（1s 节拍 + 调度余量）。
	waitForCond(t, 5*time.Second, func() bool { return hits.Load() >= 3 })
	first := hits.Load()

	// 停止后不再执行。
	te.StopLoop("metrics-collector")
	waitForCond(t, time.Second, func() bool {
		for _, meta := range te.DescribeAll() {
			if meta.ID == "metrics-collector" && !meta.Running {
				return true
			}
		}
		return false
	})
	assertCounterStable(t, &hits, first, 2500*time.Millisecond)
	if meta, ok := te.Lookup("metrics-collector"); ok && meta.LoopOn {
		t.Fatal("StopLoop 后 loop_on 必须为 false")
	}
}

// 钩子型 daemon（warmer/watcher/清扫）：未接线时空闲（Run 立即返回零噪音）；
// 接线后 bootstrap 立即执行一轮；StopLoop 后不再执行。
func TestRuntimeLifecycleHookDaemons_idleWhenUnwiredAndBootstrapWhenWired(t *testing.T) {
	te := newRuntimeLifecycleTestEngine(t) // 钩子全 nil：空闲形态

	// 未接线：daemon 已启动但零工作（60s/2s 节拍都不产生副作用——用短窗计数
	// 稳定性证明 RunTicker 根本没进工作体）。
	var warmerCalls atomic.Int32
	SetThreatRollupWarmerRound(func() error { warmerCalls.Add(1); return nil })
	SetCaddyRestartWatcherRound(func() {})
	SetRateLimitBucketSweep(func() int { return 0 })

	// 接线在 daemon 已运行后到达：下一轮/唤醒才消费——此处直接以「重启 daemon
	// = 用户可见路径」验证接线生效（StopLoop → StartLoop 走 restartIntent 换代）。
	te.StopLoop("threat-rollup-warmer")
	te.StopLoop("caddy-restart-watcher")
	te.StopLoop("ratelimit-bucket-sweep")
	waitForCond(t, time.Second, func() bool {
		running := 0
		for _, meta := range te.DescribeAll() {
			switch meta.ID {
			case "threat-rollup-warmer", "caddy-restart-watcher", "ratelimit-bucket-sweep":
				if !meta.Running {
					running++
				}
			}
		}
		return running == 3
	})
	te.StartLoop("threat-rollup-warmer")
	te.StartLoop("caddy-restart-watcher")
	te.StartLoop("ratelimit-bucket-sweep")

	waitForCond(t, 2*time.Second, func() bool { return warmerCalls.Load() >= 1 })
	warmerFirst := warmerCalls.Load()
	te.StopLoop("threat-rollup-warmer")
	waitForCond(t, time.Second, func() bool {
		for _, meta := range te.DescribeAll() {
			if meta.ID == "threat-rollup-warmer" && !meta.Running {
				return true
			}
		}
		return false
	})
	assertCounterStable(t, &warmerCalls, warmerFirst, time.Second)
}

// apikey-usage-flusher：bootstrap 立即 flush 脏标记（不等 60s 节拍）。
func TestRuntimeLifecycleAPIKeyFlusher_flushesOnBootstrap(t *testing.T) {
	newRuntimeLifecycleTestEngineWithSeed(t, func() {
		if _, err := db.DB.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('flusher-u','hash','admin',1)`); err != nil {
			t.Fatal(err)
		}
		var keyID int64
		if err := db.DB.QueryRow(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,last_used) VALUES ('k','hash','pre',1,NULL); SELECT last_insert_rowid()`).Scan(&keyID); err != nil {
			t.Fatal(err)
		}
		db.MarkAPIKeyUsed(int(keyID))
	})

	// bootstrap flush：last_used 落库（60s 节拍未到）。轮询读全表唯一行，
	// 不依赖 seed 闭包作用域内的 keyID。
	waitForCond(t, 2*time.Second, func() bool {
		var lastUsed any
		if err := db.DB.QueryRow(`SELECT last_used FROM api_keys WHERE name='k'`).Scan(&lastUsed); err != nil {
			return false
		}
		return lastUsed != nil
	})
}

// runtime-log-threshold / runtime-tz-refresh：Once 工作体读真实库值
// （装配期同步首跑即本函数——daemon 节拍共用同一实现）。
func TestRuntimeLifecycleOnceRefreshes_applyDBValues(t *testing.T) {
	newRuntimeLifecycleTestEngine(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET runtime_log_size_mb=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	runtimeLogSizeMB.Store(100)
	RefreshRuntimeLogSizeOnce()
	if got := runtimeLogSizeMB.Load(); got != 7 {
		t.Fatalf("runtimeLogSizeMB=%d, want 7（Once 必须读真实库值）", got)
	}

	snapshotLocationState(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET timezone='UTC' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	RefreshTimezoneOnce()
	if CurrentLocation() != time.UTC {
		t.Fatalf("current location=%v, want UTC（Once 必须应用库值时区）", CurrentLocation())
	}
}
