package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func initMetricsOverviewTestDB(t *testing.T) {
	t.Helper()
	// 复用单源隔离夹具：四句柄（含 db.GetDB 原子句柄）成对保存/还原。
	setupIsolatedDBWithMetrics(t)
}

func seedOverviewNode(t *testing.T, ip string, lastSeen time.Time) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO nodes (name, mode, ip_address, port, is_approved, last_seen)
		VALUES (?, 'slave', ?, 8000, 1, ?)`, ip, ip, lastSeen.UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatalf("seed node %s: %v", ip, err)
	}
}

func liveMetricsServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 5`))
	}))
	t.Cleanup(server.Close)
	return server
}

// 总览在线节点统计必须复用 nodeOfflineThreshold 的唯一
// 口径，不得在 SQL 里另写一套 MIN(86400, …) 上限。sync_interval=86400 时阈值
// 应为 48h：last_seen=30h 的节点在节点列表里判「在线」，总览也必须在线上。
func TestRefreshDBOverviewMetrics_honorsUnifiedOfflineThreshold(t *testing.T) {
	initMetricsOverviewTestDB(t)
	if _, err := db.DB.Exec("UPDATE global_config SET sync_interval = 86400 WHERE id = 1"); err != nil {
		t.Fatalf("set sync_interval: %v", err)
	}
	seedOverviewNode(t, "10.0.0.11", time.Now().Add(-30*time.Hour))

	service := NewMetricsService(liveMetricsServer(t).URL, 30)
	service.refreshDBOverviewMetrics()

	if got := service.GetOverview().OnlineNodes; got != 1 {
		t.Fatalf("online nodes=%d, want 1（sync_interval=86400 → 阈值 48h，30h 前上报仍在线；SQL 内 24h 上限会误判离线）", got)
	}

	// 回归形状：超过 48h 的节点判离线（阈值没有被放大成「永远在线」）。
	seedOverviewNode(t, "10.0.0.12", time.Now().Add(-49*time.Hour))
	service.refreshDBOverviewMetrics()
	if got := service.GetOverview().OnlineNodes; got != 1 {
		t.Fatalf("online nodes=%d, want 1（49h 前上报应离线）", got)
	}

	// 畸形形状：sync_interval 脏值（0）按 60s 归一 → 阈值 120s，30h 前上报离线。
	if _, err := db.DB.Exec("UPDATE global_config SET sync_interval = 0 WHERE id = 1"); err != nil {
		t.Fatalf("dirty sync_interval: %v", err)
	}
	service.refreshDBOverviewMetrics()
	if got := service.GetOverview().OnlineNodes; got != 0 {
		t.Fatalf("online nodes=%d, want 0（脏值归一到 60s → 阈值 120s）", got)
	}
}

// /metrics 不可达时三项 DB 派生指标（启用规则/规则总数/
// 在线节点）仍须刷新——此前它们只在采集成功的末尾更新，Caddy 未就绪时永久冻结在 0。
func TestCollect_refreshesDBDerivedMetricsWhenEndpointUnreachable(t *testing.T) {
	initMetricsOverviewTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES
		('lb_metrics_a','a','http',8080,1),
		('lb_metrics_b','b','http',8081,0)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	seedOverviewNode(t, "10.0.0.21", time.Now().Add(-10*time.Second))

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	isolateMetricsState(t)

	service := NewMetricsService(deadURL, 30)
	service.collect()

	overview := service.GetOverview()
	if overview.ActiveRules != 1 || overview.TotalRules != 2 || overview.OnlineNodes != 1 {
		t.Fatalf("overview=%+v, want ActiveRules=1 TotalRules=2 OnlineNodes=1（/metrics 不可达不影响 DB 派生指标）",
			overview)
	}
	if overview.TotalRequests != 0 {
		t.Fatalf("total requests=%d, want 0（流量样本应保持不可采信）", overview.TotalRequests)
	}

	// 非零基线形态：从 live 端点采一轮建立基线后切死端点——起点即 deadURL 时
	// `TotalRequests==0` 对错误分支恒真（零鉴别力），基线非零才能区分
	// 「保留上次样本」与「静默归零」。
	service.metricsURL = liveMetricsServer(t).URL
	service.collect()
	baseline := service.GetOverview().TotalRequests
	if baseline == 0 {
		t.Fatal("live 端点采集必须建立非零 TotalRequests 基线")
	}
	service.metricsURL = deadURL
	service.collect()
	if got := service.GetOverview().TotalRequests; got != baseline {
		t.Fatalf("total requests=%d, want %d（端点不可达时必须保留上次采样，不得归零）", got, baseline)
	}
}
