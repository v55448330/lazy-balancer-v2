package services

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"encoding/json"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// 主节点启用管理 HTTPS 后,跨主机/未跟随的 3xx 会以空 body
// 落到既有分支——Report 此前把 3xx 当成功静默吞掉,RegisterWithMaster 则报
// 「解析注册响应: unexpected end of JSON input」让运维无从下手。两处都须
// 在读 body 前给可行动错误(仿 Pull 的 3xx 分支文案)。
func TestSyncService_Report_returnsActionableErrorOnUnfollowedRedirect(t *testing.T) {
	// Given:主节点上报端点 301 指向另一主机(同主机 https 升级会被
	// DoWithSameHostTLSUpgradeRedirect 自动重放,跨主机不跟随)。
	_, database := newClusterTestService(t)
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "https://master-elsewhere.example.com/api/v1/cluster/nodes/report")
		response.WriteHeader(http.StatusMovedPermanently)
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))

	// When
	err := service.Report(context.Background())

	// Then:错误含「重定向」与 https 修正指引(不再是静默成功)。
	if err == nil {
		t.Fatal("report unexpectedly succeeded on 3xx response")
	}
	if !strings.Contains(err.Error(), "重定向") || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("report error=%q, want actionable redirect guidance", err)
	}
}

func TestSyncService_Report_followsSameHostTLSUpgradeFound(t *testing.T) {
	// Given the real plaintext-to-HTTPS upgrade shape emitted as 302.
	_, database := newClusterTestService(t)
	received := make(chan string, 1)
	tlsMaster := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method=%q, want POST", request.Method)
		}
		received <- request.Header.Get("X-Cluster-Token")
		response.WriteHeader(http.StatusOK)
	}))
	defer tlsMaster.Close()
	plaintext := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, tlsMaster.URL+request.URL.Path, http.StatusFound)
	}))
	defer plaintext.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", plaintext.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When the node reports through the plaintext address.
	err := service.Report(context.Background())

	// Then 302 is replayed before the residual-3xx guard and the report succeeds.
	if err != nil {
		t.Fatalf("same-host 302 upgrade must succeed: %v", err)
	}
	select {
	case token := <-received:
		if token != "cluster-token" {
			t.Fatalf("token=%q, want cluster-token", token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTPS target never received report")
	}
}

func TestSyncService_Report_rejectsCrossHostFound(t *testing.T) {
	// Given a 302 to another hostname, which must never receive cluster credentials.
	_, database := newClusterTestService(t)
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "https://master-elsewhere.example.com/api/v1/cluster/nodes/report")
		response.WriteHeader(http.StatusFound)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When/Then the residual-3xx guard remains fail-visible for cross-host 302.
	err := service.Report(context.Background())
	if err == nil || !strings.Contains(err.Error(), "302") || !strings.Contains(err.Error(), "重定向") {
		t.Fatalf("cross-host 302 error=%v, want actionable redirect rejection", err)
	}
}

// 同款判定也须覆盖注册链:读 body 前拦截,防「unexpected end of JSON input」。
func TestSyncService_RegisterWithMaster_returnsActionableErrorOnUnfollowedRedirect(t *testing.T) {
	// Given:主节点注册端点 301 跨主机。
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "https://master-elsewhere.example.com/api/v1/cluster/register")
		response.WriteHeader(http.StatusMovedPermanently)
	}))
	defer master.Close()
	service := NewSyncService(nil, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, err := service.RegisterWithMaster(context.Background(), master.URL, models.ClusterRegisterRequest{})

	// Then
	if err == nil {
		t.Fatal("registration unexpectedly succeeded on 3xx response")
	}
	if !strings.Contains(err.Error(), "重定向") || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("registration error=%q, want actionable redirect guidance", err)
	}
	if strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("registration error=%q leaked raw JSON parse failure instead of guidance", err)
	}
}

// 临期统计覆盖仍可能代表当前证书材料的 downloaded/failed 行，
// 不只 issued；waiting_ca 不属于部署完成/待部署证书材料口径。
// 部署生命周期 cleanup_dns/cleanup_warning（材料已落库、
// 待部署）同样必须计入——此前与规则页/任务页到期口径分叉。
func TestSyncService_Report_countsExpiringCertificatesAcrossDeployableStates(t *testing.T) {
	_, database := newClusterTestService(t)
	reported := make(chan models.ClusterReport, 1)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report models.ClusterReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reported <- report
		w.WriteHeader(http.StatusOK)
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec(`UPDATE global_config SET is_master=0,master_url=?,cluster_token='cluster-token' WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at) VALUES
		('lb_issued','issued.example.test','issued',datetime('now','+2 days')),
		('lb_downloaded','downloaded.example.test','downloaded',datetime('now','+3 days')),
		('lb_failed','failed.example.test','failed',datetime('now','+4 days')),
		('lb_waiting','waiting.example.test','waiting_ca',datetime('now','+5 days')),
		('lb_cleanup_dns','cleanup-dns.example.test','cleanup_dns',datetime('now','+6 days')),
		('lb_cleanup_warning','cleanup-warning.example.test','cleanup_warning',datetime('now','+7 days')),
		('lb_future','future.example.test','issued',datetime('now','+90 days'))`); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	if err := service.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case report := <-reported:
		if report.Health.CertsExpiring30d != 5 {
			t.Fatalf("expiring count=%d, want issued/downloaded/failed/cleanup_dns/cleanup_warning = 5", report.Health.CertsExpiring30d)
		}
	default:
		t.Fatal("master did not receive cluster report")
	}

	// 带外/旧主端脏值不得把所有 90 天证书都误判为临期；读侧回退默认 30 天。
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=100000 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := service.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case report := <-reported:
		if report.Health.CertsExpiring30d != 5 {
			t.Fatalf("expiring count with excessive threshold=%d, want default-threshold count 5", report.Health.CertsExpiring30d)
		}
	default:
		t.Fatal("master did not receive second cluster report")
	}
}

// cert_expiry_days 非法时按状态转换只记一次 warn，恢复记一次 info。
func TestReport_certExpiryWarnOnlyOnStateTransition(t *testing.T) {
	// 隔离共享状态转换 map 的该 key（同 metrics_test.go isolateMetricsState 范式）：
	// 同文件其它 Report 用例可能已把该 key 置为 failed，状态机对「已失败→再失败」
	// 不重复记，会静默吞掉本用例的首次失败告警（整文件顺序跑时复现）。
	const certExpiryStateKey = "cluster-report-cert-expiry"
	metricsStateMu.Lock()
	previousState, hadPrevious := metricsStateFailed[certExpiryStateKey]
	delete(metricsStateFailed, certExpiryStateKey)
	metricsStateMu.Unlock()
	t.Cleanup(func() {
		metricsStateMu.Lock()
		if hadPrevious {
			metricsStateFailed[certExpiryStateKey] = previousState
		} else {
			delete(metricsStateFailed, certExpiryStateKey)
		}
		metricsStateMu.Unlock()
	})

	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false) // Report 只属于从节点语境
	sync := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	t.Cleanup(func() { unregisterSyncDrainer(sync) })
	ctx := context.Background()

	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := sync.Report(ctx); err == nil {
			t.Fatal("report with empty master URL must fail")
		}
	}
	if got := strings.Count(buf.String(), "读取证书到期口径失败"); got != 1 {
		t.Fatalf("invalid cert_expiry_days logged %d times, want 1 (state transition gate)", got)
	}

	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=30 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := sync.Report(ctx); err == nil {
		t.Fatal("report with empty master URL must fail")
	}
	if got := strings.Count(buf.String(), "证书到期口径读取恢复正常"); got != 1 {
		t.Fatalf("recovery log count=%d, want 1", got)
	}

	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := sync.Report(ctx); err == nil {
		t.Fatal("report with empty master URL must fail")
	}
	if got := strings.Count(buf.String(), "读取证书到期口径失败"); got != 2 {
		t.Fatalf("failure after recovery logged %d times, want 2", got)
	}
}

// reportWafFileVersions 是上报热路径的轻量版本读取（只读两个小文件，不做
// 全树哈希），零测试引用意味着「两字段接反/路径写错/sanitize 单边改动」全绿。
// 三形状：①齐全（钉字段来源，接反即红）②seen 门（rules 目录与 xdb 均缺失 =
// 无安全数据，版本串保持空）③非法 tag 经 sanitize 置空而 CRS 版本不受影响。
func TestReportWafFileVersions_readsLightweightLabels(t *testing.T) {
	t.Run("齐全时按来源分别读取", func(t *testing.T) {
		crsDir, xdbPath := overrideWafPathsForServicesTest(t)
		if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("  v4.14.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(xdbPath+".version", []byte("v3.17.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(xdbPath, []byte("xdb-bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
		crs, tag := reportWafFileVersions()
		if crs != "v4.14.0" {
			t.Fatalf("crsVersion=%q, want 来自 crs VERSION 文件（v4.14.0）", crs)
		}
		if tag != "v3.17.0" {
			t.Fatalf("ip2regionTag=%q, want 来自 xdb 伴生 .version 文件（v3.17.0）", tag)
		}
	})

	t.Run("rules目录与xdb均缺失时不上报版本", func(t *testing.T) {
		crsDir := t.TempDir() // 无 rules 子目录
		xdbPath := filepath.Join(t.TempDir(), "absent.xdb")
		t.Cleanup(OverrideWafLivePathsForTest(crsDir, xdbPath))
		// 版本文件存在但「无安全数据」形态下不得上报
		if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.14.0"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(xdbPath+".version", []byte("v3.17.0"), 0o644); err != nil {
			t.Fatal(err)
		}
		if crs, tag := reportWafFileVersions(); crs != "" || tag != "" {
			t.Fatalf("crs=%q tag=%q, want 空（rules 目录与 xdb 均缺失=无安全数据）", crs, tag)
		}
	})

	t.Run("非法版本串经sanitize置空", func(t *testing.T) {
		crsDir, xdbPath := overrideWafPathsForServicesTest(t)
		if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.14.0"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(xdbPath+".version", []byte("v3.17.0;rm -rf /"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(xdbPath, []byte("xdb-bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
		crs, tag := reportWafFileVersions()
		if crs != "v4.14.0" {
			t.Fatalf("crsVersion=%q, want 不受 tag 形态影响", crs)
		}
		if tag != "" {
			t.Fatalf("ip2regionTag=%q, want 非法字符版本串经 sanitize 置空", tag)
		}
	})
}
