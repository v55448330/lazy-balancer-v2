package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// 「30 天内到期」必须与规则页/证书页的 expiring 语义一致（CertificateExpiryStatus
// 以 `!now.Before(NotAfter)` 先判 expired，expired 与 expiring 互斥）：只有上界
// 的计数会把数月前就已过期、且未续期的 issued/failed 行算作「临期」，从节点健康
// 卡数字虚高，运维据此判断剩余时间会完全走偏。
func TestSyncService_Report_countsOnlyNotYetExpiredCertificates(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_expiry_win','expiry-win','http','expiry-win.example.test',443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	// 三行同规则不同域名：已过期 60 天、5 天后到期、90 天后到期。
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at) VALUES
		('lb_expiry_win','expired.example.test','issued',datetime('now','-60 days')),
		('lb_expiry_win','soon.example.test','issued',datetime('now','+5 days')),
		('lb_expiry_win','later.example.test','issued',datetime('now','+90 days'))`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}

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
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	if err := service.Report(ctx); err != nil {
		t.Fatalf("report: %v", err)
	}
	var report models.ClusterReport
	select {
	case report = <-reported:
	default:
		t.Fatal("master did not receive cluster report")
	}
	if report.Health.CertsExpiring30d != 1 {
		t.Fatalf("certs_expiring_30d=%d, want 1（只计未过期且窗口内的行：已过期行属 expired，不计入临期）", report.Health.CertsExpiring30d)
	}
}
