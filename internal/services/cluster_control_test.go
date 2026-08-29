package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// issueControlTicket 在主节点语义库上签发服务控制票据，并把库切换为从节点语义
// （与 cluster_ticket_test.go 的 issueClusterLoginTicket 同模式）。
func issueControlTicket(t *testing.T, now time.Time, action string) (*ClusterService, string) {
	t.Helper()
	service, database := newClusterTestService(t)
	clusterToken := "lb_cluster_control-secret"
	key := sha256.Sum256([]byte(clusterToken))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash) VALUES (11,'slave','10.0.0.11',8000,'online',1,?)`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	issued, err := service.IssueServiceControlTicket(context.Background(), 11, action, now)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	if issued.NodeName != "slave" {
		t.Fatalf("node name=%q, want slave", issued.NodeName)
	}
	if issued.URL != "http://10.0.0.11:8000" {
		t.Fatalf("url=%q, want fallback protocol://ip:port", issued.URL)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0,cluster_token=?,registration_id=11 WHERE id=1", clusterToken); err != nil {
		t.Fatal(err)
	}
	return service, issued.Ticket
}

func TestServiceControlTicketRoundtrip(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionStopCaddy)
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionStopCaddy, now); err != nil {
		t.Fatalf("validate ticket: %v", err)
	}
}

func TestServiceControlTicketRejectsExpired(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionRestartApp)
	// 签发 TTL 90s（含时钟偏移容差），越过该窗口必须拒绝
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionRestartApp, now.Add(91*time.Second)); !errors.Is(err, ErrInvalidServiceControlTicket) {
		t.Fatalf("expired error=%v", err)
	}
}

func TestServiceControlTicketRejectsInvalidSignature(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionStartCaddy)
	parts := strings.Split(ticket, ".")
	if parts[1][0] == 'A' {
		parts[1] = "B" + parts[1][1:]
	} else {
		parts[1] = "A" + parts[1][1:]
	}
	if err := service.ValidateServiceControlTicket(context.Background(), strings.Join(parts, "."), models.ClusterServiceActionStartCaddy, now); !errors.Is(err, ErrServiceControlSignature) {
		t.Fatalf("signature error=%v", err)
	}
}

func TestServiceControlTicketRejectsReplay(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionStopCaddy)
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionStopCaddy, now); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrServiceControlReplay) {
		t.Fatalf("replay error=%v", err)
	}
}

func TestServiceControlTicketRejectsReplayAfterServiceRebuild(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionRestartCaddy)
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionRestartCaddy, now); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	rebuilt := NewClusterService(service.db, nil)
	if err := rebuilt.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionRestartCaddy, now); !errors.Is(err, ErrServiceControlReplay) {
		t.Fatalf("replay after rebuild error=%v", err)
	}
}

func TestServiceControlTicketRejectsActionMismatch(t *testing.T) {
	// 票据与动作绑定：签发给 start_caddy 的票据不得用于 stop_caddy（防动作替换）
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionStartCaddy)
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrInvalidServiceControlTicket) {
		t.Fatalf("action mismatch error=%v", err)
	}
}

func TestServiceControlTicketRejectsForeignNode(t *testing.T) {
	// registration_id 不匹配（票据发给别的节点）必须拒绝
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	clusterToken := "lb_cluster_control-foreign"
	key := sha256.Sum256([]byte(clusterToken))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash) VALUES (12,'slave','10.0.0.12',8000,'online',1,?)`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	issued, err := service.IssueServiceControlTicket(context.Background(), 12, models.ClusterServiceActionStopCaddy, now)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	// 本节点登记的是 11 号，票据声称 12 号
	if _, err := database.Exec("UPDATE global_config SET is_master=0,cluster_token=?,registration_id=11 WHERE id=1", clusterToken); err != nil {
		t.Fatal(err)
	}
	if err := service.ValidateServiceControlTicket(context.Background(), issued.Ticket, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrInvalidServiceControlTicket) {
		t.Fatalf("foreign node error=%v", err)
	}
}

func TestServiceControlTicketRejectedOnMaster(t *testing.T) {
	// 主节点持有票据（本节点 is_master=1）必须拒绝——服务控制只对从节点生效
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	key := sha256.Sum256([]byte("lb_cluster_control-master-side"))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash) VALUES (13,'slave','10.0.0.13',8000,'online',1,?)`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	issued, err := service.IssueServiceControlTicket(context.Background(), 13, models.ClusterServiceActionStopCaddy, now)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	if err := service.ValidateServiceControlTicket(context.Background(), issued.Ticket, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrInvalidServiceControlTicket) {
		t.Fatalf("master-side error=%v", err)
	}
}

func TestIssueServiceControlTicketRejectsInvalidAction(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, _ := newClusterTestService(t)
	if _, err := service.IssueServiceControlTicket(context.Background(), 1, "rm_rf_slash", now); !errors.Is(err, ErrInvalidServiceAction) {
		t.Fatalf("invalid action error=%v", err)
	}
}

func TestIssueServiceControlTicketRequiresApprovedNodeWithToken(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	// 待审批节点
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,is_approved) VALUES (14,'pending','10.0.0.14',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueServiceControlTicket(context.Background(), 14, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("pending node error=%v", err)
	}
	// 不存在的节点
	if _, err := service.IssueServiceControlTicket(context.Background(), 999, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("missing node error=%v", err)
	}
	// 已审批但令牌哈希为空（未交付令牌）——不可控节点
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,is_approved,cluster_token_hash) VALUES (15,'hashless','10.0.0.15',1,'')`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueServiceControlTicket(context.Background(), 15, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("hashless node error=%v", err)
	}
}

func TestIssueServiceControlTicketPrefersAccessURL(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	key := sha256.Sum256([]byte("cluster-token"))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,access_url,status,is_approved,cluster_token_hash) VALUES (16,'slave','172.18.0.2',8000,'http','https://node.example:8443','offline',1,?)`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	// 离线节点也可下发 restart_app（挂死节点的恢复路径），access_url 优先
	issued, err := service.IssueServiceControlTicket(context.Background(), 16, models.ClusterServiceActionRestartApp, now)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	if issued.URL != "https://node.example:8443" {
		t.Fatalf("url=%q, want access_url", issued.URL)
	}
}
