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

func issueClusterLoginTicket(t *testing.T, now time.Time) (*ClusterService, string) {
	t.Helper()
	service, database := newClusterTestService(t)
	clusterToken := "lb_cluster_login-ticket-secret"
	key := sha256.Sum256([]byte(clusterToken))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash,last_seen) VALUES (7,'slave','10.0.0.7',8000,'online',1,?,?)`, hex.EncodeToString(key[:]), now.Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (3,'alice','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
	response, err := service.GenerateLoginTicket(context.Background(), models.ClusterLoginTicketClaims{UserID: 3, Username: "alice", NodeID: 7}, now)
	if err != nil {
		t.Fatalf("generate ticket: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0,cluster_token=?,registration_id=7 WHERE id=1", clusterToken); err != nil {
		t.Fatal(err)
	}
	return service, response.Ticket
}

func TestClusterLoginTicketRejectsExpiredTicket(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	// 签发 TTL 为 90s（含时钟偏移容差），越过该窗口后必须拒绝
	if _, _, _, err := service.ValidateLoginTicket(context.Background(), ticket, now.Add(91*time.Second)); !errors.Is(err, ErrInvalidLoginTicket) {
		t.Fatalf("expired ticket error=%v", err)
	}
}

func TestClusterLoginTicketRejectsInvalidSignature(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	parts := strings.Split(ticket, ".")
	if parts[1][0] == 'A' {
		parts[1] = "B" + parts[1][1:]
	} else {
		parts[1] = "A" + parts[1][1:]
	}
	if _, _, _, err := service.ValidateLoginTicket(context.Background(), strings.Join(parts, "."), now); !errors.Is(err, ErrInvalidLoginTicket) {
		t.Fatalf("invalid signature error=%v", err)
	}
}

func TestClusterLoginTicketRejectsReplay(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	if _, _, _, err := service.ValidateLoginTicket(context.Background(), ticket, now); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	if _, _, _, err := service.ValidateLoginTicket(context.Background(), ticket, now); !errors.Is(err, ErrInvalidLoginTicket) {
		t.Fatalf("replayed ticket error=%v", err)
	}
}

func TestClusterLoginTicketPrefersAccessURL(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	key := sha256.Sum256([]byte("cluster-token"))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,access_url,status,is_approved,cluster_token_hash,last_seen) VALUES (8,'slave','172.18.0.2',8000,'http','https://node.example:8443','online',1,?,?)`, hex.EncodeToString(key[:]), now.Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}

	response, err := service.GenerateLoginTicket(context.Background(), models.ClusterLoginTicketClaims{UserID: 3, Username: "alice", NodeID: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	if response.URL != "https://node.example:8443" {
		t.Fatalf("url=%q", response.URL)
	}
}

func TestClusterLoginTicketRejectsReplayAfterServiceRebuild(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	if _, _, _, err := service.ValidateLoginTicket(context.Background(), ticket, now); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	rebuilt := NewClusterService(service.db, "")
	if _, _, _, err := rebuilt.ValidateLoginTicket(context.Background(), ticket, now); !errors.Is(err, ErrLoginTicketReplay) {
		t.Fatalf("replayed ticket after rebuild error=%v", err)
	}
}

func TestClusterLoginTicketDatabaseFailureDoesNotConsumeTicket(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	if _, err := service.db.Exec(`CREATE TRIGGER reject_used_login_ticket BEFORE INSERT ON used_login_tickets BEGIN SELECT RAISE(ABORT, 'ticket store unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := service.ValidateLoginTicket(context.Background(), ticket, now); err == nil || errors.Is(err, ErrInvalidLoginTicket) {
		t.Fatalf("database failure error=%v", err)
	}
	if _, err := service.db.Exec("DROP TRIGGER reject_used_login_ticket"); err != nil {
		t.Fatal(err)
	}
	if _, user, _, err := service.ValidateLoginTicket(context.Background(), ticket, now); err != nil || user.Role != "admin" {
		t.Fatalf("validation after database recovery user=%#v err=%v", user, err)
	}
}

func TestGenerateLoginTicketRejectsStaleApprovedNode(t *testing.T) {
	// 票据门：nodes.status 只在注册/上报时写入、从不回写 'offline'，
	// 陈旧 status='online' 不得再放行签发——已停止上报（last_seen 超过
	// 2×sync_interval）的从节点按 ComputeNodeStatus 动态判定拒绝；恢复
	// 上报后放行（判定依据 last_seen 而非陈旧列）。
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	key := sha256.Sum256([]byte("cluster-token"))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash,last_seen) VALUES (9,'stale','10.0.0.9',8000,'online',1,?,?)`, hex.EncodeToString(key[:]), now.Add(-10*time.Minute).Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	claims := models.ClusterLoginTicketClaims{UserID: 3, Username: "alice", NodeID: 9}
	// 已批准但长期未上报=离线，返回 ErrNodeOffline（handler 409，
	// 可行动文案）；未批准 → ErrNodeNotFound（404）；已批准但无 keyHash
	// （令牌待交付）→ ErrNodeTokenPending（409，节点存在但尚不可签发）。
	if _, err := service.GenerateLoginTicket(context.Background(), claims, now); !errors.Is(err, ErrNodeOffline) {
		t.Fatalf("stale node error=%v, want ErrNodeOffline", err)
	}
	if _, err := database.Exec(`UPDATE nodes SET last_seen=? WHERE id=9`, now.Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GenerateLoginTicket(context.Background(), claims, now); err != nil {
		t.Fatalf("fresh node rejected: %v", err)
	}
}

// used_login_tickets 的存储契约此前零覆盖（无测试读取 jti_hash 行，也无测试
// 覆盖过期清理）：票据表无清理会让行数无限增长；清理范围写错（清掉未过期行）
// 则重放窗口重新打开。三面同时钉住：成功消费落 hex(sha256(jti)) 行、
// expires_at<=now 的行在下次消费时删除、未过期行不受影响。
func TestConsumeClusterTicketJTI_storageContract(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

	consume := func(jti string, expiresAt time.Time) bool {
		t.Helper()
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		ok, err := consumeClusterTicketJTI(ctx, tx, jti, now, expiresAt)
		if err != nil {
			t.Fatalf("consume %s: %v", jti, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit %s: %v", jti, err)
		}
		return ok
	}
	jtiHash := func(jti string) string {
		sum := sha256.Sum256([]byte(jti))
		return hex.EncodeToString(sum[:])
	}
	countRows := func() int {
		t.Helper()
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM used_login_tickets").Scan(&count); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		return count
	}
	hasRow := func(jti string) bool {
		t.Helper()
		var exists int
		if err := database.QueryRow("SELECT COUNT(*) FROM used_login_tickets WHERE jti_hash=?", jtiHash(jti)).Scan(&exists); err != nil {
			t.Fatalf("probe row: %v", err)
		}
		return exists == 1
	}

	// (a) 成功消费落 hex(sha256(jti)) 行，重放被拒。
	if !consume("live-jti", now.Add(5*time.Minute)) {
		t.Fatal("首次消费必须成功")
	}
	if !hasRow("live-jti") {
		t.Fatal("消费后必须存在 hex(sha256(jti)) 行（重放防护的唯一持久事实）")
	}
	if consume("live-jti", now.Add(5*time.Minute)) {
		t.Fatal("同一 jti 二次消费必须被判为重放")
	}

	// (b) 过期行在下次消费时被清理。
	if !consume("stale-jti", now.Add(-time.Minute)) {
		t.Fatal("前置：过期形态行插入应成功（清理发生在插入之前）")
	}
	if !hasRow("stale-jti") {
		t.Fatal("前置：过期行应先落库（否则本条不构成清理证据）")
	}
	if !consume("fresh-consume", now.Add(5*time.Minute)) {
		t.Fatal("新票据消费应成功")
	}
	if hasRow("stale-jti") {
		t.Fatal("expires_at<=now 的过期行必须在下一次消费时删除（否则行数无限增长）")
	}

	// (c) 未过期行不受清理影响（重放窗口不得被误开）。
	if !hasRow("live-jti") || !hasRow("fresh-consume") {
		t.Fatalf("未过期行被误删（剩余行数=%d）——重放窗口重新打开", countRows())
	}
}
