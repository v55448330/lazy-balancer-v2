package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// 出口 IP 探测失败的从节点上报空地址，主节点按注册来源地址落库：
// 回退 127.0.0.1 会让多台探测失败的从节点命中 UNIQUE(ip_address,port)
// 互相覆盖（后注册者重置前者的审批与集群令牌）。

func TestClusterService_RegisterNode_blankAddressUsesRegistrationSource(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewClusterService(database, "")
	now := time.Now()

	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "no-egress-a", Port: 9000,
	}, "10.1.0.11", now)
	if err != nil {
		t.Fatalf("register without self-reported address: %v", err)
	}
	var ip, port string
	var isApproved int
	if err := database.QueryRow(`SELECT ip_address, port, COALESCE(is_approved,0) FROM nodes WHERE id=?`, first.RegistrationID).Scan(&ip, &port, &isApproved); err != nil {
		t.Fatal(err)
	}
	if ip != "10.1.0.11" {
		t.Fatalf("ip_address=%q, want registration source 10.1.0.11", ip)
	}
	if err := service.ApproveNode(context.Background(), first.RegistrationID, time.Now()); err != nil {
		t.Fatal(err)
	}
	// 集群令牌经状态轮询交付（registration_secret → cluster_token_hash）。
	if _, err := service.RegistrationStatus(context.Background(), first.RegistrationID, first.RegistrationSecret, now); err != nil {
		t.Fatalf("status poll before approval delivery: %v", err)
	}
	var tokenHash string
	if err := database.QueryRow(`SELECT COALESCE(cluster_token_hash,'') FROM nodes WHERE id=?`, first.RegistrationID).Scan(&tokenHash); err != nil {
		t.Fatal(err)
	}
	if tokenHash == "" {
		t.Fatal("approval must deliver a cluster token hash")
	}

	// 第二台探测失败的从节点（另一来源地址、同端口）不得覆盖第一台。
	secondToken, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: secondToken, Name: "no-egress-b", Port: 9000,
	}, "10.1.0.12", now)
	if err != nil {
		t.Fatalf("second registration: %v", err)
	}
	if second.RegistrationID == first.RegistrationID {
		t.Fatal("两台从节点不得落在同一 nodes 行（回环地址回退的覆盖路径）")
	}
	if second.OverwrittenNodeID != 0 {
		t.Fatalf("second registration overwrote node %d", second.OverwrittenNodeID)
	}
	var stillApproved int
	var stillHash string
	if err := database.QueryRow(`SELECT COALESCE(is_approved,0), COALESCE(cluster_token_hash,'') FROM nodes WHERE id=?`, first.RegistrationID).Scan(&stillApproved, &stillHash); err != nil {
		t.Fatal(err)
	}
	if stillApproved != 1 || stillHash != tokenHash {
		t.Fatalf("first node approval/token reset: approved=%d hash=%q", stillApproved, stillHash)
	}
}

func TestClusterService_RegisterNode_blankAddressWithoutUsableSourceRejected(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewClusterService(database, "")
	now := time.Now()
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "no-address", Port: 9000,
	}, "", now); err == nil {
		t.Fatal("来源地址不可用时必须拒绝注册，而不是写回环/空地址")
	} else if !errors.Is(err, models.ErrMissingClusterNodeIP) {
		t.Fatalf("err=%v, want ErrMissingClusterNodeIP", err)
	}
}

// 自述地址非空但不是 IP 字面量（服务层直调/旧客户端绕过 HTTP binding ip）时
// 必须拒绝：与空值分支的来源地址校验对称，否则 host:port/方括号/垃圾串会直接
// 落进 nodes.ip_address 并被票据投递地址推导消费。
func TestClusterService_RegisterNode_nonEmptyNonIPLiteralRejected(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewClusterService(database, "")
	now := time.Now()
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "bad-address", IPAddress: "10.1.0.99:8000", Port: 9000,
	}, "10.1.0.10", now); err == nil {
		t.Fatal("非空非 IP 字面量的自述地址必须拒绝注册（与 HTTP 侧 binding ip 同判）")
	} else if !errors.Is(err, models.ErrInvalidClusterNodeIP) {
		t.Fatalf("err=%v, want ErrInvalidClusterNodeIP", err)
	}
}
