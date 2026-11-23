package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// 新节点注册必须 bump cluster_version——nodes 不在版本触发器清单
// （middleware/cluster_version.go），不 bump 则快照缓存键不变，新节点的
// node_sites 缺项，继承坐标静默不生效直至下一次无关 bump。
func TestClusterService_RegisterNode_bumpsVersionAndPublishesNodeSite(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	// 基线：主节点默认坐标 + 固定版本号（令牌生成之后，隔离其写放大）。
	if _, err := database.Exec(`UPDATE global_config SET server_map_lat=35.19, server_map_lon=108.87, cluster_version=7 WHERE id=1`); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	// 预热快照缓存（稳态：缓存已建）。
	warm, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("warm snapshot: %v", err)
	}
	if len(warm.NodeSites) != 0 {
		t.Fatalf("warm snapshot NodeSites=%v, want empty", warm.NodeSites)
	}

	// When：新节点注册（目标形状）。
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "slave-a", IPAddress: "10.0.0.2", Port: 8000,
	}, "10.0.0.2", now)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}

	// Then：版本 bump（缓存键失效）+ 走缓存路径的快照立即携带新节点继承坐标。
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != 8 {
		t.Fatalf("cluster_version=%d after registration, want 8（注册必须 bump 版本失效快照缓存）", version)
	}
	fresh, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("fresh snapshot: %v", err)
	}
	site, ok := fresh.NodeSites[registration.RegistrationID]
	if !ok {
		t.Fatalf("fresh snapshot NodeSites missing node %d（缓存未失效）", registration.RegistrationID)
	}
	if site.ServerMapLat != 35.19 || site.ServerMapLon != 108.87 {
		t.Fatalf("node site=%+v, want inherited master 35.19/108.87", site)
	}

	// 回归形状：upsert 覆盖既有节点同样 bump（拓扑语义变化）。
	token2, _, err := service.GenerateRegisterToken(context.Background(), 1, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("generate second token: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=20 WHERE id=1`); err != nil {
		t.Fatalf("reset version: %v", err)
	}
	if _, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token2, Name: "slave-a2", IPAddress: "10.0.0.2", Port: 8000,
	}, "10.0.0.2", now.Add(time.Minute)); err != nil {
		t.Fatalf("re-register node: %v", err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != 21 {
		t.Fatalf("cluster_version=%d after upsert registration, want 21", version)
	}
}

// ForgetNodePin 读址 SQL 必须带 SQL 级角色条件（同族 TOCTOU 唯一
// 漏点）——降级窗口命中 0 行时按 masterScopeMissError 复核语义返回
// ErrNotMasterNode，而不是继续删除主节点目录下的 pin 文件。
func TestClusterService_ForgetNodePin_requiresMasterRole(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,is_approved) VALUES (21,'slave-pin','10.0.0.21',8000,'http',1)`); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	pinPath, err := clusterPinPath("", database, "10.0.0.21:8000")
	if err != nil {
		t.Fatalf("resolve pin path: %v", err)
	}
	writePin := func() {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(pinPath), 0700); err != nil {
			t.Fatalf("mkdir pins: %v", err)
		}
		if err := os.WriteFile(pinPath, []byte("sha256-fingerprint\n"), 0600); err != nil {
			t.Fatalf("write pin: %v", err)
		}
	}

	// 目标形状：主节点 + 存在节点 + 有钉 → 删除成功（回归保护）。
	writePin()
	host, err := service.ForgetNodePin(context.Background(), 21)
	if err != nil {
		t.Fatalf("master forget pin: %v", err)
	}
	if host != "10.0.0.21:8000" {
		t.Fatalf("host=%q, want 10.0.0.21:8000", host)
	}
	if _, statErr := os.Stat(pinPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("pin file still exists after forget (err=%v)", statErr)
	}

	// 目标形状：降级为从节点后 → ErrNotMasterNode，pin 文件保留。
	writePin()
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if _, err := service.ForgetNodePin(context.Background(), 21); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("slave forget pin err=%v, want ErrNotMasterNode（SQL 级角色门）", err)
	}
	if _, statErr := os.Stat(pinPath); statErr != nil {
		t.Fatalf("pin file removed on slave (stat err=%v), want preserved", statErr)
	}

	// 回归形状：主节点 + 节点不存在 → ErrNodeNotFound 语义不变。
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if _, err := service.ForgetNodePin(context.Background(), 999); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("missing node err=%v, want ErrNodeNotFound", err)
	}
}

// （后端 no-op 门）：坐标无变化的保存不写库、不 bump cluster_version
// ——「打开弹框原样保存」不得放大为全集群快照重放。
func TestClusterService_UpdateNodeSiteCoordinates_noopDoesNotBump(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=7 WHERE id=1`); err != nil {
		t.Fatalf("seed version: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,is_approved,server_map_lat,server_map_lon) VALUES
		(2,'edge-a','slave','10.0.0.2',8000,1,31.23,121.47),
		(3,'edge-b','slave','10.0.0.3',8000,1,0,0)`); err != nil {
		t.Fatalf("seed nodes: %v", err)
	}
	readVersion := func() int {
		t.Helper()
		var version int
		if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
			t.Fatalf("read version: %v", err)
		}
		return version
	}

	// 目标形状：显式坐标原样保存 → no-op，版本不变、坐标不变。
	if err := service.UpdateNodeSiteCoordinates(context.Background(), 2, 31.23, 121.47); err != nil {
		t.Fatalf("noop save: %v", err)
	}
	if got := readVersion(); got != 7 {
		t.Fatalf("cluster_version=%d after noop save, want 7（无变更不得 bump）", got)
	}

	// 目标形状：继承节点（0,0）原样保存 → no-op（继承关系不被固化）。
	if err := service.UpdateNodeSiteCoordinates(context.Background(), 3, 0, 0); err != nil {
		t.Fatalf("inherited noop save: %v", err)
	}
	if got := readVersion(); got != 7 {
		t.Fatalf("cluster_version=%d after inherited noop save, want 7", got)
	}

	// 回归形状：真实变更仍写库并 bump。
	if err := service.UpdateNodeSiteCoordinates(context.Background(), 2, 40.19, 116.42); err != nil {
		t.Fatalf("changed save: %v", err)
	}
	if got := readVersion(); got != 8 {
		t.Fatalf("cluster_version=%d after changed save, want 8", got)
	}
	var lat, lon float64
	if err := database.QueryRow(`SELECT server_map_lat, server_map_lon FROM nodes WHERE id=2`).Scan(&lat, &lon); err != nil {
		t.Fatalf("read node site: %v", err)
	}
	if lat != 40.19 || lon != 116.42 {
		t.Fatalf("node site=(%v,%v), want (40.19,116.42)", lat, lon)
	}

	// 回归形状：从显式坐标改为 0,0（回到继承）是真实变更 → 写库 + bump。
	if err := service.UpdateNodeSiteCoordinates(context.Background(), 2, 0, 0); err != nil {
		t.Fatalf("clear to inherited: %v", err)
	}
	if got := readVersion(); got != 9 {
		t.Fatalf("cluster_version=%d after clear-to-inherited, want 9", got)
	}

	// 畸形/越界形状：节点不存在与已降级语义不变。
	if err := service.UpdateNodeSiteCoordinates(context.Background(), 999, 1, 2); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("missing node err=%v, want ErrNodeNotFound", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if err := service.UpdateNodeSiteCoordinates(context.Background(), 2, 5, 6); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("slave save err=%v, want ErrNotMasterNode", err)
	}
}

// 单连接池下写未命中：nodeWriteMissError 必须先用同一事务连接回滚复核，
// 不能持事务再取独立连接（池耗尽时会等满请求 ctx 才失败）。
func TestClusterService_UpdateNodeSiteCoordinates_missingNodeOnSingleConnPool(t *testing.T) {
	service, database := newClusterTestService(t)
	database.SetMaxOpenConns(1)
	// 让事务先占住唯一连接：节点不存在走 nodeWriteMissError 分支。
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := service.UpdateNodeSiteCoordinates(ctx, 999, 1, 2)
	if !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("err=%v, want ErrNodeNotFound（事务内独立连接会造成单连接池等待）", err)
	}
}

// 静态锚点：pin 路径推导命名核对（sha256(host) hex 文件名），
// 防止测试与生产路径推导漂移。
func TestClusterService_pinPathDerivationMatchesTOFUNaming(t *testing.T) {
	_, database := newClusterTestService(t)
	pinPath, host, err := nodePinPathFromAccessURL("", database, "http://10.0.0.21:8000")
	if err != nil {
		t.Fatalf("resolve pin path: %v", err)
	}
	want := sha256.Sum256([]byte("10.0.0.21:8000"))
	if filepath.Base(pinPath) != hex.EncodeToString(want[:]) || host != "10.0.0.21:8000" {
		t.Fatalf("pin path=%q host=%q, want sha256(host) naming", pinPath, host)
	}
}
