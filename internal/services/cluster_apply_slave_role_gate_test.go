package services

// 从端角色条件守卫：cluster_apply.go 中三处「节点本地列」
// UPDATE（同步开关镜像 sync_users/sync_rules/sync_security、大屏站点坐标
// server_map_lat/lon、同步间隔 sync_interval）只允许在从节点语境（is_master=0）
// 落库，条件必须引用单源标识符 slaveRoleConditionSQL（db.SlaveRoleConditionSQL
// 的包内别名，cluster_role_parity_test 已钉常量同源）——回退成手抄字面量谓词
// 或条件整体丢失，都会让「升主后在途从端写覆盖主端节点本地状态」这类 TOCTOU
// 重新打开。两层钉法：
//  1. AST 守卫：三处 UPDATE 的 SQL 实参树必须引用 slaveRoleConditionSQL 标识符；
//     任何 UPDATE global_config 的 SQL 文本出现 is_master 却未经单源标识符，即红；
//  2. 行为测：is_master=0 三处写入全部落库；升主（is_master=1）后同一写入
//     路径必须 0 行生效（列值保持不变）。

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// nodeLocalUpdateClauses 三处节点本地列写的判别子句——与被守卫语句的 SET 列
// 一一对应；cluster_apply.go 中任一语句丢失判别子句即「守卫对象漂移」。
var nodeLocalUpdateClauses = []struct{ clause, desc string }{
	{"sync_users=1", "同步开关镜像（sync_rules/sync_security）"},
	{"server_map_lat=?", "大屏站点坐标（server_map_lat/lon）"},
	{"sync_interval=?", "同步间隔（sync_interval）"},
}

// TestClusterApplySlaveRoleCondition_singleSourceOnNodeLocalUpdates AST 守卫：
// 三处节点本地列 UPDATE 必须引用 slaveRoleConditionSQL 标识符（不得回退成
// 字面量条件）；全文件任何 UPDATE global_config 的 SQL 文本含 is_master 却
// 未引用角色条件标识符（手抄谓词）同样红。
func TestClusterApplySlaveRoleCondition_singleSourceOnNodeLocalUpdates(t *testing.T) {
	source, err := os.ReadFile("cluster_apply.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "cluster_apply.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}

	type updateSite struct {
		line       int
		sqlText    string
		identNames map[string]bool
	}
	var sites []updateSite
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ExecContext" || len(call.Args) == 0 {
			return true
		}
		site := updateSite{line: fset.Position(call.Pos()).Line, identNames: map[string]bool{}}
		// 仓库口径 ExecContext(ctx, sql, args...)：跳过首个 ctx 型 Ident 实参，
		// 取 SQL 实参（裸 BasicLit 或 BasicLit+条件标识符的 BinaryExpr）。
		sqlArg := ast.Expr(call.Args[0])
		if len(call.Args) > 1 {
			if _, isIdent := call.Args[0].(*ast.Ident); isIdent {
				sqlArg = call.Args[1]
			}
		}
		ast.Inspect(sqlArg, func(arg ast.Node) bool {
			switch v := arg.(type) {
			case *ast.BasicLit:
				site.sqlText += v.Value
			case *ast.Ident:
				site.identNames[v.Name] = true
			}
			return true
		})
		if strings.Contains(site.sqlText, "UPDATE global_config") {
			sites = append(sites, site)
		}
		return true
	})
	if len(sites) == 0 {
		t.Fatal("cluster_apply.go 中未找到任何 UPDATE global_config 写入——守卫对象漂移")
	}

	for _, required := range nodeLocalUpdateClauses {
		matched := false
		for _, site := range sites {
			if !strings.Contains(site.sqlText, required.clause) {
				continue
			}
			matched = true
			if !site.identNames["slaveRoleConditionSQL"] {
				t.Errorf("cluster_apply.go:%d %s 的 UPDATE 未引用 slaveRoleConditionSQL 标识符（角色条件丢失或回退成字面量谓词）", site.line, required.desc)
			}
			break
		}
		if !matched {
			t.Errorf("cluster_apply.go 中找不到带 %q 的 UPDATE global_config——守卫对象漂移，请随重构更新判别子句", required.clause)
		}
	}

	for _, site := range sites {
		if strings.Contains(site.sqlText, "is_master") &&
			!site.identNames["slaveRoleConditionSQL"] && !site.identNames["masterRoleConditionSQL"] {
			t.Errorf("cluster_apply.go:%d 的 UPDATE global_config SQL 文本包含 is_master 却未引用 slaveRoleConditionSQL/masterRoleConditionSQL 单源标识符（手抄谓词回退）", site.line)
		}
	}
}

// TestClusterApplySlaveRoleCondition_gatesNodeLocalWritesByRole 行为测：
// 从节点（is_master=0）三处带角色条件的写入全部落库；升主（is_master=1）后
// 调用同一 applySnapshot 写入路径，三处写入必须 0 行生效（列值保持不变）。
func TestClusterApplySlaveRoleCondition_gatesNodeLocalWritesByRole(t *testing.T) {
	cluster, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })

	// 基线置 0（落库断言才可分辨「写入生效」与「默认值恰巧相同」）+ 本节点
	// 注册编号 3。角色保持默认主节点——ClusterService.Snapshot 是主节点操作
	// （「该操作仅允许在主节点执行」），生产时序即「主端产出快照 → 从端应用」。
	if _, err := database.Exec(`UPDATE global_config SET registration_id=3, sync_rules=0, sync_security=0`); err != nil {
		t.Fatal(err)
	}
	clusterSnapshotCaches.Delete(database)
	incoming, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	incoming.MasterSyncSwitches = &models.ClusterSyncSwitchesPayload{Users: true, Rules: true, Security: true}
	incoming.NodeSites = map[int]models.ClusterNodeSite{3: {ServerMapLat: 31.23, ServerMapLon: 121.47}}
	// 切到从节点形态后再应用快照（快照内容不含 is_master，节点本地列不入节哈希）。
	if _, err := database.Exec(`UPDATE global_config SET is_master=0`); err != nil {
		t.Fatal(err)
	}

	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	readNodeLocalColumns := func() (syncRules, syncSecurity int, lat, lon float64) {
		t.Helper()
		if err := database.QueryRow(`SELECT sync_rules, sync_security, server_map_lat, server_map_lon FROM global_config WHERE id=1`).Scan(&syncRules, &syncSecurity, &lat, &lon); err != nil {
			t.Fatal(err)
		}
		return syncRules, syncSecurity, lat, lon
	}

	// Phase A 从节点（is_master=0）：开关镜像与站点坐标落库。
	if err := syncService.applySnapshot(context.Background(), incoming); err != nil {
		t.Fatalf("从节点 applySnapshot: %v", err)
	}
	syncRules, syncSecurity, lat, lon := readNodeLocalColumns()
	if syncRules != 1 || syncSecurity != 1 {
		t.Fatalf("从节点开关镜像未落库: sync_rules=%d sync_security=%d", syncRules, syncSecurity)
	}
	if lat != 31.23 || lon != 121.47 {
		t.Fatalf("从节点站点坐标未落库: lat=%v lon=%v", lat, lon)
	}

	// Phase B 升主（is_master=1）：同一写入路径下发相反载荷，必须 0 行生效。
	if _, err := database.Exec(`UPDATE global_config SET is_master=1`); err != nil {
		t.Fatal(err)
	}
	incoming.MasterSyncSwitches = &models.ClusterSyncSwitchesPayload{Users: true, Rules: false, Security: false}
	incoming.NodeSites[3] = models.ClusterNodeSite{ServerMapLat: 40.71, ServerMapLon: -74.0}
	if err := syncService.applySnapshot(context.Background(), incoming); err != nil {
		t.Fatalf("升主后 applySnapshot: %v", err)
	}
	syncRules, syncSecurity, lat, lon = readNodeLocalColumns()
	if syncRules != 1 || syncSecurity != 1 {
		t.Fatalf("升主后开关镜像仍被写入（角色条件失效）: sync_rules=%d sync_security=%d", syncRules, syncSecurity)
	}
	if lat != 31.23 || lon != 121.47 {
		t.Fatalf("升主后站点坐标仍被写入（角色条件失效）: lat=%v lon=%v", lat, lon)
	}
}

// TestReplaceSnapshotTxSlaveRoleCondition_gatesSyncIntervalByRole 行为测（事务层
// 口径，同步间隔写在 replaceSnapshotTx 内）：users 节 unchanged 命中 else 分支
// 时，sync_interval 的角色条件 UPDATE 在从节点落库、升主后 0 行生效。
func TestReplaceSnapshotTxSlaveRoleCondition_gatesSyncIntervalByRole(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	apply := func(snapshot models.ClusterSnapshot) {
		t.Helper()
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		skip := &sectionSkips{
			disabled:  map[string]bool{"rules": true, "security": true},
			unchanged: map[string]bool{"users": true},
		}
		if err := replaceSnapshotTx(ctx, tx, snapshot, skip); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	readSyncInterval := func() int {
		t.Helper()
		var got int
		if err := database.QueryRow(`SELECT sync_interval FROM global_config WHERE id=1`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	// 从节点（is_master=0）：sync_interval 落库（77 非默认值，可分辨生效）。
	if _, err := database.Exec(`UPDATE global_config SET is_master=0`); err != nil {
		t.Fatal(err)
	}
	slaveInterval := 77
	slave := models.ClusterSnapshot{Version: 1, Fingerprint: "guard-slave-fp"}
	slave.BasicSettings.SyncInterval = &slaveInterval
	apply(slave)
	if got := readSyncInterval(); got != slaveInterval {
		t.Fatalf("从节点 sync_interval 未落库: got=%d want=%d", got, slaveInterval)
	}

	// 升主（is_master=1）：0 行生效，列值保持从节点最后落库值。
	if _, err := database.Exec(`UPDATE global_config SET is_master=1`); err != nil {
		t.Fatal(err)
	}
	masterInterval := 99
	master := models.ClusterSnapshot{Version: 2, Fingerprint: "guard-master-fp"}
	master.BasicSettings.SyncInterval = &masterInterval
	apply(master)
	if got := readSyncInterval(); got != slaveInterval {
		t.Fatalf("升主后 sync_interval 仍被写入（角色条件失效）: got=%d want=%d", got, slaveInterval)
	}
}
