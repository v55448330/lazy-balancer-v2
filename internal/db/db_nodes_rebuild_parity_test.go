package db

// nodes 整表重建的两条历史升级路径必须共用单源 DDL。
// 此前 migrateNodesDeadColumns / migrateNodesDropMasterID 各自手写一份，已文本
// 分叉（cluster_token_delivered DEFAULT 0 vs FALSE，列序不同），并有
// 漏列丢坐标先例。本测试钉住：两条路径产出的表形状逐列等于 fresh 稳态，
// 且重建保值。

import (
	"database/sql"
	"testing"
)

// legacyNodesRebuildFixture 建出「重建前」的 nodes 表：masterID 与 legacy sync
// 列由调用方按需拼入，其余列与重建拷贝清单一致（缺列会让 INSERT 直接报错，
// 也是单源清单的回归锚点）。
func legacyNodesRebuildFixture(t *testing.T, database *sql.DB, extraColumns, extraIndexes string) {
	t.Helper()
	if _, err := database.Exec(`CREATE TABLE nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		mode VARCHAR(10) NOT NULL DEFAULT 'slave',
		ip_address VARCHAR(45) NOT NULL,
		port INTEGER DEFAULT 8000,
		protocol VARCHAR(10) DEFAULT 'http',
		access_url VARCHAR(255) DEFAULT '',
		is_approved BOOLEAN DEFAULT FALSE,
		sync_interval INTEGER DEFAULT 60,
		status VARCHAR(20) DEFAULT 'offline',
		cluster_token_hash VARCHAR(64),
		registration_secret VARCHAR(64),
		registration_secret_expires_at DATETIME,
		cluster_token_delivered BOOLEAN DEFAULT FALSE,
		reported_version INTEGER DEFAULT 0,
		health_json TEXT,
		last_sync_at DATETIME,
		last_sync_error TEXT,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		server_map_lat REAL NOT NULL DEFAULT 0,
		server_map_lon REAL NOT NULL DEFAULT 0` + extraColumns + `,
		UNIQUE(ip_address, port)
	);` + extraIndexes); err != nil {
		t.Fatalf("create legacy nodes fixture: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,protocol,access_url,cluster_token_delivered,server_map_lat,server_map_lon)
		VALUES (5,'node-parity','slave','10.0.0.5',8123,'http','https://node.example',1,12.5,34.5)`); err != nil {
		t.Fatalf("seed legacy node: %v", err)
	}
}

// nodesPragmaShapeByName 读取 nodes 的列形并按列名索引（列序不参与比较：
// fresh 的 access_url 由 newColumns ALTER 追加在末尾，重建 DDL 内联在协议列后）。
func nodesPragmaShapeByName(t *testing.T, database *sql.DB) map[string]pragmaColumn {
	t.Helper()
	shape := make(map[string]pragmaColumn)
	for _, column := range tablePragmaShape(t, database, "nodes") {
		shape[column.Name] = column
	}
	return shape
}

func assertNodesShapeEqualsFresh(t *testing.T, fresh, rebuilt map[string]pragmaColumn) {
	t.Helper()
	if len(rebuilt) != len(fresh) {
		t.Fatalf("rebuilt nodes column count=%d, fresh=%d", len(rebuilt), len(fresh))
	}
	for name, want := range fresh {
		got, ok := rebuilt[name]
		if !ok {
			t.Fatalf("rebuilt nodes missing column %q", name)
		}
		if got != want {
			t.Fatalf("nodes column %q rebuilt=%+v, fresh=%+v（两条升级重建路径必须与 fresh 同形）", name, got, want)
		}
	}
}

func assertRebuiltNodeValues(t *testing.T, database *sql.DB) {
	t.Helper()
	var accessURL string
	var delivered, lat, lon float64
	if err := database.QueryRow(`SELECT access_url, cluster_token_delivered, server_map_lat, server_map_lon FROM nodes WHERE id=5`).
		Scan(&accessURL, &delivered, &lat, &lon); err != nil {
		t.Fatalf("read rebuilt node: %v", err)
	}
	if accessURL != "https://node.example" || delivered != 1 || lat != 12.5 || lon != 34.5 {
		t.Fatalf("rebuilt node values=(%q,%v,%v,%v), want preserved (access_url,delivered,lat,lon)", accessURL, delivered, lat, lon)
	}
}

func TestNodesRebuildPaths_shareFreshDDLShapeAndPreserveValues(t *testing.T) {
	// Given fresh 稳态形状（createTables + 启动迁移后的库）。
	preserveDatabaseHandles(t)
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize fresh database: %v", err)
	}
	freshShape := nodesPragmaShapeByName(t, DB)
	if err := Close(); err != nil {
		t.Fatalf("close fresh database: %v", err)
	}

	t.Run("legacy sync columns path", func(t *testing.T) {
		database := openMigrationTestDB(t)
		legacyNodesRebuildFixture(t, database, ",\n\t\tsync_enabled BOOLEAN DEFAULT 0,\n\t\tsync_scope VARCHAR(20) DEFAULT 'all'", "")
		if err := migrateNodesDeadColumns(); err != nil {
			t.Fatalf("migrate legacy nodes columns: %v", err)
		}
		assertNodesShapeEqualsFresh(t, freshShape, nodesPragmaShapeByName(t, database))
		assertRebuiltNodeValues(t, database)
	})

	t.Run("master_id dead column path", func(t *testing.T) {
		database := openMigrationTestDB(t)
		legacyNodesRebuildFixture(t, database, ",\n\t\tmaster_id INTEGER", ";\n\tCREATE INDEX idx_nodes_master ON nodes(master_id)")
		if err := migrateNodesDropMasterID(); err != nil {
			t.Fatalf("migrate nodes master_id: %v", err)
		}
		assertNodesShapeEqualsFresh(t, freshShape, nodesPragmaShapeByName(t, database))
		assertRebuiltNodeValues(t, database)
		if _, err := database.Exec(`SELECT master_id FROM nodes LIMIT 1`); err == nil {
			t.Fatal("master_id 死列应在重建后消失")
		}
	})
}
