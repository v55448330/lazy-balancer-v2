package services

// 累犯表（autoban_recidivism）集群同步钉测——A+C 阶段 5：
//   - 主端快照恒携带累犯表（空表 []，非空逐行四列）；
//   - 累犯行变化必须翻转 security 节哈希（全量与漂移守卫轻量重建同口径）；
//   - 从端 apply 整表替换：本地漂移行收敛到主端；缺席=保留本地、空 []=清空；
//   - apply 后从端重建 security 节哈希与主端一致（哈希奇偶不变式）；
//   - 二次 apply 哈希一致跳过，累犯行不被重复改写；
//   - 会话封禁本地态：不进快照、不进 security 节哈希（阶段 3 契约固化）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// recidivismRow 是累犯表行的测试观测形态（四列全量）。
type recidivismRow struct {
	Identity  string `json:"identity"`
	Offenses  int    `json:"offense_count"`
	LastBan   string `json:"last_ban_at"`
	Escalated string `json:"escalated_duration"`
}

// readRecidivismRows 按 identity 序读全表（与 dump ORDER BY identity 同序）。
func readRecidivismRows(t *testing.T, database *sql.DB) []recidivismRow {
	t.Helper()
	rows, err := database.Query(`SELECT identity, offense_count, last_ban_at, escalated_duration FROM autoban_recidivism ORDER BY identity`)
	if err != nil {
		t.Fatalf("read recidivism: %v", err)
	}
	defer rows.Close()
	out := make([]recidivismRow, 0)
	for rows.Next() {
		var r recidivismRow
		if err := rows.Scan(&r.Identity, &r.Offenses, &r.LastBan, &r.Escalated); err != nil {
			t.Fatalf("scan recidivism: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate recidivism: %v", err)
	}
	return out
}

// seedRecidivismRows 播种主端累犯行（含 /64 归一身份与复合键之外的裸 IPv4）。
func seedRecidivismRows(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES
		('2606:4700:abcd:1234::', 3, '2026-11-15 10:00:00', 'permanent'),
		('45.33.32.10', 2, '2026-11-14 09:00:00', '24h')`); err != nil {
		t.Fatalf("seed recidivism: %v", err)
	}
}

// Given 主端累犯表两行（/64 归一身份 + IPv4）。
// When 构建全量快照。
// Then 快照携带 autoban_recidivism 载荷，逐行四列与主端库一致。
func TestClusterSnapshot_carriesAutobanRecidivism(t *testing.T) {
	cluster, database := newClusterTestService(t)
	seedRecidivismRows(t, database)

	snapshot, err := cluster.buildFullSnapshot(context.Background(), database)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.AutobanRecidivism == nil {
		t.Fatal("快照必须携带累犯表载荷（缺席=旧主端语义，新主端恒携带）")
	}
	var rows []recidivismRow
	if err := json.Unmarshal(snapshot.AutobanRecidivism, &rows); err != nil {
		t.Fatalf("解析累犯载荷: %v", err)
	}
	want := readRecidivismRows(t, database)
	if len(rows) != len(want) {
		t.Fatalf("累犯载荷行数=%d, want %d", len(rows), len(want))
	}
	for i, r := range rows {
		if r != want[i] {
			t.Fatalf("累犯行 %d=%+v, want %+v", i, r, want[i])
		}
	}
	// 线格式键：security 节顶层键名固定（从端按裸列名取值）。
	if !strings.Contains(string(snapshot.AutobanRecidivism), `"identity"`) ||
		!strings.Contains(string(snapshot.AutobanRecidivism), `"offense_count"`) ||
		!strings.Contains(string(snapshot.AutobanRecidivism), `"last_ban_at"`) ||
		!strings.Contains(string(snapshot.AutobanRecidivism), `"escalated_duration"`) {
		t.Fatalf("累犯载荷缺四列键: %s", snapshot.AutobanRecidivism)
	}
}

// Given 空累犯表（全体身份首次档）。
// When 构建全量快照。
// Then 载荷为显式空数组 []（携带即全量替换语义——从端据此清空本地残留）。
func TestClusterSnapshot_emptyRecidivismCarriesEmptyArray(t *testing.T) {
	cluster, database := newClusterTestService(t)

	snapshot, err := cluster.buildFullSnapshot(context.Background(), database)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if string(snapshot.AutobanRecidivism) != "[]" {
		t.Fatalf("空累犯表载荷=%s, want []（显式清空语义）", snapshot.AutobanRecidivism)
	}
}

// Given 主端累犯表一行。
// When 仅改动累犯行（其余 security 表域不动）。
// Then security 节哈希翻转——全量快照与漂移守卫轻量重建同口径（奇偶不变式）。
func TestSecuritySectionHash_recidivismChangeFlipsHash(t *testing.T) {
	cluster, database := newClusterTestService(t)
	ctx := context.Background()
	seedRecidivismRows(t, database)

	before, err := cluster.buildFullSnapshot(ctx, database)
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	guardBefore, err := cluster.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatalf("drift guard before: %v", err)
	}
	if before.SectionHashes["security"] != guardBefore["security"] {
		t.Fatalf("基线哈希奇偶分裂：full=%s guard=%s", before.SectionHashes["security"], guardBefore["security"])
	}

	if _, err := database.Exec(`UPDATE autoban_recidivism SET offense_count=offense_count+1 WHERE identity='45.33.32.10'`); err != nil {
		t.Fatal(err)
	}

	after, err := cluster.buildFullSnapshot(ctx, database)
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	guardAfter, err := cluster.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatalf("drift guard after: %v", err)
	}
	if after.SectionHashes["security"] == before.SectionHashes["security"] {
		t.Fatal("累犯行变化必须翻转 security 节哈希（否则从端经哈希跳过门永不收敛）")
	}
	if after.SectionHashes["security"] != guardAfter["security"] {
		t.Fatalf("累犯变化后哈希奇偶分裂：full=%s guard=%s", after.SectionHashes["security"], guardAfter["security"])
	}
}

// Given 主端累犯表两行；从端本地漂移（多余行 + 同身份不同计数）。
// When 从端 apply 主端快照。
// Then 累犯表整表替换为主端形态（漂移行清除、计数收敛）。
func TestClusterSync_recidivismRoundTrip(t *testing.T) {
	cluster, database, syncService, bump := syncSemanticsEnv(t)
	ctx := context.Background()
	seedRecidivismRows(t, database)
	bump(300)

	snap := snapshotAsMaster(t, cluster, database)
	// 从端本地漂移：多余身份 + 同身份计数/时长漂移。
	if _, err := database.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES ('45.33.32.99', 9, '2026-11-01 00:00:00', 'permanent')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE autoban_recidivism SET offense_count=1, escalated_duration='1h' WHERE identity='45.33.32.10'`); err != nil {
		t.Fatal(err)
	}
	if err := syncService.applySnapshot(ctx, snap); err != nil {
		t.Fatalf("apply: %v", err)
	}

	got := readRecidivismRows(t, database)
	want := []recidivismRow{
		{Identity: "2606:4700:abcd:1234::", Offenses: 3, LastBan: "2026-11-15 10:00:00", Escalated: "permanent"},
		{Identity: "45.33.32.10", Offenses: 2, LastBan: "2026-11-14 09:00:00", Escalated: "24h"},
	}
	if len(got) != len(want) {
		t.Fatalf("apply 后累犯表=%+v, want %+v（整表替换，漂移行必须清除）", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("apply 后累犯行 %d=%+v, want %+v", i, got[i], want[i])
		}
	}
}

// Given 主端累犯表非空。
// When 从端 apply 后按本地库重建 security 节哈希。
// Then 与主端节哈希一致（下发值/哈希输入/从端落库值三面同源）。
func TestSecuritySectionHash_recidivismParityAfterApply(t *testing.T) {
	cluster, database := newClusterTestService(t)
	ctx := context.Background()
	seedRecidivismRows(t, database)

	snapshot, _, err := cluster.Snapshot(ctx, 0, "", "cluster-token")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	masterHash := snapshot.SectionHashes["security"]
	if masterHash == "" {
		t.Fatal("security 节哈希缺失")
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applySecurityTables(ctx, tx, snapshot, true); err != nil {
		_ = tx.Rollback()
		t.Fatalf("apply security tables: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	local, err := cluster.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if local["security"] != masterHash {
		t.Fatalf("累犯同步后 security 节哈希主从不一致：master=%s local=%s", masterHash, local["security"])
	}
}

// Given 旧主端快照不携带累犯载荷（nil）。
// When 从端 apply。
// Then 本地累犯行保留（缺席=保留本地，与威胁源/爬虫源 nil 门同口径）。
func TestApplySecurityTables_recidivismAbsentPreservesLocal(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	seedRecidivismRows(t, database)

	snapshot := models.ClusterSnapshot{} // AutobanRecidivism=nil（旧主端形态）
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applySecurityTables(ctx, tx, snapshot, true); err != nil {
		_ = tx.Rollback()
		t.Fatalf("apply: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if got := readRecidivismRows(t, database); len(got) != 2 {
		t.Fatalf("缺席载荷必须保留本地累犯行, got %+v", got)
	}
}

// Given 从端本地有累犯行；主端快照携带空数组 []（主端已清空）。
// When 从端 apply。
// Then 本地累犯表清空（携带即全量替换，空载荷=显式清空）。
func TestApplySecurityTables_recidivismEmptyClearsLocal(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	seedRecidivismRows(t, database)

	snapshot := models.ClusterSnapshot{AutobanRecidivism: json.RawMessage(`[]`)}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applySecurityTables(ctx, tx, snapshot, true); err != nil {
		_ = tx.Rollback()
		t.Fatalf("apply: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if got := readRecidivismRows(t, database); len(got) != 0 {
		t.Fatalf("空载荷必须清空本地累犯表, got %+v", got)
	}
}

// Given 主端累犯表非空，从端首次 apply 已收敛。
// When 仅版本号 +1 的第二次 apply（security 节哈希一致）。
// Then security 节哈希跳过，累犯行保持主端形态（不被重复改写）。
func TestClusterSync_recidivismSecondApplySkipsUnchanged(t *testing.T) {
	cluster, database, syncService, bump := syncSemanticsEnv(t)
	ctx := context.Background()
	seedRecidivismRows(t, database)
	bump(300)
	snap := snapshotAsMaster(t, cluster, database)
	if err := syncService.applySnapshot(ctx, snap); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	bump(301)
	snap2 := snapshotAsMaster(t, cluster, database)
	if err := syncService.applySnapshot(ctx, snap2); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	details := syncAuditDetails(t, "同步")
	if len(details) == 0 {
		t.Fatal("第二次应用应产生同步汇总行")
	}
	if !strings.Contains(details[len(details)-1], "哈希一致") {
		t.Fatalf("累犯未变时 security 节必须哈希一致跳过: %s", details[len(details)-1])
	}
	if got := readRecidivismRows(t, database); len(got) != 2 {
		t.Fatalf("跳过重放后累犯行必须保持, got %+v", got)
	}
}

// Given 会话封禁在役（复合键）+ 累犯表一行。
// When 构建全量快照。
// Then 快照不携带会话封禁（本地短 TTL 态），且会话封禁写入/到期不翻转
// security 节哈希（本地态不得引发集群重放）；累犯表照常携带。
func TestClusterSnapshot_sessionBanLocalStateNotSynced(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	sessionBanTestFile(t)
	seedRecidivismRows(t, db.GetDB())
	cluster, database := newClusterTestService(t)
	ctx := context.Background()

	key := autobanIdentityKey("45.33.32.113", "c:evil")
	autobanBanSession(key)

	snapshot, err := cluster.buildFullSnapshot(ctx, database)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "c:evil") || strings.Contains(string(raw), "session_ban") {
		t.Fatal("集群快照不得携带会话封禁（本地态不跨节点同步）")
	}
	if snapshot.AutobanRecidivism == nil {
		t.Fatal("会话封禁本地态不得影响累犯表携带")
	}

	// 会话封禁到期清扫后会话态消失——security 节哈希必须不变。
	hashBefore := snapshot.SectionHashes["security"]
	autobanMu.Lock()
	autobanSweepSessionBansLocked(autobanNow().Add(2 * time.Hour))
	autobanMu.Unlock()
	after, err := cluster.buildFullSnapshot(ctx, database)
	if err != nil {
		t.Fatalf("snapshot after sweep: %v", err)
	}
	if after.SectionHashes["security"] != hashBefore {
		t.Fatal("会话封禁是本地态：其变化不得翻转 security 节哈希（否则每会话封禁引发全集群重放）")
	}
}
