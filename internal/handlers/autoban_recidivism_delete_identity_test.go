package handlers

// 单条移除累犯身份的两道处置正确性钉：
//  1. identity 归一——大写/完整形态 IPv6 与记账键（/64 归一）同键命中：
//     行删除 + 审计记录归一值（identity 经 AutobanEntryIdentity 单源）；
//     不存在身份仍幂等 200。
//  2. 守卫读+删除同事务（BEGIN IMMEDIATE）——守卫读与 DELETE 之间并发
//     merge 插入封禁条目必须被写锁拒绝，不得出现「守卫放行→封禁落库→
//     前科被删」的处置语义分裂（TOCTOU）。

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// Given 大写完整形态 IPv6 的累犯行（记账键为 /64 归一形态）+同键计数桶。
// When DELETE 路径参数为大写完整形态（URL 编码）。
// Then 200；归一身份行删除、计数桶清零、审计 detail 记归一值。
func TestAutobanRecidivism_deleteSingleUppercaseIPv6Normalizes(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	services.ResetAutobanCounters()
	const identity = "2606:4700:abcd:1234::"
	seedRecidivismTestRows(t) // 含 identity 行（offense_count=3）
	services.AutobanSeedCounterForTest(identity, 5, 3)

	rec := deleteRequest(t, router, "/security/autoban/recidivism/"+url.PathEscape("2606:4700:ABCD:1234:0:0:0:5"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity=?`, identity).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("归一身份行=%d, want 0（大写/完整形态必须归一命中删除）", n)
	}
	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("tracked_ips=%d, want 0（归一键清桶）", got)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='删除' AND resource='累犯记录' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	if !strings.Contains(detail, identity) {
		t.Fatalf("审计 detail=%q, want 含归一身份 %s", detail, identity)
	}
	if strings.Contains(detail, "ABCD") {
		t.Fatalf("审计 detail=%q, want 归一值（不得记录原始大写形态）", detail)
	}
}

// Given 大写完整形态 IPv6 的封禁条目（预置名单 /64 CIDR）+同键累犯行。
// When DELETE 大写完整形态身份。
// Then 400 封禁中守卫（守卫与删除同用归一键——不得因形态差异放行）。
func TestAutobanRecidivism_deleteSingleUppercaseIPv6BannedRejected(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)
	seedAutobanListEntries(t, `[{"value":"2606:4700:abcd:1234::/64","remark":"自动封禁"}]`)

	rec := deleteRequest(t, router, "/security/autoban/recidivism/"+url.PathEscape("2606:4700:ABCD:1234:0:0:0:5"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（封禁中守卫按归一键命中）", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='2606:4700:abcd:1234::'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("守卫拒绝后行必须保留, got %d", n)
	}
}

// Given 目标身份不存在。
// When DELETE 大写完整形态（归一后仍不存在）。
// Then 幂等 200（不存在也成功）。
func TestAutobanRecidivism_deleteSingleUppercaseIPv6Idempotent(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)
	rec := deleteRequest(t, router, "/security/autoban/recidivism/"+url.PathEscape("2606:4700:FFFF:9999:0:0:0:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（不存在幂等）", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 4 {
		t.Fatalf("table=%d rows, want 4（无关行不受影响）", n)
	}
}

// Given 累犯行（未封禁）。守卫读与 DELETE 之间并发 merge 提交封禁条目。
// When DELETE 单条（守卫+删除同一 BEGIN IMMEDIATE 事务）。
// Then 并发写在守卫读之后立即 SQLITE_BUSY（写锁屏障）——「守卫放行→
// 封禁落库→前科被删」的交错不可达；屏障解除后删除按已提交视图判定。
func TestAutobanRecidivism_deleteSingleGuardAndDeleteAtomic(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)
	const identity = "45.33.32.11"

	// 串行模拟交错：与 handler 同形态开 BEGIN IMMEDIATE 事务，守卫读
	//（预置名单 SELECT）完成后、DELETE 之前，并发写必须被写锁拒绝。
	ctx := context.Background()
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin guard tx: %v", err)
	}
	defer tx.Rollback()
	var presetID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, services.AutobanPresetListName).Scan(&presetID); err != nil {
		t.Fatalf("guard read preset: %v", err)
	}

	concurrent := openNoBusyWaitDB(t)
	_, err = concurrent.ExecContext(ctx, `UPDATE security_ip_lists SET entries=? WHERE id=?`,
		fmt.Sprintf(`[{"value":%q,"remark":"自动封禁"}]`, identity), presetID)
	if err == nil {
		t.Fatal("并发封禁写入在守卫读与删除之间完成——守卫+删除未同事务（TOCTOU：前科被删而封禁仍在）")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "locked") && !strings.Contains(strings.ToLower(err.Error()), "busy") {
		t.Fatalf("并发写错误=%v, want SQLITE_BUSY/locked（写锁屏障）", err)
	}

	// 事务内完成守卫判定+删除（与 handler 同口径）后提交。
	if _, err := tx.ExecContext(ctx, `DELETE FROM autoban_recidivism WHERE identity=?`, identity); err != nil {
		t.Fatalf("delete in tx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// 屏障解除后同一写入必须成功——证明失败确实来自写锁而非其他错误。
	if _, err := concurrent.ExecContext(ctx, `UPDATE security_ip_lists SET entries=? WHERE id=?`,
		fmt.Sprintf(`[{"value":%q,"remark":"自动封禁"}]`, identity), presetID); err != nil {
		t.Fatalf("write after commit: %v", err)
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity=?`, identity).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("行=%d, want 0（守卫放行时未封禁，删除生效）", n)
	}

	// HTTP 面回归：封禁条目已在 → 同身份 DELETE 必须 400（守卫按已提交视图）。
	rec := deleteRequest(t, router, "/security/autoban/recidivism/"+identity)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（封禁中拒绝移除）", rec.Code, rec.Body.String())
	}
}
