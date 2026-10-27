package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 限流关停是保护面收窄，与 mode→off 同型：必须逐策略留痕（快照包含
// rate_limit_enabled；rate_limit_rps 只作关停判据、不被任何回填语句改写），
// 否则审计中心只剩一条「归一了 N 行」的计数，无法回答「哪条策略被关了限流」。
func TestSecurityEnumNormalizedChanges_reportsRateLimitShutdown(t *testing.T) {
	setupIsolatedDB(t)

	// 带外脏行：限流启用但 rps<1（写侧校验恒拒绝该形态，只能来自旧版本/带外）。
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, geoip_mode, rate_limit_enabled, rate_limit_rps)
		VALUES ('legacy-rate', 'blocking', 'deny', 'deny', 1, 0)`); err != nil {
		t.Fatal(err)
	}

	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	before, err := securityEnumDirtyRows(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("脏行快照=%d 条, want 1（限流脏行必须进入快照）", len(before))
	}

	if _, err := tx.Exec(`UPDATE security_policies SET rate_limit_enabled=0 WHERE rate_limit_enabled=1 AND COALESCE(rate_limit_rps,0)<1`); err != nil {
		t.Fatal(err)
	}
	changes, err := securityEnumNormalizedChanges(context.Background(), tx, before)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ch := range changes {
		if ch.field == "rate_limit_enabled" && ch.from == "1" && ch.to == "0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("限流关停必须产出逐策略变更记录: %+v", changes)
	}
	// rps 列在同一事务内不被改写（只作关停判据）——「前快照==后回读」恒成立，
	// 该比较项是不可达分支，不得出现在变更记录里。
	for _, ch := range changes {
		if ch.field == "rate_limit_rps" {
			t.Fatalf("rate_limit_rps 不是归一目标，不得产出变更记录（不可达比较项）: %+v", changes)
		}
	}
}
