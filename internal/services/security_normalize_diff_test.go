package services

import (
	"context"
	"strconv"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 启动归一改写的字段必须逐策略留痕：只报总条数无法回答「哪条策略的异常阈值/
// 拦截状态码被改了、从什么值改成什么值」（旧备份/带外脏值的排障与审计场景）。
func TestSecurityEnumNormalizedChanges_reportsThresholdAndBlockStatus(t *testing.T) {
	setupIsolatedDB(t)

	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, geoip_mode, anomaly_threshold, block_status_code)
		VALUES ('legacy-threshold', 'blocking', 'deny', 'deny', 0, 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, geoip_mode, anomaly_threshold, block_status_code)
		VALUES ('legacy-status', 'blocking', 'deny', 'deny', 5, 429)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, geoip_mode, anomaly_threshold, block_status_code)
		VALUES ('clean-row', 'blocking', 'deny', 'deny', 10, 403)`); err != nil {
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
	if len(before) != 2 {
		t.Fatalf("脏行快照=%d 条, want 2（阈值/状态码脏行必须进入快照，合法行不入）: %+v", len(before), before)
	}

	// 与 legacySecurityEnumBackfills 同形的两条归一语句
	if _, err := tx.Exec(`UPDATE security_policies SET anomaly_threshold=` + strconv.Itoa(db.DefaultAnomalyThreshold) + ` WHERE COALESCE(anomaly_threshold,0)<=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE security_policies SET block_status_code=` + strconv.Itoa(db.DefaultBlockStatusCode) + ` WHERE block_status_code IS NOT NULL AND block_status_code NOT IN (0,400,401,` + strconv.Itoa(db.DefaultBlockStatusCode) + `,404,503)`); err != nil {
		t.Fatal(err)
	}

	changes, err := securityEnumNormalizedChanges(context.Background(), tx, before)
	if err != nil {
		t.Fatal(err)
	}
	byField := map[string]securityEnumChange{}
	for _, ch := range changes {
		byField[ch.name+"/"+ch.field] = ch
	}
	threshold, ok := byField["legacy-threshold/anomaly_threshold"]
	if !ok {
		t.Fatalf("异常阈值归一必须产出逐策略记录: %+v", changes)
	}
	if threshold.from != "0" || threshold.to != strconv.Itoa(db.DefaultAnomalyThreshold) {
		t.Fatalf("阈值记录 from/to=%q→%q, want 0→%d", threshold.from, threshold.to, db.DefaultAnomalyThreshold)
	}
	status, ok := byField["legacy-status/block_status_code"]
	if !ok {
		t.Fatalf("拦截状态码归一必须产出逐策略记录: %+v", changes)
	}
	if status.from != "429" || status.to != strconv.Itoa(db.DefaultBlockStatusCode) {
		t.Fatalf("状态码记录 from/to=%q→%q, want 429→%d", status.from, status.to, db.DefaultBlockStatusCode)
	}
	// 合法行零记录
	for _, ch := range changes {
		if ch.name == "clean-row" {
			t.Fatalf("合法行不得产出归一记录: %+v", ch)
		}
	}
}
