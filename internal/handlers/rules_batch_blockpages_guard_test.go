package handlers

// 第 49 轮 F49-P5-13：BatchRuleBlockPages 的逐规则 UPDATE 必须带同值守卫——
// 修复前同值批量（拦截页/状态码未变）同样 UPDATE 命中全部行，触发 lb_rules
// 行级同步触发器（阶段页四列在 OF 清单内）→ 同值操作引发全集群快照重放。
// U04-06（第 78 轮）：bound 改按 RowsAffected>0 计（真实变更），同值命中计入
// unchanged——修复前同值批量仍报 bound=N，把零写入算作成功。同值批量仍零写入。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// installStagePageWriteTally 安装与 cluster_version_lb_rules_update 同事件
// （UPDATE OF 阶段页四列）的写计数触发器并清零。
func installStagePageWriteTally(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`DROP TRIGGER IF EXISTS tally_stage_pages_update;
		CREATE TABLE IF NOT EXISTS stage_page_write_tally (n INTEGER);
		DELETE FROM stage_page_write_tally;
		CREATE TRIGGER tally_stage_pages_update
		AFTER UPDATE OF block_page_stage1_id,block_page_stage1_status,block_page_stage3_id,block_page_stage3_status ON lb_rules
		BEGIN INSERT INTO stage_page_write_tally VALUES (1); END`); err != nil {
		t.Fatalf("install tally trigger: %v", err)
	}
}

func stagePageWriteCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM stage_page_write_tally`).Scan(&count); err != nil {
		t.Fatalf("read tally: %v", err)
	}
	return count
}

func TestBatchRuleBlockPages_sameValueZeroWrite(t *testing.T) {
	// Given：3 条 http 规则 + 拦截页 7；首次批量设置阶段页落库
	handler, _ := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)
	first := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1","lb_b2","lb_b3"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first batch status=%d body=%s", first.Code, first.Body.String())
	}
	if bound, unchanged, skipped := batchResultWithUnchanged(t, first); bound != 3 || unchanged != 0 || len(skipped) != 0 {
		t.Fatalf("first batch bound=%d unchanged=%d skipped=%v, want bound=3 unchanged=0", bound, unchanged, skipped)
	}
	installStagePageWriteTally(t)

	// When 1：同值批量（拦截页/状态码完全未变）
	second := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1","lb_b2","lb_b3"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)

	// Then 1：同值规则进 unchanged、bound=0（不再把零写入算作成功）且阶段页四列零写入
	if second.Code != http.StatusOK {
		t.Fatalf("same-value batch status=%d body=%s", second.Code, second.Body.String())
	}
	if bound, unchanged, skipped := batchResultWithUnchanged(t, second); bound != 0 || unchanged != 3 || len(skipped) != 0 {
		t.Fatalf("same-value batch bound=%d unchanged=%d skipped=%v, want bound=0 unchanged=3 skipped=0（同值不是跳过理由）", bound, unchanged, skipped)
	}
	if n := stagePageWriteCount(t); n != 0 {
		t.Fatalf("同值批量触发 %d 次阶段页列写（应 0 次——零写入零同步 bump）", n)
	}

	// When 2：真实变更（阶段 1 状态码 403→404）
	third := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1","lb_b2","lb_b3"],"block_page_stage1_id":7,"block_page_stage1_status":404,"block_page_stage3_id":7,"block_page_stage3_status":503}`)

	// Then 2：照常落库（三行各一次写）
	if third.Code != http.StatusOK {
		t.Fatalf("changed batch status=%d body=%s", third.Code, third.Body.String())
	}
	if bound, _ := batchResult(t, third); bound != 3 {
		t.Fatalf("changed batch bound=%d, want 3", bound)
	}
	if n := stagePageWriteCount(t); n != 3 {
		t.Fatalf("真实变更触发 %d 次写（应 3=三条规则各 UPDATE 一次）", n)
	}
	var status int
	if err := db.DB.QueryRow(`SELECT block_page_stage1_status FROM lb_rules WHERE caddy_id='lb_b1'`).Scan(&status); err != nil || status != 404 {
		t.Fatalf("变更未落库：status=%d err=%v, want 404", status, err)
	}
}

// batchResultWithUnchanged 解析批量阶段页响应的 bound/unchanged/skipped
// （U04-06 新增 unchanged：RowsAffected=0 的同值命中）。
func batchResultWithUnchanged(t *testing.T, recorder *httptest.ResponseRecorder) (int, int, []map[string]any) {
	t.Helper()
	var payload struct {
		Data struct {
			Bound     int              `json:"bound"`
			Unchanged int              `json:"unchanged"`
			Skipped   []map[string]any `json:"skipped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode batch result: %v (body=%s)", err, recorder.Body.String())
	}
	return payload.Data.Bound, payload.Data.Unchanged, payload.Data.Skipped
}
