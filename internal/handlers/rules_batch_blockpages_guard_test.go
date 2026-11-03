package handlers

// BatchRuleBlockPages 的逐规则 UPDATE 必须带同值守卫——
// 修复前同值批量（拦截页/状态码未变）同样 UPDATE 命中全部行，触发 lb_rules
// 行级同步触发器（阶段页四列在 OF 清单内）→ 同值操作引发全集群快照重放。
// bound 改按 RowsAffected>0 计（真实变更），同值命中计入
// unchanged——修复前同值批量仍报 bound=N，把零写入算作成功。同值批量仍零写入。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestBatchRuleBlockPages_alwaysZeroWrite(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)
	installStagePageWriteTally(t)

	for _, body := range []string{
		`{"rule_ids":["lb_b1","lb_b2","lb_b3"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`,
		`{"rule_ids":["lb_b1","lb_b2","lb_b3"],"block_page_stage1_id":7,"block_page_stage1_status":404,"block_page_stage3_id":7,"block_page_stage3_status":503}`,
	} {
		response := postStageJSON(t, router, "/rules/batch-block-pages", body)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		if bound, unchanged, skipped := batchResultAll(t, response); bound != 0 || unchanged != 3 || len(skipped) != 0 {
			t.Fatalf("bound=%d unchanged=%d skipped=%v, want 0/3/0", bound, unchanged, skipped)
		}
	}
	if n := stagePageWriteCount(t); n != 0 {
		t.Fatalf("停用端点触发 %d 次阶段页列写（应 0 次）", n)
	}
	for _, id := range []string{"lb_b1", "lb_b2", "lb_b3"} {
		if s1, s1s, s3, s3s := stageColumnsByID(t, id); s1 != 0 || s1s != 0 || s3 != 0 || s3s != 0 {
			t.Fatalf("%s stage columns=(%d,%d,%d,%d), want all zero", id, s1, s1s, s3, s3s)
		}
	}
}
func TestBatchRuleBlockPages_rejectsOversizedBody(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)
	body := `{"rule_ids":["lb_b1"],"padding":"` + strings.Repeat("x", 1<<20) + `"}`
	response := postStageJSON(t, router, "/rules/batch-block-pages", body)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s, want 413（独立 1MB 上限）", response.Code, response.Body.String())
	}
}

// chunked/未知长度（ContentLength=-1）的超限请求体必须同样映射 413：
// MaxBytesReader 在解析期截断，错误不得被统一折成「请求参数无效」——
// 按 413 做重试/降级策略的客户端否则会误判为参数错误。
func TestBatchRuleBlockPages_rejectsOversizedChunkedBody(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)
	body := `{"rule_ids":["lb_b1"],"padding":"` + strings.Repeat("x", 1<<20) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/rules/batch-block-pages", io.NopCloser(strings.NewReader(body)))
	request.ContentLength = -1 // 模拟 chunked：快路径拿不到长度
	request.TransferEncoding = []string{"chunked"}
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s, want 413（chunked 超限不得折成参数错误）", response.Code, response.Body.String())
	}
}

// batchResultWithUnchanged 解析批量阶段页响应的 bound/unchanged/skipped
// （新增 unchanged：RowsAffected=0 的同值命中）。
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
