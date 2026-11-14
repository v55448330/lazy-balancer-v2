package handlers

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

// 热路径 Converged 收尾的提交失败分支必须走统一补发 ROLLBACK（rollbackLeakedTx）
// 而不是自造 tx.Rollback 后吞掉 ErrTxDone：Commit 失败后 database/sql 不再调用
// driver.Rollback，遗留事务会滞留写锁并让复用连接看到未提交内容。
func TestIPListHotPath_convergedCommitFailureSupplementsRollbackOnce(t *testing.T) {
	withIsolatedGlobal(t)
	restoreRollback := rollbackLeakedTx
	calls := 0
	rollbackLeakedTx = func() {
		calls++
		restoreRollback()
	}
	t.Cleanup(func() { rollbackLeakedTx = restoreRollback })

	f := newHotPathIPListFixture(t)
	listID, policyID := f.seedReferencedList(`[{"value":"203.0.113.5","remark":""}]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	committed := f.projectionContent(policyID)
	installIPListCommitFailure(t)

	rec := f.postJSON(fmt.Sprintf("/security/ip-lists/%d/ips", listID), map[string]string{"value": "198.51.100.7"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "injected commit failure") {
		t.Fatalf("提交失败错误被吞掉: %s", rec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("统一补发 ROLLBACK 调用 %d 次, want 1（自造 tx.Rollback 吞 ErrTxDone 的旧实现为 0）", calls)
	}
	if got := f.projectionContent(policyID); got != committed {
		t.Fatalf("提交失败后投影=%q, want 已提交内容 %q", got, committed)
	}
	assertCommittedHotPathList(t, listID)
}

// 源码钉测：Converged 提交失败分支不得再自造 tx.Rollback（会吞 ErrTxDone 且
// 泄漏事务无人释放）。切片终点取下一个顶层声明边界，避免注释终点造成假绿。
func TestIPListHotPath_convergedCommitFailureHasNoInlineRollback(t *testing.T) {
	source, err := os.ReadFile("securityiplists.go")
	if err != nil {
		t.Fatalf("read securityiplists.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func (h *Handlers) tryIPListHotPathApply(")
	if start < 0 {
		t.Fatal("tryIPListHotPathApply 不存在")
	}
	end := strings.Index(text[start:], "\n// ExportIPList")
	if end < 0 {
		t.Fatal("缺少函数尾部边界（ExportIPList）")
	}
	body := text[start : start+end]
	if strings.Contains(body, "tx.Rollback()") {
		t.Fatal("热路径收尾仍自造 tx.Rollback（提交失败分支必须由 rollbackLeakedTx 统一补发）")
	}
	if got := strings.Count(body, "rollbackLeakedTx()"); got != 1 {
		t.Fatalf("rollbackLeakedTx() 调用 %d 处, want 1", got)
	}
}
