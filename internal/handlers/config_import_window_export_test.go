package handlers

// 导入窗口边界的两条契约：
//   - 导出端点与同族写者一样在导入窗口内 409 fast-fail（security 分类导出要取
//     WafFileLock，而导入全程持有该锁——不接门就会阻塞到导入结束）；
//   - begin 会话的动作用词随调用语义携带（还原路径不得记成「导入失败」）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestExportConfigBackup409DuringImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := newBackupSectionRouter(h)

	beginImportWindowForTest(t)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（导入窗口内导出必须 fast-fail，不得阻塞到导入结束）", rec.Code, rec.Body.String())
	}
}

func TestExportConfigBackupAllowedOutsideImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	overrideTestWafPaths(t)
	router := newBackupSectionRouter(h)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=rules", nil))
	if rec.Code == http.StatusConflict {
		t.Fatalf("status=409, want 非冲突（导入窗口外必须放行）: %s", rec.Body.String())
	}
}

func TestBeginConfigImportCarriesCallerAction(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)

	session, err := h.beginConfigImport(context.Background(), "还原")
	if err != nil {
		t.Fatal(err)
	}
	// 建会话前的失败审计（排空超时等）直接用该动作词——遗留空白会让还原路径
	// 记成「导入失败」。
	if session.action != "还原" {
		session.close()
		t.Fatalf("session.action=%q, want 还原（动作词必须随调用语义）", session.action)
	}
	// 会话锁串行：必须先释放才能开始第二个会话。
	session.close()

	// 缺省动作词兜底为「导入」，不得写出「失败」这种无主语文案。
	defaulted, err := h.beginConfigImport(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer defaulted.close()
	if defaulted.action != "导入" {
		t.Fatalf("session.action=%q, want 导入（空动作词兜底）", defaulted.action)
	}
}

func TestRunAutoBackupOnce_rejectsNonAbsoluteBackupDir(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	gin.SetMode(gin.TestMode)

	for _, dir := range []string{"", "relative/backups"} {
		h.cfg.BackupDir = dir
		_, err := h.RunAutoBackupOnce(context.Background(), "manual", "tester", 1)
		if err == nil {
			t.Fatalf("BackupDir=%q 必须 fail-fast（相对/空路径会在 CWD 上执行文件操作）", dir)
		}
		// 判据必须是入口守卫，而不是「MkdirAll 恰好失败」：相对路径在 CWD 下
		// 是可能创建成功的。
		if !strings.Contains(err.Error(), "绝对路径") {
			t.Fatalf("BackupDir=%q err=%v, want 入口守卫（绝对路径校验）", dir, err)
		}
	}
}
