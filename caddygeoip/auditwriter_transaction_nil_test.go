package caddygeoip

import (
	"encoding/json"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// Write 对 Transaction 的 nil 判定必须与 snapshotAuditLog 同门（isNilInterface）：
// typed-nil 事务（接口非 nil 但底层指针为 nil）若被裸 != nil 放行，随后的
// HasRequest() 会解引用空指针 panic——审计写插件在 coraza defer ProcessLogging
// 里执行，panic 直接打断请求收尾。本门用 typed-nil 事务驱动真实 Write 路径，
// 断言不 panic 且审计行照常入队落盘（事务段按缺失处理）。

// typedNilTx 是「访问器解引用接收者」的事务实现（与 coraza 活事务同形：
// 方法读 t 的字段）。typed-nil 时 HasRequest() 解引用空指针——正是裸 != nil
// 放行 typed-nil 后的崩溃点。嵌入 nil 接口补足快照路径会调用的其余访问器
// （快照侧对 typed-nil 有 isNilInterface 门，不会真正调用它们）。
type typedNilTx struct {
	plugintypes.AuditLogTransaction
	hasRequest bool
}

func (t *typedNilTx) HasRequest() bool { return t.hasRequest }

// typedNilTxAuditLog 携带 typed-nil 事务的最小 AuditLog。
type typedNilTxAuditLog struct {
	plugintypes.AuditLog
}

func (typedNilTxAuditLog) Parts() types.AuditLogParts { return nil }
func (typedNilTxAuditLog) Transaction() plugintypes.AuditLogTransaction {
	return (*typedNilTx)(nil)
}
func (typedNilTxAuditLog) Messages() []plugintypes.AuditLogMessage { return nil }

func TestAuditWriterWrite_typedNilTransactionIsNoPanic(t *testing.T) {
	useTestAuditPipeline(t)
	logPath := t.TempDir() + "/audit.log"
	capture := &captureFormatter{ch: make(chan plugintypes.AuditLog, 1)}
	w := &lbAuditWriter{}
	if err := w.Init(plugintypes.AuditLogConfig{Target: logPath, FileMode: 0o644, Formatter: capture}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Given typed-nil 事务；When Write（生产在 ProcessLogging defer 内调用）。
	// Then 不得 panic（裸 != nil 会在此解引用空指针）。
	if err := w.Write(typedNilTxAuditLog{}); err != nil {
		t.Fatalf("Write(typed-nil tx) must be best-effort nil error, got %v", err)
	}

	// 审计行照常入队落盘：事务段按缺失处理（快照对 typed-nil 走 isNilInterface
	// 门，Transaction_ 留零值），不因 typed-nil 丢行。
	line := waitAuditLine(t, logPath)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &doc); err != nil {
		t.Fatalf("audit line not JSON: %v (%s)", err, line)
	}
	if _, ok := doc["transaction"]; !ok {
		t.Fatalf("audit line missing transaction envelope: %s", line)
	}
}
