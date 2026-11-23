package services

// 跨块回扫的 ReadAt 错误必须上抛：吞掉会让轮转把跨界事务切成两半并静默
// 丢单事务（前缀在归档、后缀在活文件，两半皆失）。

import (
	"os"
	"testing"
)

func TestSecurityEventsBackscanDocumentStart_reportsReadAtError(t *testing.T) {
	// 目录可 Open 但不可 ReadAt（EISDIR）——构造稳定的读错误形态。
	dir := t.TempDir()
	if _, err := securityEventsBackscanDocumentStart(dir, 64); err == nil {
		t.Fatal("ReadAt 失败必须返回错误（旧实现吞错后返回 from,nil）")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
}

func TestSecurityEventsBackscanDocumentStart_zeroOffsetIsNoop(t *testing.T) {
	if from, err := securityEventsBackscanDocumentStart("/nonexistent/path", 0); err != nil || from != 0 {
		t.Fatalf("from<=0 应零动作，got from=%d err=%v", from, err)
	}
}
