package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// R31 M1：F2 组合消息不得随连续失败无界增长——组合只保留标记段首个失败原因，
// 传输错误以「已连续 N 次」计数表示，消息长度必须有界（几百字节封顶）。
func TestSyncService_recordSyncError_repeatedTransportFailures_boundedMessageWithCount(t *testing.T) {
	// Given：重载失败标记已存在；之后连续 200 次传输层失败（错误内容固定）
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET last_sync_error=?", encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService("http://127.0.0.1:1"))
	failure := newSyncFailure(models.SyncErrorCodeTransportError, errors.New("拉取主节点快照: 连接主节点失败: 网络不可达"))

	// When：连续记录 200 次传输错误
	for i := 0; i < 200; i++ {
		service.recordSyncError(context.Background(), failure, nil)
	}

	// Then：消息长度有界、保留标记前缀、计数递增到 200、代码仍为传输错误
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, code := decodeSyncError(stored)
	if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("message=%q lost reload failure marker prefix", msg)
	}
	if !strings.Contains(msg, syncFailureCountPrefix+"200"+syncFailureCountSuffix) {
		t.Fatalf("message=%q does not contain count 200", msg)
	}
	if code != models.SyncErrorCodeTransportError {
		t.Fatalf("code=%q, want transport_error", code)
	}
	if len(stored) > 512 {
		t.Fatalf("last_sync_error=%d bytes, want bounded under 512", len(stored))
	}
	if strings.Contains(msg, "  |  ") || strings.Contains(msg, ":  ") {
		t.Fatalf("message=%q contains double spaces", msg)
	}
}

// R31 M2：PinMismatch 与传输错误同属自愈类，不得覆盖重载失败标记；
// 终止类错误（schema 过新，本节点无法安全解析）允许覆盖。
func TestSyncService_recordSyncError_pinMismatchPreservesMarker_terminalOverwrites(t *testing.T) {
	// Given：重载失败标记已存在
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET last_sync_error=?", encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService("http://127.0.0.1:1"))

	// When：记录主节点指纹不匹配错误
	service.recordSyncError(context.Background(), newSyncFailure(models.SyncErrorCodePinMismatch, errClusterPinMismatch), nil)

	// Then：标记保留，组合消息含计数，代码为 pin_mismatch
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, code := decodeSyncError(stored)
	if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("after pin mismatch last_sync_error=%q, want marker preserved", msg)
	}
	if code != models.SyncErrorCodePinMismatch {
		t.Fatalf("code=%q, want pin_mismatch", code)
	}

	// When：终止类错误（schema 过新）
	service.recordSyncError(context.Background(), &SnapshotSchemaTooNewError{Actual: 4, Supported: 3}, nil)

	// Then：标记被覆盖
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, _ = decodeSyncError(stored)
	if strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) || !strings.Contains(msg, "主节点快照版本 v4 超出本节点支持范围 v3") {
		t.Fatalf("after terminal error last_sync_error=%q, want overwritten with schema too new error", msg)
	}
}

// 审计 S-1：SchemaTooOld（v3 从节点拉到签名合法的旧 schema 主节点快照）与
// SignatureInvalid（含 v2 形态「主节点为旧版本」分支）同属非终止自愈类错误——
// E-F1 后 run 循环降级重试、主节点升级后自动恢复——不得覆盖重载失败标记；否则
// 主节点临时回退旧版本期间标记丢失，304 全量重拉补偿永不触发，陈旧运行配置
// 保持到下次真实版本变更或重启。
func TestSyncService_recordSyncError_schemaTooOldAndSignatureInvalidPreserveMarker(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		pullErr  error
		code     models.SyncErrorCode
		fragment string
	}{
		{"schema too old", &SnapshotSchemaTooOldError{Actual: 2, Supported: 3}, models.SyncErrorCodeSchemaTooOld, "快照 schema v2 过旧"},
		{"signature invalid", newSyncFailure(models.SyncErrorCodeSignatureInvalid, errors.New("快照签名校验失败：来源无法验证，可能存在中间人攻击")), models.SyncErrorCodeSignatureInvalid, "快照签名校验失败"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// Given：重载失败标记已存在
			_, database := newClusterTestService(t)
			if _, err := database.Exec("UPDATE global_config SET last_sync_error=?", encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
				t.Fatal(err)
			}
			service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService("http://127.0.0.1:1"))

			// When：记录自愈类拉取错误
			service.recordSyncError(context.Background(), testCase.pullErr, nil)

			// Then：标记保留，错误组合进消息并带失败计数，代码为传入错误码
			var stored string
			if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
				t.Fatal(err)
			}
			msg, code := decodeSyncError(stored)
			if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
				t.Fatalf("last_sync_error=%q, want reload failure marker preserved", msg)
			}
			if !strings.Contains(msg, testCase.fragment) {
				t.Fatalf("last_sync_error=%q, want combined message containing %q", msg, testCase.fragment)
			}
			if !strings.Contains(msg, syncFailureCountPrefix+"1"+syncFailureCountSuffix) {
				t.Fatalf("last_sync_error=%q, want failure count 1", msg)
			}
			if code != testCase.code {
				t.Fatalf("code=%q, want %q", code, testCase.code)
			}
		})
	}
}

// R31 M3：停机竞态下 beginPull 失败（Stop 期间）不得落库覆盖重载失败标记——
// 标记必须跨重启存活以触发首轮 304 全量重拉补偿。
func TestSyncService_Pull_stopRace_doesNotOverwriteReloadMarker(t *testing.T) {
	// Given：重载失败标记已存在；同步服务已停止（pullsStopped=true）
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET last_sync_error=?", encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService("http://127.0.0.1:1"))
	service.Stop()

	// When：停机竞态下发起 Pull（beginPull 被拒）
	_, err := service.Pull(context.Background())

	// Then：返回错误，但标记保持原样（未被 ValidationFailed 覆盖）
	if err == nil {
		t.Fatal("pull unexpectedly succeeded while stopped")
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, _ := decodeSyncError(stored)
	if msg != "apply_ok_reload_failed: caddy down" {
		t.Fatalf("after stop race last_sync_error=%q, want marker unchanged", msg)
	}
}
