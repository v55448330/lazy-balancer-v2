package caddygeoip

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// 审计写侧失败/丢弃当前仅 Caddy 日志可见：面板健康位需要跨进程可读的计数。
// 契约：管线把累计 fail/drop 计数原子维护，并由 drain 低频写入目标路径旁的
// 侧车文件（不进入请求路径）；根服务摄取 tick 读该文件。
func TestAuditPipeline_writesWriterStatsSidecar(t *testing.T) {
	closeTestAuditPipelines(t)
	oldInterval := auditWriterStatsInterval
	auditWriterStatsInterval = 30 * time.Millisecond
	t.Cleanup(func() { auditWriterStatsInterval = oldInterval })

	target := filepath.Join(t.TempDir(), "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	p.reportDropped("queue full")
	p.reportIOError("write", errors.New("injected disk failure"))
	p.reportFormatError(errors.New("injected formatter contract failure"))

	statsPath := auditWriterStatsPath(target)
	deadline := time.Now().Add(3 * time.Second)
	var raw []byte
	for {
		raw, err = os.ReadFile(statsPath)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("writer stats sidecar %s not written: %v", filepath.Base(statsPath), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var got struct {
		Dropped      uint64 `json:"dropped"`
		IOErrors     uint64 `json:"io_errors"`
		FormatErrors uint64 `json:"format_errors"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("stats sidecar malformed: %v (%s)", err, raw)
	}
	// 格式化失败必须独立计数：混入 io_errors 会把代码契约缺陷呈现为磁盘故障，
	// 排障方向被误导。
	if got.Dropped != 1 || got.IOErrors != 1 || got.FormatErrors != 1 {
		t.Fatalf("stats=%+v, want dropped=1 io_errors=1 format_errors=1", got)
	}
	if p.dropped.Load() != 1 {
		t.Fatalf("pipeline dropped counter=%d, want 1", p.dropped.Load())
	}
}

// 侧车写盘失败必须留下跨进程可读的失败标记（缺失音则根服务按「文件缺失=
// 正常」假绿）；恢复可写后标记被清除。
func TestAuditPipeline_writerStatsFailureMarker(t *testing.T) {
	closeTestAuditPipelines(t)
	oldInterval := auditWriterStatsInterval
	auditWriterStatsInterval = 0
	t.Cleanup(func() { auditWriterStatsInterval = oldInterval })

	target := filepath.Join(t.TempDir(), "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// 用「tmp 路径是目录」制造写盘失败（os.WriteFile 报错）。
	tmpDir := auditWriterStatsPath(target) + ".tmp"
	if err := os.Mkdir(tmpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	p.statsDirty.Store(true)
	p.writeWriterStatsIfDue(time.Now())

	marker := auditWriterStatsFailurePath(target)
	body, merr := os.ReadFile(marker)
	if merr != nil {
		t.Fatalf("写盘失败必须留失败标记: %v", merr)
	}
	if !bytes.Contains(body, []byte("writer-stats sidecar write failed")) {
		t.Fatalf("marker content=%q, want failure description", body)
	}

	// 恢复可写：下次写盘成功即清除标记。
	if err := os.Remove(tmpDir); err != nil {
		t.Fatal(err)
	}
	p.statsDirty.Store(true)
	p.writeWriterStatsIfDue(time.Now().Add(time.Second))
	if _, serr := os.Stat(marker); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("成功写盘后失败标记必须清除, stat err=%v", serr)
	}
	if _, serr := os.Stat(auditWriterStatsPath(target)); serr != nil {
		t.Fatalf("恢复后侧车计数文件必须存在: %v", serr)
	}
}

// 侧车文件是跨进程契约：唯一的读方是根服务的摄取 tick
// （internal/services/securityevents.go 的 securityEventsObserveAuditWriterStats），
// 它只解析 dropped / io_errors / format_errors / written_at 四个键。写侧因此
// 只允许这四键：本进程的 IPC/spool 过程量（曾经的 ipc_sent/ipc_failed/
// spool_written/spool_errors/recoverable/lost/mode）没有任何消费方，写出去等于
// 让「读侧据此区分可补采与真丢」变成不实契约，并与读侧的失败窗口
// （dropped+io_errors+format_errors）形成两套丢事件口径。
// 新增侧车字段的前置条件是先让读侧消费（改上述解析结构体），此断言随之为红。
func TestAuditPipeline_writerStatsSidecarCarriesOnlyReaderConsumedKeys(t *testing.T) {
	closeTestAuditPipelines(t)
	oldInterval := auditWriterStatsInterval
	auditWriterStatsInterval = 0
	t.Cleanup(func() { auditWriterStatsInterval = oldInterval })

	target := filepath.Join(t.TempDir(), "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	p.reportDropped("queue full")
	p.writeWriterStatsIfDue(time.Now())

	raw, err := os.ReadFile(auditWriterStatsPath(target))
	if err != nil {
		t.Fatalf("侧车未写出: %v", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("侧车 JSON 非法: %v (%s)", err, raw)
	}
	got := make([]string, 0, len(payload))
	for key := range payload {
		got = append(got, key)
	}
	sort.Strings(got)
	want := []string{"dropped", "format_errors", "io_errors", "written_at"}
	if len(got) != len(want) {
		t.Fatalf("侧车键集合=%v, want %v（多出的键无读方消费，属死口径）", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("侧车键集合=%v, want %v", got, want)
		}
	}
}
