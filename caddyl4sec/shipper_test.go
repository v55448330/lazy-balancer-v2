package caddyl4sec

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startUnixIngestServer 起一个 unix socket 上的 /security-events/ingest 假面板：
// 固定应答 status 并捕获请求（与生产同路径/同方法/同 Content-Type 面）。
// socket 路径取 os.TempDir 短名——macOS sun_path 上限 104 字节，t.TempDir
// 的长随机路径会 bind: invalid argument。
func startUnixIngestServer(t *testing.T, status int) (socket string, bodies func() []string) {
	t.Helper()
	path := filepath.Join(os.TempDir(), "l4sec-"+time.Now().Format("150405.000000000")+".sock")
	captured := make(chan string, 16)
	mux := http.NewServeMux()
	mux.HandleFunc("/security-events/ingest", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured <- r.Header.Get("Content-Type") + "\x00" + string(body)
		w.WriteHeader(status)
	})
	srv := &http.Server{Handler: mux}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = os.Remove(path)
	})
	return path, func() []string {
		select {
		case s := <-captured:
			return []string{s}
		default:
			return nil
		}
	}
}

// setSpoolDirForTest 把 spool 目录重定向到临时目录（save/restore）。
func setSpoolDirForTest(t *testing.T, dir string) {
	t.Helper()
	old := l4SpoolDir
	l4SpoolDir = dir
	t.Cleanup(func() { l4SpoolDir = old })
}

func linesFromBody(body string) []string {
	trimmed := strings.TrimSuffix(body, "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// TestShipperIPCSuccess 主路径：攒批行按 ndjson 投递，204=成功，零落盘。
func TestShipperIPCSuccess(t *testing.T) {
	socket, bodies := startUnixIngestServer(t, http.StatusNoContent)
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", socket)
	setSpoolDirForTest(t, filepath.Join(t.TempDir(), "spool"))
	p := acquirePipelineForTest()
	defer p.resetForTest()

	l1 := buildL4EventLine(2, "IP 黑名单拒绝", "r1", "203.0.113.1", time.Unix(1, 11), [4]byte{1, 2, 3, 4})
	l2 := buildL4EventLine(4, "IP 黑名单", "r1", "203.0.113.2", time.Unix(1, 12), [4]byte{5, 6, 7, 8})
	p.enqueueEvent(l1)
	p.enqueueEvent(l2)
	p.flushQuiescedForTest()

	sent, failed, spooled, spoolErrs := p.shipperCounters()
	if sent != 2 || failed != 0 || spooled != 0 || spoolErrs != 0 {
		t.Fatalf("shipper counters sent/failed/spooled/spoolErrs = %d/%d/%d/%d, want 2/0/0/0", sent, failed, spooled, spoolErrs)
	}
	got := bodies()
	if len(got) != 1 {
		t.Fatalf("ingest requests = %d, want 1（攒批）", len(got))
	}
	parts := strings.SplitN(got[0], "\x00", 2)
	if parts[0] != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q, want application/x-ndjson（跨进程契约）", parts[0])
	}
	if lines := linesFromBody(parts[1]); len(lines) != 2 || !strings.HasPrefix(lines[0], `{"transaction"`) {
		t.Fatalf("body lines = %d, want 2 ndjson lines, got %q", len(linesFromBody(parts[1])), parts[1])
	}
	entries, err := os.ReadDir(l4SpoolDir)
	if err == nil && len(entries) != 0 {
		t.Fatalf("spool dir must stay empty on success, got %v", entries)
	}
}

// TestShipperFailureSpoolsSealed 5xx → 整批落 spool（active→sealed 命名契约：
// active-<pid>-<seq>.jsonl → sealed-<unixnano>.jsonl，每行一条）。
func TestShipperFailureSpoolsSealed(t *testing.T) {
	socket, _ := startUnixIngestServer(t, http.StatusServiceUnavailable)
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", socket)
	spoolDir := filepath.Join(t.TempDir(), "spool")
	setSpoolDirForTest(t, spoolDir)
	p := acquirePipelineForTest()

	line := buildL4EventLine(7, "IP 白名单拒绝", "r2", "198.51.100.7", time.Unix(2, 22), [4]byte{9, 9, 9, 9})
	p.enqueueEvent(line)
	p.flushQuiescedForTest()
	if err := p.stopAndCloseForTest(); err != nil {
		t.Fatalf("stopAndClose: %v", err)
	}

	_, failed, spooled, spoolErrs := p.shipperCounters()
	if failed != 1 || spooled != 1 || spoolErrs != 0 {
		t.Fatalf("failed/spooled/spoolErrs = %d/%d/%d, want 1/1/0", failed, spooled, spoolErrs)
	}
	// close 后目录里只剩 sealed（active 已封存）
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatalf("read spool dir: %v", err)
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "sealed-") || !strings.HasSuffix(entries[0].Name(), ".jsonl") {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("spool entries = %v, want exactly one sealed-*.jsonl", names)
	}
	raw, err := os.ReadFile(filepath.Join(spoolDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read sealed file: %v", err)
	}
	if lines := linesFromBody(string(raw)); len(lines) != 1 || !strings.Contains(lines[0], `"X-LB-Protocol":["tcp"]`) {
		t.Fatalf("sealed content = %q, want the enqueued event line", raw)
	}
}

// TestShipper400PermanentReject 永久拒绝（400/413）不进 spool（毒批会无限
// 重试）——按丢弃计数（真丢口径）。
func TestShipper400PermanentReject(t *testing.T) {
	socket, _ := startUnixIngestServer(t, http.StatusBadRequest)
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", socket)
	spoolDir := filepath.Join(t.TempDir(), "spool")
	setSpoolDirForTest(t, spoolDir)
	p := acquirePipelineForTest()
	defer p.resetForTest()

	p.enqueueEvent(buildL4EventLine(2, "IP 黑名单拒绝", "r3", "203.0.113.3", time.Unix(3, 33), [4]byte{0, 0, 0, 1}))
	p.flushQuiescedForTest()

	_, failed, spooled, _ := p.shipperCounters()
	if failed != 1 || spooled != 0 {
		t.Fatalf("failed/spooled = %d/%d, want 1/0", failed, spooled)
	}
	if p.dropped.Load() != 1 {
		t.Fatalf("pipeline dropped = %d, want 1（永久拒绝=真丢口径）", p.dropped.Load())
	}
	if entries, err := os.ReadDir(spoolDir); err == nil && len(entries) != 0 {
		t.Fatal("400 must not spool (poison batch)")
	}
}

// TestSpoolBudgetFullDrops spool 字节预算耗尽 → 余下行无文件兜底，按
// spool_errors + dropped 计数（真丢必须可观测）。
func TestSpoolBudgetFullDrops(t *testing.T) {
	socket, _ := startUnixIngestServer(t, http.StatusServiceUnavailable)
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", socket)
	// spool 字节预算经 env 收窄（与面板侧同一 env 契约；预放 1MiB 残留必超限）
	t.Setenv("LB_SECURITY_EVENTS_SPOOL_MAX_BYTES", "64")
	spoolDir := filepath.Join(t.TempDir(), "spool")
	setSpoolDirForTest(t, spoolDir)
	p := acquirePipelineForTest()
	defer p.resetForTest()
	defer restoreTunables(setTunablesForTest(64, 1<<20, 10*time.Millisecond))

	if err := os.MkdirAll(spoolDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// 目录预放超预算残留：预算按目录现存文件跨代核算（64B 预算 < 1MiB 残留）
	if err := os.WriteFile(filepath.Join(spoolDir, "preexisting.jsonl"), make([]byte, 1<<20), 0o640); err != nil {
		t.Fatal(err)
	}
	line := buildL4EventLine(2, "IP 黑名单拒绝", "r4", "203.0.113.4", time.Unix(4, 44), [4]byte{0, 0, 0, 2})
	p.enqueueEvent(line)
	p.flushQuiescedForTest()

	_, _, spooled, spoolErrs := p.shipperCounters()
	if spooled != 0 || spoolErrs != 1 {
		t.Fatalf("spooled/spoolErrs = %d/%d, want 0/1（spool 满转真丢计数）", spooled, spoolErrs)
	}
	if p.dropped.Load() != 1 {
		t.Fatalf("pipeline dropped = %d, want 1", p.dropped.Load())
	}
}

// TestQueuePerLineCapAndBudget 单行超上限 → 立即丢弃计数，不占准入位
// （pending 归零，风暴自防不放大驻留）。
func TestQueuePerLineCapAndBudget(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	p := acquirePipelineForTest()
	defer p.resetForTest()

	huge := make([]byte, l4LineMaxBytes+1)
	for i := range huge {
		huge[i] = 'x'
	}
	p.enqueueEvent(huge)
	if p.dropped.Load() != 1 || p.pending.Load() != 0 {
		t.Fatalf("dropped/pending = %d/%d, want 1/0（超单行上限即丢）", p.dropped.Load(), p.pending.Load())
	}
}

// TestSpoolDirEnvOverride 面板侧补采目录经 LB_SECURITY_EVENTS_L4_SPOOL_DIR
// 覆盖——写侧必须消费同一 env（跨进程契约对称：写读分叉会让补采扫空目录）。
func TestSpoolDirEnvOverride(t *testing.T) {
	// socket 指向不存在路径即可：shipper 构造期不拨号（投递才拨），需要
	// IPC 启用形态才会构造 shipper 并打开 spool。
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", filepath.Join(t.TempDir(), "noop.sock"))
	override := filepath.Join(t.TempDir(), "spool-l4-override")
	t.Setenv("LB_SECURITY_EVENTS_L4_SPOOL_DIR", override)
	p := acquirePipelineForTest()
	defer p.resetForTest()

	// spool 目录在 shipper 构造期打开——env 生效即目录被创建（0700）
	if _, err := os.Stat(override); err != nil {
		t.Fatalf("shipper did not open env-overridden spool dir %s: %v", override, err)
	}
	if p.shipper == nil || p.shipper.spool == nil || p.shipper.spool.dir != override {
		t.Fatalf("shipper spool dir = %+v, want %s", p.shipper, override)
	}
}

// TestSpoolIdleSeal 静默超窗的 active 文件按 idle 封存（补采端只消费 sealed
// ——不按时间封存会让兜底条目滞留到进程退出）。
func TestSpoolIdleSeal(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "spool")
	s := openL4Spool(spoolDir, 1<<20, 1000)
	if _, err := s.appendLines([][]byte{[]byte(`{"k":1}`)}); err != nil {
		t.Fatalf("appendLines: %v", err)
	}
	if err := s.sealIfIdle(time.Now().Add(l4SpoolIdleSeal+time.Second), l4SpoolIdleSeal); err != nil {
		t.Fatalf("sealIfIdle: %v", err)
	}
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "sealed-") {
		t.Fatalf("entries = %v, want sealed file", entries)
	}
}

// TestDisabledIPCDropsWithoutFiles IPC 显式关闭（env 空串）→ 事件行计数丢弃、
// 不创建任何 spool/文件痕迹（纯文件兜底仅 HTTP 审计链支持）。
func TestDisabledIPCDropsWithoutFiles(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	spoolDir := filepath.Join(t.TempDir(), "spool")
	setSpoolDirForTest(t, spoolDir)
	p := acquirePipelineForTest()
	defer p.resetForTest()

	p.enqueueEvent(buildL4EventLine(4, "IP 黑名单", "r5", "203.0.113.5", time.Unix(5, 55), [4]byte{7, 7, 7, 7}))
	p.flushQuiescedForTest()
	if p.dropped.Load() != 1 {
		t.Fatalf("dropped = %d, want 1", p.dropped.Load())
	}
	if _, err := os.Stat(spoolDir); !os.IsNotExist(err) {
		t.Fatalf("disabled IPC must not create spool dir, stat err = %v", err)
	}
}

// TestPipelineSinkReceivesSyntheticLine 全链形状：handler 产出的行原样到达
// 投递缝（handler→队列→drain→submit），geoip 段位/文案在行内。
func TestPipelineSinkReceivesSyntheticLine(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	p := acquirePipelineForTest()
	defer p.resetForTest()

	got := make(chan []byte, 1)
	p.setSubmitSinkForTest(func(line []byte) { got <- line })

	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-sink", Reason: "geoip", PolicyID: 11})
	if err := h.Handle(newTestConn("8.8.8.8"), &nextCapture{}); err != nil {
		t.Fatalf("Handle = %v", err)
	}
	p.flushQuiescedForTest()
	select {
	case line := <-got:
		if !strings.Contains(string(line), `"id":800011`) || !strings.Contains(string(line), "GeoIP 区域拦截") {
			t.Fatalf("line missing geoip segment attribution: %s", line)
		}
	default:
		t.Fatal("sink never received the synthetic line")
	}
}
