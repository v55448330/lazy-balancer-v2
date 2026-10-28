package caddygeoip

// 安全事件 IPC 主路径 + fallback spool 的契约钉测，以及 messages 动态预算
// （1MiB 行预算扣除固定段 → clamp 128KiB/256 条）的钉测。
//
// 三条不可退让的写侧契约（跨进程语义见 auditwriter.go 顶部 IPC 段注释）：
//  1. 204 才成功，成功后不落任何文件（审计文件/ spool 都不出现）；
//  2. IPC 失败（连接失败/非 204/超时）整批进 spool（可补采），spool 满/写错
//     才退回审计文件并逐行计 spool_errors；
//  3. 请求路径零等待——所有投递/落盘都在 drain goroutine 里。

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// TestMain 把整个包切到纯文件模式（既有用例全部按「行落在审计文件」断言）。
// IPC 用例用 enableTestAuditIPC 显式开启（socket/spool 指向 t.TempDir）。
func TestMain(m *testing.M) {
	auditIPCDisabled.Store(true)
	os.Exit(m.Run())
}

// enableTestAuditIPC 开启 IPC 主路径并把跨进程路径指向测试临时目录。
// 必须在 acquireAuditPipeline 之前调用（配置在管线创建时解析一次）。
func enableTestAuditIPC(t *testing.T, socketPath, spoolDir string) {
	t.Helper()
	auditIPCDisabled.Store(false)
	t.Setenv(auditIPCSocketEnv, socketPath)
	t.Setenv(auditSpoolDirEnv, spoolDir)
	t.Cleanup(func() { auditIPCDisabled.Store(true) })
}

// shortSocketPath 返回短路径 socket：macOS 的 unix socket 路径上限 104 字节，
// t.TempDir() 给出的路径已接近该上限（bind: invalid argument）。
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "lbsp")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "ingest.sock")
}

// testIngestServer 是面板侧 UDS 摄取端点的最小替身：按预设状态码应答并记录
// 每次请求的原始 body（用于断言「body=换行分隔行 + 末尾 \n」）。
type testIngestServer struct {
	mu       sync.Mutex
	requests []string
	status   int
	server   *http.Server
}

func startTestIngestServer(t *testing.T, socketPath string, status int) *testIngestServer {
	t.Helper()
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", socketPath, err)
	}
	srv := &testIngestServer{status: status}
	mux := http.NewServeMux()
	mux.HandleFunc(auditIPCIngestPath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		srv.mu.Lock()
		srv.requests = append(srv.requests, string(body))
		srv.mu.Unlock()
		w.WriteHeader(srv.status)
	})
	srv.server = &http.Server{Handler: mux}
	go func() { _ = srv.server.Serve(ln) }()
	t.Cleanup(func() { _ = srv.server.Close() })
	return srv
}

func (s *testIngestServer) bodies() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// waitIngestBodies 等待至少 n 次投递（上限 3s）。
func waitIngestBodies(t *testing.T, srv *testIngestServer, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if bodies := srv.bodies(); len(bodies) >= n {
			return bodies
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("ingest requests did not arrive within 3s")
	return nil
}

// waitPipelineDrained 等待已准入条目全部处理完（pending==0 蕴含队列空 + 无在途）。
func waitPipelineDrained(t *testing.T, p *auditPipeline) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if p.pending.Load() == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("pipeline did not drain within 3s")
}

// enqueueCanned 入队一行固定 JSON（走真实 drain → process → IPC/文件链）。
func enqueueCanned(p *auditPipeline, body string) {
	p.enqueue(lbAuditItem{
		snap:      &auditSnapshot{},
		formatter: cannedFormatter{body: []byte(body)},
	})
}

// spoolFiles 返回 spool 目录内的文件名（目录不存在时返回空）。
func spoolFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read spool dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// spoolLines 读出 spool 目录内全部 .jsonl 的行（跨 sealed/active 累积）。
func spoolLines(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, name := range spoolFiles(t, dir) {
		if !strings.HasSuffix(name, auditSpoolFileSuffix) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read spool file %s: %v", name, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				out = append(out, line)
			}
		}
	}
	return out
}

// Given: 面板侧 UDS 端点返回 204
// When: 审计行经 drain 格式化后投递
// Then: body=行+末尾 \n，成功即不落任何文件（审计文件不存在、spool 无文件），
// 且计数落在 ipc_sent。
func TestAuditPipeline_IPCSuccessShipsAndWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	socketPath := shortSocketPath(t)
	spoolDir := filepath.Join(dir, "spool")
	srv := startTestIngestServer(t, socketPath, http.StatusNoContent)
	enableTestAuditIPC(t, socketPath, spoolDir)
	// 收尾顺序：管线先关闭（drain 封存 spool）、再删临时目录——closeTestAuditPipelines
	// 注册得比 t.TempDir 清理更晚，LIFO 下先执行。
	closeTestAuditPipelines(t)

	target := filepath.Join(dir, "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire pipeline: %v", err)
	}
	if p.ipc == nil {
		t.Fatal("IPC 主路径未启用（配置解析失败）")
	}
	enqueueCanned(p, `{"tx":"ipc-ok"}`)
	waitPipelineDrained(t, p)
	p.ipc.flush()

	bodies := waitIngestBodies(t, srv, 1)
	if got := bodies[0]; !strings.Contains(got, `{"tx":"ipc-ok"}`) {
		t.Fatalf("投递 body 缺审计行: %q", got)
	}
	if got := bodies[0]; !strings.HasSuffix(got, "\n") {
		t.Fatalf("body 必须以 \\n 结尾（换行分隔契约）: %q", got)
	}
	// 204 ack 后：审计文件与 spool 都必须为空——成功路径零文件。
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("IPC 成功后不应写审计文件, stat err=%v", err)
	}
	for _, name := range spoolFiles(t, spoolDir) {
		t.Fatalf("IPC 成功后 spool 不应有文件: %s", name)
	}
	if sent, failed, spooled, spoolErrs := p.ipc.counters(); sent != 1 || failed != 0 || spooled != 0 || spoolErrs != 0 {
		t.Fatalf("counters sent/failed/spooled/spoolErrs = %d/%d/%d/%d, want 1/0/0/0", sent, failed, spooled, spoolErrs)
	}
}

// Given: IPC 端点不可达（socket 不存在）
// When: 审计行投递失败
// Then: 整批行写入 spool（可补采），审计文件不被创建，计数 ipc_failed=spool_written=N。
func TestAuditPipeline_IPCFailureSpoolsLines(t *testing.T) {
	dir := t.TempDir()
	socketPath := shortSocketPath(t) // 不监听：连接必然失败
	spoolDir := filepath.Join(dir, "spool")
	oldTimeout := auditIPCTimeout
	auditIPCTimeout = 300 * time.Millisecond
	t.Cleanup(func() { auditIPCTimeout = oldTimeout })
	enableTestAuditIPC(t, socketPath, spoolDir)
	closeTestAuditPipelines(t)

	target := filepath.Join(dir, "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire pipeline: %v", err)
	}
	enqueueCanned(p, `{"tx":"spool-a"}`)
	enqueueCanned(p, `{"tx":"spool-b"}`)
	waitPipelineDrained(t, p)
	p.ipc.flush()

	lines := spoolLines(t, spoolDir)
	if len(lines) != 2 {
		t.Fatalf("spool 行数 = %d (%v), want 2", len(lines), lines)
	}
	if lines[0] != `{"tx":"spool-a"}` || lines[1] != `{"tx":"spool-b"}` {
		t.Fatalf("spool 行序/内容被破坏: %v", lines)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spool 可用时不应回退写审计文件, stat err=%v", err)
	}
	if sent, failed, spooled, spoolErrs := p.ipc.counters(); sent != 0 || failed != 2 || spooled != 2 || spoolErrs != 0 {
		t.Fatalf("counters = %d/%d/%d/%d, want 0/2/2/0", sent, failed, spooled, spoolErrs)
	}
	names := spoolFiles(t, spoolDir)
	if len(names) != 1 || !strings.HasPrefix(names[0], auditSpoolActivePrefix) {
		t.Fatalf("spool 应只有本进程 active 文件, got %v", names)
	}
}

// Given: spool 字节预算被压到极小（模拟 spool 满）
// When: IPC 失败行无法写入 spool
// Then: 逐行计 spool_errors、行退回审计文件兜底（不丢行），审计文件不再为空。
func TestAuditPipeline_SpoolFullCountsAndFallsBackToAuditFile(t *testing.T) {
	dir := t.TempDir()
	socketPath := shortSocketPath(t) // 不监听：IPC 必然失败
	spoolDir := filepath.Join(dir, "spool")
	oldTimeout, oldMax := auditIPCTimeout, auditSpoolMaxBytes
	auditIPCTimeout = 300 * time.Millisecond
	auditSpoolMaxBytes = 8 // 任意一行（~15B + 换行）都放不下
	t.Cleanup(func() {
		auditIPCTimeout, auditSpoolMaxBytes = oldTimeout, oldMax
	})
	enableTestAuditIPC(t, socketPath, spoolDir)
	closeTestAuditPipelines(t)

	target := filepath.Join(dir, "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire pipeline: %v", err)
	}
	enqueueCanned(p, `{"tx":"full-a"}`)
	enqueueCanned(p, `{"tx":"full-b"}`)
	waitPipelineDrained(t, p)
	p.ipc.flush()

	if lines := spoolLines(t, spoolDir); len(lines) != 0 {
		t.Fatalf("spool 满时不应写入任何行, got %v", lines)
	}
	if _, failed, spooled, spoolErrs := p.ipc.counters(); failed != 2 || spooled != 0 || spoolErrs != 2 {
		t.Fatalf("counters failed/spooled/spoolErrs = %d/%d/%d, want 2/0/2", failed, spooled, spoolErrs)
	}
	// 兜底行走的是纯文件链（bufio 阈值刷盘），测试里显式冲刷后再读。
	p.flush()
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("spool 满时必须退回审计文件兜底: %v", err)
	}
	for _, want := range []string{`{"tx":"full-a"}`, `{"tx":"full-b"}`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("审计文件缺兜底行 %s: %q", want, data)
		}
	}
}

// Given: active 文件轮转阈值被压小
// When: 多批失败行写入 spool
// Then: 达到阈值即原子 rename 为 sealed-<unixnano>.jsonl 并继续写新 active，
// 全部行跨文件完整保留、命名符合跨进程契约。
func TestAuditPipeline_SpoolRotatesSealedFiles(t *testing.T) {
	dir := t.TempDir()
	socketPath := shortSocketPath(t) // 不监听：IPC 必然失败
	spoolDir := filepath.Join(dir, "spool")
	oldTimeout, oldRotate := auditIPCTimeout, auditSpoolRotateBytes
	auditIPCTimeout = 300 * time.Millisecond
	auditSpoolRotateBytes = 24 // 每两行（~15B/行）即轮转
	t.Cleanup(func() {
		auditIPCTimeout, auditSpoolRotateBytes = oldTimeout, oldRotate
	})
	enableTestAuditIPC(t, socketPath, spoolDir)
	closeTestAuditPipelines(t)

	target := filepath.Join(dir, "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire pipeline: %v", err)
	}
	want := []string{`{"tx":"rot-1"}`, `{"tx":"rot-2"}`, `{"tx":"rot-3"}`, `{"tx":"rot-4"}`}
	for _, body := range want {
		enqueueCanned(p, body)
	}
	waitPipelineDrained(t, p)
	p.ipc.flush()

	lines := spoolLines(t, spoolDir)
	if len(lines) != len(want) {
		t.Fatalf("spool 行数 = %d (%v), want %d", len(lines), lines, len(want))
	}
	seen := map[string]bool{}
	for _, line := range lines {
		seen[line] = true
	}
	for _, body := range want {
		if !seen[body] {
			t.Fatalf("轮转丢行: %s 不在 %v", body, lines)
		}
	}
	names := spoolFiles(t, spoolDir)
	sealed := 0
	active := 0
	for _, name := range names {
		switch {
		case strings.HasPrefix(name, auditSpoolSealedPrefix) && strings.HasSuffix(name, auditSpoolFileSuffix):
			sealed++
		case strings.HasPrefix(name, auditSpoolActivePrefix) && strings.HasSuffix(name, auditSpoolFileSuffix):
			active++
		default:
			t.Fatalf("spool 文件名不符合契约: %s", name)
		}
	}
	if sealed == 0 {
		t.Fatalf("达到轮转阈值后必须出现 sealed 文件, got %v", names)
	}
	if active == 0 {
		t.Fatalf("轮转后必须继续写新 active 文件, got %v", names)
	}
}

// Given: IPC 成功投递
// When: 侧车计数写盘
// Then: 侧车带 ipc_sent/spool_written/spool_errors/mode/recoverable/lost 字段
// （读侧据此区分「可补采」与「真丢」）。
func TestAuditPipeline_WriterStatsCarriesIPCCounters(t *testing.T) {
	dir := t.TempDir()
	socketPath := shortSocketPath(t)
	spoolDir := filepath.Join(dir, "spool")
	startTestIngestServer(t, socketPath, http.StatusNoContent)
	enableTestAuditIPC(t, socketPath, spoolDir)
	oldInterval := auditWriterStatsInterval
	auditWriterStatsInterval = 20 * time.Millisecond
	t.Cleanup(func() { auditWriterStatsInterval = oldInterval })
	closeTestAuditPipelines(t)

	target := filepath.Join(dir, "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire pipeline: %v", err)
	}
	enqueueCanned(p, `{"tx":"stats"}`)
	waitPipelineDrained(t, p)
	p.ipc.flush()
	p.statsDirty.Store(true)

	statsPath := auditWriterStatsPath(target)
	deadline := time.Now().Add(3 * time.Second)
	var raw []byte
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(statsPath); err == nil && strings.Contains(string(data), `"ipc_sent"`) {
			raw = data
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if raw == nil {
		t.Fatalf("侧车未写出 ipc_sent 字段")
	}
	var got struct {
		IPCSent      uint64 `json:"ipc_sent"`
		IPCFailed    uint64 `json:"ipc_failed"`
		SpoolWritten uint64 `json:"spool_written"`
		SpoolErrors  uint64 `json:"spool_errors"`
		Recoverable  uint64 `json:"recoverable"`
		Lost         uint64 `json:"lost"`
		Mode         string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("侧车 JSON 非法: %v (%s)", err, raw)
	}
	if got.IPCSent != 1 || got.Mode != "ipc" || got.Lost != 0 || got.Recoverable != 0 {
		t.Fatalf("stats=%+v, want ipc_sent=1 mode=ipc lost=0 recoverable=0", got)
	}
}

// Given: 204 端点 + 150 行审计数据
// When: 逐行投递
// Then: 攒批在 auditIPCBatchMaxLines 处自动投递（首批恰好 100 行），收尾冲刷
// 送出剩余 50 行——单批行数上限是跨进程契约（面板侧按批 commit）。
func TestAuditPipeline_IPCBatchesAtLineLimit(t *testing.T) {
	dir := t.TempDir()
	socketPath := shortSocketPath(t)
	spoolDir := filepath.Join(dir, "spool")
	srv := startTestIngestServer(t, socketPath, http.StatusNoContent)
	enableTestAuditIPC(t, socketPath, spoolDir)
	closeTestAuditPipelines(t)

	target := filepath.Join(dir, "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire pipeline: %v", err)
	}
	const total = 150
	for i := range total {
		enqueueCanned(p, fmt.Sprintf(`{"n":%d}`, i))
	}
	waitPipelineDrained(t, p)
	p.ipc.flush()

	bodies := waitIngestBodies(t, srv, 2)
	if len(bodies) != 2 {
		t.Fatalf("批次数量 = %d, want 2（100 行满批 + 收尾 50 行）", len(bodies))
	}
	linesOf := func(body string) []string {
		var out []string
		for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
			if line != "" {
				out = append(out, line)
			}
		}
		return out
	}
	first, second := linesOf(bodies[0]), linesOf(bodies[1])
	if len(first) != auditIPCBatchMaxLines {
		t.Fatalf("首批行数 = %d, want %d（满批即投递）", len(first), auditIPCBatchMaxLines)
	}
	if len(second) != total-auditIPCBatchMaxLines {
		t.Fatalf("次批行数 = %d, want %d", len(second), total-auditIPCBatchMaxLines)
	}
	seen := map[string]bool{}
	for _, line := range append(first, second...) {
		seen[line] = true
	}
	for i := range total {
		if want := fmt.Sprintf(`{"n":%d}`, i); !seen[want] {
			t.Fatalf("批间丢行: %s", want)
		}
	}
	if sent, failed, spooled, spoolErrs := p.ipc.counters(); sent != total || failed != 0 || spooled != 0 || spoolErrs != 0 {
		t.Fatalf("counters = %d/%d/%d/%d, want %d/0/0/0", sent, failed, spooled, spoolErrs, total)
	}
}

// Given: 端点返回 5xx（可重试的服务端故障）
// Then: 整批进 spool（可补采），审计文件不写。
func TestAuditPipeline_IPC5xxSpoolsLines(t *testing.T) {
	dir := t.TempDir()
	socketPath := shortSocketPath(t)
	spoolDir := filepath.Join(dir, "spool")
	startTestIngestServer(t, socketPath, http.StatusInternalServerError)
	enableTestAuditIPC(t, socketPath, spoolDir)
	closeTestAuditPipelines(t)

	target := filepath.Join(dir, "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire pipeline: %v", err)
	}
	enqueueCanned(p, `{"tx":"retry-me"}`)
	waitPipelineDrained(t, p)
	p.ipc.flush()

	if lines := spoolLines(t, spoolDir); len(lines) != 1 || lines[0] != `{"tx":"retry-me"}` {
		t.Fatalf("5xx 必须整批进 spool, got %v", lines)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spool 可用时不应回退写审计文件, stat err=%v", err)
	}
	if _, failed, spooled, spoolErrs := p.ipc.counters(); failed != 1 || spooled != 1 || spoolErrs != 0 {
		t.Fatalf("counters failed/spooled/spoolErrs = %d/%d/%d, want 1/1/0", failed, spooled, spoolErrs)
	}
}

// Given: 端点返回 400/413（该批数据永久不可入库）
// Then: 不进 spool（避免补采侧无限重试毒批），按「真丢」计 dropped 并告警。
func TestAuditPipeline_IPC400RejectsWithoutSpooling(t *testing.T) {
	dir := t.TempDir()
	socketPath := shortSocketPath(t)
	spoolDir := filepath.Join(dir, "spool")
	startTestIngestServer(t, socketPath, http.StatusRequestEntityTooLarge)
	enableTestAuditIPC(t, socketPath, spoolDir)
	closeTestAuditPipelines(t)

	target := filepath.Join(dir, "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire pipeline: %v", err)
	}
	enqueueCanned(p, `{"tx":"poison"}`)
	waitPipelineDrained(t, p)
	p.ipc.flush()

	if lines := spoolLines(t, spoolDir); len(lines) != 0 {
		t.Fatalf("永久拒绝的批次不得进 spool（毒批会无限重试）, got %v", lines)
	}
	if _, failed, spooled, spoolErrs := p.ipc.counters(); failed != 1 || spooled != 0 || spoolErrs != 0 {
		t.Fatalf("counters failed/spooled/spoolErrs = %d/%d/%d, want 1/0/0", failed, spooled, spoolErrs)
	}
	if dropped := p.dropped.Load(); dropped != 1 {
		t.Fatalf("dropped=%d, want 1（永久拒绝对应真丢口径）", dropped)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("永久拒绝不应写审计文件兜底, stat err=%v", err)
	}
}

// —— messages 动态预算 ——
//
// 旧形态是固定 32KiB/64 条；新形态以 1MiB 行预算扣除固定段后 clamp 到
// [32KiB/64, 128KiB/256]。以下钉测覆盖三段语义：旧值不回归（小集合原样保留）、
// 小请求高命中放得下 >64、大 body 自动收缩且整行仍 ≤1MiB。

// 小请求 + 150 条小消息：必须全部保留（>旧上限 64），零丢弃。
func TestSnapshotAuditMessages_smallRequestKeepsMoreThanLegacyCap(t *testing.T) {
	raw := make([]plugintypes.AuditLogMessage, 0, 150)
	for i := range 150 {
		raw = append(raw, estimateTestMessage{
			Message_: "hit",
			Data_:    &estimateTestMessageData{ID_: 942000 + i, Msg_: "hit"},
		})
	}
	snap := snapshotAuditLog(messageOnlyAuditLog{msgs: raw})
	if snap.MessagesDropped_ != 0 {
		t.Fatalf("messages_dropped=%d, want 0（小请求预算应容得下 150 条小消息）", snap.MessagesDropped_)
	}
	if got := len(snap.Messages_); got != 150 {
		t.Fatalf("保留 %d 条, want 150（旧固定上限 64 会丢一半以上）", got)
	}
	if got := len(snap.Messages_); got <= auditMessagesMinEntries {
		t.Fatalf("保留 %d 条未超过旧上限 %d，钉测失去区分力", got, auditMessagesMinEntries)
	}
	if size := estimateAuditSnapshotBytes(snap); size > auditItemMaxBytes {
		t.Fatalf("估算 %d > 单条上限 %d", size, auditItemMaxBytes)
	}
}

// 固定段吃满（双向体 64KiB 全 `&`＝6× 转义、双向头表封顶到 64KiB、files 封顶到
// 24KiB、URI 封顶到 8KiB）时 messages 预算必须收缩，且整行估算仍 ≤1MiB
// （大 body 收缩 / 6× 转义总行 ≤1MiB）。
func TestSnapshotAuditMessages_largeFixedPartShrinksBudgetUnderItemCap(t *testing.T) {
	dense := strings.Repeat("&", auditBodyMaxBytes)
	// 头表：几千条小条目把序列化体积推到 64KiB 封顶（单条超大条目会被整条丢弃，
	// 达不到「头表吃满」的形态）。
	headers := make(map[string][]string, 4000)
	for i := range 4000 {
		headers[fmt.Sprintf("x-h%d", i)] = []string{strings.Repeat("&", 8)}
	}
	files := make([]plugintypes.AuditLogTransactionRequestFiles, 0, 200)
	for range 200 {
		files = append(files, auditSnapshotFile{Name_: dense, Size_: 1, Mime_: dense})
	}
	raw := make([]plugintypes.AuditLogMessage, 0, 400)
	for i := range 400 {
		raw = append(raw, estimateTestMessage{
			Message_: "attack " + strings.Repeat("m", 100),
			Data_:    &estimateTestMessageData{ID_: 942000 + i, Msg_: "attack"},
		})
	}
	snap := snapshotAuditLog(messageOnlyAuditLog{
		tx: auxProbeTx{
			req: auxProbeReq{
				body:    dense,
				uri:     "/probe?" + dense,
				headers: headers,
				files:   files,
			},
			resp: auxProbeResp{body: dense},
		},
		msgs: raw,
	})
	fixed := estimateAuditSnapshotFixedBytes(snap)
	if fixed <= auditItemMaxBytes-auditMessagesMaxBytesCeiling-auditMessagesBudgetReserve {
		t.Fatalf("夹具未强制预算收缩：固定段 %d 字节仍容得下 messages 上界", fixed)
	}
	maxBytes, maxEntries := auditMessagesBudget(fixed)
	if maxBytes >= auditMessagesMaxBytesCeiling {
		t.Fatalf("大固定段（%d 字节）下 messages 预算 %d 未收缩到 clamp 上界 %d 以下",
			fixed, maxBytes, auditMessagesMaxBytesCeiling)
	}
	if maxBytes < auditMessagesMinBytes {
		t.Fatalf("messages 预算 %d 低于兼容下限 %d", maxBytes, auditMessagesMinBytes)
	}
	var used int64
	for _, m := range snap.Messages_ {
		used += estimateAuditMessageBytes(m)
	}
	if used > maxBytes {
		t.Fatalf("messages 估算 %d > 动态预算 %d", used, maxBytes)
	}
	if got := len(snap.Messages_); got > maxEntries {
		t.Fatalf("保留 %d 条 > 动态条目预算 %d", got, maxEntries)
	}
	if snap.MessagesDropped_ == 0 {
		t.Fatal("400 条大消息在收缩预算下必须截断（钉测失去意义）")
	}
	if size := estimateAuditSnapshotBytes(snap); size > auditItemMaxBytes {
		t.Fatalf("估算 %d > 单条上限 %d（大 body + messages 使整行被丢弃）", size, auditItemMaxBytes)
	}
	// 6× 转义的最坏形态落到字节层面：序列化后的单行也不得越过单条上限。
	serialized, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if int64(len(serialized)) > auditItemMaxBytes {
		t.Fatalf("序列化行 %d 字节 > 单条上限 %d", len(serialized), auditItemMaxBytes)
	}
}

// 预算两端的 clamp：固定段极小 → 上界（128KiB/256 条）；固定段吃满 1MiB →
// 预算必须归零（不能用旧下限把整行重新推过 auditItemMaxBytes）。
func TestAuditMessagesBudget_clampsToFloorAndCeiling(t *testing.T) {
	maxBytes, maxEntries := auditMessagesBudget(0)
	if maxBytes != auditMessagesMaxBytesCeiling || maxEntries != auditMessagesMaxEntriesCeiling {
		t.Fatalf("小固定段预算 = %d/%d, want 上界 %d/%d",
			maxBytes, maxEntries, auditMessagesMaxBytesCeiling, auditMessagesMaxEntriesCeiling)
	}
	maxBytes, maxEntries = auditMessagesBudget(auditItemMaxBytes)
	if maxBytes != 0 || maxEntries != 0 {
		t.Fatalf("固定段吃满预算 = %d/%d, want 0/0（不得推过单条上限）",
			maxBytes, maxEntries)
	}
	// 中间形态：预算随固定段单调收缩，且不小于下限。
	prev := int64(auditMessagesMaxBytesCeiling)
	for _, fixed := range []int64{0, 100 << 10, 300 << 10, 600 << 10, 800 << 10} {
		got, entries := auditMessagesBudget(fixed)
		if got > prev {
			t.Fatalf("固定段 %d 时预算 %d 反而变大（prev=%d）", fixed, got, prev)
		}
		if got < auditMessagesMinBytes || entries < auditMessagesMinEntries {
			t.Fatalf("固定段 %d 时预算 %d/%d 低于下限", fixed, got, entries)
		}
		prev = got
	}
}

// 旧形态（小集合、远低于旧上限）必须逐条原样保留：动态预算的下限等于旧固定
// 上限，因此「旧时期能完整装下」的集合在新形态下输出不变（顺序/条数/零丢弃）。
func TestSnapshotAuditLog_legacySmallMessageSetUnchanged(t *testing.T) {
	raw := make([]plugintypes.AuditLogMessage, 0, 20)
	for i := range 20 {
		raw = append(raw, estimateTestMessage{
			Message_: strings.Repeat("m", 600),
			Data_:    &estimateTestMessageData{ID_: 942000 + i, Msg_: "mid"},
		})
	}
	snap := snapshotAuditLog(messageOnlyAuditLog{msgs: raw})
	if snap.MessagesDropped_ != 0 || len(snap.Messages_) != len(raw) {
		t.Fatalf("旧小集合被截断: dropped=%d kept=%d, want 0/%d",
			snap.MessagesDropped_, len(snap.Messages_), len(raw))
	}
	for i, m := range snap.Messages_ {
		if id := m.Data().ID(); id != raw[i].Data().ID() {
			t.Fatalf("顺序/内容改变：第 %d 条 id=%d, want %d", i, id, raw[i].Data().ID())
		}
	}
}

// 低失败量下 active 必须在静默窗口后封存：补采端只消费 sealed，否则兜底行
// 会一直滞留到进程退出/达到 8MiB。
func TestAuditSpool_idleSealMakesSmallFallbackVisible(t *testing.T) {
	dir := t.TempDir()
	spool, err := openAuditSpool(dir, 1<<20, 100)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	defer func() { _ = spool.close() }()
	if n, err := spool.appendLines([][]byte{[]byte(`{"transaction":{"id":"idle-1"}}`)}); err != nil || n != 1 {
		t.Fatalf("append=%d err=%v, want 1/nil", n, err)
	}
	if err := spool.sealIfIdle(time.Now(), auditSpoolIdleSeal); err != nil {
		t.Fatalf("early seal: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), auditSpoolActivePrefix) {
		t.Fatalf("early seal must keep active, entries=%v", names(entries))
	}
	if err := spool.sealIfIdle(time.Now().Add(auditSpoolIdleSeal+time.Second), auditSpoolIdleSeal); err != nil {
		t.Fatalf("idle seal: %v", err)
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), auditSpoolSealedPrefix) {
		t.Fatalf("idle seal must produce sealed, entries=%v", names(entries))
	}
	if data, err := os.ReadFile(filepath.Join(dir, entries[0].Name())); err != nil || !strings.Contains(string(data), `"idle-1"`) {
		t.Fatalf("sealed content=%q err=%v", string(data), err)
	}
}

func TestAuditSpool_externalReclaimRestoresBudget(t *testing.T) {
	line := []byte(`{"transaction":{"id":"reclaimed"}}`)
	for _, tc := range []struct {
		name       string
		maxBytes   int64
		maxEntries int64
	}{
		{name: "entries", maxBytes: 1 << 20, maxEntries: 1},
		{name: "bytes", maxBytes: int64(len(line)) + 1, maxEntries: 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			spool, err := openAuditSpool(dir, tc.maxBytes, tc.maxEntries)
			if err != nil {
				t.Fatalf("open spool: %v", err)
			}
			defer func() { _ = spool.close() }()
			if n, err := spool.appendLines([][]byte{line}); n != 1 || err != nil {
				t.Fatalf("first append=%d err=%v, want 1/nil", n, err)
			}
			if err := spool.sealIfIdle(time.Now().Add(auditSpoolIdleSeal+time.Second), auditSpoolIdleSeal); err != nil {
				t.Fatalf("seal: %v", err)
			}
			// 根服务补采提交后删除 sealed；写侧必须按现存文件回收预算。
			for _, name := range spoolFiles(t, dir) {
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					t.Fatalf("remove consumed spool file: %v", err)
				}
			}
			if n, err := spool.appendLines([][]byte{line}); n != 1 || err != nil {
				t.Fatalf("append after external reclaim=%d err=%v, want 1/nil", n, err)
			}
		})
	}
}

func names(entries []os.DirEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
