package caddyl4sec

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// —— L4 安全事件 IPC 主路径 + fallback spool ——
//
// caddygeoip auditwriter 的 IPC 出货器移植（L4 子集）：连接关闭事件行攒批
// （条数/字节/周期三阈值先到者触发）POST 到 unix socket 的
// POST /security-events/ingest，**只有 204 才算成功**（204=本批 DB commit
// 完成，跨进程契约）；失败整批原样写 spool（active/sealed 两态）供面板补采；
// 400/413 是永久拒绝（毒批重试无意义）→ 按真丢计数；spool 满/写失败 → 余下
// 行无文件兜底（L4 事件线没有审计文件层），按 spool_errors + dropped 计数。
//
// 与 HTTP 侧的两处有意差异：
//   - spool 目录独立为 /app/data/security-events-spool-l4（任务契约），
//     面板补采需扫描该目录（跨进程契约第三段的读侧职责）；
//   - IPC 显式关闭（env 置空串）= 纯丢弃模式（计数+节流告警），L4 无审计
//     文件兜底可用。
//
// 风暴自防（契约 C1）：2048 容量有界队列 + 64MiB 驻留字节预算 + 2s 有界入队
// 等待 + 64KiB 单行上限——超限丢弃并计数（dropped），不无界驻留。

const (
	l4IPCSocketEnv        = "LB_SECURITY_EVENTS_IPC_SOCKET"
	l4SpoolMaxBytesEnv    = "LB_SECURITY_EVENTS_SPOOL_MAX_BYTES"
	l4SpoolMaxEntriesEnv  = "LB_SECURITY_EVENTS_SPOOL_MAX_ENTRIES"
	l4SpoolDirEnv         = "LB_SECURITY_EVENTS_L4_SPOOL_DIR"
	l4IPCIngestPath       = "/security-events/ingest"
	l4IPCSocketHost       = "unix"
	l4SpoolActivePrefix   = "active-"
	l4SpoolSealedPrefix   = "sealed-"
	l4SpoolFileSuffix     = ".jsonl"
	l4DefaultIPCSocket    = "/app/data/security-events.sock"
	l4DefaultSpoolDirPath = "/app/data/security-events-spool-l4"

	// l4LineMaxBytes 单行上限：合成行由标量字段构成（无 body/快照膨胀面），
	// 64KiB 足够容纳任何现实形态；超限行属上游契约破坏，按丢弃计数。
	l4LineMaxBytes = 64 << 10
)

var (
	// l4SpoolDir spool 目录（包级变量：ConfigureWafDirs 类自定义 data_dir
	// 部署由进程环境派生——本包从 env 读 socket，spool 路径单一默认 + 测试
	// 重定向）。
	l4SpoolDir = l4DefaultSpoolDirPath
	// 攒批/队列/spool 可调量（var：与 auditwriter 同形态，测试按需收窄；
	// 生产恒走默认值）。
	l4RingCapacity     = 2048
	l4RingSlotBytes    = 8 << 10
	l4BatchMaxLines    = 100
	l4BatchMaxBytes    = int64(1024 * 1024)
	l4FlushInterval    = 50 * time.Millisecond
	l4IPCTimeout       = 2 * time.Second
	l4SpoolRotateBytes = int64(8 << 20)
	l4SpoolMaxBytes    = int64(64 << 20)
	l4SpoolMaxEntries  = int64(100_000)
	l4SpoolIdleSeal    = 2 * time.Second
	// l4SampleEvery 放行连接的国家归属采样间隔（契约 C3：每 16 连接取 1）。
	l4SampleEvery uint64 = 16
)

// l4SampleLookup 采样国家归属查库缝（Provision 期共享 searcher；测试重定向）。
var l4SampleLookup = func(xdbPath, ip string) (string, bool) {
	searcher, err := sharedGeoIPSearcher(xdbPath)
	if err != nil {
		return "", false
	}
	region, err := searcher.Search(ip)
	if err != nil || region == "" {
		return "", false
	}
	row, ok := parseRegionRow(region)
	if !ok {
		return "", false
	}
	// country 已归一：中国/规范英文国名；空串=无效键（Reserved/畸形），不入桶。
	return row.country, row.country != ""
}

// envInt64 读取整型 env（未设置/非法/非正数时返回默认值）。
func envInt64(name string, def int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// resolveIPCConfig 解析 IPC 配置：env 显式空串=关闭（丢弃模式）；未设置=容器
// 默认 socket。与 auditwriter 同一 env 名（与面板同一跨进程契约）。
func resolveIPCConfig() (enabled bool, socket string) {
	if v, ok := os.LookupEnv(l4IPCSocketEnv); ok {
		socket = strings.TrimSpace(v)
		if socket == "" {
			return false, ""
		}
		return true, socket
	}
	return true, l4DefaultIPCSocket
}

// l4Throttle 告警节流：首次立即，其后每分钟至多一条并携带被抑制数。
type l4Throttle struct {
	mu    sync.Mutex
	last  time.Time
	since int
}

func (t *l4Throttle) report(now time.Time) (suppressed int, logNow bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.since++
	suppressed = t.since - 1
	logNow = t.last.IsZero() || now.Sub(t.last) >= time.Minute
	if logNow {
		t.last = now
		t.since = 0
	}
	return suppressed, logNow
}

func l4DropLogf(format string, args ...any) {
	caddy.Log().Named("l4sec").Sugar().Warnf(format, args...)
}

func l4IOLogf(format string, args ...any) {
	caddy.Log().Named("l4sec").Sugar().Errorf(format, args...)
}

// —— spool（auditSpool 移植：active-<pid>-<seq>.jsonl → sealed-<unixnano>.jsonl）——

// l4Spool 是 IPC 失败行的本地暂存区（面板补采源）。预算按目录现存文件核算：
// 字节覆盖跨代残留（上一代遗留的补采队列同样受约束），条目记录本代已写行。
type l4Spool struct {
	mu            sync.Mutex
	dir           string
	maxBytes      int64
	maxEntries    int64
	rotateBytes   int64
	seq           uint64
	active        *os.File
	activePath    string
	bw            *bufio.Writer
	activeBytes   int64
	totalBytes    int64
	totalEntries  int64
	entriesByFile map[string]int64
	lastWrite     time.Time
	closed        bool
}

// openL4Spool 打开 spool 目录（0700，与面板侧 EnsureSecurityEventsSpoolDir
// 同权限口径）并核算跨代预算。
func openL4Spool(dir string, maxBytes, maxEntries int64) *l4Spool {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		l4IOLogf("l4sec: security-events spool dir unavailable at %s: %v", dir, err)
		return &l4Spool{dir: dir, maxBytes: -1, rotateBytes: l4SpoolRotateBytes, entriesByFile: map[string]int64{}}
	}
	s := &l4Spool{
		dir:           dir,
		maxBytes:      maxBytes,
		maxEntries:    maxEntries,
		rotateBytes:   l4SpoolRotateBytes,
		entriesByFile: make(map[string]int64),
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), l4SpoolFileSuffix) {
				continue
			}
			if info, ierr := e.Info(); ierr == nil {
				s.totalBytes += info.Size()
			}
		}
	}
	return s
}

// refreshBudgetLocked 让预算跟随面板的外部回收（sealed 被补采删除后释放）。
// 目录扫描失败保留上一份保守计数——观测失败不得放大预算。
func (s *l4Spool) refreshBudgetLocked() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	var totalBytes int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), l4SpoolFileSuffix) {
			continue
		}
		if info, statErr := entry.Info(); statErr == nil {
			totalBytes += info.Size()
		}
	}
	var totalEntries int64
	for path, count := range s.entriesByFile {
		if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
			delete(s.entriesByFile, path)
			continue
		}
		totalEntries += count
	}
	s.totalBytes = totalBytes
	s.totalEntries = totalEntries
}

// openActiveLocked 以 O_EXCL 建本次 active 文件（seq 单调，同名即跳过）。
func (s *l4Spool) openActiveLocked() error {
	pid := os.Getpid()
	for s.seq < 1<<40 {
		s.seq++
		path := filepath.Join(s.dir, fmt.Sprintf("%s%d-%d%s", l4SpoolActivePrefix, pid, s.seq, l4SpoolFileSuffix))
		fd, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o640)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		s.active = fd
		s.activePath = path
		s.bw = bufio.NewWriterSize(fd, 32*1024)
		s.activeBytes = 0
		return nil
	}
	return fmt.Errorf("l4sec: security-events spool exhausted active names in %s", s.dir)
}

// appendLines 追加一批行（每行自带换行），返回成功写入行数与停止原因
// （非 nil = 余下行由调用方转真丢计数）。单行顺序恒「内容+换行」。
func (s *l4Spool) appendLines(lines [][]byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errors.New("l4sec: security-events spool closed")
	}
	if s.maxBytes < 0 {
		return 0, errors.New("l4sec: security-events spool dir unavailable")
	}
	s.refreshBudgetLocked()
	if s.active == nil {
		if err := s.openActiveLocked(); err != nil {
			return 0, err
		}
	}
	written := 0
	for _, line := range lines {
		size := int64(len(line)) + 1
		if s.totalBytes+size > s.maxBytes || s.totalEntries+1 > s.maxEntries {
			_ = s.flushLocked()
			return written, errL4SpoolFull
		}
		if _, err := s.bw.Write(line); err != nil {
			// bufio 写失败后状态不可信（可能残留半行）：重建句柄防半行落盘。
			s.resetWriterLocked()
			return written, err
		}
		if err := s.bw.WriteByte('\n'); err != nil {
			s.resetWriterLocked()
			return written, err
		}
		written++
		s.totalBytes += size
		s.totalEntries++
		s.entriesByFile[s.activePath]++
		s.activeBytes += size
		s.lastWrite = time.Now()
		if s.activeBytes >= s.rotateBytes {
			if err := s.rotateLocked(); err != nil {
				return written, err
			}
		}
	}
	return written, s.flushLocked()
}

var errL4SpoolFull = errors.New("l4sec: security-events spool full")

func (s *l4Spool) noteActiveRenameLocked(oldPath, newPath string) {
	if count := s.entriesByFile[oldPath]; count != 0 {
		delete(s.entriesByFile, oldPath)
		s.entriesByFile[newPath] = count
	}
}

func (s *l4Spool) resetWriterLocked() {
	s.bw = nil
	if s.active != nil {
		_ = s.active.Close()
		s.active = nil
	}
	s.activePath = ""
}

func (s *l4Spool) flushLocked() error {
	if s.bw == nil {
		return nil
	}
	return s.bw.Flush()
}

func (s *l4Spool) sealedPathLocked() string {
	for k := 0; ; k++ {
		name := fmt.Sprintf("%s%d%s", l4SpoolSealedPrefix, time.Now().UnixNano(), l4SpoolFileSuffix)
		if k > 0 {
			name = fmt.Sprintf("%s%d-%d%s", l4SpoolSealedPrefix, time.Now().UnixNano(), k, l4SpoolFileSuffix)
		}
		path := filepath.Join(s.dir, name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return path
		}
	}
}

// rotateLocked 把 active 原子封存为 sealed 并开新 active。封存失败不丢行：
// 继续在同一 active 上追加（数据完整性优先于单文件大小约束）。
func (s *l4Spool) rotateLocked() error {
	if err := s.flushLocked(); err != nil {
		s.resetWriterLocked()
		return err
	}
	if s.activePath != "" {
		oldPath := s.activePath
		newPath := s.sealedPathLocked()
		if err := os.Rename(oldPath, newPath); err != nil {
			l4IOLogf("l4sec: security-events spool seal failed for %s (continuing on the same active): %v", s.activePath, err)
			return nil
		}
		s.noteActiveRenameLocked(oldPath, newPath)
		s.activePath = ""
	}
	s.bw = nil
	if s.active != nil {
		if err := s.active.Close(); err != nil {
			s.active = nil
			return err
		}
		s.active = nil
	}
	return s.openActiveLocked()
}

// sealIfIdle 把静默超窗的 active 封存：低失败量下 active 达不到轮转阈值，
// 而补采端只消费 sealed——不按时间封存则兜底条目滞留到进程退出。
func (s *l4Spool) sealIfIdle(now time.Time, idle time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.active == nil || s.activePath == "" || s.lastWrite.IsZero() {
		return nil
	}
	if now.Sub(s.lastWrite) < idle {
		return nil
	}
	if err := s.flushLocked(); err != nil {
		s.resetWriterLocked()
		return err
	}
	oldPath := s.activePath
	newPath := s.sealedPathLocked()
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	s.noteActiveRenameLocked(oldPath, newPath)
	s.activePath = ""
	s.bw = nil
	if s.active != nil {
		if err := s.active.Close(); err != nil {
			s.active = nil
			return err
		}
		s.active = nil
	}
	return nil
}

// close 收尾：刷盘 + 封存 active（本代最后一批不被封存则永不被补采）。
func (s *l4Spool) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.bw != nil {
		err = s.bw.Flush()
		s.bw = nil
	}
	if s.active != nil {
		if cerr := s.active.Close(); cerr != nil && err == nil {
			err = cerr
		}
		s.active = nil
	}
	if s.activePath != "" {
		oldPath := s.activePath
		newPath := s.sealedPathLocked()
		if rerr := os.Rename(oldPath, newPath); rerr == nil {
			s.noteActiveRenameLocked(oldPath, newPath)
			s.activePath = ""
		} else if err == nil {
			err = rerr
		}
	}
	return err
}

// —— 出货器（auditIPCShipper 移植）——

// l4Shipper 攒批 + POST + 失败落 spool。计数器是本进程投递/兜底过程量：
// 只供 shipper 与 /lb/l4-shipper-stats 观测（丢弃可观测要求），不写入跨进程
// 侧车（侧车契约属 HTTP 审计链）。
type l4Shipper struct {
	socket string
	client *http.Client
	spool  *l4Spool

	mu         sync.Mutex
	batch      [][]byte
	batchBytes int64
	batchSince time.Time

	// flushMu 串行化网络投递（mu 只保护批次缓冲，POST 期间不拖住 submit）。
	flushMu sync.Mutex

	sent      atomic.Uint64
	failed    atomic.Uint64
	spooled   atomic.Uint64
	spoolErrs atomic.Uint64

	// onDrop 是管线注入的丢弃计数回调（永久拒绝/兜底丢弃都汇入管线 dropped，
	// 统一对外口径）；nil=脱离管线构造（测试）。
	onDrop func(reason string, n int)

	spoolLog l4Throttle
}

// l4SpoolDirPath 解析 spool 目录：env LB_SECURITY_EVENTS_L4_SPOOL_DIR 优先
// （与面板补采侧同一 env 契约——写读分叉会让补采扫空目录），否则包级默认
// （容器契约路径）。
func l4SpoolDirPath() string {
	if v := strings.TrimSpace(os.Getenv(l4SpoolDirEnv)); v != "" {
		return v
	}
	return l4SpoolDir
}

// newL4Shipper 建出货器；spool 打不开不阻断投递（失败转真丢计数并告警，
// 否则「IPC 失败 + spool 缺失」会静默丢行）。
func newL4Shipper(socket string) *l4Shipper {
	s := &l4Shipper{
		socket: socket,
		client: &http.Client{
			Timeout: l4IPCTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
				MaxIdleConns:       2,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: true,
			},
		},
	}
	s.spool = openL4Spool(l4SpoolDirPath(), envInt64(l4SpoolMaxBytesEnv, l4SpoolMaxBytes), envInt64(l4SpoolMaxEntriesEnv, l4SpoolMaxEntries))
	return s
}

// submit 把一行接入批次；批满（条数/字节）立即投递。
func (s *l4Shipper) submit(line []byte) {
	s.mu.Lock()
	s.batch = append(s.batch, line)
	s.batchBytes += int64(len(line) + 1)
	if s.batchSince.IsZero() {
		s.batchSince = time.Now()
	}
	full := len(s.batch) >= l4BatchMaxLines || s.batchBytes >= l4BatchMaxBytes
	s.mu.Unlock()
	if full {
		s.flush()
	}
}

// flushIfDue 周期触发：首行到达满 l4FlushInterval 即投递 + idle 封存 spool。
func (s *l4Shipper) flushIfDue(now time.Time) {
	if s.spool != nil {
		if err := s.spool.sealIfIdle(now, l4SpoolIdleSeal); err != nil {
			l4IOLogf("l4sec: security-events spool idle seal failed: %v", err)
		}
	}
	s.mu.Lock()
	due := len(s.batch) > 0 && !s.batchSince.IsZero() && now.Sub(s.batchSince) >= l4FlushInterval
	s.mu.Unlock()
	if due {
		s.flush()
	}
}

// flush 投递当前批次（空批直接返回）。204=成功；400/413=永久拒绝（按真丢
// 计数，不进 spool）；其余失败整批落 spool。
func (s *l4Shipper) flush() {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	batch := s.batch
	s.batch = nil
	s.batchBytes = 0
	s.batchSince = time.Time{}
	s.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	status, err := s.post(batch)
	switch {
	case err == nil:
		s.sent.Add(uint64(len(batch)))
	case status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge:
		s.failed.Add(uint64(len(batch)))
		s.noteDrop(fmt.Sprintf("security-events ingest permanently rejected batch (HTTP %d)", status), len(batch))
	default:
		s.failed.Add(uint64(len(batch)))
		s.spill(batch, err)
	}
}

// noteDrop 经管线回调累计丢弃计数（nil 安全：shipper 可脱离管线构造）。
func (s *l4Shipper) noteDrop(reason string, n int) {
	if s.onDrop != nil {
		s.onDrop(reason, n)
	}
}

// spill 把整批失败行写 spool；spool 不可用/满/写错的余下行无文件兜底
// （L4 无审计文件层）→ spool_errors + dropped 计数（真丢必须可观测）。
func (s *l4Shipper) spill(batch [][]byte, cause error) {
	remaining := batch
	if s.spool != nil {
		written, err := s.spool.appendLines(batch)
		if written > 0 {
			s.spooled.Add(uint64(written))
		}
		remaining = batch[written:]
		if err != nil {
			s.reportSpoolError(cause, err, len(remaining))
			s.spoolErrs.Add(uint64(len(remaining)))
			s.noteDrop("spool unavailable", len(remaining))
			return
		}
		if len(remaining) == 0 {
			return
		}
	} else {
		s.reportSpoolError(cause, errors.New("spool unavailable"), len(remaining))
	}
	s.spoolErrs.Add(uint64(len(remaining)))
	s.noteDrop("spool unavailable", len(remaining))
}

// reportSpoolError spool 写失败节流告警（首次立即，其后每分钟一条）。
func (s *l4Shipper) reportSpoolError(cause, spoolErr error, lines int) {
	if _, logNow := s.spoolLog.report(time.Now()); logNow {
		l4IOLogf("l4sec: security-events spool write failed (%d line(s) dropped, no file fallback): ipc=%v spool=%v", lines, cause, spoolErr)
	}
}

// post 投递一批：body=换行分隔行+末尾 \n。返回 HTTP 状态码与错误（连接失败
// 状态码为 0）。只有 204 算成功。
func (s *l4Shipper) post(batch [][]byte) (int, error) {
	total := 0
	for _, line := range batch {
		total += len(line) + 1
	}
	buf := bytes.NewBuffer(make([]byte, 0, total))
	for _, line := range batch {
		buf.Write(line)
		buf.WriteByte('\n')
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://"+l4IPCSocketHost+l4IPCIngestPath, buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusNoContent {
		return resp.StatusCode, fmt.Errorf("security-events ingest status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// close 收尾：投递残留批、封存 spool、关空闲连接。
func (s *l4Shipper) close() {
	s.flush()
	if s.spool != nil {
		if err := s.spool.close(); err != nil {
			l4IOLogf("l4sec: security-events spool close failed: %v", err)
		}
	}
	if tr, ok := s.client.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func (s *l4Shipper) counters() (sent, failed, spooled, spoolErrs uint64) {
	if s == nil {
		return 0, 0, 0, 0
	}
	return s.sent.Load(), s.failed.Load(), s.spooled.Load(), s.spoolErrs.Load()
}

func (s *l4Shipper) pendingLines() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batch)
}

// —— 管线（auditPipeline 子集：队列 + drain + 出货器；无文件模式、无侧车）——

// l4Pipeline 是进程级单例投递管线。生命周期与 auditwriter acquireAuditPipeline
// 同一裁决：drain 与 shipper 活到进程退出（Caddy 重载不回收——回收语义只在
// 计数层，见 stats.go beginLoad），杜绝 teardown 竞态丢事件。
type l4Pipeline struct {
	// ring=覆写环形缓冲（方案③）：入队永不阻塞（满环覆写最旧），内存精确
	// 上界=容量×槽字节。depth==0 蕴含队列空——收尾刷盘据此排空。
	ring   *l4Ring
	notify chan struct{} // cap 1 非阻塞唤启 drain（满时静默，drain 轮询兜底）
	// dropped 丢弃事件行累计（队列满/字节预算/单行上限/IPC 关闭/永久拒绝/
	// spool 失败），/lb/l4-shipper-stats 暴露。
	dropped atomic.Uint64

	shipper   *l4Shipper // nil = IPC 关闭（丢弃模式）
	dropLog   l4Throttle
	stopCh    chan struct{}
	done      chan struct{}
	paused    atomic.Bool // 测试缝：暂停 drain 消费（制造队列满）
	sinkMu    sync.Mutex
	sink      func([]byte) // 测试缝：drain submit 落点（nil=shipper/丢弃）
	startOnce sync.Once
}

var (
	l4PipelineMu      sync.Mutex
	l4GlobalPipeline  *l4Pipeline
	l4PipelineForTest func() // 测试注入的 global 重建钩子（tests 设置；生产 nil）
)

// acquirePipeline 返回进程级管线单例（首次创建时解析 IPC 配置并启动 drain）。
func acquirePipeline() *l4Pipeline {
	l4PipelineMu.Lock()
	defer l4PipelineMu.Unlock()
	if l4GlobalPipeline != nil {
		return l4GlobalPipeline
	}
	p := newL4Pipeline()
	l4GlobalPipeline = p
	p.start()
	return p
}

// newL4Pipeline 按当前 env/可调量构造管线（不启动 drain）。
func newL4Pipeline() *l4Pipeline {
	p := &l4Pipeline{
		ring:   newL4Ring(l4RingCapacity, l4RingSlotBytes),
		notify: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
	if enabled, socket := resolveIPCConfig(); enabled {
		p.shipper = newL4Shipper(socket)
		p.shipper.onDrop = p.reportDropped
	}
	return p
}

// currentL4Pipeline 返回进程级管线（未创建=nil）。
func currentL4Pipeline() *l4Pipeline {
	l4PipelineMu.Lock()
	defer l4PipelineMu.Unlock()
	return l4GlobalPipeline
}

func (p *l4Pipeline) start() {
	p.startOnce.Do(func() {
		go p.drain()
	})
}

// enqueueEvent 有界入队：先字节预算后容量等待，超限/超时丢弃计数（风暴自防
// ——连接路径最多为一批驻留付出 enqueue 超时，事件行恒定小体量）。
func (p *l4Pipeline) enqueueEvent(line []byte) {
	// 零阻塞（方案③）：结构上不存在等待——满环覆写最旧，连接路径恒定纳秒级
	// 返回（风暴不放大 fd/goroutine 驻留）。单行上限把守槽增长上界：环内
	// 不存在超界行。
	if int64(len(line)+1) > l4LineMaxBytes {
		p.reportDropped("line exceeds per-line cap", 1)
		return
	}
	if evicted := p.ring.push(line); evicted > 0 {
		p.reportDropped("ring overwritten (oldest)", int(evicted))
	}
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

// reportDropped 丢弃计数 + 节流告警（首次立即，其后每分钟一条）——丢弃必须
// 可观测。
func (p *l4Pipeline) reportDropped(reason string, n int) {
	if n <= 0 {
		return
	}
	total := p.dropped.Add(uint64(n))
	if suppressed, logNow := p.dropLog.report(time.Now()); logNow {
		l4DropLogf("l4sec: %s, dropped %d security event line(s) (total dropped %d, suppressed %d since last report)", reason, n, total, suppressed)
	}
}

// drain 专职投递 goroutine：消费队列 → submit → 周期 flush + idle 封存。
// stop 后先排空队列余量再收尾（flush + 封存 spool + 关连接）。暂停（测试缝）
// 在消费前判定——行留在队列里占位，保证「队列满」形态确定。
func (p *l4Pipeline) drain() {
	defer close(p.done)
	ticker := time.NewTicker(l4FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			p.drainRemainder()
			return
		case <-p.notify:
		case <-ticker.C:
			p.flushIfDueSafely()
		}
		if p.paused.Load() {
			time.Sleep(time.Millisecond)
			continue
		}
		p.popAndSubmit()
	}
}

// popAndSubmit 弹出环形缓冲当前全部行并逐行 submit（批内由 shipper 攒批）。
func (p *l4Pipeline) popAndSubmit() {
	for {
		line, ok := p.ring.pop()
		if !ok {
			return
		}
		p.submit(line)
		p.flushIfDueSafely()
	}
}

// drainRemainder 排空队列余量后收尾（flush 残留批 + 封存 spool + 关连接）。
func (p *l4Pipeline) drainRemainder() {
	for p.ring.depth() > 0 {
		line, ok := p.ring.pop()
		if !ok {
			break
		}
		p.submit(line)
	}
	p.flushNowSafely()
	p.closeShipper()
}

func (p *l4Pipeline) submit(line []byte) {
	p.sinkMu.Lock()
	sink := p.sink
	p.sinkMu.Unlock()
	switch {
	case sink != nil:
		sink(line)
	case p.shipper != nil:
		p.shipper.submit(line)
	default:
		p.reportDropped("ipc disabled", 1)
	}
}

func (p *l4Pipeline) flushIfDueSafely() {
	if p.shipper == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			l4DropLogf("l4sec: recovered panic while shipping security events: %v", recovered)
		}
	}()
	p.shipper.flushIfDue(time.Now())
}

// flushNowSafely 收尾无条件冲刷（批龄门只适用于周期刷新）。
func (p *l4Pipeline) flushNowSafely() {
	if p.shipper == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			l4DropLogf("l4sec: recovered panic while flushing security events: %v", recovered)
		}
	}()
	p.shipper.flush()
}

func (p *l4Pipeline) closeShipper() {
	if p.shipper == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			l4DropLogf("l4sec: recovered panic while closing security-events shipper: %v", recovered)
		}
	}()
	p.shipper.close()
}

// flushQuiesced 等待已准入事件全部处理完（pending==0）后冲刷残留批。
func (p *l4Pipeline) flushQuiesced(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for p.ring.depth() > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	p.flushNowSafely()
}

// shipperCounters 投递/兜底过程计数（/lb/l4-shipper-stats 消费）。
func (p *l4Pipeline) shipperCounters() (sent, failed, spooled, spoolErrs uint64) {
	if p.shipper == nil {
		return 0, 0, 0, 0
	}
	return p.shipper.counters()
}
