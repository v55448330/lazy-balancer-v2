package services

// 安全事件采集的 B 形态：Caddy 审计写侧经 Unix socket 把原始 audit JSON 行
// 直接投递给面板（IPC 主路径），面板入库失败时写侧落 fallback spool 文件，
// 由本文件的补采路径兜底。Caddy 侧永不直连数据库。
//
// 本文件的三个职责：
//  1. IngestSecurityEventBatch：IPC 与 spool 补采共用的批量入库入口——解析/
//     归因/去重/自动封禁/光流/rollup 全部复用 securityEventsProcessPass
//     （tailer 单一实现），不引入第二套插入逻辑；
//  2. spool 目录扫描 + 补采（sealed 文件 commit 成功后才删除，active 不删不截断）；
//  3. spool 待补采状态（健康位 + /logs/stats cache_* 字段的单源）。
//
// 跨进程契约（与 caddygeoip auditwriter 写侧逐字对齐，改一侧必须同步另一侧）：
//   - socket 路径 env LB_SECURITY_EVENTS_IPC_SOCKET（默认 /app/data/security-events.sock）；
//   - spool 目录 env LB_SECURITY_EVENTS_SPOOL_DIR（默认 /app/data/security-events-spool）；
//   - 上限 env LB_SECURITY_EVENTS_SPOOL_MAX_ENTRIES（默认 100000）/
//     LB_SECURITY_EVENTS_SPOOL_MAX_BYTES（默认 64MiB）——写侧据此丢弃并计数，
//     面板侧据此报告 cache_limit_* 与「spool 满」；
//   - 文件命名 active-<pid>-<seq>.jsonl（写侧追加中）→ sealed-<unixnano>.jsonl
//     （写侧原子 rename 封存）；每行一条 audit JSON；
//   - POST /security-events/ingest，body 为换行分隔 audit JSON，204 仅代表
//     DB commit 完成。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	// SecurityEventsIPCSocketEnv 是 IPC socket 路径的环境变量名。
	SecurityEventsIPCSocketEnv = "LB_SECURITY_EVENTS_IPC_SOCKET"
	// SecurityEventsSpoolDirEnv 是 fallback spool 目录的环境变量名。
	SecurityEventsSpoolDirEnv = "LB_SECURITY_EVENTS_SPOOL_DIR"
	// SecurityEventsSpoolMaxEntriesEnv / SecurityEventsSpoolMaxBytesEnv 是 spool
	// 上限（与 Caddy 写侧同一契约）：面板侧只读取用于报告与「满」判定。
	SecurityEventsSpoolMaxEntriesEnv = "LB_SECURITY_EVENTS_SPOOL_MAX_ENTRIES"
	SecurityEventsSpoolMaxBytesEnv   = "LB_SECURITY_EVENTS_SPOOL_MAX_BYTES"

	// DefaultSecurityEventsIPCSocket / DefaultSecurityEventsSpoolDir 是容器默认
	// 形态（data_dir=/app/data）。自定义 data_dir 经 ConfigureWafDirs 派生。
	DefaultSecurityEventsIPCSocket = "/app/data/security-events.sock"
	DefaultSecurityEventsSpoolDir  = "/app/data/security-events-spool"

	// DefaultSecurityEventsSpoolMaxEntries / DefaultSecurityEventsSpoolMaxBytes
	// 与写侧默认值同源（100k 条 / 64MiB）。
	DefaultSecurityEventsSpoolMaxEntries = 100000
	DefaultSecurityEventsSpoolMaxBytes   = 64 << 20

	// SecurityEventsIPCIngestPath 是 IPC 入库端点路径（写侧硬编码同一路径）。
	SecurityEventsIPCIngestPath = "/security-events/ingest"
	// securityEventsIPCMaxBodyBytes 是单次 IPC 请求体上限（写侧批上限 100 行 /
	// 1MiB，本值留足余量；超出以 413 拒绝——写侧对 4xx 不 spool，避免毒批重试）。
	securityEventsIPCMaxBodyBytes = 8 << 20

	// spool 文件名前缀/后缀（写侧契约）。
	securityEventsSpoolActivePrefix = "active-"
	securityEventsSpoolSealedPrefix = "sealed-"
	securityEventsSpoolFileSuffix   = ".jsonl"

	// securityEventsSpoolOrphanIdle 是「孤儿 active」的静默判据：pid 已不存在且
	// mtime 静默超过该窗口才封存（写侧在进程收尾时会自行封存自己的 active，
	// 只有崩溃遗留才需要面板侧介入；静默窗口避免与写侧 rename 竞争）。
	securityEventsSpoolOrphanIdle = 2 * time.Minute
	// securityEventsSpoolStatusTTL 是 spool 状态（含逐文件行计数）的缓存窗口：
	// 健康位 2s 节拍与 /logs/stats 轮询共用同一快照，避免每轮重读整个 spool。
	securityEventsSpoolStatusTTL = 10 * time.Second
	// securityEventsSpoolBackoffMax 是补采失败的最大退避（DB busy/磁盘故障）。
	securityEventsSpoolBackoffMax = 60 * time.Second
)

// ErrSecurityEventsIngestUnavailable 表示批量入库依赖（数据库句柄）未就绪：
// IPC 侧映射 503（写侧按可重试处理、保留 spool），不得当成永久失败。
var ErrSecurityEventsIngestUnavailable = errors.New("security events: ingest dependencies unavailable")

// errSecurityEventsBatchIncomplete 表示批量入库在批次边界被取消（未消费完整批）：
// spool 补采据此保留文件（已提交的批次幂等，重试无重复）。
var errSecurityEventsBatchIncomplete = errors.New("security events: batch ingest incomplete")

// 包级路径变量（ConfigureWafDirs 按 data_dir 派生；测试可直接改写）。
var (
	securityEventsIPCSocketPath = DefaultSecurityEventsIPCSocket
	securityEventsSpoolDir      = DefaultSecurityEventsSpoolDir
)

// SecurityEventsIPCSocketPath 返回 IPC socket 路径（env 优先，其次派生值）。
func SecurityEventsIPCSocketPath() string {
	if v := strings.TrimSpace(os.Getenv(SecurityEventsIPCSocketEnv)); v != "" {
		return v
	}
	return securityEventsIPCSocketPath
}

// SecurityEventsSpoolDir 返回 fallback spool 目录（env 优先，其次派生值）。
func SecurityEventsSpoolDir() string {
	if v := strings.TrimSpace(os.Getenv(SecurityEventsSpoolDirEnv)); v != "" {
		return v
	}
	return securityEventsSpoolDir
}

// EnsureSecurityEventsSpoolDir 启动期建 spool 目录（0700，与写侧同用户同容器）：
// 写侧 IPC 失败时要能立刻落盘兜底，不能等第一次失败才发现目录不存在。
// 权限口径与审计数据目录一致（仅本用户可读写）。
func EnsureSecurityEventsSpoolDir() error {
	dir := SecurityEventsSpoolDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建安全事件待补采目录 %s 失败: %w", dir, err)
	}
	return nil
}

// SecurityEventsIPCMaxBodyBytes 是 IPC 单请求体上限（handlers 侧 MaxBytesReader 用）。
func SecurityEventsIPCMaxBodyBytes() int64 { return securityEventsIPCMaxBodyBytes }

// securityEventsSpoolLimits 返回 spool 上限（写侧同一 env 契约）：解析失败按
// 默认值处理（上限只用于报告/「满」判定，不参与写入）。
func securityEventsSpoolLimits() (entries, bytesLimit int64) {
	entries, bytesLimit = DefaultSecurityEventsSpoolMaxEntries, int64(DefaultSecurityEventsSpoolMaxBytes)
	if v := strings.TrimSpace(os.Getenv(SecurityEventsSpoolMaxEntriesEnv)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			entries = n
		}
	}
	if v := strings.TrimSpace(os.Getenv(SecurityEventsSpoolMaxBytesEnv)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			bytesLimit = n
		}
	}
	return entries, bytesLimit
}

// securityEventsBatchIngestState 串行化批量入库。请求级去重表与 live/归档
// 补采共享 securityEventsSharedDedupe；批锁只约束 IPC/spool 两路，跨通道的
// lookup→落库→record 原子性由 process pass 的去重锁保证。
var securityEventsBatchIngestState struct {
	mu     sync.Mutex
	dedupe *securityEventsRequestDeduper
}

type securityEventsBatchInput struct {
	*bytes.Reader
	size int64
}

func (b *securityEventsBatchInput) Stat() (os.FileInfo, error) {
	return securityEventsBatchFileInfo(b.size), nil
}

type securityEventsBatchFileInfo int64

func (securityEventsBatchFileInfo) Name() string       { return "memory-batch.jsonl" }
func (b securityEventsBatchFileInfo) Size() int64      { return int64(b) }
func (securityEventsBatchFileInfo) Mode() os.FileMode  { return 0o600 }
func (securityEventsBatchFileInfo) ModTime() time.Time { return time.Time{} }
func (securityEventsBatchFileInfo) IsDir() bool        { return false }
func (securityEventsBatchFileInfo) Sys() any           { return nil }

// IngestSecurityEventBatch 解析并入库一批换行分隔的原始 audit JSON 行，返回
// 实际新增行数（INSERT OR IGNORE 忽略的重复行不计）。IPC 请求与 spool 补采
// 共用本入口：解析/归因/去重/自动封禁/光流/rollup 全部走既有
// securityEventsProcessPass——禁止在此另写插入逻辑。
//
// 输入以内存 ReadSeeker 喂给文件流解析核心：每批零临时文件、零磁盘 IO，
// 不生成常规 audit.log、不参与轮转、不留任何持久产物。
func IngestSecurityEventBatch(ctx context.Context, raw []byte) (int, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0, nil
	}
	if db.DB == nil || db.MetricsDB == nil {
		return 0, ErrSecurityEventsIngestUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rules, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		return 0, err
	}

	securityEventsBatchIngestState.mu.Lock()
	defer securityEventsBatchIngestState.mu.Unlock()
	if securityEventsBatchIngestState.dedupe == nil {
		securityEventsBatchIngestState.dedupe = securityEventsSharedDedupe
	}

	f := &securityEventsBatchInput{Reader: bytes.NewReader(raw), size: int64(len(raw))}

	t := securityEventsNewTailer("", "")
	// 批输入是有界且不再增长的文件：归档 pass 语义（畸形段 scan-to-EOF 跳过，
	// 不进入「等待写侧补全」的停等）。
	t.archivePass = true
	t.dedupe = securityEventsBatchIngestState.dedupe
	if _, err := t.securityEventsProcessPass(ctx, f, 0, rules, bindings, policyByID); err != nil {
		return t.lastIngested, err
	}
	// 取消发生在批次边界时 pass 会正常返回但未消费完整批：已提交行幂等，
	// 调用方（spool）必须保留文件重试，不得按成功删除。
	if t.passBoundHit {
		return t.lastIngested, errSecurityEventsBatchIncomplete
	}
	return t.lastIngested, nil
}

// SecurityEventsSpoolStatus 是 fallback spool 的待补采快照（健康位与
// /logs/stats cache_* 字段的单源）。Pending（待补采）与丢失是两个相反结论：
// 这些事件仍在磁盘上、可由补采入库，不得计入 DataLoss。
type SecurityEventsSpoolStatus struct {
	Dir         string `json:"dir"`
	ActiveFiles int    `json:"active_files"`
	SealedFiles int    `json:"sealed_files"`
	// Entries 是待补采审计条目数（含尚未封存的 active 文件，按非空行计）。
	Entries int64 `json:"entries"`
	Bytes   int64 `json:"bytes"`
	// LimitEntries / LimitBytes 是写侧同一契约的上限（仅用于报告）。
	LimitEntries int64 `json:"limit_entries"`
	LimitBytes   int64 `json:"limit_bytes"`
	// Unavailable 表示 spool 目录存在但不可读：计数不可用（不是「0 条」）。
	Unavailable bool `json:"unavailable,omitempty"`
	// Saturated 表示 spool 已达上限：写侧很可能正在丢弃新事件（健康位降级）。
	Saturated bool `json:"saturated,omitempty"`
	// ConsecutiveFailures / LastError 是补采失败（DB busy/写盘故障）状态——
	// 失败只推迟补采，待补采条目仍保留。
	ConsecutiveFailures int    `json:"consecutive_failures,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	LastErrorAt         string `json:"last_error_at,omitempty"`
	LastDrainedEntries  int    `json:"-"`
	LastDrainedAt       string `json:"last_drained_at,omitempty"`
}

// securityEventsSpoolState 是 spool 状态缓存 + 补采退避状态（一个锁：
// 状态快照与退避判定必须一致）。
type securityEventsSpoolStateT struct {
	mu        sync.Mutex
	cachedAt  time.Time
	status    SecurityEventsSpoolStatus
	haveCache bool

	drainFailures int
	nextAttempt   time.Time
	drainErr      string
	drainErrAt    time.Time
	lastDrained   int
	lastDrainedAt time.Time
}

var securityEventsSpoolState securityEventsSpoolStateT

type securityEventsSpoolCountCacheEntry struct {
	size           int64
	mod            time.Time
	offset         int64
	entries        int64
	lineHasContent bool
}

var securityEventsSpoolCountCache = struct {
	sync.Mutex
	files map[string]securityEventsSpoolCountCacheEntry
}{files: map[string]securityEventsSpoolCountCacheEntry{}}

// testseam: 留驻产品文件的测试观测计数器——由生产读取路径（spool 条目装载）
// 自增、spool 计数缓存测试读取；宿主不可能在 *_test.go。
var securityEventsSpoolEntryReadBytesForTest atomic.Int64

// testseam: 留驻产品文件的测试缝——只被测试消费的缓存复位入口。
func resetSecurityEventsSpoolEntryCountCacheForTest() {
	securityEventsSpoolCountCache.Lock()
	securityEventsSpoolCountCache.files = map[string]securityEventsSpoolCountCacheEntry{}
	securityEventsSpoolCountCache.Unlock()
}

// securityEventsSpoolStatusFresh 现扫 spool 目录（绕过状态 TTL）。逐文件行数
// 另按 (size,mtime,append offset) 缓存：未变化文件零读取，追加中的 active 文件
// 只读新增字节，避免每 10s 重读整批 sealed 文件。
func securityEventsSpoolStatusFresh() SecurityEventsSpoolStatus {
	dir := SecurityEventsSpoolDir()
	limitEntries, limitBytes := securityEventsSpoolLimits()
	status := SecurityEventsSpoolStatus{Dir: dir, LimitEntries: limitEntries, LimitBytes: limitBytes}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			status.Unavailable = true
		}
		return status
	}
	seen := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, securityEventsSpoolSealedPrefix) && strings.HasSuffix(name, securityEventsSpoolFileSuffix):
			status.SealedFiles++
		case strings.HasPrefix(name, securityEventsSpoolActivePrefix) && strings.HasSuffix(name, securityEventsSpoolFileSuffix):
			status.ActiveFiles++
		default:
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			if !os.IsNotExist(ierr) {
				status.Unavailable = true
			}
			continue
		}
		status.Bytes += info.Size()
		path := filepath.Join(dir, name)
		seen[path] = struct{}{}
		if info.Size() == 0 {
			continue
		}
		n, cerr := securityEventsSpoolCountEntriesCached(path, info)
		if cerr != nil {
			if !os.IsNotExist(cerr) {
				status.Unavailable = true
			}
			continue
		}
		status.Entries += n
	}
	securityEventsSpoolCountCache.Lock()
	for path := range securityEventsSpoolCountCache.files {
		if _, ok := seen[path]; !ok {
			delete(securityEventsSpoolCountCache.files, path)
		}
	}
	securityEventsSpoolCountCache.Unlock()
	status.Saturated = (limitEntries > 0 && status.Entries >= limitEntries) ||
		(limitBytes > 0 && status.Bytes >= limitBytes)
	return status
}

func securityEventsSpoolCountEntriesCached(path string, info os.FileInfo) (int64, error) {
	securityEventsSpoolCountCache.Lock()
	defer securityEventsSpoolCountCache.Unlock()
	cached, ok := securityEventsSpoolCountCache.files[path]
	if ok && cached.size == info.Size() && cached.mod.Equal(info.ModTime()) {
		return cached.entries, nil
	}
	var offset, entries int64
	lineHasContent := false
	if ok && info.Size() > cached.offset {
		// spool 只追加：无论上次以完整行还是半行收尾，都只读取旧 EOF
		// 之后的新增字节。半行已计入 cached.entries；续读结果会再次计入
		// 该条（无论它本轮是否完成），合并时减去这次重叠。
		offset, entries, lineHasContent = cached.offset, cached.entries, cached.lineHasContent
	}
	result, err := securityEventsSpoolCountEntriesFrom(path, offset, lineHasContent)
	if err != nil {
		return 0, err
	}
	entries += result.entries
	if lineHasContent && result.entries > 0 {
		entries--
	}
	securityEventsSpoolCountCache.files[path] = securityEventsSpoolCountCacheEntry{
		size: result.offset, mod: result.mod, offset: result.offset, entries: entries, lineHasContent: result.lineHasContent,
	}
	return entries, nil
}

type securityEventsSpoolCountResult struct {
	entries        int64
	offset         int64
	mod            time.Time
	lineHasContent bool
}

// securityEventsSpoolCountEntriesFrom 流式读取指定偏移后的新增内容；末行无
// 换行同样计入。返回实际读取到的 EOF 与文件状态，调用方不得拿读取前的
// Info.Size 充当 offset——Info 与 Read 之间的并发追加会使两者分叉。
func securityEventsSpoolCountEntriesFrom(path string, offset int64, lineHasContent bool) (securityEventsSpoolCountResult, error) {
	result := securityEventsSpoolCountResult{offset: offset, lineHasContent: lineHasContent}
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return result, err
	}
	buf := make([]byte, 64<<10)
	for {
		n, rerr := f.Read(buf)
		securityEventsSpoolEntryReadBytesForTest.Add(int64(n))
		result.offset += int64(n)
		for _, b := range buf[:n] {
			switch b {
			case '\n':
				if result.lineHasContent {
					result.entries++
				}
				result.lineHasContent = false
			case ' ', '\t', '\r':
			default:
				result.lineHasContent = true
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return result, rerr
		}
	}
	if result.lineHasContent {
		result.entries++
	}
	info, err := f.Stat()
	if err != nil {
		return result, err
	}
	result.mod = info.ModTime()
	return result, nil
}

// SecurityEventsSpoolStatus 返回带缓存（TTL 内复用，补采/封存后失效）的
// spool 快照，并叠加补采失败状态。
func SecurityEventsSpoolSnapshot() SecurityEventsSpoolStatus {
	securityEventsSpoolState.mu.Lock()
	defer securityEventsSpoolState.mu.Unlock()
	if securityEventsSpoolState.haveCache && time.Since(securityEventsSpoolState.cachedAt) < securityEventsSpoolStatusTTL {
		return securityEventsSpoolState.withDrainStateLocked(securityEventsSpoolState.status)
	}
	status := securityEventsSpoolStatusFresh()
	securityEventsSpoolState.status = status
	securityEventsSpoolState.cachedAt = time.Now()
	securityEventsSpoolState.haveCache = true
	return securityEventsSpoolState.withDrainStateLocked(status)
}

// withDrainStateLocked 叠加补采失败/最近成功字段（调用方持锁）。
func (s *securityEventsSpoolStateT) withDrainStateLocked(status SecurityEventsSpoolStatus) SecurityEventsSpoolStatus {
	status.ConsecutiveFailures = s.drainFailures
	status.LastError = s.drainErr
	if !s.drainErrAt.IsZero() {
		status.LastErrorAt = s.drainErrAt.UTC().Format(time.RFC3339)
	}
	status.LastDrainedEntries = s.lastDrained
	if !s.lastDrainedAt.IsZero() {
		status.LastDrainedAt = s.lastDrainedAt.UTC().Format(time.RFC3339)
	}
	return status
}

// invalidateSecurityEventsSpoolStatus 让下一次读取重新扫描（补采/封存后调用）。
func invalidateSecurityEventsSpoolStatus() {
	securityEventsSpoolState.mu.Lock()
	securityEventsSpoolState.haveCache = false
	securityEventsSpoolState.mu.Unlock()
}

// securityEventsSpoolFile 是 spool 目录中的一个待补采文件。
type securityEventsSpoolFile struct {
	name   string
	path   string
	sealed bool
	mod    time.Time
	pid    int // active 文件的写侧 pid（sealed 为 0）
}

// listSecurityEventsSpoolFiles 列出 spool 中的 active/sealed 文件（按名字排序：
// sealed-<unixnano> 字典序≈时间序，补采按顺序保持因果）。
func listSecurityEventsSpoolFiles() ([]securityEventsSpoolFile, error) {
	dir := SecurityEventsSpoolDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	files := make([]securityEventsSpoolFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, securityEventsSpoolFileSuffix) {
			continue
		}
		f := securityEventsSpoolFile{name: name, path: filepath.Join(dir, name)}
		switch {
		case strings.HasPrefix(name, securityEventsSpoolSealedPrefix):
			f.sealed = true
		case strings.HasPrefix(name, securityEventsSpoolActivePrefix):
			f.pid = securityEventsSpoolActivePID(name)
		default:
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			if os.IsNotExist(ierr) {
				continue
			}
			return nil, ierr
		}
		f.mod = info.ModTime()
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files, nil
}

// securityEventsSpoolActivePID 从 active-<pid>-<seq>.jsonl 解析写侧 pid；
// 解析失败返回 0（不参与孤儿封存）。
func securityEventsSpoolActivePID(name string) int {
	rest := strings.TrimSuffix(strings.TrimPrefix(name, securityEventsSpoolActivePrefix), securityEventsSpoolFileSuffix)
	pidPart, _, ok := strings.Cut(rest, "-")
	if !ok {
		return 0
	}
	pid, err := strconv.Atoi(pidPart)
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

// securityEventsSpoolProcessAlive 判断 pid 是否仍存在（EPERM=存在但无权限）。
func securityEventsSpoolProcessAlive(pid int) bool {
	if pid <= 0 {
		return true // 未知 pid 按存活处理，不冒进封存
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// sealOrphanedSecurityEventsSpoolFiles 把「写侧进程已不存在且文件静默」
// 的 active 文件原子重命名为 sealed-*：写侧崩溃遗留的 active 否则永远不会被
// 补采（写侧只封存自己的 active）。这是重命名不是删除/截断——写侧不会碰
// 别人 pid 的 active，故无竞争；静默窗口 + pid 存活双判据保证不会截断在写的文件。
func sealOrphanedSecurityEventsSpoolFiles(files []securityEventsSpoolFile, now time.Time) (sealed int) {
	for _, f := range files {
		if f.sealed || f.pid == 0 {
			continue
		}
		if now.Sub(f.mod) < securityEventsSpoolOrphanIdle {
			continue
		}
		if securityEventsSpoolProcessAlive(f.pid) {
			continue
		}
		// 目标名按 mtime 纳秒（与写侧 sealed-<unixnano> 同构），冲突时追加
		// -<k>（rename 会覆盖同名目标，必须先确认名字空闲——覆盖=丢一整批事件）。
		dir := filepath.Dir(f.path)
		target := filepath.Join(dir, securityEventsSpoolSealedPrefix+strconv.FormatInt(f.mod.UnixNano(), 10)+securityEventsSpoolFileSuffix)
		for k := 1; ; k++ {
			if _, err := os.Lstat(target); os.IsNotExist(err) {
				break
			}
			target = filepath.Join(dir, fmt.Sprintf("%s%d-%d%s", securityEventsSpoolSealedPrefix, f.mod.UnixNano(), k, securityEventsSpoolFileSuffix))
		}
		if err := os.Rename(f.path, target); err != nil {
			Logf("warn", "security events spool: 孤儿 active 文件封存失败 %s: %v", f.name, err)
			continue
		}
		Logf("warn", "security events spool: 写侧进程 %d 已退出，active 文件 %s 已封存为待补采", f.pid, f.name)
		sealed++
	}
	return sealed
}

// drainSecurityEventsSpool 补采 sealed 文件（调用方：security-events-ingestion
// 任务每轮；ctx 取消在批次边界收尾）。返回本轮实际入库行数。
//
// 语义：
//   - 只有 IngestSecurityEventBatch 成功（DB commit 完成）才删除 sealed 文件；
//   - 失败（DB busy 等）保留文件并按指数退避跳过后续若干轮，本轮终止（保持
//     文件顺序：前一个没入库就不跳过它去处理后一个）；
//   - active 文件永不删除/截断（仅孤儿封存为 sealed 后走同一补采）；
//   - 失败退避期间返回 (0, nil)：待补采条目仍由健康位/统计暴露，不是丢失。
func drainSecurityEventsSpool(ctx context.Context) (int, error) {
	securityEventsSpoolState.mu.Lock()
	if time.Now().Before(securityEventsSpoolState.nextAttempt) {
		securityEventsSpoolState.mu.Unlock()
		return 0, nil
	}
	securityEventsSpoolState.mu.Unlock()

	files, err := listSecurityEventsSpoolFiles()
	if err != nil {
		return 0, securityEventsSpoolRecordFailure(fmt.Errorf("security events spool: read dir: %w", err))
	}
	if sealed := sealOrphanedSecurityEventsSpoolFiles(files, time.Now()); sealed > 0 {
		invalidateSecurityEventsSpoolStatus()
		if files, err = listSecurityEventsSpoolFiles(); err != nil {
			return 0, securityEventsSpoolRecordFailure(fmt.Errorf("security events spool: read dir: %w", err))
		}
	}
	ingested := 0
	hasSealed := false
	for _, f := range files {
		if !f.sealed {
			continue
		}
		hasSealed = true
		if ctx != nil && ctx.Err() != nil {
			// 停机/引擎取消：已入库的清零计数，未入库的留待下一轮。
			return ingested, nil
		}
		raw, rerr := os.ReadFile(f.path)
		if rerr != nil {
			if os.IsNotExist(rerr) {
				continue // 写侧/另一轮已删除，幂等跳过
			}
			return ingested, securityEventsSpoolRecordFailure(fmt.Errorf("security events spool: read %s: %w", f.name, rerr))
		}
		n, ierr := IngestSecurityEventBatch(ctx, raw)
		ingested += n
		if ierr != nil {
			return ingested, securityEventsSpoolRecordFailure(fmt.Errorf("security events spool: ingest %s: %w", f.name, ierr))
		}
		// commit 完成才删除：删除失败只告警（下一轮同一文件会被 INSERT OR IGNORE
		// 幂等重放，不会重复计数）。
		if rerr := os.Remove(f.path); rerr != nil && !os.IsNotExist(rerr) {
			Logf("warn", "security events spool: 补采成功后删除 %s 失败（下一轮幂等重放）: %v", f.name, rerr)
		}
	}
	securityEventsSpoolRecordSuccess(ingested)
	if hasSealed {
		// 只有 sealed 集合可能被本轮删除；active-only 空补采不改变文件，
		// 保留状态 TTL，避免健康轮询每 2s 重扫正在增长的 active 文件。
		invalidateSecurityEventsSpoolStatus()
	}
	return ingested, nil
}

// securityEventsSpoolRecordFailure 记录一次补采失败并推进退避（返回入参错误，
// 便于 `return 0, ...` 直接使用）。
func securityEventsSpoolRecordFailure(err error) error {
	securityEventsSpoolState.mu.Lock()
	securityEventsSpoolState.drainFailures++
	failures := securityEventsSpoolState.drainFailures
	backoff := time.Duration(1<<min(failures, 6)) * time.Second
	if backoff > securityEventsSpoolBackoffMax {
		backoff = securityEventsSpoolBackoffMax
	}
	securityEventsSpoolState.nextAttempt = time.Now().Add(backoff)
	securityEventsSpoolState.drainErr = err.Error()
	securityEventsSpoolState.drainErrAt = time.Now()
	securityEventsSpoolState.mu.Unlock()
	invalidateSecurityEventsSpoolStatus()
	return err
}

// securityEventsSpoolRecordSuccess 复位失败计数并记录最近一次成功补采。
func securityEventsSpoolRecordSuccess(ingested int) {
	securityEventsSpoolState.mu.Lock()
	securityEventsSpoolState.drainFailures = 0
	securityEventsSpoolState.nextAttempt = time.Time{}
	securityEventsSpoolState.drainErr = ""
	securityEventsSpoolState.drainErrAt = time.Time{}
	securityEventsSpoolState.lastDrained = ingested
	securityEventsSpoolState.lastDrainedAt = time.Now()
	securityEventsSpoolState.mu.Unlock()
}

// securityEventsOverlaySpoolHealth 把 spool 状态叠加到采集健康快照：
// 目录不可读 / 已达上限 / 补采连续失败达阈值 → 降级（healthy=false）。
// 待补采条目本身不是丢失（数据仍在磁盘、补采可入库），故不置 DataLoss；
// 只有写侧真正丢弃（writer-stats 的 dropped/io_errors）才是永久丢失。
func securityEventsOverlaySpoolHealth(status *SecurityEventsIngestionStatus) {
	spool := SecurityEventsSpoolSnapshot()
	status.SpoolDir = spool.Dir
	status.SpoolPendingEntries = spool.Entries
	status.SpoolPendingBytes = spool.Bytes
	status.SpoolFiles = spool.ActiveFiles + spool.SealedFiles
	status.SpoolLimitEntries = spool.LimitEntries
	status.SpoolLimitBytes = spool.LimitBytes
	status.SpoolSaturated = spool.Saturated
	status.SpoolUnavailable = spool.Unavailable
	status.SpoolConsecutiveFailures = spool.ConsecutiveFailures
	status.SpoolLastError = spool.LastError
	status.SpoolLastErrorAt = spool.LastErrorAt
	if spool.Unavailable || spool.Saturated || spool.ConsecutiveFailures >= securityEventsIngestionFailureThreshold {
		status.Observed = true
		status.Healthy = false
	}
}

// ResetSecurityEventsSpoolStateForTest 复位 spool 缓存与退避状态（测试用：
// 顺序依赖/随机序下前一用例的退避或缓存会污染后续用例）。
//
// testseam: 留驻产品文件的测试缝——导出入口被 handlers 测试跨包消费，
// 宿主不可能在同包 *_test.go。
func ResetSecurityEventsSpoolStateForTest() {
	securityEventsSpoolState.mu.Lock()
	securityEventsSpoolState.cachedAt = time.Time{}
	securityEventsSpoolState.status = SecurityEventsSpoolStatus{}
	securityEventsSpoolState.haveCache = false
	securityEventsSpoolState.drainFailures = 0
	securityEventsSpoolState.nextAttempt = time.Time{}
	securityEventsSpoolState.drainErr = ""
	securityEventsSpoolState.drainErrAt = time.Time{}
	securityEventsSpoolState.lastDrained = 0
	securityEventsSpoolState.lastDrainedAt = time.Time{}
	securityEventsSpoolState.mu.Unlock()
	securityEventsBatchIngestState.mu.Lock()
	securityEventsBatchIngestState.dedupe = nil
	securityEventsSharedDedupe.reset()
	securityEventsBatchIngestState.mu.Unlock()
	resetSecurityEventsSpoolEntryCountCacheForTest()
}
