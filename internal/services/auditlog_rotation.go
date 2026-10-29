package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 轮转/摄取失败日志限流。轮转路径由 2s tick 驱动，持久性失败（pending
// delta 补采持续失败、copy 失败、目录缺失等）若无限流会每 tick 刷一条。
// 同一归一化消息 60s 内仅首条放行；不同消息各自计时、立即放行。
// 限流 map 有界增长——每次放行时清扫已过期（≥60s）条目，仍超上限则
// 整体重置（各变体至多重复放行一条，无数据影响）；否则内嵌数字参数的变体
// 消息（见）会无界增加键（最坏 ~43k 键/天）。
var (
	auditFailureLogMu    sync.Mutex
	auditFailureLogTimes = map[string]time.Time{}
	// auditFailureLogClock 可注入时钟（测试用）。
	auditFailureLogClock = time.Now
)

// errPendingDeltaMarkerCorrupt 标记内容损坏（半写/非法 JSON/缺路径）——
// 与瞬时读取错误分判：损坏标记无法通过重试自愈，连续多轮不可解析时必须
// 隔离后重建，否则 audit.log 永久不轮转（无界增长）。
var errPendingDeltaMarkerCorrupt = errors.New("pending delta marker corrupt")

// errAuditRotationDeferred 轮转未完成（归档已就位、活文件未截断，下轮重试）。
// 与「无需轮转」（nil）和「轮转失败」（其它错误）三态区分：调用方据此披露
// 「延迟」而不是把它当成功（log-cleanup 摘要）或当硬失败（daemon 任务）。
var errAuditRotationDeferred = errors.New("audit log rotation deferred")

// pendingDeltaCorruptQuarantineRounds 连续损坏轮次达到该值后隔离标记。
// 单轮仍保留现场（fail-closed，供诊断/人工恢复），持续不可解析才自愈。
const pendingDeltaCorruptQuarantineRounds = 3

var pendingDeltaCorruptStreak = struct {
	sync.Mutex
	count int
}{}

// notePendingDeltaCorruptRound 记一轮损坏并返回连续轮次。
func notePendingDeltaCorruptRound() int {
	pendingDeltaCorruptStreak.Lock()
	defer pendingDeltaCorruptStreak.Unlock()
	pendingDeltaCorruptStreak.count++
	return pendingDeltaCorruptStreak.count
}

// resetPendingDeltaCorruptStreak 清零连续损坏轮次（标记可读或遇到非损坏类
// 读取错误时调用——只有连续损坏才触发隔离）。
func resetPendingDeltaCorruptStreak() {
	pendingDeltaCorruptStreak.Lock()
	pendingDeltaCorruptStreak.count = 0
	pendingDeltaCorruptStreak.Unlock()
}

// resetPendingDeltaCorruptStreakForTest 测试隔离连续损坏状态（仅测试）。
func resetPendingDeltaCorruptStreakForTest() { resetPendingDeltaCorruptStreak() }

// quarantineCorruptPendingDelta 把无法解析的标记重命名为
// `.corrupt-<unix>` 保留现场并解除轮转阻塞（下轮无标记即正常轮转）。
func quarantineCorruptPendingDelta(path string) error {
	target := fmt.Sprintf("%s.corrupt-%d", path, time.Now().UTC().Unix())
	if err := os.Rename(path, target); err != nil {
		return err
	}
	throttledAuditFailureLogf("audit log rotation: pending delta marker quarantined after %d corrupt rounds: %s → %s",
		pendingDeltaCorruptQuarantineRounds, path, target)
	return nil
}

// auditFailureLogWindow 是同一消息的放行窗口（60s，确立口径）。
const auditFailureLogWindow = 60 * time.Second

// auditFailureLogEvictCap 是限流 map 的键数上限：清扫后仍超此值即整体重置
const auditFailureLogEvictCap = 64

// auditFailureLogDigitPattern 用于限流键归一化。
var auditFailureLogDigitPattern = regexp.MustCompile(`\d+`)

// auditFailureThrottleKey 归一化限流键：消息中内嵌的数字串（偏移、大小等，
// 如 "ingest live tail [%d, %d)") 统一替换为 #，使同一故障的每次重试即便数字
// 参数变化也共享同一 60s 窗口（变体消息此前各键独立、限流被绕开）。
func auditFailureThrottleKey(msg string) string {
	return auditFailureLogDigitPattern.ReplaceAllString(msg, "#")
}

// auditFailureShouldLog 判定失败消息 msg 现在是否应放行输出，并记录放行时间。
// 键为归一化消息（auditFailureThrottleKey）。窗口判定、过期回收与键数上限
// 全部委托 throttleWarnAllowedCapped（与其它告警族同一顺序：判重复 → 回收 →
// 判上限 → 记录，被抑制的消息不触发清扫/重置）——此前是手写副本，注释声称
// 复用同源实现而实际只复用了回收段。
func auditFailureShouldLog(msg string) bool {
	auditFailureLogMu.Lock()
	defer auditFailureLogMu.Unlock()
	return throttleWarnAllowedCapped(&auditFailureLogTimes, auditFailureThrottleKey(msg), auditFailureLogClock(),
		auditFailureLogWindow, auditFailureLogWindow, auditFailureLogEvictCap)
}

// throttledAuditFailureLogf 以 auditFailureShouldLog 限流后输出失败日志。
func throttledAuditFailureLogf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !auditFailureShouldLog(msg) {
		return
	}
	// 经 Logf("warn") 输出——applicationLogWriter 按前缀过滤（tz.go），
	// 裸 log.Printf 的轮转遥测在 log_level 调高后全部消失。顺序安全：Logf 仅读
	// init() 初始化的原子级别（默认 info），底层仍是标准 log 包，writer 未安装
	// 前落 stderr、绝不 panic；生产序中 writer（main.go log.SetOutput）也先于
	// 首个轮转失败（摄取循环启动）就绪。
	Logf("warn", "%s", msg)
}

// auditLogPath 是 Coraza 审计日志的路径；定义为变量以便测试注入临时目录
// （生产环境为 /app/logs/waf-audit/audit.log,2026-09-14 从 /app/waf/audit 迁入）。轮转检查由事件摄取的 2s tick 驱动
// （securityevents.go StartSecurityEventsIngestion，移除从未被引用的
// auditLogCheckInterval 死常量）。
var auditLogPath = "/app/logs/waf-audit/audit.log"

// AuditLogPath 返回审计日志文件路径(导出 getter——渲染/摄取/统计/目录创建
// 四处单一源,:字面量重复收敛)。
func AuditLogPath() string {
	return auditLogPath
}

// auditLogSizeBytes 返回触发轮转的大小阈值；默认按调用方 ctx 读取
// global_config 配置（关停/导入排空预算内必须可取消），测试可通过替换该
// 变量注入小阈值以触发轮转。
var auditLogSizeBytes = getAuditLogSizeBytesContext

// auditLogCopyFile 将当前日志归档为 .1；测试可注入以模拟复制失败。
var auditLogCopyFile = copyAuditLogTo

// auditLogRotationBeforeTailIngest 在活文件尾部补采前调用（生产为 nil，仅测试
// 注入）：模拟 Coraza 在「本轮 stat → 补采」窗口内追写。持续写入下轮转仍必须
// 能截断，判据是摄取到达偏移而非本轮起始文件大小——注入点正是这两者的分界。
var auditLogRotationBeforeTailIngest func()

// auditLogRotatedIngestFrom 在归档（.1）补采前调用并传入补采起点（生产为 nil，
// 仅测试注入）：断言复制前闸门已提交的区间不会被二次解析。
var auditLogRotatedIngestFrom func(from int64)

// auditLogFileStat 活审计文件元数据读取缝；测试注入非 ENOENT 故障，
// 生产始终使用 os.Stat。
var auditLogFileStat = os.Stat

// rotateAuditLogIfNeeded 在审计日志超过大小阈值时轮转：先把当前日志复制到
// 暂存名 .1.new，成功后滚动历史副本（.4→.5 … .1→.2）并把暂存归档提升为 .1，
// 最后截断原文件（copytruncate）。复制/提升失败不改变归档代际、不截断活文件。
//
// 为什么用 copytruncate 而不是 rename：Coraza 通过长生命周期文件描述符持续
// 写入 audit.log，rename 会把写者"孤立"在已改名的 inode 上继续写 .1，而
// audit.log 永远不会被重新创建；采集器（tailer）也会因文件缺失/inode 变化而
// 重置偏移，导致首次轮转后所有安全事件永久丢失。copytruncate 保留原 inode，
// Coraza 无感知，tailer 只看到截断（size < offset 即重置偏移），从而持续摄取。
//
// 除补采条数外另返回轮转错误——所有失败分支（pending
// 标记读/补采重试、copy、归档 stat、回扫、活文件尾补采、pending 标记写、
// truncate、offset 重置、.1 补采）此前只经 throttledAuditFailureLogf 留痕，
// 持续失败时采集健康位恒 healthy、任务监控零痕迹。中止分支直接带错误返回；
// 不阻断轮转的分支（shift、offset 重置、.1 补采）记录首个错误后继续。
// 「补采失败不截断」等既有安全语义不变。
func rotateAuditLogIfNeeded(ctx context.Context) (total int, rotErr error) {
	// 返回轮转路径补采实际插入条数（pending/活文件尾部/.1 归档），
	// 由 PollOnce 并入「摄取 N 条」——补采窗口入库的事件此前从不出现在任务日志。
	noteErr := func(err error) {
		if err != nil && rotErr == nil {
			rotErr = err
		}
	}
	// 先重试上次失败的归档补采：成功才删除标记继续轮转；失败则保留 .1 不被 shift
	// 覆盖（事件尚存），待下次轮转重试，避免补采失败导致窗口事件永久丢失。
	pending, pendingErr := securityEventsReadPendingDelta()
	if pendingErr != nil {
		// 标记是否存在及其补采责任未知时不得 shift/覆盖任何归档；保留现场，
		// 下轮读恢复后先重试补采。与其他轮转 I/O 错误同走 fail-closed。
		// 损坏标记（半写/非法 JSON）无法靠重试自愈：连续 N 轮不可解析后隔离
		// 为 .corrupt-<ts> 并继续轮转——否则 audit.log 永久不轮转。
		if errors.Is(pendingErr, errPendingDeltaMarkerCorrupt) {
			if notePendingDeltaCorruptRound() >= pendingDeltaCorruptQuarantineRounds {
				if qerr := quarantineCorruptPendingDelta(securityEventsPendingDeltaPath()); qerr != nil {
					return total, fmt.Errorf("quarantine corrupt pending delta marker: %w", qerr)
				}
				resetPendingDeltaCorruptStreak()
			} else {
				return total, fmt.Errorf("read pending delta marker: %w", pendingErr)
			}
		} else {
			resetPendingDeltaCorruptStreak()
			return total, fmt.Errorf("read pending delta marker: %w", pendingErr)
		}
	} else {
		resetPendingDeltaCorruptStreak()
	}
	if pendingErr == nil && pending != nil {
		if _, err := os.Stat(pending.Path); os.IsNotExist(err) {
			// warn 走 60s 限流（throttledAuditFailureLogf）——标记删除
			// 失败（只读目录等）时标记留在盘上，2s tick 反复进入本分支，裸 warn
			// 每 tick 一条（~43k 行/天）；同归一化消息共享窗口，路径中数字已由
			// digit key 归一为 #。消息内容保持原样。
			throttledAuditFailureLogf("audit log rotation: pending delta archive %s missing, dropping marker", pending.Path)
			_ = os.Remove(securityEventsPendingDeltaPath())
		} else if !securityEventsIngestDepsReady() {
			// 补采依赖不可用时 securityEventsIngestDeltaFrom 返回 (0, nil)——
			// 「未补采」不得被当作「补采成功」：删除标记会让该轮转窗口的事件
			// 永久丢失。保留标记并中止本轮（下轮依赖恢复后先重试补采）。
			throttledAuditFailureLogf("audit log rotation: pending delta ingest deferred (security events database unavailable)")
			return total, fmt.Errorf("pending delta ingest deferred: security events database unavailable")
		} else if pendingDeltaArchiveReplaced(pending) {
			// Size 是写标记时的归档大小：当前 .1 小于该值说明归档已被外部替换/
			// 截短（原窗口内容已不可考），按旧 Offset 补采只会从无关内容解析。
			// 标记无恢复价值，丢弃并留痕。
			throttledAuditFailureLogf("audit log rotation: pending delta archive %s shrunk below recorded window (%d bytes), dropping marker", pending.Path, pending.Size)
			_ = os.Remove(securityEventsPendingDeltaPath())
		} else if n, _, err := securityEventsIngestDeltaFrom(pending.Path, pending.Offset, true); err != nil {
			throttledAuditFailureLogf("audit log rotation: pending delta ingest retry failed (rotation deferred): %v", err)
			return total, fmt.Errorf("pending delta ingest retry (rotation deferred): %w", err)
		} else {
			total += n
			Logf("info", "audit log rotation: pending delta ingest recovered from %s", pending.Path)
			_ = os.Remove(securityEventsPendingDeltaPath())
		}
	}
	info, err := auditLogFileStat(auditLogPath)
	if errors.Is(err, os.ErrNotExist) {
		return total, nil
	}
	if err != nil {
		throttledAuditFailureLogf("audit log rotation: active file stat failed: %v", err)
		return total, fmt.Errorf("stat active audit log: %w", err)
	}
	if info.Size() == 0 {
		return total, nil
	}
	maxBytes := auditLogSizeBytes(ctx)
	if info.Size() < maxBytes {
		return total, nil
	}
	// 轮转前记录已持久化的摄取偏移：tick 读到 EOF 后、复制完成前 Coraza 新写入
	// 的事件只存在于 .1，活文件截断后 tailer 重置偏移也不会再读 .1，需在归档后
	// 从 [persistedOffset, .1 size) 区间补采。
	// 读取失败不得静默按 0 补采：0 起点会把整个 .1 重灌 security_events
	// （transaction_id 唯一索引去重兜底），因此必须留 warn。偏移仍按 0 兜底；
	// 但待摄取积压超过下方复制前闸门时，本轮会推迟复制与轮转，下轮续试。
	persistedOffset, offErr := securityEventsReadOffset(securityEventsOffsetPath)
	if offErr != nil {
		throttledAuditFailureLogf("audit log rotation: 读取摄取偏移失败，补采起点退化为 0: %v", offErr)
	}
	// ingestStart 是归档后 .1 补采的起点：复制前闸门已把 [persistedOffset,
	// reached) 提交进事件库（下面 gate 分支把 reached 抬上来），从 reached 起
	// 补采可省一遍同区间 JSON 解码（上限 8MiB，去重只保证不重复成行，不省
	// CPU）。闸门未触发时等于 persistedOffset。
	ingestStart := persistedOffset
	// —— 复制前闸门：只在「本轮能追平活文件尾部」时才付全量复制/移位成本 ——
	// 持续写入（或补采持续失败）下截断判据可能连续多轮不成立；旧序每 2s 先把
	// 整文件复制到 .1.new 并移位归档，再在截断判据处推迟——推迟期间每 tick 仍付
	// O(文件大小) 复制、归档代际被反复移位覆盖，磁盘放大 ~6×、活文件无界增长。
	// 现在把尾部摄取前置为闸门：
	//   · 可追平（摄取到达 stat 边界，或剩余仅空白）→ 继续复制/移位/截断；
	//   · 追不平（仍有未摄取字节 / 补采依赖不可用 / 积压超过闸门上限）→ 本轮
	//     只做增量摄取，不复制、不移位、不改归档代际，下轮续试。
	// 已落盘事件零丢失：未截断则字节原样留在活文件；已摄取部分由
	// transaction_id 唯一索引 + 请求级去重表幂等吸收，重复补采不产生重复行。
	// 取舍：补采不可用期间不再「先复制再截断+留 pending 标记」——那条路径靠
	// 复制覆盖窗口，代价正是本项要消除的每 tick 全量复制；改为保持活文件完整、
	// 推迟轮转（磁盘增长换零丢失，健康位经 errAuditRotationDeferred 如实披露）。
	// 告警统一走 throttledAuditFailureLogf（同消息 60s 窗口），持续推迟不会每
	// tick 刷一条。
	precopySize := info.Size()
	if precopySize > persistedOffset {
		if !securityEventsIngestDepsReady() {
			throttledAuditFailureLogf("audit log rotation: pre-copy live tail ingest deferred (security events database unavailable, no copy performed)")
			return total, fmt.Errorf("%w: 补采依赖不可用，本轮不复制（活文件保持完整，下轮续试）", errAuditRotationDeferred)
		}
		if backlog := precopySize - persistedOffset; backlog > auditLogRotationPreflightTailLimit {
			throttledAuditFailureLogf("audit log rotation: pre-copy live tail backlog %d bytes exceeds %d, rotation deferred (no copy performed)", backlog, auditLogRotationPreflightTailLimit)
			return total, fmt.Errorf("%w: 活文件待摄取 %d 字节超过复制前闸门 %d（本轮只摄取不复制，下轮续试）",
				errAuditRotationDeferred, backlog, auditLogRotationPreflightTailLimit)
		}
		// 归档语义（区间有界、畸形区 scan-to-EOF）与 copy 后的尾部补采同口径；
		// 去重表与 live tailer 共享（同一 poll goroutine，见 ingestDeltaFrom）。
		n, reached, ierr := securityEventsIngestDeltaFrom(auditLogPath, persistedOffset, true)
		if ierr != nil {
			throttledAuditFailureLogf("audit log rotation: pre-copy live tail ingest failed, rotation deferred (no copy performed): %v", ierr)
			return total, fmt.Errorf("%w: 轮转前补采活文件尾部失败: %w", errAuditRotationDeferred, ierr)
		}
		total += n
		if reached < precopySize && !auditLogTailOnlyWhitespace(auditLogPath, reached, precopySize) {
			throttledAuditFailureLogf("audit log rotation: live tail not fully ingested before copy (reached %d of %d bytes), rotation deferred (no copy performed)", reached, precopySize)
			return total, fmt.Errorf("%w: 活文件尾部尚未摄取（reached %d of %d bytes，本轮不复制，下轮续试）",
				errAuditRotationDeferred, reached, precopySize)
		}
		// 闸门已提交 [persistedOffset, reached)：.1 从 reached 起补采。
		// reached 可能因归档语义（畸形尾部 scan-to-EOF）跳到 EOF——该段本就
		// 不可摄取，从 reached 起不新增丢失。
		if reached > ingestStart {
			ingestStart = reached
		}
	}
	dir := filepath.Dir(auditLogPath)
	base := auditLogBaseName()
	current := filepath.Join(dir, base+".1")
	// 先把当前日志完整复制到暂存名 .1.new，成功后才滚动历史归档并把它提升
	// 为 .1——复制失败（磁盘满/只读挂载/IO 错误）不得改变归档代际。旧序
	// （先 .4→.5 … .1→.2 再复制）在持续复制失败时每 tick（2s 驱动）蚕食一代：
	// .1..5 全存在时约 4 个 tick 即丢掉 4 代审计证据，仅留 60s 限流 warn。
	staging := current + ".new"
	if err := auditLogCopyFile(auditLogPath, staging); err != nil {
		_ = os.Remove(staging)
		throttledAuditFailureLogf("audit log rotation: copy to .1 failed (not truncating): %v", err)
		return total, fmt.Errorf("copy to .1 failed (not truncating): %w", err)
	}
	// 新归档已完整落盘（copy helper 内含临时文件 fsync+父目录 fsync）后才
	// 滚动历史副本：.4→.5、.3→.4、.2→.3、.1→.2。
	for i := 4; i >= 1; i-- {
		old := filepath.Join(dir, fmt.Sprintf("%s.%d", base, i))
		newer := filepath.Join(dir, fmt.Sprintf("%s.%d", base, i+1))
		if _, statErr := os.Stat(old); statErr == nil {
			if rerr := os.Rename(old, newer); rerr != nil {
				throttledAuditFailureLogf("audit log rotation: shift %s → %s failed: %v", old, newer, rerr)
				if i == 1 {
					// .1 未能让位时不得提升暂存归档：rename 会静默覆盖上一代
					// .1（.2 没有接住它）＝丢一代审计证据。本轮中止、保留现场。
					_ = os.Remove(staging)
					return total, fmt.Errorf("shift %s → %s: %w", old, newer, rerr)
				}
				noteErr(fmt.Errorf("shift %s → %s: %w", old, newer, rerr))
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			// 只有 NotExist 才能视为「该代不存在」。权限/IO 等 stat 失败下
			// 归档可能仍存在——继续 shift/promote 会覆盖仍有效的 .1（静默
			// 丢失一代审计证据），本轮中止并保留现场。
			_ = os.Remove(staging)
			throttledAuditFailureLogf("audit log rotation: stat %s failed (rotation aborted): %v", old, statErr)
			return total, fmt.Errorf("stat %s (rotation aborted): %w", old, statErr)
		}
	}
	// 提升暂存归档为 .1——新归档在此刻才对外可见；失败清理暂存且不截断活文件。
	// 已知中间态：历史档已移位（旧 .1 已在 .2）而提升失败时，下一轮成功轮转会
	// 把活文件（含本轮全部内容）重新复制为 .1，同一批内容在 .1/.2 各留一份
	// （代际语义错位，事件不重复入库——transaction_id 唯一索引去重）。活文件
	// 始终完整，故此处不回滚移位：回滚 rename 自身也可能失败，复杂度高于收益。
	if err := os.Rename(staging, current); err != nil {
		_ = os.Remove(staging)
		throttledAuditFailureLogf("audit log rotation: promote staged archive to .1 failed (not truncating): %v", err)
		return total, fmt.Errorf("promote staged archive (not truncating): %w", err)
	}
	// rename 产生的目录项必须落盘（copy helper 只同步了 .1.new 的目录项）；
	// 失败仅留痕不中止——内容已在 .1，掉电最多回退到暂存形态。
	if serr := syncParentDir(current); serr != nil {
		throttledAuditFailureLogf("audit log rotation: sync archive dir after promote failed: %v", serr)
		noteErr(fmt.Errorf("sync archive dir after promote: %w", serr))
	}
	archInfo, err := os.Stat(current)
	if err != nil {
		throttledAuditFailureLogf("audit log rotation: stat %s failed (not truncating): %v", current, err)
		return total, fmt.Errorf("stat %s failed (not truncating): %w", current, err)
	}
	archiveSize := archInfo.Size()
	// 补采活文件 [archiveSize, truncate 前) 的新写尾部：copy 最后一次读取后、truncate
	// 前 Coraza 新写入的事件两边都不在（.1 没有、活文件将被截断），须先于 truncate
	// 从活文件直接补采。补采失败绝不截断——尾部事件仍完整留在活文件中，下次 tick
	// 自然续读，不会丢失。
	// 有界循环（最多 3 轮）：补采 INSERT 耗时期间新写入的尾部也一并收敛，把残余
	// 窗口压缩到最后一轮补采→truncate 的系统调用间隙。该间隙内的写入两边都不在
	// （copy 早已完成、未进 .1；truncate 后活文件里也没有），下次轮转的 .1 补采
	// 覆盖不到，为可接受的尽力而为缺口（毫秒级，仅损失该瞬间的尾部事件）。
	// 本轮进度基准是「摄取到达偏移」reached（补采 pass 返回的已提交文档末尾），
	// 不是本轮起始的文件大小：补采窗口内的追写只要已被本轮解码摄入，reached 就
	// 随之前进，不会把「已摄取但文件变大」误判为「还有未摄取字节」而永远放弃
	// 截断——审计日志每事务追写，该误判在持续写入下恒成立。
	// 首轮补采起点不取 archiveSize 本身，而是后向回扫到最近一个文档头：copy 末次
	// 读可能截断在正在写入的事务中部（前缀在 .1、后缀在活文件），从截断点直接
	// 解码会前向跳过该事务后半，.1 补采又因前缀 JSON 不完整无法解码——跨界事务
	// 将两半皆失。从文档头开始即可在活文件中完整解码整个事务。
	reached := archiveSize
	for i := range 3 {
		tailInfo, terr := os.Stat(auditLogPath)
		if terr != nil || tailInfo.Size() <= reached {
			break
		}
		// 依赖不可用时补采是 no-op——不得据此推进 reached 并截断活文件：
		// 尾部事件只在活文件里，截断即永久丢失。保留现场，下轮依赖恢复后续采。
		if !securityEventsIngestDepsReady() {
			throttledAuditFailureLogf("audit log rotation: live tail ingest deferred (security events database unavailable, not truncating)")
			return total, fmt.Errorf("live tail ingest deferred (not truncating): security events database unavailable")
		}
		ingestFrom := reached
		if i == 0 {
			from, berr := securityEventsBackscanDocumentStart(auditLogPath, archiveSize)
			if berr != nil {
				throttledAuditFailureLogf("audit log rotation: backscan live tail failed (not truncating): %v", berr)
				return total, fmt.Errorf("backscan live tail failed (not truncating): %w", berr)
			}
			ingestFrom = from
		}
		if auditLogRotationBeforeTailIngest != nil {
			auditLogRotationBeforeTailIngest()
		}
		// 活文件补采以归档语义进行（archive=true）：补采区间有界且完整内容已在
		// 刚拷贝的 .1 中以归档语义摄取，活文件畸形区（≥4MB 无文档头）可安全跳过；
		// 若按活文件语义报错，轮转每 2s 周期反复中止，文件永不截断。
		n, next, ierr := securityEventsIngestDeltaFrom(auditLogPath, ingestFrom, true)
		if ierr != nil {
			throttledAuditFailureLogf("audit log rotation: ingest live tail [%d, %d) failed (not truncating): %v", ingestFrom, tailInfo.Size(), ierr)
			return total, fmt.Errorf("ingest live tail failed (not truncating): %w", ierr)
		}
		total += n
		if next <= reached {
			// 本 pass 没有推进到达偏移（尾部只剩空白分隔/解码器已到 EOF）：
			// 再循环也读不到新内容，交给截断判据决定。
			break
		}
		reached = next
	}
	// 截断判据=摄取到达偏移：尾部已无未摄取内容（reached 追平文件大小，或剩余
	// 的仅是文档间空白分隔）才截断；否则保留本轮现场、下周期先经正常路径摄取
	// 尾部再轮转——半条在途事务被截断抹除后，后续归档 pass 同样静默跳过，事件
	// 永久丢失。放宽截断必须留痕：该分支此前完全静默（rotErr 保持 nil、健康位
	// 正常、任务日志零痕迹）。复制前闸门已把「追不平尾部」的常态挡在复制之前
	// （见上），这里的残余窗口只剩 copy→最后一次补采之间新写入的字节：本轮推迟
	// 时归档已就位但活文件未截断，下轮闸门重判、仍可能在复制后推迟——告警经
	// 60s 限流，磁盘放大被限制为「闸门通过后的偶发单次复制」。
	finalInfo, ferr := os.Stat(auditLogPath)
	if ferr != nil {
		throttledAuditFailureLogf("audit log rotation: stat live log before truncate failed (not truncating): %v", ferr)
		return total, fmt.Errorf("stat live log before truncate failed (not truncating): %w", ferr)
	}
	if finalInfo.Size() > reached && !auditLogTailOnlyWhitespace(auditLogPath, reached, finalInfo.Size()) {
		throttledAuditFailureLogf("audit log rotation: live tail not fully ingested (reached %d of %d bytes), truncate deferred", reached, finalInfo.Size())
		// 轮转未完成必须可识别：返回值此前与「无需轮转」同为 nil（健康位
		// healthy、调用方无法区分「已回收空间」与「每 2s 全量复制但未截断」）。
		// 哨兵让健康位与 log-cleanup 摘要如实披露延迟。
		deferred := fmt.Errorf("%w: 活文件尾部尚未摄取（reached %d of %d bytes，下轮重试）", errAuditRotationDeferred, reached, finalInfo.Size())
		if rotErr != nil {
			return total, errors.Join(rotErr, deferred)
		}
		return total, deferred
	}
	// truncate 前先落 pending 标记。标记写失败绝不在无标记状态下截断——
	// 活文件仍完好、内容无损失，本轮中止下周期重试。truncate 成功与补采完成之间
	// 的任何崩溃点，标记都已在盘上（补采成功即删除、失败保留），下次轮转 shift 前
	// 先重试，双向崩溃安全；truncate 失败则移除标记——活文件未截断、内容完整，
	// 无需补采。
	if err := securityEventsWritePendingDelta(securityEventsPendingDelta{Path: current, Offset: ingestStart, Size: archiveSize}); err != nil {
		throttledAuditFailureLogf("audit log rotation: write pending delta marker failed, aborting rotation without truncate: %v", err)
		return total, fmt.Errorf("write pending delta marker (aborting rotation without truncate): %w", err)
	}
	// 截断失败不影响数据安全（下次轮转会重试），仅记录日志。
	if err := os.Truncate(auditLogPath, 0); err != nil {
		_ = os.Remove(securityEventsPendingDeltaPath())
		throttledAuditFailureLogf("audit log rotation: truncate failed (will retry next cycle): %v", err)
		return total, fmt.Errorf("truncate failed (will retry next cycle): %w", err)
	}
	// （2026-09-05 审计）：truncate 成功后立即把持久化 offset 归零——此前
	// 依赖下次读取时的 size 比较（新 size < 旧 offset）才回退，窗口期内 offset
	// 悬挂在旧文件大小上；写入失败仅告警不中断轮转（size 比对仍兜底）。
	if err := securityEventsWriteOffset(securityEventsOffsetPath, 0); err != nil {
		throttledAuditFailureLogf("audit log rotation: reset offset to 0 after truncate failed: %v", err)
		noteErr(fmt.Errorf("reset offset to 0 after truncate: %w", err))
	}
	Logf("info", "audit log rotation: rotated %s (%d bytes → %s.1)", auditLogPath, info.Size(), base)
	// 补采轮转窗口：归档大小可能因复制期间的新写入大于 stat 时的 size，
	// 因此以 .1 实际大小作为窗口终点，覆盖复制竞态。
	if !securityEventsIngestDepsReady() {
		// 补采依赖不可用时不得把「未补采」当成功删除 pending 安全网：
		// 保留标记（下轮 shift 前先重试，事件仍在 .1），按失败留痕。
		throttledAuditFailureLogf("audit log rotation: ingest rotated delta deferred (security events database unavailable)")
		noteErr(fmt.Errorf("ingest rotated delta deferred: security events database unavailable"))
	} else {
		if auditLogRotatedIngestFrom != nil {
			auditLogRotatedIngestFrom(ingestStart)
		}
		n, ierr := securityEventsIngestRotatedDelta(ingestStart)
		if ierr != nil {
			throttledAuditFailureLogf("audit log rotation: ingest rotated delta failed (events in %s.1 may be lost): %v", base, ierr)
			noteErr(fmt.Errorf("ingest rotated delta failed: %w", ierr))
			// 标记保留（truncate 前已落盘）：事件只在 .1，下次轮转 shift 前先重试，
			// 防止 .1→.2 后事件永久丢失。
		} else {
			total += n
			_ = os.Remove(securityEventsPendingDeltaPath())
		}
	}
	return total, rotErr
}

// auditLogRotationPreflightTailLimit 是复制前闸门允许本轮补采的活文件尾部上限：
// 超过该值说明存在大量积压（停摆恢复/长时间停更），本轮只摄取不复制——把
// 剩余积压交给 2s 节拍的限量 live pass 分摊，避免一个无界归档 pass 把轮转
// 拖过停机宽限（live pass 受事件数/字节数上限与 ctx 取消约束，归档 pass 不受）。
const auditLogRotationPreflightTailLimit = 8 << 20

// auditLogWhitespaceTailLimit 是「尾部剩余字节」按空白处理的判定上限：
// 摄取到达偏移与当前文件大小之间的差值超过该值只可能来自补采 pass 结束后的
// 新写入，按未摄取处理（保守推迟截断，下轮再判），也避免按差值分配内存。
const auditLogWhitespaceTailLimit = 1 << 20

// auditLogTailOnlyWhitespace 报告文件 [from, size) 区间是否只含空白字节
// （JSON 文档之间的分隔符/尾随换行）。JSON 解码器在 EOF 时停在最后一条文档
// 末尾、不消费其后的换行，若把该换行当成「未摄取内容」，正常 tick 的轮转
// 都会推迟截断——退化为永不 truncate。分段读取（64KiB），读取失败按非空白
// 处理（保守：本轮不截断，下轮重判）。
func auditLogTailOnlyWhitespace(path string, from, size int64) bool {
	if size <= from {
		return true
	}
	if size-from > auditLogWhitespaceTailLimit {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 64<<10)
	pos := from
	for pos < size {
		want := size - pos
		if want > int64(len(buf)) {
			want = int64(len(buf))
		}
		n, rerr := f.ReadAt(buf[:want], pos)
		for _, b := range buf[:n] {
			switch b {
			case ' ', '\t', '\r', '\n':
			default:
				return false
			}
		}
		pos += int64(n)
		if rerr != nil {
			return pos >= size
		}
	}
	return true
}

// securityEventsBackscanDocumentStart 后向扫描 [0, from) 内最近一个文档头 "\n{"
// （pretty-print 格式中下一个顶层文档的起始 `{`），返回该 `{` 的字节位置；
// 未找到（超大事务/畸形区）或打开失败时回退 from 本身。用于确定活文件补采起点：
// copy 末次读可能截断在事务中部，从截断点直接解码会跳过该事务。回扫取全量区间
// 而非固定窗口——回扫时活文件仍完好，from（归档大小）有界于轮转阈值（默认
// 10MB），固定 8MB 窗口会漏掉文档头更靠前的跨界事务（前缀在 .1、后缀在活文件），
// 两半皆失。
//
// 实现为 1MB 分块从尾部向前读（而非一次 ReadAt 分配 from 字节）：阈值来自
// audit_log_size_mb 且无上限校验，配置大值时整块分配会 OOM 崩溃循环。
// 文档头可跨块边界（前块末字节 '\n' + 后块首字节 '{'），跨块时返回后块起点。
func securityEventsBackscanDocumentStart(path string, from int64) (int64, error) {
	const chunkSize = 1 << 20
	if from <= 0 {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return from, err
	}
	defer f.Close()
	var nextFirst byte // 已扫描的下一块（更高偏移）首字节，用于跨块 "\n{" 检测
	hasNext := false
	pos := from
	for pos > 0 {
		start := pos - chunkSize
		if start < 0 {
			start = 0
		}
		buf := make([]byte, pos-start)
		n, _ := f.ReadAt(buf, start)
		if n > 0 {
			if hasNext && buf[n-1] == '\n' && nextFirst == '{' {
				return pos, nil // "\n{" 跨块边界：`{` 在 pos 处
			}
			if idx := bytes.LastIndex(buf[:n], []byte("\n{")); idx >= 0 {
				return start + int64(idx) + 1, nil
			}
			nextFirst = buf[0]
			hasNext = true
		}
		if n < len(buf) {
			// 文件小于 from（拷贝期间被截断/缩小）：更高偏移无更多数据
			break
		}
		pos = start
	}
	return from, nil
}

// copyAuditLogTo 将 src 完整复制到 dst，并保留原文件权限位；先写临时文件再
// 原子重命名，避免读者读到半成品。任何一步失败都清理临时文件并返回错误，
// 调用方据此绝不截断原文件。
func copyAuditLogTo(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	// 归档必须在 truncate 活文件前真正落盘：否则掉电后 .1 可能为空/半截，
	// pending 标记无从补采。
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncParentDir(dst)
}

func auditLogBaseName() string {
	return filepath.Base(auditLogPath)
}

// securityEventsPendingDelta 记录一次失败的归档补采：内容为待补采的归档路径 +
// 起始偏移 + 归档大小，持久化为 <auditlog>.delta-pending 标记文件。下次轮转
// shift 前先重试补采（成功才删除标记），防止 .1 被 shift 覆盖后事件永久丢失。
// Size 用于识别「归档被外部替换/截短」：当前文件小于记录值时旧偏移已无意义。
type securityEventsPendingDelta struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
}

// pendingDeltaArchiveReplaced 报告标记记录的归档窗口是否已失效：写标记时的
// .1 大小（Size）大于当前文件即说明归档被替换/截短，按旧 Offset 补采只会从
// 无关内容解析。Size<=0 为旧版标记（无该字段），不做判定。
func pendingDeltaArchiveReplaced(p *securityEventsPendingDelta) bool {
	if p == nil || p.Size <= 0 {
		return false
	}
	info, err := os.Stat(p.Path)
	if err != nil {
		return false // 缺失/不可读由补采分支自身的错误路径处理
	}
	return info.Size() < p.Size
}

func securityEventsPendingDeltaPath() string {
	return auditLogPath + ".delta-pending"
}

// securityEventsWritePendingDelta 持久化待补采标记：先写临时文件再原子重命名
// （与 securityEventsWriteOffset 同模式），避免半写 JSON 被 ReadPendingDelta
// 静默视为无标记而丢失轮转窗口。标记是轮转窗口事件的唯一安全网：写失败必须让
// 调用方在 truncate 前中止轮转（绝不无标记截断），故返回错误而非仅记日志。
func securityEventsWritePendingDelta(p securityEventsPendingDelta) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	// 单源原子落盘（tmp+fsync+父目录 fsync）——半写/掉电丢失标记
	// 会让轮转窗口事件永久丢失。
	return writeFileAtomicSynced(securityEventsPendingDeltaPath(), data, 0o644)
}

// securityEventsReadPendingDelta 读取待补采标记；不存在返回 (nil,nil)。损坏标记
// （半写/解析失败/路径缺失）与读错误同口径返回 error 并由轮转入口中止本轮：
// 旧实现清除标记后返回 (nil,nil)，恰好等于「无标记」，调用方继续 .1→.2 移位，
// 该轮转窗口的事件再无补采依据。标记保留在盘上供下轮重试与人工
// 诊断——不得在补采责任未知时静默丢弃。其他读取错误同样返回给调用方，绝不
// 在补采责任未知时移位归档。
func securityEventsReadPendingDelta() (*securityEventsPendingDelta, error) {
	path := securityEventsPendingDeltaPath()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		throttledAuditFailureLogf("audit log rotation: pending delta marker read failed (rotation deferred): %v", err)
		return nil, err
	}
	var p securityEventsPendingDelta
	if err := json.Unmarshal(data, &p); err != nil || p.Path == "" {
		throttledAuditFailureLogf("audit log rotation: pending delta marker corrupt (rotation deferred, marker kept): %s", path)
		return nil, fmt.Errorf("%w: %s", errPendingDeltaMarkerCorrupt, path)
	}
	return &p, nil
}

// auditLogSizeCacheTTL 是轮转阈值的缓存窗口：2s 轮转 tick 在
// 日志非空时此前每轮都查主库取阈值，稳态每 2s 一条主库查询。阈值是管理端偶尔
// 修改的常量，60s 生效延迟对按大小轮转无实际影响；缓存后稳态每 tick 仅一次
// stat、零 DB 查询。主库读失败不缓存：回退 10MB 当轮生效、下一 tick 重试，
// 不把瞬时故障的回退值钉死整个窗口。
const auditLogSizeCacheTTL = 60 * time.Second

// 审计轮转阈值缓存（缓存机制单源 dbValueCache，「读库失败不缓存」
// 语义与任务日志侧统一——此前两套实现易单侧漏改）。
var auditLogSizeValueCache = dbValueCache{ttl: auditLogSizeCacheTTL}

// beforeAuditLogSizeQuery 保留审计轮转阈值查询前注入缝，供关停交错回归测试使用。
var beforeAuditLogSizeQuery = func() {}

// getAuditLogSizeBytesContext 读取轮转阈值（ctx 版）。轮转由安全事件摄取的
// 2s tick 驱动，tick 处在有界关停/导入排空预算内——读库必须用 QueryRowContext，
// 否则关停时这一读最坏被主库写锁挡住整个 busy_timeout。
func getAuditLogSizeBytesContext(ctx context.Context) int64 {
	defaultBytes := int64(db.DefaultAuditLogSizeMB) * 1024 * 1024
	// 未初始化库回退治理默认值（db.DefaultAuditLogSizeMB），不得 nil deref。
	beforeAuditLogSizeQuery()
	database := db.DB
	if database == nil {
		return defaultBytes
	}
	return auditLogSizeValueCache.getCtx(ctx, func(queryCtx context.Context) (int64, error) {
		var sizeMB int
		if err := database.QueryRowContext(queryCtx, "SELECT COALESCE(audit_log_size_mb, ?) FROM global_config WHERE id = 1", db.DefaultAuditLogSizeMB).Scan(&sizeMB); err != nil {
			// 读失败回退默认值当轮生效，且必须留痕：此前静默回退让「轮转阈值
			// 长期按兜底值滚动而面板配置形同虚设」零信号。状态转换口径（首报
			// warn + 恢复 info）与同族配置读取（运行日志尺寸/时区刷新）同源，
			// 缓存未命中才走到这里，稳态不刷屏。
			if lvl := logStateTransition("audit-log-size-refresh", true); lvl != "" {
				Logf(lvl, "读取审计日志轮转阈值失败，回退默认 %dMB（本轮生效，下一轮重试）: %v", db.DefaultAuditLogSizeMB, err)
			}
			return 0, err // 失败不缓存：回退默认值当轮生效，下一 tick 重试
		}
		if sizeMB <= 0 {
			// 库值 <=0（带外改库/半迁移形态）与读失败同口径 fail-visible：
			// 回退默认当轮生效，但必须含库值留痕——静默回落让「面板配置形同
			// 虚设」零信号。状态转换去重（首报 warn/恢复 info），缓存 TTL 到期
			// 才走到这里，稳态不刷屏。
			if lvl := logStateTransition("audit-log-size-refresh", true); lvl != "" {
				Logf(lvl, "审计日志轮转阈值库值 %d 不可用（≤0），回退默认 %dMB（本轮生效）", sizeMB, db.DefaultAuditLogSizeMB)
			}
			sizeMB = db.DefaultAuditLogSizeMB
		} else if lvl := logStateTransition("audit-log-size-refresh", false); lvl != "" {
			Logf(lvl, "读取审计日志轮转阈值已恢复")
		}
		return int64(sizeMB) * 1024 * 1024, nil
	}, defaultBytes)
}
