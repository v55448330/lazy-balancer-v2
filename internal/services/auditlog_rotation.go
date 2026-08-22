package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"lazy-balancer-v2/internal/db"
)

// auditLogPath 是 Coraza 审计日志的路径；定义为变量以便测试注入临时目录
// （生产环境为 /app/waf/audit/audit.log）。轮转检查由事件摄取的 2s tick 驱动
// （securityevents.go StartSecurityEventsIngestion，R65 B-S3 移除从未被引用的
// auditLogCheckInterval 死常量）。
var auditLogPath = "/app/waf/audit/audit.log"

// auditLogSizeBytes 返回触发轮转的大小阈值；默认读取 global_config 配置，
// 测试可通过替换该变量注入小阈值以触发轮转。
var auditLogSizeBytes = getAuditLogSizeBytes

// auditLogCopyFile 将当前日志归档为 .1；测试可注入以模拟复制失败。
var auditLogCopyFile = copyAuditLogTo

// rotateAuditLogIfNeeded 在审计日志超过大小阈值时轮转：先滚动历史副本
// （.4→.5 … .1→.2），再将当前日志以 copytruncate 方式归档为 .1 并截断原文件。
//
// 为什么用 copytruncate 而不是 rename：Coraza 通过长生命周期文件描述符持续
// 写入 audit.log，rename 会把写者"孤立"在已改名的 inode 上继续写 .1，而
// audit.log 永远不会被重新创建；采集器（tailer）也会因文件缺失/inode 变化而
// 重置偏移，导致首次轮转后所有安全事件永久丢失。copytruncate 保留原 inode，
// Coraza 无感知，tailer 只看到截断（size < offset 即重置偏移），从而持续摄取。
func rotateAuditLogIfNeeded() {
	// 先重试上次失败的归档补采：成功才删除标记继续轮转；失败则保留 .1 不被 shift
	// 覆盖（事件尚存），待下次轮转重试，避免补采失败导致窗口事件永久丢失。
	if pending := securityEventsReadPendingDelta(); pending != nil {
		if _, err := os.Stat(pending.Path); os.IsNotExist(err) {
			log.Printf("audit log rotation: pending delta archive %s missing, dropping marker", pending.Path)
			_ = os.Remove(securityEventsPendingDeltaPath())
		} else if err := securityEventsIngestDeltaFrom(pending.Path, pending.Offset, true); err != nil {
			log.Printf("audit log rotation: pending delta ingest retry failed (rotation deferred): %v", err)
			return
		} else {
			log.Printf("audit log rotation: pending delta ingest recovered from %s", pending.Path)
			_ = os.Remove(securityEventsPendingDeltaPath())
		}
	}
	info, err := os.Stat(auditLogPath)
	if err != nil || info.Size() == 0 {
		return
	}
	maxBytes := auditLogSizeBytes()
	if info.Size() < maxBytes {
		return
	}
	// 轮转前记录已持久化的摄取偏移：tick 读到 EOF 后、复制完成前 Coraza 新写入
	// 的事件只存在于 .1，活文件截断后 tailer 重置偏移也不会再读 .1，需在归档后
	// 从 [persistedOffset, .1 size) 区间补采。
	persistedOffset, _ := securityEventsReadOffset(securityEventsOffsetPath)
	dir := filepath.Dir(auditLogPath)
	base := auditLogBaseName()
	// 先滚动历史副本：.4→.5、.3→.4、.2→.3、.1→.2
	for i := 4; i >= 1; i-- {
		old := filepath.Join(dir, fmt.Sprintf("%s.%d", base, i))
		newer := filepath.Join(dir, fmt.Sprintf("%s.%d", base, i+1))
		if _, err := os.Stat(old); err == nil {
			if rerr := os.Rename(old, newer); rerr != nil {
				log.Printf("audit log rotation: shift %s → %s failed: %v", old, newer, rerr)
			}
		}
	}
	// 归档当前日志到 .1；复制失败绝不截断，避免丢失尚未归档的数据。
	current := filepath.Join(dir, base+".1")
	if err := auditLogCopyFile(auditLogPath, current); err != nil {
		log.Printf("audit log rotation: copy to .1 failed (not truncating): %v", err)
		return
	}
	archInfo, err := os.Stat(current)
	if err != nil {
		log.Printf("audit log rotation: stat %s failed (not truncating): %v", current, err)
		return
	}
	archSize := archInfo.Size()
	// 补采活文件 [archSize, truncate 前) 的新写尾部：copy 最后一次读取后、truncate
	// 前 Coraza 新写入的事件两边都不在（.1 没有、活文件将被截断），须先于 truncate
	// 从活文件直接补采。补采失败绝不截断——尾部事件仍完整留在活文件中，下次 tick
	// 自然续读，不会丢失。
	// 有界循环（最多 3 轮）：补采 INSERT 耗时期间新写入的尾部也一并收敛，把残余
	// 窗口压缩到最后一轮 stat→truncate 的系统调用间隙。该间隙内的写入两边都不在
	// （copy 早已完成、未进 .1；truncate 后活文件里也没有），下次轮转的 .1 补采
	// 覆盖不到，为可接受的尽力而为缺口（毫秒级，仅损失该瞬间的尾部事件）。
	// 补采起点不取 archSize 本身，而是后向回扫到最近一个文档头：copy 末次读可能
	// 截断在正在写入的事务中部（前缀在 .1、后缀在活文件），从截断点直接解码会
	// 前向跳过该事务后半，.1 补采又因前缀 JSON 不完整无法解码——跨界事务将两半
	// 皆失。从文档头开始即可在活文件中完整解码整个事务。
	for i := 0; i < 3; i++ {
		tailInfo, terr := os.Stat(auditLogPath)
		if terr != nil || tailInfo.Size() <= archSize {
			break
		}
		ingestFrom, berr := securityEventsBackscanDocumentStart(auditLogPath, archSize)
		if berr != nil {
			log.Printf("audit log rotation: backscan live tail failed (not truncating): %v", berr)
			return
		}
		// 活文件补采以归档语义进行（archive=true）：补采区间有界且完整内容已在
		// 刚拷贝的 .1 中以归档语义摄取，活文件畸形区（≥4MB 无文档头）可安全跳过；
		// 若按活文件语义 F1 报错，轮转每 2s 周期反复中止，文件永不截断（R33 F1）。
		if ierr := securityEventsIngestDeltaFrom(auditLogPath, ingestFrom, true); ierr != nil {
			log.Printf("audit log rotation: ingest live tail [%d, %d) failed (not truncating): %v", ingestFrom, tailInfo.Size(), ierr)
			return
		}
		archSize = tailInfo.Size()
	}
	// F5: truncate 前先落 pending 标记。标记写失败绝不在无标记状态下截断——
	// 活文件仍完好、内容无损失，本轮中止下周期重试。truncate 成功与补采完成之间
	// 的任何崩溃点，标记都已在盘上（补采成功即删除、失败保留），下次轮转 shift 前
	// 先重试，双向崩溃安全；truncate 失败则移除标记——活文件未截断、内容完整，
	// 无需补采。
	if err := securityEventsWritePendingDelta(securityEventsPendingDelta{Path: current, Offset: persistedOffset, Size: archSize}); err != nil {
		log.Printf("audit log rotation: write pending delta marker failed, aborting rotation without truncate: %v", err)
		return
	}
	// 截断失败不影响数据安全（下次轮转会重试），仅记录日志。
	if err := os.Truncate(auditLogPath, 0); err != nil {
		_ = os.Remove(securityEventsPendingDeltaPath())
		log.Printf("audit log rotation: truncate failed (will retry next cycle): %v", err)
		return
	}
	log.Printf("audit log rotation: rotated %s (%d bytes → %s.1)", auditLogPath, info.Size(), base)
	// 补采轮转窗口：归档大小可能因复制期间的新写入大于 stat 时的 size，
	// 因此以 .1 实际大小作为窗口终点，覆盖复制竞态。
	if err := securityEventsIngestRotatedDelta(persistedOffset); err != nil {
		log.Printf("audit log rotation: ingest rotated delta failed (events in %s.1 may be lost): %v", base, err)
		// 标记保留（truncate 前已落盘）：事件只在 .1，下次轮转 shift 前先重试，
		// 防止 .1→.2 后事件永久丢失。
	} else {
		_ = os.Remove(securityEventsPendingDeltaPath())
	}
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
// audit_log_size_mb 且无上限校验，配置大值时整块分配会 OOM 崩溃循环（R33 F3）。
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
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func auditLogBaseName() string {
	return filepath.Base(auditLogPath)
}

// securityEventsPendingDelta 记录一次失败的归档补采：内容为待补采的归档路径 +
// 起始偏移 + 归档大小，持久化为 <auditlog>.delta-pending 标记文件。下次轮转
// shift 前先重试补采（成功才删除标记），防止 .1 被 shift 覆盖后事件永久丢失。
type securityEventsPendingDelta struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
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
	path := securityEventsPendingDeltaPath()
	tmp := path + ".tmp"
	if werr := os.WriteFile(tmp, data, 0o644); werr != nil {
		return werr
	}
	if werr := os.Rename(tmp, path); werr != nil {
		return werr
	}
	return nil
}

// securityEventsReadPendingDelta 读取待补采标记；不存在或损坏返回 nil。
func securityEventsReadPendingDelta() *securityEventsPendingDelta {
	data, err := os.ReadFile(securityEventsPendingDeltaPath())
	if err != nil {
		return nil
	}
	var p securityEventsPendingDelta
	if err := json.Unmarshal(data, &p); err != nil || p.Path == "" {
		return nil
	}
	return &p
}

func getAuditLogSizeBytes() int64 {
	var sizeMB int
	if err := db.DB.QueryRow("SELECT COALESCE(audit_log_size_mb, 10) FROM global_config WHERE id = 1").Scan(&sizeMB); err != nil {
		sizeMB = 10
	}
	if sizeMB <= 0 {
		sizeMB = 10
	}
	return int64(sizeMB) * 1024 * 1024
}
