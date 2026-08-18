package services

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	auditLogCheckInterval = 5 * time.Minute
)

// auditLogPath 是 Coraza 审计日志的路径；定义为变量以便测试注入临时目录
// （生产环境为 /app/waf/audit/audit.log）。
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
	// 截断失败不影响数据安全（下次轮转会重试），仅记录日志。
	if err := os.Truncate(auditLogPath, 0); err != nil {
		log.Printf("audit log rotation: truncate failed (will retry next cycle): %v", err)
		return
	}
	log.Printf("audit log rotation: rotated %s (%d bytes → %s.1)", auditLogPath, info.Size(), base)
	// 补采轮转窗口：归档大小可能因复制期间的新写入大于 stat 时的 size，
	// 因此以 .1 实际大小作为窗口终点，覆盖复制竞态。
	if err := securityEventsIngestRotatedDelta(persistedOffset); err != nil {
		log.Printf("audit log rotation: ingest rotated delta failed (events in %s.1 may be lost): %v", base, err)
	}
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
