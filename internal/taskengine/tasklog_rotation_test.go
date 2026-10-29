package taskengine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestAppendTaskLogLine_rotatesBeforeWriteAtConfiguredThreshold(t *testing.T) {
	// Given：两个独立日志文件，共享 64B 阈值；A 已超阈，B 未超阈
	dir := t.TempDir()
	setLogDirForTest(t, dir)
	SetTaskLogSizeBytesFn(func(context.Context) int64 { return 64 })
	t.Cleanup(func() { SetTaskLogSizeBytesFn(nil) })
	if err := os.WriteFile(filepath.Join(dir, "a.log"), []byte(strings.Repeat("a", 60)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.log"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When：A 写入导致 size+line 超阈；B 写入仍低于阈值
	taskLogAppend("a", "next")
	taskLogAppend("b", "next")

	// Then：只有 A 在写入前滚动；活动文件只剩新内容，B 不受影响
	rotated, err := os.ReadFile(filepath.Join(dir, "a.log.1"))
	if err != nil {
		t.Fatalf("A 未在写入前滚动: %v", err)
	}
	if len(rotated) != 60 {
		t.Errorf("A.1 大小=%d want 60（真实文件大小驱动）", len(rotated))
	}
	active, err := os.ReadFile(filepath.Join(dir, "a.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(active), strings.Repeat("a", 60)) || !strings.Contains(string(active), "next") {
		t.Errorf("A 活动文件未在滚动后重建: %q", active)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.log.1")); !os.IsNotExist(err) {
		t.Errorf("B 不应滚动: err=%v", err)
	}
}

// 保留期删除与写入侧必须共用「活动路径」锁：清理侧扫描到的是轮转副本名
// （x.log.1），若按该名字取锁就与写入侧（持 x.log 锁做 stat→移位→append）
// 落在两把互斥量上——「锁内 stat 判定过期」与 os.Remove 之间可插入一次轮转，
// 被删掉的是**刚移位出的新一代**而不是本来要删的旧一代。
func TestTaskLogCopyCleanupSharesActivePathWriterLock(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "cleanup.log")
	copyPath := active + ".1"
	if err := os.WriteFile(copyPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().AddDate(0, -6, 0)
	if err := os.Chtimes(copyPath, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, []byte("fresh"), 0o644); err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		removed bool
		err     error
	}
	cutoff := time.Now().AddDate(0, -3, 0)
	lock := lockTaskLogPath(active)
	lock.Lock()
	done := make(chan outcome, 1)
	go func() {
		removed, err := RemoveTaskLogIfModifiedBefore(copyPath, cutoff)
		done <- outcome{removed: removed, err: err}
	}()

	// 写入侧持锁期间（stat→移位→append 全程）副本删除不得执行。
	select {
	case got := <-done:
		lock.Unlock()
		t.Fatalf("副本删除未等待活动路径写锁（与写入侧轮转可交错）: removed=%v err=%v", got.removed, got.err)
	case <-time.After(200 * time.Millisecond):
	}

	// 锁内发生一次轮转：旧 .1 被淘汰、刚写入的活动文件移位成 .1。
	if err := rotateTaskLogFile(active, 1); err != nil {
		lock.Unlock()
		t.Fatalf("轮转: %v", err)
	}
	lock.Unlock()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("清理: %v", got.err)
		}
		if got.removed {
			t.Fatal("清理删除了刚移位出的新一代（锁内复核应看到 fresh mtime）")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("解锁后清理未完成")
	}
	body, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatalf("刚移位出的新一代被删除: %v", err)
	}
	if string(body) != "fresh" {
		t.Fatalf(".1 内容=%q, want fresh（移位后的即当前一代）", body)
	}
}

// 轮转副本名必须归一到活动路径的锁；活动文件名本身可含点与数字后缀
// （任务 ID 白名单允许 '.'），不得被当作副本剥离成别人的锁。
func TestTaskLogPathLockTreatsRotatedCopiesAsActivePath(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "task.log")
	activeLock := lockTaskLogPath(active)
	for _, copyPath := range []string{active + ".1", active + ".5", active + ".2.gz", active + ".1.zst"} {
		if lockTaskLogPath(copyPath) != activeLock {
			t.Fatalf("%s 未归一到活动路径锁（写入侧轮转与保留期删除将持不同互斥量）", copyPath)
		}
	}
	if dotted := lockTaskLogPath(filepath.Join(dir, "task.2.log")); dotted == activeLock {
		t.Fatal("活动文件名带点/数字后缀被错误当作副本剥离（task.2.log 与 task.log 共锁）")
	}
	if other := lockTaskLogPath(filepath.Join(dir, "other.log")); other == activeLock {
		t.Fatal("不同任务日志路径共用了同一把锁（日志写入互相阻塞）")
	}
}

// 未注入尺寸函数（引擎早于 services 装配 / 纯 taskengine 测试）时的回退值必须
// 与治理默认值同源（db.DefaultTaskLogSizeMB），不得写第二份字面量。
func TestTaskLogSizeFallbackUsesDBDefault(t *testing.T) {
	SetTaskLogSizeBytesFn(nil)
	t.Cleanup(func() { SetTaskLogSizeBytesFn(nil) })
	want := int64(db.DefaultTaskLogSizeMB) * 1024 * 1024
	if got := taskLogSizeBytes(context.Background()); got != want {
		t.Fatalf("任务日志尺寸回退=%d, want %d（须引用 db.DefaultTaskLogSizeMB）", got, want)
	}
}
