package services

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SYSB44-2(P3):轮转同秒碰撞后缀原为 UnixNano()%1000 随机数——同秒第二次轮转
// 若撞上既有副本名,os.Rename 静默覆盖(吞掉上一份轮转日志)。修复为循环递增
// -2/-3/...(与 autobackup 同秒序号 -2..-201 同模式)直至文件名不存在。
// 确定性 RED 构造:预建基准名 path.T 与全部 1000 个可能的 nano 后缀
// (path.T.0~999,各占位子内容唯一)——旧实现无论随机到何值必撞名覆盖;
// 为消除翻秒竞态,当前秒与下一秒两套戳都预建。
func TestSYSB44_2_rotateLocked_never_overwrites_same_second_copies(t *testing.T) {
	// Given
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	now := time.Now()
	type copyExpect struct {
		name    string
		content string
	}
	var expects []copyExpect
	for _, ts := range []time.Time{now, now.Add(time.Second)} {
		stamp := ts.Format("20060102-150405")
		base := fmt.Sprintf("runtime.log.%s", stamp)
		expects = append(expects, copyExpect{name: base, content: "base-copy-" + stamp})
		for i := 0; i < 1000; i++ {
			name := fmt.Sprintf("%s.%d", base, i)
			expects = append(expects, copyExpect{name: name, content: fmt.Sprintf("pad-%s-%d", stamp, i)})
		}
	}
	for _, e := range expects {
		if err := os.WriteFile(filepath.Join(dir, e.name), []byte(e.content), 0o644); err != nil {
			t.Fatalf("precreate %s: %v", e.name, err)
		}
	}
	// 活动日志文件带可识别内容
	if err := os.WriteFile(logPath, []byte("live-content\n"), 0o644); err != nil {
		t.Fatalf("write live log: %v", err)
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open live log: %v", err)
	}
	w := &RotatingFileWriter{path: logPath, file: f, size: int64(len("live-content\n"))}
	t.Cleanup(func() { _ = w.Close() })

	// When 同秒轮转
	if err := w.rotateLocked(); err != nil {
		t.Fatalf("rotateLocked: %v", err)
	}

	// Then ①全部既有副本内容原样保留(无任何覆盖)
	for _, e := range expects {
		data, rerr := os.ReadFile(filepath.Join(dir, e.name))
		if rerr != nil {
			t.Fatalf("既有副本 %s 丢失: %v", e.name, rerr)
		}
		if string(data) != e.content {
			t.Fatalf("既有副本 %s 被覆盖: 内容=%q, want %q(同秒轮转不得吞掉旧副本)", e.name, string(data), e.content)
		}
	}
	// Then ②轮转出的新副本完整携带活动内容(独立于 1000 个占位文件之外的第 2003 个文件)
	entries, derr := os.ReadDir(dir)
	if derr != nil {
		t.Fatalf("readdir: %v", derr)
	}
	rotatedWithLive := 0
	for _, entry := range entries {
		if entry.Name() == "runtime.log" {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if rerr == nil && string(data) == "live-content\n" {
			rotatedWithLive++
		}
	}
	if rotatedWithLive != 1 {
		t.Fatalf("携带活动内容的轮转副本数=%d, want 1(轮转内容必须完整落盘且仅此一份)", rotatedWithLive)
	}
	// Then ③活动文件已重开(继续可写)
	if _, serr := os.Stat(logPath); serr != nil {
		t.Fatalf("轮转后活动文件未重开: %v", serr)
	}
}

// SYSB44-2 回归形状:无碰撞时仍轮转为 path.T 基准名(单后缀形态不变)。
func TestSYSB44_2_rotateLocked_plain_rotation_keeps_timestamp_suffix(t *testing.T) {
	// Given 无任何既有副本
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	if err := os.WriteFile(logPath, []byte("first\n"), 0o644); err != nil {
		t.Fatalf("write live log: %v", err)
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open live log: %v", err)
	}
	w := &RotatingFileWriter{path: logPath, file: f, size: 6}
	t.Cleanup(func() { _ = w.Close() })

	// When
	if err := w.rotateLocked(); err != nil {
		t.Fatalf("rotateLocked: %v", err)
	}

	// Then 目录中恰有一个 path.<时间戳> 形态副本,内容为 first
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	rotated := []string{}
	for _, entry := range entries {
		if entry.Name() != "runtime.log" {
			rotated = append(rotated, entry.Name())
		}
	}
	if len(rotated) != 1 {
		t.Fatalf("轮转副本数=%d (%v), want 1", len(rotated), rotated)
	}
	data, err := os.ReadFile(filepath.Join(dir, rotated[0]))
	if err != nil || string(data) != "first\n" {
		t.Fatalf("轮转副本内容=%q err=%v, want %q", string(data), err, "first\n")
	}
}
