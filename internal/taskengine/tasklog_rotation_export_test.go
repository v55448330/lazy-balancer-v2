package taskengine

// 导出轮转入口的两个契约守卫：
//   - 自取路径写锁：外部调用方（证书任务日志写入）不持锁调用，入口内
//     不取锁则 stat→rotate 与并发写入方的 stat→rotate→append 可交错（各写
//     一份「轮转后」内容或互相覆盖归档代）；
//   - 唯一入口：曾存在的 Context 变体零消费且 ctx 传播未接线（阈值读库仍走
//     Background），删除后不得再引入「看似支持 ctx 实则无人接线」的第二入口。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotateTaskLogBeforeWriteTakesPathLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exported.log")
	SetTaskLogSizeBytesFn(func(context.Context) int64 { return 1 }) // 恒超阈 → 必轮转
	t.Cleanup(func() { SetTaskLogSizeBytesFn(nil) })
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	lock := lockTaskLogPath(path)
	lock.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := RotateTaskLogBeforeWrite(path, 1, 1)
		done <- err
	}()
	select {
	case err := <-done:
		lock.Unlock()
		t.Fatalf("导出轮转入口未等待路径写锁（与写入侧 stat→rotate→append 可交错）: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	lock.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("解锁后轮转失败: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("解锁后导出轮转入口未完成")
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("超阈文件未轮转出 .1: %v", err)
	}
}

func TestTaskLogRotationHasNoUnwiredContextEntry(t *testing.T) {
	src, err := os.ReadFile("tasklog_rotation.go")
	if err != nil {
		t.Fatalf("读取 tasklog_rotation.go: %v", err)
	}
	if strings.Contains(string(src), "RotateTaskLogBeforeWriteContext") {
		t.Fatal("tasklog_rotation.go 又引入 Context 变体导出：其 ctx 从未传播到阈值读库（零消费），只保留 RotateTaskLogBeforeWrite 一个入口")
	}
}
