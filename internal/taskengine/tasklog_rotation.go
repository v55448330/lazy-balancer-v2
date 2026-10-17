package taskengine

import (
	"fmt"
	"os"
	"sync"
)

// 任务日志统一滚动：所有写入都在追加前按真实文件大小判断。
// 阈值由 services 注入 task_log_size_mb（默认 10MB）；保留期清理由
// log-cleanup 另行负责，不参与尺寸滚动。
var taskLogSizeBytesFn func() int64

func SetTaskLogSizeBytesFn(fn func() int64) { taskLogSizeBytesFn = fn }

func TaskLogSizeBytes() int64 {
	if taskLogSizeBytesFn != nil {
		return taskLogSizeBytesFn()
	}
	return 10 * 1024 * 1024
}

// 按路径粒度的写入锁（U10-F08）：stat→rotate→append 必须整体互斥——两个写入
// 方在 stat 与 rotate 之间交错会各写一份「轮转后」内容到同名活动文件，或
// 互相覆盖归档代（并发跨阈值丢行）。锁表按路径惰性创建；路径集合=任务日志
// 固定集（注册任务 + 证书任务日志），不随写入行增长。
var (
	taskLogPathLocksMu sync.Mutex
	taskLogPathLocks   = map[string]*sync.Mutex{}
)

// lockTaskLogPath 返回路径写入锁（调用方 Lock/Unlock）。
func lockTaskLogPath(path string) *sync.Mutex {
	taskLogPathLocksMu.Lock()
	defer taskLogPathLocksMu.Unlock()
	l, ok := taskLogPathLocks[path]
	if !ok {
		l = &sync.Mutex{}
		taskLogPathLocks[path] = l
	}
	return l
}

// RotateTaskLogBeforeWrite 在 size+incoming 超阈时先滚动再写入。
// keep=归档份数（主流水 1、证书任务 5）；返回是否发生滚动。
func RotateTaskLogBeforeWrite(path string, incoming int64, keep int) (bool, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Size()+incoming <= TaskLogSizeBytes() {
		return false, nil
	}
	if err := RotateTaskLogFile(path, keep); err != nil {
		return false, err
	}
	return true, nil
}

// RotateTaskLogFile 把 current 逐代下移到 .1（.1→.2 …），删除最旧代。
func RotateTaskLogFile(path string, keep int) error {
	if keep < 1 {
		keep = 1
	}
	for i := keep; i >= 1; i-- {
		if i == keep {
			if err := os.Remove(fmt.Sprintf("%s.%d", path, i)); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		oldPath := fmt.Sprintf("%s.%d", path, i)
		newPath := fmt.Sprintf("%s.%d", path, i+1)
		if err := os.Rename(oldPath, newPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Rename(path, path+".1")
}
