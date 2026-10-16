package taskengine

import (
	"fmt"
	"os"
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
