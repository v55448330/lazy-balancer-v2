package taskengine

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 任务日志统一滚动：所有写入都在追加前按真实文件大小判断。
// 阈值由 services 注入 task_log_size_mb（默认 10MB）；保留期清理由
// log-cleanup 另行负责，不参与尺寸滚动。尺寸函数存于 taskLogConf
// （与目录同一把读写锁——裸全局在测试并发下存在数据竞争）。
func SetTaskLogSizeBytesFn(fn func(context.Context) int64) {
	taskLogConf.Lock()
	taskLogConf.sizeFn = fn
	taskLogConf.Unlock()
}

func taskLogSizeBytes(ctx context.Context) int64 {
	taskLogConf.RLock()
	fn := taskLogConf.sizeFn
	taskLogConf.RUnlock()
	if fn != nil {
		return fn(ctx)
	}
	// 未注入时的回退与治理默认值同源（services 读库侧同样引用
	// db.DefaultTaskLogSizeMB）：默认值只有一处定义，禁止在本包写第二份字面量。
	return int64(db.DefaultTaskLogSizeMB) * 1024 * 1024
}

// 按路径粒度的写入锁：stat→rotate→append 必须整体互斥——两个写入
// 方在 stat 与 rotate 之间交错会各写一份「轮转后」内容到同名活动文件，或
// 互相覆盖归档代（并发跨阈值丢行）。锁表按路径惰性创建；路径集合=任务日志
// 固定集（注册任务 + 证书任务日志），不随写入行增长；轮转副本（.N/.gz/.zst）归一到
// 活动路径键（见 taskLogActivePath），键集不因归档代增加而增长。
var (
	taskLogPathLocksMu sync.Mutex
	taskLogPathLocks   = map[string]*sync.Mutex{}
)

// lockTaskLogPath 返回路径写入锁（调用方 Lock/Unlock）。
// 键=活动日志路径（taskLogActivePath）：写入侧传活动名、保留期删除侧传扫描到
// 的副本名（x.log.1），两者必须落在同一把互斥量上。
func lockTaskLogPath(path string) *sync.Mutex {
	key := taskLogActivePath(path)
	taskLogPathLocksMu.Lock()
	defer taskLogPathLocksMu.Unlock()
	l, ok := taskLogPathLocks[key]
	if !ok {
		l = &sync.Mutex{}
		taskLogPathLocks[key] = l
	}
	return l
}

// rotationCompressionSuffixes 轮转副本的压缩后缀集合（单源）。锁键归一
// （taskLogActivePath）与读侧副本分类器（handlers 的
// classifyRotationCopyName 经 StripRotationCompressionSuffix 调用）共用同一
// 集合——两侧各持一份会让 .zst 副本在分类器里归族、在锁键里却不归一，保留期
// 删除取到副本名自己的锁，与写入侧的活动路径锁互不排斥。
var rotationCompressionSuffixes = []string{".gz", ".zst"}

// StripRotationCompressionSuffix 剥掉轮转副本的压缩后缀（.gz / .zst）并报告
// 是否压缩。读侧命名分类与写侧锁键归一必须同源，避免两侧命名知识各写一份后
// 漂移。
func StripRotationCompressionSuffix(name string) (core string, compressed bool) {
	for _, suffix := range rotationCompressionSuffixes {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix), true
		}
	}
	return name, false
}

// taskLogActivePath 把轮转副本路径归一到其活动文件名（x.log.1 / x.log.3.gz
// → x.log），非副本路径原样返回。副本删除与写入侧轮转必须同锁：写入侧持活动
// 路径锁做 stat→移位→append，若删除侧按副本名各自取锁，两把锁互不排斥——
// 「锁内 stat 判定过期」与 os.Remove 之间插入一次轮转，删掉的就是刚移位出的
// 当前一代（最多一份 task_log_size_mb），而非本来要删的旧代。
//
// 只剥离末尾一段「.纯数字」后缀（先剥压缩后缀 .gz/.zst）：活动文件名本身允许
// 含点与数字（任务 ID 白名单含 '.'），x.2.log 不得被当成 x.2 的副本。
func taskLogActivePath(path string) string {
	base, _ := StripRotationCompressionSuffix(path)
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 {
		return path
	}
	generation := base[dot+1:]
	if generation == "" {
		return path
	}
	for _, ch := range generation {
		if ch < '0' || ch > '9' {
			return path
		}
	}
	if !strings.HasSuffix(base[:dot], ".log") {
		return path
	}
	return base[:dot]
}

// RemoveTaskLogIfModifiedBefore 在任务日志写入锁内重新 stat 后按保留期删除。
// 扫描者锁外看到的旧 FileInfo 可能已被「rotate→rename→append」替换；
// 锁内复核避免误删刚移位或刚写入的新一代文件。
// path 可以是轮转副本名（x.log.1）——锁键归一到活动路径（taskLogActivePath），
// 与写入侧持的是同一把锁，轮转无法插进 stat→remove 之间。
func RemoveTaskLogIfModifiedBefore(path string, cutoff time.Time) (bool, error) {
	lock := lockTaskLogPath(path)
	lock.Lock()
	defer lock.Unlock()
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.ModTime().Before(cutoff) {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	return true, nil
}

// RotateTaskLogBeforeWrite 在 size+incoming 超阈时先滚动再写入。
// keep=归档份数（主流水 1、证书任务 5）；返回是否发生滚动。
//
// 阈值在调用时读取（sizeFn 可能读库）：已持路径写锁的调用方应改用
// rotateTaskLogBeforeWrite 并把锁外取到的阈值传入——持锁读库会把同条件的
// 其他日志写者一起拖到 busy_timeout。
func RotateTaskLogBeforeWrite(path string, incoming int64, keep int) (bool, error) {
	return RotateTaskLogBeforeWriteContext(context.Background(), path, incoming, keep)
}

// RotateTaskLogBeforeWriteContext 与 RotateTaskLogBeforeWrite 同语义，
// 阈值数据库读取消费调用方上下文。
func RotateTaskLogBeforeWriteContext(ctx context.Context, path string, incoming int64, keep int) (bool, error) {
	return rotateTaskLogBeforeWrite(path, incoming, keep, taskLogSizeBytes(ctx))
}

// rotateTaskLogBeforeWrite 与 RotateTaskLogBeforeWrite 同语义，阈值由调用方
// 提供（锁序：先取阈值再取路径锁）。
func rotateTaskLogBeforeWrite(path string, incoming int64, keep int, sizeLimit int64) (bool, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Size()+incoming <= sizeLimit {
		return false, nil
	}
	if err := rotateTaskLogFile(path, keep); err != nil {
		return false, err
	}
	return true, nil
}

// rotateTaskLogFile 把 current 逐代下移到 .1（.1→.2 …），删除最旧代。
func rotateTaskLogFile(path string, keep int) error {
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
