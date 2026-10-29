// Package atomicfile 提供「持久化原子落盘」原语：同目录临时文件 →
// 设置权限 → 写入 → fsync → rename → 父目录 fsync。掉电/内核崩溃下读者只会
// 看到完整旧文件或完整新文件，且新内容已持久（rename 前 fsync 数据，rename 后
// fsync 目录项）。任一失败都清理临时文件并返回错误。
//
// Ruling（post-rename 策略）：rename 已生效后父目录 fsync 失败仍向调用方返回
// error，由上层执行簿记补偿；wafiplist/fastformat.go 因模块边界与「新产物已可见，
// 不得谎报编译失败」选择告警并返回 nil，两种策略刻意不同，改动时须互相对照。
// 该叶模块无法反向 import 本包，是允许重复实现而非新增第三套语义的理由。
//
// 放在无仓内依赖的叶子包，供互不成环的包共用（acme 的账户密钥/元数据、
// services 的簿记文件）：同仓出现第二种「无 fsync/无目录同步」的落盘形态时，
// 崩溃窗口下会留下截断文件或丢失刚写入的目录项，而调用方只能按「文件不存在」
// 误判。
package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
)

// 失败注入面：本原语的契约是「任一失败都清理临时文件并返回错误」，但这些
// 分支在真实磁盘上无法可靠触发（权限位/写入/fsync/close/rename 需要盘满、
// 只读挂载或权限异常）。把系统调用收在包级变量上，测试即可逐条注入失败，
// 断言「错误上抛 + 目录零残留」；默认值就是标准库实现，无行为差异。
var (
	createTemp = os.CreateTemp
	removePath = os.Remove
	renamePath = os.Rename
	openPath   = os.Open

	fileChmod = (*os.File).Chmod
	fileWrite = (*os.File).Write
	fileSync  = (*os.File).Sync
	fileClose = (*os.File).Close
	dirSync   = (*os.File).Sync
)

// Staged 是一次「已写临时文件并 fsync、尚未 rename」的落盘。多文件批量落盘
// 用它把失败窗口压到提交之前：全部 staging 成功后才统一 Commit，任一 staging
// 失败只 Abort（live 文件面零改动）——逐文件 WriteAtomic 时第二份写失败会留下
// 第一份已生效的半应用状态。
type Staged struct {
	tmp  string
	path string
}

// Stage 写同目录临时文件、设权并 fsync 数据（不 rename：目标保持不变）。
// 目录必须已存在。失败时清理临时文件并返回错误（与 WriteAtomic 同契约）。
func Stage(path string, data []byte, mode os.FileMode) (*Staged, error) {
	dir := filepath.Dir(path)
	tmp, err := createTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	fail := func(cause error) (*Staged, error) {
		return nil, errors.Join(cause, fileClose(tmp), removePath(tmpName))
	}
	if err := fileChmod(tmp, mode); err != nil {
		return fail(err)
	}
	if _, err := fileWrite(tmp, data); err != nil {
		return fail(err)
	}
	if err := fileSync(tmp); err != nil {
		return fail(err)
	}
	if err := fileClose(tmp); err != nil {
		_ = removePath(tmpName)
		return nil, err
	}
	return &Staged{tmp: tmpName, path: path}, nil
}

// Commit 把暂存文件 rename 到目标并 fsync 父目录（rename 后父目录同步失败仍
// 返回错误——post-rename 策略见包注释）。
func (s *Staged) Commit() error {
	if s == nil || s.tmp == "" {
		return nil
	}
	tmpName := s.tmp
	if err := renamePath(tmpName, s.path); err != nil {
		_ = removePath(tmpName)
		s.tmp = ""
		return err
	}
	s.tmp = ""
	return SyncParent(s.path)
}

// Abort 丢弃尚未提交的暂存文件（幂等；已提交时目标保持不变）。
func (s *Staged) Abort() {
	if s == nil || s.tmp == "" {
		return
	}
	_ = removePath(s.tmp)
	s.tmp = ""
}

// WriteAtomic 原子且持久地写入 path（覆盖既有内容）。mode 为最终文件权限
// （显式 chmod，不受进程 umask 影响）。目录必须已存在。
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	staged, err := Stage(path, data, mode)
	if err != nil {
		return err
	}
	return staged.Commit()
}

// SyncParent 对 path 所在目录做 fsync：rename 只改目录项，目录本身的持久化
// 需要单独同步，否则掉电后新文件名可能不存在。
func SyncParent(path string) error {
	dir, err := openPath(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dirSync(dir); err != nil {
		return errors.Join(err, fileClose(dir))
	}
	return fileClose(dir)
}
