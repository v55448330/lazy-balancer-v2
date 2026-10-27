package config

// JWT 签名密钥落盘形态门：internal/atomicfile 的包注释把「同仓唯一原子落盘
// 原语」写成硬约束（第二种「无 fsync/无目录同步」的落盘形态在崩溃窗口下会留
// 截断文件）。此前的 os.WriteFile 直写正是这第二种形态——掉电后密钥可能半截，
// 下次启动判为弱密钥重生成，全部已签发 JWT/OIDC state 失效（fail-visible 但
// 全员重登）。本文件钉住：①默认落盘走该原语；②写失败时告警可见且旧密钥文件
// 不被破坏；③成功后磁盘形态完整（0600、无临时文件残留）；④生产代码不再出现
// 直写落盘。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/atomicfile"
)

// withJWSecretWrite 注入落盘接缝实现并复位（默认即 atomicfile.WriteAtomic）。
func withJWSecretWrite(t *testing.T, impl func(string, []byte, os.FileMode) error) {
	t.Helper()
	prev := jwtSecretWrite
	jwtSecretWrite = impl
	t.Cleanup(func() { jwtSecretWrite = prev })
}

// collectJWSecretWarns 以收集器替代 log 出口直调生成入口（与既有
// loadOrCreateJWTSecretForTest 同源，但需要观察告警文本）。
func collectJWSecretWarns(dataDir string) (string, []string) {
	var warns []string
	secret := loadOrCreateJWTSecretWith(dataDir, func(format string, args ...any) {
		warns = append(warns, fmt.Sprintf(format, args...))
	})
	return secret, warns
}

// 默认接缝必须是仓内唯一原子原语：改回 os.WriteFile / ioutil.WriteFile 形态
// 时本断言立即变红（函数指针身份比对，不做文本匹配）。
func TestJWTSecretWriteDefaultsToAtomicPrimitive(t *testing.T) {
	got := reflect.ValueOf(jwtSecretWrite).Pointer()
	want := reflect.ValueOf(atomicfile.WriteAtomic).Pointer()
	if got != want {
		t.Fatal("jwtSecretWrite 默认实现不是 atomicfile.WriteAtomic（出现第二种落盘形态）")
	}
}

// 写失败：告警必须可见，且路径上既有的旧密钥文件必须保持原样（不得被截断成
// 半截内容）。内存返回值仍是本次新生成的密钥（本次进程可用）。
func TestJWTSecretWriteFailureWarnsAndKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "jwt_secret")
	if err := os.WriteFile(secretPath, []byte("too-short"), 0600); err != nil {
		t.Fatalf("seed weak secret: %v", err)
	}
	withJWSecretWrite(t, func(string, []byte, os.FileMode) error {
		return errors.New("injected disk-full")
	})

	secret, warns := collectJWSecretWarns(dir)

	after, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("旧密钥文件必须仍然存在: %v", err)
	}
	if string(after) != "too-short" {
		t.Fatalf("旧密钥文件被改写为 %q，want 保持原样（写失败不得破坏既有文件）", after)
	}
	var writeWarned bool
	for _, w := range warns {
		if strings.Contains(w, "写入") && strings.Contains(w, secretPath) {
			writeWarned = true
		}
	}
	if !writeWarned {
		t.Fatalf("写失败必须告警（旧令牌重启后失效），got warns=%v", warns)
	}
	if len(secret) != 64 {
		t.Fatalf("返回值应是本次新生成的 32 字节十六进制密钥，got len=%d", len(secret))
	}
}

// 成功落盘后的磁盘形态：内容与返回值一致、权限 0600、目录内无临时文件残留
// （原子原语的 rename 收尾）。
func TestJWTSecretPersistIsAtomicOnDisk(t *testing.T) {
	dir := t.TempDir()

	secret, warns := collectJWSecretWarns(dir)
	if len(warns) != 0 {
		t.Fatalf("首次生成不应告警，got %v", warns)
	}

	secretPath := filepath.Join(dir, "jwt_secret")
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read persisted secret: %v", err)
	}
	if string(data) != secret {
		t.Fatalf("磁盘内容与返回值不一致（fallback/截断）")
	}
	info, err := os.Stat(secretPath)
	if err != nil {
		t.Fatalf("stat secret: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("密钥文件权限 %o，want 600", perm)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read data dir: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != "jwt_secret" {
			t.Fatalf("数据目录存在残留文件 %q（原子落盘的临时文件必须被 rename/清理）", entry.Name())
		}
	}

	// 再次加载必须复用同一密钥（原子落盘的成功路径不得改变「重启沿用」语义）。
	if again, _ := collectJWSecretWarns(dir); again != secret {
		t.Fatal("同一目录再次加载应复用已落盘密钥")
	}
}

// 生产代码不得再出现直写落盘形态（第二种形态即缺陷形态；测试文件可自便）。
func TestConfigProductionSourcesHaveNoDirectFileWrite(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob sources: %v", err)
	}
	scanned := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		scanned++
		if strings.Contains(string(data), "os.WriteFile(") {
			t.Fatalf("%s 出现 os.WriteFile 直写：落盘必须走 internal/atomicfile", file)
		}
	}
	if scanned == 0 {
		t.Fatal("未扫描到任何生产源文件（glob 面漂移会让本门空转）")
	}
}
