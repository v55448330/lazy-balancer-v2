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
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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

// 生产快照不得绕过 atomicfile；专用日志、下载与已有事务型格式转换必须显式
// 登记理由。AST 扫描避免注释假阳性，并覆盖 WriteFile/Create/CreateTemp 与带写
// 标志的 OpenFile（只读 OpenFile 不是落盘写入）。扫描面=internal/ 全量 +
// cmd/（入口进程的直写同样在崩溃窗口内留截断文件）。
func TestConfigProductionSourcesHaveNoDirectFileWrite(t *testing.T) {
	exempt := map[string]string{
		"../cmd/server/main.go":           "监督器 pause 标记协议（与 handlers/caddy.go 同一标记文件）",
		"db/permissions.go":               "SQLite 文件预建与权限校正，不替换既有快照",
		"handlers/caddy.go":               "监督器 pause 标记协议",
		"handlers/config_backup_lbbak.go": "备份包临时解包与 WAF 目录事务恢复",
		"services/auditlog_rotation.go":   "审计日志轮转专用流式复制",
		"services/caddy.go":               "CLI 校验临时输入",
		"services/certjoblog.go":          "证书任务追加日志",
		"services/certstore.go":           "证书双文件一致性专用实现",
		"services/cluster_sync.go":        "集群 TLS 信任锚专用临时文件",
		"services/crshttp.go":             "CRS 下载落盘",
		"services/crsinstall.go":          "CRS 安装/回滚事务",
		"services/crsrelease.go":          "CRS 发布快照专用实现",
		"services/ip2regionhttp.go":       "IP 数据库下载落盘",
		"services/logrotate.go":           "追加型轮转日志",
		"services/securityevents.go":      "安全事件追加日志",
		"services/threatupdate.go":        "威胁库更新临时文件与备份",
		"services/waffiles_sync.go":       "WAF 文件树同步专用实现",
		"taskengine/engine.go":            "任务追加日志",
		"testsupport/tmpdir.go":           "测试环境临时目录可写探针",
	}
	scanned := 0
	cmdScanned := 0
	scanTree := func(root string, counter *int) error {
		return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			scanned++
			*counter++
			calls, err := directFileWriteCalls(path)
			if err != nil {
				return err
			}
			if len(calls) == 0 {
				return nil
			}
			rel, err := filepath.Rel("..", path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if reason, ok := exempt[rel]; ok {
				t.Logf("%s: %d direct-write call(s), exemption: %s", rel, len(calls), reason)
				return nil
			}
			t.Errorf("%s 出现直写落盘 %v：快照必须走 internal/atomicfile，专用形态须登记 Ruling", rel, calls)
			return nil
		})
	}
	if err := scanTree("..", new(int)); err != nil {
		t.Fatalf("scan internal production sources: %v", err)
	}
	if err := scanTree(filepath.Join("..", "..", "cmd"), &cmdScanned); err != nil {
		t.Fatalf("scan cmd production sources: %v", err)
	}
	if scanned < 100 {
		t.Fatalf("仅扫描到 %d 个生产源文件，递归扫描面退化", scanned)
	}
	if cmdScanned == 0 {
		t.Fatal("cmd/ 扫描面为零：入口进程直写不再被守卫覆盖")
	}
}

func directFileWriteCalls(path string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	var calls []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != "os" {
			return true
		}
		writeCall := selector.Sel.Name == "WriteFile" || selector.Sel.Name == "Create" || selector.Sel.Name == "CreateTemp"
		if selector.Sel.Name == "OpenFile" && len(call.Args) >= 2 {
			ast.Inspect(call.Args[1], func(flagNode ast.Node) bool {
				if ident, ok := flagNode.(*ast.Ident); ok {
					switch ident.Name {
					case "O_WRONLY", "O_RDWR", "O_CREATE", "O_APPEND", "O_TRUNC":
						writeCall = true
					}
				}
				return true
			})
		}
		if writeCall {
			calls = append(calls, fmt.Sprintf("%s:%d os.%s", path, fset.Position(call.Pos()).Line, selector.Sel.Name))
		}
		return true
	})
	return calls, nil
}

func TestDirectFileWriteCallScan_discriminatesWriteForms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.go")
	source := `package sample
import "os"
// os.WriteFile("comment-only", nil, 0600)
func sample() {
	_ = os.WriteFile
	_ = os.WriteFile("direct", nil, 0600)
	_, _ = os.CreateTemp("", "temporary")
	_, _ = os.OpenFile("read", os.O_RDONLY, 0)
	_, _ = os.OpenFile("write", os.O_CREATE|os.O_WRONLY, 0600)
}
`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	calls, err := directFileWriteCalls(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatalf("direct write calls=%v, want WriteFile/CreateTemp/write-OpenFile only", calls)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{":6 os.WriteFile", ":7 os.CreateTemp", ":9 os.OpenFile"} {
		if !strings.Contains(joined, want) {
			t.Errorf("scanner missing %s: %v", want, calls)
		}
	}
}

// 扫描面覆盖钉：cmd/ 入口源码必须在直写守卫的扫描面内（扫描面退化回仅
// internal/ 时，入口进程新增 os.WriteFile 直写不再被拦）。用合成直写样本
// 验证扫描器对 cmd 形态文件的检出能力——不依赖现存 pause 标记（该标记
// 将来若改走原子原语，本钉不得随之失效）。
func TestDirectFileWriteGuard_coversCmdEntrypointSources(t *testing.T) {
	cmdDir := filepath.Join("..", "..", "cmd", "server")
	if _, err := os.Stat(filepath.Join(cmdDir, "main.go")); err != nil {
		t.Fatalf("cmd 入口源码缺失（扫描面锚点失效）: %v", err)
	}
	path := filepath.Join(t.TempDir(), "cmd_sample.go")
	source := "package main\nimport \"os\"\nfunc sample() { _ = os.WriteFile(\"snapshot\", nil, 0o600) }\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	calls, err := directFileWriteCalls(path)
	if err != nil {
		t.Fatalf("scan cmd-shaped sample: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("cmd 形态直写样本检出=%v, want 1（扫描器退化）", calls)
	}
}
