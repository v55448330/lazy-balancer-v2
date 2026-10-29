package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/atomicfile"
	"lazy-balancer-v2/internal/models"
)

// skipChmodFaultInjectionIfRoot：权限位故障注入在 root 下无效（root 无视
// 0000/0555 权限），用例会从「期望失败」静默变成「成功」。显式跳过并声明
// 原因，而不是让断言隐式失效。
func skipChmodFaultInjectionIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root 无视文件权限位，chmod 故障注入不生效（CI 容器以 root 运行时跳过）")
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("fixture mkdir %s: %v", path, err)
	}
}

func TestSanitizeBundleVersion(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{name: "empty", input: "", want: ""},
		{name: "valid semver", input: "v4.28.0", want: "v4.28.0"},
		{name: "valid with separators", input: "v4.28.0-beta.1+x86_64", want: "v4.28.0-beta.1+x86_64"},
		{name: "valid max length", input: strings.Repeat("v", 64), want: strings.Repeat("v", 64)},
		{name: "too long", input: strings.Repeat("v", 65), want: ""},
		{name: "newline injection", input: "v4.28.0\nINJECTED", want: ""},
		{name: "control char", input: "v4.28.0\x01", want: ""},
		{name: "trailing space", input: "v4.28.0 ", want: ""},
		{name: "slash", input: "v4/28", want: ""},
		{name: "chinese", input: "v4.版本", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeBundleVersion(tt.input); got != tt.want {
				t.Fatalf("sanitizeBundleVersion(%q)=%q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildWafFileBundleInLockChecked_reportsRefReadFailure(t *testing.T) {
	src := t.TempDir()
	crsDir := filepath.Join(src, "crs")
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "a.conf"), []byte("SecRule X 1"), 0644); err != nil {
		t.Fatal(err)
	}
	// VERSION 是目录 → Ref 构造读取失败；旧实现静默省略后仍宣称完整。
	if err := os.Mkdir(filepath.Join(crsDir, "VERSION"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(OverrideWafLivePathsForTest(crsDir, filepath.Join(src, "ip2region.xdb")))

	WafFileLock().Lock()
	_, complete := BuildWafFileBundleInLockChecked()
	WafFileLock().Unlock()
	if complete {
		t.Fatal("ref read failure was silently reported as a complete bundle")
	}
}

func TestWafFileBundleRoundTrip(t *testing.T) {
	src := t.TempDir()
	rules := filepath.Join(src, "crs", "rules")
	// 布景错误必须 Fatal：旧实现忽略 MkdirAll/WriteFile 错误，sub 目录从未
	// 创建导致嵌套目录还原能力零覆盖（只验证了 a.conf）。
	if err := os.MkdirAll(filepath.Join(rules, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		path    string
		content string
	}{
		{filepath.Join(rules, "a.conf"), "SecRule X 1"},
		{filepath.Join(rules, "sub", "b.conf"), "SecRule X 2"},
		{filepath.Join(src, "crs", "VERSION"), "v4.14.0"},
	} {
		if err := os.WriteFile(f.path, []byte(f.content), 0o644); err != nil {
			t.Fatalf("fixture %s: %v", f.path, err)
		}
	}

	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(src, "crs"), filepath.Join(src, "ip2region.xdb")))
	writeTestFile(t, ip2regionLivePath, "fake-xdb-bytes")

	bundle := BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGz) == 0 || len(bundle.Xdb) == 0 {
		t.Fatalf("bundle incomplete: %+v", bundle)
	}
	ref := BuildWafFileRef()
	if ref == nil || ref.CRSSha256 != bundle.CRSSha256 || ref.IP2RegionSha != bundle.IP2RegionSha {
		t.Fatalf("ref/hash mismatch: %+v vs %+v", ref, bundle)
	}
	if wafFilesRefDiffers(ref) {
		t.Fatalf("ref should match local after build")
	}
	if !wafFilesRefMatchesBundle(ref, bundle) {
		t.Fatalf("bundle must match its ref")
	}

	// First apply to an empty live dir → both components changed
	os.RemoveAll(filepath.Join(src, "crs"))
	mustMkdirAll(t, filepath.Join(src, "crs"))
	os.Remove(ip2regionLivePath)
	crsChanged, xdbChanged, _, err := ApplyWafFileBundle(bundle)
	if err != nil || !crsChanged || !xdbChanged {
		t.Fatalf("first apply crsChanged=%v xdbChanged=%v err=%v", crsChanged, xdbChanged, err)
	}
	if got, _ := os.ReadFile(filepath.Join(rules, "a.conf")); string(got) != "SecRule X 1" {
		t.Fatalf("rules not restored: %q", got)
	}
	if got, err := os.ReadFile(filepath.Join(rules, "sub", "b.conf")); err != nil || string(got) != "SecRule X 2" {
		t.Fatalf("嵌套规则未还原: (%q,%v)", got, err)
	}
	if got, _ := os.ReadFile(ip2regionLivePath); string(got) != "fake-xdb-bytes" {
		t.Fatalf("xdb not restored: %q", got)
	}

	// Identical content → differs=false and apply is a no-op
	if wafFilesRefDiffers(ref) {
		t.Fatalf("identical files must not be re-fetched")
	}
	crsChanged, xdbChanged, _, err = ApplyWafFileBundle(bundle)
	if err != nil || crsChanged || xdbChanged {
		t.Fatalf("idempotent apply crsChanged=%v xdbChanged=%v err=%v", crsChanged, xdbChanged, err)
	}
}

func TestApplyWafFileBundleRejectsTamperedBytes(t *testing.T) {
	src := t.TempDir()
	srcRules := filepath.Join(src, "crs", "rules")
	mustMkdirAll(t, srcRules)
	writeTestFile(t, filepath.Join(srcRules, "a.conf"), "SecRule X 1")
	writeTestFile(t, filepath.Join(src, "crs", "VERSION"), "v4.14.0")

	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(src, "crs"), filepath.Join(src, "ip2region.xdb")))
	writeTestFile(t, ip2regionLivePath, "fake-xdb-bytes")

	bundle := BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGz) == 0 || len(bundle.Xdb) == 0 {
		t.Fatalf("bundle incomplete: %+v", bundle)
	}

	// Target live tree: empty, ready to receive the sync.
	dst := t.TempDir()
	dstRules := filepath.Join(dst, "crs", "rules")
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(dst, "crs"), filepath.Join(dst, "ip2region.xdb")))
	mustMkdirAll(t, crsLiveDir)

	// Tampered CRS tar.gz: declared hash unchanged, bytes differ.
	tampered := *bundle
	tamperDir := t.TempDir()
	if err := untarGzTo(bundle.CRSTarGz, tamperDir, ""); err != nil {
		t.Fatalf("untar bundle: %v", err)
	}
	writeTestFile(t, filepath.Join(tamperDir, "rules", "a.conf"), "SecRule X EVIL")
	data, _, err := tarGzDir(tamperDir)
	if err != nil {
		t.Fatalf("re-archive tampered: %v", err)
	}
	tampered.CRSTarGz = data
	tampered.Xdb = nil
	if _, _, _, err := ApplyWafFileBundle(&tampered); err == nil {
		t.Fatalf("tampered CRS must be rejected")
	}
	if _, err := os.Stat(filepath.Join(dstRules, "a.conf")); !os.IsNotExist(err) {
		t.Fatalf("tampered CRS must not be written to live tree")
	}

	// Tampered xdb: declared hash unchanged, bytes differ.
	tamperedXdb := *bundle
	tamperedXdb.CRSTarGz = nil
	tamperedXdb.Xdb = append([]byte(nil), bundle.Xdb...)
	tamperedXdb.Xdb[0] ^= 0xFF
	if _, _, _, err := ApplyWafFileBundle(&tamperedXdb); err == nil {
		t.Fatalf("tampered xdb must be rejected")
	}
	if _, err := os.Stat(ip2regionLivePath); !os.IsNotExist(err) {
		t.Fatalf("tampered xdb must not be written to live path")
	}

	// Untampered bundle still applies cleanly.
	crsChanged, xdbChanged, _, err := ApplyWafFileBundle(bundle)
	if err != nil || !crsChanged || !xdbChanged {
		t.Fatalf("valid bundle apply crsChanged=%v xdbChanged=%v err=%v", crsChanged, xdbChanged, err)
	}
}

// tarEntry 描述 rawTarGz 的一个条目；declaredSize 非零时构造只有头部的
// 单条目截断包，用有界字节覆盖声明体积门（不得为声明体积分配/压缩正文）。
type tarEntry struct {
	name         string
	declaredSize int64
	body         []byte
	// typeflag 非零时写入指定 tar 类型（如 tar.TypeDir 构造目录条目）。
	typeflag byte
}

// rawTarGz 按给定条目直接构造 tar.gz（不做路径归一/排序，用于构造恶意包）。
func rawTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		size := int64(len(entry.body))
		headerOnly := entry.declaredSize > 0
		if headerOnly {
			if len(entries) != 1 || len(entry.body) != 0 {
				t.Fatal("declaredSize 截断夹具只支持无正文的单条目")
			}
			size = entry.declaredSize
		}
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0644, Size: size, Typeflag: entry.typeflag}); err != nil {
			t.Fatal(err)
		}
		if headerOnly {
			// 解包器在读取正文前就必须按 hdr.Size 拒绝；不关闭 tar writer，
			// 避免它为补齐声明体积而写入 256MiB 零块。gzip 本身仍正常收尾。
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			return buf.Bytes()
		}
		if _, err := tw.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func assertNoStagingRemains(t *testing.T, destDir string) {
	t.Helper()
	if _, err := os.Stat(destDir + ".sync-in"); !os.IsNotExist(err) {
		t.Fatalf("staging %q still present after failure (err=%v)", destDir+".sync-in", err)
	}
}

func TestUntarGzTo_rejectsOversizedBundleAndCleansStaging(t *testing.T) {
	// 解包必须在写放大发生前拦截——文件数与字节数双限，且失败不得
	// 遗留 staging 目录到下一周期。
	t.Run("file count over limit", func(t *testing.T) {
		entries := make([]tarEntry, 0, maxWafSyncExtractFiles+1)
		for i := 0; i <= maxWafSyncExtractFiles; i++ {
			entries = append(entries, tarEntry{
				name: filepath.Join("rules", fmt.Sprintf("f%05d.conf", i)),
				body: []byte("SecRule"),
			})
		}
		destDir := t.TempDir()
		err := untarGzTo(rawTarGz(t, entries), destDir, "")
		if err == nil || !strings.Contains(err.Error(), "文件数超过上限") {
			t.Fatalf("error=%v, want file-count limit rejection", err)
		}
		assertNoStagingRemains(t, destDir)
	})
	t.Run("directory entries over limit", func(t *testing.T) {
		// 目录条目无上限时，64MB 包可让 staging 建出十余万目录
		// （元数据/inode 写放大）——必须在落盘前按条目数拦截。
		entries := make([]tarEntry, 0, maxWafSyncExtractDirs+1)
		for i := 0; i <= maxWafSyncExtractDirs; i++ {
			entries = append(entries, tarEntry{
				name:     fmt.Sprintf("d%05d", i),
				typeflag: tar.TypeDir,
			})
		}
		destDir := t.TempDir()
		err := untarGzTo(rawTarGz(t, entries), destDir, "")
		if err == nil || !strings.Contains(err.Error(), "目录条目数超过上限") {
			t.Fatalf("error=%v, want directory-count limit rejection", err)
		}
		assertNoStagingRemains(t, destDir)
	})
	t.Run("bytes over limit", func(t *testing.T) {
		destDir := t.TempDir()
		// 声明体积超限但实际内容极小：tar reader 按声明读取，校验必须在
		// 写放大发生前以声明体积拦截。
		data := rawTarGz(t, []tarEntry{{name: "huge.bin", declaredSize: maxWafSyncExtractBytes + 1}})
		err := untarGzTo(data, destDir, "")
		if err == nil || !strings.Contains(err.Error(), "解包体积超过上限") {
			t.Fatalf("error=%v, want byte-size limit rejection", err)
		}
		assertNoStagingRemains(t, destDir)
	})
}

func TestUntarGzTo_rejectsIllegalPathAndCleansStaging(t *testing.T) {
	// 非法路径拒绝时同样不得遗留 staging 目录。
	destDir := t.TempDir()
	data := rawTarGz(t, []tarEntry{{name: "../evil.conf", body: []byte("SecRule X EVIL")}})
	err := untarGzTo(data, destDir, "")
	if err == nil || !strings.Contains(err.Error(), "非法路径") {
		t.Fatalf("error=%v, want illegal path rejection", err)
	}
	assertNoStagingRemains(t, destDir)
}

func TestApplyWafFileBundle_rejectsCRSWithoutDeclaredHash(t *testing.T) {
	// 发现2：声明哈希为空但携带 CRS 内容——非法主节点构造（合法
	// BuildWafFileBundle 恒成对设置），untarGzTo 在 expectSum=="" 时跳过
	// 整树哈希校验，未验证字节会直接安装进 live CRS 树。必须与 xdb 分支
	// 对称拒绝，不得落盘。
	dst := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(dst, "crs"), filepath.Join(dst, "ip2region.xdb")))
	bundle := &WafFileBundle{CRSTarGz: rawTarGz(t, []tarEntry{{name: "rules/evil.conf", body: []byte("SecRule X EVIL")}}), CRSSha256: ""}
	if _, _, _, err := ApplyWafFileBundle(bundle); err == nil || !strings.Contains(err.Error(), "缺少声明哈希") {
		t.Fatalf("error=%v, want missing declared hash rejection", err)
	}
	if _, err := os.Stat(filepath.Join(crsLiveDir, "rules", "evil.conf")); !os.IsNotExist(err) {
		t.Fatalf("CRS tree must not be written without declared hash")
	}
}

func TestBuildWafFileRef_sanitizesMalformedIP2RegionTag(t *testing.T) {
	// 主端 BuildWafFileRef 把.version 原文写进 ref.IP2RegionTag（参与
	// waf_files 节哈希），而从端落盘前经 sanitizeBundleVersion 置空——同一畸形
	// 版本串两端推导结果不同，节哈希永不对齐，从端永久节流重拉。主端必须用同一
	// 规则推导 tag。
	// Given：live 树存在，.version 附带畸形版本串（含换行注入）
	src := t.TempDir()
	rules := filepath.Join(src, "crs", "rules")
	mustMkdirAll(t, rules)
	writeTestFile(t, filepath.Join(rules, "a.conf"), "SecRule X 1")
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(src, "crs"), filepath.Join(src, "ip2region.xdb")))
	writeTestFile(t, ip2regionLivePath, "fake-xdb-bytes")
	writeTestFile(t, ip2regionLivePath+".version", "v3.17.0\nINJECTED")

	// When：构建引用
	ref := BuildWafFileRef()

	// Then：tag 与从端同规则被置空（而非原文透传）
	if ref == nil {
		t.Fatalf("ref must be built when xdb exists")
	}
	if ref.IP2RegionTag != "" {
		t.Fatalf("malformed .version must sanitize to \"\", got %q", ref.IP2RegionTag)
	}
}

func TestBuildWafFileRef_keepsWellFormedIP2RegionTag(t *testing.T) {
	// Given：live 树存在，.version 为合法 [0-9.]+ 形版本串
	src := t.TempDir()
	rules := filepath.Join(src, "crs", "rules")
	mustMkdirAll(t, rules)
	writeTestFile(t, filepath.Join(rules, "a.conf"), "SecRule X 1")
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(src, "crs"), filepath.Join(src, "ip2region.xdb")))
	writeTestFile(t, ip2regionLivePath, "fake-xdb-bytes")
	writeTestFile(t, ip2regionLivePath+".version", "3.17.0\n")

	// When：构建引用
	ref := BuildWafFileRef()

	// Then：合法版本串原样保留（TrimSpace 后）
	if ref == nil {
		t.Fatalf("ref must be built when xdb exists")
	}
	if ref.IP2RegionTag != "3.17.0" {
		t.Fatalf("well-formed version must pass through unchanged, got %q", ref.IP2RegionTag)
	}
}

func TestApplyWafFileBundle_rejectsXdbWithoutDeclaredHash(t *testing.T) {
	// 声明哈希为空但携带 xdb 内容——非法主节点构造（合法
	// BuildWafFileBundle 恒成对设置），必须拒绝整包而非裸写原始字节。
	dst := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(dst, "crs"), filepath.Join(dst, "ip2region.xdb")))
	bundle := &WafFileBundle{Xdb: []byte("raw-bytes"), IP2RegionSha: ""}
	if _, _, _, err := ApplyWafFileBundle(bundle); err == nil || !strings.Contains(err.Error(), "缺少声明哈希") {
		t.Fatalf("error=%v, want missing declared hash rejection", err)
	}
	if _, err := os.Stat(ip2regionLivePath); !os.IsNotExist(err) {
		t.Fatalf("xdb must not be written without declared hash")
	}
}

func TestApplyWafFileBundle_preservesVersionFileRawBytes(t *testing.T) {
	// 上游 CRS 发布包的 VERSION 自带尾换行（如 "v4.29.0\n"），主端
	// CRSSha256 基于含原始字节的 tar 计算。Apply 不得以 TrimSpace 后的
	// bundle.CRSVersion 覆写 VERSION——否则本地 tar 哈希与已应用节哈希永久
	// 分叉，wafFilesDrifted 每轮误判漂移、全量重拉永不收敛（从端持续
	// 「安全数据持续同步失败」）。
	src := t.TempDir()
	srcRules := filepath.Join(src, "master-crs", "rules")
	mustMkdirAll(t, srcRules)
	writeTestFile(t, filepath.Join(srcRules, "a.conf"), "SecRule X 1")
	writeTestFile(t, filepath.Join(src, "master-crs", "VERSION"), "v4.99.0\n")

	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(src, "master-crs"), filepath.Join(src, "ip2region.xdb")))
	bundle := BuildWafFileBundle()
	if bundle == nil || bundle.CRSVersion != "v4.99.0" {
		t.Fatalf("bundle CRSVersion=%q, want trimmed v4.99.0", bundle.CRSVersion)
	}

	dst := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(dst, "crs"), filepath.Join(dst, "ip2region.xdb")))
	mustMkdirAll(t, crsLiveDir)

	crsChanged, _, _, err := ApplyWafFileBundle(bundle)
	if err != nil || !crsChanged {
		t.Fatalf("apply crsChanged=%v err=%v", crsChanged, err)
	}
	if got, _ := os.ReadFile(filepath.Join(crsLiveDir, "VERSION")); string(got) != "v4.99.0\n" {
		t.Fatalf("VERSION raw bytes must survive apply, got %q", got)
	}
	if liveSum, err := tarGzDirSum(crsLiveDir); err != nil || liveSum != bundle.CRSSha256 {
		t.Fatalf("live tree hash %q (err=%v) must equal declared %q — slave must converge", liveSum, err, bundle.CRSSha256)
	}
}

func TestUntarGzTo_midCopyFailure_restoresPureOldTree(t *testing.T) {
	skipChmodFaultInjectionIfRoot(t)
	// staging→destDir 复制中途失败时，恢复必须产出纯旧树。旧实现只
	// 用 backup 覆盖同名文件，已复制成功的新树文件残留为混合树。staging 预置
	// 的只读子目录（含文件使函数起始的 RemoveAll(staging) 静默失败而存活）
	// 让 copyDir 在复制完 a-new.conf 后失败。
	// Given：非空旧树 + 含一个新文件的同步包 + staging 内预置只读子目录
	destDir := filepath.Join(t.TempDir(), "crs")
	mustMkdirAll(t, filepath.Join(destDir, "rules"))
	writeTestFile(t, filepath.Join(destDir, "old.conf"), "SecRule OLD")
	// 完整 CRS 树形态（探针文件）：备份完整性门通过后才进入恢复拷贝路径。
	writeTestFile(t, filepath.Join(destDir, "rules", crsRulesProbeFile), "SecRule INIT")
	newTree := t.TempDir()
	writeTestFile(t, filepath.Join(newTree, "a-new.conf"), "SecRule NEW")
	data, _, err := tarGzDir(newTree)
	if err != nil {
		t.Fatal(err)
	}
	staging := destDir + ".sync-in"
	planted := filepath.Join(staging, "z-planted")
	if err := os.MkdirAll(planted, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(planted, "inner"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(planted, 0755)
		_ = os.RemoveAll(staging)
	})

	// When：expectSum 传空以跳过哈希校验（校验会读取只读目录，与本用例无关）
	err = untarGzTo(data, destDir, "")

	// Then：返回安装错误，且 destDir 恰好是纯旧树（无新树残留）
	if err == nil || !strings.Contains(err.Error(), "安装同步规则集") {
		t.Fatalf("err=%v, want 安装同步规则集 copy failure", err)
	}
	if got, readErr := os.ReadFile(filepath.Join(destDir, "old.conf")); readErr != nil || string(got) != "SecRule OLD" {
		t.Fatalf("old.conf=(%q,%v), want intact old tree file", got, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(destDir, "a-new.conf")); !os.IsNotExist(statErr) {
		t.Fatal("a-new.conf residue（混合树：恢复前未清空已复制的新文件）")
	}
	entries, readErr := os.ReadDir(destDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	// 纯旧树 = 备份的完整内容（old.conf + rules/ 探针），无新树残留。
	if len(names) != 2 || names[0] != "old.conf" || names[1] != "rules" {
		t.Fatalf("destDir entries=%v, want exactly [old.conf rules]（纯旧树）", names)
	}
	if got, err := os.ReadFile(filepath.Join(destDir, "rules", crsRulesProbeFile)); err != nil || string(got) != "SecRule INIT" {
		t.Fatalf("rules/%s=(%q,%v), want intact（纯旧树含探针）", crsRulesProbeFile, got, err)
	}
}

func TestUntarGzTo_firstInstall_midCopyFailure_leavesNoPartialTree(t *testing.T) {
	skipChmodFaultInjectionIfRoot(t)
	// Given：destDir 不存在（首装）且 copy 回退在复制新文件后失败。
	destDir := filepath.Join(t.TempDir(), "crs")
	newTree := t.TempDir()
	if err := os.WriteFile(filepath.Join(newTree, "a-new.conf"), []byte("SecRule NEW"), 0644); err != nil {
		t.Fatal(err)
	}
	data, _, err := tarGzDir(newTree)
	if err != nil {
		t.Fatal(err)
	}
	staging := destDir + ".sync-in"
	planted := filepath.Join(staging, "z-planted")
	if err := os.MkdirAll(planted, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(planted, "inner"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(planted, 0755)
		_ = os.Chmod(filepath.Join(destDir, "z-planted"), 0755)
		_ = os.RemoveAll(staging)
		_ = os.RemoveAll(destDir)
	})
	forceRenameFailure(t)

	// When
	err = untarGzTo(data, destDir, "")

	// Then：失败后首装目标必须回到「不存在」，不得留下部分新树。
	if err == nil {
		t.Fatal("err=nil, want copy fallback failure")
	}
	if _, statErr := os.Stat(destDir); !os.IsNotExist(statErr) {
		t.Fatalf("first install failure left partial tree at %s (stat=%v)", destDir, statErr)
	}
}

func TestUntarGzTo_removeAllFailure_attemptsBackupRestore(t *testing.T) {
	skipChmodFaultInjectionIfRoot(t)
	// rename 失败后 os.RemoveAll(destDir) 失败时 backup 已就绪，
	// 必须与 copyDir 失败分支对称地尝试从 backup 恢复（先清空再复制），恢复
	// 错误 errors.Join 并入返回；而非直接 return 留下部分删除的旧树。
	// Given：非空旧树（locked/ 0555 使 RemoveAll 失败但 backup 复制可读）+ 合法同步包
	destDir := filepath.Join(t.TempDir(), "crs")
	locked := filepath.Join(destDir, "locked")
	if err := os.MkdirAll(locked, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "old.conf"), []byte("SecRule OLD"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "inner.conf"), []byte("SecRule LOCKED"), 0644); err != nil {
		t.Fatal(err)
	}
	// 完整 CRS 树形态（探针文件）：备份完整性门通过后才进入恢复拷贝路径，
	// 本用例考的正是恢复失败的错误透传。
	if err := os.MkdirAll(filepath.Join(destDir, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "rules", crsRulesProbeFile), []byte("SecRule INIT"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0555); err != nil {
		t.Fatal(err)
	}
	backup := destDir + ".sync-bak"
	t.Cleanup(func() {
		_ = os.Chmod(locked, 0755)
		_ = os.Chmod(filepath.Join(backup, "locked"), 0755)
		_ = os.RemoveAll(destDir)
		_ = os.RemoveAll(backup)
	})
	newTree := t.TempDir()
	if err := os.WriteFile(filepath.Join(newTree, "a-new.conf"), []byte("SecRule NEW"), 0644); err != nil {
		t.Fatal(err)
	}
	data, _, err := tarGzDir(newTree)
	if err != nil {
		t.Fatal(err)
	}

	// When
	err = untarGzTo(data, destDir, "")

	// Then：返回错误同时包含清空失败与恢复尝试（恢复不得被跳过）
	if err == nil {
		t.Fatal("err=nil, want 清空目标规则树 failure（locked/ 应使 RemoveAll 失败）")
	}
	if !strings.Contains(err.Error(), "清空目标规则树") {
		t.Fatalf("err=%v, want 清空目标规则树 failure context", err)
	}
	if !strings.Contains(err.Error(), "恢复旧树") {
		t.Fatalf("err=%v, want backup restore attempt joined into the returned error（RemoveAll 失败分支跳过恢复，恢复面不对称）", err)
	}
	// 旧树未损的部分仍在，新树文件不得残留
	if got, readErr := os.ReadFile(filepath.Join(locked, "inner.conf")); readErr != nil || string(got) != "SecRule LOCKED" {
		t.Fatalf("locked/inner.conf=(%q,%v), want intact（RemoveAll 失败的旧树残留不得被新树污染）", got, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(destDir, "a-new.conf")); !os.IsNotExist(statErr) {
		t.Fatal("a-new.conf residue（新树文件不得出现在失败的清空路径）")
	}
	// backup 保留完整旧树，供下一轮同步兜底
	if got, readErr := os.ReadFile(filepath.Join(backup, "old.conf")); readErr != nil || string(got) != "SecRule OLD" {
		t.Fatalf("backup old.conf=(%q,%v), want intact backup tree", got, readErr)
	}
}

func TestUntarGzTo_restoreFailure_joinedIntoReturnedError(t *testing.T) {
	skipChmodFaultInjectionIfRoot(t)
	// 恢复自身的错误不得被 `_ =` 吞掉，必须并入返回错误。用两个确定性
	// 故障点替代临时文件轮询：staging 的不可读目录让新树复制失败；备份事务
	// rename 缝中预置的不可读目录让从备份恢复失败。
	destDir := filepath.Join(t.TempDir(), "crs")
	if err := os.MkdirAll(filepath.Join(destDir, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "old.conf"), []byte("SecRule OLD"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "rules", crsRulesProbeFile), []byte("SecRule INIT"), 0644); err != nil {
		t.Fatal(err)
	}
	newTree := t.TempDir()
	if err := os.WriteFile(filepath.Join(newTree, "a-new.conf"), []byte("SecRule NEW"), 0644); err != nil {
		t.Fatal(err)
	}
	data, _, err := tarGzDir(newTree)
	if err != nil {
		t.Fatal(err)
	}
	staging := destDir + ".sync-in"
	planted := filepath.Join(staging, "z-planted")
	if err := os.MkdirAll(planted, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(planted, "inner"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0000); err != nil {
		t.Fatal(err)
	}

	backup := destDir + ".sync-bak"
	oldCopyRename := copyDirRename
	copyDirRename = func(src, dst string) error {
		if src == backup+".tmp" && dst == backup {
			blocker := filepath.Join(src, "blocker")
			if err := os.MkdirAll(blocker, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(blocker, "inner"), []byte("x"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(blocker, 0000); err != nil {
				t.Fatal(err)
			}
		}
		return oldCopyRename(src, dst)
	}
	t.Cleanup(func() {
		copyDirRename = oldCopyRename
		_ = os.Chmod(planted, 0755)
		_ = os.Chmod(filepath.Join(backup, "blocker"), 0755)
		_ = os.RemoveAll(staging)
		_ = os.RemoveAll(destDir)
		_ = os.RemoveAll(backup)
	})
	forceRenameFailure(t)

	err = untarGzTo(data, destDir, "")

	if err == nil {
		t.Fatal("err=nil, want joined copy+restore failure")
	}
	if !strings.Contains(err.Error(), "安装同步规则集") {
		t.Fatalf("err=%v, want 安装同步规则集 copy failure context", err)
	}
	if !strings.Contains(err.Error(), "恢复旧树") {
		t.Fatalf("err=%v, want restore failure joined into the returned error（恢复错误被吞）", err)
	}
}

func TestUntarGzTo_nonEmptyDest_removesStaleFiles(t *testing.T) {
	// rename 到非空目录恒失败，兜底分支即主路径；合并复制不删除旧树中
	// 新包缺失的文件，CRS 更新删除/改名规则文件后从端树为旧+新合并、永不收敛。
	// 兜底分支必须先清空 destDir 再复制。
	// Given：非空目标树，含新包中不存在的陈旧文件与子目录
	destDir := t.TempDir()
	mustMkdirAll(t, filepath.Join(destDir, "rules"))
	writeTestFile(t, filepath.Join(destDir, "rules", "stale.conf"), "SecRule STALE")
	writeTestFile(t, filepath.Join(destDir, "rules", "kept.conf"), "SecRule OLD")
	mustMkdirAll(t, filepath.Join(destDir, "stale-dir"))
	writeTestFile(t, filepath.Join(destDir, "stale-dir", "gone.conf"), "SecRule GONE")

	// 新包：kept.conf 内容更新 + 新增文件，不含 stale.conf / stale-dir/
	newTree := t.TempDir()
	mustMkdirAll(t, filepath.Join(newTree, "rules"))
	writeTestFile(t, filepath.Join(newTree, "rules", "kept.conf"), "SecRule NEW")
	writeTestFile(t, filepath.Join(newTree, "rules", "added.conf"), "SecRule ADDED")
	data, declaredSum, err := tarGzDir(newTree)
	if err != nil {
		t.Fatal(err)
	}

	// When
	if err := untarGzTo(data, destDir, declaredSum); err != nil {
		t.Fatalf("untarGzTo: %v", err)
	}

	// Then：陈旧文件/目录被清除，live 树哈希等于声明哈希（从端收敛）
	if _, err := os.Stat(filepath.Join(destDir, "rules", "stale.conf")); !os.IsNotExist(err) {
		t.Fatal("stale.conf must be removed（合并复制残留 → 永不收敛）")
	}
	if _, err := os.Stat(filepath.Join(destDir, "stale-dir")); !os.IsNotExist(err) {
		t.Fatal("stale-dir must be removed（合并复制残留 → 永不收敛）")
	}
	if got, _ := os.ReadFile(filepath.Join(destDir, "rules", "kept.conf")); string(got) != "SecRule NEW" {
		t.Fatalf("kept.conf not updated: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(destDir, "rules", "added.conf")); string(got) != "SecRule ADDED" {
		t.Fatalf("added.conf missing: %q", got)
	}
	liveSum, err := tarGzDirSum(destDir)
	if err != nil {
		t.Fatal(err)
	}
	if liveSum != declaredSum {
		t.Fatalf("live tree hash %q must equal declared %q — slave must converge", liveSum, declaredSum)
	}
}

// 单元：主节点 bundle tag 为空是合法收敛信号（主端.version 缺失、损坏
// 或形状校验置空），本地陈旧 tag 必须同步清空——否则 waf_files 节哈希（含
// 标签）两端永不对齐，从端永久假漂移全量重拉。
func TestRewriteVersionIfMissingOrStale_emptyTagClearsStaleSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip2region.xdb.version")
	if err := os.WriteFile(path, []byte("v3.16.0"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := rewriteVersionIfMissingOrStale(path, ""); err != nil {
		t.Fatalf("empty tag must clear the stale sidecar: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale sidecar must be removed after empty-tag sync, stat err=%v", err)
	}
	// 幂等：目标本就不存在时同样成功（无文件可清）。
	if err := rewriteVersionIfMissingOrStale(path, ""); err != nil {
		t.Fatalf("empty tag on missing sidecar must be a noop success: %v", err)
	}
}

// 端到端：主端.version 缺失（tag 空）+ 从端内容一致但残留陈旧标签。
// 应用空 tag bundle 后从端标签必须清空，两端本地 ref 的 waf_files 节哈希
// （漂移判定口径）必须一致——否则永久假漂移。
func TestApplyWafFileBundle_emptyMasterTagConvergesSectionHash(t *testing.T) {
	// 主端：crs + xdb 齐备但无 .version（BuildWafFileRef 的 tag 保持为空）。
	master := t.TempDir()
	mustMkdirAll(t, filepath.Join(master, "crs", "rules"))
	writeTestFile(t, filepath.Join(master, "crs", "rules", "a.conf"), "SecRule X 1")
	writeTestFile(t, filepath.Join(master, "crs", "VERSION"), "v4.28.0")
	masterXdb := filepath.Join(master, "ip2region.xdb")
	writeTestFile(t, masterXdb, "same-xdb-bytes")

	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(master, "crs"), masterXdb))
	masterRef := BuildWafFileRef()
	bundle := BuildWafFileBundle()
	if masterRef == nil || bundle == nil || masterRef.IP2RegionTag != "" {
		t.Fatalf("master ref=%+v bundle=%v, want non-nil with empty tag", masterRef, bundle)
	}

	// 从端：内容与主端完全一致，仅残留陈旧 .version 标签。
	slave := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(slave, "crs"), filepath.Join(slave, "ip2region.xdb")))
	mustMkdirAll(t, filepath.Join(crsLiveDir, "rules"))
	writeTestFile(t, filepath.Join(crsLiveDir, "rules", "a.conf"), "SecRule X 1")
	writeTestFile(t, filepath.Join(crsLiveDir, "VERSION"), "v4.28.0")
	writeTestFile(t, ip2regionLivePath, "same-xdb-bytes")
	writeTestFile(t, ip2regionLivePath+".version", "v3.16.0")

	if _, _, _, err := ApplyWafFileBundle(bundle); err != nil {
		t.Fatalf("apply bundle with empty master tag: %v", err)
	}
	if _, err := os.Stat(ip2regionLivePath + ".version"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale slave tag must be cleared on empty-tag sync, stat err=%v", err)
	}
	slaveRef := BuildWafFileRef()
	if slaveRef == nil || slaveRef.IP2RegionTag != "" {
		t.Fatalf("slave ref tag=%q, want empty after convergence", slaveRef.IP2RegionTag)
	}
	masterHash, err := wafFilesSectionHash(masterRef)
	if err != nil {
		t.Fatal(err)
	}
	slaveHash, err := wafFilesSectionHash(slaveRef)
	if err != nil {
		t.Fatal(err)
	}
	if masterHash != slaveHash {
		t.Fatalf("waf_files section hash not converged: master=%s slave=%s", masterHash, slaveHash)
	}
}

// zeroReader 提供无限零字节流：构造超限响应体而不实际分配 64MB+ 内存。
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// 回归：响应体超过 64MB 上限时必须显式拒绝并点名上限（疑似主节点
// 数据异常），不得静默截断成损坏 JSON、以误导性的解析错误或哈希不匹配收场。
func TestFetchWafFiles_rejectsOversizeBundleBody(t *testing.T) {
	const bodyLimit = 64 << 20 // 与 fetchWafFiles 的响应体上限同口径
	_, database := newClusterTestService(t)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.CopyN(w, zeroReader{}, bodyLimit+1)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET master_url=?, cluster_token='token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := &SyncService{db: database, client: &http.Client{}}

	_, err := service.fetchWafFiles(context.Background(), &models.ClusterWafFilesRef{CRSSha256: "aa", IP2RegionSha: "bb"})
	if err == nil {
		t.Fatal("oversize bundle body must be rejected")
	}
	if !strings.Contains(err.Error(), "安全数据包超过 64MB 上限") {
		t.Fatalf("error must name the 64MB cap explicitly, got: %v", err)
	}
}

// RDB 文件化（v2.3.4）：威胁库 .fast 随 waf_files 通道同步——主节点
// BuildWafFileBundle 附带内容 + 哈希进 ref，从节点 ApplyWafFileBundle 落盘
// 幂等（哈希一致跳过）。
func TestWafFileBundleThreatFastRoundTrip(t *testing.T) {
	wafDir := t.TempDir()
	restoreWaf := OverrideThreatWafDirForTest(wafDir)
	defer restoreWaf()

	// 主节点产物：threat-ustc.iplist + .fast
	iplistPath := filepath.Join(wafDir, "threat-ustc.iplist")
	if err := os.WriteFile(iplistPath, []byte("192.0.2.0/24\n198.51.100.7\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := CompileFromIplistFile(iplistPath); err != nil {
		t.Fatal(err)
	}
	fastPath := iplistPath + ".fast"

	bundle := BuildWafFileBundle()
	if bundle == nil {
		t.Fatal("bundle 必须非 nil（含威胁文件时）")
	}
	found := false
	var wantFast []byte
	for _, tf := range bundle.ThreatFiles {
		if tf.Name == "ustc" {
			found = true
			if len(tf.Content) == 0 {
				t.Fatal("ustc .fast 内容必须随 bundle 携带")
			}
			wantFast = append([]byte(nil), tf.Content...)
		}
	}
	if !found {
		t.Fatalf("bundle.ThreatFiles 必须含 ustc: %+v", bundle.ThreatFiles)
	}
	ref := BuildWafFileRef()
	if ref == nil || ref.ThreatSha256s["ustc"] == "" {
		t.Fatalf("ref.ThreatSha256s 必须含 ustc: %+v", ref)
	}

	// 从节点：清掉 .fast 模拟未同步，再 Apply 落盘——字节必须等于主端内容
	// （只 Stat 存在性会让写空/截断同样通过）。
	if err := os.Remove(fastPath); err != nil {
		t.Fatal(err)
	}
	_, _, threatChanged, err := ApplyWafFileBundle(bundle)
	if err != nil {
		t.Fatalf("ApplyWafFileBundle: %v", err)
	}
	if !threatChanged {
		t.Fatal("威胁 .fast 首次落盘必须报告 threat 变更")
	}
	if got, readErr := os.ReadFile(fastPath); readErr != nil || !bytes.Equal(got, wantFast) {
		t.Fatalf(".fast 落盘字节与主端内容不一致（got %d bytes, err=%v）", len(got), readErr)
	}

	// 幂等：再次 Apply 三标志全 false 且字节不变（不得重写/截断）。
	crsChanged, xdbChanged, threatChanged, err := ApplyWafFileBundle(bundle)
	if err != nil || crsChanged || xdbChanged || threatChanged {
		t.Fatalf("幂等 Apply crs=%v xdb=%v threat=%v err=%v, want 全 false", crsChanged, xdbChanged, threatChanged, err)
	}
	if got, readErr := os.ReadFile(fastPath); readErr != nil || !bytes.Equal(got, wantFast) {
		t.Fatalf("幂等 Apply 后 .fast 字节变化（got %d bytes, err=%v）", len(got), readErr)
	}
}

// 威胁库.fast 分支防御奇偶——污染 bundle（声明
// 哈希与内容不符）必须整包拒绝落盘，与 xdb 分支同形；否则 bundle 在主端
// 构造或传输途中被污染的字节会直接安装进从节点威胁库（零编译直接消费）。
func TestApplyWafFileBundle_rejectsTamperedThreatFast(t *testing.T) {
	dst := t.TempDir()
	restoreWaf := OverrideThreatWafDirForTest(dst)
	defer restoreWaf()

	goodSum := sha256.Sum256([]byte("192.0.2.0/24\n198.51.100.7\n"))
	bundle := &WafFileBundle{
		ThreatFiles: []models.ThreatFileEntry{{
			Name:    "ustc",
			Sha256:  hex.EncodeToString(goodSum[:]),
			Content: []byte("203.0.113.0/24\nEVIL\n"),
		}},
	}
	_, _, threatChanged, err := ApplyWafFileBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "哈希不匹配") {
		t.Fatalf("error=%v, want threat .fast content hash mismatch rejection", err)
	}
	if threatChanged {
		t.Fatal("tampered threat .fast must not be applied")
	}
	fastPath := filepath.Join(dst, "threat-ustc.iplist.fast")
	if _, statErr := os.Stat(fastPath); !os.IsNotExist(statErr) {
		t.Fatalf("tampered .fast must not be written to live path, stat err=%v", statErr)
	}
	if _, statErr := os.Stat(fastPath + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("tampered .fast tmp must not be written, stat err=%v", statErr)
	}
}

// 空声明哈希携内容——合法主节点 BuildWafFileBundle 恒成对设置，
// 仅恶意/损坏主节点可构造；与 CRS/xdb 侧同纵深防御，拒绝而非裸写未验证
// 字节（原实现会在本地文件缺失时以整读哈希空串哨兵==tf.Sha256 静默跳过或
// 直接落盘）。
func TestApplyWafFileBundle_rejectsThreatFastWithoutDeclaredHash(t *testing.T) {
	dst := t.TempDir()
	restoreWaf := OverrideThreatWafDirForTest(dst)
	defer restoreWaf()

	bundle := &WafFileBundle{
		ThreatFiles: []models.ThreatFileEntry{{Name: "ustc", Sha256: "", Content: []byte("198.51.100.0/24\n")}},
	}
	if _, _, _, err := ApplyWafFileBundle(bundle); err == nil || !strings.Contains(err.Error(), "缺少声明哈希") {
		t.Fatalf("error=%v, want missing declared hash rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(dst, "threat-ustc.iplist.fast")); !os.IsNotExist(statErr) {
		t.Fatalf(".fast must not be written without declared hash, stat err=%v", statErr)
	}
}

// wafFilesRefMatchesBundle 交叉核验必须覆盖威胁面——bundle 携带
// 的逐源 .fast 哈希与 ref.ThreatSha256s 不符或缺失都必须判不匹配，否则
// 威胁面与 ref 漂移的 bundle 会被静默放行装进从节点。
func TestWafFilesRefMatchesBundle_verifiesThreatSha256s(t *testing.T) {
	ref := &models.ClusterWafFilesRef{CRSSha256: "crs", IP2RegionSha: "xdb"}
	baseBundle := WafFileBundle{CRSSha256: "crs", IP2RegionSha: "xdb"}

	t.Run("matching threat hashes pass", func(t *testing.T) {
		ref.ThreatSha256s = map[string]string{"ustc": "aa", "firehol1": "bb"}
		b := baseBundle
		b.ThreatFiles = []models.ThreatFileEntry{
			{Name: "ustc", Sha256: "aa", Content: []byte("a")},
			{Name: "firehol1", Sha256: "bb", Content: []byte("b")},
		}
		if !wafFilesRefMatchesBundle(ref, &b) {
			t.Fatal("matching threat hashes must pass")
		}
	})
	t.Run("mismatched threat hash fails", func(t *testing.T) {
		ref.ThreatSha256s = map[string]string{"ustc": "aa"}
		b := baseBundle
		b.ThreatFiles = []models.ThreatFileEntry{{Name: "ustc", Sha256: "zz", Content: []byte("z")}}
		if wafFilesRefMatchesBundle(ref, &b) {
			t.Fatal("mismatched threat hash must fail")
		}
	})
	t.Run("missing threat source fails", func(t *testing.T) {
		ref.ThreatSha256s = map[string]string{"ustc": "aa", "firehol1": "bb"}
		b := baseBundle
		b.ThreatFiles = []models.ThreatFileEntry{{Name: "ustc", Sha256: "aa", Content: []byte("a")}}
		if wafFilesRefMatchesBundle(ref, &b) {
			t.Fatal("threat source missing from bundle must fail")
		}
	})

	t.Run("bundle extra undeclared threat source fails", func(t *testing.T) {
		ref.ThreatSha256s = map[string]string{"ustc": "aa"}
		b := baseBundle
		b.ThreatFiles = []models.ThreatFileEntry{
			{Name: "ustc", Sha256: "aa", Content: []byte("a")},
			{Name: "et_compromised", Sha256: "cc", Content: []byte("c")},
		}
		if wafFilesRefMatchesBundle(ref, &b) {
			t.Fatal("bundle carrying an undeclared threat source must fail")
		}
	})
	t.Run("duplicate same-name threat source fails", func(t *testing.T) {
		ref.ThreatSha256s = map[string]string{"ustc": "aa", "firehol1": "bb", "et_compromised": "cc"}
		b := baseBundle
		b.ThreatFiles = []models.ThreatFileEntry{
			{Name: "ustc", Sha256: "aa", Content: []byte("a")},
			{Name: "ustc", Sha256: "aa", Content: []byte("a-duplicate")},
			{Name: "firehol1", Sha256: "bb", Content: []byte("b")},
		}
		if wafFilesRefMatchesBundle(ref, &b) {
			t.Fatal("duplicate same-name threat source must fail")
		}
	})
}

// 集群同步路径的 WAF ref 构建不得静默省略分量——
// 组件存在但读取/哈希失败时，旧实现少一项分量，从端不拉取、主端无告警，
// 主从静默分叉（从端继续用旧 WAF 规则/旧库）。修复后读失败显式化：
// 整个 ref 视为不可用（nil）+ 错误日志，从端漂移检测把 nil 当分叉处理
// （wafFilesDrifted: localRef==nil → 全量重拉，自愈方向）。
func TestBuildWafFileRef_readFailureIsExplicit(t *testing.T) {
	src := t.TempDir()
	crsDir := filepath.Join(src, "crs")
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "a.conf"), []byte("SecRule X 1"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(OverrideWafLivePathsForTest(crsDir, filepath.Join(src, "ip2region.xdb")))

	// 回归形状：完好树 → ref 含 CRS 分量。
	ref := BuildWafFileRef()
	if ref == nil || ref.CRSSha256 == "" {
		t.Fatalf("完好 CRS 树必须产出含 CRSSha256 的 ref: %+v", ref)
	}

	// 目标形状：VERSION 是目录（读失败）→ 不得静默省略分量后宣称完整。
	if err := os.Mkdir(filepath.Join(crsDir, "VERSION"), 0755); err != nil {
		t.Fatal(err)
	}
	if ref := BuildWafFileRef(); ref != nil {
		t.Fatalf("分量读失败必须显式化（nil ref + 错误日志），不得静默省略: %+v", ref)
	}
}

// xdb sidecar 只在内容哈希校验通过后才改写（拒绝路径不得留下
// 「新标签 + 旧库」跨代偏斜）。
func TestApplyWafFileBundle_xdbHashMismatchLeavesVersionSidecarUntouched(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	if err := os.WriteFile(live, []byte("old-live-xdb"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live+".version", []byte("v3.0.0"), 0644); err != nil {
		t.Fatal(err)
	}
	// 声明哈希与携带内容不符（传输损坏/异常主端）
	declared := sha256.Sum256([]byte("declared-bytes"))
	bundle := &WafFileBundle{
		IP2RegionTag: "v9.9.9",
		IP2RegionSha: hex.EncodeToString(declared[:]),
		Xdb:          []byte("tampered-bytes"),
	}

	// When
	if _, _, _, err := ApplyWafFileBundle(bundle); err == nil {
		t.Fatal("哈希不符的 xdb 包必须被拒绝")
	}

	// Then：live 与 sidecar 均保持更新前状态
	if got, err := os.ReadFile(live); err != nil || string(got) != "old-live-xdb" {
		t.Fatalf("live xdb 被改写: %q, %v", got, err)
	}
	if got, err := os.ReadFile(live + ".version"); err != nil || strings.TrimSpace(string(got)) != "v3.0.0" {
		t.Fatalf("拒绝路径改写了 .version sidecar: %q, %v（新标签+旧库跨代偏斜）", got, err)
	}
}

// 空内容 + 非空声明哈希的威胁条目拒绝整包（否则从端永不落盘、
// ref 哈希永不等，每轮误判漂移全量重拉永不收敛）。
func TestApplyWafFileBundle_emptyThreatContentWithDeclaredHashRejected(t *testing.T) {
	dir := t.TempDir()
	restore := OverrideThreatWafDirForTest(dir)
	t.Cleanup(restore)
	emptySum := sha256.Sum256(nil)
	bundle := &WafFileBundle{ThreatFiles: []models.ThreatFileEntry{{
		Name:    "ustc",
		Sha256:  hex.EncodeToString(emptySum[:]),
		Content: nil,
	}}}

	// When
	_, _, _, err := ApplyWafFileBundle(bundle)

	// Then：整体拒绝
	if err == nil {
		t.Fatal("空内容+非空声明哈希必须拒绝整包")
	}
	if !strings.Contains(err.Error(), "内容为空但声明哈希非空") {
		t.Fatalf("err=%v, want 空内容拒绝语义", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "threat-ustc.iplist.fast")); !os.IsNotExist(statErr) {
		t.Fatalf("拒绝路径不得落盘: %v", statErr)
	}
}

// 不完整 bundle 的响应体不得进入合并缓存（异常形态不得在 2s
// 窗口内放大传播）；完整 bundle 仍必须缓存。
func TestBuildWafFileBundleResponse_incompleteBundleNotCached(t *testing.T) {
	dir := t.TempDir()
	restoreWaf := OverrideThreatWafDirForTest(dir)
	t.Cleanup(restoreWaf)
	oldCache := wafFileBundleCache
	t.Cleanup(func() { wafFileBundleCache = oldCache })
	oldWindow := wafFileBundleResponseCoalesceWindow
	t.Cleanup(func() { wafFileBundleResponseCoalesceWindow = oldWindow })

	// Given 引用声明 CRS 哈希但物化缺内容（瞬时读失败形态）的缓存条目
	crsDir := filepath.Join(dir, "crs")
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "REQUEST-901.conf"), []byte("SecRule x"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(OverrideWafLivePathsForTest(crsDir, ip2regionLivePath))

	ref := BuildWafFileRef()
	if ref == nil || ref.CRSSha256 == "" {
		t.Fatal("测试布景未能构造 CRS 引用（目录不可哈希）——布景失败必须显式失败，不得静默跳过回归")
	}
	wafFileBundleCache.key = wafFileRefKey(ref)
	wafFileBundleCache.bundle = &WafFileBundle{CRSVersion: ref.CRSVersion, CRSSha256: ref.CRSSha256} // 缺 CRSTarGz
	wafFileBundleCache.response = nil
	wafFileBundleCache.responseValidatedAt = time.Time{}

	// When
	body := BuildWafFileBundleResponse()

	// Then 响应可返回但不得缓存
	if body == nil {
		t.Fatal("不完整 bundle 也应返回本次字节（只是不缓存）")
	}
	if wafFileBundleCache.response != nil {
		t.Fatal("不完整 bundle 的响应体被缓存（2s 窗口内持续放大异常形态）")
	}

	// 正对照：完整 bundle 仍必须缓存（门只排除异常形态，不影响合并优化）
	wafFileBundleCache.bundle = nil
	wafFileBundleResponseCoalesceWindow = 0 // 强制重算引用
	if BuildWafFileBundleResponse() == nil {
		t.Fatal("完整 bundle 响应为空")
	}
	if wafFileBundleCache.response == nil {
		t.Fatal("完整 bundle 的响应体未被缓存（合并窗口失效）")
	}
}

// 入口残留自愈：上次同步在「清空 live 后复制」窗口被 SIGKILL 时会留下
// 缺失 live + .sync-bak。本轮若解包/校验失败（拒绝落盘），旧实现直接返回、
// live 仍缺失（对应防护静默失效且无任何自愈通道）；新实现入口先按备份恢复
// 旧树，失败也守住「旧树优于无树」。
func TestUntarGzTo_healsCrashWindowResidueFromBackup(t *testing.T) {
	root := t.TempDir()
	destDir := filepath.Join(root, "crs")
	// 崩溃窗口形态：live 整体缺失，备份在场（完整树）。
	writeTestFile(t, filepath.Join(destDir+".sync-bak", "rules", "REQUEST-900.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(destDir+".sync-bak", "rules", crsRulesProbeFile), "SecRule init")
	// staging 残骸（上一轮中断留下）：必须被丢弃重建，不得合并进备份/新树。
	writeTestFile(t, filepath.Join(destDir+".sync-in", "rules", "STALE.conf"), "SecRule stale")

	payload := rawTarGz(t, []tarEntry{
		{name: "rules/REQUEST-901.conf", body: []byte("SecRule new")},
	})
	// 声明哈希不匹配 → 拒绝落盘（校验门在替换 live 之前）。
	if err := untarGzTo(payload, destDir, "deadbeef"); err == nil {
		t.Fatal("哈希不匹配必须拒绝落盘")
	}

	if data, err := os.ReadFile(filepath.Join(destDir, "rules", "REQUEST-900.conf")); err != nil || string(data) != "SecRule old" {
		t.Fatalf("live 缺失时必须按备份恢复旧树: err=%v data=%q", err, data)
	}
	if _, err := os.Stat(filepath.Join(destDir, "rules", "STALE.conf")); !os.IsNotExist(err) {
		t.Fatalf("staging 残骸不得进入 live 树: %v", err)
	}
	assertNoStagingRemains(t, destDir)
}

// 同族：live 非空（正常树）不受入口自愈影响——备份在场也不得以备份覆盖
// live（备份可能就是陈旧树，覆盖会回退用户刚同步的规则）。
func TestUntarGzTo_doesNotRestoreBackupOverHealthyLive(t *testing.T) {
	root := t.TempDir()
	destDir := filepath.Join(root, "crs")
	writeTestFile(t, filepath.Join(destDir, "rules", "REQUEST-900.conf"), "SecRule live")
	writeTestFile(t, filepath.Join(destDir+".sync-bak", "rules", "REQUEST-900.conf"), "SecRule stale-backup")
	writeTestFile(t, filepath.Join(destDir+".sync-bak", "rules", "REQUEST-901-INITIALIZATION.conf"), "SecRule backup-init")

	payload := rawTarGz(t, []tarEntry{
		{name: "rules/REQUEST-901.conf", body: []byte("SecRule new")},
	})
	if err := untarGzTo(payload, destDir, ""); err != nil {
		t.Fatalf("untar: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(destDir, "rules", "REQUEST-900.conf")); !os.IsNotExist(err) {
		t.Fatalf("全新替换必须删除旧树文件（纯新树不变量）: err=%v data=%q", err, data)
	}
}

// 多条目威胁库同步包必须先全部预检、再进行落盘：后续条目损坏时，前序条目
// 不得已经落盘（旧实现逐条「校验→写入」，随后条目失败会留下半更新的威胁库，
// 与错误文案「已拒绝整包」直接矛盾）。同一字节在预检阶段就要被拦下，任何
// 条目都不得写 live。
func TestApplyWafFileBundle_laterTamperedThreatEntryWritesNothing(t *testing.T) {
	dst := t.TempDir()
	restoreWaf := OverrideThreatWafDirForTest(dst)
	defer restoreWaf()

	good := []byte("203.0.113.0/24\n198.51.100.7\n")
	goodSum := sha256.Sum256(good)
	bundle := &WafFileBundle{
		ThreatFiles: []models.ThreatFileEntry{
			{Name: "ustc", Sha256: hex.EncodeToString(goodSum[:]), Content: good},
			{Name: "firehol_l1", Sha256: "deadbeef", Content: []byte("198.51.100.0/24\n")},
		},
	}

	_, _, threatChanged, err := ApplyWafFileBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "哈希不匹配") {
		t.Fatalf("error=%v, want 哈希不匹配拒绝", err)
	}
	if threatChanged {
		t.Fatal("整包被拒时不得报告威胁库已变更")
	}
	// 前序合法条目同样不得落盘（预检先于任何写入）。
	if _, statErr := os.Stat(filepath.Join(dst, "threat-ustc.iplist.fast")); !os.IsNotExist(statErr) {
		t.Fatalf("后续条目损坏时前序条目已落盘（半更新威胁库），stat err=%v", statErr)
	}
}

// 同一形态对 CRS/xdb 段同样成立：威胁条目损坏必须在 CRS/xdb 落盘之前被拦下，
// 否则「拒绝整包」实际只保住威胁库。
func TestApplyWafFileBundle_tamperedThreatEntryRejectedBeforeOthers(t *testing.T) {
	dst := t.TempDir()
	restoreWaf := OverrideThreatWafDirForTest(dst)
	defer restoreWaf()

	xdbDir := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(xdbDir, "crs"), filepath.Join(xdbDir, "ip2region.xdb")))

	xdb := []byte("fake-xdb-bytes")
	xdbSum := sha256.Sum256(xdb)
	bundle := &WafFileBundle{
		Xdb:          xdb,
		IP2RegionSha: hex.EncodeToString(xdbSum[:]),
		IP2RegionTag: "2026-10-01",
		ThreatFiles: []models.ThreatFileEntry{
			{Name: "ustc", Sha256: "deadbeef", Content: []byte("203.0.113.0/24\n")},
		},
	}

	if _, _, _, err := ApplyWafFileBundle(bundle); err == nil {
		t.Fatal("损坏威胁条目必须拒绝整包")
	}
	if _, statErr := os.Stat(ip2regionLivePath); !os.IsNotExist(statErr) {
		t.Fatalf("威胁条目损坏时 IP2Region 库已落盘（部分应用），stat err=%v", statErr)
	}
}

// 预检全过后进入落盘阶段：第二条写失败（盘满/权限/IO 错的真实形态）不得留下
// 第一条已生效的半更新威胁库——错误文案承诺「拒绝整包」，逐条原子写却让前序
// 条目真实生效，主从不一致会一直保持到下一次成功同步。
// 修复=落盘分两相位：全部暂存（写 temp+fsync）成功后才统一 rename。
func TestApplyWafFileBundle_stagingFailureLeavesNoPartialThreatFiles(t *testing.T) {
	dst := t.TempDir()
	restoreWaf := OverrideThreatWafDirForTest(dst)
	defer restoreWaf()

	first := []byte("203.0.113.0/24\n")
	second := []byte("198.51.100.0/24\n")
	firstSum := sha256.Sum256(first)
	secondSum := sha256.Sum256(second)
	bundle := &WafFileBundle{
		ThreatFiles: []models.ThreatFileEntry{
			{Name: "ustc", Sha256: hex.EncodeToString(firstSum[:]), Content: first},
			{Name: "firehol_l1", Sha256: hex.EncodeToString(secondSum[:]), Content: second},
		},
	}

	// 注入：第二条的暂存失败（等价 ENOSPC），第一条暂存成功。
	oldStage := wafBundleStage
	calls := 0
	wafBundleStage = func(path string, data []byte, mode os.FileMode) (*atomicfile.Staged, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("injected staging failure")
		}
		return atomicfile.Stage(path, data, mode)
	}
	t.Cleanup(func() { wafBundleStage = oldStage })

	_, _, _, err := ApplyWafFileBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "injected staging failure") {
		t.Fatalf("error=%v, want 注入的暂存失败", err)
	}
	for _, name := range []string{"ustc", "firehol_l1"} {
		live := filepath.Join(dst, "threat-"+name+".iplist.fast")
		if _, statErr := os.Stat(live); !os.IsNotExist(statErr) {
			t.Fatalf("暂存阶段失败时 %s 已生效（半更新威胁库），stat err=%v", name, statErr)
		}
	}
	// 暂存残留（含第一条已成功的 temp）必须全部清理。
	entries, readErr := os.ReadDir(dst)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("暂存失败后残留临时文件 %s", e.Name())
		}
	}
}
