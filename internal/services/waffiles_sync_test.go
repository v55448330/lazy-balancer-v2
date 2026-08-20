package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestWafFileBundleRoundTrip(t *testing.T) {
	src := t.TempDir()
	rules := filepath.Join(src, "crs", "rules")
	os.MkdirAll(rules, 0755)
	os.WriteFile(filepath.Join(rules, "a.conf"), []byte("SecRule X 1"), 0644)
	os.WriteFile(filepath.Join(rules, "sub", "b.conf"), []byte("SecRule X 2"), 0644)
	os.WriteFile(filepath.Join(src, "crs", "VERSION"), []byte("v4.14.0"), 0644)

	oldLive := crsLiveDir
	oldXdb := ip2regionLivePath
	crsLiveDir = filepath.Join(src, "crs")
	ip2regionLivePath = filepath.Join(src, "ip2region.xdb")
	defer func() { crsLiveDir, ip2regionLivePath = oldLive, oldXdb }()
	os.WriteFile(ip2regionLivePath, []byte("fake-xdb-bytes"), 0644)

	bundle := BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGzB64) == 0 || len(bundle.XdbB64) == 0 {
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
	os.MkdirAll(filepath.Join(src, "crs"), 0755)
	os.Remove(ip2regionLivePath)
	crsChanged, xdbChanged, err := ApplyWafFileBundle(bundle)
	if err != nil || !crsChanged || !xdbChanged {
		t.Fatalf("first apply crsChanged=%v xdbChanged=%v err=%v", crsChanged, xdbChanged, err)
	}
	if got, _ := os.ReadFile(filepath.Join(rules, "a.conf")); string(got) != "SecRule X 1" {
		t.Fatalf("rules not restored: %q", got)
	}
	if got, _ := os.ReadFile(ip2regionLivePath); string(got) != "fake-xdb-bytes" {
		t.Fatalf("xdb not restored: %q", got)
	}

	// Identical content → differs=false and apply is a no-op
	if wafFilesRefDiffers(ref) {
		t.Fatalf("identical files must not be re-fetched")
	}
	crsChanged, xdbChanged, err = ApplyWafFileBundle(bundle)
	if err != nil || crsChanged || xdbChanged {
		t.Fatalf("idempotent apply crsChanged=%v xdbChanged=%v err=%v", crsChanged, xdbChanged, err)
	}
}

func TestApplyWafFileBundleRejectsTamperedBytes(t *testing.T) {
	src := t.TempDir()
	srcRules := filepath.Join(src, "crs", "rules")
	os.MkdirAll(srcRules, 0755)
	os.WriteFile(filepath.Join(srcRules, "a.conf"), []byte("SecRule X 1"), 0644)
	os.WriteFile(filepath.Join(src, "crs", "VERSION"), []byte("v4.14.0"), 0644)

	oldLive := crsLiveDir
	oldXdb := ip2regionLivePath
	crsLiveDir = filepath.Join(src, "crs")
	ip2regionLivePath = filepath.Join(src, "ip2region.xdb")
	defer func() { crsLiveDir, ip2regionLivePath = oldLive, oldXdb }()
	os.WriteFile(ip2regionLivePath, []byte("fake-xdb-bytes"), 0644)

	bundle := BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGzB64) == 0 || len(bundle.XdbB64) == 0 {
		t.Fatalf("bundle incomplete: %+v", bundle)
	}

	// Target live tree: empty, ready to receive the sync.
	dst := t.TempDir()
	dstRules := filepath.Join(dst, "crs", "rules")
	crsLiveDir = filepath.Join(dst, "crs")
	ip2regionLivePath = filepath.Join(dst, "ip2region.xdb")
	os.MkdirAll(crsLiveDir, 0755)

	// Tampered CRS tar.gz: declared hash unchanged, bytes differ.
	tampered := *bundle
	tamperDir := t.TempDir()
	if err := untarGzTo(bundle.CRSTarGzB64, tamperDir, ""); err != nil {
		t.Fatalf("untar bundle: %v", err)
	}
	os.WriteFile(filepath.Join(tamperDir, "rules", "a.conf"), []byte("SecRule X EVIL"), 0644)
	data, _, err := tarGzDir(tamperDir)
	if err != nil {
		t.Fatalf("re-archive tampered: %v", err)
	}
	tampered.CRSTarGzB64 = data
	tampered.XdbB64 = nil
	if _, _, err := ApplyWafFileBundle(&tampered); err == nil {
		t.Fatalf("tampered CRS must be rejected")
	}
	if _, err := os.Stat(filepath.Join(dstRules, "a.conf")); !os.IsNotExist(err) {
		t.Fatalf("tampered CRS must not be written to live tree")
	}

	// Tampered xdb: declared hash unchanged, bytes differ.
	tamperedXdb := *bundle
	tamperedXdb.CRSTarGzB64 = nil
	tamperedXdb.XdbB64 = append([]byte(nil), bundle.XdbB64...)
	tamperedXdb.XdbB64[0] ^= 0xFF
	if _, _, err := ApplyWafFileBundle(&tamperedXdb); err == nil {
		t.Fatalf("tampered xdb must be rejected")
	}
	if _, err := os.Stat(ip2regionLivePath); !os.IsNotExist(err) {
		t.Fatalf("tampered xdb must not be written to live path")
	}

	// Untampered bundle still applies cleanly.
	crsChanged, xdbChanged, err := ApplyWafFileBundle(bundle)
	if err != nil || !crsChanged || !xdbChanged {
		t.Fatalf("valid bundle apply crsChanged=%v xdbChanged=%v err=%v", crsChanged, xdbChanged, err)
	}
}

// tarEntry 描述 rawTarGz 的一个条目；declaredSize 非零时以声明体积写头
// （正文可小于声明，用于构造超大声明条目）。
type tarEntry struct {
	name         string
	declaredSize int64
	body         []byte
}

// rawTarGz 按给定条目直接构造 tar.gz（不做路径归一/排序，用于构造恶意包）。
func rawTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		size := int64(len(entry.body))
		if entry.declaredSize > 0 {
			size = entry.declaredSize
			// tar writer 要求正文与声明体积一致：以零填充补齐（gzip 压缩
			// 膨胀极小），让超限条目以真实体积通过解包流。
			body := entry.body
			if int64(len(body)) < size {
				body = make([]byte, size)
				copy(body, entry.body)
			}
			entry.body = body
		}
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0644, Size: size}); err != nil {
			t.Fatal(err)
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
	// N-02：解包必须在写放大发生前拦截——文件数与字节数双限，且失败不得
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
	// N-02：非法路径拒绝时同样不得遗留 staging 目录。
	destDir := t.TempDir()
	data := rawTarGz(t, []tarEntry{{name: "../evil.conf", body: []byte("SecRule X EVIL")}})
	err := untarGzTo(data, destDir, "")
	if err == nil || !strings.Contains(err.Error(), "非法路径") {
		t.Fatalf("error=%v, want illegal path rejection", err)
	}
	assertNoStagingRemains(t, destDir)
}

func TestApplyWafFileBundle_rejectsXdbWithoutDeclaredHash(t *testing.T) {
	// N-04：声明哈希为空但携带 xdb 内容——非法主节点构造（合法
	// BuildWafFileBundle 恒成对设置），必须拒绝整包而非裸写原始字节。
	dst := t.TempDir()
	oldLive, oldXdb := crsLiveDir, ip2regionLivePath
	crsLiveDir, ip2regionLivePath = filepath.Join(dst, "crs"), filepath.Join(dst, "ip2region.xdb")
	defer func() { crsLiveDir, ip2regionLivePath = oldLive, oldXdb }()
	bundle := &WafFileBundle{XdbB64: []byte("raw-bytes"), IP2RegionSha: ""}
	if _, _, err := ApplyWafFileBundle(bundle); err == nil || !strings.Contains(err.Error(), "缺少声明哈希") {
		t.Fatalf("error=%v, want missing declared hash rejection", err)
	}
	if _, err := os.Stat(ip2regionLivePath); !os.IsNotExist(err) {
		t.Fatalf("xdb must not be written without declared hash")
	}
}

func TestApplyWafFileBundle_preservesVersionFileRawBytes(t *testing.T) {
	// R46-E1：上游 CRS 发布包的 VERSION 自带尾换行（如 "v4.29.0\n"），主端
	// CRSSha256 基于含原始字节的 tar 计算。Apply 不得以 TrimSpace 后的
	// bundle.CRSVersion 覆写 VERSION——否则本地 tar 哈希与已应用节哈希永久
	// 分叉，wafFilesDrifted 每轮误判漂移、全量重拉永不收敛（从端持续
	// 「安全数据持续同步失败」）。
	src := t.TempDir()
	srcRules := filepath.Join(src, "master-crs", "rules")
	os.MkdirAll(srcRules, 0755)
	os.WriteFile(filepath.Join(srcRules, "a.conf"), []byte("SecRule X 1"), 0644)
	os.WriteFile(filepath.Join(src, "master-crs", "VERSION"), []byte("v4.99.0\n"), 0644)

	oldLive, oldXdb := crsLiveDir, ip2regionLivePath
	crsLiveDir = filepath.Join(src, "master-crs")
	ip2regionLivePath = filepath.Join(src, "ip2region.xdb")
	bundle := BuildWafFileBundle()
	if bundle == nil || bundle.CRSVersion != "v4.99.0" {
		t.Fatalf("bundle CRSVersion=%q, want trimmed v4.99.0", bundle.CRSVersion)
	}
	crsLiveDir, ip2regionLivePath = oldLive, oldXdb

	dst := t.TempDir()
	crsLiveDir, ip2regionLivePath = filepath.Join(dst, "crs"), filepath.Join(dst, "ip2region.xdb")
	defer func() { crsLiveDir, ip2regionLivePath = oldLive, oldXdb }()
	os.MkdirAll(crsLiveDir, 0755)

	crsChanged, _, err := ApplyWafFileBundle(bundle)
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
	// R48 A-F3：staging→destDir 复制中途失败时，恢复必须产出纯旧树。旧实现只
	// 用 backup 覆盖同名文件，已复制成功的新树文件残留为混合树。staging 预置
	// 的只读子目录（含文件使函数起始的 RemoveAll(staging) 静默失败而存活）
	// 让 copyDir 在复制完 a-new.conf 后失败。
	// Given：非空旧树 + 含一个新文件的同步包 + staging 内预置只读子目录
	destDir := filepath.Join(t.TempDir(), "crs")
	os.MkdirAll(destDir, 0755)
	os.WriteFile(filepath.Join(destDir, "old.conf"), []byte("SecRule OLD"), 0644)
	newTree := t.TempDir()
	os.WriteFile(filepath.Join(newTree, "a-new.conf"), []byte("SecRule NEW"), 0644)
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
	if len(entries) != 1 || entries[0].Name() != "old.conf" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("destDir entries=%v, want exactly [old.conf]（纯旧树）", names)
	}
}

func TestUntarGzTo_restoreFailure_joinedIntoReturnedError(t *testing.T) {
	// R48 A-F3：恢复（清空+从 backup 复制）自身的错误不得被 `_ =` 吞掉，必须
	// 并入返回错误。destDir 写入 32MB 新文件的窗口内注入只读子目录，使恢复路径
	// 的 RemoveAll(destDir) 失败。
	// Given：非空旧树 + 含大文件的同步包 + staging 内预置只读子目录
	destDir := filepath.Join(t.TempDir(), "crs")
	os.MkdirAll(destDir, 0755)
	os.WriteFile(filepath.Join(destDir, "old.conf"), []byte("SecRule OLD"), 0644)
	newTree := t.TempDir()
	os.WriteFile(filepath.Join(newTree, "a-new.conf"), make([]byte, 32<<20), 0644)
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
	blocker := filepath.Join(destDir, "blocker")
	t.Cleanup(func() {
		_ = os.Chmod(planted, 0755)
		_ = os.Chmod(blocker, 0755)
		_ = os.RemoveAll(staging)
		_ = os.RemoveAll(destDir)
	})
	tmpMarker := filepath.Join(destDir, "a-new.conf.tmp")
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		for {
			select {
			case <-stopWatch:
				return
			default:
			}
			if _, statErr := os.Stat(tmpMarker); statErr == nil {
				if mkErr := os.MkdirAll(blocker, 0755); mkErr != nil {
					return
				}
				if writeErr := os.WriteFile(filepath.Join(blocker, "inner"), []byte("x"), 0644); writeErr != nil {
					return
				}
				_ = os.Chmod(blocker, 0000)
				return
			}
		}
	}()
	defer func() {
		close(stopWatch)
		<-watchDone
	}()

	// When
	err = untarGzTo(data, destDir, "")

	// Then：返回错误同时包含复制失败与恢复失败（errors.Join）
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
	// R47 A-#2：rename 到非空目录恒失败，兜底分支即主路径；合并复制不删除旧树中
	// 新包缺失的文件，CRS 更新删除/改名规则文件后从端树为旧+新合并、永不收敛。
	// 兜底分支必须先清空 destDir 再复制。
	// Given：非空目标树，含新包中不存在的陈旧文件与子目录
	destDir := t.TempDir()
	os.MkdirAll(filepath.Join(destDir, "rules"), 0755)
	os.WriteFile(filepath.Join(destDir, "rules", "stale.conf"), []byte("SecRule STALE"), 0644)
	os.WriteFile(filepath.Join(destDir, "rules", "kept.conf"), []byte("SecRule OLD"), 0644)
	os.MkdirAll(filepath.Join(destDir, "stale-dir"), 0755)
	os.WriteFile(filepath.Join(destDir, "stale-dir", "gone.conf"), []byte("SecRule GONE"), 0644)

	// 新包：kept.conf 内容更新 + 新增文件，不含 stale.conf / stale-dir/
	newTree := t.TempDir()
	os.MkdirAll(filepath.Join(newTree, "rules"), 0755)
	os.WriteFile(filepath.Join(newTree, "rules", "kept.conf"), []byte("SecRule NEW"), 0644)
	os.WriteFile(filepath.Join(newTree, "rules", "added.conf"), []byte("SecRule ADDED"), 0644)
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
