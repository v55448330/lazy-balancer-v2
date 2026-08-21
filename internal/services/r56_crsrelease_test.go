package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractCRSTarball_rejectsEntryWhenDeclaredSizeOverflowsInt64(t *testing.T) {
	// R56 发现1：与 R55 A-#2（untarGzTo）同形的「先加后比」int64 溢出——
	// totalBytes(≥1) + MaxInt64 回绕为负，> 500MB 判假，解压上限被绕过，
	// 构造 tarball 可按声明体积写爆数据卷（新 tag 首次下载无 TOFU 基线可比，
	// 该上限是最后一道防线）。修复后必须先减后比，按声明体积在写盘前拒绝。
	// Given：1 字节正常条目 + 声明 math.MaxInt64 的恶意条目（正文缺席——拒绝
	// 必须发生在读正文之前）
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "coreruleset-4.15.0/rules/a.conf", Mode: 0644, Size: 1}); err != nil {
		t.Fatalf("write small entry header: %v", err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatalf("write small entry body: %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "coreruleset-4.15.0/rules/bomb.bin", Mode: 0644, Size: math.MaxInt64}); err != nil {
		t.Fatalf("write overflow entry header: %v", err)
	}
	// 不写正文也不写 tar 尾部零块：头部已随流写出，拒绝必须发生在解包方
	// 读取正文之前，尾部缺失不影响用例。
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	src := filepath.Join(t.TempDir(), "crs-release.tar.gz")
	if err := os.WriteFile(src, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	// When
	err := extractCRSTarball(src, t.TempDir())

	// Then：必须被体积上限拒绝（而非落盘后 io.ErrUnexpectedEOF 等其它错误）。
	if err == nil || !strings.Contains(err.Error(), "解压超过大小上限") {
		t.Fatalf("error=%v, want 解压超过大小上限 rejection（溢出不得绕过 500MB 解压上限）", err)
	}
}
