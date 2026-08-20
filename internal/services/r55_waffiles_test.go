package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"math"
	"strings"
	"testing"
)

func TestUntarGzTo_rejectsEntryWhenDeclaredSizeOverflowsInt64(t *testing.T) {
	// R55 A-#2：GNU base-256 尺寸允许 hdr.Size 接近 2^63-1。旧检查
	// writtenBytes+hdr.Size > max 在已有写入（writtenBytes≥1）时 int64 溢出为负，
	// 上限判定被绕过，256MB 写放大防护失效（gzip 炸弹可膨胀远超上限）。
	// 修复后必须先减后比，按声明体积在写盘前拒绝。
	// Given：1 字节正常条目 + 声明 math.MaxInt64 的恶意条目（正文缺席——拒绝
	// 必须发生在读正文之前）
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "a.conf", Mode: 0644, Size: 1}); err != nil {
		t.Fatalf("write small entry header: %v", err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatalf("write small entry body: %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "bomb.bin", Mode: 0644, Size: math.MaxInt64}); err != nil {
		t.Fatalf("write overflow entry header: %v", err)
	}
	// 不写正文也不写 tar 尾部零块（tw.Close 会校验正文长度）：头部已随流写出，
	// 拒绝必须发生在解包方读取正文之前，尾部缺失不影响用例。
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	destDir := t.TempDir()

	// When
	err := untarGzTo(buf.Bytes(), destDir, "")

	// Then：必须被体积上限拒绝（而非落盘后 io.ErrUnexpectedEOF 等其它错误），
	// 且 staging 不遗留。
	if err == nil || !strings.Contains(err.Error(), "解包体积超过上限") {
		t.Fatalf("error=%v, want 解包体积超过上限 rejection（溢出不得绕过写放大防护）", err)
	}
	assertNoStagingRemains(t, destDir)
}
