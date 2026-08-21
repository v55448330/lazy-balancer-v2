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

func TestUntarGzTo_budgetExactlyExhaustedBoundary(t *testing.T) {
	// R56 N-4：预算恰好用尽边界——writtenBytes == max 后 remaining=0，任何
	// hdr.Size>0 的后续条目都必须按「先减后比」拒绝（边界 false-pass 会把
	// 总量推超预算）；而恰好顶满预算本身不得被误拒（边界 false-reject）。
	old := maxWafSyncExtractBytes
	maxWafSyncExtractBytes = 8
	t.Cleanup(func() { maxWafSyncExtractBytes = old })

	t.Run("one more byte rejected after exact exhaustion", func(t *testing.T) {
		// Given：8 字节条目恰好用尽预算 + 1 字节后续条目
		destDir := t.TempDir()
		data := rawTarGz(t, []tarEntry{
			{name: "a.conf", body: []byte("12345678")},
			{name: "b.conf", body: []byte("x")},
		})

		// When
		err := untarGzTo(data, destDir, "")

		// Then
		if err == nil || !strings.Contains(err.Error(), "解包体积超过上限") {
			t.Fatalf("error=%v, want 解包体积超过上限 rejection（预算用尽后 1 字节也不得放行）", err)
		}
		assertNoStagingRemains(t, destDir)
	})

	t.Run("exactly exhausted budget accepted", func(t *testing.T) {
		// Given：单条目恰好顶满预算
		destDir := filepath.Join(t.TempDir(), "live")
		data := rawTarGz(t, []tarEntry{{name: "a.conf", body: []byte("12345678")}})

		// When
		err := untarGzTo(data, destDir, "")

		// Then
		if err != nil {
			t.Fatalf("untar exactly-at-budget bundle: %v（顶满预算不得被误拒）", err)
		}
		content, readErr := os.ReadFile(filepath.Join(destDir, "a.conf"))
		if readErr != nil || string(content) != "12345678" {
			t.Fatalf("extracted content=(%q,%v), want a.conf installed", content, readErr)
		}
	})
}
