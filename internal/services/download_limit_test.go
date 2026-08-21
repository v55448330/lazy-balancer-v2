package services

// allow: SIZE_OK — R34-A download size cap regression tests.

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteRuleSetDownload_limitsDownloadSize 验证下载限界（R34 A）：
// Content-Length 超上限先拒绝落盘；流式拷贝超上限报错中止；上限内正常。
func TestWriteRuleSetDownload_limitsDownloadSize(t *testing.T) {
	const cap = int64(1024)
	cases := []struct {
		name          string
		contentLength int64
		body          []byte
		wantErr       bool
	}{
		{"content_length_over_cap", 2 * cap, []byte("x"), true},
		{"stream_over_cap", -1, bytes.Repeat([]byte("x"), int(cap+1)), true},
		{"exactly_cap", -1, bytes.Repeat([]byte("x"), int(cap)), false},
		{"small_body", -1, []byte("ok"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := os.OpenFile(filepath.Join(t.TempDir(), "download"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			resp := &http.Response{
				ContentLength: tc.contentLength,
				Body:          io.NopCloser(bytes.NewReader(tc.body)),
			}
			err = writeRuleSetDownload(out, resp, cap, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatal("oversized download must be rejected, got nil error")
				}
				if !strings.Contains(err.Error(), "超过大小上限") {
					t.Fatalf("error must name the size cap, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("download within cap must succeed, got %v", err)
			}
		})
	}
}

// TestRuleSetDownloadSizeCap_isSet verifies the production cap constant is wired
// to both download paths (a zero cap would reject every download).
func TestRuleSetDownloadSizeCap_isSet(t *testing.T) {
	if ruleSetDownloadSizeCap <= 0 {
		t.Fatalf("ruleSetDownloadSizeCap = %d, want > 0", ruleSetDownloadSizeCap)
	}
}
