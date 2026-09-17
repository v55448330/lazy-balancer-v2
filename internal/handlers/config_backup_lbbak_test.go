package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// v2.3.0 lbbak 格式(用户裁定):规则库数据库分类含数据文件本体,纯 JSON 不
// 适合承载——导出为 tar.gz( manifest.json + config.json + waf/* ),逐条目
// sha256 完整性校验;导入后文件与版本记录原子一致。
func unpackLbbak(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("lbbak not gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar entry %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = data
	}
	return out
}

func unpackLbbakJSONTables(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	pack := unpackLbbak(t, raw)
	var cfg struct {
		Tables map[string]any `json:"tables"`
	}
	_ = json.Unmarshal(pack["config.json"], &cfg)
	return cfg.Tables
}

func TestConfigBackup_lbbakRoundTrip(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	// seed 临时 CRS 目录与 xdb(生产路径是容器内绝对路径)
	crsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.29.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "crs-setup.conf"), []byte("# crs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	xdbPath := filepath.Join(t.TempDir(), "ip2region.xdb")
	if err := os.WriteFile(xdbPath, bytes.Repeat([]byte{0xAB}, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := services.OverrideWafLivePathsForTest(crsDir, xdbPath)
	defer restore()
	// 分类导入不动 users:本地需已有管理员(导入后管理员守卫)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}

	// ---- 导出:勾选规则库数据库 → tar.gz 包,含 manifest/config/waf 文件 ----
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=rules,waf_files", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}
	pack := unpackLbbak(t, rec.Body.Bytes())
	manifestRaw, ok := pack["manifest.json"]
	if !ok {
		t.Fatal("lbbak missing manifest.json")
	}
	var manifest struct {
		Format   string            `json:"format"`
		Checksum map[string]string `json:"checksum"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.Format != "lbbak" || len(manifest.Checksum) == 0 {
		t.Fatalf("manifest malformed: %+v", manifest)
	}
	for name, sum := range manifest.Checksum {
		data, exists := pack[name]
		if !exists {
			t.Fatalf("manifest lists %s but pack lacks it", name)
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != sum {
			t.Fatalf("entry %s checksum mismatch", name)
		}
	}
	if _, exists := pack["config.json"]; !exists {
		t.Fatal("lbbak missing config.json")
	}
	if _, exists := pack["waf/crs.tar.gz"]; !exists {
		t.Fatal("lbbak missing waf/crs.tar.gz")
	}
	if _, exists := pack["waf/ip2region.xdb"]; !exists {
		t.Fatal("lbbak missing waf/ip2region.xdb")
	}

	// ---- 导入:.lbbak 整包回放 → 版本记录与文件一致落库 ----
	var dbgAdmins int
	db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND is_enabled=1`).Scan(&dbgAdmins)
	t.Logf("pre-import admins=%d tables_in_pack=%d", dbgAdmins, len(unpackLbbakJSONTables(t, rec.Body.Bytes())))
	req := httptest.NewRequest(http.MethodPost, "/config/import", bytes.NewReader(rec.Body.Bytes()))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec2 := httptest.NewRecorder()
	g.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("import lbbak status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	// 数据文件已落盘(与导出一致)——文件与版本记录原子同批
	if _, err := os.Stat(filepath.Join(crsDir, "rules", "crs-setup.conf")); err != nil {
		t.Fatalf("lbbak import must write CRS files: %v", err)
	}
	got, err := os.ReadFile(xdbPath)
	if err != nil || len(got) != 4096 {
		t.Fatalf("lbbak import must write xdb: err=%v len=%d", err, len(got))
	}

	// ---- 完整性:篡改 config.json → 导入 400 ----
	tampered := bytes.Clone(rec.Body.Bytes())
	// 重打包:同 entries 但 config.json 篡改
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	writeEntry := func(name string, data []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))})
		_, _ = tw.Write(data)
	}
	entries := map[string][]byte{}
	for k, v := range pack {
		entries[k] = v
	}
	entries["config.json"] = []byte(strings.Replace(string(pack["config.json"]), `"version":2`, `"version":9`, 1))
	names := []string{"manifest.json", "config.json", "waf/crs.tar.gz", "waf/ip2region.xdb"}
	for _, n := range names {
		writeEntry(n, entries[n])
	}
	_ = tw.Close()
	_ = gzw.Close()
	tampered = buf.Bytes()
	req = httptest.NewRequest(http.MethodPost, "/config/import", bytes.NewReader(tampered))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec3 := httptest.NewRecorder()
	g.ServeHTTP(rec3, req)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("tampered lbbak status=%d body=%s, want 400", rec3.Code, rec3.Body.String())
	}
}
