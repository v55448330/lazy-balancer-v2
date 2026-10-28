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

func TestConfigBackup_lbbakRoundTrip(t *testing.T) {
	h := newBackupTestHandlers(t)
	t.Cleanup(services.ResetIP2RegionSearcherForTest)
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
	// 导入落盘前校验 xdb 可装载——夹具必须是真实可装载
	// 的 ip2region 库（此前 4096 字节 0xAB 垃圾被当合法文件断言 200）。
	xdbBytes, err := os.ReadFile(filepath.Join("..", "..", "caddygeoip", "testdata", "ip2region_v4.xdb"))
	if err != nil {
		t.Fatalf("read xdb fixture: %v", err)
	}
	if err := os.WriteFile(xdbPath, xdbBytes, 0o644); err != nil {
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
	// 让 live 文件与包内字节不同：若整个导入写入相位被删除，下面的
	// 逐字节断言会红；同哈希 live 文件只能证明「文件本来就在」。
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "crs-setup.conf"), []byte("# live-diverged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xdbPath, []byte("live-diverged"), 0o644); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/config/import", bytes.NewReader(rec.Body.Bytes()))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec2 := httptest.NewRecorder()
	g.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("import lbbak status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	// 数据文件必须从包内字节重新落盘（而非 live 同哈希时假绿）。
	crsBytes, err := os.ReadFile(filepath.Join(crsDir, "rules", "crs-setup.conf"))
	if err != nil || !bytes.Equal(crsBytes, []byte("# crs\n")) {
		t.Fatalf("lbbak import must restore CRS bytes: err=%v content=%q", err, crsBytes)
	}
	got, err := os.ReadFile(xdbPath)
	if err != nil || !bytes.Equal(got, xdbBytes) {
		t.Fatalf("lbbak import must restore exact xdb bytes: err=%v equal=%v", err, bytes.Equal(got, xdbBytes))
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
	entries["config.json"] = []byte(strings.Replace(string(pack["config.json"]), `"version":3`, `"version":9`, 1))
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

func TestConfigBackup_exportUsesSingletonGlobalConfigRow(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`PRAGMA ignore_check_constraints=ON;
		DELETE FROM global_config WHERE id=1;
		INSERT INTO global_config (id,log_level) VALUES (-1,'warn');
		INSERT INTO global_config (id,log_level) VALUES (1,'info');
		PRAGMA ignore_check_constraints=OFF;`); err != nil {
		t.Fatalf("seed out-of-band duplicate global_config rows: %v", err)
	}
	router := newBackupSectionRouter(h)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/config/export?sections=users", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	pack := unpackLbbak(t, recorder.Body.Bytes())
	var exported struct {
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(pack["config.json"], &exported); err != nil {
		t.Fatal(err)
	}
	if got := exported.Config["log_level"]; got != "info" {
		t.Fatalf("导出 global_config 行 log_level=%v, want 唯一事实行 id=1 的 info", got)
	}
}
