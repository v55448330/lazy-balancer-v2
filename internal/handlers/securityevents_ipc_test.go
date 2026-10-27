package handlers

// 安全事件 IPC 服务端（B 形态主路径）的 handlers 侧验收：
//   - POST 204 后 DB 有行、重复 transaction_id 去重；
//   - DB 错误返回 5xx（写侧据此保留 spool）；超限 body 413；方法与路径守卫；
//   - 真实 UDS：socket 权限 0600、端点可达、关停后 socket 文件清除；
//   - /logs/stats 的 security_events 行下发 cache_*（待补采 spool）口径。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// securityEventsIPCTestLine 构造一行写侧形态的 audit JSON。
func securityEventsIPCTestLine(txID, clientIP string, blocked bool, ts int64) string {
	return fmt.Sprintf(`{"transaction":{"unix_timestamp":%d,"id":%q,"client_ip":%q,"server_id":"example.com","request":{"method":"GET","uri":"/ipc","headers":{"host":["example.com"]}},"is_interrupted":%t},"messages":[{"message":"rule","data":{"id":"942100","raw":"SecRule"}}]}`,
		ts, txID, clientIP, blocked)
}

func securityEventsIPCRowCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&n); err != nil {
		t.Fatalf("count security_events: %v", err)
	}
	return n
}

func postSecurityEventsBatch(t *testing.T, h *SecurityEventsIPCServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	return rec
}

func TestSecurityEventsIPCHandler_returns204OnlyAfterCommitAndDedupes(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	h := &SecurityEventsIPCServer{}
	body := securityEventsIPCTestLine("tx-ipc-h1", "198.51.100.10", false, 1786447200) + "\n" +
		securityEventsIPCTestLine("tx-ipc-h2", "198.51.100.11", true, 1786447201) + "\n"

	rec := postSecurityEventsBatch(t, h, body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s, want 204", rec.Code, rec.Body.String())
	}
	if got := securityEventsIPCRowCount(t); got != 2 {
		t.Fatalf("rows=%d, want 2（204 必须代表 commit 完成后的可见行）", got)
	}
	if got := rec.Header().Get("X-Lb-Security-Events-Ingested"); got != "2" {
		t.Fatalf("ingested header=%q, want 2", got)
	}

	// 写侧重试/补采重放同一批：仍 204，但 transaction_id 去重不新增行。
	rec = postSecurityEventsBatch(t, h, body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("replay status=%d, want 204", rec.Code)
	}
	if got := securityEventsIPCRowCount(t); got != 2 {
		t.Fatalf("rows after replay=%d, want 2", got)
	}
}

func TestSecurityEventsIPCHandler_dbErrorReturns5xx(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	h := &SecurityEventsIPCServer{}
	closed := db.MetricsDB
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	rec := postSecurityEventsBatch(t, h, securityEventsIPCTestLine("tx-ipc-fail", "198.51.100.20", false, 1786447202)+"\n")
	if rec.Code < 500 || rec.Code > 599 {
		t.Fatalf("status=%d body=%s, want 5xx（写侧据此保留 spool）", rec.Code, rec.Body.String())
	}
}

func TestSecurityEventsIPCHandler_rejectsOversizeAndBadRequests(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	h := &SecurityEventsIPCServer{}
	oversize := strings.Repeat("x", int(services.SecurityEventsIPCMaxBodyBytes())+1)
	rec := postSecurityEventsBatch(t, h, oversize)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status=%d, want 413（4xx=不可入库，写侧不 spool）", rec.Code)
	}

	// 方法守卫：GET 不可入库。
	req := httptest.NewRequest(http.MethodGet, services.SecurityEventsIPCIngestPath, nil)
	rec = httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status=%d, want 405", rec.Code)
	}

	// 路径守卫：最小暴露面（只接受契约端点）。
	req = httptest.NewRequest(http.MethodPost, "/other", strings.NewReader(""))
	rec = httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("other path status=%d, want 404", rec.Code)
	}

	// 空 body：无事可做，仍 204（写侧不会为空批产生 spool）。
	rec = postSecurityEventsBatch(t, h, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("empty body status=%d, want 204", rec.Code)
	}
}

func TestStartSecurityEventsIPCServer_servesOverUnixSocketWith0600(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	// UDS 的 sun_path 有长度上限（macOS 104 字节）：t.TempDir() 的路径过长会
	// 让 bind 报 invalid argument，故用短前缀目录。
	sockDir, err := os.MkdirTemp("/tmp", "lbsock")
	if err != nil {
		t.Fatalf("create short socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "security-events.sock")
	t.Setenv(services.SecurityEventsIPCSocketEnv, sockPath)
	server, err := StartSecurityEventsIPCServer()
	if err != nil {
		t.Fatalf("start IPC server: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	})

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("socket not created: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode=%v, want unix socket", info.Mode())
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket perm=%o, want 600（仅本机同用户可写）", perm)
	}

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sockPath)
		},
	}}
	body := securityEventsIPCTestLine("tx-uds-1", "198.51.100.30", false, 1786447203) + "\n"
	resp, err := client.Post("http://unix"+services.SecurityEventsIPCIngestPath, "application/x-ndjson", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post over unix socket: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d, want 204", resp.StatusCode)
	}
	if got := securityEventsIPCRowCount(t); got != 1 {
		t.Fatalf("rows=%d, want 1", got)
	}

	// 关停后 socket 文件必须清除（陈旧 socket 会让下次启动的 Listen 失败前
	// 先被判为占用）。
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Stop(ctx); err != nil {
		t.Fatalf("stop IPC server: %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket 文件应在关停后移除: %v", err)
	}
}

func TestGetLogStats_securityEventsRow_reportsSpoolCache(t *testing.T) {
	h := newBackupTestHandlers(t)
	dataDir := t.TempDir()
	h.cfg.DataDir = dataDir
	oldWafLog := wafAuditLogFile
	wafAuditLogFile = filepath.Join(dataDir, "logs", "waf-audit", "audit.log")
	t.Cleanup(func() { wafAuditLogFile = oldWafLog })
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	t.Cleanup(func() {
		if db.MetricsDB != nil {
			_ = db.MetricsDB.Close()
		}
		db.MetricsDB = nil
	})

	spoolDir := filepath.Join(dataDir, "security-events-spool")
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(services.SecurityEventsSpoolDirEnv, spoolDir)
	t.Setenv(services.SecurityEventsSpoolMaxEntriesEnv, "100")
	t.Setenv(services.SecurityEventsSpoolMaxBytesEnv, "65536")
	services.ResetSecurityEventsSpoolStateForTest()
	t.Cleanup(services.ResetSecurityEventsSpoolStateForTest)
	// 2 条待补采（IPC 主路径失败的残留）+ 1 个空 sealed 文件。
	if err := os.WriteFile(filepath.Join(spoolDir, "sealed-1700000000000000001.jsonl"),
		[]byte(securityEventsIPCTestLine("tx-cache-1", "198.51.100.40", false, 1786447300)+"\n"+
			securityEventsIPCTestLine("tx-cache-2", "198.51.100.41", true, 1786447301)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, "sealed-1700000000000000002.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats?key=security_events", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Logs []struct {
				Key               string `json:"key"`
				Rows              *int64 `json:"rows"`
				LimitRows         *int64 `json:"limit_rows"`
				DBBytes           *int64 `json:"db_bytes"`
				CacheEntries      *int64 `json:"cache_entries"`
				CacheBytes        *int64 `json:"cache_bytes"`
				CacheLimitEntries *int64 `json:"cache_limit_entries"`
				CacheLimitBytes   *int64 `json:"cache_limit_bytes"`
				CacheUnavailable  bool   `json:"cache_unavailable"`
				RowsUnavailable   bool   `json:"rows_unavailable"`
			} `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Logs) != 1 || resp.Data.Logs[0].Key != "security_events" {
		t.Fatalf("logs=%+v, want exactly security_events row", resp.Data.Logs)
	}
	row := resp.Data.Logs[0]
	// 主容量口径：库内行数/行帽 + 库容量。
	if row.Rows == nil || row.RowsUnavailable {
		t.Fatalf("rows=%v, want 可读计数", row.Rows)
	}
	if row.LimitRows == nil || *row.LimitRows <= 0 {
		t.Fatalf("limit_rows=%v, want 行帽", row.LimitRows)
	}
	if row.DBBytes == nil || *row.DBBytes <= 0 {
		t.Fatalf("db_bytes=%v, want >0", row.DBBytes)
	}
	// 缓存口径（待补采 spool）：entries=2（空文件不计），bytes>0，上限来自 env。
	if row.CacheUnavailable {
		t.Fatal("cache_unavailable=true, want 可读")
	}
	if row.CacheEntries == nil || *row.CacheEntries != 2 {
		t.Fatalf("cache_entries=%v, want 2", row.CacheEntries)
	}
	if row.CacheBytes == nil || *row.CacheBytes <= 0 {
		t.Fatalf("cache_bytes=%v, want >0", row.CacheBytes)
	}
	if row.CacheLimitEntries == nil || *row.CacheLimitEntries != 100 {
		t.Fatalf("cache_limit_entries=%v, want 100", row.CacheLimitEntries)
	}
	if row.CacheLimitBytes == nil || *row.CacheLimitBytes != 65536 {
		t.Fatalf("cache_limit_bytes=%v, want 65536", row.CacheLimitBytes)
	}
}
