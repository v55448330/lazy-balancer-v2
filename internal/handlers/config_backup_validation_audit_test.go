package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 事务前失败面必须有审计：篡改/损坏备份被拒绝时，操作审计页要能看到
// 尝试（此前这些分支直接 400 早退，事故复盘只能翻 stdout）。
func TestImportConfigBackup_preTransactionFailuresAreAudited(t *testing.T) {
	h := newBackupTestHandlers(t)
	countImportFailureAudits := func() int {
		t.Helper()
		var count int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='导入失败' AND resource='配置备份'`).Scan(&count); err != nil {
			t.Fatalf("count import failure audits: %v", err)
		}
		return count
	}
	assertLatestFailureDetail := func(recorderBody []byte) {
		t.Helper()
		var response struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(recorderBody, &response); err != nil {
			t.Fatalf("decode failure response: %v", err)
		}
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='导入失败' AND resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatalf("read latest failure audit: %v", err)
		}
		if detail == "" || detail != response.Message {
			t.Fatalf("失败审计 detail=%q 与本次响应 message=%q 不一致（累计计数无法归因形状）", detail, response.Message)
		}
	}

	// When：损坏的 lbbak（gzip 魔数但不完整）
	corrupt := string([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00})
	rec := importBackupShared(h, t, corrupt)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("corrupt lbbak status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if got := countImportFailureAudits(); got != 1 {
		t.Fatalf("audit rows=%d after corrupt lbbak, want 1", got)
	}
	assertLatestFailureDetail(rec.Body.Bytes())

	// When：JSON 绑定失败（非对象载荷）
	rec = importBackupShared(h, t, `[1,2,3]`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json shape status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if got := countImportFailureAudits(); got != 2 {
		t.Fatalf("audit rows=%d after bind failure, want 2", got)
	}
	assertLatestFailureDetail(rec.Body.Bytes())

	// When：校验链失败（校验和不匹配）
	body := legacyBackupJSON(t, nil, map[string]any{}, nil)
	tampered := strings.Replace(body, `"app":"lazy-balancer-v2"`, `"app":"lazy-balancer-v3"`, 1)
	rec = importBackupShared(h, t, tampered)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("checksum mismatch status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if got := countImportFailureAudits(); got != 3 {
		t.Fatalf("audit rows=%d after checksum mismatch, want 3", got)
	}
	assertLatestFailureDetail(rec.Body.Bytes())

	// When：空请求体（被拒绝的导入尝试，端点侧 read 前置门）
	rec = importBackupShared(h, t, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if got := countImportFailureAudits(); got != 4 {
		t.Fatalf("audit rows=%d after empty body, want 4", got)
	}
	assertLatestFailureDetail(rec.Body.Bytes())
}

// http 三超时只有一个导入门：负值与 0 同口径归治理默认并留审计，
// 不再先被 400 拒绝（两道门对同一输入给出相反结论）。
func TestImportConfigBackup_negativeHTTPTimeoutNormalizedNotRejected(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := legacyBackupJSON(t, nil, map[string]any{"http_read_timeout": -5, "http_idle_timeout": 0}, nil)
	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（负值/0 由导入钳制归默认）", rec.Code, rec.Body.String())
	}
	var readTimeout, idleTimeout int
	if err := db.DB.QueryRow("SELECT http_read_timeout, http_idle_timeout FROM global_config WHERE id=1").Scan(&readTimeout, &idleTimeout); err != nil {
		t.Fatalf("read imported timeouts: %v", err)
	}
	if readTimeout != db.DefaultHTTPReadTimeout || idleTimeout != db.DefaultHTTPIdleTimeout {
		t.Fatalf("timeouts=(%d,%d), want 治理默认 (%d,%d)", readTimeout, idleTimeout, db.DefaultHTTPReadTimeout, db.DefaultHTTPIdleTimeout)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='导入' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read import audit: %v", err)
	}
	if !strings.Contains(detail, "http_read_timeout") || !strings.Contains(detail, "http_idle_timeout") {
		t.Fatalf("import audit detail=%q, want 归一留痕（http_read_timeout/http_idle_timeout）", detail)
	}
}
