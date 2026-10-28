package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// cert_jobs.expires_at 在两条证书清单端点（/certificates 聚合清单与
// /certificates/jobs 任务列表）必须走**同一套**解析：任务列表由驱动把
// DATETIME 列扫描成时间值，聚合清单曾把同一列当字符串、只认两个硬编码布局，
// 带小数秒/其它合法形态的值会静默回落 PEM 或 null——同一任务的到期时刻在两个
// 入口给出不同结论（MCP list_certificates 消费方结论分叉）。
// 本用例植入「非空但非 canonical 形态」的库值，断言两端点 not_after 一致。
func TestListCertificates_expiresAtParseMatchesCertJobs(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 证书 PEM 的到期时间与库值刻意不同：只要聚合清单回落 PEM，两端点就会分叉。
	pemNotAfter := time.Now().UTC().Add(720 * time.Hour).Truncate(time.Second)
	certPEM, keyPEM, err := generateTestCert("offset-expiry.test", time.Now().Add(-time.Hour), pemNotAfter)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	// 带时区偏移的库值：驱动侧的 DATETIME 解析（与任务列表同一机制）接受
	// 「2006-01-02 15:04:05-07:00」形态；聚合清单的手工布局表只有
	// "2006-01-02 15:04:05" 与 RFC3339（要求 T 分隔）——偏移形态匹配不上，
	// 于是静默回落 PEM 派生值。（小数秒两侧都能解析，不能作为分叉样本。）
	libraryExpiry := time.Date(2027, time.January, 1, 19, 4, 5, 0, time.UTC)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, expires_at)
		VALUES ('lb_cert_offset','offset-expiry.test','issued',?,?,'2027-01-02 03:04:05+08:00')`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed offset expiry row: %v", err)
	}

	aggregate := fetchCertificateNotAfter(t, h, "/certificates?page_size=100", "certificates")
	jobs := fetchCertificateNotAfter(t, h, "/certificates/jobs?page_size=100", "list")

	aggregateNotAfter, ok := aggregate["lb_cert_offset"]
	if !ok || aggregateNotAfter == nil {
		t.Fatalf("/certificates 未给出 not_after: %+v", aggregate)
	}
	jobsNotAfter, ok := jobs["lb_cert_offset"]
	if !ok || jobsNotAfter == nil {
		t.Fatalf("/certificates/jobs 未给出 not_after: %+v", jobs)
	}
	aggregateTime, err := time.Parse(time.RFC3339Nano, *aggregateNotAfter)
	if err != nil {
		t.Fatalf("聚合清单 not_after=%q 无法解析: %v", *aggregateNotAfter, err)
	}
	jobsTime, err := time.Parse(time.RFC3339Nano, *jobsNotAfter)
	if err != nil {
		t.Fatalf("任务列表 not_after=%q 无法解析: %v", *jobsNotAfter, err)
	}
	// 两端点必须给出同一时刻，且该时刻来自库值（不是 PEM 派生值）。
	if !aggregateTime.Equal(jobsTime) {
		t.Fatalf("同一任务两条清单端点 not_after 分叉：/certificates=%v /certificates/jobs=%v", aggregateTime, jobsTime)
	}
	if !aggregateTime.Equal(libraryExpiry) {
		t.Fatalf("not_after=%v, want 库值 expires_at=%v（不得回落 PEM 派生 %v）", aggregateTime, libraryExpiry, pemNotAfter)
	}
}

// 同一 cert_jobs 坏行（列类型漂移/带外改库）在两条清单端点必须同语义：
// 任务列表读失败即 500，聚合清单曾静默跳过该行并继续（total 仍按 COUNT(*)
// 计入 → 翻页集合与 total 不闭合，且运维只能从应用日志发现）。
// 统一为 fail-visible：两端点都返回 500 且文案一致。
func TestListCertificates_rowScanFailureMatchesCertJobs(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 驱动把 DATETIME 文本解析为时间；无法解析的形态会让 NullTime 扫描失败，
	// 这正是「单行读失败」在两条端点上的同一触发点。
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, expires_at)
		VALUES ('lb_cert_bad_row','bad-row.test','issued','','','not-a-timestamp')`); err != nil {
		t.Fatalf("seed unparsable expiry row: %v", err)
	}
	// 对照行：健康行不得让坏行的影响被掩盖（两端点都应整体失败）。
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, expires_at)
		VALUES ('lb_cert_ok_row','ok-row.test','issued','','','2027-01-02 03:04:05')`); err != nil {
		t.Fatalf("seed healthy row: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/certificates", h.ListCertificates)
	router.GET("/certificates/jobs", h.ListCertJobs)

	aggregateRec := httptest.NewRecorder()
	router.ServeHTTP(aggregateRec, httptest.NewRequest(http.MethodGet, "/certificates?page_size=100", nil))
	jobsRec := httptest.NewRecorder()
	router.ServeHTTP(jobsRec, httptest.NewRequest(http.MethodGet, "/certificates/jobs?page_size=100", nil))

	if jobsRec.Code != http.StatusInternalServerError {
		t.Fatalf("/certificates/jobs status=%d, want 500（坏行必须 fail-visible）: %s", jobsRec.Code, jobsRec.Body.String())
	}
	if aggregateRec.Code != http.StatusInternalServerError {
		t.Fatalf("/certificates status=%d, want 500（与 /certificates/jobs 同语义，不得静默丢行）: %s", aggregateRec.Code, aggregateRec.Body.String())
	}
	var aggregateResp, jobsResp models.APIResponse
	if err := json.Unmarshal(aggregateRec.Body.Bytes(), &aggregateResp); err != nil {
		t.Fatalf("decode /certificates body: %v", err)
	}
	if err := json.Unmarshal(jobsRec.Body.Bytes(), &jobsResp); err != nil {
		t.Fatalf("decode /certificates/jobs body: %v", err)
	}
	if aggregateResp.Message != jobsResp.Message {
		t.Fatalf("坏行文案分叉：/certificates=%q /certificates/jobs=%q", aggregateResp.Message, jobsResp.Message)
	}
	// 5xx 响应不得回显底层错误原文（脱敏契约）。
	if body := aggregateRec.Body.String(); strings.Contains(body, "not-a-timestamp") {
		t.Fatalf("/certificates 5xx 回显了底层错误原文: %s", body)
	}
}

// fetchCertificateNotAfter 请求一条证书清单端点，返回 ruleID → not_after 映射。
func fetchCertificateNotAfter(t *testing.T, h *Handlers, target, dataKey string) map[string]*string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	switch dataKey {
	case "certificates":
		router.GET("/certificates", h.ListCertificates)
	default:
		router.GET("/certificates/jobs", h.ListCertJobs)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s status=%d body=%s", target, rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Certificates []struct {
				RuleID   string  `json:"rule_id"`
				NotAfter *string `json:"not_after"`
			} `json:"certificates"`
			List []struct {
				RuleID   string  `json:"rule_id"`
				NotAfter *string `json:"not_after"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s: %v", target, err)
	}
	out := map[string]*string{}
	for _, cert := range resp.Data.Certificates {
		out[cert.RuleID] = cert.NotAfter
	}
	for _, job := range resp.Data.List {
		out[job.RuleID] = job.NotAfter
	}
	return out
}
