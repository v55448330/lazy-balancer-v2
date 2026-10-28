package handlers

//   审计下拉单行 Scan 失败必须与查询/迭代失败同按故障轮处理
//     （partial=true 且不写 60s 缓存）；
//   /logs/stats 的阈值读取收窄到一次并按 want 门控（结构门——
//     任务循环曾逐任务重复读同一 task_log_size_mb 列）；
//   证书有 SAN 时不得回退 CN（现代客户端以 SAN 为准）；
//   DNS 服务器多冒号畸形地址不得回落「含点即 FQDN」；
//   /metrics/history 空结果必须是 []（不是 null）；
//   admin-only 写端点的 403 权限分支必须进 OpenAPI；
//   dirBytes 与 aggregateDirStats 两套轮转分类器同输入必须等价；
//   queryRowsAsMaps 的迭代错误必须携带表/快照 label。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"math/big"
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

// 审计下拉单行 Scan 失败 ----

type auditScanFailConnector struct{ match func(string) bool }

func (c auditScanFailConnector) Connect(context.Context) (driver.Conn, error) {
	return &auditScanFailConn{match: c.match}, nil
}
func (auditScanFailConnector) Driver() driver.Driver { return auditScanFailDriver{} }

type auditScanFailDriver struct{}

func (auditScanFailDriver) Open(string) (driver.Conn, error) { return &auditScanFailConn{}, nil }

type auditScanFailConn struct{ match func(string) bool }

func (c *auditScanFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *auditScanFailConn) Close() error              { return nil }
func (c *auditScanFailConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }
func (c *auditScanFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if c.match != nil && c.match(query) {
		return &auditScanFailRows{cols: []string{"value", "cnt"}}, nil
	}
	return &auditScanFailRows{cols: []string{"value", "cnt"}, empty: true}, nil
}

type auditScanFailRows struct {
	cols  []string
	empty bool
	done  bool
}

func (r *auditScanFailRows) Columns() []string { return r.cols }
func (r *auditScanFailRows) Close() error      { return nil }
func (r *auditScanFailRows) Next(dest []driver.Value) error {
	if r.empty || r.done {
		return io.EOF
	}
	r.done = true
	// 只填第一列：COUNT(*) 目标保持 nil → database/sql 在 Scan 时即失败
	// （与 rows.Err 迭代失败是不同形状）。
	dest[0] = "scan-fail-user"
	return nil
}

func TestAuditLogOptions_scanErrorRoundDoesNotPoisonCache(t *testing.T) {
	router, _ := newAuditLogRouter(t)
	t.Cleanup(resetAuditOptionsCacheForTest)
	resetAuditOptionsCacheForTest()

	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('scan-recover-user', '登录', '用户认证', '', '1.1.1.1')`); err != nil {
		t.Fatal(err)
	}
	buf := captureLog(t)
	get := func() ([]string, bool) {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs/options", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("options status=%d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				Partial   bool `json:"partial"`
				Usernames []struct {
					Value string `json:"value"`
				} `json:"usernames"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, u := range resp.Data.Usernames {
			out = append(out, u.Value)
		}
		return out, resp.Data.Partial
	}

	healthy := db.AuditDB
	broken := sql.OpenDB(auditScanFailConnector{match: func(q string) bool { return strings.Contains(q, "GROUP BY") }})
	t.Cleanup(func() { _ = broken.Close() })
	db.AuditDB = broken
	first, partial := get()
	db.AuditDB = healthy
	if !partial {
		t.Fatal("Scan 失败轮必须标记 partial=true")
	}
	if len(first) != 0 {
		t.Fatalf("Scan 失败轮应返回空选项, got %v", first)
	}
	if !strings.Contains(buf.String(), "行扫描失败") {
		t.Fatalf("Scan 失败须 warn 留痕, log=%q", buf.String())
	}
	if !strings.Contains(buf.String(), "审计日志下拉") {
		t.Fatalf("warn 须带分类标签, log=%q", buf.String())
	}

	// 60s 窗口内：Scan 失败轮不得写缓存，第二次必须读到真实数据。
	second, _ := get()
	found := false
	for _, v := range second {
		if v == "scan-recover-user" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Scan 失败轮毒化缓存：第二次 options 须重新拉取真实数据, got %v", second)
	}
}

// SAN 优先于 CN ----

func TestTLSCertCoversDomain_sanTakesPrecedenceOverCN(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cn.example.test"},
		DNSNames:     []string{"san.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCertCoversDomain(leaf, "cn.example.test") {
		t.Fatal("证书有 SAN 且 SAN 不覆盖时不得回退 CN（现代客户端以 SAN 为准）")
	}
	if !tlsCertCoversDomain(leaf, "san.example.test") {
		t.Fatal("SAN 覆盖的域名必须通过")
	}

	// 回归形状：无 SAN 的老证书仍回退 CN。
	legacy := &x509.Certificate{Subject: pkix.Name{CommonName: "legacy.example.test"}}
	if !tlsCertCoversDomain(legacy, "legacy.example.test") {
		t.Fatal("无 SAN 的老证书必须回退 CN 精确匹配")
	}
	legacyWildcard := &x509.Certificate{Subject: pkix.Name{CommonName: "*.example.test"}}
	if !tlsCertCoversDomain(legacyWildcard, "a.example.test") {
		t.Fatal("无 SAN 的老证书必须回退 CN 单段通配")
	}
}

// DNS 服务器畸形冒号地址 ----

func TestValidateDnsServerShape_rejectsMalformedColonAddresses(t *testing.T) {
	valid := []string{
		"8.8.8.8", "8.8.8.8:53", "dns.example.com", "dns.example.com:53",
		"localhost", "localhost:53", "[2001:db8::1]:53", "2001:db8::1", "[2001:db8::1]",
	}
	for _, raw := range valid {
		if err := validateDnsServerShape(raw); err != nil {
			t.Errorf("validateDnsServerShape(%q) = %v, want nil", raw, err)
		}
	}
	invalid := []string{
		"bad.example.com:80:90", "1.2.3.4:80:90", "8.8.8.8:", ":53",
		"[2001:db8::1", "8.8.8.8:53:extra", "2001:db8::1:53:extra",
	}
	for _, raw := range invalid {
		if err := validateDnsServerShape(raw); err == nil {
			t.Errorf("validateDnsServerShape(%q) = nil, want error（多冒号/空端口畸形不得回落含点即 FQDN）", raw)
		}
	}
}

// /metrics/history 空结果数组形状 ----

func TestGetMetricsHistory_emptyResultIsEmptyArray(t *testing.T) {
	newMetricsTestDatabase(t)
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics/history", h.GetMetricsHistory)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics/history", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if got := strings.TrimSpace(string(resp.Data)); got != "[]" {
		t.Fatalf("空结果 data=%s, want []（同族列表端点契约）", got)
	}
}

// OpenAPI 403 权限分支 ----

func TestAPIDocRoutes_documentAdminWriteForbidden(t *testing.T) {
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}
	for _, key := range []string{"POST /admin-tls/inspect", "PUT /ca-providers/:id"} {
		route, ok := routes[key]
		if !ok {
			t.Fatalf("%s 未登记 OpenAPI", key)
		}
		if !containsRouteError(route.Errors, "403") {
			t.Errorf("%s errors=%v, want 403（非管理员写面拒绝）", key, route.Errors)
		}
	}
}

// 两套轮转分类器同输入等价 ----

func TestDirBytes_MatchesAggregateDirStatsForRotationFamilies(t *testing.T) {
	dir := t.TempDir()
	files := map[string]int{
		"caddy.log":                               200,
		"caddy.log.1":                             10,
		"caddy.log.2":                             20,
		"caddy.log.20260921-120000":               30,
		"caddy-20260921T120000-1048576-size.log":  40,
		"caddy-20260920T115900-2048-size.log.gz":  50,
		"caddy-tls.log":                           300,
		"caddy-tls-20260921T120000-4096-size.log": 60,
	}
	for name, size := range files {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aggregate := aggregateDirStatsWithEntries(dir, nil, caddyLogFamilyMatch)
	for _, base := range []string{"caddy.log", "caddy-tls.log"} {
		active, rotated, count := dirBytesWithEntries(filepath.Join(dir, base), nil)
		st := aggregate[base]
		if active != st.Active || rotated != st.Rotated || count != st.RotCount {
			t.Fatalf("%s: dirBytes=(%d,%d,%d) aggregate=(%d,%d,%d)——两套分类器分叉",
				base, active, rotated, count, st.Active, st.Rotated, st.RotCount)
		}
	}
}

// /logs/stats 阈值读取收窄（结构门） ----

func TestGetLogStats_thresholdReadsHoistedAndGated(t *testing.T) {
	raw, err := os.ReadFile("logstats.go")
	if err != nil {
		t.Fatalf("read logstats.go: %v", err)
	}
	source := string(raw)
	start := strings.Index(source, "func (h *Handlers) GetLogStats(c *gin.Context) {")
	if start < 0 {
		t.Fatal("GetLogStats 未找到")
	}
	body := source[start:]
	for _, column := range []string{"task_log_size_mb", "caddy_log_size_mb", "runtime_log_size_mb", "audit_log_size_mb"} {
		if got := strings.Count(body, `sizeLimitMB("`+column+`"`); got != 1 {
			t.Errorf(`sizeLimitMB(%q) 在 GetLogStats 内出现 %d 次, want 1（阈值须读出循环且按 want 门控）`, column, got)
		}
	}
	if strings.Contains(body, "LimitBytes: sizeLimitMB(") {
		t.Error("静态行仍无条件计算阈值——须按 want 门控（弹框只取单行时不得读全部阈值）")
	}
}

// queryRowsAsMaps 错误 label ----

type rowIterErrConnector struct{}

func (rowIterErrConnector) Connect(context.Context) (driver.Conn, error) {
	return rowIterErrConn{}, nil
}
func (rowIterErrConnector) Driver() driver.Driver { return rowIterErrDriver{} }

type rowIterErrDriver struct{}

func (rowIterErrDriver) Open(string) (driver.Conn, error) { return rowIterErrConn{}, nil }

type rowIterErrConn struct{}

func (rowIterErrConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (rowIterErrConn) Close() error              { return nil }
func (rowIterErrConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }
func (rowIterErrConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return rowIterErrRows{cols: []string{"c"}}, nil
}

type rowIterErrRows struct {
	cols []string
}

func (r rowIterErrRows) Columns() []string { return r.cols }
func (rowIterErrRows) Close() error        { return nil }
func (rowIterErrRows) Next([]driver.Value) error {
	return errors.New("注入的行迭代失败")
}

func TestQueryRowsAsMaps_wrapsIterationErrorWithLabel(t *testing.T) {
	database := sql.OpenDB(rowIterErrConnector{})
	defer database.Close()
	_, err := queryRowsAsMaps(context.Background(), database, rowQuery{label: "表 demo_rows", query: "SELECT 1"})
	if err == nil {
		t.Fatal("迭代失败必须返回 error")
	}
	if !strings.Contains(err.Error(), "表 demo_rows") {
		t.Fatalf("error=%q, want 携带表/snapshot label（与 Query/Scan 分支同口径）", err.Error())
	}
	if !strings.Contains(err.Error(), "注入的行迭代失败") {
		t.Fatalf("error=%q, want 保留底层原因（%%w 包装）", err.Error())
	}
}

// finishTxApply 两条 commit 失败分支的已提交视图恢复 ----

func TestFinishTxApplyCommitFailureBranchesRestoreCommittedView(t *testing.T) {
	raw, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("read handlers.go: %v", err)
	}
	source := string(raw)
	start := strings.Index(source, "func (h *Handlers) finishTxApply(c *gin.Context, tx *sql.Tx, f txApplyFinish) {")
	if start < 0 {
		t.Fatal("finishTxApply 未找到")
	}
	body := source[start:]
	if end := strings.Index(body, "\nfunc (h *Handlers) reloadDetailFor("); end > 0 {
		body = body[:end]
	}
	// 提交入口是测试缝单源 commitTx(tx)（txCommitForTest 注入）；两形态都必须
	// 走该入口，否则提交失败分支不可钉测。两种等价写法都认，避免换入口即假红。
	needles := []string{"if err := commitTx(tx); err != nil {", "if err := tx.Commit(); err != nil {"}
	branches := 0
	searchFrom := 0
	for {
		nextIndex, nextLen := -1, 0
		for _, needle := range needles {
			if index := strings.Index(body[searchFrom:], needle); index >= 0 && (nextIndex < 0 || index < nextIndex) {
				nextIndex, nextLen = index, len(needle)
			}
		}
		if nextIndex < 0 {
			break
		}
		branchStart := searchFrom + nextIndex
		searchFrom = branchStart + nextLen
		branches++
		// 分支体在收口重构后变长（recovery 两通道 + joined + 审计/响应），
		// 窗口按「到下一个 commit 分支或文件尾」取整段，不做定长截断。
		windowEnd := len(body)
		for _, needle := range needles {
			if index := strings.Index(body[searchFrom:], needle); index >= 0 && searchFrom+index < windowEnd {
				windowEnd = searchFrom + index
			}
		}
		window := body[branchStart:windowEnd]
		if !strings.Contains(window, "recoverCommittedViewAfterCommitFailure(tx)") {
			t.Errorf("第 %d 个 commit 失败分支缺少已提交视图恢复（运行配置/LKG/投影须同口径回退）", branches)
		}
		if !strings.Contains(window, "recordPostCommitRestoreFailure(") {
			t.Errorf("第 %d 个 commit 失败分支缺少提交后失败横幅写点（对象=提交、两通道分离）", branches)
		}
	}
	if branches != 2 {
		t.Fatalf("finishTxApply commit 失败分支=%d, want 2（apply 成功与退化提交两形态）", branches)
	}
	// 成功链只经 reloadNote 清除一次 caddy_apply_error。
	if got := strings.Count(body, "recordCaddyApplyResult(nil)"); got != 0 {
		t.Errorf("finishTxApply 内重复清除 caddy_apply_error %d 处（reloadNote 已覆盖成功/同字节两形态）", got)
	}
	if !strings.Contains(body, "reloadNote.finalize()") {
		t.Error("finishTxApply 成功链缺少 reloadNote.finalize()（重载审计/横幅清除的唯一收口）")
	}
}

// 行为：提交失败的统一恢复必须回滚事务、把运行配置 /load 回已提交
// 视图、并把 last-known-good 从「未提交内容」写回已提交视图字节。
func TestRecoverCommittedViewAfterCommitFailureRestoresRuntimeAndLKG(t *testing.T) {
	h := newBackupTestHandlers(t)
	rec := &fakeCaddyRecorder{}
	fake := newFakeCaddyServer(t, rec)
	h.caddyService = services.NewCaddyService(fake.URL)
	lkgPath := filepath.Join(t.TempDir(), "last-good.json")
	h.caddyService.SetLastGoodPath(lkgPath)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		VALUES ('lb_committed','committed','http','committed.example.test',18431,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_committed','10.1.1.1',18431,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if _, err := tx.Exec(`UPDATE lb_rules SET domain='uncommitted.example.test' WHERE caddy_id='lb_committed'`); err != nil {
		t.Fatalf("tx update: %v", err)
	}
	// 事务内 apply 成功时的 LKG（持久化发生在每次成功 /load 之后）。
	if err := os.WriteFile(lkgPath, []byte(`{"apps":{"uncommitted":true}}`), 0o600); err != nil {
		t.Fatalf("seed lkg: %v", err)
	}

	if recovery := h.recoverCommittedViewAfterCommitFailure(tx); recovery.err() != nil {
		t.Fatalf("恢复失败: %v", recovery.err())
	}
	if err := tx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("恢复后未提交事务必须已回滚, Rollback err=%v", err)
	}
	var domain string
	if err := db.DB.QueryRow(`SELECT domain FROM lb_rules WHERE caddy_id='lb_committed'`).Scan(&domain); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if domain != "committed.example.test" {
		t.Fatalf("未提交事务未回滚: domain=%q", domain)
	}
	if len(rec.loads) == 0 {
		t.Fatal("提交失败后必须重渲染并 /load 已提交视图")
	}
	last := rec.loads[len(rec.loads)-1]
	if !strings.Contains(last, "committed.example.test") {
		t.Fatalf("恢复 /load 未包含已提交内容: %s", last)
	}
	if strings.Contains(last, "uncommitted.example.test") {
		t.Fatalf("恢复 /load 仍含未提交内容: %s", last)
	}
	lkg, err := os.ReadFile(lkgPath)
	if err != nil {
		t.Fatalf("read lkg: %v", err)
	}
	if !strings.Contains(string(lkg), "committed.example.test") || strings.Contains(string(lkg), "uncommitted") {
		t.Fatalf("LKG 未回退到已提交视图: %s", lkg)
	}
}
