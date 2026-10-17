package caddygeoip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// plugintypesConfigFor 构造指向 path 的审计写插件配置（JSON 格式）。
func plugintypesConfigFor(t *testing.T, path string) plugintypes.AuditLogConfig {
	t.Helper()
	return plugintypes.AuditLogConfig{Target: path, FileMode: 0o644, Formatter: jsonFormatterForTest{}}
}

// jsonFormatterForTest 复用 coraza 内置 JSON 格式化器形态（顶层单行 JSON 对象）。
type jsonFormatterForTest struct{}

func (jsonFormatterForTest) Format(al plugintypes.AuditLog) ([]byte, error) {
	type wire struct {
		Transaction struct {
			ID string `json:"id"`
		} `json:"transaction"`
	}
	var w wire
	if al.Transaction() != nil {
		w.Transaction.ID = al.Transaction().ID()
	}
	return json.Marshal(w)
}

func (jsonFormatterForTest) MIME() string { return "application/json" }

// fullJSONFormatter 与 coraza 内置 JSON 格式化器同形（json.Marshal 直出完整
// 信封）——用于核对快照→drain 链路的完整字段面（transaction/messages/headers/
// body 全部经快照消费）。
type fullJSONFormatter struct{}

func (fullJSONFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	return json.Marshal(al)
}

func (fullJSONFormatter) MIME() string { return "application/json" }

// blockingFormatter 首次 Format 阻塞至 release 关闭——钉「格式化已移出请求
// 路径」：若 Write 仍在请求路径同步格式化，ProcessLogging 将无法在超时内返回。
type blockingFormatter struct {
	release chan struct{}
}

func (f *blockingFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	<-f.release
	return json.Marshal(al)
}

func (*blockingFormatter) MIME() string { return "application/json" }

// lbfenceFormatter AUD-1（第 77 轮）测试同步栅栏：Format 阻塞至 release 关闭，
// 放行后按 json.Marshal 直出（信封与内置 JSON 格式化器一致，见 auditSnapshot
// 注释）。经 plugins.RegisterAuditLogFormatter 注册为专用格式名 lbfence、由
// 被测指令 SecAuditLogFormat lbfence 装入 coraza 写路径——drain 侧 process
// 先 Format 后查计时注册表，栅栏把「主 goroutine 完成 record+close」定序在
// drain 查表之前，消除迟到注入钉测对 goroutine 调度序的依赖（修复前：drain
// 抢先完成格式化+首轮查表未命中 → auditTimingWait 未知 tid 即返 → lb_timing
// 缺失 → 断言随机红）。
type lbfenceFormatter struct {
	release chan struct{}
}

func (f *lbfenceFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	<-f.release
	return json.Marshal(al)
}

func (*lbfenceFormatter) MIME() string { return "application/json" }

// cannedFormatter 忽略审计内容返回固定正文——管线级测试（阻塞/轮转）无需构造
// 完整 AuditLog（plugintypes 接口的 Args 返回类型是 coraza 内部类型，测试无法
// 合成），只验证入队/刷盘语义。
type cannedFormatter struct{ body []byte }

func (f cannedFormatter) Format(plugintypes.AuditLog) ([]byte, error) { return f.body, nil }

func (cannedFormatter) MIME() string { return "application/json" }

// 审计写插件（lbfile）测试：入队/刷盘/轮转重开兼容/阻塞零丢/timing 注入。
// 写侧契约（第 76 轮）：决策→计时（请求路径，纯评估口径）→终态标记；审计
// Write 只格式化+入队（阻塞式有界队列，零丢弃）；专职 drain goroutine 等待
// per-tx 计时终态后注入 lb_timing 顶层字段并 bufio 批量刷盘。

// useTestAuditPipeline 把默认管线参数收窄到测试量级并隔离全局注册表。
func useTestAuditPipeline(t *testing.T) {
	t.Helper()
	releaseAllAuditPipelines(t)
	origQueue, origThreshold, origInterval := auditQueueSize, auditFlushThreshold, auditFlushInterval
	origWait, origPoll, origTTL := auditTimingWaitLimit, auditTimingPollStep, auditTimingEntryTTL
	auditQueueSize = 64
	auditFlushThreshold = 1
	auditFlushInterval = 5 * time.Millisecond
	auditTimingWaitLimit = 200 * time.Millisecond
	auditTimingPollStep = time.Millisecond
	auditTimingEntryTTL = 50 * time.Millisecond
	auditTimingMu.Lock()
	auditTimingEntries = make(map[string]*auditTimingEntry)
	auditTimingMu.Unlock()
	t.Cleanup(func() {
		auditQueueSize, auditFlushThreshold, auditFlushInterval = origQueue, origThreshold, origInterval
		auditTimingWaitLimit, auditTimingPollStep, auditTimingEntryTTL = origWait, origPoll, origTTL
		auditTimingMu.Lock()
		auditTimingEntries = make(map[string]*auditTimingEntry)
		auditTimingMu.Unlock()
	})
}

// waitAuditLine 轮询等待临时审计文件出现一行可解析 JSON（上限 2s）。
func waitAuditLine(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if json.Valid([]byte(line)) {
					return line
				}
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("audit line did not appear in %s within 2s", path)
	return ""
}

// Given: SecAuditLogType lbfile + phase:1 deny 的 coraza WAF，请求携带 timing ID 头
// When: 事务中断 + ProcessLogging（audit Write 入队）之后才 record+close timing
//
//	——复刻生产时序（coraza-caddy 在 WAF handler 退出时 defer ProcessLogging，
//	blocked_counter 在其之后才写分段）
//
// Then: 审计行含 lb_timing.end_us=42（写 goroutine 等待迟到分段后注入，零丢弃）
func TestAuditWriter_registeredAndInjectsLateTiming(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// AUD-1（第 77 轮）同步栅栏：drain 侧 Format 点阻塞至主 goroutine 完成
	// 「迟到分段 record+close」后放行——生产时序（Write 入队严格早于计时写点，
	// coraza defer ProcessLogging 契约）原样保持，drain 查表被定序在写点之后，
	// 断言不再依赖调度序。已知取舍窗口（与 auditTimingWait 的 AUD-1 注释同源，
	// 此处钉明）：生产中 drain 抢先完成格式化并首轮查表的极小竞态窗内的行不
	// 注入 lb_timing（耗时属增强信息，展示层报「—」，可接受）；本钉测锚定的
	// 契约是「行到 drain 时终态已置位 → 必注入」，栅栏使该契约确定性成立。
	fence := &lbfenceFormatter{release: make(chan struct{})}
	plugins.RegisterAuditLogFormatter("lbfence", fence)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbfence",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABIJDEFHKZ",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990001,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("coraza must accept lbfile audit writer: %v", err)
	}

	const id = "abcdef0123456789"
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set(securityTimingHeader, id)
	req.Header.Set("X-Probe", "hit")
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	for k, v := range req.Header {
		for _, val := range v {
			tx.AddRequestHeader(k, val)
		}
	}
	tx.ProcessRequestHeaders()
	if !tx.IsInterrupted() {
		t.Fatal("rule must interrupt")
	}
	// 生产时序：ProcessLogging（audit Write 先入队）先于计时写点。
	tx.ProcessLogging()
	// blocked_counter 同位写点：决策已出，纯评估耗时入注册表，随后终态标记。
	auditTimingRecord(id, "end", 42)
	auditTimingClose(id)
	// 栅栏放行：drain 此刻才执行 Format→查表，必见已终态条目（保序，零调度依赖）。
	close(fence.release)

	line := waitAuditLine(t, logPath)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &doc); err != nil {
		t.Fatalf("audit line not JSON: %v", err)
	}
	lb, ok := doc["lb_timing"]
	if !ok {
		t.Fatalf("lb_timing missing from audit line: %s", line)
	}
	var timing struct {
		PreUs *int64 `json:"pre_us"`
		EndUs *int64 `json:"end_us"`
	}
	if err := json.Unmarshal(lb, &timing); err != nil {
		t.Fatalf("lb_timing malformed: %v (%s)", err, lb)
	}
	if timing.EndUs == nil || *timing.EndUs != 42 {
		t.Fatalf("lb_timing.end_us = %v; want 42", timing.EndUs)
	}
	if timing.PreUs != nil {
		t.Fatalf("lb_timing.pre_us = %v; want absent", *timing.PreUs)
	}
}

// useTestAuditPipeline 追加：用例结束时排空全部测试管线（drain 退出、fd 关闭）。
func releaseAllAuditPipelines(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		auditPipelinesMu.Lock()
		pipelines := make([]*auditPipeline, 0, len(auditPipelines))
		for _, p := range auditPipelines {
			pipelines = append(pipelines, p)
		}
		auditPipelinesMu.Unlock()
		for _, p := range pipelines {
			p.release()
		}
	})
}

// Given: 无 timing ID 头的审计事务
// Then: 审计行不含 lb_timing 字段（耗时报「—」的旧语义），且写路径不等待
func TestAuditWriter_noTimingHeaderOmitsField(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990002,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	tx.AddRequestHeader("X-Probe", "hit")
	tx.ProcessRequestHeaders()
	if !tx.IsInterrupted() {
		t.Fatal("rule must interrupt")
	}
	start := time.Now()
	tx.ProcessLogging()
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("ProcessLogging waited %v without timing header; must skip wait", time.Since(start))
	}

	line := waitAuditLine(t, logPath)
	if strings.Contains(line, "lb_timing") {
		t.Fatalf("lb_timing must be omitted without timing header: %s", line)
	}
}

// Given: 审计行携带 timing ID 头但注册表无该条目（未知 tid：陈旧行积压超 TTL
//
//	被清扫/写点缺失异常行），等待上限收窄到可观测量级（200ms，useTestAuditPipeline）
//
// When: 事务入队（ProcessLogging）→ drain 侧处理
// Then: 行在远小于上限的时间内落盘（<80ms——旧行为轮询满上限，恒 ≥200ms 本断言
//
//	必红），且不注入 lb_timing——AUD-1 钉：未知 tid 不阻塞单 drain goroutine
//	（积压行批量到场时逐行满等=无背压阀下的 drain 沉陷，请求路径被入队阻塞拖住）
func TestAuditPipeline_unknownTidDoesNotBlockDrain(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990003,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	// timing ID 头在场（16 字符生产形态）但注册表无条目——不 record 不 close
	const orphanTID = "0000000000000000"
	start := time.Now()
	driveProbeTx(t, waf, orphanTID)
	line := waitAuditLine(t, logPath)
	elapsed := time.Since(start)
	if elapsed > 80*time.Millisecond {
		t.Fatalf("unknown tid must not block drain (AUD-1): line landed after %v (limit 200ms, old polling behavior >=200ms)", elapsed)
	}
	if strings.Contains(line, "lb_timing") {
		t.Fatalf("unknown tid must inject nothing: %s", line)
	}
}

// waitAuditLines 轮询等待临时审计文件出现至少 n 行可解析 JSON（上限 2s）。
func waitAuditLines(t *testing.T, path string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var lines []string
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			lines = lines[:0]
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && json.Valid([]byte(line)) {
					lines = append(lines, line)
				}
			}
			if len(lines) >= n {
				return lines
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("expected %d audit lines in %s within 2s, got %d", n, path, len(lines))
	return nil
}

// driveProbeTx 驱动一次 phase:1 deny 事务（X-Probe=hit 规则），复刻生产时序：
// ProcessLogging（审计 Write）先于调用方计时写点。返回事务 ID。
func driveProbeTx(t *testing.T, waf coraza.WAF, timingID string) string {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if timingID != "" {
		req.Header.Set(securityTimingHeader, timingID)
	}
	req.Header.Set("X-Probe", "hit")
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	for k, v := range req.Header {
		for _, val := range v {
			tx.AddRequestHeader(k, val)
		}
	}
	tx.ProcessRequestHeaders()
	if !tx.IsInterrupted() {
		t.Fatal("rule must interrupt")
	}
	tx.ProcessLogging()
	return tx.ID()
}

// Given: 快照化写侧（Write 只构建快照入队，drain 侧格式化）+ phase:2 body 规则
// When: ProcessLogging（入队）→ tx.Close（变量集合 reset+事务归还池——live 引用
//
//	污染源）→ 计时终态 → 才放行 drain 侧格式化
//
// Then: 审计行完整（transaction.id/unix_timestamp/client_ip/server_id/method/
//
//	uri/headers/body/messages.data.id 全部为 Close 前的值）且含 lb_timing——
//	入队后改原（Close reset）不影响输出；且 ProcessLogging 未被格式化阻塞。
func TestAuditWriter_snapshotSurvivesTxCycle(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	fmtr := &blockingFormatter{release: make(chan struct{})}
	cfg := plugintypesConfigFor(t, logPath)
	cfg.Formatter = fmtr
	w := &lbAuditWriter{}
	if err := w.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABCIJDEFHKZ",
		"SecRule ARGS:payload \"@streq hit\" \"id:990003,phase:2,deny,status:403,log,msg:'probe-body'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	const id = "abcdef0123456789"
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetServerName("example.com")
	req := httptest.NewRequest(http.MethodPost, "/probe", nil)
	req.Header.Set(securityTimingHeader, id)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	for k, v := range req.Header {
		for _, val := range v {
			tx.AddRequestHeader(k, val)
		}
	}
	tx.ProcessRequestHeaders()
	if _, n, err := tx.WriteRequestBody([]byte("payload=hit")); err != nil || n != len("payload=hit") {
		t.Fatalf("WriteRequestBody: n=%d err=%v", n, err)
	}
	if intr, err := tx.ProcessRequestBody(); err != nil || intr == nil {
		t.Fatalf("rule must interrupt body phase: intr=%v err=%v", intr, err)
	}
	txID := tx.ID()

	// 生产时序：ProcessLogging（审计 Write 入队）不能被格式化阻塞——格式化
	// 已移出请求路径。
	logged := make(chan struct{})
	go func() {
		tx.ProcessLogging()
		close(logged)
	}()
	select {
	case <-logged:
	case <-time.After(2 * time.Second):
		t.Fatal("ProcessLogging blocked in formatter.Format — formatting still on request path")
	}

	// 改原：tx.Close reset 变量集合（headers/body 归零、事务归还 sync.Pool），
	// 随后计时终态，最后才放行 drain 侧格式化。
	tx.Close()
	auditTimingRecord(id, "end", 77)
	auditTimingClose(id)
	close(fmtr.release)

	line := waitAuditLine(t, logPath)
	var doc struct {
		Transaction struct {
			ID            string `json:"id"`
			UnixTimestamp int64  `json:"unix_timestamp"`
			ClientIP      string `json:"client_ip"`
			ServerID      string `json:"server_id"`
			IsInterrupted bool   `json:"is_interrupted"`
			Request       struct {
				Method  string              `json:"method"`
				URI     string              `json:"uri"`
				Headers map[string][]string `json:"headers"`
				Body    string              `json:"body"`
			} `json:"request"`
		} `json:"transaction"`
		Messages []struct {
			Message string `json:"message"`
			Data    struct {
				ID  int    `json:"id"`
				Raw string `json:"raw"`
			} `json:"data"`
		} `json:"messages"`
		LbTiming struct {
			Pre *int64 `json:"pre_us"`
			End *int64 `json:"end_us"`
		} `json:"lb_timing"`
	}
	if err := json.Unmarshal([]byte(line), &doc); err != nil {
		t.Fatalf("audit line not JSON: %v (%s)", err, line)
	}
	if doc.Transaction.ID != txID {
		t.Fatalf("transaction.id = %q; want %q", doc.Transaction.ID, txID)
	}
	if doc.Transaction.UnixTimestamp == 0 {
		t.Fatal("transaction.unix_timestamp missing")
	}
	if doc.Transaction.ClientIP == "" || doc.Transaction.ServerID == "" {
		t.Fatalf("client_ip/server_id missing: %+v", doc.Transaction)
	}
	if !doc.Transaction.IsInterrupted {
		t.Fatal("transaction.is_interrupted must be true (deny)")
	}
	if doc.Transaction.Request.Method != http.MethodPost || doc.Transaction.Request.URI != "/probe" {
		t.Fatalf("request line = %s %s", doc.Transaction.Request.Method, doc.Transaction.Request.URI)
	}
	if got := securityTimingIDFromHeaders(doc.Transaction.Request.Headers); got != id {
		t.Fatalf("timing header missing from snapshot headers: %v (got %q)", doc.Transaction.Request.Headers, got)
	}
	if doc.Transaction.Request.Body != "payload=hit" {
		t.Fatalf("request body polluted by tx.Close: %q", doc.Transaction.Request.Body)
	}
	if len(doc.Messages) == 0 || doc.Messages[0].Data.ID != 990003 || !strings.Contains(doc.Messages[0].Data.Raw, "ARGS:payload") {
		t.Fatalf("messages incomplete: %+v", doc.Messages)
	}
	if doc.LbTiming.End == nil || *doc.LbTiming.End != 77 {
		t.Fatalf("lb_timing.end_us = %v; want 77", doc.LbTiming.End)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// Given: 管线已 release（重载窗口：旧 WAF release、在途事务仍 Write）
// When: 关闭态入队
// Then: 同步回退直写该行（短生命周期 fd O_APPEND），零丢弃；计时同步短等注入
//
//	（先行终态立即注入；无计时头的行照常落盘且无 lb_timing）。
func TestAuditPipeline_releasedPipelineSyncWritesRow(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	cfg := plugintypesConfigFor(t, logPath)
	cfg.Formatter = fullJSONFormatter{}
	w := &lbAuditWriter{}
	if err := w.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990004,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	const id1 = "1111111111111111"
	const id2 = "2222222222222222"
	id1Tx := driveProbeTx(t, waf, id1)
	auditTimingRecord(id1, "end", 42)
	auditTimingClose(id1)
	lines := waitAuditLines(t, logPath, 1)
	if !strings.Contains(lines[0], id1Tx) {
		t.Fatalf("first row = %s", lines[0])
	}

	// 重载窗口：管线 release（drain 退出、fd 关闭、队列置 nil），writer 仍持引用。
	w.pipeline.release()

	// 关闭态写入 #1：timing 先置终态 → 同步短等立即注入。
	auditTimingRecord(id2, "end", 7)
	auditTimingClose(id2)
	id2Tx := driveProbeTx(t, waf, id2)

	// 关闭态写入 #2：无计时头 → 同步直写，零丢弃且不注入。
	id3Tx := driveProbeTx(t, waf, "")

	if err := w.Write(nil); err != nil {
		t.Fatalf("Write(nil) must be no-op, got %v", err)
	}

	lines = waitAuditLines(t, logPath, 3)
	var sawID2Timing, sawID3 bool
	for _, line := range lines {
		switch {
		case strings.Contains(line, id2Tx):
			if !strings.Contains(line, `"end_us":7`) {
				t.Fatalf("sync-written row missing injected timing: %s", line)
			}
			sawID2Timing = true
		case strings.Contains(line, id3Tx):
			if strings.Contains(line, "lb_timing") {
				t.Fatalf("no-timing row must omit lb_timing: %s", line)
			}
			sawID3 = true
		}
	}
	if !sawID2Timing || !sawID3 {
		t.Fatalf("sync fallback rows missing (zero-drop violated): %v", lines)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// Given: 有界队列（容量 2）且 drain 未消费
// When: 先同步填满 2 条，再异步入队第 3 条
// Then: 第 3 条阻塞等待（零丢弃），drain 启动后完成——退化价=退役前 serial 同步写
func TestAuditPipeline_enqueueBlocksWhenFullZeroDrop(t *testing.T) {
	useTestAuditPipeline(t)
	p := &auditPipeline{
		target: filepath.Join(t.TempDir(), "audit.log"),
		queue:  make(chan lbAuditItem, 2),
		done:   make(chan struct{}),
	}
	if err := p.openFile(0o644); err != nil {
		t.Fatalf("open: %v", err)
	}

	// 同步填满队列（无 drain 消费）
	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"a":1}`)}})
	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"b":2}`)}})

	// 第 3 条异步入队：队列满必须阻塞（而非丢弃/报错）
	thirdDone := make(chan struct{})
	go func() {
		p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"c":3}`)}})
		close(thirdDone)
	}()
	select {
	case <-thirdDone:
		t.Fatal("third enqueue completed while queue full; must block (zero-drop backpressure)")
	case <-time.After(50 * time.Millisecond):
	}

	// drain 启动消化 → 阻塞的第三条最终入队成功（零丢弃）
	go p.drain()
	select {
	case <-thirdDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked enqueue never completed after drain started")
	}
	p.release()
}

// Given: 管线持有长生命周期 fd
// When: 轮转侧 copytruncate（文件被截断，inode 不变）后再写
// Then: 新行落在截断后的文件头（O_APPEND 语义），无需重开 fd——与
//
//	internal/services rotateAuditLogIfNeeded 的 copytruncate 契约配对
func TestAuditPipeline_copytruncateCompatible(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	w := &lbAuditWriter{}
	if err := w.Init(plugintypesConfigFor(t, logPath)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// 直接 enqueue 无 tid 条目（不注入），验证纯刷盘链路
	w.pipeline.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"n":1}`)}})
	line1 := waitAuditLine(t, logPath)
	if !strings.Contains(line1, `"n":1`) {
		t.Fatalf("first line = %s", line1)
	}
	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatal(err)
	}
	w.pipeline.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"n":2}`)}})
	deadline := time.Now().Add(2 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		data, _ = os.ReadFile(logPath)
		if strings.Contains(string(data), `"n":2`) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !strings.Contains(string(data), `"n":2`) {
		t.Fatalf("post-truncate write lost: %q", data)
	}
	if strings.Contains(string(data), `"n":1`) {
		t.Fatal("pre-truncate content must not reappear after copytruncate")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// Given: 目标路径目录缺失
// When: Init
// Then: 返回错误（/load 拒收，与 serial writer 同 fail-fast 语义），后续 Write 零 panic
func TestAuditWriter_initFailureFailsFast(t *testing.T) {
	useTestAuditPipeline(t)
	w := &lbAuditWriter{}
	err := w.Init(plugintypesConfigFor(t, filepath.Join(t.TempDir(), "missing-dir", "audit.log")))
	if err == nil {
		t.Fatal("Init must fail on unwritable target (fail-fast /load rejection)")
	}
	if wErr := w.Write(nil); wErr != nil {
		t.Fatalf("Write after failed Init must be silent no-op, got %v", wErr)
	}
}

// injectAuditTiming 单元钉：pre/end 独立注入、缺席省略、0 值保留、畸形 JSON 原样返回。
func TestInjectAuditTiming(t *testing.T) {
	// 双段注入
	out := injectAuditTiming([]byte(`{"transaction":{"id":"a"}}`), auditTimingSnapshot{preUs: 7, preSet: true, endUs: 42, endSet: true})
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var timing struct {
		PreUs *int64 `json:"pre_us"`
		EndUs *int64 `json:"end_us"`
	}
	if err := json.Unmarshal(doc["lb_timing"], &timing); err != nil {
		t.Fatal(err)
	}
	if timing.PreUs == nil || *timing.PreUs != 7 || timing.EndUs == nil || *timing.EndUs != 42 {
		t.Fatalf("timing = %+v; want pre=7 end=42", timing)
	}

	// 单段注入（pre 缺席）
	out = injectAuditTiming([]byte(`{"k":1}`), auditTimingSnapshot{endUs: 5, endSet: true})
	doc = nil
	_ = json.Unmarshal(out, &doc)
	timing = struct {
		PreUs *int64 `json:"pre_us"`
		EndUs *int64 `json:"end_us"`
	}{}
	_ = json.Unmarshal(doc["lb_timing"], &timing)
	if timing.PreUs != nil || timing.EndUs == nil || *timing.EndUs != 5 {
		t.Fatalf("single-segment injection wrong: %s", out)
	}

	// 0 值必须保留（0µs 是合法计时）
	out = injectAuditTiming([]byte(`{}`), auditTimingSnapshot{preUs: 0, preSet: true})
	if !strings.Contains(string(out), `"pre_us":0`) {
		t.Fatalf("zero timing dropped: %s", out)
	}

	// 空 snapshot 不注入
	out = injectAuditTiming([]byte(`{"k":1}`), auditTimingSnapshot{})
	if string(out) != `{"k":1}` {
		t.Fatalf("empty snapshot must return body unchanged, got %s", out)
	}

	// 畸形 JSON 原样返回（不注入不 panic）
	bad := []byte(`not-json`)
	if out := injectAuditTiming(bad, auditTimingSnapshot{preUs: 1, preSet: true}); string(out) != string(bad) {
		t.Fatalf("malformed JSON must be returned unchanged, got %s", out)
	}
}

// 注册表钉：record→wait（未终态，超时返回部分快照）→close→wait 立即返回完整快照。
func TestAuditTimingRegistry_recordWaitClose(t *testing.T) {
	useTestAuditPipeline(t)
	const id = "0123456789abcdef"

	// AUD-1（第 76 轮）：未知 tid（注册表无条目）首轮即返空快照——不轮询到超时
	// （旧行为本断言必红：轮询走满超时）。条目稍后创建也不追加等待（预检拦行
	// 的微秒级建条窗口由 drain 侧格式化先行吸收，见 auditTimingWait 注释）。
	start := time.Now()
	snap := auditTimingWait(id, 30*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 5*time.Millisecond {
		t.Fatalf("unknown entry must return immediately (AUD-1), took %v", elapsed)
	}
	if snap.preSet || snap.endSet {
		t.Fatalf("unknown entry must yield empty snapshot: %+v", snap)
	}

	auditTimingRecord(id, "pre", 11)
	// 未终态：wait 走满超时并返回部分快照（pre 在场）
	snap = auditTimingWait(id, 30*time.Millisecond)
	if !snap.preSet || snap.preUs != 11 || snap.closed {
		t.Fatalf("partial snapshot = %+v; want pre=11 unclosed", snap)
	}

	auditTimingRecord(id, "end", 22)
	auditTimingClose(id)
	start = time.Now()
	snap = auditTimingWait(id, time.Second)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("closed entry must return immediately")
	}
	if !snap.closed || snap.preUs != 11 || snap.endUs != 22 || !snap.preSet || !snap.endSet {
		t.Fatalf("final snapshot = %+v; want closed pre=11 end=22", snap)
	}

	// 空 ID 短路
	if snap := auditTimingWait("", time.Millisecond); snap.preSet || snap.endSet {
		t.Fatal("empty id must short-circuit")
	}
	auditTimingRecord("", "pre", 1)
	auditTimingClose("")
}

// 注册表清理钉：TTL 过期条目在批量写入点被清扫，新条目保留（无界增长防线）。
func TestAuditTimingRegistry_sweep(t *testing.T) {
	useTestAuditPipeline(t)
	const stale = "aaaaaaaaaaaaaaaa"
	auditTimingRecord(stale, "pre", 1)
	// 强制 stale 条目超龄
	auditTimingMu.Lock()
	auditTimingEntries[stale].created = time.Now().Add(-time.Hour)
	auditTimingMu.Unlock()

	for i := range 128 { // 跨过 sweep 周期（64）多批
		auditTimingRecord(fmt.Sprintf("bbbbbbbbbbbbbb%03d", i), "pre", int64(i))
	}

	auditTimingMu.Lock()
	_, staleExists := auditTimingEntries[stale]
	count := len(auditTimingEntries)
	auditTimingMu.Unlock()
	if staleExists {
		t.Fatal("expired entry must be swept")
	}
	if count < 100 {
		t.Fatalf("recent entries must survive sweep, got %d", count)
	}
}

// timing ID 提取钉：大小写不敏感、多值取首、缺失空串。
func TestSecurityTimingIDFromHeaders(t *testing.T) {
	got := securityTimingIDFromHeaders(map[string][]string{
		"X-Lb-Security-Timing-Id": {"abc123"},
		"Other":                   {"x"},
	})
	if got != "abc123" {
		t.Fatalf("got %q", got)
	}
	if got := securityTimingIDFromHeaders(map[string][]string{"x-lb-security-timing-id": {"low"}}); got != "low" {
		t.Fatalf("case-insensitive lookup failed: %q", got)
	}
	if got := securityTimingIDFromHeaders(map[string][]string{"Other": {"x"}}); got != "" {
		t.Fatalf("missing header must be empty, got %q", got)
	}
}

// ---- 第 78 轮 U14-03 / U14-04 / U14-10 ----

func TestAuditTiming_closeOnlyPathSweepsExpired(t *testing.T) {
	useTestAuditPipeline(t)
	const stale = "cccccccccccccccc"
	auditTimingRecord(stale, "pre", 1)
	auditTimingMu.Lock()
	auditTimingEntries[stale].created = time.Now().Add(-time.Hour)
	// 把创建计数推到清扫触发点前一条：下一次 close 建条（纯 close 路径）即
	// 触发摊销清扫——旧实现 close 不递增计数，从不触发。
	auditTimingCreateCount = 63
	auditTimingMu.Unlock()

	auditTimingClose("dddddddddddddddd")

	auditTimingMu.Lock()
	_, staleExists := auditTimingEntries[stale]
	_, freshExists := auditTimingEntries["dddddddddddddddd"]
	auditTimingMu.Unlock()
	if staleExists {
		t.Fatal("close-only path must sweep expired entries")
	}
	if !freshExists {
		t.Fatal("closed entry must be registered")
	}
}

type failingFormatter struct{}

func (failingFormatter) Format(plugintypes.AuditLog) ([]byte, error) {
	return nil, fmt.Errorf("injected format failure")
}
func (failingFormatter) MIME() string { return "application/json" }

func TestAuditDrain_ioErrorSurfacedAndReopens(t *testing.T) {
	var mu sync.Mutex
	var logs []string
	oldLog := auditIOLogf
	auditIOLogf = func(format string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	t.Cleanup(func() { auditIOLogf = oldLog })

	target := filepath.Join(t.TempDir(), "audit.log")
	p := &auditPipeline{target: target, mode: 0o644}
	if err := p.openFile(p.mode); err != nil {
		t.Fatal(err)
	}
	// 模拟粘性 IO 错误：先入缓冲（空 bufio 刷盘不触 fd），再关闭 fd 后刷盘必须
	// 报错并重建。
	p.ioMu.Lock()
	p.appendLine([]byte("buffered-before-error"))
	_ = p.fd.Close()
	p.flushLocked()
	p.ioMu.Unlock()

	mu.Lock()
	if len(logs) == 0 {
		mu.Unlock()
		t.Fatal("io error must be surfaced via auditIOLogf")
	}
	mu.Unlock()

	p.ioMu.Lock()
	p.appendLine([]byte("line-after-reopen"))
	p.flushLocked()
	p.ioMu.Unlock()
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "line-after-reopen") {
		t.Fatalf("write must continue after fd reopen, got %q", data)
	}

	// 格式化失败：单条跳过、后续行继续落盘（process 自行取 ioMu，不得在
	// 测试侧持锁调用——否则自死锁）。
	p.process(lbAuditItem{snap: &auditSnapshot{}, formatter: failingFormatter{}})
	p.process(lbAuditItem{snap: &auditSnapshot{}, formatter: jsonFormatterForTest{}})
	p.ioMu.Lock()
	p.flushLocked()
	p.ioMu.Unlock()
	data, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `{"transaction"`) {
		t.Fatalf("line after a format failure must still be written, got %q", data)
	}
	p.closeFile()
}

func TestAuditPipelineRelease_doesNotHoldRegistryLockWhileDraining(t *testing.T) {
	target := filepath.Join(t.TempDir(), "audit.log")
	p := &auditPipeline{target: target, mode: 0o644, queue: make(chan lbAuditItem, 1), done: make(chan struct{}), refs: 1}
	if err := p.openFile(p.mode); err != nil {
		t.Fatal(err)
	}
	auditPipelinesMu.Lock()
	auditPipelines[target] = p
	auditPipelinesMu.Unlock()

	released := make(chan struct{})
	go func() {
		p.release()
		close(released)
	}()
	// 等待 release 进入 <-p.done（延迟 20ms 足够覆盖删表动作）。
	time.Sleep(20 * time.Millisecond)
	select {
	case <-released:
		t.Fatal("release must wait for the drain goroutine")
	default:
	}

	acquired := make(chan *auditPipeline, 1)
	go func() {
		np, err := acquireAuditPipeline(target, 0o644)
		if err != nil {
			acquired <- nil
			return
		}
		acquired <- np
	}()
	select {
	case np := <-acquired:
		if np == nil {
			t.Fatal("acquire failed")
		}
		np.release()
	case <-time.After(2 * time.Second):
		t.Fatal("acquire blocked on the registry lock while release waited for drain (U14-10)")
	}
	close(p.done) // 放行 release
	<-released
}
