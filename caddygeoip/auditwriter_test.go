package caddygeoip

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
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
// 经 plugins.RegisterAuditLogFormatter 装入被测 WAF 的 SecAuditLogFormat（同
// lbfence 模式）——只有挂进 coraza 真实写路径，栅栏与调用计数才有意义
// （挂在手工创建、WAF 从不使用的 writer 上时栅栏失效）。
// calls 计数钉「栅栏确在写路径」——formatter 未被调用即布线失效，确定性红。
type blockingFormatter struct {
	release chan struct{}
	calls   atomic.Int32
}

func (f *blockingFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	f.calls.Add(1)
	<-f.release
	return json.Marshal(al)
}

func (*blockingFormatter) MIME() string { return "application/json" }

// lbfenceFormatter 测试同步栅栏：Format 阻塞至 release 关闭，
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

// gatedFormatter 阻塞在 Format 内直到 release 关闭——模拟「已入队、drain
// 在途处理中」的收尾窗口。
type gatedFormatter struct {
	entered chan struct{}
	release chan struct{}
	body    []byte
}

func (f *gatedFormatter) Format(plugintypes.AuditLog) ([]byte, error) {
	close(f.entered)
	<-f.release
	return f.body, nil
}

func (*gatedFormatter) MIME() string { return "application/json" }

// 收尾刷盘必须先等 drain 排空（队列空+无在途处理）再刷 bufio——否则进程
// 退出/reload 的 Cleanup 会把已入队未处理的审计行整批丢掉（旧实现只刷
// bufio，在队行全损）。
func TestAuditPipeline_flushWaitsForQueuedItems(t *testing.T) {
	useTestAuditPipeline(t)
	target := filepath.Join(t.TempDir(), "audit.log")
	w := &lbAuditWriter{}
	if err := w.Init(plugintypesConfigFor(t, target)); err != nil {
		t.Fatalf("init: %v", err)
	}
	fmtr := &gatedFormatter{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		body:    []byte(`{"gated":"ZZZ777"}`),
	}
	// 失败路径同样必须放行 drain（否则测试收尾会等一个永不返回的处理）。
	var releaseOnce sync.Once
	releaseGate := func() { releaseOnce.Do(func() { close(fmtr.release) }) }
	t.Cleanup(releaseGate)
	w.pipeline.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: fmtr})
	select {
	case <-fmtr.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("drain 未进入在途处理")
	}

	done := make(chan struct{})
	go func() {
		FlushAuditPipelines()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("drain 在途时收尾刷盘必须等待（已入队行不得丢弃）")
	case <-time.After(100 * time.Millisecond):
	}
	releaseGate()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain 完成后收尾刷盘未返回")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "ZZZ777") {
		t.Fatalf("收尾后审计行必须已落盘: %q", data)
	}
}

// 审计写插件（lbfile）测试：入队/刷盘/轮转重开兼容/有界背压/timing 注入。
// 写侧契约：决策→计时（请求路径，纯评估口径）→终态标记；审计
// Write 只格式化+入队（有界队列：字节预算+容量等待，超限丢弃并计数）；
// 专职 drain goroutine 等待 per-tx 计时终态后注入 lb_timing 顶层字段并
// bufio 批量刷盘。

// useTestAuditPipeline 把默认管线参数收窄到测试量级并隔离全局注册表。
// 清理顺序（t.Cleanup LIFO）：先注册「恢复全局参数」，后注册「收尾全部
// 管线」——执行时 drain 先退出（closeTestAuditPipelines 等 p.done），再恢复
// auditFlushThreshold/auditTiming* 全局值；逆序会在 drain 仍读这些变量时
// 写入（-race 实测：cleanup 恢复 vs appendLine/process 读，历史验证期暴露）。
func useTestAuditPipeline(t *testing.T) {
	t.Helper()
	origQueue, origThreshold, origInterval := auditQueueSize, auditFlushThreshold, auditFlushInterval
	origWait, origPoll := auditTimingWaitLimit, auditTimingPollStep
	origTTL := auditTimingEntryTTLNs.Load()
	auditQueueSize = 64
	auditFlushThreshold = 1
	auditFlushInterval = 5 * time.Millisecond
	auditTimingWaitLimit = 200 * time.Millisecond
	auditTimingPollStep = time.Millisecond
	auditTimingEntryTTLNs.Store(int64(50 * time.Millisecond))
	// 冲刷合并状态是进程级：上一个用例的冲刷时刻会让本用例的
	// FlushAuditPipelines 落进窗口被快进，必须复位。
	auditLastFlushNano.Store(0)
	auditTimingMu.Lock()
	resetAuditTimingRegistryLockedForTest()
	auditTimingMu.Unlock()
	t.Cleanup(func() {
		auditQueueSize, auditFlushThreshold, auditFlushInterval = origQueue, origThreshold, origInterval
		auditTimingWaitLimit, auditTimingPollStep = origWait, origPoll
		auditTimingEntryTTLNs.Store(origTTL)
		auditTimingMu.Lock()
		resetAuditTimingRegistryLockedForTest()
		auditTimingMu.Unlock()
	})
	closeTestAuditPipelines(t)
}

// resetAuditTimingRegistryLockedForTest 清空计时注册表全部状态（调用方持
// auditTimingMu）——条目/建条 FIFO/游标/清扫计数一并复位，避免测试间串扰。
func resetAuditTimingRegistryLockedForTest() {
	auditTimingEntries = make(map[string]*auditTimingEntry)
	auditTimingOrder = nil
	auditTimingHead = 0
	auditTimingCreateCount = 0
	auditTimingPollCountForTest.Store(0)
	auditTimingSweepVisitsForTest.Store(0)
	auditRetainedPreEntries = map[string]auditRetainedPreEntry{}
	auditRetainedPreOrder = nil
	auditRetainedPreHead = 0
}

// seedAuditTimingEntryForTest 以指定建条时刻直接种入条目（含 FIFO 项——
// 与生产建条路径同形，保证清扫不变量成立）。
func seedAuditTimingEntryForTest(id string, created time.Time) {
	auditTimingMu.Lock()
	auditTimingEntries[id] = &auditTimingEntry{created: created}
	auditTimingOrder = append(auditTimingOrder, auditTimingQueueEntry{id: id, created: created})
	auditTimingMu.Unlock()
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

	// 同步栅栏：drain 侧 Format 点阻塞至主 goroutine 完成
	// 「迟到分段 record+close」后放行——生产时序（Write 入队严格早于计时写点，
	// coraza defer ProcessLogging 契约）原样保持，drain 查表被定序在写点之后，
	// 断言不再依赖调度序。已知取舍窗口（与 auditTimingWait 的注释同源，
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
	auditTimingRecord(id, timingSegmentEnd, 42)
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

// useTestAuditPipeline 追加：用例结束时收尾全部测试管线（drain 退出、fd 关闭）。
// 生产路径没有这条通道（管线是进程级单例，见 acquireAuditPipeline）；测试侧
// 先把管线摘出注册表再关队列，保证收尾之后不再有新生产者（writer.Close 只刷盘
// 不拆管线）。
func closeTestAuditPipelines(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		auditPipelinesMu.Lock()
		pipelines := make([]*auditPipeline, 0, len(auditPipelines))
		for _, p := range auditPipelines {
			pipelines = append(pipelines, p)
		}
		auditPipelines = map[string]*auditPipeline{}
		auditPipelinesMu.Unlock()
		for _, p := range pipelines {
			close(p.queue)
			<-p.done
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
	auditTimingPollCountForTest.Store(0)
	tx.ProcessLogging()

	line := waitAuditLine(t, logPath)
	// 零轮询钉替代挂钟阈值——无计时头行 id 为空，auditTimingWait
	// 短路返回，drain 全程零轮询（旧轮询实现此处恒 >0）。
	if n := auditTimingPollCountForTest.Load(); n != 0 {
		t.Fatalf("no timing header must skip wait entirely: drain polled %d times", n)
	}
	if strings.Contains(line, "lb_timing") {
		t.Fatalf("lb_timing must be omitted without timing header: %s", line)
	}
}

// Given: 审计行携带 timing ID 头但注册表无该条目（未知 tid：陈旧行积压超 TTL
//
//	被清扫/写点缺失异常行），等待上限收窄到可观测量级（200ms，useTestAuditPipeline）
//
// When: 事务入队（ProcessLogging）→ drain 侧处理
// Then: 行落盘且 drain 全程零轮询（旧行为轮询满上限 200ms/步 1ms 恒约 200 次，
//
//	零轮询钉对其必红），且不注入 lb_timing——钉：未知 tid 不阻塞单
//	drain goroutine（积压行批量到场时逐行满等=无背压阀下的 drain 沉陷，
//	请求路径被入队阻塞拖住）
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
	auditTimingPollCountForTest.Store(0)
	driveProbeTx(t, waf, orphanTID)
	line := waitAuditLine(t, logPath)
	// 零轮询钉替代挂钟阈值——行落盘时 drain 的等待已完成，
	// 未知 tid 首轮查表未命中即返（零轮询）；旧行为轮询满 200ms 上限
	// （poll step 1ms → 恒约 200 次），本断言对旧实现必红。
	if n := auditTimingPollCountForTest.Load(); n != 0 {
		t.Fatalf("unknown tid must not block drain : drain polled %d times, want 0", n)
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

	// 栅栏 formatter 必须经注册名装入被测 WAF 的
	// SecAuditLogFormat（lbfence 同模式）——旧实现把它挂在手工创建、WAF
	// 从不使用的 writer 上（WAF 自建 lbfile writer 用 JSON 格式化器），
	// 栅栏永不触发，「ProcessLogging 未被格式化阻塞」恒真、计时注入依赖
	// 调度序偶发红。calls 计数把布线失效变成确定性红。
	fmtr := &blockingFormatter{release: make(chan struct{})}
	plugins.RegisterAuditLogFormatter("lbsnapfmt", fmtr)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbsnapfmt",
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
	auditTimingRecord(id, timingSegmentEnd, 77)
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
	// 栅栏确实挂在 WAF 写路径（drain 侧格式化恰好一次）：0=布线失效
	// （旧形态，上述阻塞/计时断言全部形同虚设）。
	if n := fmtr.calls.Load(); n != 1 {
		t.Fatalf("fence formatter invocations = %d; want exactly 1 on the WAF write path", n)
	}
}

// captureFormatter 捕获 coraza 交给写路径的审计对象（快照）并按 JSON 直出。
type captureFormatter struct{ ch chan plugintypes.AuditLog }

func (f *captureFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	select {
	case f.ch <- al:
	default:
	}
	return json.Marshal(al)
}

func (*captureFormatter) MIME() string { return "application/json" }

func TestSnapshotAuditBody_capAndBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantLen   int
		truncated bool
		marker    bool
	}{
		{name: "small body unchanged", body: "payload=hit", wantLen: len("payload=hit")},
		{name: "exact limit unchanged", body: strings.Repeat("x", auditBodyMaxBytes), wantLen: auditBodyMaxBytes},
		// 目标形状：超限文本 = 前缀 64KiB + 显式截断标记（写侧与读侧上限相等，
		// 读侧无法凭长度判断截断——契约，标记 15 字节超出上限部分）。
		{name: "over limit truncated", body: strings.Repeat("x", auditBodyMaxBytes+1), wantLen: auditBodyMaxBytes + len("\n...[TRUNCATED]"), truncated: true, marker: true},
		// 畸形形状：前缀含非法 UTF-8 时不追加标记（会破坏读侧 base64 判定），
		// 只保留 64KiB 前缀。
		{name: "over limit binary no marker", body: strings.Repeat("x", 100) + "\xff" + strings.Repeat("y", auditBodyMaxBytes), wantLen: auditBodyMaxBytes, truncated: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, truncated := snapshotAuditBody(tc.body)
			if len(got) != tc.wantLen || truncated != tc.truncated {
				t.Fatalf("len=%d truncated=%v, want len=%d truncated=%v", len(got), truncated, tc.wantLen, tc.truncated)
			}
			prefix := got
			if tc.marker {
				if !strings.HasSuffix(got, "\n...[TRUNCATED]") {
					t.Fatalf("truncated text body must carry the explicit marker: ...%q", got[len(got)-24:])
				}
				prefix = strings.TrimSuffix(got, "\n...[TRUNCATED]")
			}
			if prefix != tc.body[:len(prefix)] {
				t.Fatal("captured body must preserve the original prefix")
			}
		})
	}
}

// 大请求体经真实 coraza phase:2 命中后，快照与 JSON 行只能保留有界前缀，
// 并显式携带截断标记；不能把工作区/队列/格式化链放大到原始 body 大小。
func TestAuditWriter_requestBodyCapAndTruncationMarker(t *testing.T) {
	useTestAuditPipeline(t)
	capture := &captureFormatter{ch: make(chan plugintypes.AuditLog, 1)}
	plugins.RegisterAuditLogFormatter("lbcap", capture)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbcap",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABCIJDEFHKZ",
		"SecRule ARGS:payload \"@streq hit\" \"id:990005,phase:2,deny,status:403,log,msg:'probe-large-body'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	body := "payload=hit&pad=" + strings.Repeat("x", auditBodyMaxBytes+32)
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodPost, "/probe-large", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	for k, v := range req.Header {
		for _, val := range v {
			tx.AddRequestHeader(k, val)
		}
	}
	tx.ProcessRequestHeaders()
	if _, n, err := tx.WriteRequestBody([]byte(body)); err != nil || n != len(body) {
		t.Fatalf("WriteRequestBody: n=%d err=%v", n, err)
	}
	if intr, err := tx.ProcessRequestBody(); err != nil || intr == nil {
		t.Fatalf("rule must interrupt large body phase: intr=%v err=%v", intr, err)
	}
	tx.ProcessLogging()

	var al plugintypes.AuditLog
	select {
	case al = <-capture.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("large-body audit snapshot was not captured")
	}
	sr, ok := al.Transaction().Request().(*auditSnapshotRequest)
	if !ok {
		t.Fatalf("snapshot request type = %T", al.Transaction().Request())
	}
	// 契约：快照体 = 原始前缀 64KiB + 显式标记 \n...[TRUNCATED]。
	wantPrefix := body[:auditBodyMaxBytes]
	if got := sr.Body(); got != wantPrefix+"\n...[TRUNCATED]" {
		t.Fatalf("snapshot body must be the %d-byte prefix plus truncation marker (len=%d)", auditBodyMaxBytes, len(got))
	}
	if !sr.BodyTruncated_ {
		t.Fatal("oversized snapshot body must carry the truncation marker")
	}
	line, err := json.Marshal(al)
	if err != nil {
		t.Fatalf("marshal capped audit snapshot: %v", err)
	}
	var wire struct {
		Transaction struct {
			Request struct {
				Body          string `json:"body"`
				BodyTruncated bool   `json:"body_truncated"`
			} `json:"request"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal(line, &wire); err != nil {
		t.Fatalf("audit line not JSON: %v", err)
	}
	if wire.Transaction.Request.Body != wantPrefix+"\n...[TRUNCATED]" || !wire.Transaction.Request.BodyTruncated {
		t.Fatalf("serialized body len=%d truncated=%v", len(wire.Transaction.Request.Body), wire.Transaction.Request.BodyTruncated)
	}
}

// 审计响应体快照与请求体同上限（64KiB 前缀 + 显式截断标记 +
// body_truncated 标记位，JSON 契约对称）。check-response 策略形态
// （SecResponseBodyAccess On + SecAuditLogParts 恒含 E）下 coraza 默认
// SecResponseBodyLimit=512KiB，无快照侧硬限时单条审计行可携带约 512KiB
// 响应体——2048 深队列内存放大 + 落盘放大。真实 coraza phase:4 命中验证。
func TestAuditWriter_responseBodyCapAndTruncationMarker(t *testing.T) {
	useTestAuditPipeline(t)
	capture := &captureFormatter{ch: make(chan plugintypes.AuditLog, 1)}
	plugins.RegisterAuditLogFormatter("lbrespcap", capture)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecResponseBodyAccess On",
		"SecResponseBodyMimeType text/plain",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbrespcap",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABIJDEFHKZ",
		"SecRule RESPONSE_BODY \"@rx leak\" \"id:990006,phase:4,deny,status:403,log,msg:'probe-resp-body'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	body := "leak:" + strings.Repeat("y", auditBodyMaxBytes+64)
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodGet, "/probe-resp", nil)
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.AddResponseHeader("Content-Type", "text/plain")
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if _, n, err := tx.WriteResponseBody([]byte(body)); err != nil || n != len(body) {
		t.Fatalf("WriteResponseBody: n=%d err=%v", n, err)
	}
	if intr, err := tx.ProcessResponseBody(); err != nil || intr == nil {
		t.Fatalf("rule must interrupt response phase: intr=%v err=%v", intr, err)
	}
	tx.ProcessLogging()

	var al plugintypes.AuditLog
	select {
	case al = <-capture.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("response-body audit snapshot was not captured")
	}
	sresp, ok := al.Transaction().Response().(*auditSnapshotResponse)
	if !ok {
		t.Fatalf("snapshot response type = %T", al.Transaction().Response())
	}
	wantPrefix := body[:auditBodyMaxBytes]
	if got := sresp.Body(); got != wantPrefix+"\n...[TRUNCATED]" {
		t.Fatalf("response snapshot body must be the %d-byte prefix plus truncation marker (len=%d)", auditBodyMaxBytes, len(got))
	}
	line, err := json.Marshal(al)
	if err != nil {
		t.Fatalf("marshal capped response snapshot: %v", err)
	}
	var wire struct {
		Transaction struct {
			Response struct {
				Body          string `json:"body"`
				BodyTruncated bool   `json:"body_truncated"`
			} `json:"response"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal(line, &wire); err != nil {
		t.Fatalf("audit line not JSON: %v", err)
	}
	if wire.Transaction.Response.Body != wantPrefix+"\n...[TRUNCATED]" || !wire.Transaction.Response.BodyTruncated {
		t.Fatalf("serialized response body len=%d truncated=%v", len(wire.Transaction.Response.Body), wire.Transaction.Response.BodyTruncated)
	}

	// 回归形状：未超限响应体原样保留、无截断标记位（同测试第二事务）。
	tx2 := waf.NewTransaction()
	defer tx2.Close()
	tx2.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx2.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	tx2.ProcessRequestHeaders()
	tx2.AddResponseHeader("Content-Type", "text/plain")
	tx2.ProcessResponseHeaders(200, "HTTP/1.1")
	if _, _, err := tx2.WriteResponseBody([]byte("leak:small")); err != nil {
		t.Fatalf("WriteResponseBody small: %v", err)
	}
	if intr, err := tx2.ProcessResponseBody(); err != nil || intr == nil {
		t.Fatalf("small response must interrupt: intr=%v err=%v", intr, err)
	}
	tx2.ProcessLogging()
	select {
	case al = <-capture.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("small response audit snapshot was not captured")
	}
	sresp2, ok := al.Transaction().Response().(*auditSnapshotResponse)
	if !ok {
		t.Fatalf("snapshot response type = %T", al.Transaction().Response())
	}
	if got := sresp2.Body(); got != "leak:small" {
		t.Fatalf("small response body must pass through unchanged, got len=%d", len(got))
	}
}

// 审计快照的 Args() 提升源必须是「冻结」接口值（同动态类型
// typed-nil），不得引用 coraza 事务活对象——drain 侧格式化恒晚于 tx.Close，
// 活引用在事务回池复用后会读到下一请求的参数。冻结后 Args() 返回空集合。
func TestAuditSnapshotRequest_argsFrozen(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	capture := &captureFormatter{ch: make(chan plugintypes.AuditLog, 4)}
	plugins.RegisterAuditLogFormatter("lbcapture", capture)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbcapture",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABCIJDEFHKZ",
		"SecRule ARGS:payload \"@streq hit\" \"id:990004,phase:2,deny,status:403,log,msg:'probe-body'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodPost, "/probe", nil)
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
	tx.ProcessLogging()

	var al plugintypes.AuditLog
	select {
	case al = <-capture.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("audit snapshot was not captured")
	}
	// 快照已在 tx 存活时构建：此刻冻结形态已生效（不是等 tx.Close 后才成立）。
	snapshotReq := al.Transaction().Request()
	sr, ok := snapshotReq.(*auditSnapshotRequest)
	if !ok {
		t.Fatalf("snapshot request type = %T", snapshotReq)
	}
	embedded := sr.AuditLogTransactionRequest
	if embedded == nil {
		t.Fatal("embedded args source must be present for interface promotion")
	}
	if rv := reflect.ValueOf(embedded); !rv.IsNil() {
		t.Fatalf("embedded request must be a typed-nil freeze, got live %T", embedded)
	}
	args := snapshotReq.Args()
	if args == nil {
		t.Fatal("frozen Args() must return an empty collection (coraza nil-receiver branch)")
	}
	if got := args.Get("payload"); len(got) != 0 {
		t.Fatalf("frozen Args() leaked request arguments: %v", got)
	}
	// 回归形状：其余字段仍来自自持快照。
	if snapshotReq.Body() != "payload=hit" || snapshotReq.Method() != http.MethodPost {
		t.Fatalf("snapshot body/method drifted: %q %q", snapshotReq.Body(), snapshotReq.Method())
	}
}

// Given: writer.Close() 被调用（coraza v3.8.1 实际从不调用它）
// When: 之后继续 Write
// Then: 管线不拆——同 target 仍返回同一实例、drain 仍在跑，行照常经 drain
// 注入计时后落盘（审计事件不因收尾语义丢失，也不退化为同步直写）。
func TestAuditWriter_closeKeepsProcessSingletonPipeline(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	cfg := plugintypesConfigFor(t, logPath)
	cfg.Formatter = fullJSONFormatter{}
	w := &lbAuditWriter{}
	if err := w.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	pipeline := w.pipeline
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
	auditTimingRecord(id1, timingSegmentEnd, 42)
	auditTimingClose(id1)
	lines := waitAuditLines(t, logPath, 1)
	if !strings.Contains(lines[0], id1Tx) {
		t.Fatalf("first row = %s", lines[0])
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Then：同 target 再取仍是同一实例，drain 未退出（进程级单例）。
	again, err := acquireAuditPipeline(logPath, cfg.FileMode)
	if err != nil {
		t.Fatalf("acquire after Close: %v", err)
	}
	if again != pipeline {
		t.Fatal("Close must not tear down the process-level pipeline")
	}
	select {
	case <-pipeline.done:
		t.Fatal("drain goroutine exited after Close")
	default:
	}

	// 关闭后写入：仍由活 drain 消费并注入计时（注入在 drain 侧等待终态）。
	auditTimingRecord(id2, timingSegmentEnd, 7)
	auditTimingClose(id2)
	id2Tx := driveProbeTx(t, waf, id2)
	if err := w.Write(nil); err != nil {
		t.Fatalf("Write(nil) must be no-op, got %v", err)
	}

	lines = waitAuditLines(t, logPath, 2)
	var sawID2Timing bool
	for _, line := range lines {
		if strings.Contains(line, id2Tx) {
			if !strings.Contains(line, `"end_us":7`) {
				t.Fatalf("row after Close missing injected timing: %s", line)
			}
			sawID2Timing = true
		}
	}
	if !sawID2Timing {
		t.Fatalf("row written after Close was dropped: %v", lines)
	}
}

// Given: 有界队列（容量 2）且 drain 未消费
// When: 先填满 2 条，再入队第 3 条
// Then: 入队有界等待后丢弃（不再无限阻塞请求路径），丢弃计数 +1 且只丢该条；
// drain 启动后新条目照常入队并落盘。
func TestAuditPipeline_enqueueDropsWhenFullBeyondTimeout(t *testing.T) {
	useTestAuditPipeline(t)
	oldTimeout := auditEnqueueTimeout
	auditEnqueueTimeout = 30 * time.Millisecond
	t.Cleanup(func() { auditEnqueueTimeout = oldTimeout })
	oldLog := auditDropLogf
	var dropLogs atomic.Int32
	auditDropLogf = func(string, ...any) { dropLogs.Add(1) }
	t.Cleanup(func() { auditDropLogf = oldLog })

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	p := &auditPipeline{
		target: logPath,
		queue:  make(chan lbAuditItem, 2),
		done:   make(chan struct{}),
	}
	if err := p.openFile(0o644); err != nil {
		t.Fatalf("open: %v", err)
	}

	// 同步填满队列（无 drain 消费）
	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"a":1}`)}})
	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"b":2}`)}})

	// 第 3 条入队：有界等待后丢弃（不得无限阻塞请求路径）
	pendingBefore := p.pending.Load()
	bytesBefore := p.queueBytes.Load()
	start := time.Now()
	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"c":3}`)}})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("enqueue blocked %v on full queue; must be bounded by auditEnqueueTimeout", elapsed)
	}
	// 丢弃路径必须回滚准入时预扣的 pending/queueBytes——漏回滚会让
	// flushQuiesced 的 pending==0 判据恒不成立（每次收尾都等满 3s）。
	if got := p.pending.Load(); got != pendingBefore {
		t.Fatalf("pending=%d after timeout drop, want %d（准入预扣未回滚）", got, pendingBefore)
	}
	if got := p.queueBytes.Load(); got != bytesBefore {
		t.Fatalf("queueBytes=%d after timeout drop, want %d（字节占额未回滚）", got, bytesBefore)
	}
	if got := p.dropped.Load(); got != 1 {
		t.Fatalf("dropped count=%d, want 1", got)
	}
	if got := dropLogs.Load(); got == 0 {
		t.Fatal("dropped audit line must be reported via warn log")
	}
	if got := len(p.queue); got != 2 {
		t.Fatalf("queue length=%d, want 2 (only the third line dropped)", got)
	}

	// drain 启动后队列消化，新条目照常入队并落盘（丢弃不是永久失效）。
	go p.drain()
	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"d":4}`)}})
	close(p.queue)
	<-p.done
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	for _, want := range []string{`{"a":1}`, `{"b":2}`, `{"d":4}`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("audit log missing %s after drain: %q", want, data)
		}
	}
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

	// 字节保真：插入必须是字节级拼接——HTML 敏感字符不得被转义成 \u003c
	// （重编码会让行体最多放大 6×），顶层键序不得被重排。
	rawBody := `{"transaction":{"request":{"body":"a<b>c&d"}},"messages":[{"m":"x"}]}`
	out = injectAuditTiming([]byte(rawBody), auditTimingSnapshot{preUs: 7, preSet: true})
	if strings.Contains(string(out), `\u003c`) || strings.Contains(string(out), `\u0026`) {
		t.Fatalf("注入不得重编码/转义原行: %s", out)
	}
	if !strings.HasPrefix(string(out), `{"transaction":`) {
		t.Fatalf("注入不得重排顶层键序: %s", out)
	}
	if !json.Valid(out) {
		t.Fatalf("注入后必须是合法 JSON: %s", out)
	}
	doc = nil
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("注入行解码: %v", err)
	}
	if string(doc["transaction"]) != `{"request":{"body":"a<b>c&d"}}` {
		t.Fatalf("transaction 必须逐字节保留: %s", doc["transaction"])
	}

	// 行尾空白/换行：注入后输出为单行对象（行分隔由 appendLine 统一追加），
	// 与重编码时代的输出形态一致，不产生双换行。
	if out := injectAuditTiming([]byte("{\"k\":1}\n"), auditTimingSnapshot{endUs: 3, endSet: true}); strings.HasSuffix(string(out), "\n") {
		t.Fatalf("注入后不得保留 formatter 行尾换行（避免双换行）: %q", out)
	}
}

// 注册表钉：record→wait（未终态，超时返回部分快照）→close→wait 立即返回完整快照。
func TestAuditTimingRegistry_recordWaitClose(t *testing.T) {
	useTestAuditPipeline(t)
	const id = "0123456789abcdef"

	// 未知 tid（注册表无条目）首轮即返空快照——不轮询到超时
	// （旧行为本断言必红：轮询走满超时）。条目稍后创建也不追加等待（预检拦行
	// 的微秒级建条窗口由 drain 侧格式化先行吸收，见 auditTimingWait 注释）。
	// 零轮询钉替代挂钟阈值（CI 负载抖动下挂钟断言会假红）。
	auditTimingPollCountForTest.Store(0)
	snap := auditTimingWait(id, 30*time.Millisecond)
	if n := auditTimingPollCountForTest.Load(); n != 0 {
		t.Fatalf("unknown entry must return immediately without polling (AUD-1), polls=%d", n)
	}
	if snap.preSet || snap.endSet {
		t.Fatalf("unknown entry must yield empty snapshot: %+v", snap)
	}

	auditTimingRecord(id, timingSegmentPre, 11)
	// 未终态：wait 走满超时并返回部分快照（pre 在场）
	snap = auditTimingWait(id, 30*time.Millisecond)
	if !snap.preSet || snap.preUs != 11 || snap.closed {
		t.Fatalf("partial snapshot = %+v; want pre=11 unclosed", snap)
	}

	auditTimingRecord(id, timingSegmentEnd, 22)
	auditTimingClose(id)
	auditTimingPollCountForTest.Store(0)
	snap = auditTimingWait(id, time.Second)
	if n := auditTimingPollCountForTest.Load(); n != 0 {
		t.Fatalf("closed entry must return on first read without polling, polls=%d", n)
	}
	if !snap.closed || snap.preUs != 11 || snap.endUs != 22 || !snap.preSet || !snap.endSet {
		t.Fatalf("final snapshot = %+v; want closed pre=11 end=22", snap)
	}

	// 空 ID 短路
	if snap := auditTimingWait("", time.Millisecond); snap.preSet || snap.endSet {
		t.Fatal("empty id must short-circuit")
	}
	auditTimingRecord("", timingSegmentPre, 1)
	auditTimingClose("")
}

// 注册表清理钉：TTL 过期条目在批量写入点被清扫，新条目保留（无界增长防线）。
func TestAuditTimingRegistry_sweep(t *testing.T) {
	useTestAuditPipeline(t)
	const stale = "aaaaaaaaaaaaaaaa"
	seedAuditTimingEntryForTest(stale, time.Now().Add(-time.Hour))

	for i := range 128 { // 跨过 sweep 周期（64）多批
		auditTimingRecord(fmt.Sprintf("bbbbbbbbbbbb%04x", i), timingSegmentPre, int64(i))
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

func TestAuditTimingRegistry_sweepClosesWaitedEntry(t *testing.T) {
	useTestAuditPipeline(t)
	const id = "cccccccccccccccc"
	seedAuditTimingEntryForTest(id, time.Now().Add(-time.Hour))

	result := make(chan auditTimingSnapshot, 1)
	go func() {
		result <- auditTimingWait(id, 30*time.Millisecond)
	}()
	// 等到 wait 已取出条目指针并完成首轮未终态读取，再从注册表清扫；
	// 旧实现只 delete 不置 closed，wait 只能轮询到超时并返回未终态快照。
	deadline := time.Now().Add(time.Second)
	for auditTimingPollCountForTest.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if auditTimingPollCountForTest.Load() == 0 {
		t.Fatal("wait did not observe the seeded unclosed entry")
	}
	auditTimingMu.Lock()
	auditTimingSweepLocked(time.Now())
	_, exists := auditTimingEntries[id]
	auditTimingMu.Unlock()
	if exists {
		t.Fatal("expired entry must still be removed from the registry")
	}

	select {
	case snap := <-result:
		if !snap.closed {
			t.Fatalf("swept entry returned unclosed after wait timeout: %+v", snap)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not finish after its entry was swept")
	}
}

// 清扫成本必须随「过期条目数」增长，而不是注册表规模——旧实现
// 每 64 次建条全表 map 扫描（O(n)，n≈TTL×RPS ⇒ CPU 随 RPS² 增长）。
func TestAuditTimingRegistry_sweepCostIsIncremental(t *testing.T) {
	useTestAuditPipeline(t)
	auditTimingEntryTTLNs.Store(int64(time.Hour)) // 焦点在清扫检查量，不让新条目过期

	const expired = 100
	base := time.Now().Add(-2 * time.Hour)
	for i := range expired {
		seedAuditTimingEntryForTest(fmt.Sprintf("%016x", i), base)
	}
	const fresh = 5000
	for i := range fresh {
		auditTimingRecord(fmt.Sprintf("%016x", 0x10000+i), timingSegmentPre, 0)
	}

	auditTimingMu.Lock()
	entries := len(auditTimingEntries)
	auditTimingMu.Unlock()
	if entries < fresh {
		t.Fatalf("fresh entries must survive, got %d", entries)
	}
	// 期间触发约 fresh/64≈78 次清扫：检查量 ≈ 过期条目数 + 每次一条未过期队首。
	// 旧实现每次全表扫描 ⇒ 约 Σn/64 ≈ 19 万次检查。
	if visits := auditTimingSweepVisitsForTest.Load(); visits > expired+2*(fresh/64) {
		t.Fatalf("sweep visited %d queue entries; want O(expired) not O(registry)", visits)
	}
}

// close 不再建条（未知 tid 的 drain 首轮即返，close 建条只占 TTL
// 条目）；已有条目照常置终态。
func TestAuditTimingClose_requiresExistingEntry(t *testing.T) {
	useTestAuditPipeline(t)
	auditTimingClose("dddddddddddddddd")

	auditTimingMu.Lock()
	_, created := auditTimingEntries["dddddddddddddddd"]
	count := len(auditTimingEntries)
	auditTimingMu.Unlock()
	if created || count != 0 {
		t.Fatalf("close must not create entries, got %d entries", count)
	}

	auditTimingRecord("eeeeeeeeeeeeeeee", timingSegmentPre, 5)
	auditTimingClose("eeeeeeeeeeeeeeee")
	if snap := auditTimingLookupForTest(t, "eeeeeeeeeeeeeeee"); !snap.closed {
		t.Fatal("close must mark an existing entry as terminal")
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

// 管线是进程级单例：同 target 的并发 acquire 恒返回同一实例（不重建 fd/
// drain，也不做引用计数—上游从不调 AuditLogWriter.Close，refs 计数无消费方）。
func TestAcquireAuditPipeline_processSingleton(t *testing.T) {
	useTestAuditPipeline(t)
	target := filepath.Join(t.TempDir(), "audit.log")
	first, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	const workers = 16
	results := make([]*auditPipeline, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := acquireAuditPipeline(target, 0o644)
			if err != nil {
				return
			}
			results[i] = p
		}(i)
	}
	wg.Wait()
	for i, p := range results {
		if p == nil {
			t.Fatalf("worker %d acquire failed", i)
		}
		if p != first {
			t.Fatalf("worker %d got a distinct pipeline for the same target (fd/drain rebuild)", i)
		}
	}
}

// 注册表条目硬上限——无 counter 路由时代理层校验
// 之外的纵深（任何新 key 生产路径都不得让注册表无界增长）。满时拒绝新键，
// 既有键的分段写入不受影响。
func TestAuditTimingRegistry_entryCap(t *testing.T) {
	useTestTimingRegistry(t)
	origCap := auditTimingMaxEntries
	auditTimingMaxEntries = 4
	t.Cleanup(func() { auditTimingMaxEntries = origCap })

	ids := []string{"0000000000000001", "0000000000000002", "0000000000000003", "0000000000000004"}
	for _, id := range ids {
		auditTimingRecord(id, timingSegmentPre, 1)
	}
	if got := len(auditTimingEntriesSnapshotForTest(t)); got != 4 {
		t.Fatalf("cap=4 must admit 4 entries, got %d", got)
	}

	// 第 5 个新键被拒绝（注册表不增长）；既有键照常更新。
	auditTimingRecord("0000000000000005", timingSegmentPre, 1)
	if got := len(auditTimingEntriesSnapshotForTest(t)); got != 4 {
		t.Fatalf("new key beyond cap must be dropped, got %d entries", got)
	}
	auditTimingRecord("0000000000000001", timingSegmentEnd, 2)
	if snap := auditTimingLookupForTest(t, "0000000000000001"); !snap.endSet {
		t.Fatal("existing entry must still accept segments at cap")
	}

	// 畸形形状：非 16-hex key 连单条都不得建（auditTimingRecord 自身纵深）。
	auditTimingRecord("not-a-valid-id", timingSegmentPre, 1)
	if snap := auditTimingLookupForTest(t, "not-a-valid-id"); snap.preSet {
		t.Fatal("malformed id must be rejected at registry write")
	}
}

// 周期清扫——旧实现清扫仅由建条驱动（停流后过期条目永久驻留）。
// 后台 sweeper 按周期弹出 TTL 过期条目，零建条流量下注册表也必须收敛。
func TestAuditTimingRegistry_periodicSweep(t *testing.T) {
	useTestTimingRegistry(t)
	origInterval := auditTimingSweepIntervalNs.Load()
	auditTimingSweepIntervalNs.Store(int64(5 * time.Millisecond))
	t.Cleanup(func() { auditTimingSweepIntervalNs.Store(origInterval) })

	// 种入已过期条目（不经建条路径——建条驱动的清扫不触发）。
	seedAuditTimingEntryForTest("00000000000000aa", time.Now().Add(-2*time.Duration(auditTimingEntryTTLNs.Load())))
	startAuditTimingSweeperForTest()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := len(auditTimingEntriesSnapshotForTest(t)); got == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("expired entry must be reaped by the periodic sweeper without new traffic")
}

// panicFormatter 首次 Format 直接 panic（模拟 formatter/快照实现的异常），
// 其后恢复正常输出。
type panicFormatter struct {
	calls atomic.Int32
}

func (f *panicFormatter) Format(plugintypes.AuditLog) ([]byte, error) {
	if f.calls.Add(1) == 1 {
		panic("formatter exploded")
	}
	return []byte(`{"after":1}`), nil
}

func (*panicFormatter) MIME() string { return "application/json" }

// drain 是进程级单例消费者：单条处理中的 panic 不得终止 goroutine（终止后
// 写侧再无消费者，审计行只能靠超时丢弃）。panic 后必须继续消费后续条目。
func TestAuditDrain_recoversFromProcessPanic(t *testing.T) {
	useTestAuditPipeline(t)
	oldLog := auditDropLogf
	var recovered atomic.Int32
	auditDropLogf = func(string, ...any) { recovered.Add(1) }
	t.Cleanup(func() { auditDropLogf = oldLog })

	logPath := filepath.Join(t.TempDir(), "audit.log")
	p := &auditPipeline{
		target: logPath,
		queue:  make(chan lbAuditItem, 4),
		done:   make(chan struct{}),
	}
	if err := p.openFile(0o644); err != nil {
		t.Fatalf("open: %v", err)
	}
	go p.drain()

	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: &panicFormatter{}})
	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"after-panic":2}`)}})

	line := waitAuditLine(t, logPath)
	if !strings.Contains(line, `"after-panic":2`) {
		t.Fatalf("drain did not survive formatter panic: %q", line)
	}
	if recovered.Load() == 0 {
		t.Fatal("recovered panic must be reported via warn log")
	}

	close(p.queue)
	<-p.done
}

// 长请求（生命周期 > 条目 TTL）不得丢预检段：条目被 TTL 清扫时把已到场的
// pre 段转入独立的预检保留区；终态写入重建条目时回填 pre。旧实现整条丢弃，
// 审计行 pre_us 显示「—」（慢上游/流式下载场景常见）。
func TestAuditTimingRegistry_retainsPreAcrossEntryTTL(t *testing.T) {
	useTestAuditPipeline(t)
	origRetention := auditPreRetentionTTLNs.Load()
	auditPreRetentionTTLNs.Store(int64(time.Hour))
	t.Cleanup(func() { auditPreRetentionTTLNs.Store(origRetention) })

	const id = "eeeeeeeeeeeeeeee"
	auditTimingRecord(id, timingSegmentPre, 1234)
	// 越过条目 TTL（useTestAuditPipeline 置 50ms）后清扫：模拟长请求仍在途中。
	time.Sleep(80 * time.Millisecond)
	auditTimingMu.Lock()
	auditTimingSweepLocked(time.Now())
	_, stillThere := auditTimingEntries[id]
	auditTimingMu.Unlock()
	if stillThere {
		t.Fatal("expired timing entry must be swept")
	}

	// 终态分段迟到（重建条目）：pre 必须从预检保留区回填。
	auditTimingRecord(id, timingSegmentEnd, 999)
	snap := auditTimingWait(id, 20*time.Millisecond)
	if !snap.preSet || snap.preUs != 1234 {
		t.Fatalf("pre segment lost across entry TTL: %+v（长请求必须保留预检段）", snap)
	}
	if !snap.endSet || snap.endUs != 999 {
		t.Fatalf("end segment missing: %+v", snap)
	}
}

// 预检保留区自身必须有界：超过保留期即回收（不成为第二张无界表）。
func TestAuditTimingRegistry_preRetentionExpires(t *testing.T) {
	useTestAuditPipeline(t)
	origRetention := auditPreRetentionTTLNs.Load()
	auditPreRetentionTTLNs.Store(int64(10 * time.Millisecond))
	t.Cleanup(func() { auditPreRetentionTTLNs.Store(origRetention) })

	const id = "ffffffffffffffff"
	auditTimingRecord(id, timingSegmentPre, 7)
	time.Sleep(80 * time.Millisecond)
	auditTimingMu.Lock()
	auditTimingSweepLocked(time.Now())                  // 条目过期 → pre 转保留区
	auditTimingSweepLocked(time.Now().Add(time.Minute)) // 保留期同样过期 → 回收
	retained := len(auditRetainedPreEntries)
	auditTimingMu.Unlock()
	if retained != 0 {
		t.Fatalf("retained pre entries=%d, want 0（保留期到期必须回收）", retained)
	}
}

// jsonStringEscapedLen 与 json.Marshal 逐字节等值钉：控制字符/HTML 安全
// 字符/短转义/多字节 UTF-8/非法 UTF-8 全形态随机对拍——估算若与真实编码
// 分叉，64KiB 上限口径会静默失真（超限漏丢或误丢）。
func TestJSONStringEscapedLen_matchesEncodingJSON(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261022, 90))
	alphabet := []rune("ab AZ09\"\\<>&=\b\f\n\r\t\x00\x1f\x7f中文字符é\u2028\u2029\ufffd")
	check := func(s string) {
		t.Helper()
		quoted, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal(%q): %v", s, err)
		}
		if got, want := jsonStringEscapedLen(s), len(quoted)-2; got != want {
			t.Fatalf("jsonStringEscapedLen(%q)=%d, want %d（与 json.Marshal 等值）", s, got, want)
		}
	}
	check("")
	for range 2000 {
		n := rng.IntN(24)
		buf := make([]byte, 0, n*3)
		for range n {
			switch rng.IntN(8) {
			case 0: // 非法 UTF-8 裸字节
				buf = append(buf, byte(0x80+rng.IntN(0x80)))
			default:
				buf = append(buf, string(alphabet[rng.IntN(len(alphabet))])...)
			}
		}
		check(string(buf))
	}
}

// 快照 headers 有界口径（与 part C/E 同 64KiB 上限）：伪造的客户端丢弃计数
// 键在首个受信触点剥离；超限按序列化体积降序丢条目并以合成键记数。返回的
// 精确字节数必须与实际序列化体积一致（差 ≤1 字节的上界），入队预算据此执法。
func TestSnapshotAuditHeaders_boundedWithMarker(t *testing.T) {
	t.Run("上限内深拷贝且剥离伪造标记", func(t *testing.T) {
		src := map[string][]string{
			"Host":                {"a.example.com"},
			"_lb_dropped_headers": {"999"},
		}
		got, exact := snapshotAuditHeaders(src)
		if _, ok := got[auditSnapshotDroppedHeadersKey]; ok {
			t.Fatalf("客户端伪造的丢弃计数键必须剥离: %v", got)
		}
		if len(got) != 1 || got["Host"][0] != "a.example.com" {
			t.Fatalf("真实头必须保留: %v", got)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if exact < int64(len(raw)) || exact > int64(len(raw))+1 {
			t.Fatalf("精确字节=%d, want %d..%d（须与序列化体积一致）", exact, len(raw), len(raw)+1)
		}
		src["Host"][0] = "mutated"
		if got["Host"][0] != "a.example.com" {
			t.Fatal("快照必须深拷贝（源改动不得穿透）")
		}
	})

	t.Run("超限丢最大条目并记数", func(t *testing.T) {
		src := map[string][]string{
			"Host":       {"a.example.com"},
			"User-Agent": {"probe"},
			"X-Big":      {strings.Repeat("B", auditHeadersMaxBytes)},
		}
		got, exact := snapshotAuditHeaders(src)
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > auditHeadersMaxBytes {
			t.Fatalf("快照 headers 序列化 %d 字节，超过 %d 上限", len(raw), auditHeadersMaxBytes)
		}
		if exact < int64(len(raw)) || exact > int64(len(raw))+1 {
			t.Fatalf("截断后精确字节=%d, want %d..%d（上界不得超过 1 字节）", exact, len(raw), len(raw)+1)
		}
		if _, ok := got["X-Big"]; ok {
			t.Fatal("最大条目必须首先丢弃")
		}
		if got["Host"][0] != "a.example.com" || got["User-Agent"][0] != "probe" {
			t.Fatalf("小条目必须保留: %v", got)
		}
		if values := got[auditSnapshotDroppedHeadersKey]; len(values) != 1 || values[0] != "1" {
			t.Fatalf("丢弃计数键=%v, want [\"1\"]", got[auditSnapshotDroppedHeadersKey])
		}
	})
}

// 头部密集形态的字节估算必须用快照侧已算出的精确序列化字节：5000 条三字符
// header（请求+响应各一份）实际序列化 ~131KiB，旧实现按每条 (键 48 + 值 16)
// 固定开销重估成 ~700KiB（5.7×），在按字节预算执法/单条上限判定下会把真实
// ~131KiB 的头部密集高价值行误判成超限。钉两点：估算不低于实际、不夸大实际
// （旧固定开销口径的数倍高估不得回归），且入队不因估算失真丢行。
func TestEstimateAuditSnapshotBytes_headerDenseExactBytesUnderItemCap(t *testing.T) {
	// 5000 个互不相同的三字符键（aaa..，26 进制）。
	headers := make(map[string][]string, 5000)
	for i := range 5000 {
		n := i
		key := []byte{'a', 'a', 'a'}
		for pos := 2; pos >= 0; pos-- {
			key[pos] = byte('a' + n%26)
			n /= 26
		}
		headers[string(key)] = []string{string(key)}
	}
	reqHeaders, reqExact := snapshotAuditHeaders(headers)
	respHeaders, respExact := snapshotAuditHeaders(headers)
	if reqExact <= 0 || respExact <= 0 {
		t.Fatalf("精确字节缺失: req=%d resp=%d", reqExact, respExact)
	}
	// 5000 条 14 字节条目 = 70KB > 64KiB 上限 → 两侧各被裁剪到上限内。
	if reqExact > auditHeadersMaxBytes || respExact > auditHeadersMaxBytes {
		t.Fatalf("快照 header 字节 req=%d resp=%d 超过 %d 上限", reqExact, respExact, auditHeadersMaxBytes)
	}
	snap := &auditSnapshot{}
	snap.Transaction_.Request_ = &auditSnapshotRequest{Headers_: reqHeaders, HeadersBytes_: reqExact}
	snap.Transaction_.Response_ = &auditSnapshotResponse{Headers_: respHeaders, HeadersBytes_: respExact}

	serialized, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	got := estimateAuditSnapshotBytes(snap)
	if got < int64(len(serialized)) {
		t.Fatalf("估算 %d < 序列化 %d：低估会让实际驻留突破字节预算", got, len(serialized))
	}
	// 旧口径（48/16 固定开销）对照：同一快照会被估成 ~5.7×——精确估算必须
	// 显著低于该高估（比值下界 3×），否则「按条固定开销」回归会再次把真实
	// ~131KiB 估算成数百 KiB 挤压队列预算与单条上限。
	var legacy int64 = auditSnapshotFixedBytes
	for _, hs := range []map[string][]string{reqHeaders, respHeaders} {
		for k, vs := range hs {
			legacy += int64(len(k)) + 48
			for _, v := range vs {
				legacy += int64(len(v)) + 16
			}
		}
	}
	if legacy < 3*got {
		t.Fatalf("夹具无效：旧固定开销口径估算 %d 未显著高于精确估算 %d（应 ≥3×）", legacy, got)
	}
	if got > auditItemMaxBytes {
		t.Fatalf("精确估算 %d > 单条上限 %d（整行仍会被丢弃）", got, auditItemMaxBytes)
	}

	// 入队路径：不因估算失真丢弃该行。
	p := &auditPipeline{
		target: filepath.Join(t.TempDir(), "audit.log"),
		queue:  make(chan lbAuditItem, 2),
		done:   make(chan struct{}),
	}
	if err := p.openFile(0o644); err != nil {
		t.Fatal(err)
	}
	p.enqueue(lbAuditItem{snap: snap, formatter: cannedFormatter{body: []byte(`{"row":"header-dense"}`)}})
	if dropped := p.dropped.Load(); dropped != 0 {
		t.Fatalf("dropped=%d, want 0（头部密集行不得因估算失真被整行丢弃）", dropped)
	}
	if length := len(p.queue); length != 1 {
		t.Fatalf("queue length=%d, want 1", length)
	}
}

// 转义密集体的最坏形态：64KiB 全 `&`（表单体天然密集）在 JSON 转义口径下
// 展开为 384KiB/段。单条上限必须按最坏转义比推导——旧「四段原始字节+余量」
// 的 320KiB 上限让请求/响应体仅体一项就超限，整条安全事件被丢弃（攻击者
// 可用体字符分布让自身事件不留库）。钉：估算 ≥ 实际序列化、≤ 单条上限，
// 且入队零丢弃。
func TestEstimateAuditSnapshotBytes_escapeDenseBodiesUnderItemCap(t *testing.T) {
	dense := strings.Repeat("&", auditBodyMaxBytes)
	if got, truncated := snapshotAuditBody(dense); truncated || len(got) != auditBodyMaxBytes {
		t.Fatalf("夹具无效：64KiB 原始体不应被体截断（len=%d truncated=%v）", len(got), truncated)
	}
	snap := &auditSnapshot{}
	snap.Transaction_.Request_ = &auditSnapshotRequest{Body_: dense}
	snap.Transaction_.Response_ = &auditSnapshotResponse{Body_: dense}

	serialized, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	got := estimateAuditSnapshotBytes(snap)
	if got < int64(len(serialized)) {
		t.Fatalf("估算 %d < 序列化 %d：低估会让实际驻留突破字节预算", got, len(serialized))
	}
	// 旧上限（四段原始字节 + 余量 = 320KiB）必被越限——夹具有效性反证。
	const legacyItemCap int64 = 320 * 1024
	if got <= legacyItemCap {
		t.Fatalf("夹具无效：转义密集体估算 %d 本应越过旧上限 %d", got, legacyItemCap)
	}
	if got > auditItemMaxBytes {
		t.Fatalf("转义密集体估算 %d > 单条上限 %d（整行仍会被丢弃）", got, auditItemMaxBytes)
	}

	p := &auditPipeline{
		target: filepath.Join(t.TempDir(), "audit.log"),
		queue:  make(chan lbAuditItem, 2),
		done:   make(chan struct{}),
	}
	if err := p.openFile(0o644); err != nil {
		t.Fatal(err)
	}
	p.enqueue(lbAuditItem{snap: snap, formatter: cannedFormatter{body: []byte(`{"row":"escape-dense"}`)}})
	if dropped := p.dropped.Load(); dropped != 0 {
		t.Fatalf("dropped=%d, want 0（64KiB 全 `&` 体不得整行丢弃）", dropped)
	}
	if length := len(p.queue); length != 1 {
		t.Fatalf("queue length=%d, want 1", length)
	}
}

// headerProbe* 是只携带 headers 的最小 AuditLog 实现（快照精确字节接线单测）：
// 嵌入 nil 接口补足不可命名的 Args() 等方法，覆盖快照实际读取的方法。
type headerProbeAuditLog struct{ tx headerProbeTx }

func (l headerProbeAuditLog) Parts() types.AuditLogParts { return nil }
func (l headerProbeAuditLog) Transaction() plugintypes.AuditLogTransaction {
	return l.tx
}
func (l headerProbeAuditLog) Messages() []plugintypes.AuditLogMessage { return nil }

type headerProbeTx struct {
	plugintypes.AuditLogTransaction
	req  headerProbeReq
	resp headerProbeResp
}

func (t headerProbeTx) Timestamp() string       { return "" }
func (t headerProbeTx) UnixTimestamp() int64    { return 0 }
func (t headerProbeTx) ID() string              { return "tx-header-probe" }
func (t headerProbeTx) ClientIP() string        { return "" }
func (t headerProbeTx) ClientPort() int         { return 0 }
func (t headerProbeTx) HostIP() string          { return "" }
func (t headerProbeTx) HostPort() int           { return 0 }
func (t headerProbeTx) ServerID() string        { return "" }
func (t headerProbeTx) HighestSeverity() string { return "" }
func (t headerProbeTx) IsInterrupted() bool     { return false }
func (t headerProbeTx) Request() plugintypes.AuditLogTransactionRequest {
	return t.req
}
func (t headerProbeTx) Response() plugintypes.AuditLogTransactionResponse {
	return t.resp
}
func (t headerProbeTx) Producer() plugintypes.AuditLogTransactionProducer { return nil }

type headerProbeReq struct {
	plugintypes.AuditLogTransactionRequest
	headers map[string][]string
}

func (r headerProbeReq) Method() string               { return "GET" }
func (r headerProbeReq) Protocol() string             { return "HTTP/1.1" }
func (r headerProbeReq) URI() string                  { return "/probe" }
func (r headerProbeReq) HTTPVersion() string          { return "HTTP/1.1" }
func (r headerProbeReq) Headers() map[string][]string { return r.headers }
func (r headerProbeReq) Body() string                 { return "" }
func (r headerProbeReq) Files() []plugintypes.AuditLogTransactionRequestFiles {
	return nil
}
func (r headerProbeReq) Length() int32 { return 0 }

type headerProbeResp struct {
	plugintypes.AuditLogTransactionResponse
	headers map[string][]string
}

func (r headerProbeResp) Protocol() string             { return "HTTP/1.1" }
func (r headerProbeResp) Status() int                  { return 200 }
func (r headerProbeResp) Headers() map[string][]string { return r.headers }
func (r headerProbeResp) Body() string                 { return "" }

// 快照构建必须把精确 header 字节写入 HeadersBytes_（入队估算的唯一来源）：
// 请求/响应两侧都要。
func TestSnapshotTransaction_recordsExactHeaderBytes(t *testing.T) {
	reqHeaders := map[string][]string{"Host": {"a.example.com"}, "X-Probe": {"1"}}
	respHeaders := map[string][]string{"Content-Type": {"text/html"}}
	al := headerProbeAuditLog{tx: headerProbeTx{
		req:  headerProbeReq{headers: reqHeaders},
		resp: headerProbeResp{headers: respHeaders},
	}}
	snap := snapshotAuditLog(al)
	check := func(name string, hs map[string][]string, exact int64) {
		t.Helper()
		if exact == 0 {
			t.Fatalf("%s HeadersBytes_ 未写入", name)
		}
		raw, err := json.Marshal(hs)
		if err != nil {
			t.Fatal(err)
		}
		if exact < int64(len(raw)) || exact > int64(len(raw))+1 {
			t.Fatalf("%s 精确字节=%d, want %d..%d", name, exact, len(raw), len(raw)+1)
		}
	}
	if req := snap.Transaction_.Request_; req == nil {
		t.Fatal("请求快照缺失")
	} else {
		check("请求侧", req.Headers_, req.HeadersBytes_)
		// 字节记账字段不得进入 JSON（json:"-"，审计行信封零变化）。
		full, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(full), "HeadersBytes") {
			t.Fatalf("HeadersBytes_ 不得进入 JSON: %s", full)
		}
	}
	if resp := snap.Transaction_.Response_; resp == nil {
		t.Fatal("响应快照缺失")
	} else {
		check("响应侧", resp.Headers_, resp.HeadersBytes_)
	}
}

// 队列字节预算：条数上限不界字节——大快照洪峰下按字节收敛驻留。
// 超预算立即丢弃（非阻塞，不走 2s 入队等待）并计数；drain 消费后预算释放，
// 后续条目照常入队。
func TestAuditPipeline_enqueueDropsWhenByteBudgetExceeded(t *testing.T) {
	useTestAuditPipeline(t)
	oldBudget := auditQueueByteBudget
	auditQueueByteBudget = 128 * 1024
	t.Cleanup(func() { auditQueueByteBudget = oldBudget })

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	p := &auditPipeline{
		target: logPath,
		queue:  make(chan lbAuditItem, 8),
		done:   make(chan struct{}),
	}
	if err := p.openFile(0o644); err != nil {
		t.Fatalf("open: %v", err)
	}
	bigItem := func(marker string) lbAuditItem {
		snap := &auditSnapshot{}
		snap.Transaction_.ID_ = marker
		snap.Transaction_.Request_ = &auditSnapshotRequest{Body_: strings.Repeat("x", 64*1024)}
		return lbAuditItem{snap: snap, formatter: cannedFormatter{body: []byte(`{"row":"` + marker + `"}`)}}
	}

	// 第 1 条（~64.5KiB）在预算内入队；第 2 条使驻留 ~129KiB 超 128KiB 预算
	// → 立即丢弃（不等待、不占队）。
	p.enqueue(bigItem("AAA111"))
	if got := p.queueBytes.Load(); got <= 64*1024 {
		t.Fatalf("queueBytes=%d, want >64KiB after first enqueue", got)
	}
	start := time.Now()
	p.enqueue(bigItem("BBB222"))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("超预算入队必须立即丢弃，不得走有界等待: %v", elapsed)
	}
	if got := p.dropped.Load(); got != 1 {
		t.Fatalf("dropped=%d, want 1", got)
	}
	if got := len(p.queue); got != 1 {
		t.Fatalf("queue length=%d, want 1（被丢弃条不占队）", got)
	}

	// 超单条上限的快照即使空队也直接丢弃（2MiB 体 > 1MiB 单条上限）。
	huge := &auditSnapshot{}
	huge.Transaction_.Request_ = &auditSnapshotRequest{Body_: strings.Repeat("y", 2<<20)}
	p.enqueue(lbAuditItem{snap: huge, formatter: cannedFormatter{body: []byte(`{"row":"HHH999"}`)}})
	if got := p.dropped.Load(); got != 2 {
		t.Fatalf("dropped=%d, want 2（单条超限丢弃）", got)
	}
	if got := len(p.queue); got != 1 {
		t.Fatalf("queue length=%d, want 1（超限条不占队）", got)
	}

	// drain 消费后字节预算释放，新条目照常入队落盘。
	go p.drain()
	// 等 AAA111 被消费（预算释放）再入队 CCC333——否则 CCC333 的占额与
	// 尚在队中的 AAA111 叠加超预算被丢弃（竞态非确定性）。
	deadline := time.Now().Add(2 * time.Second)
	for p.queueBytes.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	p.enqueue(bigItem("CCC333"))
	close(p.queue)
	<-p.done
	if got := p.queueBytes.Load(); got != 0 {
		t.Fatalf("drain 完成后 queueBytes=%d, want 0", got)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "AAA111") || !strings.Contains(content, "CCC333") {
		t.Fatalf("预算内条目必须落盘: %s", content)
	}
	if strings.Contains(content, "BBB222") || strings.Contains(content, "HHH999") {
		t.Fatalf("被丢弃条目不得落盘: %s", content)
	}
}

// 侧车写盘失败必须可观测且可重试：失败时保留脏标记（下一 drain 节拍重试）
// 并经 auditIOLogf 节流留痕——磁盘满/目录只读时侧车双向失效，静默 return
// 会让写侧丢弃/IO 计数对面板恒 0（假绿）。
func TestWriteWriterStatsIfDue_failureKeepsDirtyAndLogs(t *testing.T) {
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
	// 侧车路径占位为目录 → WriteFile(tmp) 可行但 Rename(tmp, 目录) 失败。
	sidecar := auditWriterStatsPath(target)
	if err := os.Mkdir(sidecar, 0o755); err != nil {
		t.Fatal(err)
	}
	p := &auditPipeline{target: target, mode: 0o644}
	p.dropped.Store(2)
	p.statsDirty.Store(true)

	p.writeWriterStatsIfDue(time.Now())

	if !p.statsDirty.Load() {
		t.Fatal("sidecar write failure must keep dirty flag（下节拍重试）")
	}
	mu.Lock()
	if len(logs) == 0 {
		mu.Unlock()
		t.Fatal("sidecar write failure must be surfaced via auditIOLogf")
	}
	mu.Unlock()

	// 故障排除后同一管线重试成功落盘。
	if err := os.Remove(sidecar); err != nil {
		t.Fatal(err)
	}
	p.lastStatsWrite = time.Time{} // 越过节流窗口直验重试
	p.writeWriterStatsIfDue(time.Now().Add(auditWriterStatsInterval + time.Second))
	if p.statsDirty.Load() {
		t.Fatal("retry after recovery must clear dirty flag")
	}
	data, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatalf("sidecar not written after recovery: %v", err)
	}
	if !strings.Contains(string(data), `"dropped":2`) {
		t.Fatalf("sidecar=%s, want dropped=2", data)
	}
}

// 冲刷合并窗口：窗口内重复领取直接快进，窗口外重新领取——一次 reload 的
// N 个规则实例不再各等满 3s。
func TestAuditFlushCoalescing_claimWindow(t *testing.T) {
	oldWindow := auditFlushCoalesceWindow
	auditFlushCoalesceWindow = 20 * time.Millisecond
	t.Cleanup(func() {
		auditFlushCoalesceWindow = oldWindow
		auditLastFlushNano.Store(0)
	})
	auditLastFlushNano.Store(0)

	if !claimAuditFlush() {
		t.Fatal("首次领取必须成功")
	}
	if claimAuditFlush() {
		t.Fatal("窗口内重复领取必须快进")
	}
	time.Sleep(30 * time.Millisecond)
	if !claimAuditFlush() {
		t.Fatal("窗口过后必须可再次领取")
	}
}

// 一次 reload 里每个规则实例各调一次 Cleanup：首个付出排空等待，其余必须
// 立即返回（收尾成本不得随规则数线性叠加）。
func TestSecurityBlockedCounter_cleanupCoalescedAcrossInstances(t *testing.T) {
	useTestAuditPipeline(t)
	target := filepath.Join(t.TempDir(), "audit.log")
	w := &lbAuditWriter{}
	if err := w.Init(plugintypesConfigFor(t, target)); err != nil {
		t.Fatalf("init: %v", err)
	}
	fmtr := &gatedFormatter{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		body:    []byte(`{"coalesced":"YES"}`),
	}
	var releaseOnce sync.Once
	releaseGate := func() { releaseOnce.Do(func() { close(fmtr.release) }) }
	t.Cleanup(releaseGate)
	w.pipeline.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: fmtr})
	select {
	case <-fmtr.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("drain 未进入在途处理")
	}

	firstDone := make(chan struct{})
	go func() {
		_ = (&SecurityBlockedCounter{}).Cleanup()
		close(firstDone)
	}()
	select {
	case <-firstDone:
		t.Fatal("首个 Cleanup 在 drain 在途时必须等待排空")
	case <-time.After(100 * time.Millisecond):
	}

	// 同一次 reload 的下一个规则实例：合并窗口内直接返回，不得再等 3s。
	start := time.Now()
	if err := (&SecurityBlockedCounter{}).Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("后续 Cleanup 等待 %v；同代际重复冲刷必须快进", elapsed)
	}

	releaseGate()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("首个 Cleanup 未在排空后返回")
	}
}

// 合并窗口内被快进（不排空等待）的 Cleanup 仍必须把 bufio 残留刷盘：reload
// 领到冲刷资格后窗口内进程停止时，停机那次 Cleanup 是唯一收尾机会——省掉的
// 只能是等待，不能是刷盘，否则最后一批审计行随进程退出静默丢失。
func TestFlushAuditPipelines_coalescedStillFlushes(t *testing.T) {
	oldWindow := auditFlushCoalesceWindow
	auditFlushCoalesceWindow = time.Minute
	t.Cleanup(func() {
		auditFlushCoalesceWindow = oldWindow
		auditLastFlushNano.Store(0)
	})
	auditLastFlushNano.Store(0)

	target := filepath.Join(t.TempDir(), "audit.log")
	p := &auditPipeline{target: target, mode: 0o644}
	if err := p.openFile(0o644); err != nil {
		t.Fatalf("openFile: %v", err)
	}
	auditPipelinesMu.Lock()
	auditPipelines[target] = p
	auditPipelinesMu.Unlock()
	t.Cleanup(func() {
		auditPipelinesMu.Lock()
		delete(auditPipelines, target)
		auditPipelinesMu.Unlock()
		p.closeFile()
	})

	// Given 一次 reload 已领到冲刷资格，随后有行落在 bufio 里（500ms 周期
	// 刷盘尚未到来）
	if !claimAuditFlush() {
		t.Fatal("首个冲刷资格必须领取成功（前置条件）")
	}
	p.ioMu.Lock()
	if _, err := p.bw.WriteString("{\"tail\":1}\n"); err != nil {
		p.ioMu.Unlock()
		t.Fatalf("write bufio: %v", err)
	}
	p.ioMu.Unlock()

	// When 窗口内的停机 Cleanup
	start := time.Now()
	FlushAuditPipelines()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("窗口内 Cleanup 等待 %v；快进分支不得做排空等待", elapsed)
	}

	// Then 已刷盘（旧实现直接 return，行随进程退出丢弃）
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !strings.Contains(string(data), `{"tail":1}`) {
		t.Fatalf("审计文件=%q；窗口内快进的 Cleanup 必须刷盘", data)
	}
}

// 合并窗口内被快进的 Cleanup 仍须小额有界排空：旧实现只刷 bufio，队列/在途
// 行（≤2048）随紧随其后的进程停止静默丢失。本用例钉「窗口内 Cleanup 等到
// 在途行落盘再返回」。
func TestFlushAuditPipelines_coalescedDrainsInFlightRows(t *testing.T) {
	oldWindow := auditFlushCoalesceWindow
	auditFlushCoalesceWindow = time.Minute
	t.Cleanup(func() {
		auditFlushCoalesceWindow = oldWindow
		auditLastFlushNano.Store(0)
	})
	auditLastFlushNano.Store(0)
	useTestAuditPipeline(t)

	target := filepath.Join(t.TempDir(), "audit.log")
	w := &lbAuditWriter{}
	if err := w.Init(plugintypesConfigFor(t, target)); err != nil {
		t.Fatalf("init: %v", err)
	}
	fmtr := &gatedFormatter{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		body:    []byte(`{"coalesced-drain":"YES"}`),
	}
	var releaseOnce sync.Once
	releaseGate := func() { releaseOnce.Do(func() { close(fmtr.release) }) }
	t.Cleanup(releaseGate)
	w.pipeline.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: fmtr})
	select {
	case <-fmtr.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("drain 未进入在途处理")
	}

	// Given 上一次 reload 已领到冲刷资格（本次 Cleanup 落在合并窗口内）
	if !claimAuditFlush() {
		t.Fatal("首个冲刷资格必须领取成功（前置条件）")
	}
	// 在途行 50ms 后处理完：窗口内 Cleanup 的有界排空必须等到它
	time.AfterFunc(50*time.Millisecond, releaseGate)

	start := time.Now()
	FlushAuditPipelines()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("窗口内 Cleanup 等待 %v；有界排空必须 ≤%v", elapsed, auditFlushCoalescedDrainWait)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !strings.Contains(string(data), `{"coalesced-drain":"YES"}`) {
		t.Fatalf("审计文件=%q；窗口内 Cleanup 必须在有界窗口内排空在途行并刷盘", data)
	}
}

// estimateTestMessage 与 coraza 内置 Message 同形（导出字段进 JSON），用于
// 钉「估算 >= 实际序列化字节」。
type estimateTestMessage struct {
	Actionset_    string                   `json:"actionset"`
	Message_      string                   `json:"message"`
	ErrorMessage_ string                   `json:"error_message"`
	Data_         *estimateTestMessageData `json:"data"`
}

func (m estimateTestMessage) Actionset() string    { return m.Actionset_ }
func (m estimateTestMessage) Message() string      { return m.Message_ }
func (m estimateTestMessage) ErrorMessage() string { return m.ErrorMessage_ }
func (m estimateTestMessage) Data() plugintypes.AuditLogMessageData {
	return m.Data_
}

type estimateTestMessageData struct {
	File_     string   `json:"file"`
	Line_     int      `json:"line"`
	ID_       int      `json:"id"`
	Rev_      string   `json:"rev"`
	Msg_      string   `json:"msg"`
	Data_     string   `json:"data"`
	Severity_ int      `json:"severity"`
	Ver_      string   `json:"ver"`
	Maturity_ int      `json:"maturity"`
	Accuracy_ int      `json:"accuracy"`
	Tags_     []string `json:"tags"`
	Raw_      string   `json:"raw"`
}

func (d *estimateTestMessageData) File() string   { return d.File_ }
func (d *estimateTestMessageData) Line() int      { return d.Line_ }
func (d *estimateTestMessageData) ID() int        { return d.ID_ }
func (d *estimateTestMessageData) Rev() string    { return d.Rev_ }
func (d *estimateTestMessageData) Msg() string    { return d.Msg_ }
func (d *estimateTestMessageData) Data() string   { return d.Data_ }
func (d *estimateTestMessageData) Ver() string    { return d.Ver_ }
func (d *estimateTestMessageData) Maturity() int  { return d.Maturity_ }
func (d *estimateTestMessageData) Accuracy() int  { return d.Accuracy_ }
func (d *estimateTestMessageData) Tags() []string { return d.Tags_ }
func (d *estimateTestMessageData) Raw() string    { return d.Raw_ }
func (d *estimateTestMessageData) Severity() types.RuleSeverity {
	return types.RuleSeverity(d.Severity_)
}

// 估算必须不低于实际序列化字节：enqueue 按估算执法字节预算，低估即意味着
// 实际驻留可突破 auditQueueByteBudget 数倍（header 洪峰是主要放大器）。
func TestEstimateAuditSnapshotBytes_isUpperBound(t *testing.T) {
	mkMsg := func(pad int) estimateTestMessage {
		return estimateTestMessage{
			Actionset_: "block",
			Message_:   "SQL Injection Attack",
			Data_: &estimateTestMessageData{
				File_: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", Line_: 61,
				ID_: 942100, Rev_: "4", Msg_: "SQLi", Data_: strings.Repeat("x", pad),
				Severity_: 2, Ver_: "1.0", Maturity_: 4, Accuracy_: 8,
				Tags_: []string{"application-multi", "language-multi", "attack-sqli"},
				Raw_:  "SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/ \"@detectSQLi\"",
			},
		}
	}
	envelope := func() auditSnapshot {
		return auditSnapshot{
			Transaction_: auditSnapshotTransaction{
				Timestamp_: "23/Oct/2026:10:00:00 +0800", UnixTimestamp_: 1790000000,
				ID_: "abcdefghijklmnop", ClientIP_: "203.0.113.7", ClientPort_: 51234,
				HostIP_: "10.0.0.2", HostPort_: 443, ServerID_: "srv-1",
				Request_: &auditSnapshotRequest{
					Method_: "GET", Protocol_: "HTTP/1.1", URI_: "/admin",
					HTTPVersion_: "HTTP/1.1", Length_: 0,
					Headers_: map[string][]string{"host": {"example.com"}},
				},
				Response_: &auditSnapshotResponse{
					Protocol_: "HTTP/1.1", Status_: 403,
					Headers_: map[string][]string{"content-type": {"text/html"}},
				},
				Producer_: &auditSnapshotProducer{
					Connector_: "caddy", Version_: "v3.8.1", Server_: "coraza",
					RuleEngine_: "On", Stopwatch_: "total=1ms",
					Rulesets_: []string{"crs"},
				},
				HighestSeverity_: "CRITICAL", IsInterrupted_: true,
			},
		}
	}

	headerHeavy := envelope()
	for i := 0; i < 1000; i++ {
		headerHeavy.Transaction_.Request_.Headers_[fmt.Sprintf("h%d", i)] = []string{"v"}
	}
	filesCase := envelope()
	for i := 0; i < 200; i++ {
		filesCase.Transaction_.Request_.Files_ = append(filesCase.Transaction_.Request_.Files_,
			auditSnapshotFile{Name_: "upload.bin", Size_: 1024, Mime_: "application/octet-stream"})
	}
	messagesCase := envelope()
	for i := 0; i < 50; i++ {
		messagesCase.Messages_ = append(messagesCase.Messages_, mkMsg(64))
	}
	// HTML 安全字符在 JSON 里按 \u00XX 六字节转义：URI/body 用原始 len 估算
	// 会低估至多 6×（攻击者构造 &&&… 即可让单条实际驻留突破预算）。
	escapeHeavy := envelope()
	escapeHeavy.Transaction_.Request_.URI_ = "/" + strings.Repeat("&", 4000)
	escapeHeavy.Transaction_.Request_.Body_ = strings.Repeat("<>", 2000)
	escapeHeavy.Transaction_.Response_.Body_ = strings.Repeat("&", 4000)
	escapeHeavy.Messages_ = append(escapeHeavy.Messages_, mkMsg(0))

	cases := []struct {
		name string
		snap *auditSnapshot
	}{
		{"header 密集", &headerHeavy},
		{"上传文件", &filesCase},
		{"多 messages", &messagesCase},
		{"HTML 转义密集", &escapeHeavy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serialized, err := json.Marshal(tc.snap)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got := estimateAuditSnapshotBytes(tc.snap)
			if got < int64(len(serialized)) {
				t.Fatalf("估算 %d < 序列化 %d：预算按估算执法，低估即实际驻留可突破上限", got, len(serialized))
			}
		})
	}
}

// messageOnlyAuditLog 只承载 messages 的最小 AuditLog 实现（截断逻辑单测）。
type messageOnlyAuditLog struct {
	msgs []plugintypes.AuditLogMessage
}

func (l messageOnlyAuditLog) Parts() types.AuditLogParts { return nil }
func (l messageOnlyAuditLog) Transaction() plugintypes.AuditLogTransaction {
	return nil
}
func (l messageOnlyAuditLog) Messages() []plugintypes.AuditLogMessage { return l.msgs }

// messages 写侧上限：四段全满时，旧形态（messages 无独立上限）让单条快照
// 越过 auditItemMaxBytes 被**整行丢弃**（命中规则多的高价值行反而丢失）。
// 截断后整行保留，并在 messages_dropped 显性披露丢弃条数。
func TestSnapshotAuditLog_truncatesMessagesUnderItemCap(t *testing.T) {
	// 每条 6KB：200 条未截断共 ~1.2MB，必然越过 1MiB 单条上限（钉子有效性
	// 反证的分母；截断后 messages 自身口径仍受 32KiB 预算约束）。
	raw := make([]plugintypes.AuditLogMessage, 0, 200)
	for range 200 {
		raw = append(raw, estimateTestMessage{Message_: strings.Repeat("m", 6000)})
	}
	snap := snapshotAuditLog(messageOnlyAuditLog{msgs: raw})
	if got := len(snap.Messages_); got > auditMessagesMaxEntries {
		t.Fatalf("messages 保留 %d 条 > 上限 %d", got, auditMessagesMaxEntries)
	}
	if snap.MessagesDropped_ != len(raw)-len(snap.Messages_) || snap.MessagesDropped_ == 0 {
		t.Fatalf("messages_dropped=%d, want %d（丢弃条数须显性披露）",
			snap.MessagesDropped_, len(raw)-len(snap.Messages_))
	}
	var used int64
	for _, m := range snap.Messages_ {
		used += estimateAuditMessageBytes(m)
	}
	if used > auditMessagesMaxBytes {
		t.Fatalf("messages 估算 %d 字节 > 上限 %d", used, auditMessagesMaxBytes)
	}

	// 四段全满（请求/响应体与头各 64KiB）且体取转义最坏比（全 `&`）+
	// 截断后的 messages：必须落在单条上限内；同形但未截断的 messages 集合
	// 必然超限（钉子有效性反证）。
	dense := strings.Repeat("&", auditBodyMaxBytes)
	reqHeaders, reqExact := snapshotAuditHeaders(map[string][]string{"h": {dense}})
	respHeaders, respExact := snapshotAuditHeaders(map[string][]string{"h": {dense}})
	snap.Transaction_ = auditSnapshotTransaction{
		Request_:  &auditSnapshotRequest{Body_: dense, Headers_: reqHeaders, HeadersBytes_: reqExact},
		Response_: &auditSnapshotResponse{Body_: dense, Headers_: respHeaders, HeadersBytes_: respExact},
	}
	if size := estimateAuditSnapshotBytes(snap); size > auditItemMaxBytes {
		t.Fatalf("截断后 size=%d > 单条上限 %d（整行仍会被丢弃）", size, auditItemMaxBytes)
	}
	untruncated := *snap
	untruncated.Messages_ = raw
	untruncated.MessagesDropped_ = 0
	if estimateAuditSnapshotBytes(&untruncated) <= auditItemMaxBytes {
		t.Fatal("夹具无效：未截断 messages 形态本应超单条上限")
	}

	// 序列化后 messages_dropped 可见、messages 条数受限。
	serialized, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(serialized), `"messages_dropped":`) {
		t.Fatalf("截断标记缺失: %s", serialized[:min(len(serialized), 200)])
	}
}

// messages 截断方向必须是「掐中间、保两头」：CRS 的 949xxx/959xxx 评估汇总
// 消息位于消息序列末尾，异常分只从它的 msg 文本读 "Total Score"——只保开头
// 会把命中规则多的请求的分数截成 0（而这类请求恰是审计价值最高的）。
func TestSnapshotAuditLog_keepsThreatEvaluationMessagesWhenTruncated(t *testing.T) {
	mk := func(id int, msg string) plugintypes.AuditLogMessage {
		return estimateTestMessage{Message_: msg, Data_: &estimateTestMessageData{ID_: id, Msg_: msg}}
	}
	raw := make([]plugintypes.AuditLogMessage, 0, 200)
	for i := 0; i < 196; i++ {
		raw = append(raw, mk(942000+i, "attack "+strings.Repeat("m", 100)))
	}
	raw = append(raw,
		mk(949110, "Inbound Anomaly Score Exceeded (Total Score: 42)"),
		mk(959100, "Outbound Anomaly Score Exceeded (Total Score: 3)"),
	)
	snap := snapshotAuditLog(messageOnlyAuditLog{msgs: raw})
	if snap.MessagesDropped_ != len(raw)-len(snap.Messages_) || snap.MessagesDropped_ == 0 {
		t.Fatalf("messages_dropped=%d, want %d（中间段丢弃条数须显性披露）",
			snap.MessagesDropped_, len(raw)-len(snap.Messages_))
	}
	if got := len(snap.Messages_); got > auditMessagesMaxEntries {
		t.Fatalf("messages 保留 %d 条 > 上限 %d", got, auditMessagesMaxEntries)
	}
	var used int64
	for _, m := range snap.Messages_ {
		used += estimateAuditMessageBytes(m)
	}
	if used > auditMessagesMaxBytes {
		t.Fatalf("messages 估算 %d 字节 > 上限 %d", used, auditMessagesMaxBytes)
	}
	// 头段保留首条（攻击特征命中的起点），尾段保留评估汇总。
	if first := snap.Messages_[0]; first.(estimateTestMessage).Data_.ID_ != 942000 {
		t.Fatalf("头部首条被丢弃：id=%d（截断退化成尾部截断）",
			first.(estimateTestMessage).Data_.ID_)
	}
	kept := make(map[int]bool, len(snap.Messages_))
	for _, m := range snap.Messages_ {
		kept[m.Data().ID()] = true
	}
	for _, id := range []int{949110, 959100} {
		if !kept[id] {
			t.Fatalf("截断丢弃了评估汇总消息 %d：异常分归零/低估且无分数可解释", id)
		}
	}
	if last := snap.Messages_[len(snap.Messages_)-1]; last.Data().ID() != 959100 {
		t.Fatalf("尾段顺序被破坏：末条 id=%d, want 959100", last.Data().ID())
	}
	// 未触发上限的形态必须原序原样保留（不因截断逻辑重排）。
	small := snapshotAuditLog(messageOnlyAuditLog{msgs: raw[:3]})
	if small.MessagesDropped_ != 0 || len(small.Messages_) != 3 {
		t.Fatalf("未超限形态被截断：dropped=%d kept=%d", small.MessagesDropped_, len(small.Messages_))
	}
	for i, m := range small.Messages_ {
		if m.Data().ID() != raw[i].Data().ID() {
			t.Fatalf("未超限形态顺序改变：第 %d 条 id=%d", i, m.Data().ID())
		}
	}
}

// 分段键常量即审计行字段的 wire 契约（pre_us/end_us）：常量值被改动会改变
// 已落盘行的语义解释，必须显式钉住；注册表按常量分派（字面量 switch 会在
// 改值时静默丢分段）。
func TestAuditTimingSegmentConstants_wireContract(t *testing.T) {
	if timingSegmentPre != "pre" || timingSegmentEnd != "end" {
		t.Fatalf("分段键=%q/%q, want pre/end（审计行 pre_us/end_us 字段语义）", timingSegmentPre, timingSegmentEnd)
	}
}

// auxProbeAuditLog/auxProbeTx/auxProbeReq/auxProbeResp 是只携带
// method/uri/body/files/headers 的最小 AuditLog 实现（客户端可控段上限单测）：
// 嵌入 nil 接口补足不可命名的 Args() 等方法，其余访问器走本地值。
type auxProbeAuditLog struct{ tx auxProbeTx }

func (l auxProbeAuditLog) Parts() types.AuditLogParts { return nil }
func (l auxProbeAuditLog) Transaction() plugintypes.AuditLogTransaction {
	return l.tx
}
func (l auxProbeAuditLog) Messages() []plugintypes.AuditLogMessage { return nil }

type auxProbeTx struct {
	plugintypes.AuditLogTransaction
	req      auxProbeReq
	resp     auxProbeResp
	serverID string
}

func (t auxProbeTx) Timestamp() string       { return "" }
func (t auxProbeTx) UnixTimestamp() int64    { return 0 }
func (t auxProbeTx) ID() string              { return "tx-aux-probe" }
func (t auxProbeTx) ClientIP() string        { return "" }
func (t auxProbeTx) ClientPort() int         { return 0 }
func (t auxProbeTx) HostIP() string          { return "" }
func (t auxProbeTx) HostPort() int           { return 0 }
func (t auxProbeTx) ServerID() string        { return t.serverID }
func (t auxProbeTx) HighestSeverity() string { return "" }
func (t auxProbeTx) IsInterrupted() bool     { return false }
func (t auxProbeTx) Request() plugintypes.AuditLogTransactionRequest {
	return t.req
}
func (t auxProbeTx) Response() plugintypes.AuditLogTransactionResponse {
	if t.resp.headers == nil && t.resp.body == "" {
		return nil
	}
	return t.resp
}
func (t auxProbeTx) Producer() plugintypes.AuditLogTransactionProducer { return nil }

type auxProbeReq struct {
	plugintypes.AuditLogTransactionRequest
	method  string
	uri     string
	body    string
	headers map[string][]string
	files   []plugintypes.AuditLogTransactionRequestFiles
}

func (r auxProbeReq) Method() string {
	if r.method != "" {
		return r.method
	}
	return "POST"
}
func (r auxProbeReq) Protocol() string             { return "HTTP/1.1" }
func (r auxProbeReq) URI() string                  { return r.uri }
func (r auxProbeReq) HTTPVersion() string          { return "HTTP/1.1" }
func (r auxProbeReq) Headers() map[string][]string { return r.headers }
func (r auxProbeReq) Body() string                 { return r.body }
func (r auxProbeReq) Files() []plugintypes.AuditLogTransactionRequestFiles {
	return r.files
}
func (r auxProbeReq) Length() int32 { return 0 }

type auxProbeResp struct {
	plugintypes.AuditLogTransactionResponse
	body    string
	headers map[string][]string
}

func (r auxProbeResp) Protocol() string             { return "HTTP/1.1" }
func (r auxProbeResp) Status() int                  { return 200 }
func (r auxProbeResp) Headers() map[string][]string { return r.headers }
func (r auxProbeResp) Body() string                 { return r.body }

// 客户端可控的「非体段」（uri 与 multipart files[].name/mime）必须与体/头同门
// 封顶且入估算：否则单个 90KiB 全 `&` 文件名（≈540KiB 转义）+ 64KiB 全 `&`
// 体（384KiB）+ 超长 URI 即可把本行推过 auditItemMaxBytes——被丢弃的恰是
// 「触发 WAF 的这次请求」自身的安全事件（事件列表/大屏/自动封禁全缺）。
// 钉：封顶后事件入队零丢弃、files_dropped 显性披露、估算不低于实际序列化。
func TestSnapshotAuditLog_clientControlledAuxSegmentsStayUnderItemCap(t *testing.T) {
	dense := strings.Repeat("&", 90*1024)
	files := make([]plugintypes.AuditLogTransactionRequestFiles, 0, 200)
	for range 200 {
		files = append(files, auditSnapshotFile{Name_: dense, Size_: 1, Mime_: dense})
	}
	bigURI := "/probe?" + strings.Repeat("&", 60*1024)
	snap := snapshotAuditLog(auxProbeAuditLog{tx: auxProbeTx{req: auxProbeReq{
		uri:   bigURI,
		body:  strings.Repeat("&", auditBodyMaxBytes),
		files: files,
	}}})
	req := snap.Transaction_.Request_
	if req == nil {
		t.Fatal("请求快照缺失")
	}

	// 上限必须真实截断（不是靠估算漏算通过）。门槛写成字面量：用例要在
	// 未修复基线上也能编译，从而红在断言上（而不是红在符号缺失）。
	//   uri 8KiB 转义字节 / files 64 条 / 单字段 1KiB 转义字节 /
	//   条目内容总预算 24KiB 转义字节
	const (
		uriCapEscaped   = 8 * 1024
		filesMaxEntries = 64
		fieldCapEscaped = 1024
		filesCapEscaped = 24 * 1024
		truncatedSuffix = "\n...[TRUNCATED]"
	)
	if got := len(req.URI_); got >= len(bigURI) {
		t.Fatalf("URI 未截断：保留 %d 字节（原始 %d）", got, len(bigURI))
	}
	if got := jsonStringEscapedLen(req.URI_); got > uriCapEscaped+len(truncatedSuffix) {
		t.Fatalf("URI 转义字节 %d 越过 %d 上限", got, uriCapEscaped)
	}
	if got := len(req.Files_); got > filesMaxEntries {
		t.Fatalf("files 保留 %d 条 > 上限 %d", got, filesMaxEntries)
	}
	// 截断披露必须出现在 wire 契约上（files_dropped，omitempty）。
	type filesWire struct {
		Files []struct {
			Name string `json:"name"`
			Mime string `json:"mime"`
		} `json:"files"`
		FilesDropped int `json:"files_dropped"`
	}
	rawReq, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var wire filesWire
	if err := json.Unmarshal(rawReq, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.FilesDropped == 0 {
		t.Fatal("files 截断必须显性披露 files_dropped")
	}
	var fileEscaped int64
	for _, f := range req.Files_ {
		if jsonStringEscapedLen(f.Name()) > fieldCapEscaped+len(truncatedSuffix) ||
			jsonStringEscapedLen(f.Mime()) > fieldCapEscaped+len(truncatedSuffix) {
			t.Fatalf("文件名/MIME 转义字节越过单字段上限：name=%d mime=%d",
				jsonStringEscapedLen(f.Name()), jsonStringEscapedLen(f.Mime()))
		}
		fileEscaped += int64(jsonStringEscapedLen(f.Name()) + jsonStringEscapedLen(f.Mime()))
	}
	if fileEscaped > filesCapEscaped {
		t.Fatalf("files 条目内容转义字节 %d > 总预算 %d", fileEscaped, filesCapEscaped)
	}

	// 估算口径仍是实际序列化的上界，且整条落在单条上限内。
	serialized, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	size := estimateAuditSnapshotBytes(snap)
	if size < int64(len(serialized)) {
		t.Fatalf("估算 %d < 序列化 %d：低估会让实际驻留突破字节预算", size, len(serialized))
	}
	if size > auditItemMaxBytes {
		t.Fatalf("估算 %d > 单条上限 %d（被构造的这次请求自身事件仍会被整行丢弃）", size, auditItemMaxBytes)
	}

	// 入队路径：本行必须留在事件里（dropped==0）。
	p := &auditPipeline{
		target: filepath.Join(t.TempDir(), "audit.log"),
		queue:  make(chan lbAuditItem, 2),
		done:   make(chan struct{}),
	}
	if err := p.openFile(0o644); err != nil {
		t.Fatal(err)
	}
	p.enqueue(lbAuditItem{snap: snap, formatter: cannedFormatter{body: []byte(`{"row":"aux-dense"}`)}})
	if dropped := p.dropped.Load(); dropped != 0 {
		t.Fatalf("dropped=%d, want 0（客户端构造的超长文件名/URI 不得挤掉自身事件）", dropped)
	}
	if length := len(p.queue); length != 1 {
		t.Fatalf("queue length=%d, want 1", length)
	}
}

// 未超限形态必须原样保留（封顶只在越限时生效，不改写正常 uri/文件名）。
func TestSnapshotAuditLog_auxSegmentsPassThroughWhenUnderCap(t *testing.T) {
	files := []plugintypes.AuditLogTransactionRequestFiles{
		auditSnapshotFile{Name_: "report.pdf", Size_: 1024, Mime_: "application/pdf"},
	}
	snap := snapshotAuditLog(auxProbeAuditLog{tx: auxProbeTx{req: auxProbeReq{
		uri: "/upload?x=1", files: files,
	}}})
	req := snap.Transaction_.Request_
	if req == nil {
		t.Fatal("请求快照缺失")
	}
	rawReq, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		URI   string `json:"uri"`
		Files []struct {
			Name string `json:"name"`
			Mime string `json:"mime"`
		} `json:"files"`
		FilesDropped int `json:"files_dropped"`
	}
	if err := json.Unmarshal(rawReq, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.URI != "/upload?x=1" {
		t.Fatalf("URI 被改写：%q", wire.URI)
	}
	if len(wire.Files) != 1 || wire.FilesDropped != 0 {
		t.Fatalf("files=%d dropped=%d, want 1/0", len(wire.Files), wire.FilesDropped)
	}
	if wire.Files[0].Name != "report.pdf" || wire.Files[0].Mime != "application/pdf" {
		t.Fatalf("文件条目被改写：%#v", wire.Files[0])
	}
}

// 截断原语只在 UTF-8 边界停：上限按转义字节累计，落点却可能切进多字节字符
// 中间。按字节切的实现会把中文 URI/文件名切成半个字符，落盘 JSON 经 UI 渲染
// 成替换符——用户看到的是「被损坏」而不是「被截断」。故断言三件事：结果仍是
// 合法 UTF-8、保留字符数等于「不越过上限的最大前缀」、末尾带截断标记。
func TestSnapshotClipEscaped_stopsOnRuneBoundary(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		max   int
		runes int
	}{
		// 三字节字符：上限 8 落在第三个「中」（字节 6..9）内部。
		{"cjk mid-rune", strings.Repeat("中", 3), 8, 2},
		// 四字节字符：上限 10 落在第三个 emoji（字节 8..12）内部。
		{"emoji mid-rune", strings.Repeat("😀", 3), 10, 2},
		// 转义放大 6×：`<`/`>` 每个按 6 字节计，上限 13 只容得下两个字符。
		{"escaped 6x stops at character", "<><><>", 13, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, truncated := snapshotClipEscaped(tc.in, tc.max)
			if !truncated {
				t.Fatalf("未截断：%q（上限 %d 转义字节）", got, tc.max)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("截断结果不是合法 UTF-8：%q", got)
			}
			if !strings.HasSuffix(got, auditTruncatedMarker) {
				t.Fatalf("截断结果缺少显式标记：%q", got)
			}
			body := strings.TrimSuffix(got, auditTruncatedMarker)
			if n := utf8.RuneCountInString(body); n != tc.runes {
				t.Fatalf("保留 %d 个字符，期望 %d（按字节集会切坏字符）", n, tc.runes)
			}
			if n := jsonStringEscapedLen(body); n > tc.max {
				t.Fatalf("保留内容转义字节 %d 越过上限 %d", n, tc.max)
			}
		})
	}
}

// 恰好等于上限不得截断（边界判定是 `> max` 而不是 `>= max`）：差一个字节的
// off-by-one 会把「刚好装满」的正常取值标成 TRUNCATED，取证时误判为丢数据。
func TestSnapshotClipEscaped_keepsInputThatExactlyFillsTheCap(t *testing.T) {
	in := strings.Repeat("a", 128)
	got, truncated := snapshotClipEscaped(in, len(in))
	if truncated {
		t.Fatalf("恰好等于上限被截断：%q", got)
	}
	if got != in {
		t.Fatalf("未超限取值被改写：%q", got)
	}

	// 少一字节上限必须截断，且切口落在「上限-1」：与上一条配对，任何方向的
	// 边界错位（>= / 提前一字节）都会让两者之一失败。
	got, truncated = snapshotClipEscaped(in, len(in)-1)
	if !truncated {
		t.Fatalf("超限一字节未截断：%q", got)
	}
	if want := strings.Repeat("a", len(in)-1) + auditTruncatedMarker; got != want {
		t.Fatalf("截断切口错位：got %q, want %q", got, want)
	}

	// 早退形态：空串与非正上限原样返回（上限 0 是「不限额」语义，不是「全截」）。
	if got, truncated := snapshotClipEscaped("", 16); got != "" || truncated {
		t.Fatalf("空串被改写：%q truncated=%v", got, truncated)
	}
	if got, truncated := snapshotClipEscaped(in, 0); got != in || truncated {
		t.Fatalf("非正上限未按不限额处理：len=%d truncated=%v", len(got), truncated)
	}
}

// 调用点契约：超限 URI 必须以标记结尾（标记缺失时 UI 无法区分「半截」与
// 「完整」），未超限 URI 必须逐字节原样。
func TestSnapshotAuditLog_uriSegmentsCarryTruncationMarker(t *testing.T) {
	overCap := "/probe?" + strings.Repeat("&", 60*1024) // `&` 转义 6×，必然越限
	snap := snapshotAuditLog(auxProbeAuditLog{tx: auxProbeTx{req: auxProbeReq{uri: overCap}}})
	req := snap.Transaction_.Request_
	if req == nil {
		t.Fatal("请求快照缺失")
	}
	if !strings.HasSuffix(req.URI_, auditTruncatedMarker) {
		t.Fatalf("超限 URI 缺少截断标记（尾部 %q）", tailOf(req.URI_, 24))
	}
	if n := jsonStringEscapedLen(req.URI_); n > auditURIMaxEscapedBytes {
		t.Fatalf("超限 URI 转义字节 %d 越过上限 %d", n, auditURIMaxEscapedBytes)
	}

	// 未超限形态：同一字段必须原样保留（上面所有截断逻辑不得外溢）。
	const underCap = "/api/v1/rules?page=2"
	snap = snapshotAuditLog(auxProbeAuditLog{tx: auxProbeTx{req: auxProbeReq{uri: underCap}}})
	req = snap.Transaction_.Request_
	if req == nil {
		t.Fatal("请求快照缺失")
	}
	if req.URI_ != underCap {
		t.Fatalf("未超限 URI 被改写：%q", req.URI_)
	}
}

// tailOf 返回 s 的末 n 个字节（失败信息用，避免把 60KiB 夹具打印出来）。
func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// files_dropped 是文件条目截断的披露键，估算必须为它留出固定开销：少算这一项，
// 「截断披露」本身就会把实际序列化体积推过估算口径，而估算正是入队/单条字节
// 预算的执法值。断言差值与常量逐字节相等，删除该估算项或改小常量都会红。
func TestEstimateAuditSnapshotBytes_countsFilesDroppedDisclosure(t *testing.T) {
	build := func(dropped int) *auditSnapshot {
		return &auditSnapshot{Transaction_: auditSnapshotTransaction{
			Request_: &auditSnapshotRequest{URI_: "/upload", FilesDropped_: dropped},
		}}
	}
	withoutDrop, withDrop := build(0), build(3)
	base := estimateAuditSnapshotBytes(withoutDrop)
	got := estimateAuditSnapshotBytes(withDrop)
	if diff := got - base; diff != auditFilesDroppedOverhead {
		t.Fatalf("files_dropped 估算增量 %d，期望 %d（披露键未被计入）", diff, auditFilesDroppedOverhead)
	}
	// 上界性：估算不得低于实际序列化体积（含披露键）。
	raw, err := json.Marshal(withDrop)
	if err != nil {
		t.Fatal(err)
	}
	if got < int64(len(raw)) {
		t.Fatalf("估算 %d < 序列化 %d", got, len(raw))
	}
}

// messages_dropped 与 files_dropped 同属截断披露：非零时必须计入固定开销，
// 零值继续遵循 omitempty；估算在任何丢弃数量下都不得低于实际序列化体积。
func TestEstimateAuditSnapshotBytes_countsMessagesDroppedDisclosure(t *testing.T) {
	build := func(dropped int) *auditSnapshot {
		return &auditSnapshot{MessagesDropped_: dropped}
	}
	base := estimateAuditSnapshotBytes(build(0))
	for _, dropped := range []int{3, 999999999} {
		withDrop := build(dropped)
		got := estimateAuditSnapshotBytes(withDrop)
		if diff := got - base; diff != auditMessagesDroppedOverhead {
			t.Fatalf("messages_dropped=%d 估算增量 %d，期望 %d（披露键未被计入）", dropped, diff, auditMessagesDroppedOverhead)
		}
		raw, err := json.Marshal(withDrop)
		if err != nil {
			t.Fatal(err)
		}
		if got < int64(len(raw)) {
			t.Fatalf("messages_dropped=%d 估算 %d < 序列化 %d", dropped, got, len(raw))
		}
	}
	if got := estimateAuditSnapshotBytes(build(0)); got != base {
		t.Fatalf("零值重复估算从 %d 变为 %d（omitempty 形态不稳定）", base, got)
	}
}

// denseHeaderSet 返回 5000 条三字符键/值互不相同的 header 表：序列化体积
// ~70KiB，越过 64KiB 快照上限，用于构造「头段打满」的最坏形态夹具。
func denseHeaderSet() map[string][]string {
	headers := make(map[string][]string, 5000)
	for i := range 5000 {
		n := i
		key := []byte{'a', 'a', 'a'}
		for pos := 2; pos >= 0; pos-- {
			key[pos] = byte('a' + n%26)
			n /= 26
		}
		headers[string(key)] = []string{string(key)}
	}
	return headers
}

// 事务字符串（request.method 与 transaction.server_id）与 uri/files 同属
// 客户端可控段：不设限时任一项都能把快照推过 auditItemMaxBytes，让「触发
// WAF 的这次请求」自身的安全事件整行丢弃（事件列表/大屏/自动封禁喂入全缺）。
// 钉：越限按转义字节封顶并留标记、估算仍 ≥ 实际序列化且 ≤ 单条上限、入队
// 零丢弃。
func TestSnapshotAuditLog_transactionStringsStayUnderItemCap(t *testing.T) {
	denseBody := strings.Repeat("&", auditBodyMaxBytes)
	denseField := strings.Repeat("&", 90*1024)
	files := make([]plugintypes.AuditLogTransactionRequestFiles, 0, 200)
	for range 200 {
		files = append(files, auditSnapshotFile{Name_: denseField, Size_: 1, Mime_: denseField})
	}
	headers := denseHeaderSet()
	denseFixture := func() auxProbeTx {
		return auxProbeTx{
			req: auxProbeReq{
				uri:     "/probe?" + strings.Repeat("&", 60*1024),
				body:    denseBody,
				headers: headers,
				files:   files,
			},
			resp: auxProbeResp{body: denseBody, headers: headers},
		}
	}
	// 上限门槛写字面量：用例要在未修复基线上也能编译，从而红在断言上。
	const (
		methodCapEscaped = 64
		serverCapEscaped = 256
		truncatedSuffix  = "\n...[TRUNCATED]"
	)
	wide := func(ch string) string { return strings.Repeat(ch, 128*1024) }
	cases := []struct {
		name     string
		mutate   func(*auxProbeTx)
		field    func(*auditSnapshotTransaction) string
		capBytes int
	}{
		{
			name:     "长 method",
			mutate:   func(tx *auxProbeTx) { tx.req.method = wide("M") },
			field:    func(tr *auditSnapshotTransaction) string { return tr.Request_.Method_ },
			capBytes: methodCapEscaped,
		},
		{
			name:     "长 server_id",
			mutate:   func(tx *auxProbeTx) { tx.serverID = wide("h") },
			field:    func(tr *auditSnapshotTransaction) string { return tr.ServerID_ },
			capBytes: serverCapEscaped,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := denseFixture()
			tc.mutate(&tx)
			snap := snapshotAuditLog(auxProbeAuditLog{tx: tx})
			got := tc.field(&snap.Transaction_)
			if !strings.HasSuffix(got, truncatedSuffix) {
				t.Fatalf("截断标记缺失：保留 %d 字节", len(got))
			}
			if escaped := jsonStringEscapedLen(got); escaped > tc.capBytes+len(truncatedSuffix) {
				t.Fatalf("转义字节 %d 越过 %d 上限", escaped, tc.capBytes)
			}

			serialized, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			size := estimateAuditSnapshotBytes(snap)
			if size < int64(len(serialized)) {
				t.Fatalf("估算 %d < 序列化 %d：低估会让实际驻留突破字节预算", size, len(serialized))
			}
			if size > auditItemMaxBytes {
				t.Fatalf("估算 %d > 单条上限 %d（被构造的这次请求自身事件仍会被整行丢弃）", size, auditItemMaxBytes)
			}

			p := &auditPipeline{
				target: filepath.Join(t.TempDir(), "audit.log"),
				queue:  make(chan lbAuditItem, 2),
				done:   make(chan struct{}),
			}
			if err := p.openFile(0o644); err != nil {
				t.Fatal(err)
			}
			p.enqueue(lbAuditItem{snap: snap, formatter: cannedFormatter{body: []byte(`{"row":"tx-string-dense"}`)}})
			if dropped := p.dropped.Load(); dropped != 0 {
				t.Fatalf("dropped=%d, want 0（客户端构造的超长 method/server_id 不得挤掉自身事件）", dropped)
			}
			if length := len(p.queue); length != 1 {
				t.Fatalf("queue length=%d, want 1", length)
			}
		})
	}
}

// 未超限的 method/server_id 必须原样保留（封顶只在越限时生效，不改写正常值）。
func TestSnapshotAuditLog_transactionStringsPassThroughWhenUnderCap(t *testing.T) {
	snap := snapshotAuditLog(auxProbeAuditLog{tx: auxProbeTx{
		serverID: "edge-node-1",
		req:      auxProbeReq{method: "PROPFIND"},
	}})
	if got := snap.Transaction_.Request_.Method_; got != "PROPFIND" {
		t.Fatalf("method 被改写：%q", got)
	}
	if got := snap.Transaction_.ServerID_; got != "edge-node-1" {
		t.Fatalf("server_id 被改写：%q", got)
	}
}

// auditItemMaxBytes 的上界推导必须可复算：所有客户端可控段的上限之和 + 48KiB
// 余量 ≤ 单条上限。任何新增客户端可控段（或放宽既有上限）若不同步扩容，本门
// 立即失败——否则「封顶后仍整行丢弃」的同族缺陷会以新字段形式回归。
func TestAuditItemMaxBytes_coversAllClientControlledSegments(t *testing.T) {
	const reserve int64 = 48 * 1024
	marker := int64(len(auditTruncatedMarker))
	worst := 2*(6*int64(auditBodyMaxBytes)+marker) + // 请求/响应体（64KiB 全 `&` + 标记）
		2*int64(auditHeadersMaxBytes) + // 请求/响应头（快照侧已按转义字节封顶）
		int64(auditMessagesMaxBytes) + // messages 内容预算
		int64(auditMethodMaxEscapedBytes) + // 内容预算已扣除标记长度
		int64(auditServerIDMaxEscapedBytes) +
		int64(auditURIMaxEscapedBytes) +
		int64(auditFilesMaxEscapedBytes) +
		int64(auditFilesMaxEntries)*auditFileEntryOverhead // files 条目固定开销
	if worst+reserve > auditItemMaxBytes {
		t.Fatalf("客户端可控段上限之和 %d + 余量 %d = %d > 单条上限 %d",
			worst, reserve, worst+reserve, auditItemMaxBytes)
	}
	// 夹具有效性：上限之和 + 余量后剩余的头部空间必须小于 16KiB（条目固定
	// 开销与插件侧字符串的既有实测余量）。放宽到 ≥16KiB 说明出现了未被任何
	// 段声明的空间，新客户端可控段会在不报错的情况下挤占它。
	if slack := auditItemMaxBytes - worst - reserve; slack >= 16*1024 {
		t.Fatalf("余量口径漂移：上限之和 + 余量后仍余 %d 字节未被任何段声明", slack)
	}
}
