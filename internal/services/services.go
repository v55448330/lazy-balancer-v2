package services

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// exposition 解析不再使用逐族全文正则：单趟按指标名前缀分派（见
// aggregatePrometheusText）。原先 9 条 prometheus*Pattern 每周期各扫一遍全文，
// 16MB body 形态 ≈144MB 正则输入，已随单趟聚合统一移除。

// MetricsService collects and stores metrics from Caddy。
//
// 采集/清理循环已按 task-engine 标准 v2.2 归口（30s 采集=metrics-collector
// daemon 的 RunTicker 节拍；24h 历史清理=metrics-history-cleanup Periodic
// 任务）——本结构只保留无状态工作体：collect()（单轮采集）与
// cleanupHistory()（单轮清理，返回错误交任务终态）。生命周期（启停/节拍/
// 排空）归任务引擎：引擎排空先于 db.Close，原 Start/Stop 的 stopped 守卫与
// 清理单飞 WaitGroup 随自建循环一并退役。
type MetricsService struct {
	metricsURL    string
	interval      int
	client        *http.Client
	overview      models.MetricsOverview
	mu            sync.RWMutex
	lastTotal     int64
	lastSampleAt  time.Time
	hasLastSample bool
}

// caddyMetricsScrapeTimeout 是 Caddy admin /metrics 的唯一抓取预算单源。
// 采集链（30s 周期）与仪表盘「限流拦截」卡片抓取的是同一地址、同一 16MB
// 正文上限，预算分叉会让同一瞬间出现「首页指标正常、限流卡片超时不可用」。
// 统一取 5s：卡片是同步用户请求且带 5s 缓存窗口，等待预算必须与之一致；
// 采集链超时只丢一个样本、下一周期自愈，而卡片超时直接表现为数据不可用。
// 同容器环回下 16MB/5s ≈ 3.2MB/s，正常响应远低于此。
const caddyMetricsScrapeTimeout = 5 * time.Second

func NewMetricsService(metricsURL string, interval int) *MetricsService {
	return &MetricsService{
		metricsURL: metricsURL,
		interval:   interval,
		client: &http.Client{
			Timeout: caddyMetricsScrapeTimeout,
		},
		overview: models.MetricsOverview{},
	}
}

// tickerInterval 采集节拍（cfg.MetricsInterval 秒；0/负值交给 RunTicker 的
// 1s 兜底并显性 warn——任务引擎标准禁止静默空转）。
func (m *MetricsService) tickerInterval() time.Duration {
	return time.Duration(m.interval) * time.Second
}

// metrics 采集失败族状态转换日志。30s 采集周期下，持久性失败
// （端点不可达、非 200、body 中段读取失败、body 超限、解析/入库失败）逐
// tick 裸记日志约 2880 行/天同一消息。改为状态转换口径：ok→fail 记一次
// （warn）、fail→ok 恢复记一次（info）、持续同一状态静默。状态按失败类别
// （key）独立跟踪：前置类别失败（如 Get 失败）不评估后续类别，其恢复标记
// 只在后续 tick 实际通过该检查时才落，避免「仍失败却记恢复」。
//
// 键空间是静态族 + 动态族的混合体：静态族（metrics 采集 8 类、时区/日志轮转/
// 排程读取/集群上报/自动备份/任务监控等固定前缀）总量随功能增长；动态族
// （rulelog-tail-cap-<规则 id>、status-mirror-<任务 id>、config-read-<列>、
// system-metrics-<部件>）按实体无界增长。因此上限淘汰必须按族进行——
// 整表重置会清掉其他族的「已失败」记忆，让持久故障族重新各打一条 warn。
var (
	metricsStateMu     sync.Mutex
	metricsStateFailed = map[string]bool{}
	// metricsStateOrder 是键的 FIFO 序（与 map 同步维护）：上限淘汰按「同族
	// 最旧键」取值。外部直接删键（测试隔离）留下的陈旧序项在淘汰时顺手清理。
	metricsStateOrder []string
)

// metricsStateEvictCap 是状态 map 的防御性键数上限（见 logStateTransition）。
const metricsStateEvictCap = 64

// stateTransitionFamily 返回状态键的族（首段前缀）。动态键按实体追加后缀，
// 按族淘汰因此只会清掉同一调用方的状态，其他族不受影响。
func stateTransitionFamily(key string) string {
	if i := strings.IndexByte(key, '-'); i > 0 {
		return key[:i]
	}
	return key
}

// evictStateTransitionLocked 在上限超出时按键淘汰（调用方须持 metricsStateMu）。
// 优先清理同族最旧键（动态族无界增长的主要来源）；同族只有新键自身时退化为
// 全局最旧键，保证 map 始终有界。
func evictStateTransitionLocked(newKey string) {
	family := stateTransitionFamily(newKey)
	for len(metricsStateFailed) > metricsStateEvictCap {
		victim := -1
		for i, k := range metricsStateOrder {
			if _, alive := metricsStateFailed[k]; !alive {
				victim = i // 陈旧序项（键已被外部删除）
				break
			}
			if victim < 0 && k != newKey && stateTransitionFamily(k) == family {
				victim = i
			}
		}
		if victim < 0 {
			for i, k := range metricsStateOrder {
				if _, alive := metricsStateFailed[k]; alive && k != newKey {
					victim = i
					break
				}
			}
		}
		if victim < 0 {
			return // 无可淘汰对象（序项不足，理论上不可达）
		}
		delete(metricsStateFailed, metricsStateOrder[victim])
		metricsStateOrder = append(metricsStateOrder[:victim], metricsStateOrder[victim+1:]...)
	}
}

// logStateTransition 是状态转换日志的通用状态机（同一 key 独立跟踪）：
// ok→fail="warn"、fail→ok="info"、持续同态=""。初始状态视为 ok：首次失败记
// 一次 warn，首次成功静默（无恢复可记）。metrics 采集族与低频巡检循环
// （时区刷新/运行日志尺寸刷新/排程读取）共用——持久失败在 30s tick 下不再
// 各打 2880 行/天同一消息；键空间按调用方前缀隔离。map 有界
// （metricsStateEvictCap）：超上限按族淘汰最旧键，各族的状态记忆互不牵连。
// 与「同键窗口内只告警一次」的限频族（throttleWarnAllowed）语义不同：本函数
// 按状态转换记账（恢复要留一条 info），不做窗口判定，故不复用该 helper。
func logStateTransition(key string, failed bool) string {
	metricsStateMu.Lock()
	defer metricsStateMu.Unlock()
	prev, seen := metricsStateFailed[key]
	if seen && prev == failed {
		return ""
	}
	if !seen && !failed {
		return ""
	}
	if !seen {
		metricsStateOrder = append(metricsStateOrder, key)
	}
	metricsStateFailed[key] = failed
	evictStateTransitionLocked(key)
	if failed {
		return "warn"
	}
	return "info"
}

// metrics 采集失败类别（状态转换日志的 key，固定集合）。
const (
	metricsFailureCollect      = "collect"
	metricsFailureEndpoint     = "endpoint"
	metricsFailureRead         = "read"
	metricsFailureBodyCap      = "body-cap"
	metricsFailureParse        = "parse"
	metricsFailureParseRules   = "parse-rules"
	metricsFailureStore        = "store"
	metricsFailureStorePerRule = "store-per-rule"
)

// geoIPPassSeriesMarker geoip 透传路由（buildGeoipPassRoute）的 Prometheus
// 序列片段——该路由无 reverse_proxy，其序列不含任何上游语义。透传路由与
// 主/路径路由会为同一请求各注入一次指标，任何消费 /metrics 正文的解析器都
// 必须在行分派前跳过命中该片段的整行，否则同一请求被记两次（请求数/字节量/
// 状态码分布/限流 429 计数翻倍）。字面量只在本文件出现一次，三个消费点统一
// 走 IsGeoIPPassSeries——不要把标记片段复制到消费侧自行匹配。
const geoIPPassSeriesMarker = `handler="http.handlers.geoip2region"`

// IsGeoIPPassSeries 报告该行是否为 geoip 透传路由注入的序列；采集聚合、实时
// 指标解析（handlers）与限流卡片 429 解析共用本判据。
// 只有 Caddy 的 caddy_http_* 指标族携带 handler 标签；本插件自注册的
// lazybalancer_* 族标签集只有 rule/class/direction（见 caddygeoip/rule_metrics.go），
// 且透传路由不挂规则计量处理器——前缀判定如实表达这一事实，也免去在其他族上
// 逐行做无意义扫描。
func IsGeoIPPassSeries(line string) bool {
	return strings.HasPrefix(line, "caddy_http_") && strings.Contains(line, geoIPPassSeriesMarker)
}

func (m *MetricsService) collect() {
	// 三项 DB 派生指标先于 /metrics 采集刷新——Caddy 未就绪或
	// /metrics 不可达时它们仍然准确，只有流量样本受影响。
	m.refreshDBOverviewMetrics()

	resp, err := m.client.Get(m.metricsURL)
	if err != nil {
		if logStateTransition(metricsFailureCollect, true) != "" {
			Logf("warn", "Failed to collect metrics: %v", err)
		}
		return
	}
	if lvl := logStateTransition(metricsFailureCollect, false); lvl != "" {
		Logf("info", "metrics collection recovered")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if logStateTransition(metricsFailureEndpoint, true) != "" {
			Logf("warn", "Metrics endpoint returned status %d, skipping sample", resp.StatusCode)
		}
		return
	}
	if lvl := logStateTransition(metricsFailureEndpoint, false); lvl != "" {
		Logf("info", "metrics endpoint recovered")
	}

	// 读取上限对齐 overviewmetrics 的 16MB 探测模式
	//规则数×状态码×host 序列的基数爆炸在 30s 采集周期里
	// 可分配大块内存，超限按解析失败跳过本样本。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20+1))
	if err != nil {
		// body 中段读取错误此前裸 return——失败族中唯一零信号成员
		// （52fdb0f7 枚举未覆盖）。现与其他类别同口径走状态转换日志。
		if logStateTransition(metricsFailureRead, true) != "" {
			Logf("warn", "Failed to read metrics body: %v", err)
		}
		return
	}
	if lvl := logStateTransition(metricsFailureRead, false); lvl != "" {
		Logf("info", "metrics body read recovered")
	}
	if len(body) > 16<<20 {
		if logStateTransition(metricsFailureBodyCap, true) != "" {
			Logf("warn", "Metrics endpoint body exceeded 16MB cap, skipping sample")
		}
		return
	}
	if lvl := logStateTransition(metricsFailureBodyCap, false); lvl != "" {
		Logf("info", "metrics endpoint body back under 16MB cap")
	}

	// string 拷贝只做一次——parse 与 store 共用同一
	// text，此前两次 string(body) 最坏双拷贝 32MB（16MB body ×2）。
	text := string(body)
	// geoip 透传序列在单趟聚合内逐行剔除（aggregatePrometheusText 的行分派
	// 前调用 IsGeoIPPassSeries）——不再先重组一份过滤全文（16MB 上限下
	// 省去每周期一次全量副本）。
	// 单趟聚合：全局样本与规则级样本共用一次全文遍历（旧实现全局 6 趟 +
	// 规则 4 趟全文正则，且同一 text 喂两条解析链）。两族错误语义独立——规则级
	// 畸形只丢 per-rule 行，不影响全局样本与 overview。
	scan := aggregatePrometheusText(text, prometheusScanGlobal|prometheusScanRules)
	metrics := scan.global
	if scan.globalErr != nil {
		if logStateTransition(metricsFailureParse, true) != "" {
			Logf("warn", "Failed to parse metrics: %v", scan.globalErr)
		}
		return
	}
	if lvl := logStateTransition(metricsFailureParse, false); lvl != "" {
		Logf("info", "metrics parse recovered")
	}
	if scan.rulesErr != nil {
		if logStateTransition(metricsFailureParseRules, true) != "" {
			Logf("warn", "Failed to parse per-rule metrics: %v", scan.rulesErr)
		}
	} else if lvl := logStateTransition(metricsFailureParseRules, false); lvl != "" {
		Logf("info", "per-rule metrics parse recovered")
	}
	if err := m.storeMetrics(metrics); err != nil {
		if logStateTransition(metricsFailureStore, true) != "" {
			Logf("warn", "Failed to store metrics: %v, values: %d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
				err, metrics.requestsTotal, metrics.requests2xx, metrics.requests3xx,
				metrics.requests4xx, metrics.requests5xx, metrics.bytesIn, metrics.bytesOut,
				metrics.latencyP50, metrics.latencyP95, metrics.latencyP99)
		}
	} else if lvl := logStateTransition(metricsFailureStore, false); lvl != "" {
		Logf("info", "metrics store recovered")
	}
	if scan.rulesErr == nil {
		if err := m.storePerRuleMetrics(scan.rules); err != nil {
			if logStateTransition(metricsFailureStorePerRule, true) != "" {
				Logf("warn", "Failed to store per-rule metrics: %v", err)
			}
		} else if lvl := logStateTransition(metricsFailureStorePerRule, false); lvl != "" {
			Logf("info", "metrics per-rule store recovered")
		}
	}
	m.applyTrafficSample(metrics)
}

type parsedMetrics struct {
	requestsTotal int64
	requests2xx   int64
	requests3xx   int64
	requests4xx   int64
	requests5xx   int64
	bytesIn       int64
	bytesOut      int64
	latencyP50    int
	latencyP95    int
	latencyP99    int
}

type statusClassCounts struct {
	status2xx int64
	status3xx int64
	status4xx int64
	status5xx int64
}

// classifyStatusCodes 按 2xx/3xx/4xx/5xx 归类。区间外码（1xx/0/600+）不进入
// 任何分类——other 桶生产零消费（仅测试观测）已删除，「四类之和 < 总请求」
// 即区间外码存在的可观测形态。
func classifyStatusCodes(codes map[int]int64) statusClassCounts {
	var counts statusClassCounts
	for code, value := range codes {
		switch {
		case code >= 200 && code < 300:
			counts.status2xx += value
		case code >= 300 && code < 400:
			counts.status3xx += value
		case code >= 400 && code < 500:
			counts.status4xx += value
		case code >= 500 && code < 600:
			counts.status5xx += value
		}
	}
	return counts
}

// prometheusScanHook 仅供测试观测全文扫描次数（生产恒 nil）。聚合改为单趟
// 分派后，测试以此钉住「每个采集周期恰 1 趟全文扫描」（旧实现每周期 10 趟
// 全文正则：全局 6 + 规则 4，16MB body 时约 144MB 正则输入）。
var prometheusScanHook func(text string)

// overviewRefreshHook 仅供测试观测 DB 派生指标刷新次数（生产恒 nil）：钉住
// 「每采集周期只刷新一次」（旧形态 collect + updateOverview 各刷一次 = 6 条
// COUNT/周期）。
var overviewRefreshHook func()

// metricsCleanupHook 仅供测试观测/控速历史清理（生产恒 nil）：钉住清理与采集
// 不再串行（清理在途时采集仍按节拍推进）与单飞语义。
var metricsCleanupHook func()

// prometheusScanMode 选择本次聚合要解析的指标族——全局样本与规则级样本的
// 错误语义独立（规则级畸形只丢 per-rule 行，不影响全局样本与 overview）。
type prometheusScanMode uint8

const (
	prometheusScanGlobal prometheusScanMode = 1 << iota
	prometheusScanRules
)

// prometheusScanResult 单趟扫描的聚合结果（逐族首个错误独立保留）。
type prometheusScanResult struct {
	global    parsedMetrics
	globalErr error
	codes     map[int]int64
	buckets   map[float64]int64
	rules     map[string]*ruleLabelAggregate
	rulesErr  error
}

// prometheusLabelBlockEnd 返回标签块 `}` 的下标：按引号状态扫描，
// 引号内的 `}`（标签值合法可含该字符）不算块尾。缺失块/引号未闭合返回 -1。
func prometheusLabelBlockEnd(line string) int {
	open := strings.IndexByte(line, '{')
	if open < 0 {
		return -1
	}
	inQuote := false
	for i := open + 1; i < len(line); i++ {
		switch line[i] {
		case '\\':
			if inQuote {
				i++ // 跳过转义字符（\" 与 \\ 不得改变引号状态）
			}
		case '"':
			inQuote = !inQuote
		case '}':
			if !inQuote {
				return i
			}
		}
	}
	return -1
}

// PrometheusSampleLine 解析单行 exposition 文本，返回指标名（含标签块）与样本值
// token。两处消费方（handlers 的仪表盘实时指标、本包的规则/全局指标采集）必须
// 共用本实现——各写一套切分会得出相反结论（`strings.Fields` 会把合法的
// `host="a b"` 切成残片并让整段正文报错）。ok=false 表示该行不成形（缺名称/
// 缺值、标签块未闭合），调用方按非样本跳过；值本身的解析与有限性判定在
// PrometheusSampleFloat（错误口径由调用方决定）。
func PrometheusSampleLine(line string) (name, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	labelEnd := prometheusLabelBlockEnd(line)
	switch {
	case labelEnd >= 0:
		name = line[:labelEnd+1]
		value = line[labelEnd+1:]
	case strings.IndexByte(line, '{') >= 0:
		// 有 `{` 但引号/括号未闭合：畸形行，不猜取值位置。
		return "", "", false
	default:
		// 无标签块的行（`process_start_time_seconds 1`）：名称到首个空白为止。
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			return "", "", false
		}
		name, value = line[:sp], line[sp+1:]
	}
	value = strings.TrimSpace(value)
	if name == "" || value == "" {
		return "", "", false
	}
	if sp := strings.IndexByte(value, ' '); sp >= 0 {
		value = value[:sp]
	}
	return name, value, true
}

// PrometheusSampleFloat 解析样本值 token。finite=false 表示非有限值（NaN/±Inf）：
// 消费侧把样本值转 int64 时非有限值的转换结果实现相关，两处消费方统一「跳过该
// 样本」而不是报错（此前仪表盘跳过、规则指标报错，同一次抓取两步结论相反）。
// err 表示 token 不可解析为数值。
func PrometheusSampleFloat(raw string) (value float64, finite bool, err error) {
	value, err = strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false, err
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false, nil
	}
	return value, true, nil
}

// prometheusLabelValue 取标签块内 name="value" 的值。标签名必须从 `{` 或 `,`
// 之后开始（允许空白）——子串定位会让 `le="` 命中 `role="`、`code="` 命中
// `status_code="`，标签形态变化时静默取错值。
func prometheusLabelValue(line, name string) (string, bool) {
	needle := name + `="`
	off := 0
	for {
		idx := strings.Index(line[off:], needle)
		if idx < 0 {
			return "", false
		}
		idx += off
		// 左边界：向前跳过空白，要求是 `{` 或 `,`。
		prev := idx - 1
		for prev >= 0 && (line[prev] == ' ' || line[prev] == '\t') {
			prev--
		}
		if prev >= 0 && (line[prev] == '{' || line[prev] == ',') {
			start := idx + len(needle)
			end := strings.IndexByte(line[start:], '"')
			if end < 0 {
				return "", false
			}
			return line[start : start+end], true
		}
		off = idx + 1
	}
}

// aggregatePrometheusText 单趟遍历 exposition 文本，按指标名前缀分派到各族
// 解析器——替代此前每族一次全文 FindAllStringSubmatch（每周期 10 趟全文正则
// + 同文本重复喂给两条解析链）。族内取值语义与错误文案保持不变。
func aggregatePrometheusText(text string, mode prometheusScanMode) prometheusScanResult {
	if prometheusScanHook != nil {
		prometheusScanHook(text)
	}
	wantGlobal := mode&prometheusScanGlobal != 0
	wantRules := mode&prometheusScanRules != 0
	res := prometheusScanResult{
		codes:   make(map[int]int64),
		buckets: make(map[float64]int64),
	}
	if wantRules {
		res.rules = make(map[string]*ruleLabelAggregate)
	}
	ruleAgg := func(rule string) *ruleLabelAggregate {
		agg := res.rules[rule]
		if agg == nil {
			agg = &ruleLabelAggregate{}
			res.rules[rule] = agg
		}
		return agg
	}

	for line := range strings.SplitSeq(text, "\n") {
		// geoip 规则的请求先过独立透传路由（首处理器 http.handlers.geoip2region，
		// buildGeoipPassRoute）再过主/路径路由，两条路由各自注入 metrics——同一
		// 请求的请求数/状态码/字节量全部翻倍。透传路由无 reverse_proxy，其序列
		// 不含任何上游语义，整行跳过即恢复真实计数（单趟、零额外副本）。
		// 规则族（lazybalancer_*）不挂该路由，天然不命中——判据只在 caddy_http_*
		// 族上生效（见 IsGeoIPPassSeries）。
		if IsGeoIPPassSeries(line) {
			continue
		}
		switch {
		// --- 全局指标族 ---
		case strings.HasPrefix(line, "caddy_http_requests_total{"):
			// Request totals come from caddy_http_requests_total, which carries no
			// code label; status classes come from caddy_http_request_duration_seconds_count.
			if !wantGlobal || res.globalErr != nil {
				continue
			}
			_, raw, ok := PrometheusSampleLine(line)
			if !ok {
				continue
			}
			value, err := parsePrometheusInteger(raw)
			if err != nil {
				res.globalErr = fmt.Errorf("parse request count %q: %w", raw, err)
				continue
			}
			res.global.requestsTotal += value
		case strings.HasPrefix(line, "caddy_http_request_duration_seconds_count{"):
			if !wantGlobal || res.globalErr != nil {
				continue
			}
			rawCode, hasCode := prometheusLabelValue(line, "code")
			_, rawValue, hasValue := PrometheusSampleLine(line)
			if !hasCode || !hasValue {
				continue
			}
			code, err := strconv.ParseInt(rawCode, 10, 64)
			if err != nil {
				res.globalErr = fmt.Errorf("parse HTTP status code %q: %w", rawCode, err)
				continue
			}
			value, err := parsePrometheusInteger(rawValue)
			if err != nil {
				res.globalErr = fmt.Errorf("parse status class count %q: %w", rawValue, err)
				continue
			}
			res.codes[int(code)] += value
		case strings.HasPrefix(line, "caddy_http_response_size_bytes_sum{"):
			if !wantGlobal || res.globalErr != nil {
				continue
			}
			_, raw, ok := PrometheusSampleLine(line)
			if !ok {
				continue
			}
			value, err := parsePrometheusInteger(raw)
			if err != nil {
				res.globalErr = fmt.Errorf("parse response size %q: %w", raw, err)
				continue
			}
			res.global.bytesOut += value
		case strings.HasPrefix(line, "caddy_http_request_size_bytes_sum{"):
			if !wantGlobal || res.globalErr != nil {
				continue
			}
			_, raw, ok := PrometheusSampleLine(line)
			if !ok {
				continue
			}
			value, err := parsePrometheusInteger(raw)
			if err != nil {
				res.globalErr = fmt.Errorf("parse request size %q: %w", raw, err)
				continue
			}
			res.global.bytesIn += value
		case strings.HasPrefix(line, "caddy_http_request_duration_seconds_bucket{"):
			if !wantGlobal || res.globalErr != nil {
				continue
			}
			if err := parsePrometheusBucketSample(line, res.buckets); err != nil {
				res.globalErr = err
			}
		// --- 规则级指标族（lazybalancer_*，rule label 聚合）---
		case strings.HasPrefix(line, "lazybalancer_requests_total{"):
			if !wantRules || res.rulesErr != nil {
				continue
			}
			rule, hasRule := prometheusLabelValue(line, "rule")
			_, raw, hasValue := PrometheusSampleLine(line)
			if !hasRule || !hasValue {
				continue
			}
			v, err := parsePrometheusInteger(raw)
			if err != nil {
				res.rulesErr = fmt.Errorf("parse rule requests %q: %w", raw, err)
				continue
			}
			ruleAgg(rule).requests += v
		case strings.HasPrefix(line, "lazybalancer_request_status_total{"):
			if !wantRules || res.rulesErr != nil {
				continue
			}
			class, hasClass := prometheusLabelValue(line, "class")
			rule, hasRule := prometheusLabelValue(line, "rule")
			_, raw, hasValue := PrometheusSampleLine(line)
			if !hasClass || !hasRule || !hasValue {
				continue
			}
			v, err := parsePrometheusInteger(raw)
			if err != nil {
				res.rulesErr = fmt.Errorf("parse rule status %q: %w", raw, err)
				continue
			}
			agg := ruleAgg(rule)
			switch class {
			case "2xx":
				agg.status2xx += v
			case "3xx":
				agg.status3xx += v
			case "4xx":
				agg.status4xx += v
			case "5xx":
				agg.status5xx += v
			}
		case strings.HasPrefix(line, "lazybalancer_bytes_total{"):
			if !wantRules || res.rulesErr != nil {
				continue
			}
			direction, hasDirection := prometheusLabelValue(line, "direction")
			rule, hasRule := prometheusLabelValue(line, "rule")
			_, raw, hasValue := PrometheusSampleLine(line)
			if !hasDirection || !hasRule || !hasValue {
				continue
			}
			v, err := parsePrometheusInteger(raw)
			if err != nil {
				res.rulesErr = fmt.Errorf("parse rule bytes %q: %w", raw, err)
				continue
			}
			agg := ruleAgg(rule)
			if direction == "in" {
				agg.bytesIn += v
			} else {
				agg.bytesOut += v
			}
		case strings.HasPrefix(line, "lazybalancer_security_blocked_total{"):
			if !wantRules || res.rulesErr != nil {
				continue
			}
			rule, hasRule := prometheusLabelValue(line, "rule")
			_, raw, hasValue := PrometheusSampleLine(line)
			if !hasRule || !hasValue {
				continue
			}
			v, err := parsePrometheusInteger(raw)
			if err != nil {
				res.rulesErr = fmt.Errorf("parse blocked count %q: %w", raw, err)
				continue
			}
			ruleAgg(rule).blocked += v
		}
	}

	if wantGlobal && res.globalErr == nil {
		classified := classifyStatusCodes(res.codes)
		res.global.requests2xx = classified.status2xx
		res.global.requests3xx = classified.status3xx
		res.global.requests4xx = classified.status4xx
		res.global.requests5xx = classified.status5xx
		res.global.latencyP50, res.global.latencyP95, res.global.latencyP99 = latencyPercentilesFromBuckets(res.buckets)
	}
	return res
}

// parsePrometheusBucketSample 解析一行 duration bucket 样本并累加到 byLE
// （同一 le 的多 host/handler 序列求和）。无 le 标签/无值的行按非样本跳过。
func parsePrometheusBucketSample(line string, byLE map[float64]int64) error {
	rawLE, hasLE := prometheusLabelValue(line, "le")
	_, rawValue, hasValue := PrometheusSampleLine(line)
	if !hasLE || !hasValue {
		return nil
	}
	le, err := strconv.ParseFloat(rawLE, 64)
	if err != nil {
		return fmt.Errorf("parse latency bucket boundary %q: %w", rawLE, err)
	}
	count, err := parsePrometheusInteger(rawValue)
	if err != nil {
		return fmt.Errorf("parse latency bucket count %q: %w", rawValue, err)
	}
	if count < 0 {
		return fmt.Errorf("latency bucket count %q is negative", rawValue)
	}
	byLE[le] += count
	return nil
}

// parsePrometheusInteger 解析样本值 token 为计数。非有限值（NaN/±Inf）按 0
// 处理——即「该样本不参与聚合」：转 int64 对非有限值的转换结果实现相关，且必须
// 与仪表盘实时指标解析器（PrometheusSampleFloat）同口径，否则同一次抓取在两步
// 得到相反结论。不可解析或超出 int64 范围仍是错误（不静默吞掉畸形值）。
func parsePrometheusInteger(raw string) (int64, error) {
	value, finite, err := PrometheusSampleFloat(raw)
	if err != nil {
		return 0, err
	}
	if !finite {
		return 0, nil
	}
	if value > math.MaxInt64 || value < math.MinInt64 {
		return 0, fmt.Errorf("value %q is out of int64 range", raw)
	}
	return int64(value), nil
}

// latencyPercentilesFromBuckets 从按 le 聚合的累计直方图估算 p50/p95/p99
// （毫秒）。纯计算，无可失败点（解析错误在 bucket 采样阶段已回报）。
func latencyPercentilesFromBuckets(byLE map[float64]int64) (int, int, int) {
	type bucket struct {
		le    float64
		count int64
	}
	if len(byLE) == 0 {
		return 0, 0, 0
	}
	buckets := make([]bucket, 0, len(byLE))
	var total int64
	for le, count := range byLE {
		buckets = append(buckets, bucket{le, count})
		if count > total {
			total = count
		}
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].le < buckets[j].le })
	// histogram_quantile 桶内线性插值（2026-10-09 用户裁定）：观察值在落桶
	// 内按均匀分布估计——旧实现恒返回 le 桶边（值永远落在 5/10/25/50/2500ms
	// 桶边上「太整齐」）。与 Prometheus histogram_quantile 同算法：
	// rank=q×total，落桶后 value=lower+×/bucketCount。
	percentile := func(q float64) int {
		if total <= 0 {
			return 0
		}
		rank := float64(total) * q
		var prevLE float64 // 首个桶下界=0
		var prevCum int64
		for _, b := range buckets {
			if float64(b.count) >= rank {
				if math.IsInf(b.le, 1) {
					// +Inf 桶不可插值——回退最大有限桶边（只表明长尾存在）。
					return int(math.Round(prevLE * 1000))
				}
				bucketCount := b.count - prevCum
				if bucketCount <= 0 {
					prevLE = b.le
					prevCum = b.count
					continue
				}
				fraction := (rank - float64(prevCum)) / float64(bucketCount)
				if fraction > 1 {
					fraction = 1
				}
				v := prevLE + (b.le-prevLE)*fraction
				return int(math.Round(v * 1000))
			}
			prevLE = b.le
			prevCum = b.count
		}
		// rank 超出全部累计（畸形输入兜底）——最大有限桶边。
		return int(math.Round(buckets[len(buckets)-1].le * 1000))
	}
	return percentile(0.5), percentile(0.95), percentile(0.99)
}

// ruleLabelAggregate 是 lazybalancer_* 指标按 rule label 聚合的结构。
type ruleLabelAggregate struct {
	requests                                   int64
	status2xx, status3xx, status4xx, status5xx int64
	blocked                                    int64
	bytesIn, bytesOut                          int64
}

// storePerRuleMetrics 在单个事务内批量写入规则级历史行（每规则一条）。
// 此前每规则一条独立 Exec（各自隐式事务＝独立 WAL 提交）：300 规则形态每
// 采集周期 300 次写事务。单事务 + 预处理语句把提交次数收敛为 1；批内共用
// 同一时间戳，使同一周期的规则行属于同一采样点。
func (m *MetricsService) storePerRuleMetrics(byRule map[string]*ruleLabelAggregate) error {
	if db.MetricsDB == nil {
		return errMetricsDBUnavailable
	}
	if len(byRule) == 0 {
		return nil
	}
	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05")
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		return fmt.Errorf("begin per-rule metrics batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`
		INSERT INTO metrics_history
		(rule_id, timestamp, requests_total, requests_2xx, requests_3xx,
		 requests_4xx, requests_5xx, requests_blocked, bytes_in, bytes_out,
		 latency_p50, latency_p95, latency_p99)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0)
	`)
	if err != nil {
		return fmt.Errorf("prepare per-rule metrics batch: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for ruleID, agg := range byRule {
		if _, err := stmt.Exec(ruleID, timestamp, agg.requests, agg.status2xx, agg.status3xx, agg.status4xx, agg.status5xx, agg.blocked, agg.bytesIn, agg.bytesOut); err != nil {
			return fmt.Errorf("store per-rule metrics for %s: %w", ruleID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit per-rule metrics batch: %w", err)
	}
	return nil
}

// cleanupHistory 单轮指标历史清理（metrics-history-cleanup Periodic 任务体）。
// 错误上抛交任务终态（同族 audit-retention / security-events-retention：
// 清理失败必须进 task_runs failed，不得恒 success）；状态转换日志口径保留。
func (m *MetricsService) cleanupHistory() error {
	if metricsCleanupHook != nil {
		metricsCleanupHook()
	}
	// 2026-09-15 用户裁定:指标历史固定保留最近 7 天(覆盖复用「日志
	// 保留」的裁定——用户明确指标类数据独立于日志保留配置);实时接口
	// (/metrics/*)不受影响,仅历史图窗口收敛到 7 天。
	const retentionDays = 7
	if db.MetricsDB == nil {
		// 守卫与 refreshDBOverviewMetrics 同口径（生产启动链不可达；防
		// 测试/嵌入形态 nil 库 panic）。nil 库按失败上抛——「清理没跑成」
		// 必须可见，不得伪装 success。
		if lvl := logStateTransition("metrics-history-cleanup", true); lvl != "" {
			Logf(lvl, "Failed to clean up metrics history: metrics database is not initialized")
		}
		return errMetricsDBUnavailable
	}
	if err := db.CleanupMetricsHistory(retentionDays); err != nil {
		if lvl := logStateTransition("metrics-history-cleanup", true); lvl != "" {
			Logf(lvl, "Failed to clean up metrics history: %v", err)
		}
		return err
	}
	if lvl := logStateTransition("metrics-history-cleanup", false); lvl != "" {
		Logf(lvl, "metrics history cleanup recovered")
	}
	return nil
}

// errMetricsDBUnavailable 指标库未初始化或已关闭（关停期 db.Close() 置 nil）。
// 生产启动链（db.Initialize 失败即退出）不可达；守卫防测试/嵌入形态下
// goroutine 直接 nil deref 崩溃，也是关停尾部在途轮的唯一可见出口。
var errMetricsDBUnavailable = errors.New("metrics database not initialized")

// storeMetrics 将全局指标写入独立 metrics 库；错误返回给调用方
// （collect）按状态转换口径记日志，避免本方法与 collect 双通道重复记录。
func (m *MetricsService) storeMetrics(metrics parsedMetrics) error {
	if db.MetricsDB == nil {
		return errMetricsDBUnavailable
	}
	// Store global metrics in independent metrics database
	_, err := db.MetricsDB.Exec(`
		INSERT INTO metrics_history 
		(rule_id, timestamp, requests_total, requests_2xx, requests_3xx, 
		 requests_4xx, requests_5xx, bytes_in, bytes_out, 
		 latency_p50, latency_p95, latency_p99)
		VALUES (NULL, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, metrics.requestsTotal, metrics.requests2xx, metrics.requests3xx,
		metrics.requests4xx, metrics.requests5xx, metrics.bytesIn, metrics.bytesOut,
		metrics.latencyP50, metrics.latencyP95, metrics.latencyP99)
	return err
}

// refreshDBOverviewMetrics 独立刷新三项纯 DB 派生指标（启用规则/规则总数/
// 在线节点）。此前三条查询写在 updateOverview 内，而
// updateOverview 只在 /metrics 采集成功的末尾调用——Caddy 未就绪或 /metrics
// 不可达期间（含空库启动、运维最需要节点状态的时刻）三项指标永久冻结在 0。
// 现在它们随每个采集周期独立刷新，只有流量样本受 /metrics 可用性影响。
func (m *MetricsService) refreshDBOverviewMetrics() {
	if overviewRefreshHook != nil {
		overviewRefreshHook()
	}
	// 后台 goroutine 统一走 db.GetDB()（atomic 句柄，与
	// tz/logrotate 刷新链同源）；db.DB 只归同步调用方。两来源并存时后台
	// 循环可能选中未随 Initialize/Close 同步维护的那一个，表征是「指标永久
	// 不生效且零日志」。
	database := db.GetDB()
	if database == nil {
		return
	}
	m.mu.RLock()
	activeRules, totalRules, onlineNodes := m.overview.ActiveRules, m.overview.TotalRules, m.overview.OnlineNodes
	m.mu.RUnlock()

	// 错误必须显式处理，否则 DB 故障时 overview 三项指标静默归零。
	// 查询失败时保留既有 overview 行中的前值（与 onlineNodes 分支同口径）。
	// 日志走状态转换口径（首报 warn + 恢复 info）：30s×2~3 行/天的同一消息
	// 会淹没真实信号并加速应用日志轮转（与全项目「日志只记真实执行/状态转换
	// 去重」裁定一致）；「keeping previous value=N」语义保留在首报行。
	if err := database.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE enabled = 1").Scan(&activeRules); err != nil {
		if lvl := logStateTransition("overview-count-active-rules", true); lvl != "" {
			Logf(lvl, "updateOverview: query active rules failed: %v (keeping previous value=%d)", err, activeRules)
		}
	} else if lvl := logStateTransition("overview-count-active-rules", false); lvl != "" {
		Logf(lvl, "updateOverview: query active rules recovered")
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM lb_rules").Scan(&totalRules); err != nil {
		if lvl := logStateTransition("overview-count-total-rules", true); lvl != "" {
			Logf(lvl, "updateOverview: query total rules failed: %v (keeping previous value=%d)", err, totalRules)
		}
	} else if lvl := logStateTransition("overview-count-total-rules", false); lvl != "" {
		Logf(lvl, "updateOverview: query total rules recovered")
	}

	// 在线节点数口径与 ComputeNodeStatus 统一：nodes.status 只在注册/上报时写入、
	// 从不回写为 'offline'，按 status 字段统计会拿到陈旧值，改为动态判定——
	// 已批准且 last_seen 未超过离线阈值秒数（倍率常量 nodeOfflineMultiplier 共用）。
	// 阈值不再在 SQL 里另写一套
	// （MIN(86400, MAX(?*COALESCE(...),120))）——那套口径把阈值硬顶在 24h，
	// 而 Go 侧 nodeOfflineThreshold 的上限是 2×86400=48h，sync_interval∈(43200,86400]
	// 时节点列表判「在线」而总览判离线。现在统一由 Go 侧算出秒数后作为参数传入。
	// 边界语义与 ComputeNodeStatus 对齐：ComputeNodeStatus 仅在 now.Sub(lastSeen) > N 时判离线，
	// 即恰好 N 秒整的节点仍算在线，故这里用 >= 把「等于 N 秒」归入在线，避免口径漂移。
	offlineThresholdSeconds := nodeOfflineThresholdSeconds(database)
	if err := database.QueryRow(`
		SELECT COUNT(*) FROM nodes
		WHERE is_approved = 1
		  AND last_seen IS NOT NULL
		  AND datetime(last_seen) >= datetime('now', printf('-%d seconds', ?))
	`, offlineThresholdSeconds).Scan(&onlineNodes); err != nil {
		if lvl := logStateTransition("overview-count-online-nodes", true); lvl != "" {
			Logf(lvl, "updateOverview: query online nodes failed: %v (keeping previous value=%d)", err, onlineNodes)
		}
	} else if lvl := logStateTransition("overview-count-online-nodes", false); lvl != "" {
		Logf(lvl, "updateOverview: query online nodes recovered")
	}

	m.mu.Lock()
	m.overview.ActiveRules = activeRules
	m.overview.TotalRules = totalRules
	m.overview.OnlineNodes = onlineNodes
	m.mu.Unlock()
}

// applyTrafficSample 只覆盖 /metrics 流量样本（DB 派生三项由
// refreshDBOverviewMetrics 维护，这里原样保留）。
func (m *MetricsService) applyTrafficSample(metrics parsedMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rps float64
	now := time.Now()
	if m.hasLastSample && metrics.requestsTotal >= m.lastTotal {
		if elapsed := now.Sub(m.lastSampleAt).Seconds(); elapsed > 0 {
			rps = float64(metrics.requestsTotal-m.lastTotal) / elapsed
		}
	}
	m.lastTotal = metrics.requestsTotal
	m.lastSampleAt = now
	m.hasLastSample = true

	// DB 派生三项由 refreshDBOverviewMetrics 每个采集周期独立维护，
	// 这里只覆盖流量样本，三项原样保留。
	activeRules, totalRules, onlineNodes := m.overview.ActiveRules, m.overview.TotalRules, m.overview.OnlineNodes
	m.overview = models.MetricsOverview{
		TotalRequests:  metrics.requestsTotal,
		RequestsPerSec: rps,
		BytesIn:        metrics.bytesIn,
		BytesOut:       metrics.bytesOut,
		Status2xx:      metrics.requests2xx,
		Status3xx:      metrics.requests3xx,
		Status4xx:      metrics.requests4xx,
		Status5xx:      metrics.requests5xx,
		LatencyP50:     metrics.latencyP50,
		LatencyP95:     metrics.latencyP95,
		LatencyP99:     metrics.latencyP99,
		ActiveRules:    activeRules,
		TotalRules:     totalRules,
		OnlineNodes:    onlineNodes,
	}
}

func (m *MetricsService) GetOverview() models.MetricsOverview {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.overview
}
