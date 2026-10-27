package caddygeoip

// 审计写插件（架构改进：耗时侧车文件退役 → 审计行内嵌 timing）。
//
// coraza 以 `SecAuditLogType lbfile` 选用本插件（security.go 渲染层发射）。
// 与退役的 serial 直写相比的两个职责：
//
//  1. timing 注入：进程内 per-request 计时注册表（auditTiming*，写点=
//     blocked_counter / SecurityTimingPre / SecurityTimingEnd，键=blocked_counter
//     注入的 X-Lb-Security-Timing-Id 头值——审计 JSON 的 request.headers 天然
//     收录该头，Write 无需解析正文即可取得关联键）在刷盘前注入审计 JSON 顶层
//     lb_timing 字段：{"pre_us":N,"end_us":M}（缺席分段省略）。读侧
//     （internal/services/securityevents.go）直接从审计行取值，
//     侧车文件与读侧 tick 级查表已整体退役。
//
//  2. 异步批量落盘 + 格式化后置：Write 只构建审计快照入队（formatter.Format
//     已移出请求路径——快照是 headers map 深拷贝+不可变字符串持有的 memcpy 级
//     开销，防 tx.Close 归还 sync.Pool 后的 live 引用污染），专职 drain goroutine
//     用注册 formatter 格式化、限时等待计时终态、注入 lb_timing、bufio 批量刷盘
//     （阈值/周期双触发）。入队有界：队列空位直接入队，满时最多等待
//     auditEnqueueTimeout，超时丢弃该条并计数告警（不把请求路径无限期拖住）。
//     管线是**进程级单例**：同一 target
//     的 fd/drain goroutine 进程内只建一次，不随 reload 重建、也不回收（见
//     acquireAuditPipeline）；写路径因此恒有活 drain 消费，不存在「管线已关」
//     的同步回退分支——上游从不调 AuditLogWriter.Close（见 FlushAuditPipelines）。
//
// 时序契约（为什么注入在 drain 侧而非 Write 侧）：coraza-caddy v2.6.2 在 WAF
// 处理函数入口即 defer tx.ProcessLogging()+tx.Close()，这两个调用在处理函数
// 返回时才执行——即审计 Write 发生在 coraza 中间件返回前的一刻：请求要么已
// 跑完下游链，要么已被中断（下游链未执行）。据此两类事件的到场状态不同：
//   - logged/放行事件：SecurityTimingPre 与 SecurityTimingEnd 都在链内、先于
//     ProcessLogging 执行，Write 时 pre/end 两段已经写好；
//   - 拦截事件（WAF/GeoIP/IP ACL/限流）：链在下游收点之前中断，拦截分段
//     （pre 或 end）与终态标记由链最外层 blocked_counter 的计时收尾写入
//     注册表——严格晚于该 Write（coraza 的 defer 先于外层包装恢复执行）。
//
// 因此注入必须留在 drain 侧：drain goroutine 对每条审计行限时等待注册表终态
// （closed），等待发生在请求路径之外；耗时数值在决策点测得（time.Since 决策
// 瞬间），入队/队列等待/刷盘延迟永不进入数值——「决策→计时→入队」的顺序保证
// 耗时数字不受污染。
//
// 轮转兼容（auditlog_rotation.go 核对）：轮转 = copytruncate（复制后截断，
// 长生命周期 fd 恒有效，O_APPEND 恒写当前 EOF），本插件不做 rename 重开；
// bufio 中暂存的字节在截断后落盘会出现在新文件头部，摄取按行解码+transaction_id
// 幂等去重，乱序无影响、零丢失。

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// auditWriterName 是插件注册名——渲染层以 `SecAuditLogType lbfile` 选用
// （coraza GetWriter 大小写不敏感）。
const auditWriterName = "lbfile"

// auditBodyMaxBytes 限制审计 part C（请求体）与 part E（响应体）在快照/队列/
// 格式化链中保留的原始体字节数（两侧同一硬上限——coraza 默认
// SecResponseBodyLimit=512KiB，响应侧不设限会让 2048 深队列放大到 ~1GiB）。
// 截断只影响审计展示，不影响 WAF 已完成的规则评估。
//
// 该上限是**原始字节**口径，而单条/队列字节估算走 JSON 转义口径
// （jsonStringEscapedLen，`<`/`>`/`&` 计 6 字节）：auditItemMaxBytes 已按
// 6× 最坏比推导，保证 64KiB 转义密集体不会被整行丢弃。
const auditBodyMaxBytes = 64 * 1024

// auditTruncatedMarker 是快照文本段（体/URI/文件名/MIME）超限截断的显式标记
// （与落库侧 services.securityEventsTruncatedMarker 同形态）：落盘值自带标记，
// 展示与导出可直接观测「该字段被裁剪」，不静默截断。二进制体不带标记，只带
// BodyTruncated_ 标记位。
const auditTruncatedMarker = "\n...[TRUNCATED]"

// 客户端可控的「非体段」上限（与 auditBodyMaxBytes/auditHeadersMaxBytes 同族）：
// transaction.request.method、transaction.server_id、transaction.request.uri 与
// files[].name/mime 同样进快照 JSON、同样按 JSON 转义口径计入单条/队列字节
// 预算。不设限时任一项即可把快照推过 auditItemMaxBytes——被丢弃的恰是「触发
// WAF 的这次请求」自身的安全事件（事件列表/大屏/自动封禁喂入全缺），客户端
// 可控字符分布即决定自身事件是否留库（与体段同一失效面）。
//
// 上限取 **转义后字节** 口径（估算/执法与落盘 JSON 同口径；原始字节上限在
// `&`/`<`/`>` 密集输入上会放大 6×）：
//   - method：64B 转义字节——标准方法名（含 WebDAV/扩展方法）远短于此；越限
//     视为构造请求，保留前缀与截断标记作证据；
//   - server_id：256B 转义字节——Caddy 服务端名称/ID 由配置生成，实践中远短于
//     此；同样保留前缀与标记；
//   - URI：8KiB，与落库侧 services.securityEventsURICap(8192) 同量级——摄取侧
//     无需二次裁剪；
//   - 单个文件名 / 单条 MIME：各 1KiB 转义字节（多部分文件名/类型实践中远小于
//     此；90KiB 全 `&` 的文件名正是漏封段）；
//   - files[] 条数：64 条；条目内容总预算 24KiB 转义字节——「条数 × 单条上限」
//     相加（64×2KiB）本身仍是 128KiB 量级，必须有总预算才能保证与体/头/
//     messages 相加后仍落在 auditItemMaxBytes 之内。
//
// 上述各段的「上限之和 + 48KiB 余量 ≤ auditItemMaxBytes」由
// TestAuditItemMaxBytes_coversAllClientControlledSegments 复算钉住：新增客户端
// 可控段必须同步声明上限，否则同族缺陷会以新字段形式回归。
const (
	auditMethodMaxEscapedBytes   = 64
	auditServerIDMaxEscapedBytes = 256
	auditURIMaxEscapedBytes      = 8 * 1024
	auditFilesMaxEntries         = 64
	auditFileFieldMaxEscaped     = 1024
	auditFilesMaxEscapedBytes    = 24 * 1024
)

func init() {
	// 计时注册表清扫参数默认值（atomic 存储，见下方 var 块说明）。
	auditTimingEntryTTLNs.Store(int64(30 * time.Second))
	auditTimingSweepIntervalNs.Store(int64(10 * time.Second))
	auditPreRetentionTTLNs.Store(int64(10 * time.Minute))
	plugins.RegisterAuditLogWriter(auditWriterName, func() plugintypes.AuditLogWriter {
		return &lbAuditWriter{}
	})
}

// 管线参数（var 供测试收窄）。
var (
	// auditQueueSize 有界队列容量：2048 条 × 典型 2-8KB；part C/E 另由快照侧
	// 64KiB 硬限。打满后入队有界等待，超时丢弃并计数告警。
	auditQueueSize = 2048
	// auditQueueByteBudget 队列驻留字节总预算：条数上限不界字节——单条快照
	// 最坏 ≈1MiB（见 auditItemMaxBytes：四段 64KiB 原始内容按 6× 转义最坏比
	// 展开）+messages，2048 深度下大 body/大 header 洪峰若不按字节收敛会撞
	// 容器内存上限（64MiB 预算下最坏形态驻留 ≤64 条）。
	// 按字节收敛后驻留有界；超预算立即丢弃（走既有 reportDropped 计数/
	// 节流告警/健康位联动），请求路径不再为超预算快照付 2s 入队等待。
	auditQueueByteBudget = int64(64 << 20)
	// auditItemMaxBytes 单条快照字节硬上限：**按转义最坏比推导**，不是原始
	// 字节相加。估算/执法口径是 JSON 转义后字节（jsonStringEscapedLen 对
	// `<`/`>`/`&` 与控制字符计 6 字节），而体段按 64KiB 原始字节截断
	// （snapshotAuditBody）——两口径必须对齐，否则 64KiB 全 `&`/`<` 的合法体
	// 展开为 384KiB，仅请求体一项就超过「四段原始字节 + 余量」的旧上限
	// （320KiB），整条安全事件被丢弃（客户端可控的字符分布即可让自身事件
	// 不留库）。
	// 上界 = 6×请求体 + 6×响应体 + 请求头 + 响应头（后两者已在快照侧按转义
	// 字节截断到各 64KiB）+ messages（转义字节 32KiB）+ method（转义字节 64B，
	// 见 auditMethodMaxEscapedBytes）+ server_id（转义字节 256B，见
	// auditServerIDMaxEscapedBytes）+ URI（转义字节 8KiB，见
	// auditURIMaxEscapedBytes）+ files[]（转义字节 24KiB + 单条余量，见
	// auditFilesMaxEscapedBytes）+ 48KiB 余量（时间戳/事务 ID/协议/地址等
	// 插件与栈侧字符串、producer 字符串、条目固定开销、messages 评估族溢出）。
	// 客户端可控段全部有显式上限，余量不再替它们兜底——越限按上限截断留标记，
	// 不整行丢弃。取 1MiB。
	auditItemMaxBytes = int64(1024 * 1024)
	// auditFlushThreshold bufio 批量刷盘字节数阈值；auditFlushInterval 周期
	// 兜底（低流量下 bufio 滞留行不超周期）。
	auditFlushThreshold = 32 * 1024
	auditFlushInterval  = 500 * time.Millisecond
	// auditEnqueueTimeout 入队有界等待上限：队列满时请求路径最多等待这么久，
	// 超时丢弃该条并计数告警——drain 沉陷时不再把请求路径无限期拖住（旧设计
	// 阻塞式零丢弃，退化价=退役前 serial 同步写，且无背压阀时请求堆积）。
	auditEnqueueTimeout = 2 * time.Second
	// auditTimingWaitLimit drain 对「条目在场但未终态」分段的限时等待：正常形态
	// （blocked_counter 是链最外层收点，紧随 coraza 中间件 defer）等待 <1ms；
	// 上限仅兜底异常形态（计时写点缺失），超时按已到场分段注入。未知 tid
	// （注册表无条目）不进本等待——auditTimingWait 首轮查表未命中即返回；
	// 若对未知 tid 也等待，单 drain goroutine 会逐行满等，就是无背压阀下的
	// drain 沉陷。
	auditTimingWaitLimit = 2 * time.Second
	auditTimingPollStep  = 200 * time.Microsecond
	// auditTimingEntryTTLNs 注册表条目存活上限（纳秒）：条目由周期性清扫回收
	// （消费不删——同一请求可产多条审计行[预检+策略引擎]，共享同一注册表条目）。
	// 以 atomic.Int64 纳秒存储而非普通 time.Duration：常驻 sweeper goroutine
	// 读、测试收窄参数写，普通变量在 `go test -race` 下构成数据竞争。零值为 0
	// （立即全部过期），默认值在 init 中置入。
	auditTimingEntryTTLNs atomic.Int64
	// auditTimingMaxEntries 注册表条目硬上限：计时 ID
	// 形态校验之外的第二道内存 DoS 防线——任何新键生产路径（含未来写点）都不
	// 得让注册表无界增长。100k 条目 ≈ 30s TTL × ~3.3k RPS 的合法上限，内存
	// 约 15MB；满时拒绝新键（该请求不计耗时，静默降级），既有键照常写入。
	auditTimingMaxEntries = 100_000
	// auditTimingSweepIntervalNs 周期清扫间隔（纳秒）：旧实现清扫仅
	// 由建条驱动（每 64 次建条一次），停流后过期条目永久驻留；后台 sweeper 按
	// 本周期兜底回收，零流量下注册表同样收敛。atomic 存储原因同上。
	auditTimingSweepIntervalNs atomic.Int64
	// auditPreRetentionTTLNs 是预检段（pre）在条目被 TTL 清扫后的独立保留期：
	// 长请求（慢上游/流式下载/大响应体）生命周期可远超条目 TTL，旧实现整条
	// 丢弃 → 终态迟到时 pre 永久缺失（审计行 pre_us 显示「—」，WAF 段还退化为
	// 全链耗时）。只保留 pre：它是链入口分段且体积恒定，跨 TTL 保留成本可控。
	auditPreRetentionTTLNs atomic.Int64
	// auditRetainedPreMaxEntries 是预检保留区硬上限：满则放弃保留（该请求
	// pre 缺失，静默降级），既有条目照常到期回收——第二张表不得无界。
	auditRetainedPreMaxEntries = 8192
)

// auditRetainedPreEntry 是条目过期后仍要保留的预检分段（键=计时 ID，
// 进程内唯一，created=转入保留区的时刻）。
type auditRetainedPreEntry struct {
	id      string
	preUs   int64
	created time.Time
}

var (
	// auditRetainedPreEntries/Order/Head 镜像主注册表的 FIFO 清扫模型
	// （调用方持 auditTimingMu）。
	auditRetainedPreEntries = map[string]auditRetainedPreEntry{}
	auditRetainedPreOrder   []auditRetainedPreEntry
	auditRetainedPreHead    int
)

// —— per-request 计时注册表 ——
// 写点：SecurityTimingPre(:pre)/SecurityTimingEnd(:end)/blocked_counter(:pre 或
// :end + 终态 close)。读点：audit drain goroutine（限时等待终态后注入）。
// 键=X-Lb-Security-Timing-Id 头值（16 字符随机 hex，进程内唯一；coraza tx ID
// 每引擎独立生成，一个请求多个引擎多个 tx ID，不能作请求级键）。

type auditTimingEntry struct {
	mu     sync.Mutex
	preUs  int64
	endUs  int64
	preSet bool
	endSet bool
	// closed 终态标记：链最外层收点（blocked_counter post-next）在全部分段
	// 写点完成后的空值写法（guard）下置位——drain 见 closed 即注入并停止等待。
	closed  bool
	created time.Time
}

// auditTimingSnapshot 是 wait 的只读快照；preSet/endSet 区分「未记录」与
// 「记录为 0」（0µs 是合法计时值）。
type auditTimingSnapshot struct {
	preUs  int64
	preSet bool
	endUs  int64
	endSet bool
	closed bool
}

func (s auditTimingSnapshot) hasAny() bool { return s.preSet || s.endSet }

// auditTimingQueueEntry 是建条顺序 FIFO 的元素：id + 建条时刻（携带单调
// 时钟读数，入队顺序即时间顺序）。
type auditTimingQueueEntry struct {
	id      string
	created time.Time
}

var (
	auditTimingMu      sync.Mutex
	auditTimingEntries = map[string]*auditTimingEntry{}
	// auditTimingOrder 是建条顺序的 FIFO：清扫只从队首弹出 TTL 已过期条目，
	// 摊销 O(过期数)。旧实现每 64 次建条全表扫描（O(n)，n≈TTL×RPS），
	// 每次请求摊销 O(n/64) 次 map 迭代且持全局锁 ⇒ CPU 随 RPS² 增长。
	// 不变量：队列内 created 单调不减（time.Now 的单调读数）。**同一条目可
	// 重建并再次入队**：条目已被 TTL 清扫后终态迟到时，retained-pre 回填
	// 路径会为同一 id 新建条目并再 append 一个 FIFO 项——所以「每条目只入队
	// 一次」不成立；清扫以 created 相等判定弹出项是否属于当前那次建条，
	// 重建条目的旧队列项不会误删新条目。
	auditTimingOrder []auditTimingQueueEntry
	// auditTimingHead 是队首游标：已弹出的前缀留在切片里，达到一定规模后
	// 整体压缩（摊销 O(1)）。
	auditTimingHead int
	// auditTimingCreateCount 记录创建次数——每 64 次创建触发一次过期清扫。
	auditTimingCreateCount int
	// auditTimingPollCountForTest 轮询总次数（测试观测钉：未知 tid/已终态
	// 条目/无计时头行必须零轮询立即返回——替代挂钟阈值断言，消除 CI 负载
	// 抖动假红）。仅 auditTimingWait 轮询步 incr，成本可忽略。
	auditTimingPollCountForTest atomic.Int64
	// auditTimingSweepVisitsForTest 清扫检查的队列元素数（钉：清扫
	// 成本必须随「过期条目数」而非注册表规模增长）。
	auditTimingSweepVisitsForTest atomic.Int64
)

// auditTimingRecord 写入一个分段计时（µs）。id 为空（计时 ID 生成失败的降级
// 形态）或形态非法（纵深：非 16-hex 不得建条——头值客户端可控）
// 静默忽略——耗时是增强信息，不产生请求路径错误。
// 条目硬上限：注册表满时拒绝新键（该请求不计耗时），既有键照常更新。
func auditTimingRecord(id, segment string, us int64) {
	if id == "" || !isValidSecurityTimingID(id) {
		return
	}
	now := time.Now()
	auditTimingMu.Lock()
	e := auditTimingEntries[id]
	if e == nil {
		if len(auditTimingEntries) >= auditTimingMaxEntries {
			auditTimingMu.Unlock()
			return
		}
		e = &auditTimingEntry{created: now}
		// 终态迟到（条目已被 TTL 清扫）时回填预检保留区里的 pre 段。
		if preUs, ok := auditRetainedPreLookupLocked(id); ok {
			e.preUs, e.preSet = preUs, true
		}
		auditTimingEntries[id] = e
		auditTimingOrder = append(auditTimingOrder, auditTimingQueueEntry{id: id, created: now})
		auditTimingSweepIfDueLocked(now)
	}
	auditTimingMu.Unlock()
	// 首个条目创建时启动周期 sweeper（进程级单例，注册表本身即
	// 包级生命周期）——停流后过期条目也由周期清扫回收，不再仅依赖建条驱动。
	startAuditTimingSweeperForTest()
	e.mu.Lock()
	// 分段键用同包常量（timingSegmentPre/End）而非字面量：生产调用点传常量，
	// 此处若写死字面量，改常量值或新增第三段时会静默不命中（分段丢失且无
	// 日志）。未知分段显式跳过——耗时是增强信息，不为它引入请求路径错误。
	switch segment {
	case timingSegmentPre:
		e.preUs, e.preSet = us, true
	case timingSegmentEnd:
		e.endUs, e.endSet = us, true
	}
	e.mu.Unlock()
}

// auditTimingSweeperOnce 保证周期 sweeper 进程内单例（Caddy reload 不复制）。
var auditTimingSweeperOnce sync.Once

// startAuditTimingSweeperForTest 启动周期清扫 goroutine（幂等；命名带
// ForTest 后缀以便测试直接触发启动而不必先建条）。每周期从 FIFO 队首弹出
// TTL 过期条目并压缩已弹出前缀，成本与过期条目数成正比。
func startAuditTimingSweeperForTest() {
	auditTimingSweeperOnce.Do(func() {
		go func() {
			// 50ms 量子累加而非一次睡满整周期：测试收窄清扫间隔后下个量子即
			// 生效（一次睡满会让测试竞速 10s 默认周期）。
			const tick = 50 * time.Millisecond
			elapsed := time.Duration(0)
			for {
				time.Sleep(tick)
				elapsed += tick
				if elapsed < time.Duration(auditTimingSweepIntervalNs.Load()) {
					continue
				}
				elapsed = 0
				auditTimingMu.Lock()
				auditTimingSweepLocked(time.Now())
				auditTimingMu.Unlock()
			}
		}()
	})
}

// auditTimingClose 标记该请求的全部分段已写完（终态）。由链最外层收点
// （blocked_counter post-next）调用——此刻整个安全链已返回，不会再有分段写点。
// 条目不存在时直接返回：drain 对未知 tid 首轮即返，
// close 建条没有收益——它只会给「零分段写点」的请求额外占一个 TTL 条目。
func auditTimingClose(id string) {
	if id == "" {
		return
	}
	auditTimingMu.Lock()
	e := auditTimingEntries[id]
	auditTimingMu.Unlock()
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
}

// auditTimingSweepIfDueLocked 建条计数 + 摊销清扫（调用方持 auditTimingMu）。
// 清扫成本与过期条目数成正比（队首弹出），不再随注册表规模增长。
func auditTimingSweepIfDueLocked(now time.Time) {
	auditTimingCreateCount++
	if auditTimingCreateCount%64 == 0 {
		auditTimingSweepLocked(now)
	}
}

// auditTimingSweepLocked 从队首弹出 TTL 过期条目（调用方持 auditTimingMu）。
// 队列 created 单调不减 ⇒ 队首未过期即整队未过期。
func auditTimingSweepLocked(now time.Time) {
	// TTL 只读一次：清扫循环内无需重复 Load（sweeper 与测试并发时口径一致）。
	ttl := time.Duration(auditTimingEntryTTLNs.Load())
	for auditTimingHead < len(auditTimingOrder) {
		item := auditTimingOrder[auditTimingHead]
		auditTimingSweepVisitsForTest.Add(1)
		if now.Sub(item.created) <= ttl {
			break
		}
		if e, ok := auditTimingEntries[item.id]; ok && e.created.Equal(item.created) {
			// drain 可能已经取出条目指针并正在等待 closed。删除前先置终态，
			// 否则后续 close 查表必 miss，等待方只能逐行轮询到超时。
			e.mu.Lock()
			// 置位前终态：已被 auditTimingClose 标记的条目其分段已全部消费，
			// pre 不再有迟到终态需要回填——若一并转入保留区，它们会与真正的
			// 长请求公平竞争并基本占满上限（高 rps 下保留区≈13.7 条/s 的
			// 稳态容量被已终态条目吃光，慢请求 pre 反而永远保留不下来）。
			wasClosed := e.closed
			e.closed = true
			preUs, preSet := e.preUs, e.preSet
			e.mu.Unlock()
			// 长请求跨 TTL：pre 是链入口分段，转入独立保留区等待终态迟到时
			// 回填（整条丢弃会让审计行 pre_us 永久「—」）。
			if preSet && !wasClosed {
				auditRetainPreLocked(item.id, preUs, now)
			}
			delete(auditTimingEntries, item.id)
		}
		auditTimingHead++
	}
	// 保留区自身按保留期回收（与主表同一次清扫，无独立 goroutine）。
	auditRetainedPreExpireLocked(now)
	// 已弹出前缀达到半量时压缩，避免 backing array 无界增长（摊销 O(1)）。
	if auditTimingHead >= 1024 && auditTimingHead*2 >= len(auditTimingOrder) {
		auditTimingOrder = append(auditTimingOrder[:0], auditTimingOrder[auditTimingHead:]...)
		auditTimingHead = 0
	}
}

// auditRetainPreLocked 把条目过期前的预检分段转入保留区（调用方持
// auditTimingMu）。满员时放弃本次保留：预检段是增强信息，不值得为它引入
// 淘汰抖动或阻塞热路径。
func auditRetainPreLocked(id string, preUs int64, now time.Time) {
	if id == "" {
		return
	}
	if _, exists := auditRetainedPreEntries[id]; !exists && len(auditRetainedPreEntries) >= auditRetainedPreMaxEntries {
		return
	}
	entry := auditRetainedPreEntry{id: id, preUs: preUs, created: now}
	auditRetainedPreEntries[id] = entry
	auditRetainedPreOrder = append(auditRetainedPreOrder, entry)
}

// auditRetainedPreLookupLocked 读保留区里的预检分段（调用方持 auditTimingMu）。
func auditRetainedPreLookupLocked(id string) (int64, bool) {
	entry, ok := auditRetainedPreEntries[id]
	if !ok {
		return 0, false
	}
	return entry.preUs, true
}

// auditRetainedPreExpireLocked 按保留期从队首弹出保留区条目（调用方持
// auditTimingMu）。FIFO 的 created 单调不减（转入时刻递增），队首未过期即
// 整队未过期。
func auditRetainedPreExpireLocked(now time.Time) {
	ttl := time.Duration(auditPreRetentionTTLNs.Load())
	for auditRetainedPreHead < len(auditRetainedPreOrder) {
		item := auditRetainedPreOrder[auditRetainedPreHead]
		if now.Sub(item.created) <= ttl {
			break
		}
		if current, ok := auditRetainedPreEntries[item.id]; ok && current.created.Equal(item.created) {
			delete(auditRetainedPreEntries, item.id)
		}
		auditRetainedPreHead++
	}
	if auditRetainedPreHead >= 1024 && auditRetainedPreHead*2 >= len(auditRetainedPreOrder) {
		auditRetainedPreOrder = append(auditRetainedPreOrder[:0], auditRetainedPreOrder[auditRetainedPreHead:]...)
		auditRetainedPreHead = 0
	}
}

// auditTimingWait 限时等待该请求的计时终态并返回快照。正常形态下 blocked_counter
// 在 coraza 中间件 defer 之后数微秒内置位终态，等待≈一个调度间隙；上限只兜底
// 「条目在场但未终态」的异常形态（计时写点缺失，超时返回已到场分段，行不丢、
// 缺段省略）。id 为空（无 timing 头的审计行）或首轮查表无条目（未知 tid）立即
// 返回空快照。
//
// 未知 tid 首轮即返，不轮询到超时。drain 在**另一个
// goroutine**里先格式化（整行 json.Marshal）再查表，与请求 goroutine 内
// 「Write（coraza defer ProcessLogging）→ blocked_counter 收点写终态」之间
// 没有因果序保证，只剩一个微秒级竞态窗（drain 抢先完成格式化并发起查表时，
// 终态可能尚未写入——此时首轮未命中，本行不注入 lb_timing）。其余首轮未命中
// 的来源：条目已被 TTL 清扫（现在 pre 转入保留区，见 auditPreRetentionTTLNs）
// 或计时写点缺失的异常行。旧行为对未知 tid 轮询满超时：单 drain goroutine ×
// 逐行满等 2s（入队当时无背压阀）= 积压行批量到场时 drain 沉陷；现入队已有
// 2s 有界等待 + 超时丢弃计数（auditEnqueueTimeout），仍不让 drain 为未知 tid
// 满等。代价：竞态窗内的行缺耗时——耗时是增强信息，展示层报「—」，可接受。
func auditTimingWait(id string, timeout time.Duration) auditTimingSnapshot {
	if id == "" {
		return auditTimingSnapshot{}
	}
	auditTimingMu.Lock()
	e := auditTimingEntries[id]
	var retained *auditTimingSnapshot
	if e == nil {
		// 长请求的条目已被 TTL 清扫、终态尚未写入：保留区里的 pre 仍有效，
		// 按「已到场分段」返回（否则整条 lb_timing 缺失）。
		if preUs, ok := auditRetainedPreLookupLocked(id); ok {
			retained = &auditTimingSnapshot{preUs: preUs, preSet: true, closed: true}
		}
	}
	auditTimingMu.Unlock()
	if e == nil {
		if retained != nil {
			return *retained
		}
		return auditTimingSnapshot{}
	}
	deadline := time.Now().Add(timeout)
	var lastSeen auditTimingSnapshot
	for {
		e.mu.Lock()
		snap := auditTimingSnapshot{preUs: e.preUs, preSet: e.preSet, endUs: e.endUs, endSet: e.endSet, closed: e.closed}
		e.mu.Unlock()
		if snap.closed {
			return snap
		}
		lastSeen = snap
		if time.Now().After(deadline) {
			// 超时：有部分分段就带部分分段（与退役前读侧「按到场键选值」同形）
			return lastSeen
		}
		auditTimingPollCountForTest.Add(1)
		time.Sleep(auditTimingPollStep)
	}
}

// securityTimingIDFromHeaders 从审计事务的请求头提取计时关联键（大小写不敏感；
// coraza 按收到形态收录 canonical 键，容错非常规形态）。缺失返回空串=不注入。
func securityTimingIDFromHeaders(headers map[string][]string) string {
	for key, values := range headers {
		if strings.EqualFold(key, securityTimingHeader) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// injectAuditTiming 把计时快照注入审计 JSON 顶层 lb_timing 字段。缺席分段省略
// （preSet/endSet 区分「未记录」与 0——0µs 是合法计时值）。解析失败原样返回
// （畸形行不因注入丢失，摄取侧自行跳过）。在 drain goroutine 内执行，不在
// 请求路径。
//
// 字节级插入而非 unmarshal→map→marshal：重编码会把 HTML 敏感字符
// （`<`/`>`/`&`/U+2028/U+2029）转义成 \uXXXX（行体最多放大 6×，审计日志
// 轮转按体积触发 ⇒ 保留窗口等比例缩短），并重排顶层键序（原始行可读性与
// formatter 字节稳定性丢失）。插入只需在单行对象的收尾 `}` 前追加一个字段。
func injectAuditTiming(body []byte, snap auditTimingSnapshot) []byte {
	if !snap.hasAny() {
		return body
	}
	payload := make([]byte, 0, 64)
	payload = append(payload, '{')
	if snap.preSet {
		payload = append(payload, `"pre_us":`...)
		payload = strconv.AppendInt(payload, snap.preUs, 10)
		if snap.endSet {
			payload = append(payload, ',')
		}
	}
	if snap.endSet {
		payload = append(payload, `"end_us":`...)
		payload = strconv.AppendInt(payload, snap.endUs, 10)
	}
	payload = append(payload, '}')

	// 容忍 formatter 可能追加的行尾空白（如尾随换行）；注入后只保留单行
	// 对象本体，行分隔由 appendLine 统一追加（与重编码时代一致，避免双换行）。
	trimmed := bytes.TrimRight(body, " \t\r\n")
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return body
	}
	if !json.Valid(trimmed) {
		return body
	}
	out := make([]byte, 0, len(trimmed)+len(payload)+16)
	out = append(out, trimmed[:len(trimmed)-1]...)
	// 空对象 `{}` 不加逗号（否则产出非法 JSON）。
	if len(bytes.TrimSpace(trimmed[1:len(trimmed)-1])) > 0 {
		out = append(out, ',')
	}
	out = append(out, `"lb_timing":`...)
	out = append(out, payload...)
	out = append(out, '}')
	return out
}

// —— 审计快照（plugintypes.AuditLog 的自持拷贝）——
//
// coraza 内部 Log 持有事务变量的 live 引用（request/response headers map、args
// 集合视图），tx.Close 会 reset 全部变量集合并把事务归还 sync.Pool 供下一请求
// 复用——格式化若晚于 Close（drain 侧延迟格式化）读到的是被清空甚至被复写的
// 数据。快照在 Write 时点（Close 之前）拷贝全部 formatter 消费面：字符串在 Go
// 不可变直接持有，headers map/文件列表/消息切片重建隔离。畸形兼容：零值事务
// （无 Transaction 的畸形 AuditLog）走零值快照，格式化输出 zero 对象，不 panic。

// auditSnapshot 实现 plugintypes.AuditLog。字段标签与 coraza 内部 Log 逐一对齐
// （transaction 恒在场、messages omitempty、parts 不入 JSON），注册 formatter
// （内置 JSON=json.Marshal 直出）的输出信封与同步格式化时代逐字段一致。
type auditSnapshot struct {
	Parts_       types.AuditLogParts           `json:"-"`
	Transaction_ auditSnapshotTransaction      `json:"transaction"`
	Messages_    []plugintypes.AuditLogMessage `json:"messages,omitempty"`
	// MessagesDropped_ 是写侧 messages 上限截断时丢弃的条数（0 不发射）：
	// 整行不再因命中规则过多被 auditItemMaxBytes 丢弃，丢失量显性可见。
	// 丢弃只发生在中间段——头部与尾部（CRS 评估汇总）都保留。
	MessagesDropped_ int `json:"messages_dropped,omitempty"`
}

func (s *auditSnapshot) Parts() types.AuditLogParts { return s.Parts_ }

func (s *auditSnapshot) Transaction() plugintypes.AuditLogTransaction { return &s.Transaction_ }

func (s *auditSnapshot) Messages() []plugintypes.AuditLogMessage { return s.Messages_ }

// auditSnapshotTransaction 实现 plugintypes.AuditLogTransaction。request 恒在场
// （coraza 的 tx.AuditLog 总是分配 Request_），pointer nil=原始缺失。
type auditSnapshotTransaction struct {
	Timestamp_       string                 `json:"timestamp"`
	UnixTimestamp_   int64                  `json:"unix_timestamp"`
	ID_              string                 `json:"id"`
	ClientIP_        string                 `json:"client_ip"`
	ClientPort_      int                    `json:"client_port"`
	HostIP_          string                 `json:"host_ip"`
	HostPort_        int                    `json:"host_port"`
	ServerID_        string                 `json:"server_id"`
	Request_         *auditSnapshotRequest  `json:"request,omitempty"`
	Response_        *auditSnapshotResponse `json:"response,omitempty"`
	Producer_        *auditSnapshotProducer `json:"producer,omitempty"`
	HighestSeverity_ string                 `json:"highest_severity"`
	IsInterrupted_   bool                   `json:"is_interrupted"`
}

func (t *auditSnapshotTransaction) Timestamp() string {
	if t == nil {
		return ""
	}
	return t.Timestamp_
}

func (t *auditSnapshotTransaction) UnixTimestamp() int64 {
	if t == nil {
		return 0
	}
	return t.UnixTimestamp_
}

func (t *auditSnapshotTransaction) ID() string {
	if t == nil {
		return ""
	}
	return t.ID_
}

func (t *auditSnapshotTransaction) ClientIP() string {
	if t == nil {
		return ""
	}
	return t.ClientIP_
}

func (t *auditSnapshotTransaction) ClientPort() int {
	if t == nil {
		return 0
	}
	return t.ClientPort_
}

func (t *auditSnapshotTransaction) HostIP() string {
	if t == nil {
		return ""
	}
	return t.HostIP_
}

func (t *auditSnapshotTransaction) HostPort() int {
	if t == nil {
		return 0
	}
	return t.HostPort_
}

func (t *auditSnapshotTransaction) ServerID() string {
	if t == nil {
		return ""
	}
	return t.ServerID_
}

func (t *auditSnapshotTransaction) HasRequest() bool {
	return t != nil && t.Request_ != nil
}

// Request 缺席时返回 nil 接口（比 coraza 的 typed-nil 更保守：formatter 侧的
// != nil 哨兵在此语义下成立）。
func (t *auditSnapshotTransaction) Request() plugintypes.AuditLogTransactionRequest {
	if t == nil || t.Request_ == nil {
		return nil
	}
	return t.Request_
}

func (t *auditSnapshotTransaction) HasResponse() bool {
	return t != nil && t.Response_ != nil
}

func (t *auditSnapshotTransaction) Response() plugintypes.AuditLogTransactionResponse {
	if t == nil {
		return nil
	}
	return t.Response_
}

func (t *auditSnapshotTransaction) Producer() plugintypes.AuditLogTransactionProducer {
	if t == nil {
		return nil
	}
	return t.Producer_
}

func (t *auditSnapshotTransaction) HighestSeverity() string {
	if t == nil {
		return ""
	}
	return t.HighestSeverity_
}

func (t *auditSnapshotTransaction) IsInterrupted() bool {
	return t != nil && t.IsInterrupted_
}

// auditSnapshotRequest 实现 plugintypes.AuditLogTransactionRequest。嵌入原始请求
// 接口仅为提升 Args()——其返回类型是 coraza internal 包（collections.ConcatKeyed），
// 外部包无法命名实现；其余访问器全部走本快照（影子方法遮蔽提升方法）。Args() 仅
// OCSF/自定义格式化器消费（本项目固定 JSON 渲染，JSON 输出经下方标签字段与内置
// 格式化器一致：args 恒 {} 空对象）。
//
// 嵌入值不是事务活对象，而是 frozenArgsRequest(req) 返回的同动态类型
// typed-nil 指针——只保留 Args() 的接口契约，不引用事务变量集合。旧实现嵌入 live
// 请求，注释声称「tx.Close 后为空读」与 coraza 实现不符（ConcatKeyed 持有事务
// argsGet/argsPost 的长期引用，tx 回池复用后 Args() 会读到下一请求的参数，而
// drain 侧格式化恒晚于 tx.Close）。
type auditSnapshotRequest struct {
	plugintypes.AuditLogTransactionRequest `json:"-"`
	Method_                                string              `json:"method"`
	Protocol_                              string              `json:"protocol"`
	URI_                                   string              `json:"uri"`
	HTTPVersion_                           string              `json:"http_version"`
	Headers_                               map[string][]string `json:"headers"`
	// HeadersBytes_ 是 Headers_ 的精确序列化字节数（snapshotAuditHeaders 已算出，
	// 不入 JSON）：入队字节估算直接引用，避免按条固定开销重估失真。
	HeadersBytes_  int64                                         `json:"-"`
	Body_          string                                        `json:"body"`
	BodyTruncated_ bool                                          `json:"body_truncated,omitempty"`
	Files_         []plugintypes.AuditLogTransactionRequestFiles `json:"files"`
	// FilesDropped_ 是被条数/字节预算上限省略的 files[] 条目数（omitempty）：
	// 文件明细只服务取证展示，不能因其挤掉整条安全事件——超出时截断并把丢弃
	// 条数显性记入本键（与 messages_dropped 同一披露姿态）。
	FilesDropped_ int      `json:"files_dropped,omitempty"`
	ArgsStub      struct{} `json:"args"`
	Length_       int32    `json:"length"`
}

func (r *auditSnapshotRequest) Method() string {
	if r == nil {
		return ""
	}
	return r.Method_
}

func (r *auditSnapshotRequest) Protocol() string {
	if r == nil {
		return ""
	}
	return r.Protocol_
}

func (r *auditSnapshotRequest) URI() string {
	if r == nil {
		return ""
	}
	return r.URI_
}

func (r *auditSnapshotRequest) HTTPVersion() string {
	if r == nil {
		return ""
	}
	return r.HTTPVersion_
}

func (r *auditSnapshotRequest) Headers() map[string][]string {
	if r == nil {
		return nil
	}
	return r.Headers_
}

func (r *auditSnapshotRequest) Body() string {
	if r == nil {
		return ""
	}
	return r.Body_
}

func (r *auditSnapshotRequest) Files() []plugintypes.AuditLogTransactionRequestFiles {
	if r == nil {
		return nil
	}
	return r.Files_
}

func (r *auditSnapshotRequest) Length() int32 {
	if r == nil {
		return 0
	}
	return r.Length_
}

// auditSnapshotFile 实现 plugintypes.AuditLogTransactionRequestFiles（值类型，
// 与 coraza 内部形态一致）。
type auditSnapshotFile struct {
	Name_ string `json:"name"`
	Size_ int64  `json:"size"`
	Mime_ string `json:"mime"`
}

func (f auditSnapshotFile) Name() string { return f.Name_ }

func (f auditSnapshotFile) Size() int64 { return f.Size_ }

func (f auditSnapshotFile) Mime() string { return f.Mime_ }

// auditSnapshotResponse 实现 plugintypes.AuditLogTransactionResponse。
// BodyTruncated_ 与请求侧同标记位（JSON 契约对称 omitempty）。
type auditSnapshotResponse struct {
	Protocol_ string              `json:"protocol"`
	Status_   int                 `json:"status"`
	Headers_  map[string][]string `json:"headers"`
	// HeadersBytes_ 同请求侧（精确序列化字节，不入 JSON）。
	HeadersBytes_  int64  `json:"-"`
	Body_          string `json:"body"`
	BodyTruncated_ bool   `json:"body_truncated,omitempty"`
}

func (r *auditSnapshotResponse) Protocol() string {
	if r == nil {
		return ""
	}
	return r.Protocol_
}

func (r *auditSnapshotResponse) Status() int {
	if r == nil {
		return 0
	}
	return r.Status_
}

func (r *auditSnapshotResponse) Headers() map[string][]string {
	if r == nil {
		return nil
	}
	return r.Headers_
}

func (r *auditSnapshotResponse) Body() string {
	if r == nil {
		return ""
	}
	return r.Body_
}

// auditSnapshotProducer 实现 plugintypes.AuditLogTransactionProducer。
type auditSnapshotProducer struct {
	Connector_  string   `json:"connector"`
	Version_    string   `json:"version"`
	Server_     string   `json:"server"`
	RuleEngine_ string   `json:"rule_engine"`
	Stopwatch_  string   `json:"stopwatch"`
	Rulesets_   []string `json:"rulesets"`
}

func (p *auditSnapshotProducer) Connector() string {
	if p == nil {
		return ""
	}
	return p.Connector_
}

func (p *auditSnapshotProducer) Version() string {
	if p == nil {
		return ""
	}
	return p.Version_
}

func (p *auditSnapshotProducer) Server() string {
	if p == nil {
		return ""
	}
	return p.Server_
}

func (p *auditSnapshotProducer) RuleEngine() string {
	if p == nil {
		return ""
	}
	return p.RuleEngine_
}

func (p *auditSnapshotProducer) Stopwatch() string {
	if p == nil {
		return ""
	}
	return p.Stopwatch_
}

func (p *auditSnapshotProducer) Rulesets() []string {
	if p == nil {
		return nil
	}
	return p.Rulesets_
}

// 快照类型接口合规钉（编译期）。
var (
	_ plugintypes.AuditLog                        = (*auditSnapshot)(nil)
	_ plugintypes.AuditLogTransaction             = (*auditSnapshotTransaction)(nil)
	_ plugintypes.AuditLogTransactionRequest      = (*auditSnapshotRequest)(nil)
	_ plugintypes.AuditLogTransactionRequestFiles = auditSnapshotFile{}
	_ plugintypes.AuditLogTransactionResponse     = (*auditSnapshotResponse)(nil)
	_ plugintypes.AuditLogTransactionProducer     = (*auditSnapshotProducer)(nil)
)

// snapshotAuditBody 对审计体（part C 请求体 / part E 响应体，同
// 上限同语义）做字节级硬截断。超长前缀必须 Clone：直接切片会让快照继续持有
// 原始大 string 的整个 backing array，失去内存上限意义。
func snapshotAuditBody(body string) (string, bool) {
	if len(body) <= auditBodyMaxBytes {
		return body, false
	}
	cut := auditBodyMaxBytes
	// 写侧与读侧上限相等，读侧无法凭长度判断截断；文本在写侧显式追加
	// 标记，避免 UI 把半截 body 当完整内容。二进制不
	// 追加（会破坏 base64 判定）。
	for cut > 0 && !utf8.RuneStart(body[cut]) {
		cut--
	}
	prefix := strings.Clone(body[:cut])
	if utf8.ValidString(prefix) {
		return prefix + auditTruncatedMarker, true
	}
	return prefix, true
}

// snapshotClipEscaped 按 **JSON 转义后字节** 预算截断文本（估算/执法与落盘
// JSON 同口径，见 jsonStringEscapedLen）：逐字符累加转义长度，超限处停在
// UTF-8 边界，克隆前缀并追加 auditTruncatedMarker。原始字节上限在 `&`/`<`/`>`
// 密集输入上会放大 6×，正是本函数存在的理由。
//
// 只对超限文本扫描到上限（未超限走一次全串计数，返回值复用原 string，
// 零分配）；超限前缀必须 Clone，否则快照继续持有原始大 string 的 backing
// array，内存上限失真。
func snapshotClipEscaped(s string, maxEscapedBytes int) (string, bool) {
	if maxEscapedBytes <= 0 || s == "" {
		return s, false
	}
	used := 0
	cut := 0
	for cut < len(s) {
		_, size := utf8.DecodeRuneInString(s[cut:])
		if size <= 0 {
			break
		}
		esc := jsonStringEscapedLen(s[cut : cut+size])
		if used+esc > maxEscapedBytes {
			break
		}
		used += esc
		cut += size
	}
	if cut >= len(s) {
		return s, false
	}
	return strings.Clone(s[:cut]) + auditTruncatedMarker, true
}

// auditHeadersMaxBytes 快照 headers（请求/响应）序列化字节硬上限（与 part
// C/E 的 64KiB 同口径）：Caddy 默认 MaxHeaderBytes≈1MB，整表深拷贝不设限
// 会让 2048 深队列与 2s 入队等待期的在途快照在洪峰下被单条大头放大数百倍。
// 截断只影响审计展示，不影响 WAF 已完成的规则评估。
const auditHeadersMaxBytes = 64 * 1024

// auditSnapshotDroppedHeadersKey 与摄取落库侧（services 的 64KB 落库裁剪）
// 同一合成键：面板按信息行渲染该键。插件是客户端头的首个受信触点——伪造的
// 同名客户端头在此一律剥离，此后管线内出现的该键均为写侧真实丢弃计数。
const auditSnapshotDroppedHeadersKey = "_lb_dropped_headers"

// auditHeaderEntrySerializedBytes 返回单条 header 条目 `"k":["v1","v2"],` 的
// 精确序列化字节数（含 JSON 语法与条目间逗号）：键/值走
// jsonStringEscapedLen 逐字节对齐 json.Marshal，零分配。
func auditHeaderEntrySerializedBytes(k string, vs []string) int64 {
	size := int64(jsonStringEscapedLen(k)) + 3 // "k":
	if len(vs) == 0 {
		size += 2 // []
	} else {
		size += 2 // 两侧 []
		for _, s := range vs {
			size += int64(jsonStringEscapedLen(s)) + 2 // "v"
		}
		size += int64(len(vs) - 1) // 值间逗号
	}
	return size + 1 // 条目间逗号
}

// snapshotAuditHeaders 深拷贝请求/响应头并施加 64KiB 序列化上限（有界口径与
// part C/E 一致）：先剥离客户端伪造的丢弃计数键，再按序列化体积降序丢条目
// 直至落入上限，丢弃数写入合成键（摄取落库侧会把该计数并入自身裁剪计数）。
// 尺寸估算用 jsonStringEscapedLen 精确计数（与 json.Marshal 逐字节一致，
// 零分配字节扫描）——请求路径不再为每个 header key/value 付出一次
// json.Marshal 的编码与分配。
//
// 第二个返回值是该 map 的精确序列化字节数（含外层 `{}` 与条目逗号，恒为实际
// 值的上界至多 1 字节）：入队字节预算直接引用它，不再按每条 header 的固定
// 开销重估——固定开销在头部密集（几千条短 header）时会把约 70KiB 估成
// ~350KiB，请求/响应两侧叠加即越过 auditItemMaxBytes 把整行丢弃。
func snapshotAuditHeaders(hs map[string][]string) (map[string][]string, int64) {
	if hs == nil {
		return nil, 0
	}
	out := make(map[string][]string, len(hs))
	type keySize struct {
		key  string
		size int64
	}
	keys := make([]keySize, 0, len(hs))
	total := int64(2) // 外层 {}
	for k, v := range hs {
		if strings.EqualFold(k, auditSnapshotDroppedHeadersKey) {
			continue // 客户端伪造的丢弃计数键一律剥离（写侧保留键）
		}
		vv := append([]string(nil), v...)
		out[k] = vv
		size := auditHeaderEntrySerializedBytes(k, vv)
		keys = append(keys, keySize{key: k, size: size})
		total += size
	}
	if len(out) == 0 {
		return nil, 0
	}
	if total <= auditHeadersMaxBytes {
		return out, total
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].size != keys[j].size {
			return keys[i].size > keys[j].size
		}
		return keys[i].key < keys[j].key
	})
	// 丢弃标记键的精确形态开销（dropped 位数按 6 位上限预留）。
	markerOverhead := int64(len(`"_lb_dropped_headers":["000000"]`) + 1)
	dropped := 0
	for _, ks := range keys {
		if total+markerOverhead <= auditHeadersMaxBytes {
			break
		}
		delete(out, ks.key)
		total -= ks.size
		dropped++
	}
	marker := strconv.Itoa(dropped)
	out[auditSnapshotDroppedHeadersKey] = []string{marker}
	return out, total + int64(len(`"_lb_dropped_headers":[""]`)+len(marker)+1)
}

// jsonStringEscapedLen 返回 s 经 encoding/json 字符串编码后的精确字节数
// （不含两侧引号），与 json.Marshal 的转义规则逐一对齐：引号/反斜杠与
// \b\f\n\r\t 双字节短转义，其余控制字符与 HTML 安全字符 <>& 按 \u00XX
// 六字节，U+2028/U+2029 按 \u202X 六字节，非法 UTF-8 字节替换为
// U+FFFD（3 字节）。等值性由随机串对拍测试钉住；纯字节扫描零分配。
func jsonStringEscapedLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			switch {
			case c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t':
				n += 2
			case c == '<' || c == '>' || c == '&' || c < 0x20:
				n += 6
			default:
				n++
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			n += 3 // 非法 UTF-8 字节 → 替换为 U+FFFD
		case r == '\u2028' || r == '\u2029':
			n += 6
		default:
			n += size
		}
	}
	return n
}

// snapshotAuditLog 把 live AuditLog 拷贝为自持快照。接口 nil 检查穿透 typed-nil
// （coraza 的 Response()/Producer() 返回 typed-nil 指针——接口非 nil 但底层为
// nil，按缺失处理保持 JSON 信封一致：response/producer omitempty）。
func snapshotAuditLog(al plugintypes.AuditLog) *auditSnapshot {
	s := &auditSnapshot{Parts_: append(types.AuditLogParts(nil), al.Parts()...)}
	if tx := al.Transaction(); !isNilInterface(tx) {
		s.Transaction_ = *snapshotTransaction(tx)
	}
	// messages 写侧上限：条数 + 估算字节双门（与快照估算同口径）。超限不再
	// 让整行撞 auditItemMaxBytes 被丢弃——保留高价值事务信息并把丢弃条数
	// 显性记入 messages_dropped。
	s.Messages_, s.MessagesDropped_ = snapshotAuditMessages(al.Messages())
	return s
}

// snapshotAuditMessages 按「掐中间、保两头」截断 messages：丢弃只发生在中间
// 段，头部（攻击特征命中序列的前若干条）与尾部（CRS 评估汇总）都保留。
//
// 尾部固定保留不是可选优化：CRS 的 949xxx/959xxx 评估规则在 phase 4/5 运行，
// 其 msg 携带事务累计总分（"Total Score: N"），异常分只从那里读；只保开头
// 会把汇总消息丢掉，使命中规则多的请求分数归零（与 severityScale 分档冲突），
// 且这类请求恰是审计价值最高的。尾部估算字节独立预算，评估消息（数十字节）
// 不会挤压头部条目。
func snapshotAuditMessages(msgs []plugintypes.AuditLogMessage) ([]plugintypes.AuditLogMessage, int) {
	if len(msgs) == 0 {
		return nil, 0
	}
	// 尾段：从末尾向前保留至多 auditMessagesTailEntries 条 / auditMessagesTailBytes
	// 估算；评估汇总消息超出条数上限也继续收集（有上限，防单行串成条）。
	tailStart := len(msgs)
	var tailBytes int64
	tailEntries := 0
	for tailStart > 0 && tailEntries < auditMessagesTailEntries*2 {
		m := msgs[tailStart-1]
		eval := auditMessageIsEvaluation(m)
		if !eval && tailEntries >= auditMessagesTailEntries {
			break
		}
		size := estimateAuditMessageBytes(m)
		if !eval && tailEntries > 0 && tailBytes+size > auditMessagesTailBytes {
			break
		}
		tailBytes += size
		tailEntries++
		tailStart--
	}
	// 头段：填满剩余条目/字节预算（总字节 = 头 + 尾 ≤ auditMessagesMaxBytes）。
	headEntries := 0
	var headBytes int64
	headLimit := auditMessagesMaxEntries - tailEntries
	if headLimit < 0 {
		headLimit = 0
	}
	for headEntries < tailStart && headEntries < headLimit {
		size := estimateAuditMessageBytes(msgs[headEntries])
		if headBytes+size > auditMessagesMaxBytes-tailBytes {
			break
		}
		headBytes += size
		headEntries++
	}
	out := make([]plugintypes.AuditLogMessage, 0, headEntries+(len(msgs)-tailStart))
	out = append(out, msgs[:headEntries]...)
	out = append(out, msgs[tailStart:]...)
	return out, tailStart - headEntries
}

// auditMessageIsEvaluation 判定 CRS 评估汇总消息（949xxx 入站/959xxx 出站）：
// 异常分只从这类消息的 msg 文本里读，截断必须优先收纳在尾段。
func auditMessageIsEvaluation(m plugintypes.AuditLogMessage) bool {
	if isNilInterface(m) {
		return false
	}
	data := m.Data()
	if isNilInterface(data) {
		return false
	}
	id := data.ID()
	return (id >= 949000 && id <= 949999) || (id >= 959000 && id <= 959999)
}

func snapshotTransaction(tx plugintypes.AuditLogTransaction) *auditSnapshotTransaction {
	// server_id 与请求侧客户端可控段同门封顶（见 auditServerIDMaxEscapedBytes）：
	// 超长取值同样进 JSON 转义口径的单条/队列预算，不封顶即可让本行撞
	// auditItemMaxBytes 整行丢弃。
	serverID, _ := snapshotClipEscaped(tx.ServerID(), auditServerIDMaxEscapedBytes-len(auditTruncatedMarker))
	t := &auditSnapshotTransaction{
		Timestamp_:       tx.Timestamp(),
		UnixTimestamp_:   tx.UnixTimestamp(),
		ID_:              tx.ID(),
		ClientIP_:        tx.ClientIP(),
		ClientPort_:      tx.ClientPort(),
		HostIP_:          tx.HostIP(),
		HostPort_:        tx.HostPort(),
		ServerID_:        serverID,
		HighestSeverity_: tx.HighestSeverity(),
		IsInterrupted_:   tx.IsInterrupted(),
	}
	if req := tx.Request(); !isNilInterface(req) {
		body, bodyTruncated := snapshotAuditBody(req.Body())
		// URI 与 files[] 是客户端可控的非体段，必须与体/头同门封顶（见
		// auditURIMaxEscapedBytes）：否则单个超长 URI/文件名即可把本行推过
		// auditItemMaxBytes，让「触发 WAF 的这次请求」自身的安全事件被整行丢弃。
		// 内容预算留出标记字节 → 截断后整字段转义字节 ≤ 上限，摄取侧
		// （services.securityEventsURICap 同值）不再二次裁剪（避免双标记）。
		uri, _ := snapshotClipEscaped(req.URI(), auditURIMaxEscapedBytes-len(auditTruncatedMarker))
		// method 同属客户端可控的事务字符串：超长伪造方法名（请求行由客户端
		// 决定）不封顶时会与体/头/URI 叠加把本行推过 auditItemMaxBytes。按
		// auditMethodMaxEscapedBytes 封顶并留截断标记，保留前缀作为取证线索。
		method, _ := snapshotClipEscaped(req.Method(), auditMethodMaxEscapedBytes-len(auditTruncatedMarker))
		r := &auditSnapshotRequest{
			Method_:        method,
			Protocol_:      req.Protocol(),
			URI_:           uri,
			HTTPVersion_:   req.HTTPVersion(),
			Body_:          body,
			BodyTruncated_: bodyTruncated,
			Length_:        req.Length(),
			ArgsStub:       struct{}{},
		}
		if hs := req.Headers(); hs != nil {
			r.Headers_, r.HeadersBytes_ = snapshotAuditHeaders(hs)
		}
		files := req.Files()
		fileBudget := int64(auditFilesMaxEscapedBytes)
		for i, f := range files {
			if i >= auditFilesMaxEntries {
				r.FilesDropped_ = len(files) - i
				break
			}
			if isNilInterface(f) {
				continue
			}
			name, _ := snapshotClipEscaped(f.Name(), auditFileFieldMaxEscaped)
			mime, _ := snapshotClipEscaped(f.Mime(), auditFileFieldMaxEscaped)
			cost := int64(jsonStringEscapedLen(name)+jsonStringEscapedLen(mime)) + auditFileEntryOverhead
			if cost > fileBudget {
				// 条目内容总预算：条数上限之外的第二道门（64×2KiB 相加仍是
				// 128KiB 量级，必须另有总预算才保证与体/头/messages 相加后
				// 不越过单条上限）。
				r.FilesDropped_ = len(files) - i
				break
			}
			fileBudget -= cost
			r.Files_ = append(r.Files_, auditSnapshotFile{Name_: name, Size_: f.Size(), Mime_: mime})
		}
		r.AuditLogTransactionRequest = frozenArgsRequest(req)
		t.Request_ = r
	}
	if resp := tx.Response(); !isNilInterface(resp) {
		// 响应体与请求体同硬上限（coraza 默认
		// SecResponseBodyLimit=512KiB——不截断则快照/队列/落盘全链放大）。
		respBody, respTruncated := snapshotAuditBody(resp.Body())
		q := &auditSnapshotResponse{
			Protocol_:      resp.Protocol(),
			Status_:        resp.Status(),
			Body_:          respBody,
			BodyTruncated_: respTruncated,
		}
		if hs := resp.Headers(); hs != nil {
			q.Headers_, q.HeadersBytes_ = snapshotAuditHeaders(hs)
		}
		t.Response_ = q
	}
	if prod := tx.Producer(); !isNilInterface(prod) {
		p := &auditSnapshotProducer{
			Connector_:  prod.Connector(),
			Version_:    prod.Version(),
			Server_:     prod.Server(),
			RuleEngine_: prod.RuleEngine(),
			Stopwatch_:  prod.Stopwatch(),
		}
		if rs := prod.Rulesets(); rs != nil {
			p.Rulesets_ = append([]string(nil), rs...)
		}
		t.Producer_ = p
	}
	return t
}

// frozenArgsRequest 返回不再引用 coraza 事务活对象的请求接口值，仅用于满足
// AuditLogTransactionRequest 的 Args() 方法（返回类型不可命名，外部包只能经
// 接口提升实现）。做法：取该请求动态类型的零值（typed-nil 指针）——coraza 的
// *auditlog.TransactionRequest.Args() 在 nil 接收者上返回全新的空 ConcatKeyed
// （internal/auditlog/auditlog.go，nil 分支），因此任何迟到的 Args() 读取得到
// 「空」而不是复用事务里下一请求的参数。
//
// 保守回退：动态类型非指针、类型断言失败，或零值上 Args() panic/返回 nil 时，
// 返回原接口（行为与修复前一致）。coraza 当前形态恒走冻结分支。
func frozenArgsRequest(req plugintypes.AuditLogTransactionRequest) plugintypes.AuditLogTransactionRequest {
	t := reflect.TypeOf(req)
	if t == nil || t.Kind() != reflect.Pointer {
		return req
	}
	frozen, ok := reflect.Zero(t).Interface().(plugintypes.AuditLogTransactionRequest)
	if !ok {
		return req
	}
	if !argsNilSafe(t, frozen) {
		return req
	}
	return frozen
}

// frozenArgsSafety 缓存「该动态类型零值上 Args() 是否安全」的探测结果——
// 探测会分配一个空集合，按类型缓存一次即可（审计行构建在请求路径上）。
var frozenArgsSafety sync.Map // reflect.Type → bool

// argsNilSafe 探测零值请求上的 Args() 是否安全返回非 nil（nil 接收者实现）。
// 返回值类型是 coraza internal 类型，只能以 any 承接；仅做 nil 判定。
func argsNilSafe(t reflect.Type, req plugintypes.AuditLogTransactionRequest) bool {
	if cached, ok := frozenArgsSafety.Load(t); ok {
		return cached.(bool)
	}
	safe := func() (safe bool) {
		defer func() {
			if recover() != nil {
				safe = false
			}
		}()
		args := req.Args()
		return args != nil
	}()
	frozenArgsSafety.Store(t, safe)
	return safe
}

// isNilInterface 判定接口值为 nil 或持 typed-nil 指针。
func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	}
	return false
}

// —— 审计写插件与共享管线 ——

// lbAuditItem 是队列元素：审计快照 + 注册格式化器 + 计时关联键（空=无计时）。
// 格式化已移出请求路径——Write 只构建快照，drain 侧用随行 formatter
// 格式化（同一 target 的 writer 同构，但保守以 Write 时点的 formatter 为准）。
type lbAuditItem struct {
	snap      *auditSnapshot
	formatter plugintypes.AuditLogFormatter
	tid       string
	// bytes 是快照驻留字节估算（enqueue 时计算一次，drain 消费后从队列
	// 字节预算中扣减）。
	bytes int64
}

// auditPipeline 是按目标路径共享的落盘管线（单 drain goroutine + 单 fd +
// bufio）。多个 coraza WAF 实例（预检+各策略引擎，各自 NewWAF→独立 writer
// 实例）追加同一审计文件时共享一条管线。
//
// 生命周期=进程级单例（用户可感知的持久性取舍见 acquireAuditPipeline）：
// target/queue/done/mode 创建后只读——queue 恒非 nil 且写侧永不关闭它，故
// 入队无需锁；done 在 drain 退出时关闭（进程运行期恒不闭合，仅测试收尾观测）。
type auditPipeline struct {
	target string
	queue  chan lbAuditItem
	done   chan struct{}
	mode   os.FileMode
	// ioMu 保护 fd/bufio（仅 drain goroutine 触碰，独立于注册表锁，防止请求
	// 路径 enqueue 与刷盘互斥）。
	ioMu sync.Mutex
	fd   *os.File
	bw   *bufio.Writer
	// dropped 是入队超时丢弃的审计行累计计数（进程级管线全生命周期）。
	dropped atomic.Uint64
	// queueBytes 是队列驻留字节估算（enqueue 占额、drain 消费扣减、丢弃
	// 回滚）——auditQueueByteBudget 的记账源。
	queueBytes atomic.Int64
	// pending 是「已准入但尚未处理完」的条目计数：enqueue 准入时递增、
	// drain 处理完递减。准入先于入队/等待，因此 pending==0 蕴含「队列为空
	// 且无在途处理」——收尾刷盘（flushQuiesced）据此判定已入队行全部落盘，
	// 不存在「已出队未计数」的判定窗口。
	pending atomic.Int64
	// ioErrors 是落盘/刷盘/重开/关闭错误累计计数：与 dropped 一起由 drain
	// 低频写入侧车文件，供根服务健康位消费。格式化失败不计入本计数——它是
	// 代码/契约缺陷（formatter 或快照实现），不是磁盘 IO 故障，混计会把
	// 代码问题伪装成基础设施告警。
	ioErrors atomic.Uint64
	// formatErrors 是 formatter.Format 失败累计计数（独立侧车字段
	// format_errors）：排障路径与 io_errors 完全不同（先查代码而非磁盘）。
	formatErrors atomic.Uint64
	// dropLog/ioErrLog/formatErrLog 是三类写侧失败告警的节流状态（单源
	// auditLogThrottle：首次立即记录，其后每分钟至多一条并携带被抑制数）。
	// 计数目标/日志缝/文案各不相同，但窗口与首报规则必须一致。
	dropLog      auditLogThrottle
	ioErrLog     auditLogThrottle
	formatErrLog auditLogThrottle
	// statsDirty 标记累计计数自上次写盘后是否变化；statsMu 保护写盘节流
	// 状态（仅 drain goroutine 触碰，无需与请求路径互斥——计数是原子读）。
	statsDirty     atomic.Bool
	statsMu        sync.Mutex
	lastStatsWrite time.Time
	// statsFailLog 是侧车写盘失败的告警节流状态（磁盘满/目录只读时侧车双向
	// 失效：写不进也读不到；不留痕则写侧丢弃/IO 计数对外恒 0、健康位假绿）。
	statsFailLog auditLogThrottle
}

// auditWriterStatsSuffix 是写侧失败计数侧车文件名后缀（紧跟审计日志目标路径）。
// 契约另一端：根服务 internal/services 的 securityEventsAuditWriterStatsPath
// （跨 Go module 无共享包，两处后缀/字段名必须同步；两侧各有钉测）。
const auditWriterStatsSuffix = ".writer-stats.json"

// auditWriterStatsInterval 是侧车计数写盘的最小间隔（drain 侧低频写；
// 失败洪峰不放大磁盘 IO，请求路径零参与）。var 供测试收窄。
var auditWriterStatsInterval = 3 * time.Second

// auditWriterStatsPath 返回目标路径对应的侧车计数文件路径。
func auditWriterStatsPath(target string) string { return target + auditWriterStatsSuffix }

// auditWriterStatsFailureSuffix 是侧车写盘失败标记（紧跟侧车计数文件）。
// 跨进程协议第三段：计数侧车写不进去时（磁盘满/目录只读），计数变化无法
// 落盘——根服务看到的是旧值或文件缺失（首写即失败），按「缺失=正常」会假绿。
// 失败标记让写侧故障跨进程可见；成功写盘即删除标记。根服务按
// securityEventsAuditWriterStatsFailureSuffix 同值读取（跨 module 两处同步）。
const auditWriterStatsFailureSuffix = ".failed"

// auditWriterStatsFailurePath 返回侧车写盘失败标记路径。
func auditWriterStatsFailurePath(target string) string {
	return auditWriterStatsPath(target) + auditWriterStatsFailureSuffix
}

// markWriterStatsFailure 尽力写入失败标记（磁盘满时同样可能失败：此时只剩
// 进程日志，根侧按「侧车缺失」处理，不虚构成功）。内容携带时间与原因，供
// 排障直接读取。
func (p *auditPipeline) markWriterStatsFailure(now time.Time, cause error) {
	path := auditWriterStatsFailurePath(p.target)
	body := fmt.Sprintf("writer-stats sidecar write failed at %s: %v\n", now.UTC().Format(time.RFC3339), cause)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		auditIOLogf("audit writer: writer-stats failure marker write failed for %s: %v", p.target, err)
	}
}

// clearWriterStatsFailure 删除失败标记（侧车计数恢复可写）。
func (p *auditPipeline) clearWriterStatsFailure() {
	if err := os.Remove(auditWriterStatsFailurePath(p.target)); err != nil && !errors.Is(err, os.ErrNotExist) {
		auditIOLogf("audit writer: writer-stats failure marker removal failed for %s: %v", p.target, err)
	}
}

// auditIOLogf 审计落盘错误日志缝（测试注入；缺省 caddy.Log）。
var auditIOLogf = func(format string, args ...any) {
	caddy.Log().Named("auditwriter").Sugar().Errorf(format, args...)
}

// auditDropLogf 审计行丢弃/消费异常告警日志缝（测试注入；缺省 caddy.Log）。
var auditDropLogf = func(format string, args ...any) {
	caddy.Log().Named("auditwriter").Sugar().Warnf(format, args...)
}

// auditLogThrottle 是写侧失败告警的单源节流状态：首次立即记录，其后每个
// 窗口（minute）至多一条，并携带窗口内被抑制的次数。三个调用点（行丢弃/
// 落盘 IO 错误/formatter 契约失败）的计数目标、日志缝与文案各不相同，
// 但首报与节流规则必须一致——各写一份会让窗口/首报语义逐处漂移。
type auditLogThrottle struct {
	mu    sync.Mutex
	last  time.Time
	since int
}

// report 登记一次事件，返回本次被抑制数与是否应输出告警。首个事件恒记录。
func (t *auditLogThrottle) report(now time.Time) (suppressed int, logNow bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.since++
	suppressed = t.since - 1
	logNow = t.last.IsZero() || now.Sub(t.last) >= time.Minute
	if logNow {
		t.last = now
		t.since = 0
	}
	return suppressed, logNow
}

// reportIOError 记录落盘 IO 错误：首次立即记录，其后每分钟至多
// 一条（携带被抑制计数），保证「静默丢行」不可能。错误不再只是被丢弃的
// error 返回值——drain 侧旧实现 `_, _ = p.bw.Write(...)` 完全不可观测。
func (p *auditPipeline) reportIOError(op string, err error) {
	if err == nil {
		return
	}
	// 累计计数（面板健康位消费）先于节流告警：告警被抑制也绝不丢计数。
	p.ioErrors.Add(1)
	p.statsDirty.Store(true)
	if suppressed, logNow := p.ioErrLog.report(time.Now()); logNow {
		auditIOLogf("audit writer: %s failed for %s (suppressed %d since last report): %v", op, p.target, suppressed, err)
	}
}

// reportFormatError 记录 formatter.Format 失败（独立于落盘 IO 错误）：
// 计数进侧车 format_errors，日志同族按分钟节流。格式化失败是可重放的
// 代码/契约缺陷，与磁盘/权限故障的处置路径不同，不得混入 io_errors。
func (p *auditPipeline) reportFormatError(err error) {
	if err == nil {
		return
	}
	p.formatErrors.Add(1)
	p.statsDirty.Store(true)
	if suppressed, logNow := p.formatErrLog.report(time.Now()); logNow {
		auditDropLogf("audit writer: format failed for %s (suppressed %d since last report): %v", p.target, suppressed, err)
	}
}

// reopenLocked 丢弃当前 bufio/fd 并重建（O_APPEND 兼容 copytruncate）。
func (p *auditPipeline) reopenLocked() {
	if p.bw != nil {
		_ = p.bw.Flush()
		p.bw = nil
	}
	if p.fd != nil {
		_ = p.fd.Close()
		p.fd = nil
	}
	fd, err := os.OpenFile(p.target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, p.mode)
	if err != nil {
		p.reportIOError("reopen", err)
		return
	}
	p.fd = fd
	p.bw = bufio.NewWriterSize(fd, 64*1024)
}

// appendLine 写入一行并处理错误：粘性写错误先记录、再重建 fd，
// 后续行继续落盘；调用方持 ioMu。
func (p *auditPipeline) appendLine(body []byte) {
	if p.bw == nil {
		p.reopenLocked()
		if p.bw == nil {
			return
		}
	}
	if _, err := p.bw.Write(body); err != nil {
		p.reportIOError("write", err)
		p.reopenLocked()
		return
	}
	if _, err := p.bw.WriteString("\n"); err != nil {
		p.reportIOError("write", err)
		p.reopenLocked()
		return
	}
	if p.bw.Buffered() >= auditFlushThreshold {
		p.flushLocked()
	}
}

// flushLocked 刷盘并处理错误。调用方持 ioMu。
func (p *auditPipeline) flushLocked() {
	if p.bw == nil {
		return
	}
	if err := p.bw.Flush(); err != nil {
		p.reportIOError("flush", err)
		p.reopenLocked()
	}
}

var (
	auditPipelinesMu sync.Mutex
	auditPipelines   = map[string]*auditPipeline{}
)

// acquireAuditPipeline 取目标路径的进程级共享管线（不存在则创建：打开 fd +
// 启动 drain）。fd 打开失败返回错误——coraza NewWAF 会把 Init 错误上抛为配置
// 拒绝（/load fail-fast，与退役前 serial writer 同语义）。
//
// 为什么是进程级单例（不回收、不随 reload 换血）：上游从不调
// AuditLogWriter.Close（coraza v3.8.1 的 WAF.Close 与插件的 Destruct
// 都不触碰审计写插件，见 FlushAuditPipelines），因此引用计数与「最后一个引用
// 释放即关队列」的 teardown 在进程内不可能被触发——保留它们只会让写路径依赖
// 一条永不发生的生命周期事件。这里改为：同一 target 恒返回同一管线，fd 与
// drain goroutine 活到进程退出。代价是渲染目标 auditLogPath 变更时旧路径的
// fd/goroutine 不再回收（每个历史 target 一条，进程重启归零）；收益是写路径
// 恒有活 drain 消费——审计事件不会因任何 teardown 竞态被丢弃或转同步直写。
func acquireAuditPipeline(target string, mode os.FileMode) (*auditPipeline, error) {
	auditPipelinesMu.Lock()
	defer auditPipelinesMu.Unlock()
	if p, ok := auditPipelines[target]; ok {
		return p, nil
	}
	p := &auditPipeline{
		target: target,
		mode:   mode,
		queue:  make(chan lbAuditItem, auditQueueSize),
		done:   make(chan struct{}),
	}
	if err := p.openFile(mode); err != nil {
		return nil, err
	}
	// 新进程的计数从 0 起：盘上残留的失败标记描述的是上一代进程的故障，对本代
	// 无效（读侧另有按标记内时间做的代际判定）。不清除会让「上次故障 + 本代
	// 计数无变化」的部署永久显示写侧不可用——侧车只在计数变化时写盘，本代无
	// 失败即无写盘，标记永远不会被成功路径删除。
	p.clearWriterStatsFailure()
	auditPipelines[target] = p
	go p.drain()
	return p, nil
}

// openFile 打开目标文件（O_APPEND——copytruncate 轮转下 fd 恒有效）。
func (p *auditPipeline) openFile(mode os.FileMode) error {
	fd, err := os.OpenFile(p.target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, mode)
	if err != nil {
		return err
	}
	p.ioMu.Lock()
	p.fd = fd
	p.bw = bufio.NewWriterSize(fd, 64*1024)
	p.ioMu.Unlock()
	return nil
}

// 快照字节估算的固定开销项：估算 = 内容字节（len 求和，常数级、零分配）
// + JSON 语法与容器驻留开销。各项按上界取整（slice 桶头 + 引号/冒号/括号/
// 逗号），使多文件、多 messages 形态的估算不低于实际序列化字节——enqueue 按
// 估算执法字节预算，低估即意味着实际驻留可突破 auditQueueByteBudget 数倍
// （旧实现只累加 len()）。header 段不走固定开销：快照侧已算出精确序列化字节
// （HeadersBytes_），只在手工构造的快照上按同一 jsonStringEscapedLen 口径现算。
const (
	// 每个 message tag：slice 元素头 + `"tag",`。header 不再按条固定开销
	// 估算——快照侧已算出精确序列化字节（HeadersBytes_），按 48/16 逐条累加
	// 在头部密集形态下会把 70KiB 的 header 表估成 ~350KiB。
	auditTagEntryOverhead = 16
	// 每个上传文件条目：`{"name":"…","size":N,"mime":"…"},` + 结构体驻留。
	auditFileEntryOverhead = 96
	// auditFilesDroppedOverhead 是文件条目截断披露键（`"files_dropped":N,`）
	// 的固定估算（丢弃数按 6 位上限预留）。
	auditFilesDroppedOverhead = 32
	// auditMessagesDroppedOverhead 是消息条目截断披露键
	// （`"messages_dropped":N,`）的固定估算（丢弃数按 6 位上限预留）。
	auditMessagesDroppedOverhead = 40
	// 每条 message：键名/数字字段/tags 语法 + slice 元素与 RuleMatch 驻留；
	// 内容串（actionset/message/error_message/data 各字段）另按 len 计入。
	auditMessageOverhead = 512
	// auditMessagesMaxEntries / auditMessagesMaxBytes 是写侧 messages 上限：
	// 四段（请求/响应体与头，各 64KiB）+ 固定开销后仅剩 ~65KiB 余量，约 70-80
	// 条规则命中即触发 auditItemMaxBytes 整行丢弃——丢的恰是「命中规则多」的
	// 高价值行。写侧先截断 messages 并标记 messages_dropped，保留整行；
	// auditItemMaxBytes 仍是兜底（真超限才丢行）。截断方向是「掐中间、保两头」
	// （见 snapshotAuditMessages）：尾部承载 CRS 评估汇总（949xxx/959xxx，异常
	// 分的唯一来源），只保开头会让高分请求的分数归零。
	auditMessagesMaxEntries = 64
	auditMessagesMaxBytes   = 32 * 1024
	// auditMessagesTailEntries / auditMessagesTailBytes 是尾段保留预算：
	// 评估汇总消息位于消息序列末尾，条数按「4 条评估 × 相位数 + 余量」取 8，
	// 字节预算独立（评估消息仅数十字节），避免尾段挤压头部攻击特征条目。
	// 评估族消息超出条数上限仍继续收纳，硬上限为条数的 2 倍。
	auditMessagesTailEntries = 8
	auditMessagesTailBytes   = 8 * 1024
	// 快照骨架：transaction/request/response/producer 的固定键名与 envelope。
	auditSnapshotFixedBytes = 512
)

// estimateAuditMessageBytes 单条 message 的驻留/序列化字节估算（内容 +
// 固定开销）。写侧 messages 截断与快照估算共用同一口径，避免两处上限漂移。
func estimateAuditMessageBytes(m plugintypes.AuditLogMessage) int64 {
	if isNilInterface(m) {
		return 0
	}
	// 全部字符串段按 JSON 转义后字节计（jsonStringEscapedLen 与 json.Marshal
	// 逐字节一致）：原始 len 会低估 <>&/控制字符（至多 6×），而本估算同时是
	// 队列/单条字节预算的执法口径，低估即实际驻留可突破预算数倍。
	n := int64(jsonStringEscapedLen(m.Actionset())+jsonStringEscapedLen(m.Message())) + auditMessageOverhead
	// error_message 不在 plugintypes.AuditLogMessage 接口上，但内置 JSON
	// formatter 直接序列化具体值（coraza 的 Message 带该导出字段）。
	if em, ok := m.(interface{ ErrorMessage() string }); ok {
		n += int64(jsonStringEscapedLen(em.ErrorMessage()))
	}
	// 规则数据段（file/line/id/rev/msg/data/severity/ver/maturity/
	// accuracy/tags/raw）同样进 JSON；Data() 可能是 typed-nil，取任何
	// 访问器前必须走 isNilInterface。
	if d := m.Data(); !isNilInterface(d) {
		n += int64(jsonStringEscapedLen(d.File()) + jsonStringEscapedLen(d.Rev()) +
			jsonStringEscapedLen(d.Msg()) + jsonStringEscapedLen(d.Data()) +
			jsonStringEscapedLen(d.Ver()) + jsonStringEscapedLen(d.Raw()))
		for _, tag := range d.Tags() {
			n += int64(jsonStringEscapedLen(tag)) + auditTagEntryOverhead
		}
	}
	return n
}

// estimateAuditSnapshotBytes 估算快照驻留字节（请求路径可付：只做 len 求和
// 与固定开销累加，零分配）。口径见上方常量：内容 + 语法/容器固定开销，对
// 文件/messages 条目数是保守上界；header 段直接用快照侧已算出的精确序列化
// 字节（HeadersBytes_），不再按条固定开销重估——后者在头部密集时高估数倍，
// 会把实际 ~131KiB 的双向 header 表估成 ~700KiB 并越过单条上限整行丢弃。
func estimateAuditSnapshotBytes(s *auditSnapshot) int64 {
	if s == nil {
		return 0
	}
	// 兜底形态（快照未携带精确字节：仅手工构造/测试）按同一 jsonStringEscapedLen
	// 口径现算，仍为零分配扫描且不低于实际序列化体积。
	headerBytes := func(hs map[string][]string, exact int64) int64 {
		if exact > 0 {
			return exact
		}
		if hs == nil {
			return 0
		}
		n := int64(2) // 外层 {}
		for k, vs := range hs {
			n += auditHeaderEntrySerializedBytes(k, vs)
		}
		return n
	}
	n := int64(auditSnapshotFixedBytes)
	t := &s.Transaction_
	// 全部字符串段按 JSON 转义后字节计（header 段已用同一口径）：估算即
	// 队列/单条字节预算的执法口径，原始 len 会把 &&&… 类取值低估至多 6×。
	// ServerID_ 已按 auditServerIDMaxEscapedBytes 封顶，此处按封顶后的实际值
	// 计入——封顶与计费同源，估算不会因原始超长取值把整行判成超限。
	n += int64(jsonStringEscapedLen(t.Timestamp_) + jsonStringEscapedLen(t.ID_) +
		jsonStringEscapedLen(t.ClientIP_) + jsonStringEscapedLen(t.HostIP_) +
		jsonStringEscapedLen(t.ServerID_) + jsonStringEscapedLen(t.HighestSeverity_))
	if r := t.Request_; r != nil {
		// Method_ 同样已按 auditMethodMaxEscapedBytes 封顶（见 snapshotTransaction）。
		n += int64(jsonStringEscapedLen(r.Method_) + jsonStringEscapedLen(r.Protocol_) +
			jsonStringEscapedLen(r.URI_) + jsonStringEscapedLen(r.HTTPVersion_) +
			jsonStringEscapedLen(r.Body_))
		n += headerBytes(r.Headers_, r.HeadersBytes_)
		// files_dropped 是文件条目截断的披露键（`"files_dropped":N,`）：估算
		// 必须计入，否则截断披露本身会把实际序列化体积推过估算口径。
		if r.FilesDropped_ > 0 {
			n += auditFilesDroppedOverhead
		}
		for _, f := range r.Files_ {
			n += auditFileEntryOverhead
			if isNilInterface(f) {
				continue
			}
			n += int64(jsonStringEscapedLen(f.Name()) + jsonStringEscapedLen(f.Mime()))
		}
	}
	if q := t.Response_; q != nil {
		n += int64(jsonStringEscapedLen(q.Protocol_) + jsonStringEscapedLen(q.Body_))
		n += headerBytes(q.Headers_, q.HeadersBytes_)
	}
	if pr := t.Producer_; pr != nil {
		n += int64(jsonStringEscapedLen(pr.Connector_) + jsonStringEscapedLen(pr.Version_) +
			jsonStringEscapedLen(pr.Server_) + jsonStringEscapedLen(pr.RuleEngine_) +
			jsonStringEscapedLen(pr.Stopwatch_))
		for _, rs := range pr.Rulesets_ {
			n += int64(jsonStringEscapedLen(rs))
		}
	}
	if s.MessagesDropped_ > 0 {
		n += auditMessagesDroppedOverhead
	}
	for _, m := range s.Messages_ {
		n += estimateAuditMessageBytes(m)
	}
	return n
}

// enqueue 有界入队：空位直接入队；队列满时最多等待 auditEnqueueTimeout，
// 超时丢弃该条、累计 dropped 并按分钟节流告警——请求路径不再被 drain 沉陷
// 无限期拖住。所有路径均为 best-effort（入队或计数丢弃），无失败返回值。
// queue 创建后只读且永不关闭（进程级单例，见
// acquireAuditPipeline），因此发送无需锁、也不存在竞态。
//
// 字节预算（auditQueueByteBudget/auditItemMaxBytes）先于容量等待判定：
// 占额成功才进入入队/等待，超预算或超单条上限立即丢弃——恒压下在途
// 等待者同样持有快照，字节占额把「队列+等待中」的总驻留一并约束。
// 占额先加后验（超预算回滚），并发瞬时过冲有界于同窗口入队者×单条上限。
func (p *auditPipeline) enqueue(item lbAuditItem) {
	size := estimateAuditSnapshotBytes(item.snap)
	if size > auditItemMaxBytes {
		p.reportDropped("item exceeds per-item size cap")
		return
	}
	item.bytes = size
	if p.queueBytes.Add(size) > auditQueueByteBudget {
		p.queueBytes.Add(-size)
		p.reportDropped("byte budget exceeded")
		return
	}
	// 准入即计（先于实际入队）：收尾刷盘以 pending==0 判定排空，
	// 计数先于投递使判定不含「已准入未入队」的漏窗。
	p.pending.Add(1)
	select {
	case p.queue <- item:
		return
	default:
	}
	timer := time.NewTimer(auditEnqueueTimeout)
	defer timer.Stop()
	select {
	case p.queue <- item:
	case <-timer.C:
		p.pending.Add(-1)
		p.queueBytes.Add(-size)
		p.reportDropped("queue full")
	}
}

// reportDropped 累计丢弃计数并节流告警（首次立即记录，其后每分钟至多一条，
// 携带被抑制计数与累计总数）——丢弃必须是可观测事件。reason 标明丢弃根因
// （queue full / byte budget exceeded / per-item cap），排障不必猜路径。
func (p *auditPipeline) reportDropped(reason string) {
	total := p.dropped.Add(1)
	p.statsDirty.Store(true)
	suppressed, logNow := p.dropLog.report(time.Now())
	if logNow {
		auditDropLogf("audit writer: %s for %s, dropped audit line (total dropped %d, suppressed %d since last report)", reason, p.target, total, suppressed)
	}
}

// drain 专职落盘 goroutine：注入 timing → bufio 批量写 → 阈值/周期双触发刷盘。
// 队列关闭后排空余量再退出、刷盘、关 fd。单条处理/刷盘的 panic 均被隔离：
// drain 是进程级单例消费者，goroutine 一旦退出写侧将再无消费者。
func (p *auditPipeline) drain() {
	defer close(p.done)
	q := p.queue
	ticker := time.NewTicker(auditFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case item, ok := <-q:
			if !ok {
				p.flushPendingSafely()
				p.closeFile()
				return
			}
			p.queueBytes.Add(-item.bytes)
			p.processSafely(item)
			p.pending.Add(-1)
		case <-ticker.C:
			p.flushPendingSafely()
			p.writeWriterStatsIfDue(time.Now())
		}
	}
}

// writeWriterStatsIfDue 把累计失败/丢弃计数写入侧车文件（低频节流；仅计数
// 变化时写）。drain goroutine 独享调用，请求路径零参与：失败洪峰不会放大
// 磁盘 IO，读侧（根服务摄取 tick）也不碰热路径。
func (p *auditPipeline) writeWriterStatsIfDue(now time.Time) {
	if !p.statsDirty.Load() {
		return
	}
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	if !p.lastStatsWrite.IsZero() && now.Sub(p.lastStatsWrite) < auditWriterStatsInterval {
		return
	}
	// 先清脏标记再读计数：读到计数后到达的新失败会重新置脏，不丢更新。
	p.statsDirty.Store(false)
	payload := struct {
		Dropped      uint64 `json:"dropped"`
		IOErrors     uint64 `json:"io_errors"`
		FormatErrors uint64 `json:"format_errors"`
		WrittenAt    string `json:"written_at"`
	}{
		Dropped:      p.dropped.Load(),
		IOErrors:     p.ioErrors.Load(),
		FormatErrors: p.formatErrors.Load(),
		WrittenAt:    now.UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	path := auditWriterStatsPath(p.target)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		// 尽力而为但可观测：恢复脏标记下个 drain 节拍重试（否则计数不再
		// 变化时永不重试，侧车永久缺失），并按分钟节流留痕一次。
		// 失败标记让「侧车写不进去」跨进程可见（根侧不再按缺失=正常假绿）。
		p.statsDirty.Store(true)
		p.markWriterStatsFailure(now, err)
		p.logStatsWriteFailureLocked(now, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		p.statsDirty.Store(true)
		p.markWriterStatsFailure(now, err)
		p.logStatsWriteFailureLocked(now, err)
		return
	}
	p.clearWriterStatsFailure()
	p.lastStatsWrite = now
}

// logStatsWriteFailureLocked 侧车写盘失败节流留痕（调用方已持 statsMu，
// 每分钟至多一条；与其余写侧失败告警共用 auditLogThrottle 的窗口语义）。
func (p *auditPipeline) logStatsWriteFailureLocked(now time.Time, err error) {
	if _, logNow := p.statsFailLog.report(now); !logNow {
		return
	}
	auditIOLogf("audit writer: writer-stats sidecar write failed for %s (writer counters unavailable to panel until retry succeeds): %v", p.target, err)
}

// processSafely 隔离单条审计行处理的 panic（formatter/快照实现异常）：
// recover 后继续消费后续条目，不终止 drain。
func (p *auditPipeline) processSafely(item lbAuditItem) {
	defer func() {
		if recovered := recover(); recovered != nil {
			auditDropLogf("audit writer: recovered panic while processing audit line for %s: %v", p.target, recovered)
		}
	}()
	p.process(item)
}

// flushPendingSafely 隔离周期刷盘的 panic（fd/bufio 异常形态），drain 继续。
func (p *auditPipeline) flushPendingSafely() {
	defer func() {
		if recovered := recover(); recovered != nil {
			auditDropLogf("audit writer: recovered panic while flushing %s: %v", p.target, recovered)
		}
	}()
	p.flushPending()
}

// process 处理单条审计行：注册 formatter 格式化快照（请求路径之外）→ 限时等待
// 计时终态 → 注入 → bufio 写（阈值刷盘）。计时等待在请求路径之外（见文件头
// 时序契约注释）。格式化失败/空输出跳过该行（与旧同步链 Write 返回错误同效，
// coraza 已在写错误点记日志）。
func (p *auditPipeline) process(item lbAuditItem) {
	if item.snap == nil || item.formatter == nil {
		return
	}
	body, err := item.formatter.Format(item.snap)
	if err != nil {
		// 单行格式化失败只跳过该行，不阻断后续（错误可见化：旧实现静默丢弃）。
		// 独立计数/告警：格式化缺陷与磁盘 IO 故障的排障路径不同。
		p.reportFormatError(err)
		return
	}
	if len(body) == 0 {
		return
	}
	if item.tid != "" {
		snap := auditTimingWait(item.tid, auditTimingWaitLimit)
		body = injectAuditTiming(body, snap)
	}
	p.ioMu.Lock()
	p.appendLine(body)
	p.ioMu.Unlock()
}

func (p *auditPipeline) flushPending() {
	p.ioMu.Lock()
	if p.bw != nil && p.bw.Buffered() > 0 {
		p.flushLocked()
	}
	p.ioMu.Unlock()
}

// flush 立即把 bufio 中的行写入 fd（不关闭管线）；供 Caddy Cleanup 优雅收尾。
func (p *auditPipeline) flush() {
	p.ioMu.Lock()
	if p.bw != nil {
		if err := p.bw.Flush(); err != nil {
			p.reportIOError("flush", err)
		}
	}
	p.ioMu.Unlock()
}

// auditShutdownDrainWait 收尾刷盘等待 drain 排空的上限：已入队未处理的行
// 给有界窗口完成处理（格式化含计时等待 auditTimingWaitLimit），超时仍刷
// 已落 bufio 的部分——尾部完整性是 best-effort，但进程退出/reload 不再
// 无条件丢失全部在队行。
const auditShutdownDrainWait = 3 * time.Second

// auditFlushCoalescedDrainWait 是合并窗口内（非首个）Cleanup 的小额有界
// 排空时间：全体管线共享一次等待（drain 单消费者并发处理，总代价与管线数
// 无关），把「窗口内紧跟进程停止」的丢失面从「全部在队行」收敛到窗口内
// 未处理的行（队列上限 2048，正常流量下 200ms 足够排空）。
const auditFlushCoalescedDrainWait = 200 * time.Millisecond

// auditFlushCoalesceWindow 是 FlushAuditPipelines 的合并窗口：一次 Caddy
// reload/优雅停机会让**每个规则**的 SecurityBlockedCounter 各调一次 Cleanup
// （实例数 = 规则数）。持续审计流量下 pending 很难为 0，每个实例都等满
// auditShutdownDrainWait，收尾成本即「规则数 × 3s」（管理面 /load 卡顿）。
// 窗口内的重复调用跳过排空等待（首个调用已把同一批管线排空，其后的等待纯属
// 叠加），但**不跳过刷盘本身**——见 FlushAuditPipelines。窗口远小于两次
// reload 的间隔，且 500ms 周期刷盘兜底尾部行。var 供测试收窄。
var auditFlushCoalesceWindow = auditShutdownDrainWait

// auditLastFlushNano 是最近一次领到冲刷资格的时刻（单调读数，基线见
// auditFlushClockBase；0=从未冲刷）。CAS 领取保证并发 Cleanup 只有一个走
// 等待路径。旧实现存挂钟 UnixNano：NTP/手动回拨使 n-last 为负 → 判定「窗口
// 内」→ 整个回拨期间所有 Cleanup 都跳过排空（与 wafiplist 的单调读数修复
// 同口径）。
var auditLastFlushNano atomic.Int64

// auditFlushClockBase 是单调时钟基线（包加载时取一次）。
var auditFlushClockBase = time.Now()

func auditMonotonicNowNano() int64 { return int64(time.Since(auditFlushClockBase)) }

// claimAuditFlush 在合并窗口内领取一次冲刷资格；窗口内返回 false（本次
// Cleanup 走小额有界排空，见 FlushAuditPipelines）。无锁 CAS：并发调用者
// 同刻到达时只有一个成功。
func claimAuditFlush() bool {
	n := auditMonotonicNowNano()
	for {
		last := auditLastFlushNano.Load()
		if last != 0 && n-last < int64(auditFlushCoalesceWindow) {
			return false
		}
		if auditLastFlushNano.CompareAndSwap(last, n) {
			return true
		}
	}
}

// flushQuiesced 限时等待「已准入条目全部处理完」后刷盘（pending==0 蕴含
// 队列空 + 无在途处理）。drain 是恒活的进程级单例消费者，等待有界
// （auditShutdownDrainWait）。同一代际的重复等待由 FlushAuditPipelines 的
// 合并窗口消除（见 claimAuditFlush）。
func (p *auditPipeline) flushQuiesced() {
	deadline := time.Now().Add(auditShutdownDrainWait)
	for time.Now().Before(deadline) {
		if p.pending.Load() == 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	p.flush()
}

// FlushAuditPipelines 冲刷全部存活管线；Caddy 模块 Cleanup（reload/优雅停机）
// 调用，弥补上游从不调用 AuditLogWriter.Close 导致的尾部丢失——先限时等
// drain 排空已入队行（auditShutdownDrainWait），再刷 bufio。
// 只刷盘不关闭：管线是进程级单例，fd/drain 的生命周期与进程一致。
//
// 合并窗口（claimAuditFlush）：一次 reload 会按规则数调用 N 次本函数，
// 只有窗口内首个调用付出完整排空等待（auditShutdownDrainWait），其余走
// 小额有界排空（auditFlushCoalescedDrainWait，全体管线共享一次等待）——
// 收尾成本与实例数解耦。窗口内若紧跟进程停止，这次 Cleanup 就是唯一收尾
// 机会：**省掉的只能是等待时长**，bufio 残留与已在队/在途行都要尽量落盘
// （旧实现窗口分支只 flush bufio，队列里最多 2048 行随进程退出静默丢失且
// 侧车 dropped/io_errors 不统计该类丢失）。
func FlushAuditPipelines() {
	quiesce := claimAuditFlush()
	auditPipelinesMu.Lock()
	pipelines := make([]*auditPipeline, 0, len(auditPipelines))
	for _, p := range auditPipelines {
		pipelines = append(pipelines, p)
	}
	auditPipelinesMu.Unlock()
	if quiesce {
		for _, p := range pipelines {
			p.flushQuiesced()
		}
		return
	}
	deadline := time.Now().Add(auditFlushCoalescedDrainWait)
	for time.Now().Before(deadline) {
		pending := false
		for _, p := range pipelines {
			if p.pending.Load() != 0 {
				pending = true
				break
			}
		}
		if !pending {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	for _, p := range pipelines {
		p.flush()
	}
}

func (p *auditPipeline) closeFile() {
	p.ioMu.Lock()
	if p.bw != nil {
		p.flushLocked()
		p.bw = nil
	}
	if p.fd != nil {
		if err := p.fd.Close(); err != nil {
			p.reportIOError("close", err)
		}
		p.fd = nil
	}
	p.ioMu.Unlock()
}

// lbAuditWriter 是 coraza 审计写插件实例（每个 coraza WAF 一个；多实例共享
// 按路径的进程级落盘管线）。Write 只构建审计快照入队（formatter.Format 已移出
// 请求路径——黑名单预检计时窗内只剩快照拷贝，memcpy 级），格式化/计时等待/
// 落盘全部后置到 drain。
type lbAuditWriter struct {
	formatter plugintypes.AuditLogFormatter
	pipeline  *auditPipeline
	// failed 标记 Init 失败（fd 打不开）：后续 Write 静默 no-op——与 coraza
	// serial writer Init 失败后 Write 短路同形态（coraza 已在 Init 错误点
	// 上抛/记日志，配置加载被拒）。
	failed bool
}

func (w *lbAuditWriter) Init(c plugintypes.AuditLogConfig) error {
	w.formatter = c.Formatter
	if c.Target == "" {
		return nil
	}
	p, err := acquireAuditPipeline(c.Target, c.FileMode)
	if err != nil {
		w.failed = true
		return err
	}
	w.pipeline = p
	return nil
}

func (w *lbAuditWriter) Write(al plugintypes.AuditLog) error {
	if w.failed || w.pipeline == nil || w.formatter == nil || al == nil {
		return nil
	}
	tid := ""
	if al.Transaction() != nil && al.Transaction().HasRequest() {
		tid = securityTimingIDFromHeaders(al.Transaction().Request().Headers())
	}
	// 入队全路径 best-effort（入队或计数丢弃），error 恒 nil——返回值仅
	// 满足 plugintypes.AuditLogWriter 接口签名。
	w.pipeline.enqueue(lbAuditItem{snap: snapshotAuditLog(al), formatter: w.formatter, tid: tid})
	return nil
}

// Close 满足 plugintypes.AuditLogWriter 接口（coraza v3.8.1 实际从不调用它）。
// 只刷盘、不拆管线：管线是进程级单例，拆除会让写侧失去恒活的 drain（见
// acquireAuditPipeline）；真被上游调用时此处的语义是「限时等 drain 排空后
// 尽力把已入队行刷出」。
func (w *lbAuditWriter) Close() error {
	if w.pipeline != nil {
		w.pipeline.flushQuiesced()
	}
	return nil
}
