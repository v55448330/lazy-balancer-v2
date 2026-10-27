package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/accesslog"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// caddyInternalKeyPrefix 渲染层内部标记键统一前缀：caddyPayload 按前缀整体
// 剔除——内部键一律不得进 Caddy 载荷（真 Caddy
// StrictUnmarshalJSON 拒未知顶层字段返 400，内部键漏网会让降级配置被硬拒，
// 可用性优先被反转）。新增内部键必须复用本前缀。
const caddyInternalKeyPrefix = "__lazy_balancer_"

const (
	caddyConfigGenerationErrorKey = caddyInternalKeyPrefix + "generation_error"
	caddyCertFilesSnapshotKey     = caddyInternalKeyPrefix + "cert_files_snapshot"
)

// CaddyAdminListenAddr 是渲染产物中 Caddy admin 的监听地址（单源常量）。
// 首次成功 /load 后 Caddy admin 即迁到本地址——cfg.CaddyAdminURL 仅是
// 「首次 /load 之前」的引导端点，稳态必须指向同一地址，否则面板配置的
// 端点在首次 /load 后失联（启动期一致性 WARN 见 config.LoadCollectWarnings）。
const CaddyAdminListenAddr = "127.0.0.1:2019"

// CaddyAdminListenPort 是 CaddyAdminListenAddr 的端口部分（规则端口冲突门
// 等只需端口的消费方使用——稳态 admin 恒听本端口，与 caddy_admin_url 配置
// 无关）。
const CaddyAdminListenPort = 2019

// ErrNoEnabledUpstreams 规则（或路径规则）没有启用上游时生成的哨兵错误。
// 生成侧两处产出点（GenerateSingleRuleCaddyConfig 直返、buildHTTPHandleChain
// %w 包装）统一引用；handlers 侧以 errors.Is 特判零上游为「跳过而非失败」
// 语义，未来追加规则上下文包装后特判不会静默失效。
var ErrNoEnabledUpstreams = errors.New("no enabled upstreams")

// UpstreamEnabledSQLValue 上游「启用」判定的 SQL 值形态（0/1 投影，供 SELECT
// 取布尔列）；谓词形态由本常量派生，整个仓库只此一处 IIF 字面量（services 渲染
// 装载/预览/看门狗与 handlers 的上游读取/冲突门全部引用本常量或其谓词形态，
// 源码级单源钉测见 caddy_render_surface_test.go）。
// 别名约定：u=upstreams（单表查询须给表加 u 别名后引用）。
const UpstreamEnabledSQLValue = `IIF(u.enabled IN ('1',1),1,0)`

// UpstreamEnabledSQLPredicate 上游「启用」的 SQL 判定单源（渲染上游装载查询、
// 单规则服务上下文预览、看门狗发布谓词与 handlers 的自动封禁生效判定共用——
// 多处各写一份 IIF 表达式易单侧漂移，；源码级单源断言在 services
// 测试内，新增第二处谓词字面量即红）。别名约定：u=upstreams。
const UpstreamEnabledSQLPredicate = UpstreamEnabledSQLValue + ` = 1`

// publishableRulesSQLPredicate 「哪些规则会被发布到运行配置」的 SQL 谓词
// 单源：规则启用 ∧ 至少一个启用上游。两个消费层必须恒等：
//   - 看门狗 expectedRenderedRules 直接用本谓词把期望集收窄到发布集；
//   - 渲染主查询只按 enabled=1 装载（端口分组/80 端口遮蔽复核/零上游跳过
//     warn 需要全集），再在 Go 侧按 hasEnabledUpstream（同语义：存在启用
//     上游）逐规则跳过。
//
// 修改任一判定（启用语义/上游过滤）必须同步另一侧对应层。
const publishableRulesSQLPredicate = `enabled = 1 AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id = lb_rules.caddy_id AND ` + UpstreamEnabledSQLPredicate + `)`

// ConfigRejectedError 标记「该配置本身不可被 Caddy 接受」——admin 4xx（provision
// /校验拒绝）或渲染生成失败，区别于传输/系统失败（Caddy 不可达、5xx、序列化
// 失败）。门控提交（2026-09-06 裁定 ①②：只有可渲染配置可落库）据此
// 分流：拒绝 → 回滚不落库 + 400；其余 → 退化提交 + caddy_apply_error 标记。
// 文本原样透传（Error/Unwrap 委托底层），既有错误断言不受影响。
type ConfigRejectedError struct{ Err error }

func (e *ConfigRejectedError) Error() string { return e.Err.Error() }
func (e *ConfigRejectedError) Unwrap() error { return e.Err }

// IsConfigRejected 判定 err（含 join 链）是否为配置被拒。
func IsConfigRejected(err error) bool {
	var rej *ConfigRejectedError
	return errors.As(err, &rej)
}

// ErrDynamicDNSUpstreamCount 动态 DNS 模式配置了多个启用上游时的哨兵错误
// （动态解析仅支持单一上游）。产出点与 ErrNoEnabledUpstreams 相同两处，消费点
// （rule_features.go 预校验）以 errors.Is 命中，避免脆弱的字符串匹配。
var ErrDynamicDNSUpstreamCount = errors.New("dynamic DNS requires exactly one enabled upstream")

// landingBodyMu 保护 defaultLandingBody(branding.json 的 landing_text 注入,
// 与 footer_text 同语义:空/缺失回退 DefaultLandingText 常量)。Caddy 渲染
// 可并发(集群快照/事务/handler),读侧走 RLock。
var (
	landingBodyMu         sync.RWMutex
	defaultLandingBodyVal = DefaultLandingText
)

// DefaultLandingText 是空域名命中 http_80 catch-all 时的产品默认提示文案。
const DefaultLandingText = "Lazy Balancer V2 is running!"

// SetDefaultLandingBody 注入 branding.json 的 landing_text(已归一:空串
// 由调用方回退默认后传入)。下一次 Caddy 渲染即生效;渲染侧见
// DefaultLandingBody()。
func SetDefaultLandingBody(text string) {
	landingBodyMu.Lock()
	defaultLandingBodyVal = text
	landingBodyMu.Unlock()
}

// DefaultLandingBody 返回当前默认站点文案(branding 注入或默认)。
func DefaultLandingBody() string {
	landingBodyMu.RLock()
	defer landingBodyMu.RUnlock()
	return defaultLandingBodyVal
}

// CaddyService handles Caddy configuration management
type CaddyService struct {
	adminURL   string
	metricsURL string
	client     *http.Client
	mu         sync.Mutex
	// lastGoodPath 非空时，每次成功 /load 后把已应用 JSON 原子落盘到该路径，
	// 供启动兜底（裁定 2026-09-06 ③）读取回放。
	lastGoodPath string
	// cliValidate 非空时，写路径在事务内应用前先用 caddy CLI（validate-only：
	// run(cfg,false) 执行完整 provisionContext(含 coraza 编译)仅跳过 Start、
	// 不绑端口——比「不 provision」更强,引擎级错误在此被捕获)校验
	// 最终渲染（裁定 2026-09-06 ④'）。默认关闭，main 显式启用，测试注入桩。
	cliValidate func(rendered []byte) error

	healthMu             sync.Mutex
	healthCache          map[string]map[string]*UpstreamHealthDetail
	healthCacheExpiresAt time.Time
	healthInflight       *upstreamHealthCall
}

func NewCaddyService(adminURL string) *CaddyService {
	// 兼容 admin 与指标同址的调用方；独立指标端点必须使用
	// NewCaddyServiceWithMetricsURL（生产装配显式传配置值）。
	return NewCaddyServiceWithMetricsURL(adminURL, strings.TrimRight(adminURL, "/")+"/metrics")
}

func NewCaddyServiceWithMetricsURL(adminURL, metricsURL string) *CaddyService {
	return &CaddyService{
		adminURL:   adminURL,
		metricsURL: metricsURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GenerateCaddyID() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	id := make([]byte, 13)
	id[0] = 'l'
	id[1] = 'b'
	id[2] = '_'
	for i := 3; i < 13; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		id[i] = charset[idx.Int64()]
	}
	return string(id), nil
}

// ApplyConfig pushes configuration to Caddy
// 调用方 MUST 已持有 CaddyOpLock（与 GenerateAndApplyConfig 同契约）
// 本函数仅持 s.mu 保护 CaddyService 内部状态；跨层互斥（与后台重载/其他写路径
// 的 apply→commit 窗口）由调用方的 CaddyOpLock 临界区承担——生产调用点
// （handlers 写路径 / cluster_apply）均全程持锁，函数内自取锁会重入死锁。
func (s *CaddyService) ApplyConfig(config map[string]interface{}) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.applyConfigLocked(config, true)
	if IsSameConfig(err) {
		// 同字节短路=成功空操作（2026-09-25 审计真实性裁定）：restore 调用点把
		// 哨兵 join 进失败消息=把「无需恢复」谎报成「恢复失败」——此处归一为成功；
		// 需要感知短路的只有审计层（applyFromTxNote，走 ApplyConfigFromTx）。
		return nil
	}
	return err
}

// ApplyConfigReporting 同 ApplyConfig，但报告是否发生了真实 /load——审计
// 真实性裁定（2026-09-25）：自记「重载」审计的调用方（PutCaddyConfig）据
// loaded 决定落笔与否（同字节短路 loaded=false=零真实重载，不落审计）。
func (s *CaddyService) ApplyConfigReporting(config map[string]interface{}) (loaded bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.applyConfigLocked(config, true)
	if IsSameConfig(err) {
		return false, nil
	}
	return true, err
}

// ApplyConfigReportingForCommit 应用原始配置但把 last-known-good 延后到
// 调用方 commit 成功后补写；返回值同时携带已下发字节与真实 /load 标记。
func (s *CaddyService) ApplyConfigReportingForCommit(config map[string]interface{}) (applied []byte, loaded bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	applied, err = s.applyConfigWithOptions(config, caddyApplyOptions{persistDegradation: true, persistLastGood: false})
	if IsSameConfig(err) {
		return nil, false, nil
	}
	return applied, true, err
}

// caddyConfigJSONEqual 结构级 JSON 相等（键序/空白/尾换行不敏感）——Caddy
// GET /config/ 会在原文末尾补换行（2026-09-25 生产实测差 1 字节，纯字节比对
// 永不命中致同字节门形同虚设），与 Caddy changeConfig 的结构化 sameConfig
// 判定同语义。
func caddyConfigJSONEqual(a, b []byte) bool {
	var aj, bj interface{}
	if err := json.Unmarshal(a, &aj); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bj); err != nil {
		return false
	}
	return reflect.DeepEqual(aj, bj)
}

// GenerateAndApplyConfig 非强制重载（同字节短路）。
// 调用方 MUST 已持有 CaddyOpLock：当前唯一生产调用方（Start/Restart/集群动作/
// 导入重播种）均全程持锁；在本函数内自取锁会与这些路径重入死锁（历史
// 新增调用方必须显式持锁或改用 GenerateAndApplyConfigForce。
func (s *CaddyService) GenerateAndApplyConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigLocked(generateCaddyConfigFromStore(db.DB), true)
}

// GenerateAndApplyConfigForce 强制重载变体：POST /load 带
// must-revalidate，绕过 Caddy 对字节相同配置的跳过（caddy v2.11.4 changeConfig
// 对相同 JSON 短路返回 errSameConfig、不执行 provision）。xdb/CRS/证书文件是
// 配置 JSON 之外的磁盘数据（geoip handler 路径键仅在非默认 data_dir 形态
// 发射、默认形态字节稳定——既有裁定，见 buildGeoipHandler；
// CRS include 只嵌路径），替换后 JSON 不变——不强制重载时 Caddy 插件
// （geoip searcher / coraza WAF / TLS 证书）内存仍停留旧库，更新流程却已报
// 成功。所有「磁盘数据变化」的重载入口（IP 库/CRS/CA 证书队列）必须走本变体。
func (s *CaddyService) GenerateAndApplyConfigForce() error {
	// 后台数据更新（证书/CRS/xdb/威胁）的重载与 handler
	// 写路径共享跨层互斥（CaddyOpLock）——曾仅持 s.mu，与「caddyOpMu 全程+
	// 事务提交」的写序存在 apply→commit 边界缺口（混合态+last_good 污染）。
	CaddyOpLock.Lock()
	defer CaddyOpLock.Unlock()
	return s.GenerateAndApplyConfigForceInLock()
}

// GenerateAndApplyConfigForceInLock 已持有 CaddyOpLock 的调用方使用
// （handler 路径全程持锁，重入取锁=死锁——rules.go 两处补偿路径同源）。
func (s *CaddyService) GenerateAndApplyConfigForceInLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigLockedOpt(generateCaddyConfigFromStore(db.DB), true, true)
}

// CaddyOpLock 跨层 Caddy 写互斥：handler 写路径（原 handlers 包
// caddyOpMu——已别名到此实例）与后台重载（GenerateAndApplyConfigForce）
// 在此汇合——两类写者的「渲染+/load+落库」全程串行，消除 apply→commit
// 边界的混合态窗口（后台渲染跨写方提交点读出混合新旧态+last_good 污染）。
// 单一锁实例、叶操作、无嵌套重入。
type CaddyWriteLock struct{ mu sync.Mutex }

func (l *CaddyWriteLock) Lock()         { l.mu.Lock() }
func (l *CaddyWriteLock) Unlock()       { l.mu.Unlock() }
func (l *CaddyWriteLock) TryLock() bool { return l.mu.TryLock() }

var CaddyOpLock = &CaddyWriteLock{}

// withCaddyOpLock 在 CaddyOpLock 临界区内执行 fn，defer 释放：临界区含渲染与
// /load，panic 若逃出（被 gin.Recovery 兜住）会让全局写锁永久泄漏——之后所有
// 配置写窗口（规则保存/证书部署/重载/导入）永久阻塞。
func withCaddyOpLock(fn func()) {
	CaddyOpLock.Lock()
	defer CaddyOpLock.Unlock()
	fn()
}

// errSameConfig 渲染产物与运行配置字节一致（Caddy changeConfig 同源短路）。
// 审计真实性裁定（2026-09-25 用户裁定：审计事件必须真实有效）——同字节时
// 跳过 /load 调用（Caddy 端本就零 provision），调用方据此不落「重载」审计。
var errSameConfig = errors.New("config byte-identical to running config")

// caddyConfigDegradationKey 渲染降级标记：渲染层某组件读库/
// 解析失败按安全侧兜底渲染（可用性优先，不 fail-visible——一份带外脏行不得
// 阻断整份配置生成），但「渲染产物与 UI 宣称分叉」的事实随配置图携带，apply
// 成功后落审计行+caddy_apply_error 横幅，面板可见。
const caddyConfigDegradationKey = caddyInternalKeyPrefix + "generation_degradation"

// lastRenderDegradation 记录最近一次成功应用的配置携带的降级说明（空=无降级）。
// recordCaddyApplyResult 的成功清除先查本值——降级不是应用失败，横幅不得被
// 成功清除吞掉；下次干净渲染+成功 apply 时置空，横幅随清除恢复正常语义。
var (
	renderDegradationMu            sync.Mutex
	lastRenderDegradationV         string
	renderDegradationAuditPendingV bool
)

// LastRenderDegradation 返回最近一次成功应用的配置携带的渲染降级说明。
func LastRenderDegradation() string {
	renderDegradationMu.Lock()
	defer renderDegradationMu.Unlock()
	return lastRenderDegradationV
}

// setLastRenderDegradation 设置进程级降级状态（测试缝：审计/横幅收敛用例
// 需要预置“上一轮降级”形态；生产写入统一经 applyRenderDegradationState）。
func setLastRenderDegradation(msg string) {
	renderDegradationMu.Lock()
	lastRenderDegradationV = msg
	renderDegradationMu.Unlock()
}

// TakePendingRenderDegradationAudit 取走「事务内 apply 暂缓落审计」的降级说明
// （空=无待落）。事务内 apply（persist=false）立即写审计会在随后
// commit 失败时留下描述「从未提交配置」的降级事件——审计必须等 commit 成功
// 后由 recordCaddyApplyResult 补落；非事务 apply 仍在应用成功时立即留痕。
func TakePendingRenderDegradationAudit() string {
	renderDegradationMu.Lock()
	defer renderDegradationMu.Unlock()
	if !renderDegradationAuditPendingV {
		return ""
	}
	renderDegradationAuditPendingV = false
	return lastRenderDegradationV
}

// IsSameConfig 报告错误为「配置同字节未变化」短路。
func IsSameConfig(err error) bool { return errors.Is(err, errSameConfig) }

// getRunningConfigBytes 拉取 Caddy 当前运行配置的原始字节（admin GET /config/）。
// 失败时返回错误——比对调用方按「未知→照常 /load」处理（fail-open，
// 与 Caddy 自身短路同向：误放行的代价只是一次被 Caddy 短路的 /load）。
func (s *CaddyService) getRunningConfigBytes() ([]byte, error) {
	resp, err := s.client.Get(s.adminURL + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// 同族防线（全文件最后一处无界 admin 读取收口）。
	// 与 GetConfig 共用 ReadAdminConfigBody（状态分类 + 32MB+1 探测），
	// 超限返回显式错误而非静默截断——比对方按 fail-open 照常 /load，但日志
	// 可见「超限」而非「配置变化」的假象。
	return ReadAdminConfigBody(resp)
}

func (s *CaddyService) applyConfigLocked(config map[string]interface{}, persistDegradation bool) (err error) {
	return s.applyConfigLockedOpt(config, false, persistDegradation)
}

// ApplyConfigForce 与 ApplyConfig 同语义，但强制 Caddy 重载
// must-revalidate）——供数据类更新路径与测试使用。
// 调用方 MUST 已持有 CaddyOpLock：当前唯一生产调用方
// （cluster_apply.go 的同步应用路径）在锁内；本函数仅持 s.mu，新增调用方漏锁会
// 重现 apply→commit 混合态窗口。已持锁调用方不得再经
// GenerateAndApplyConfigForce 自取锁（重入死锁）。
func (s *CaddyService) ApplyConfigForce(config map[string]interface{}) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigLockedOpt(config, true, true)
}

// caddyApplyOptions 收集一次 apply 的副作用开关：
//   - force：强制 /load（must-revalidate，击穿 Caddy 同字节短路）；
//   - persistDegradation：应用成功即持久化渲染降级横幅与审计（事务内 apply
//     必须为 false——未提交配置的降级不得写入主库/审计）；
//   - persistLastGood：应用成功即写 last-known-good。事务内 apply 必须为
//     false：apply 在 commit 之前执行，进程若在 commit 前中断（SIGKILL/OOM/
//     容器被杀），启动兜底会把从未提交的配置当作「最后已知正确」真实回放。
//     调用方在 commit 成功后用返回的应用字节调 PersistLastGoodBytesInLock
//     补齐（零额外渲染）。
type caddyApplyOptions struct {
	force              bool
	persistDegradation bool
	persistLastGood    bool
}

func (s *CaddyService) applyConfigLockedOpt(config map[string]interface{}, force, persistDegradation bool) error {
	_, err := s.applyConfigWithOptions(config, caddyApplyOptions{
		force:              force,
		persistDegradation: persistDegradation,
		persistLastGood:    true,
	})
	return err
}

// applyConfigWithOptions 是 apply 的唯一实现。返回本次真实下发到 /load 的
// 载荷字节（nil=同字节短路或被拒/失败）——仅事务内调用方（persistLastGood=
// false）消费，用于 commit 成功后补写 last-known-good。
func (s *CaddyService) applyConfigWithOptions(config map[string]interface{}, opts caddyApplyOptions) (applied []byte, err error) {
	force := opts.force
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		// 生成失败 = 该 DB 视图渲染不出合法配置，按「配置被拒」分类（门控回滚）。
		return nil, &ConfigRejectedError{Err: errors.New(message)}
	}
	snapshot, hasSnapshot := config[caddyCertFilesSnapshotKey].(CertFilesSnapshot)
	// 本次生成实际写盘了证书文件（MaterializeCertPairs 检出
	// 内容/权限差异，快照非空）而证书路径确定性意味着 JSON 可能字节相同——
	// 不强制重载时 errSameConfig 短路会让 Caddy 内存里继续用旧证书（重传证书
	// 静默不生效，DB/UI 全报成功）。快照非空即自动升级为强制。
	if hasSnapshot && len(snapshot) > 0 {
		force = true
	}
	if hasSnapshot {
		defer func() {
			if err != nil {
				err = errors.Join(err, RestoreCertFiles(snapshot))
			}
		}()
	}

	data, err := json.Marshal(caddyPayload(config))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	// 审计真实性门（2026-09-25 用户裁定）：非强制路径先比对运行配置字节——
	// 相同则跳过 /load（Caddy changeConfig 本就短路零 provision），返回
	// errSameConfig 让审计层知道「没有发生真实重载」。比对失败按未知照常
	// /load（fail-open，与 Caddy 自身短路同向）。
	if !force {
		running, runningErr := s.getRunningConfigBytes()
		if runningErr == nil && caddyConfigJSONEqual(running, data) {
			// 同字节短路同样收敛降级状态（见函数说明）。
			applyRenderDegradationState(config, opts.persistDegradation)
			return nil, errSameConfig
		}
		if errors.Is(runningErr, errCaddyAdminConfigTooLarge) {
			// 超限是形态异常（非常规瞬时读失败），跳过短路但显式留痕。
			Logf("warn", "Caddy 运行配置超过同字节比对上限，跳过短路照常 /load: %v", runningErr)
		}
	}

	req, err := http.NewRequest(http.MethodPost, s.adminURL+"/load", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to build config apply request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if force {
		// Caddy admin 官方逃生口（admin.go: forceReload:= Header ""
		// == "must-revalidate"）：相同 JSON 也执行完整 provision，磁盘数据
		//（xdb/CRS/证书）的变化得以进入插件内存。
		req.Header.Set("Cache-Control", "must-revalidate")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to apply config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		inner := fmt.Errorf("config apply failed: %s", string(readCaddyErrorBody(resp.Body)))
		if resp.StatusCode < 500 {
			// admin 4xx = Caddy 拒绝该配置（provision/校验失败），配置本身不可用；
			// 5xx 归为系统失败（Caddy 存活但内部错误），不阻断落库。
			return nil, &ConfigRejectedError{Err: inner}
		}
		return nil, inner
	}

	Logf("info", "Caddy config applied successfully")
	// 重载重建 registry：限流 429 计数归零，/metrics 抓取缓存必须同步失效
	//（否则安全总览在 ≤5s 内仍显示重载前累计值）。
	InvalidateOverviewMetricsCache()
	if opts.persistLastGood {
		s.persistLastGoodLocked(data)
	}
	// 整轮渲染 apply 成功（=本轮全部在役名单已投影且被 Caddy 接受）后统一
	// GC 名单投影文件——此时引用集落齐，差集安全。
	maybeGCStaleIPListFiles()
	// 渲染降级随配置图到达此处——成功应用后落审计行+
	// caddy_apply_error 横幅（不阻断应用）；干净渲染置空状态，handlers 侧
	// recordCaddyApplyResult(nil) 据此恢复常规清除。
	applyRenderDegradationState(config, opts.persistDegradation)
	// 后台强制重载（证书部署 / CRS / IP 库 / 威胁库 / 自动封禁）成功即运行
	// 配置已按库对齐——此前这类成功不清陈旧 caddy_apply_error（只有 handler
	// 写路径经 recordCaddyApplyResult 清），上一次写路径失败留下的横幅会一直
	// 亮到下一次写请求，与实际状态相反。仅强制且非事务内形态（persist）执行：
	// 事务内 apply 会在 commit 前清横幅，commit 失败时留下「看起来已恢复」的
	// 假象；本轮渲染有降级时上方刚写入降级横幅，不得覆盖。
	if force && opts.persistDegradation && LastRenderDegradation() == "" && db.DB != nil {
		if _, execErr := db.DB.Exec(`UPDATE global_config SET caddy_apply_error='' WHERE id=1 AND caddy_apply_error<>''`); execErr != nil {
			Logf("warn", "后台重载成功但清除陈旧应用失败横幅失败（横幅可能滞留）: %v", execErr)
		}
	}
	return data, nil
}

// applyRenderDegradationState 收敛本轮渲染的降级状态。
// 必须在「同字节短路」与「成功 /load」两条出口都调用：降级键经 caddyPayload
// 从载荷剔除、不参与字节比较，若只在真实 /load 后处理，则
//   - 启用某特性但本轮渲染降级、产物又与运行配置同字节（如受信代理开启瞬间
//     读设置失败按未启用渲染）→ 保存「成功」、横幅/审计全无，面板显示已启用
//     而实际未生效；
//   - 降级已解除但新渲染与运行配置同字节 → applyRenderDegradationState("") 不可达，
//     LastRenderDegradation 残留旧值，recordCaddyApplyResult(nil) 会把旧降级
//     重新持久化。
//
// persist=false（事务内 apply）不写主库：未提交事务仍持写锁，持久化交给
// commit 后的 recordCaddyApplyResult(nil)。审计同样暂缓
// 立即落「应用降级」会在 commit 失败时描述一份从未提交的
// 配置；recordCaddyApplyResult 在成功收尾时经 TakePendingRenderDegradationAudit
// 补落。非事务 apply（persist=true）仍即时留痕。
func applyRenderDegradationState(config map[string]interface{}, persist bool) {
	degraded, _ := config[caddyConfigDegradationKey].(string)
	renderDegradationMu.Lock()
	lastRenderDegradationV = degraded
	// persist=false（事务内 apply）只标记待落，commit 成功后由
	// recordCaddyApplyResult 补审计（否则 commit 失败会留下
	// 「从未提交配置」的降级事件）。
	renderDegradationAuditPendingV = degraded != "" && !persist
	renderDegradationMu.Unlock()
	if degraded == "" {
		return
	}
	if !persist {
		return
	}
	RecordAuditLog("system", "应用降级", "Caddy配置", degraded, "")
	if db.DB != nil {
		if _, err := db.DB.Exec(`UPDATE global_config SET caddy_apply_error=? WHERE id=1`, degraded); err != nil {
			Logf("warn", "D3: 持久化渲染降级横幅失败: %v", err)
		}
	}
}

// SetLastGoodPath 启用「最后已知正确配置」落盘（裁定 2026-09-06 ③）。每次
// 成功 /load 后写入；启动时 DB 渲染被拒（升级判定漂移、不变量破坏等残余
// 场景）可回退应用该文件，保证负载均衡服务可用性。IO 失败仅记日志——
// 落盘是兜底通道，不得影响主应用路径。
func (s *CaddyService) SetLastGoodPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastGoodPath = path
}

func (s *CaddyService) persistLastGoodLocked(data []byte) {
	if s.lastGoodPath == "" {
		return
	}
	tmp := s.lastGoodPath + ".tmp"
	// 0 字节 last-good 会让启动兜底失效——与 certstore 原子写同口径
	// （临时文件 fsync + 父目录 fsync 后 rename）。
	if err := writeSyncedFile(tmp, data, 0o600); err != nil {
		Logf("error", "last-known-good: write temp file failed: %v", err)
		return
	}
	if err := os.Rename(tmp, s.lastGoodPath); err != nil {
		Logf("error", "last-known-good: rename into place failed: %v", err)
		return
	}
	if err := syncParentDir(s.lastGoodPath); err != nil {
		Logf("error", "last-known-good: sync parent dir failed: %v", err)
	}
}

// ApplyLastKnownGood 读取并原样应用最后一次成功下发的配置（启动兜底）。
// 未配置/文件缺失/应用失败均返回错误，由调用方决定后续。
// /load 入 CaddyOpLock——此前仅持 s.mu，与持
// CaddyOpLock 的并发「渲染+/load」写者（handler 写路径/后台 Force 重载）交错时，
// last-good 的旧配置可后到覆盖新配置。持锁序 CaddyOpLock→s.mu 与
// GenerateAndApplyConfigForce 同型（叶操作无 AB-BA）；唯一生产调用方
// ApplyConfigOnStartup 在 applyCaddyConfigE 返回（锁已释放）后调用，无需 InLock 变体。
func (s *CaddyService) ApplyLastKnownGood() error {
	CaddyOpLock.Lock()
	defer CaddyOpLock.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastGoodPath == "" {
		return errors.New("last-known-good path not configured")
	}
	data, err := os.ReadFile(s.lastGoodPath)
	if err != nil {
		return fmt.Errorf("read last-known-good config: %w", err)
	}
	resp, err := s.client.Post(s.adminURL+"/load", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("apply last-known-good config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("apply last-known-good config failed: %s", string(readCaddyErrorBody(resp.Body)))
	}
	// 启动兜底同样是一次真实 /load：registry 已重建，缓存口径必须失效。
	InvalidateOverviewMetricsCache()
	return nil
}

// ErrCLIValidatorUnavailable 表示 CLI 校验器本身不可用（二进制缺失、超时、
// 临时文件失败）——区别于「配置被拒」。调用方对其记日志放行：事务内
// ApplyConfigFromTx 仍是最终门控，校验器故障不得阻断全部写入。
var ErrCLIValidatorUnavailable = errors.New("caddy CLI validator unavailable")

// cliValidatorNotEnabledError 标记「校验器未装配」（EnableCLIValidation 未被
// 调用 / 测试未注入）——候选配置从未经过 Caddy 级预检。与真正故障同属
// ErrCLIValidatorUnavailable（调用方按统一「不可用→记录后放行」处理），
// 消息保留具体原因供日志排障；不再暴露独立哨兵——其「可区分」契约没有任何
// 消费方（文案/日志/审计两条路径完全相同），层级只会误导读者以为存在分支。
func cliValidatorNotEnabledError() error {
	return fmt.Errorf("%w: validator not enabled (EnableCLIValidation not called)", ErrCLIValidatorUnavailable)
}

// caddyCLIValidateTimeout 是 CLI 校验子进程的超时。var 而非 const：测试需注入
// 毫秒级超时驱动「超时=校验器不可用」分支；生产预算短于前端 30s 默认超时。
var caddyCLIValidateTimeout = 20 * time.Second

// EnableCLIValidation 启用 CLI 校验层（仅 main 装配调用；测试用桩注入）。
func (s *CaddyService) EnableCLIValidation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cliValidate = execCaddyValidate
}

// SetCLIValidatorForTest 注入 CLI 校验桩（测试专用）。
func (s *CaddyService) SetCLIValidatorForTest(fn func(rendered []byte) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cliValidate = fn
}

// execCaddyValidate 把渲染产物写入临时文件并执行 `caddy validate`。非零退出
// = 配置被拒（输出含 provision/校验详情）；二进制缺失/超时 = 校验器不可用。
func execCaddyValidate(rendered []byte) error {
	tmp, err := os.CreateTemp("", "lazy-balancer-cli-validate-*.json")
	if err != nil {
		return fmt.Errorf("%w: create temp file: %v", ErrCLIValidatorUnavailable, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(rendered); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: write temp file: %v", ErrCLIValidatorUnavailable, err)
	}
	tmp.Close()
	ctx, cancel := context.WithTimeout(context.Background(), caddyCLIValidateTimeout)
	defer cancel()
	// 输出收集侧有界——异常巨量输出（病态配置/插件刷屏）不得无界驻留
	// 内存；超出上限的字节继续读取但不保留。
	output := &cappedOutputBuffer{limit: caddyValidateOutputLimit}
	cmd := exec.CommandContext(ctx, "caddy", "validate", "--config", tmpPath)
	cmd.Stdout = output
	cmd.Stderr = output
	err = cmd.Run()
	if err != nil {
		return classifyCaddyValidateFailure(ctx.Err(), err, output.buf.Bytes())
	}
	return nil
}

// isRuntimeFatalOutput 识别 Go 运行时在配置解析前自行 abort 的输出签名。
// 生产实证：容器 ulimit -u 过紧时 caddy validate 以
// 「runtime: failed to create new OS thread ... fatal error: newosproc」退出，
// 退出码 2——若不区分，任何保存（含基础设置）都会被误报为配置被拒。
func isRuntimeFatalOutput(output []byte) bool {
	for _, sig := range [...]string{
		"fatal error:",
		"failed to create new OS thread",
		"runtime: out of memory",
		"fatal error: newosproc",
	} {
		if bytes.Contains(output, []byte(sig)) {
			return true
		}
	}
	return false
}

// classifyCaddyValidateFailure 归类 `caddy validate` 的执行错误：
//   - 配置被拒 = 进程确实运行并以非零退出码结束（*exec.ExitError 且 Exited()），
//     且输出不是 Go 运行时致命错误；
//   - 校验器不可用 = 其余全部形态（超时 ctx 到期、二进制缺失/不可执行/权限
//     拒绝（*fs.PathError/*exec.Error，无 ExitError）、信号致死/OOM
//     （*exec.ExitError 但 !Exited()）、运行时 fatal abort）。
//
// 抽取为纯函数以钉住后两类分支：把环境故障（权限/被信号杀死/线程耗尽）归为
// 「配置被拒」会以 400+回滚把基础设施问题伪装成用户配置错误。
func classifyCaddyValidateFailure(ctxErr, runErr error, output []byte) error {
	var exitErr *exec.ExitError
	if ctxErr != nil || errors.Is(runErr, exec.ErrNotFound) || !errors.As(runErr, &exitErr) {
		return fmt.Errorf("%w: %v", ErrCLIValidatorUnavailable, runErr)
	}
	if state := exitErr.ProcessState; state != nil && !state.Exited() {
		return fmt.Errorf("%w: caddy validate 进程异常终止: %v", ErrCLIValidatorUnavailable, runErr)
	}
	// Go 运行时致命错误（ulimit 线程耗尽/内存耗尽）会在任何配置解析之前
	// 直接 abort，退出码非零却与配置内容无关——归为校验器不可用，避免把
	// 宿主资源问题伪装成「配置被拒」阻断保存。
	if isRuntimeFatalOutput(output) {
		return fmt.Errorf("%w: caddy validate 进程运行时崩溃: %s: %s", ErrCLIValidatorUnavailable, runErr, string(boundedValidateDetail(output)))
	}
	// caddy validate 以非零退出码表达「配置被拒」。
	return fmt.Errorf("caddy validate 拒绝配置: %s", string(boundedValidateDetail(output)))
}

// caddyValidateOutputLimit 是 execCaddyValidate 收集子进程输出的上限：错误详情
// 只保留 caddyErrorBodyMaxBytes，额外留一个 rune 的余量，使「先按上限切字节→
// 再归一到 UTF-8 边界」的尾 rune 回退有可用的合法字节序列。
const caddyValidateOutputLimit = caddyErrorBodyMaxBytes + utf8.UTFMax

// cappedOutputBuffer 是有界输出收集器（子进程 stdout/stderr 可用）。
// Write 恒报告全额消费（短写会让子进程/管道误判），仅保留前 limit 字节。
type cappedOutputBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedOutputBuffer) Write(p []byte) (int, error) {
	written := len(p)
	if remain := c.limit - c.buf.Len(); remain > 0 {
		if len(p) > remain {
			p = p[:remain]
		}
		c.buf.Write(p)
	}
	return written, nil
}

// boundedValidateDetail 生成嵌入 error 的校验输出详情：先按上限切字节、再回退
// 到合法 UTF-8 边界（与 jobstate.go 消息截断、readCaddyErrorBody 同序
// ——先归一再按固定字节位硬切会把切口落在多字节字符中间，序列化后成为 U+FFFD
// 残片）。
func boundedValidateDetail(output []byte) []byte {
	if len(output) > caddyErrorBodyMaxBytes {
		output = output[:caddyErrorBodyMaxBytes]
	}
	return truncateValidUTF8Tail(output)
}

// ErrUnvalidatedApply 标记「应用失败时配置未经过任何 Caddy 级校验」（CLI
// 校验器不可用且 admin 应用传输失败同时发生）。此情形无法排除坏配置，写
// 路径必须回滚而非退化提交（2026-09-06 乱填保障补充裁定：乱填要么被拦、
// 要么写入失败，绝不全量落库）。
var ErrUnvalidatedApply = errors.New("config unvalidated by any Caddy-level check")

// ValidateTxRenderViaCLI 用 caddy CLI 校验事务视图渲染出的全量候选配置——
// 校验输入=最终将应用的渲染本身（裁定 2026-09-06 ④'：任意 Caddy 修改三层
// 校验的 Caddy 层），零运行时副作用。未启用时返回 nil。分类：拒绝→
// *ConfigRejectedError（门控回滚 400）；不可用→ErrCLIValidatorUnavailable。
// rulesWrittenInTx：调用方事务是否写过 lb_rules（ACME 谓词 miss 补查门控，
// 见 generateCaddyConfigWithCertSource）。
func (s *CaddyService) ValidateTxRenderViaCLI(tx *sql.Tx, rulesWrittenInTx bool) error {
	s.mu.Lock()
	validator := s.cliValidate
	s.mu.Unlock()
	if validator == nil {
		Logf("warn", "caddy CLI 校验器未装配：本次写入未经 Caddy 级预检（事务内应用仍为最终门控）")
		return cliValidatorNotEnabledError()
	}
	// 渲染会写 IP 名单投影；CLI 拒绝时必须自回滚，不能依赖每个调用方
	//成功路径保留新投影供随后的 ApplyConfigFromTx 使用。
	// 快照失败（目录/投影瞬时读失败）必须显式失败：以不完整快照渲染后，
	// 拒绝路径既无法回写缺项内容，也不能用「目录里有、快照里没有」判定新增
	// ——那会把在役投影当渲染产物删掉。
	projectionSnapshot, snapshotErr := SnapshotIPListProjections()
	if snapshotErr != nil {
		return fmt.Errorf("IP 名单投影快照失败，拒绝在不可回滚的前提下渲染: %w", snapshotErr)
	}
	applied := false
	defer func() {
		if applied {
			// 渲染成功＝新建投影随配置提交，清单只释放不删除。
			EndIPListProjectionPass()
			return
		}
		if rerr := RestoreIPListProjections(projectionSnapshot); rerr != nil {
			// 回滚不完整=投影目录可能残留未提交的名单内容（稳定命名热路径
			// ≤1s 会被在役配置感知），必须留痕供排障。
			Logf("error", "caddy CLI 预检失败后的 IP 名单投影回滚不完整: %v", rerr)
		}
	}()
	config := generateCaddyConfigWithCertSource(tx, db.DB, rulesWrittenInTx)
	// 2026-09-07：渲染过程中 MaterializeCertPairs 可能已将证书文件
	// 写盘——无论校验结果如何都恢复快照（后续 ApplyConfigFromTx 会重新生成
	// 并重新物化），使本函数真正「零运行时副作用」（事务回滚时磁盘不留
	// 未提交证书）。快照为空（无证书差异）时 RestoreCertFiles 为 no-op。
	if snapshot, ok := config[caddyCertFilesSnapshotKey].(CertFilesSnapshot); ok {
		defer func() { _ = RestoreCertFiles(snapshot) }()
	}
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		return &ConfigRejectedError{Err: errors.New(message)}
	}
	rendered, err := json.Marshal(caddyPayload(config))
	if err != nil {
		return fmt.Errorf("%w: marshal candidate: %v", ErrCLIValidatorUnavailable, err)
	}
	if err := validator(rendered); err != nil {
		if errors.Is(err, ErrCLIValidatorUnavailable) {
			return err
		}
		return &ConfigRejectedError{Err: err}
	}
	applied = true
	return nil
}

// ValidateJSONViaCLI 用 caddy CLI 校验一份原始 JSON 配置（PutCaddyConfig
// 逃生口，裁定 2026-09-06 ④' 边界补齐）。分类同 ValidateTxRenderViaCLI。
func (s *CaddyService) ValidateJSONViaCLI(data []byte) error {
	s.mu.Lock()
	validator := s.cliValidate
	s.mu.Unlock()
	if validator == nil {
		Logf("warn", "caddy CLI 校验器未装配：本份原始配置未经 Caddy 级预检")
		return cliValidatorNotEnabledError()
	}
	if err := validator(data); err != nil {
		if errors.Is(err, ErrCLIValidatorUnavailable) {
			return err
		}
		return &ConfigRejectedError{Err: err}
	}
	return nil
}

// readCaddyErrorBody 读取 Caddy 管理接口错误响应体并截断到 1KB 内。Caddy 错误体被
// 完整嵌入 error 后，会经 apply_ok_reload_failed 标记、集群 last_sync_error、证书
// 任务 message 等有界通道传播；按字节截断后回退到合法 UTF-8
// 边界，避免多字节字符残片乱码（复用 cluster_sync.go 的 truncateValidUTF8Tail 模式）。
func readCaddyErrorBody(body io.Reader) []byte {
	limited, _ := io.ReadAll(io.LimitReader(body, caddyErrorBodyMaxBytes))
	return truncateValidUTF8Tail(limited)
}

// caddyErrorBodyMaxBytes 限制嵌入 error 的 Caddy 管理接口错误响应体大小。
const caddyErrorBodyMaxBytes = 1024

// caddyAdminConfigMaxBytes admin GET /config/ 响应体解码上限（32MB 家族口径：
// 与 getRunningConfigBytes/看门狗同源，防止异常对端无界分配）。
const caddyAdminConfigMaxBytes = 32 << 20

// errCaddyAdminConfigTooLarge 标记 admin GET /config/ 超过比对上限
// 调用方据此把「超限」与瞬时读失败区分开留痕（二者都按 fail-open 照常 /load）。
var errCaddyAdminConfigTooLarge = errors.New("Caddy admin 配置响应超过 32MB 上限")

// ReadAdminConfigBody 读取 admin GET /config/ 的响应体：非 2xx 一律返回带状态码
// 的错误（错误体经 readCaddyErrorBody 截断到 1KB 供诊断），2xx 时按 32MB 上限
// 返回原始字节（超限经 +1 探测返回 errCaddyAdminConfigTooLarge 显式错误，
// 绝不静默截断）。此前 GetConfig/GetUpstreamHealthDetailed
// 直接解码响应体——Caddy 错误体本身是合法 JSON（{"error":"..."}），4xx/5xx 时错误
// 对象会被当配置返回，健康查询更会静默退化为「无健康数据」的空表。
// 跨包单源：handlers.GetCaddyConfig 同样复用本函数（裸 LimitReader 会把超限
// 误报为「解析失败」，排障误导）。
func ReadAdminConfigBody(resp *http.Response) ([]byte, error) {
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("GET /config/ returned %d: %s", resp.StatusCode, strings.TrimSpace(string(readCaddyErrorBody(resp.Body))))
	}
	// +1 探测（metrics 16MB 家族同口径）——裸 LimitReader 静默截断
	// 会让超限与「合法短响应」不可区分（配置结构比对恒不等 → 多余一次 /load；
	// upstreams 解码静默失败为空表）。
	data, err := io.ReadAll(io.LimitReader(resp.Body, caddyAdminConfigMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > caddyAdminConfigMaxBytes {
		return nil, fmt.Errorf("%w（上限 %d 字节）", errCaddyAdminConfigTooLarge, caddyAdminConfigMaxBytes)
	}
	return data, nil
}

// ValidateConfig validates Caddy configuration using the /load API with validate=true
func (s *CaddyService) ValidateConfig(config map[string]interface{}) (err error) {
	// validate=true 实为真实加载（Caddy 以校验模式执行完整的 provision/
	// 加载路径，coraza 等插件照常编译并持有资源），与 apply 同为写操作——
	// 跨层串行化契约：**调用方须持 CaddyOpLock** 进入（本函数仅持 s.mu 保护
	// CaddyService 内部状态；与并发 apply/证书快照恢复的互斥由调用方的
	// CaddyOpLock 临界区承担——，历史：原注释「必须持写锁串行化」
	// 误读为本函数自取跨层写锁）。
	s.mu.Lock()
	defer s.mu.Unlock()
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		return errors.New(message)
	}
	snapshot, hasSnapshot := config[caddyCertFilesSnapshotKey].(CertFilesSnapshot)
	if hasSnapshot {
		defer func() {
			err = errors.Join(err, RestoreCertFiles(snapshot))
		}()
	}
	data, err := json.Marshal(caddyPayload(config))
	if err != nil {
		return err
	}

	validateURL := s.adminURL + "/load?validate=true"
	resp, err := s.client.Post(validateURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// admin 4xx=候选配置被拒（可安全的 400 映射），
		// 5xx=admin 内部故障（Caddy 存活但 provision/资源失败），与
		// applyConfigWithOptions 同构：只有 <500 归 ConfigRejectedError，
		// 调用侧 IsConfigRejected 才能把系统故障如实映射为 500。
		inner := fmt.Errorf("validation failed: %s", string(readCaddyErrorBody(resp.Body)))
		if resp.StatusCode < 500 {
			return &ConfigRejectedError{Err: inner}
		}
		return inner
	}

	return nil
}

func caddyPayload(config map[string]interface{}) map[string]interface{} {
	payload := make(map[string]interface{}, len(config))
	for key, value := range config {
		// 按 __lazy_balancer_ 前缀整体剔除内部键
		//（generation_error/cert_files_snapshot/degradation 及未来新增），
		// 不再逐键枚举——漏一枚即被真 Caddy 严格解码 400 硬拒。
		if strings.HasPrefix(key, caddyInternalKeyPrefix) {
			continue
		}
		payload[key] = value
	}
	return payload
}

// RouteIDBelongsToRule 判断运行配置中的路由 @id 是否归属某规则：主路由
// （@id == ruleID）或其兄弟路由。兄弟路由按生成侧已知后缀精确判定
// （tagRuleRoute 的 path_<序号>、geoip，以及 HTTP→HTTPS 跳转的 redirect），
// 不做 ruleID+"_" 的裸前缀匹配——v1 导入/历史 ID 可含下划线，`lb_web` 与
// `lb_web_path` 两条规则并存时裸前缀会把后者的主路由混进前者的配置查看框。
// 当前唯一生产消费点是 handlers 侧 GetRuleCaddyConfig 的兄弟路由收集。
func RouteIDBelongsToRule(routeID, ruleID string) bool {
	if ruleID == "" {
		return false
	}
	if routeID == ruleID {
		return true
	}
	suffix, ok := strings.CutPrefix(routeID, ruleID+"_")
	if !ok || suffix == "" {
		return false
	}
	switch {
	case suffix == "geoip", suffix == "redirect":
		return true
	case strings.HasPrefix(suffix, "path_"):
		rest := strings.TrimPrefix(suffix, "path_")
		if rest == "" {
			return false
		}
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// RuleIDNamespaceConflict 报告 ruleID 与 ids 中另一条规则 ID 是否撞入生成式
// 子路由 @id 命名空间（<ruleID>_path_<n> / <ruleID>_geoip / <ruleID>_redirect）。
// 子路由 @id 由字符串拼接产生，同形规则 ID 会让 Caddy 在 /load 以 duplicate ID
// 拒绝整份配置（400 + 回滚）；写/导入/集群应用侧提前点名冲突的两条规则，
// 用户得到字段级中文错误而非引擎的配置路径报错。判定复用运行配置归属函数
// RouteIDBelongsToRule，两侧命名空间口径保持同源。无冲突返回空串。
func RuleIDNamespaceConflict(ruleID string, ids []string) string {
	for _, other := range ids {
		if other == ruleID {
			continue
		}
		if RouteIDBelongsToRule(ruleID, other) {
			return other
		}
	}
	return ""
}

// GetConfig gets current Caddy configuration
func (s *CaddyService) GetConfig() (map[string]interface{}, error) {
	resp, err := s.client.Get(s.adminURL + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 非 2xx 必须先拦（Caddy 错误体是合法 JSON，直接解码会把
	// 错误对象当配置返回）；解码上限沿用 32MB 家族口径。
	body, err := ReadAdminConfigBody(resp)
	if err != nil {
		return nil, err
	}

	var config map[string]interface{}
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}

	return config, nil
}

// UpstreamHealthDetail contains detailed health information for an upstream
type UpstreamHealthDetail struct {
	Healthy bool `json:"healthy"`
	Unknown bool `json:"unknown"`
	// Dynamic 标记动态 DNS 上游:Caddy 动态池按解析后 IP:port 键控
	// (reverseproxy/hosts.go),域名:port 键在指标/健康两数据源均不可命中——
	// 域名级健康/请求数不可观测(N/A),负载均衡与被动健康运行时不受影响。
	Dynamic     bool `json:"dynamic,omitempty"`
	Degraded    bool `json:"degraded"`
	NumRequests int  `json:"num_requests"`
	Fails       int  `json:"fails"`
}

// upstreamHealthCacheTTL 限制面板多轮询实例对 admin/metrics 的放大；失败不缓存。
var upstreamHealthCacheTTL = 5 * time.Second

type upstreamHealthCall struct {
	done   chan struct{}
	health map[string]map[string]*UpstreamHealthDetail
	err    error
}

// GetUpstreamHealthDetailed returns detailed health status of all upstreams from Caddy.
// 成功结果按 5s TTL 缓存且并发单飞；每次返回深拷贝，调用方不能污染共享缓存。
func (s *CaddyService) GetUpstreamHealthDetailed() (map[string]map[string]*UpstreamHealthDetail, error) {
	return s.aggregateUpstreamHealthWithSingleflight(s.getUpstreamHealthDetailedUncached)
}

// aggregateUpstreamHealthWithSingleflight 是健康聚合的单飞+TTL 缓存宿主。
// 单飞槽位与 done 通道必须在 defer 中收尾：聚合内部 panic（畸形 admin 响应
// 解析等）若直接冲出函数，healthInflight 会永久驻留——所有后续调用阻塞在
// <-call.done 上，健康面板永久悬挂且无法自愈。panic 仍向首个调用方传播，
// 等待者拿到错误；下一次调用重新发起聚合。
func (s *CaddyService) aggregateUpstreamHealthWithSingleflight(load func() (map[string]map[string]*UpstreamHealthDetail, error)) (health map[string]map[string]*UpstreamHealthDetail, err error) {
	s.healthMu.Lock()
	if s.healthCache != nil && time.Now().Before(s.healthCacheExpiresAt) {
		cached := cloneUpstreamHealthDetails(s.healthCache)
		s.healthMu.Unlock()
		return cached, nil
	}
	if call := s.healthInflight; call != nil {
		s.healthMu.Unlock()
		<-call.done
		if call.err != nil {
			return nil, call.err
		}
		return cloneUpstreamHealthDetails(call.health), nil
	}
	call := &upstreamHealthCall{done: make(chan struct{})}
	s.healthInflight = call
	s.healthMu.Unlock()

	finish := func() {
		s.healthMu.Lock()
		call.err = err
		if err == nil && health != nil {
			// 缓存持有独立克隆：首个调用方拿到的是函数体里的另一次克隆，
			// 等待者再从 call.health 克隆——三者互不共享，调用方变更不会
			// 污染共享缓存。
			cached := cloneUpstreamHealthDetails(health)
			call.health = cached
			s.healthCache = cached
			s.healthCacheExpiresAt = time.Now().Add(upstreamHealthCacheTTL)
		} else {
			call.health = health
		}
		s.healthInflight = nil
		s.healthMu.Unlock()
		close(call.done)
	}
	defer func() {
		if p := recover(); p != nil {
			// 等待者不能悬挂：记为错误后照常传递 panic（首个调用方看到真实栈）。
			health, err = nil, fmt.Errorf("上游健康聚合 panic: %v", p)
			finish()
			panic(p)
		}
		finish()
	}()

	health, err = load()
	if err != nil {
		return nil, err
	}
	return cloneUpstreamHealthDetails(health), nil
}

func cloneUpstreamHealthDetails(src map[string]map[string]*UpstreamHealthDetail) map[string]map[string]*UpstreamHealthDetail {
	clone := make(map[string]map[string]*UpstreamHealthDetail, len(src))
	for server, upstreams := range src {
		serverClone := make(map[string]*UpstreamHealthDetail, len(upstreams))
		for dial, detail := range upstreams {
			if detail == nil {
				serverClone[dial] = nil
				continue
			}
			detailClone := *detail
			serverClone[dial] = &detailClone
		}
		clone[server] = serverClone
	}
	return clone
}

// upstreamHealthAggregateTimeout 限制健康聚合一轮三轮 admin 读取的整体
// deadline：单请求 client 超时 30s × 3 串行最坏 ~90s，且单飞
// 让所有并发轮询者等待同一个 call.done。整体截止后按既有降级语义返回：
// metrics 缺失=空表，config 读取失败=错误（不静默空表）。
var upstreamHealthAggregateTimeout = 10 * time.Second

// upstreamDetailFor 由被动指标与主动健康观测推导单个上游的展示明细——
// HTTP 静态上游 / 动态上游 / layer4 三段共用此单源（原三份逐字
// 重复的推导副本，健康语义修订需改三处且易漂移）。
func upstreamDetailFor(dial string, metrics map[string]*upstreamMetric, health map[string]bool, dynamic bool) *UpstreamHealthDetail {
	detail := &UpstreamHealthDetail{Dynamic: dynamic}
	if metric, ok := metrics[dial]; ok && metric != nil {
		detail.NumRequests = metric.NumRequests
		detail.Fails = metric.Fails
	}
	if observedHealthy, ok := health[dial]; ok {
		// Caddy reports a definitive health status for this upstream.
		detail.Healthy = observedHealthy
		// Passive circuit breakers forget failures after the fail window, so the
		// gauge flaps back to healthy while the upstream is still erroring;
		// surface that as degraded.
		if observedHealthy && detail.Fails > 0 {
			detail.Degraded = true
		}
	} else if detail.Fails > 0 {
		// Passive health observed failures.
		detail.Healthy = false
	} else {
		// No observation from Caddy at all.
		detail.Unknown = true
	}
	return detail
}

func (s *CaddyService) getUpstreamHealthDetailedUncached() (map[string]map[string]*UpstreamHealthDetail, error) {
	healthStatus := make(map[string]map[string]*UpstreamHealthDetail)

	ctx, cancel := context.WithTimeout(context.Background(), upstreamHealthAggregateTimeout)
	defer cancel()
	upstreamHealth := s.getUpstreamHealthFromMetrics(ctx)
	upstreamMetrics := s.getUpstreamMetrics(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.adminURL+"/config/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 与 GetConfig 同源状态门——错误页/4xx/5xx 不得静默退化为
	// 「无上游健康数据」的空表（旧实现此处直接解码错误 JSON 后返回 nil error）。
	body, err := ReadAdminConfigBody(resp)
	if err != nil {
		return nil, err
	}

	var config map[string]interface{}
	// 同族防线：admin 响应解码上限统一在
	// ReadAdminConfigBody（32MB，较 GetConfig 历史 4MB 宽：本端点返回完整
	// routes 视图，超大部署体积大，上限只为异常对端兜底，不得截断正常健康视图）。
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return healthStatus, nil
	}

	if httpApp, ok := apps["http"].(map[string]interface{}); ok {
		if servers, ok := httpApp["servers"].(map[string]interface{}); ok {
			for serverName, serverVal := range servers {
				server, ok := serverVal.(map[string]interface{})
				if !ok {
					continue
				}

				routes, ok := server["routes"].([]interface{})
				if !ok {
					continue
				}

				for _, route := range routes {
					routeMap, ok := route.(map[string]interface{})
					if !ok {
						continue
					}

					handleGroups, ok := routeMap["handle"].([]interface{})
					if !ok {
						continue
					}

					for _, handleGroup := range handleGroups {
						handle, ok := handleGroup.(map[string]interface{})
						if !ok || handle["handler"] != "reverse_proxy" {
							continue
						}
						if _, exists := healthStatus[serverName]; !exists {
							healthStatus[serverName] = make(map[string]*UpstreamHealthDetail)
						}

						// Handle static upstreams (dial addresses)
						if upstreams, ok := handle["upstreams"].([]interface{}); ok {
							for _, upstream := range upstreams {
								up, ok := upstream.(map[string]interface{})
								if !ok {
									continue
								}

								dial, ok := up["dial"].(string)
								if !ok {
									continue
								}

								healthStatus[serverName][dial] = upstreamDetailFor(dial, upstreamMetrics, upstreamHealth, false)
							}
						}

						// Handle dynamic upstreams (SRV/A record resolution)
						if dynamicUpstreams, ok := handle["dynamic_upstreams"].(map[string]interface{}); ok {
							name, _ := dynamicUpstreams["name"].(string)
							port, _ := dynamicUpstreams["port"].(string)
							if name != "" {
								// 动态 DNS 上游按域名键展示,标记 Dynamic=true——
								// 引擎按解析后 IP 跟踪健康,域名级观测恒 N/A(UI 显示 N/A
								// 而非误导性的「未知」)。查找保持原样(命中即附带数据)。
								dial := net.JoinHostPort(name, port)

								healthStatus[serverName][dial] = upstreamDetailFor(dial, upstreamMetrics, upstreamHealth, true)
							}
						}
					}
				}
			}
		}
	}

	if layer4App, ok := apps["layer4"].(map[string]interface{}); ok {
		if servers, ok := layer4App["servers"].(map[string]interface{}); ok {
			for serverName, serverVal := range servers {
				server, ok := serverVal.(map[string]interface{})
				if !ok {
					continue
				}
				routes, ok := server["routes"].([]interface{})
				if !ok {
					continue
				}
				for _, route := range routes {
					routeMap, ok := route.(map[string]interface{})
					if !ok {
						continue
					}
					handleGroups, ok := routeMap["handle"].([]interface{})
					if !ok {
						continue
					}
					for _, handleGroup := range handleGroups {
						handle, ok := handleGroup.(map[string]interface{})
						if !ok || handle["handler"] != "proxy" {
							continue
						}
						upstreams, ok := handle["upstreams"].([]interface{})
						if !ok {
							continue
						}
						if _, exists := healthStatus[serverName]; !exists {
							healthStatus[serverName] = make(map[string]*UpstreamHealthDetail)
						}
						for _, upstream := range upstreams {
							up, ok := upstream.(map[string]interface{})
							if !ok {
								continue
							}
							dialList, ok := up["dial"].([]interface{})
							if !ok || len(dialList) == 0 {
								continue
							}
							// layer4 upstream 的 dial 是数组——遍历全部条目
							// 逐个导出健康明细（原实现只取 dialList[0]，带外/外来
							// 多 peer 配置的其余 peer 静默漏报）。本产品渲染恒单 dial，
							// 常规路径形状不变。
							for _, dialValue := range dialList {
								dial, _ := dialValue.(string)
								if dial == "" {
									continue
								}
								healthStatus[serverName][dial] = upstreamDetailFor(dial, upstreamMetrics, upstreamHealth, false)
							}
						}
					}
				}
			}
		}
	}

	return healthStatus, nil
}

// upstreamMetric stores num_requests and fails for an upstream
type upstreamMetric struct {
	NumRequests int
	Fails       int
}

// getUpstreamMetrics fetches num_requests and fails from /reverse_proxy/upstreams
func (s *CaddyService) getUpstreamMetrics(ctx context.Context) map[string]*upstreamMetric {
	result := make(map[string]*upstreamMetric)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.adminURL+"/reverse_proxy/upstreams", nil)
	if err != nil {
		Logf("error", "Failed to build reverse_proxy/upstreams request: %v", err)
		return result
	}
	resp, err := s.client.Do(req)
	if err != nil {
		Logf("error", "Failed to get reverse_proxy/upstreams: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		Logf("info", "reverse_proxy/upstreams returned status %d", resp.StatusCode)
		return result
	}

	// 32MB 上限同族防线（口径见 GetUpstreamHealthDetailed）。
	// +1 探测——裸 LimitReader 静默截断会让解码失败被当作「空表」，
	// 运维无法区分「Caddy 无上游」与「响应超限」。
	body, err := io.ReadAll(io.LimitReader(resp.Body, caddyAdminConfigMaxBytes+1))
	if err != nil {
		Logf("error", "Failed to read reverse_proxy/upstreams: %v", err)
		return result
	}
	if len(body) > caddyAdminConfigMaxBytes {
		Logf("error", "reverse_proxy/upstreams 响应超过 %d 字节上限，指标本轮缺失", caddyAdminConfigMaxBytes)
		return result
	}
	var upstreams []map[string]interface{}
	if err := json.Unmarshal(body, &upstreams); err != nil {
		Logf("error", "Failed to decode reverse_proxy/upstreams: %v", err)
		return result
	}

	for _, up := range upstreams {
		// Caddy uses "address" for the upstream key in this endpoint.
		key, ok := up["address"].(string)
		if !ok {
			key, ok = up["dial"].(string)
		}
		if !ok {
			continue
		}

		metric := &upstreamMetric{}

		if numReq, ok := up["num_requests"].(float64); ok {
			metric.NumRequests = int(numReq)
		}

		if fails, ok := up["fails"].(float64); ok {
			metric.Fails = int(fails)
		}

		result[key] = metric
	}

	return result
}

var (
	caddyReverseProxyHealthyMetricPrefix = []byte("caddy_reverse_proxy_upstreams_healthy{")
	caddyLayer4ProxyHealthyMetricPrefix  = []byte("caddy_layer4_proxy_upstream_healthy{")
)

func (s *CaddyService) getUpstreamHealthFromMetrics(ctx context.Context) map[string]bool {
	result := make(map[string]bool)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.metricsURL, nil)
	if err != nil {
		return result
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return result
	}

	// 与 handlers/metrics.go fetchCaddyMetrics 同型——
	// limit+1 探测读取，超 16MB 按读取失败处理（返回空健康表），防指标基数
	// 膨胀时裸 ReadAll 的无界内存分配。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20+1))
	if err != nil || len(body) > 16<<20 {
		return result
	}

	for rawLine := range bytes.Lines(body) {
		if bytes.HasPrefix(rawLine, caddyReverseProxyHealthyMetricPrefix) || bytes.HasPrefix(rawLine, caddyLayer4ProxyHealthyMetricPrefix) {
			line := string(rawLine)
			upstream := ExtractMetricLabel(line, "upstream")
			spaceIdx := strings.LastIndex(line, " ")
			var isHealthy float64
			if spaceIdx > 0 {
				fmt.Sscanf(line[spaceIdx+1:], "%f", &isHealthy)
			}
			if upstream != "" {
				result[upstream] = isHealthy == 1
			}
		}
	}

	// 健康表全量打印降为 debug——该函数被规则指标/总览轮询周期调用，
	// 上游多时单行数 KB，INFO 级放大日志滚动。
	Logf("debug", "Health metrics parsed: %v", result)
	return result
}

// ExtractMetricLabel（LBS/收敛为单源）
// label 键必须以标签边界出现。裸子串匹配会把
// peer_upstream 等前缀兄弟标签的值误归到目标 label。handlers 侧同名叶函数
// extractLabel 已删除并改调本函数（跨包唯一实现）。
func ExtractMetricLabel(metricName string, label string) string {
	start := -1
	for _, boundary := range []string{"," + label + `="`, "{" + label + `="`} {
		if idx := strings.Index(metricName, boundary); idx >= 0 {
			start = idx + len(boundary)
			break
		}
	}
	if start < 0 && strings.HasPrefix(metricName, label+`="`) {
		start = len(label) + 2
	}
	if start < 0 {
		return ""
	}
	end := strings.Index(metricName[start:], `"`)
	if end == -1 {
		return ""
	}
	return metricName[start : start+end]
}

// GenerateCaddyConfig generates Caddy configuration from database
// 渲染链全程只读（Query/QueryRow）；写接口不属于本契约——曾有的 Exec 零调用点，
// 保留只会误导读者以为渲染会写库，并迫使未来替身实现不需要的写方法。
type caddyConfigStore interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

// securityPolicyContext 是生成期批量预载的安全策略状态：每个规则绑定的全部
// 启用策略（policy_id ASC，v2.2.0 多策略绑定，与 GetSecurityPoliciesForRule
// 同口径）以及策略引用的品牌拦截页内容。经与规则/上游同一 store（事务时即 tx）
// 预载，事务内生成可读到未提交的策略变更，替代此前逐规则走全局 db.DB 的 N+1 查询。
type securityPolicyContext struct {
	policyByRule  map[string][]*models.SecurityPolicy
	blockPageByID map[int]string
	// blockPageTypeByID 页 id → （2026-09-25 用户裁定可配置）；
	// 缺失/空值在渲染处回退 text/html; charset=utf-8。
	blockPageTypeByID map[int]string
	// policySynthetic 是拦截页按触发策略归因的合成中断码分配（policy_id →
	// 481+序号）：取全部被任一规则绑定的启用策略中 BlockPageID>0 且页内容
	// 非空者，按 policy_id ASC 分配。按策略身份（非绑定序）使同一策略在所有
	// 规则上同码，错误路由可按策略去重。无有效页的策略不进表（取值 0=不抬
	// 码），避免合成码无路由承接泄漏到客户端。区间上限 599（合法状态码），
	// 超出策略不进表（回落 403 兜底路由）。
	policySynthetic map[int]int
	// store 是预载所用 caddyConfigStore（事务内生成即 tx）
	// BuildCorazaDirectives → resolvePolicyCustomRules 必须沿同一 store 读取
	// security_custom_rules，否则 v2 导入事务内重插的规则在渲染期静默丢失。
	store caddyConfigStore
	// scopedListCache 单次全量生成的 CRS 作用域排除列表引用缓存
	// 键=排序后的 listRefs，避免规则×策略重复读库/整文件。
	scopedListCache scopedCRSListCache
	// securityLibsOK 随上下文一次计算并透传：逐规则重探（ReadDir/WalkDir
	// rules 目录）在千条规则全量渲染下放大为千次探测与千条重复 WARN；且
	// CRS 树交换（RemoveAll→moveTree，不持 CaddyOpLock）与生成并发时逐规则
	// 探测会让同一份配置前后规则得到不同的可用性结论（半链窗口）。
	securityLibsOK bool
	// crsLibOK/ip2regionLibOK 与 securityLibsOK 同一次探测的分解结果——缺失
	// 告警描述直接复用，不再重探目录。
	crsLibOK       bool
	ip2regionLibOK bool
	// securityLibsWarnOnce 库缺失 WARN 每次生成一条（替代逐规则一条）。
	securityLibsWarnOnce sync.Once
	// crsFingerprintOnce/crsFingerprint：CRS 池指纹的渲染批次级缓存——同一轮
	// 全量渲染内 CRS 文件与版本行不会变，逐链求值（每链 1 次 SELECT + 1 次
	// stat）在 R 条有策略的 HTTP 规则下放大为 R 次查询+stat（单次保存最多
	// 3 轮渲染 → 3R）。批次级一次求值后透传，正确性零变化。
	crsFingerprintOnce sync.Once
	crsFingerprint     string
	// crsIndexOnce：本轮生成的 CRS 规则索引惰性求值（首次消费才读目录）。
	// 索引指纹键含 ReadDir+全量 stat+版本查询，逐（规则×策略）重算在
	// 1000 规则 × 2 策略下带来 1~2s 的锁内开销——提到生成上下文后每轮一次。
	// BuildCorazaDirectives 的三个消费点共享同一实例；无选组/无作用域排除时
	// 零触发（惰性）。
	crsIndexOnce func() *CRSRuleIndex
	// allowIntersectionMu/allowIntersection：allow 模式多策略交集按「绑定策略
	// 集合签名」缓存（交集只依赖 allow 策略的身份与名单条目，同一策略集绑定
	// 的多条规则此前各算一遍：64 名单 × 5000 条最坏 2500 万次比较/对）。
	allowIntersectionMu sync.Mutex
	allowIntersection   map[string][]string
}

// crsRuleIndex 返回本生成轮的 CRS 规则索引（上下文缺失时回退全局惰性取值）。
func (ctx *securityPolicyContext) crsRuleIndex() func() *CRSRuleIndex {
	if ctx == nil || ctx.crsIndexOnce == nil {
		return lazyCRSRuleIndex()
	}
	return ctx.crsIndexOnce
}

// allowIntersectionCached 返回 allow 策略集的交集（按签名缓存，命中零计算）。
func (ctx *securityPolicyContext) allowIntersectionCached(signature string, compute func() []string) []string {
	if ctx == nil || signature == "" {
		return compute()
	}
	ctx.allowIntersectionMu.Lock()
	if cached, ok := ctx.allowIntersection[signature]; ok {
		ctx.allowIntersectionMu.Unlock()
		return cached
	}
	ctx.allowIntersectionMu.Unlock()
	result := compute()
	ctx.allowIntersectionMu.Lock()
	if ctx.allowIntersection == nil {
		ctx.allowIntersection = make(map[string][]string)
	}
	ctx.allowIntersection[signature] = result
	ctx.allowIntersectionMu.Unlock()
	return result
}

// securityLibsMissingDesc 返回本批次探测的库缺失描述（无缺失返回空串）。
// 与 securityLibsOK 同源，不重探目录。
func (ctx *securityPolicyContext) securityLibsMissingDesc() string {
	if ctx == nil || ctx.securityLibsOK {
		return ""
	}
	return securityLibrariesMissingDesc(ctx.crsLibOK, ctx.ip2regionLibOK)
}

// crsPoolFingerprintCached 返回本渲染批次的 CRS 池指纹（首次调用时求值并
// 缓存）。仅批量预载上下文（全量渲染）使用；单规则/无上下文路径由调用方
// 自行缓存（见 buildHTTPHandleChain 的 needFingerprint 闭包）。
func (ctx *securityPolicyContext) crsPoolFingerprintCached() string {
	ctx.crsFingerprintOnce.Do(func() {
		ctx.crsFingerprint = crsPoolFingerprint()
	})
	return ctx.crsFingerprint
}

// loadSecurityPolicyContext 一次性查询 security_policy_bindings +
// security_policies（仅启用策略）+ security_block_pages，构建
// ruleCaddyID → 启用策略切片（policy_id ASC）映射与 block_page_id → content
// 映射。查询次数与规则数无关（常数级：最多 3 次 Query）。
// v2.2.0 多策略绑定：与 GetSecurityPoliciesForRule 严格同构——绑定按
// policy_id ASC 全量取出，策略按 id 批量查询并过滤 enabled，逐规则按 ASC
// 顺序收集启用策略（禁用绑定仅占位，不产生元素）。
func loadSecurityPolicyContext(store caddyConfigStore) (*securityPolicyContext, error) {
	// CRS 树交换窗口互斥：窗口内 rules 树可能整体缺失（RemoveAll 后、rename
	// 前）或只拷入一部分（copyDir 回退中断）。前者会让「缺库降级」路径成功
	// 发布一份无安全链的配置，后者探测通过但只匹配到部分 CRS 文件（WAF 静默
	// 弱化）——两种都必须失败，而不是发布降级/弱化配置。
	if crsTreeSwapInFlightNow() {
		return nil, errCRSTreeSwapInFlight
	}
	ctx := &securityPolicyContext{
		policyByRule:      make(map[string][]*models.SecurityPolicy),
		blockPageByID:     make(map[int]string),
		blockPageTypeByID: make(map[int]string),
		policySynthetic:   make(map[int]int),
		store:             store,
		scopedListCache:   make(scopedCRSListCache),
		crsIndexOnce:      lazyCRSRuleIndex(),
	}
	ctx.crsLibOK, ctx.ip2regionLibOK = SecurityLibraryStatus()
	ctx.securityLibsOK = ctx.crsLibOK && ctx.ip2regionLibOK
	bindingRows, err := store.Query(`SELECT rule_caddy_id, policy_id FROM security_policy_bindings ORDER BY rule_caddy_id, policy_id ASC`)
	if err != nil {
		return nil, err
	}
	rulePolicyIDs := make(map[string][]int)
	distinctPolicyIDs := make([]int, 0)
	seenPolicyIDs := make(map[int]struct{})
	for bindingRows.Next() {
		var ruleCaddyID string
		var policyID int
		if err := bindingRows.Scan(&ruleCaddyID, &policyID); err != nil {
			_ = bindingRows.Close()
			return nil, err
		}
		rulePolicyIDs[ruleCaddyID] = append(rulePolicyIDs[ruleCaddyID], policyID)
		if _, seen := seenPolicyIDs[policyID]; !seen {
			seenPolicyIDs[policyID] = struct{}{}
			distinctPolicyIDs = append(distinctPolicyIDs, policyID)
		}
	}
	if err := bindingRows.Err(); err != nil {
		_ = bindingRows.Close()
		return nil, err
	}
	if err := bindingRows.Close(); err != nil {
		return nil, err
	}
	policiesByID := make(map[int]*models.SecurityPolicy, len(distinctPolicyIDs))
	if len(distinctPolicyIDs) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(distinctPolicyIDs)), ",")
		args := make([]interface{}, len(distinctPolicyIDs))
		for i, policyID := range distinctPolicyIDs {
			args[i] = policyID
		}
		rows, err := store.Query(`
			SELECT id, name, COALESCE(description,''), COALESCE(mode,'off'), COALESCE(anomaly_threshold,0),
			       COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_whitelist,'[]'), COALESCE(ip_whitelist_enabled,1), COALESCE(ip_blacklist,'[]'),
			       COALESCE(rate_limit_enabled,0), COALESCE(rate_limit_rps,0), COALESCE(rate_limit_burst,0),
			       COALESCE(crs_rule_groups,'[]'), COALESCE(crs_excluded_rules,'[]'), COALESCE(custom_rules,'[]'),
		COALESCE(block_page_id,0), COALESCE(block_status_code,0), enabled, COALESCE(created_at,''), COALESCE(updated_at,''),
			       COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,'off'), COALESCE(geoip_crawler_exempt,0), COALESCE(geoip_crawler_engines,'[]'), COALESCE(waf_check_response,0), COALESCE(log_request_body,0),
			       COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(policy_type,''), COALESCE(trust_detection,0)
		FROM security_policies WHERE id IN (`+placeholders+`) AND enabled = 1`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var p models.SecurityPolicy
			var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries, crawlerEnginesRaw string
			if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold,
				&p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &ipWhitelist, &p.IPWhitelistEnabled, &ipBlacklist,
				&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst,
				&crsRuleGroups, &crsExcludedRules, &customRules,
				&p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.CreatedAt, &p.UpdatedAt,
				&geoipCountries, &p.GeoIPMode, &p.GeoIPCrawlerExempt, &crawlerEnginesRaw, &p.WAFCheckResponse, &p.LogRequestBody, &p.IPACLListRefs, &p.IPWhitelistRefs, &p.PolicyType, &p.TrustDetection); err != nil {
				_ = rows.Close()
				return nil, err
			}
			p.IPWhitelist = json.RawMessage(ipWhitelist)
			p.IPBlacklist = json.RawMessage(ipBlacklist)
			p.CRSRuleGroups = json.RawMessage(crsRuleGroups)
			p.CRSExcludedRules = json.RawMessage(crsExcludedRules)
			p.CustomRules = json.RawMessage(customRules)
			p.GeoIPCountries = json.RawMessage(geoipCountries)
			p.GeoIPCrawlerEngines = json.RawMessage(crawlerEnginesRaw)
			policiesByID[p.ID] = &p
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		// 引用 IP 列表批量解析（与策略预载同一 store——事务内重插的列表行仅 tx
		// 可见；跨整个批次一次查询，预算与策略数无关），合并集附加到各策略。
		batch := make([]*models.SecurityPolicy, 0, len(policiesByID))
		for _, policy := range policiesByID {
			batch = append(batch, policy)
		}
		resolvePolicyIPListRefs(batch, store)
		// 自定义规则按去重策略在此解析一次（缓存于策略对象），
		// BuildCorazaDirectives 对同策略的多次调用（多规则绑定同策略）零重复查询。
		for _, bp := range batch {
			if bp != nil {
				policyCustomRulesCached(bp, store)
			}
		}
	}
	for ruleCaddyID, policyIDs := range rulePolicyIDs {
		for _, policyID := range policyIDs {
			if policy := policiesByID[policyID]; policy != nil && !policy.IPRefMissing {
				// RDB 严格模式：IPRefMissing 策略（威胁库文件缺失）不参与渲染
				ctx.policyByRule[ruleCaddyID] = append(ctx.policyByRule[ruleCaddyID], policy)
			}
		}
	}
	var referencedPage bool
	for _, policies := range ctx.policyByRule {
		for _, policy := range policies {
			if policy.BlockPageID > 0 {
				referencedPage = true
				break
			}
		}
		if referencedPage {
			break
		}
	}
	if !referencedPage {
		// 阶段拦截页（规则级覆盖层）同样触发页预载——规则配了阶段页但无任何
		// 策略配页时，页内容仍需可用（481/482 阶段路由与抬码判定）。
		if err := store.QueryRow(`SELECT EXISTS(SELECT 1 FROM lb_rules WHERE COALESCE(block_page_stage1_id,0)>0 OR COALESCE(block_page_stage3_id,0)>0)`).Scan(&referencedPage); err != nil {
			return nil, err
		}
	}
	if !referencedPage {
		return ctx, nil
	}
	pageRows, err := store.Query(`SELECT id, COALESCE(content,''), COALESCE(content_type,'') FROM security_block_pages`)
	if err != nil {
		return nil, err
	}
	for pageRows.Next() {
		var id int
		var content, contentType string
		if err := pageRows.Scan(&id, &content, &contentType); err != nil {
			_ = pageRows.Close()
			return nil, err
		}
		ctx.blockPageByID[id] = content
		ctx.blockPageTypeByID[id] = contentType
	}
	if err := pageRows.Err(); err != nil {
		_ = pageRows.Close()
		return nil, err
	}
	if err := pageRows.Close(); err != nil {
		return nil, err
	}
	// 合成中断码按策略身份分配（policySynthetic 字段注释）：遍历去重后的
	// 启用策略（policiesByID 仅含被绑定且 enabled 者），页内容非空才获码；
	// policy_id ASC 保证多次生成同码（路由去重与钉测试确定性前提）。
	syntheticIDs := make([]int, 0, len(policiesByID))
	for policyID, policy := range policiesByID {
		if policy.BlockPageID > 0 && ctx.blockPageByID[policy.BlockPageID] != "" {
			syntheticIDs = append(syntheticIDs, policyID)
		}
	}
	sort.Ints(syntheticIDs)
	for i, policyID := range syntheticIDs {
		if blockPageSyntheticBase+i > blockPageSyntheticMax {
			break
		}
		ctx.policySynthetic[policyID] = blockPageSyntheticBase + i
	}
	return ctx, nil
}

// 拦截页归因合成中断码区间（阶段化模型重排）：阶段码固定 481=阶段 1（IP
// 访问控制+地域拦截预检）、482=阶段 3（WAF）；逐策略合成码 483 起按策略身份
// 递增，上限 599（HTTP 状态码合法区间）。481-599 在标准/常见扩展码中无占用
// （全仓 grep status:48 零冲突），且只出现于 {http.error.status_code} matcher
// 与 coraza status 动作（coraza 对 status 无范围校验，actions/status.go 仅
// Atoi）。规则配了阶段页（id>0 且页内容非空）→ 对应阶段全部 deny 抬阶段码；
// 未配=跟随策略（逐策略 483+ 归因默认层）。
// 容量边界：483..599 ⇒ 最多 117 个「配了非空拦截页」
// 的启用策略可获得逐策略合成码；超出的策略不获码（下方 break），其拦截中断回落
// buildBlockPageErrorRoute 的 403 兜底路由——渲染的是该规则首绑定配置了拦截页
// 的策略页面（可能与实际触发策略不同）。当前规模（策略数十条）不可达；若未来
// 策略数逼近上限，须先扩展码域（如 600+ 段或改归因头）而非依赖兜底。
const (
	blockPageStage1Code    = 481
	blockPageStage3Code    = 482
	blockPageSyntheticBase = 483
	blockPageSyntheticMax  = 599
)

// policiesForRule 返回规则绑定的全部启用安全策略（policy_id ASC）：批量预载
// 上下文存在时查映射，否则回退单规则查询（GenerateSingleRuleCaddyConfig/
// generateHTTPRouteObjects 等非批量路径）。无绑定或全部禁用时返回 nil。
func policiesForRule(ctx *securityPolicyContext, ruleCaddyID string) []*models.SecurityPolicy {
	if ctx != nil {
		return ctx.policyByRule[ruleCaddyID]
	}
	return GetSecurityPoliciesForRule(ruleCaddyID)
}

func GenerateCaddyConfig(overrides ...*models.UpdateConfigRequest) map[string]interface{} {
	return generateCaddyConfigFromStore(db.DB, overrides...)
}

// trustedProxyProjectionScope 是受信代理合并网段投影文件的稳定命名
// （tp.txt，IPListDataDir 下）——受信代理无多实例形态（全局单份），文件名
// 恒定 → 配置字节恒定，内容变化纯走文件热感知。已列入 GC 白名单
// （ipListProjectedFileName），停用 24h 后自然回收。
const trustedProxyProjectionScope = "tp"

// trustedProxyServerFields 渲染受信代理（CDN 真实 IP）的 server 级字段
// （v2.3.x）：enabled=false 时返回 (nil, "")（未启用非降级）；读错/解析失败
// /投影写失败时返回 (nil, 降级说明)——按未启用渲染（fail-closed=不注入，
// 与「未启用」同形——宁可退回 socket IP 也不采信未校验的头），但降级说明
// 随配置图携带落横幅（面板「已启用」与实际渲染分叉必须可见）。
// 启用：内联 ∪ 引用名单合并网段投影到稳定路径文件（2026-10-15 热路径化，
// trustedProxyProjectionScope）+ 发射 trusted_proxies:{source:lb_file,path}
// （http.ip_sources.lb_file 文件源 ≤1s stat 热感知，名单/网段变化零 /load；
// 存量 static 发射面在升级后首次渲染变化 → 一次全量重载自愈，此后配置字节
// 恒定）+ trusted_proxies_strict（1/0 恒输出）+ client_ip_headers（非空才
// 输出，空=仅 X-Forwarded-For）。store 形参保证事务内渲染
// （ApplyConfigFromTx）读到未提交的设置与名单。
func trustedProxyServerFields(store caddyConfigStore) (map[string]interface{}, string) {
	var enabled, strict bool
	var rangesJSON, refsJSON, headersJSON string
	if err := store.QueryRow(`SELECT COALESCE(trusted_proxy_enabled,0), COALESCE(trusted_proxy_ranges,'[]'), COALESCE(trusted_proxy_range_refs,'[]'), COALESCE(trusted_proxy_headers,'[]'), COALESCE(trusted_proxy_strict,1) FROM global_config WHERE id = 1`).
		Scan(&enabled, &rangesJSON, &refsJSON, &headersJSON, &strict); err != nil {
		Logf("error", "读取受信代理设置失败（按未启用渲染）: %v", err)
		return nil, fmt.Sprintf("受信代理设置读取失败，本轮渲染按未启用处理（CDN 真实 IP 还原失效，面板显示的启用态与实际渲染分叉）: %v", err)
	}
	if !enabled {
		return nil, ""
	}
	var ranges, headers []string
	if err := json.Unmarshal([]byte(rangesJSON), &ranges); err != nil {
		Logf("error", "解析受信代理网段失败（按未启用渲染）: %v", err)
		return nil, fmt.Sprintf("受信代理网段配置解析失败，本轮渲染按未启用处理（CDN 真实 IP 还原失效，面板显示的启用态与实际渲染分叉）: %v", err)
	}
	if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		Logf("error", "解析受信代理请求头失败（按未启用渲染）: %v", err)
		return nil, fmt.Sprintf("受信代理请求头配置解析失败，本轮渲染按未启用处理（CDN 真实 IP 还原失效，面板显示的启用态与实际渲染分叉）: %v", err)
	}
	merged, err := expandTrustedProxyRanges(store, ranges, refsJSON)
	if err != nil {
		Logf("error", "展开受信代理引用名单失败（按未启用渲染）: %v", err)
		return nil, fmt.Sprintf("受信代理引用名单展开失败，本轮渲染按未启用处理（CDN 真实 IP 还原失效，面板显示的启用态与实际渲染分叉）: %v", err)
	}
	// 投影热路径化（2026-10-15）：合并网段写入稳定路径文件（writeIPListFile
	// 同族——聚合+原子换名+同字节跳写），发射 lb_file 文件源。内联网段同样
	// 走文件 → 内联修改亦为零 /load 热路径（渲染时重写文件即可）。写失败按
	// 既有降级口径处理（不注入+横幅说明）。
	path, err := writeIPListFile(trustedProxyProjectionScope, merged)
	if err != nil {
		Logf("error", "受信代理网段投影写入失败（按未启用渲染）: %v", err)
		return nil, fmt.Sprintf("受信代理网段投影写入失败，本轮渲染按未启用处理（CDN 真实 IP 还原失效，面板显示的启用态与实际渲染分叉）: %v", err)
	}
	fields := map[string]interface{}{
		"trusted_proxies": map[string]interface{}{
			"source": "lb_file",
			"path":   path,
		},
	}
	if strict {
		fields["trusted_proxies_strict"] = 1
	} else {
		fields["trusted_proxies_strict"] = 0
	}
	if len(headers) > 0 {
		fields["client_ip_headers"] = headers
	}
	return fields, ""
}

// TrustedProxyMinPrefixBits 返回受信代理允许的最小前缀长度（IPv4=/8，
// IPv6=/29）。/29 覆盖 Cloudflare 官方最宽回源段 2a06:98c0::/29；
// 过宽网段会让伪造的头在任意来源被采信。写侧（内联 ranges 与
// 引用名单条目）与渲染侧共用本判据。
func TrustedProxyMinPrefixBits(addr netip.Addr) int {
	if addr.Is6() {
		return 29
	}
	return 8
}

// TrustedProxyPrefixAllSpace 报告前缀是否覆盖全部地址空间（等同信任任意
// 来源）：0.0.0.0/8、0.0.0.0/0、::/0 与 v4-mapped 全零 /96 两种规范写法。
// 曾在内联通道显式拒绝这组形态，引用通道此前漏掉——判据
// 单源后两通道同口径。
func TrustedProxyPrefixAllSpace(prefix netip.Prefix) bool {
	switch prefix.String() {
	case "0.0.0.0/8", "0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96", "::ffff:0:0/96":
		return true
	}
	return false
}

// TrustedProxyPrefixTooWide 是上述两条判据的合取（过宽=全空间或低于最小
// 前缀长度），渲染侧防御带外改库/旧配置时使用。
func TrustedProxyPrefixTooWide(prefix netip.Prefix) bool {
	return TrustedProxyPrefixAllSpace(prefix) || prefix.Bits() < TrustedProxyMinPrefixBits(prefix.Addr())
}

// expandTrustedProxyRanges 合并内联网段与引用名单条目（2026-10-12；2026-10-15
// 起消费方=受信代理投影文件 tp.txt，不再内联进配置本体）：refs 按 id 经
// loadIPListEntriesVia 装载（system=1 读 .iplist 文件、自定义读 DB entries
// ——与策略 refs 同一装载通道）；内联在前、引用按 refs 出现顺序追加；跨来源
// 按规范前缀去重（裸 IP 补 /32 //128）；逐条经 CIDR 校验，非法条目跳过并
// 留痕（名单写侧已过 validIPOrCIDR，此处仅防御带外改库/导入残留）。悬空引用
// （名单不存在）贡献零条目——保存侧存在性门与删除守卫保证常规路径不产生；
// 装载失败整体 fail-closed 上抛（调用方按未启用渲染，宁可退回 socket IP）。
func expandTrustedProxyRanges(store caddyConfigStore, inline []string, refsJSON string) ([]string, error) {
	refIDs := parseIPListRefs(refsJSON)
	if strings.TrimSpace(refsJSON) != "" && refIDs == nil {
		// 非空但解析不出 id：畸形 JSON 或全非整数条目（带外改库形态）。
		return nil, fmt.Errorf("trusted_proxy_range_refs 畸形: %q", refsJSON)
	}
	merged := make([]string, 0, len(inline))
	seen := make(map[string]struct{}, len(inline))
	appendCIDR := func(value string) {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			addr, addrErr := netip.ParseAddr(strings.TrimSpace(value))
			if addrErr != nil {
				Logf("warn", "受信代理引用条目 %q 不是有效 IP/CIDR（跳过）", value)
				return
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefix = netip.PrefixFrom(addr, bits)
		}
		if _, dup := seen[prefix.String()]; dup {
			return
		}
		// 防御复检：写侧两通道（内联/引用）都已拒绝过宽网段，此处
		// 覆盖带外改库与旧版本残留配置——过宽网段会让伪造头在任意来源被采信，
		// 宁可跳过并留痕（运行配置缺该来源 = 退回 socket IP，偏安全侧）。
		if TrustedProxyPrefixTooWide(prefix) {
			Logf("warn", "受信代理条目 %q 过宽（最小 /8（IPv4）与 /29（IPv6），且不得覆盖全部地址空间，跳过）", value)
			return
		}
		seen[prefix.String()] = struct{}{}
		merged = append(merged, prefix.String())
	}
	for _, entry := range inline {
		appendCIDR(entry)
	}
	if len(refIDs) == 0 {
		return merged, nil
	}
	entriesByID, _, err := loadIPListEntriesVia(store, refIDs)
	if err != nil {
		return nil, err
	}
	for _, id := range refIDs {
		entries, ok := entriesByID[id]
		if !ok {
			Logf("warn", "受信代理引用的地址列表 #%d 不存在（贡献零条目）", id)
			continue
		}
		for _, entry := range entries {
			appendCIDR(entry)
		}
	}
	return merged, nil
}

// mergeTrustedProxyServerFields 把受信代理字段并入每个 HTTP server 条目
// （含 :80 默认站）；layer4/admin 不在此函数视野内，天然不注入。
// 产出为共享实例（fields 同一份 map 经 maps.Copy 逐键并入各 server，
// 值内嵌套结构仍被多 server 共享引用）——消费方禁变异，如需改动须先深拷贝。
// 返回渲染降级说明，调用方随配置图携带。
func mergeTrustedProxyServerFields(servers map[string]interface{}, store caddyConfigStore) string {
	fields, degraded := trustedProxyServerFields(store)
	if len(fields) == 0 {
		return degraded
	}
	for _, serverVal := range servers {
		if srv, ok := serverVal.(map[string]interface{}); ok {
			maps.Copy(srv, fields)
		}
	}
	return degraded
}

// acmeCertCandidatesQuery 只取「启用 + TLS + acme_dns」规则名下未禁用任务的
// 证书候选（与 db 迁移的 legacyHTTPSHasCertPredicate 及 selectCertificate 的
// 跳过口径同源）。前为全库全量拉取：已删除规则的残留行、disabled 任务与
// 非 acme 规则的历史 PEM 都会在每次全量生成时载入内存，而后置消费方
// （resolveACMECert 仅按 allRules 中 acme_dns 规则查表、selectCertificate
// 跳过 disabled）根本不会使用这些行——过滤前移只减 IO/内存，不改变候选集语义。
// var（非 const）：谓词由 CertJobMaterialPredicateSQL（带 alias 的函数）单源
// 生成——本查询在包初始化时求值一次。
var acmeCertCandidatesQuery = `
	SELECT rule_id, id, domain, status, cert_pem, key_pem,
	       COALESCE(julianday(COALESCE(updated_at, created_at)), 0)
	FROM cert_jobs
	WHERE ` + CertJobMaterialPredicateSQL("") + `
	  AND rule_id IN (SELECT caddy_id FROM lb_rules WHERE enabled = 1 AND enable_tls = 1 AND tls_source = 'acme_dns')
	ORDER BY updated_at DESC, id DESC
`

// generateCaddyConfigFromStore 以已提交连接（db.DB）为证书候选源渲染配置（.1
// 默认语义）；规则/安全段读传入 store。兼容包装：等价于 rulesWrittenInTx=true
// （保守补查，与历史行为一致）——生产路径应改用带显式门控的入口（见下）。
func generateCaddyConfigFromStore(store caddyConfigStore, overrides ...*models.UpdateConfigRequest) map[string]interface{} {
	return generateCaddyConfigWithCertSource(store, db.DB, true, overrides...)
}

// generateCaddyConfigWithCertSource 渲染配置，证书候选源可指定
//
//	certSource=db.DB（默认）：.1 防护——UpdateConfig 类纯 global_config 事务
//	  的 tx 视角对 cert_jobs 纯陈旧性，已提交连接恒见最新证书。
//	- certSource=tx（ApplyConfigFromTxCertAwareForce，v2 导入专用）：导入事务全量
//	  deleteOrder+重插 cert_jobs（restoreTable 保留原 id，PEM 可更新），已提交
//	  视图会返回将被替换的旧行——MaterializeCertPairs 用旧 PEM 覆写
//	  materializeImportCertificates 刚写入的新文件，DB=新证/磁盘=旧证静默分叉。
//
// rulesWrittenInTx 是「谓词 miss 补查」的显式门控：true=调用方事务写过
// lb_rules（UpdateRule 切 acme/EnableRule/导入），store 的规则视图与 certSource
// 已提交视图可能分叉，需要 per-rule 补查；false=事务未触碰 lb_rules
// （UpdateConfig/名单-only 等），主候选查询在 certSource 视图已完备，补查是
// 纯冗余（此前粗门 certSource!=store 让 UpdateConfig 形态每轮渲染为每条
// 无候选 acme 规则空跑一次 SELECT，单次保存最多 3 轮 → 3N）。
//
// 导入期 CA 队列已 PauseAndDrain，无并发证书提交，tx 视图即最新真相。
func generateCaddyConfigWithCertSource(store, certSource caddyConfigStore, rulesWrittenInTx bool, overrides ...*models.UpdateConfigRequest) map[string]interface{} {
	var filesSnapshot CertFilesSnapshot
	generationFailure := func(format string, args ...any) map[string]interface{} {
		err := fmt.Errorf(format, args...)
		Logf("error", "Caddy 配置生成失败；状态：旧配置已保留（启动期则未加载）：%v", err)
		if filesSnapshot != nil {
			err = errors.Join(err, RestoreCertFiles(filesSnapshot))
			filesSnapshot = nil
		}
		return map[string]interface{}{caddyConfigGenerationErrorKey: err.Error()}
	}

	type lbRule struct {
		CaddyID                       string
		Name                          string
		Protocol                      string
		Domain                        string
		ListenPort                    int
		Strategy                      string
		DynamicDNS                    bool
		EnableDnsServer               bool
		DnsServer                     string
		DnsFamily                     string
		HealthCheckPath               string
		HealthCheckInterval           int
		HealthCheckTimeout            int
		HealthCheckUnhealthyThreshold int
		HealthCheckHealthyThreshold   int
		EnableTLS                     bool
		TLSSource                     string
		TLSCert                       string
		TLSKey                        string
		TLSHTTPRedirect               bool
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		TCPHealthCheckPort            int
		TCPProxyProtocol              bool
		TCPTryDuration                int
		TCPTryInterval                int
		RequestBodyMaxSizeMB          int
		UpstreamKeepaliveTimeout      int
		ServerTokensHidden            int
		NTLMCompatible                int
		UpstreamForceHTTP1            int
		CustomRoutesEnabled           bool
		ProxyDialTimeout              int
		ProxyResponseHeaderTimeout    int
		ProxyReadTimeout              int
		ProxyWriteTimeout             int
		ProxyStreamTimeout            int
		ProxyFlushInterval            int
		ProxyStreamCloseDelay         int
		PathRules                     []PathRuleConfig
		HostHeader                    string
		HealthCheckHost               string
		LogEnabled                    bool
		BlockPageStage1ID             int
		BlockPageStage1Status         int
		BlockPageStage3ID             int
		BlockPageStage3Status         int
	}

	type upstream struct {
		Host           string
		Port           int
		Weight         int
		Enabled        bool
		Protocol       string
		MaxConnections int
		OriginDomain   string
	}

	type ruleWithUpstreams struct {
		rule      lbRule
		upstreams []upstream
	}

	// lb_rules.id 为可空遗留列（生产形态恒 NULL），ORDER BY id 语义
	// 退化；rowid 显式化——行为与现状等价（NULL 排序实践上即 rowid 序）。
	// Load all enabled rules into memory first to avoid holding cursor while querying upstreams/global_config
	rows, err := store.Query(`
		SELECT COALESCE(caddy_id,''), name, protocol, COALESCE(domain,''), listen_port, COALESCE(strategy,'weighted_round_robin'),
		       IIF(dynamic_dns IN ('1',1),1,0), IIF(enable_dns_server IN ('1',1),1,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       COALESCE(health_check_path,''), health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       IIF(enable_tls IN ('1',1),1,0), COALESCE(tls_source,'manual'), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       IIF(tls_http_redirect IN ('1',1),1,0),
		       IIF(enable_compress IN ('1',1),1,0), COALESCE(compress_types,'gzip'),
		       IIF(enable_active_health_check IN ('1',1),1,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), tcp_try_interval,
	       COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0), COALESCE(ntlm_compatible,0), COALESCE(upstream_force_http1,0), COALESCE(host_header,''), COALESCE(health_check_host,''),
		       IIF(log_enabled IN ('1',1),1,0), IIF(custom_routes_enabled IN ('1',1),1,0),
		       COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
		       COALESCE(block_page_stage1_id,0), COALESCE(block_page_stage1_status,0), COALESCE(block_page_stage3_id,0), COALESCE(block_page_stage3_status,0)
		FROM lb_rules WHERE enabled = 1
		ORDER BY rowid
	`)
	if err != nil {
		return generationFailure("query enabled rules: %v", err)
	}

	var allRules []ruleWithUpstreams
	for rows.Next() {
		var r lbRule
		err := rows.Scan(&r.CaddyID, &r.Name, &r.Protocol, &r.Domain, &r.ListenPort, &r.Strategy,
			&r.DynamicDNS, &r.EnableDnsServer, &r.DnsServer, &r.DnsFamily, &r.HealthCheckPath, &r.HealthCheckInterval,
			&r.HealthCheckTimeout, &r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
			&r.EnableTLS, &r.TLSSource, &r.TLSCert, &r.TLSKey,
			&r.TLSHTTPRedirect, &r.EnableCompress, &r.CompressTypes,
			&r.EnableActiveHealthCheck, &r.TCPHealthCheckPort, &r.TCPProxyProtocol, &r.TCPTryDuration, &r.TCPTryInterval,
			&r.RequestBodyMaxSizeMB, &r.UpstreamKeepaliveTimeout, &r.ServerTokensHidden, &r.NTLMCompatible, &r.UpstreamForceHTTP1, &r.HostHeader, &r.HealthCheckHost, &r.LogEnabled,
			&r.CustomRoutesEnabled, &r.ProxyDialTimeout, &r.ProxyResponseHeaderTimeout,
			&r.ProxyReadTimeout, &r.ProxyWriteTimeout, &r.ProxyStreamTimeout, &r.ProxyFlushInterval, &r.ProxyStreamCloseDelay,
			&r.BlockPageStage1ID, &r.BlockPageStage1Status, &r.BlockPageStage3ID, &r.BlockPageStage3Status)

		if err != nil {
			closeErr := rows.Close()
			return generationFailure("scan enabled rule: %v", errors.Join(err, closeErr))
		}

		if r.Strategy == "" {
			r.Strategy = "weighted_round_robin"
		}

		allRules = append(allRules, ruleWithUpstreams{rule: r})
	}
	if err := rows.Err(); err != nil {
		closeErr := rows.Close()
		return generationFailure("iterate enabled rules: %v", errors.Join(err, closeErr))
	}
	if err := rows.Close(); err != nil {
		return generationFailure("close enabled rules: %v", err)
	}

	rulesByID := make(map[string]*ruleWithUpstreams, len(allRules))
	hasCustomRoutes := false
	hasACMETLS := false
	for i := range allRules {
		rulesByID[allRules[i].rule.CaddyID] = &allRules[i]
		hasCustomRoutes = hasCustomRoutes || allRules[i].rule.CustomRoutesEnabled
		hasACMETLS = hasACMETLS || (allRules[i].rule.EnableTLS && allRules[i].rule.TLSSource == "acme_dns")
	}

	upstreamRows, err := store.Query(`
		SELECT u.rule_id, u.host, u.port, COALESCE(u.weight,1), ` + UpstreamEnabledSQLValue + `, COALESCE(u.protocol,'http'), COALESCE(u.max_connections,0), COALESCE(u.origin_domain,'')
		FROM upstreams u JOIN lb_rules r ON r.caddy_id = u.rule_id
		WHERE ` + UpstreamEnabledSQLPredicate + ` AND r.enabled = 1 ORDER BY u.rule_id, u.id
	`)
	if err != nil {
		return generationFailure("query enabled upstreams: %v", err)
	}
	for upstreamRows.Next() {
		var ruleID string
		var u upstream
		if err := upstreamRows.Scan(&ruleID, &u.Host, &u.Port, &u.Weight, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.OriginDomain); err != nil {
			closeErr := upstreamRows.Close()
			return generationFailure("scan upstream: %v", errors.Join(err, closeErr))
		}
		if r := rulesByID[ruleID]; r != nil {
			r.upstreams = append(r.upstreams, u)
		}
	}
	if err := upstreamRows.Err(); err != nil {
		closeErr := upstreamRows.Close()
		return generationFailure("iterate enabled upstreams: %v", errors.Join(err, closeErr))
	}
	if err := upstreamRows.Close(); err != nil {
		return generationFailure("close enabled upstreams: %v", err)
	}

	if hasCustomRoutes {
		pathRows, pathErr := store.Query(`
		SELECT p.rule_id, p.sort_order, p.match_type, p.path, p.upstream_path, p.upstreams_json, p.response_mode, p.response_status, p.response_body, p.response_content_type, p.redirect_to
			FROM path_rules p JOIN lb_rules r ON r.caddy_id = p.rule_id
			WHERE r.enabled = 1 AND r.custom_routes_enabled = 1
			ORDER BY p.rule_id, p.sort_order, p.id
		`)
		if pathErr != nil {
			return generationFailure("query path rules: %v", pathErr)
		}
		for pathRows.Next() {
			var ruleID string
			var pathRule PathRuleConfig
			var upstreamsJSON sql.NullString
			if scanErr := pathRows.Scan(&ruleID, &pathRule.SortOrder, &pathRule.MatchType, &pathRule.Path, &pathRule.UpstreamPath, &upstreamsJSON,
				&pathRule.ResponseMode, &pathRule.ResponseStatus, &pathRule.ResponseBody, &pathRule.ResponseContentType, &pathRule.RedirectTo); scanErr != nil {
				closeErr := pathRows.Close()
				return generationFailure("scan path rule: %v", errors.Join(scanErr, closeErr))
			}
			r := rulesByID[ruleID]
			if r == nil || !r.rule.CustomRoutesEnabled {
				continue
			}
			if upstreamsJSON.Valid {
				pathUpstreams, unmarshalErr := decodePathUpstreams(upstreamsJSON.String)
				if unmarshalErr != nil {
					closeErr := pathRows.Close()
					return generationFailure("decode path upstreams for rule %s: %v", ruleID, errors.Join(unmarshalErr, closeErr))
				}
				pathRule.Upstreams = pathUpstreams
			}
			r.rule.PathRules = append(r.rule.PathRules, pathRule)
		}
		if err := pathRows.Err(); err != nil {
			closeErr := pathRows.Close()
			return generationFailure("iterate path rules: %v", errors.Join(err, closeErr))
		}
		if err := pathRows.Close(); err != nil {
			return generationFailure("close path rules: %v", err)
		}
	}

	acmeCerts := make(map[string][]CertificateCandidate)
	if hasACMETLS {
		// .1：证书候选固定走已提交连接（db.DB）而非传入 store——UpdateConfig 的
		// ApplyConfigFromTx 会把 global_config 事务传入此处，该事务不写 cert_jobs，
		// tx 视角对证书零信息增益、纯陈旧性：在途 ACME 部署（certissuer 不持 caddyOpMu，
		// transitionJob 独立连接提交新证书）若在 tx 快照固定后落库，本查询经 tx 会读到
		// 旧 PEM，MaterializeCertPairs 内容比对 miss 即用旧证书覆写磁盘新证书——
		// DB=issued 新证、磁盘/Caddy=旧证的静默分叉（reconcile 只查存在不查内容），
		// 持续到下次 apply/重启。规则/安全段仍走 store（规则 CRUD 全程持 caddyOpMu，
		// 与 UpdateConfig 互斥，无并发写入可见性；安全段有意读 tx 内未提交状态）。
		certRows, certErr := certSource.Query(acmeCertCandidatesQuery)
		if certErr != nil {
			return generationFailure("读取 ACME 证书阶段查询失败: %v", certErr)
		}
		for certRows.Next() {
			var ruleID string
			var candidate CertificateCandidate
			if scanErr := certRows.Scan(&ruleID, &candidate.ID, &candidate.Domain, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt); scanErr != nil {
				closeErr := certRows.Close()
				return generationFailure("读取 ACME 证书阶段解析失败: %v", errors.Join(scanErr, closeErr))
			}
			// 装载阶段统一预解析（disabled 候选由 selectCertificate
			// 直接跳过，无需付解析成本），选择/后续复用走 Leaf 快路径。
			if candidate.Status != "disabled" {
				candidate.Leaf = ParseCertificateLeaf(candidate.CertPEM, candidate.KeyPEM)
			}
			acmeCerts[ruleID] = append(acmeCerts[ruleID], candidate)
		}
		if rowsErr := certRows.Err(); rowsErr != nil {
			closeErr := certRows.Close()
			return generationFailure("读取 ACME 证书阶段遍历失败: %v", errors.Join(rowsErr, closeErr))
		}
		if closeErr := certRows.Close(); closeErr != nil {
			return generationFailure("读取 ACME 证书阶段关闭结果集失败: %v", closeErr)
		}
		// （谓词 miss 补查）：主候选查询的 lb_rules 子查询在 certSource 的
		// 视图上执行——tx 渲染路径中，事务对 lb_rules 的写入（UpdateRule 切换
		// tls_source manual→acme_dns、EnableRule 置 enabled=1、导入插入新规则）使
		// allRules（tx 视图）含 acme 规则而已提交视图的子查询将其排除，候选为空，
		// 该规则按无证书渲染（TLS 静默丢失）。此时经 store（tx）做无子查询的
		// per-rule 补查——补查读的是事务视图（修正、校正举例：tx 内
		// 写 cert_jobs 的调用点是 DisableRule 置 disabled、DeleteRule 删行、
		// UpdateRule tcp 切换删除；UpdateRule 域名迁移的证书 UPDATE 在 commit 后
		// 独立 certTx。对 tx 内写者，事务视图恰是渲染目标状态，行为正确）；
		// selectCertificate 仍按 status 过滤 disabled。
		// 门控显式化：补查仅当调用方声明 rulesWrittenInTx（事务写过 lb_rules，
		// 规则视图与 certSource 已提交视图可能分叉）时执行；UpdateConfig（tx 只写
		// global_config）、名单-only 热路径等形态传 false——两视图恒一致，
		// 主查询已完备，不再为每个无候选 acme 规则空跑 per-rule 查询。
		// CertAware 路径 certSource==store（主查询已完备），门控同样不触发。
		if rulesWrittenInTx && certSource != store {
			for _, ru := range allRules {
				r := ru.rule
				if !r.EnableTLS || r.TLSSource != "acme_dns" || len(acmeCerts[r.CaddyID]) > 0 {
					continue
				}
				acmeCerts[r.CaddyID] = acmeCertCandidatesForRule(store, r.CaddyID)
			}
		}
	}
	selectionNow := time.Now()
	resolveACMECert := func(ruleID, domain string) (CertMaterial, bool) {
		selected, ok := selectCertificate(acmeCerts[ruleID], domain, selectionNow)
		if ok {
			return CertMaterial{RuleID: ruleID, CertPEM: selected.Candidate.CertPEM, KeyPEM: selected.Candidate.KeyPEM}, true
		}
		return CertMaterial{}, false
	}

	availableCerts := make(map[string]CertMaterial)
	materials := make([]CertMaterial, 0)
	for _, ru := range allRules {
		r := ru.rule
		// 与发布门（下方 isTCP/TLS 策略段）同判据：TCP/layer4 规则不能终止
		// TLS，写侧/迁移/导入已把 TCP 的 TLS 字段归零；带外保留 enable_tls 的
		// TCP 行不得在此物化私钥文件（纵深防御，不是功能判据）。
		if r.Protocol != "http" || !r.EnableTLS {
			continue
		}
		if r.TLSSource == "manual" && r.TLSCert != "" && r.TLSKey != "" {
			material := CertMaterial{RuleID: r.CaddyID, CertPEM: r.TLSCert, KeyPEM: r.TLSKey}
			availableCerts[r.CaddyID] = material
			materials = append(materials, material)
			continue
		}
		if r.TLSSource == "acme_dns" {
			material, available := resolveACMECert(r.CaddyID, r.Domain)
			if available {
				availableCerts[r.CaddyID] = material
				materials = append(materials, material)
			}
		}
	}
	if len(materials) > 0 {
		filesSnapshot, err = MaterializeCertPairs(materials)
		if err != nil {
			return generationFailure("materialize certificate files: %v", err)
		}
	}

	var caddyLogLevel string
	var caddyLogSizeMB int
	var accessLogJSON bool
	var accessLogFormat string
	var global struct {
		requestBodyMaxSizeMB, httpReadTimeout, httpWriteTimeout, httpIdleTimeout, upstreamKeepaliveTimeout    int
		proxyDialTimeout, proxyResponseHeaderTimeout, proxyReadTimeout, proxyWriteTimeout, proxyStreamTimeout int
		proxyFlushInterval, proxyStreamCloseDelay                                                             int
		serverTokensHidden                                                                                    bool
	}
	// dns_provider/acme_email 不参与 Caddy 渲染（签发链路 certissuer 侧
	// 独立消费），渲染侧不再读列也不再接受 overrides 覆写——原读取+覆写后零消费
	// 是死链，会让读者误判「改这两项会触发渲染」。
	if err := store.QueryRow(`
		SELECT COALESCE(caddy_log_level,'info'), caddy_log_size_mb,
		       request_body_max_size_mb, http_read_timeout, http_write_timeout,
		       http_idle_timeout, COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,FALSE),
		       COALESCE(access_log_json,TRUE), COALESCE(access_log_format,''), COALESCE(proxy_dial_timeout,0),
		       COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0)
		FROM global_config WHERE id = 1
	`).Scan(&caddyLogLevel, &caddyLogSizeMB,
		&global.requestBodyMaxSizeMB, &global.httpReadTimeout, &global.httpWriteTimeout, &global.httpIdleTimeout,
		&global.upstreamKeepaliveTimeout, &global.serverTokensHidden, &accessLogJSON, &accessLogFormat,
		&global.proxyDialTimeout, &global.proxyResponseHeaderTimeout, &global.proxyReadTimeout, &global.proxyWriteTimeout,
		&global.proxyStreamTimeout, &global.proxyFlushInterval, &global.proxyStreamCloseDelay); err != nil {
		// 库值唯一真相（批 1+2）：类型①值型列（caddy_log_size_mb/request_body/
		// http 三超时）直读——NOT NULL DEFAULT+每启动回填报证 NULL/无效不可达；
		// 扫描失败（含 NULL）即渲染失败显性暴露，不再 COALESCE 数值默认掩盖。
		return generationFailure("load global config: %v", err)
	}

	// 安全策略经同一 store 批量预载（常数级查询），替代逐规则走
	// 全局 db.DB 的 N+1——事务内生成（ApplyConfigFromTx）由此读到未提交的策略。
	securityCtx, err := loadSecurityPolicyContext(store)
	if err != nil {
		return generationFailure("preload security policy context: %v", err)
	}

	if len(overrides) > 0 && overrides[0] != nil {
		o := overrides[0]
		if o.CaddyLogLevel != nil {
			caddyLogLevel = *o.CaddyLogLevel
		}
		if o.CaddyLogSizeMB != nil {
			caddyLogSizeMB = *o.CaddyLogSizeMB
		}
		if o.RequestBodyMaxSizeMB != nil {
			global.requestBodyMaxSizeMB = *o.RequestBodyMaxSizeMB
		}
		if o.HTTPReadTimeout != nil {
			global.httpReadTimeout = *o.HTTPReadTimeout
		}
		if o.HTTPWriteTimeout != nil {
			global.httpWriteTimeout = *o.HTTPWriteTimeout
		}
		if o.HTTPIdleTimeout != nil {
			global.httpIdleTimeout = *o.HTTPIdleTimeout
		}
		if o.UpstreamKeepaliveTimeout != nil {
			global.upstreamKeepaliveTimeout = *o.UpstreamKeepaliveTimeout
		}
		if o.ProxyDialTimeout != nil {
			global.proxyDialTimeout = *o.ProxyDialTimeout
		}
		if o.ProxyResponseHeaderTimeout != nil {
			global.proxyResponseHeaderTimeout = *o.ProxyResponseHeaderTimeout
		}
		if o.ProxyReadTimeout != nil {
			global.proxyReadTimeout = *o.ProxyReadTimeout
		}
		if o.ProxyWriteTimeout != nil {
			global.proxyWriteTimeout = *o.ProxyWriteTimeout
		}
		if o.ProxyStreamTimeout != nil {
			global.proxyStreamTimeout = *o.ProxyStreamTimeout
		}
		if o.ProxyFlushInterval != nil {
			global.proxyFlushInterval = *o.ProxyFlushInterval
		}
		if o.ProxyStreamCloseDelay != nil {
			global.proxyStreamCloseDelay = *o.ProxyStreamCloseDelay
		}
		if o.ServerTokensHidden != nil {
			global.serverTokensHidden = *o.ServerTokensHidden
		}
		if o.AccessLogJSON != nil {
			accessLogJSON = *o.AccessLogJSON
		}
		if o.AccessLogFormat != nil {
			accessLogFormat = *o.AccessLogFormat
		}
	}

	// 库值唯一真相（批 1+2）：http_read/write/idle_timeout 为类型①值型列——
	// 渲染直读无条件发射（原「>0 才发射」的省略形态废除：0 已非合法库值），
	// <=0 返回错误使配置生成失败（fail-visible）。
	applyTimeouts := func(server map[string]interface{}) error {
		if global.httpReadTimeout <= 0 {
			return fmt.Errorf("全局读取超时无效（http_read_timeout=%d <=0）", global.httpReadTimeout)
		}
		if global.httpWriteTimeout <= 0 {
			return fmt.Errorf("全局写入超时无效（http_write_timeout=%d <=0）", global.httpWriteTimeout)
		}
		if global.httpIdleTimeout <= 0 {
			return fmt.Errorf("全局空闲超时无效（http_idle_timeout=%d <=0）", global.httpIdleTimeout)
		}
		server["read_timeout"] = fmt.Sprintf("%ds", global.httpReadTimeout)
		server["write_timeout"] = fmt.Sprintf("%ds", global.httpWriteTimeout)
		server["idle_timeout"] = fmt.Sprintf("%ds", global.httpIdleTimeout)
		return nil
	}

	servers := make(map[string]interface{})

	httpServersByPort := make(map[int][]ruleWithUpstreams)
	tcpServersByPort := make(map[int][]ruleWithUpstreams)
	// 发布集与按端口分组在同一遍历内收集（allRules/rowid 序）——此前在
	// logger_names 构建处再由 httpServersByPort（map 遍历）重建：多一次全量
	// 拷贝，且顺序来源依赖 map。消费面（按端口分组 + map 键）当前不依赖
	// 跨端口序，但顺序确定化是不变量，避免未来消费方引入「随 map 序漂移」。
	publishedHTTPRules := make([]ruleWithUpstreams, 0, len(allRules))

	for _, ru := range allRules {
		r := ru.rule
		ups := ru.upstreams

		// 同族收敛：全量路径与单规则路径共用 http/tcp 白名单，
		// 带外 https/udp 等脏值不得被静默暴露成原始 TCP 代理。
		if r.Protocol != "http" && r.Protocol != "tcp" {
			return generationFailure("rule %s: unsupported protocol: %s", r.CaddyID, r.Protocol)
		}

		// dial 值零消费(仅判空)——改计数器,免每启用
		// 上游一次 JoinHostPort+append 的渲染热路径分配。
		enabledUpstreamCount := 0
		for _, u := range ups {
			if u.Enabled {
				enabledUpstreamCount++
			}
		}

		if enabledUpstreamCount == 0 {
			// 发布谓词 publishableRulesSQLPredicate 的 Go 侧同义层（零启用上游
			// 不发布）——看门狗期望集按同一谓词收窄，两侧判定必须恒等。
			Logf("warn", "规则 %s 没有可用的启用上游，已跳过该规则", r.CaddyID)
			continue
		}

		// TLS 规则在证书就绪前不得发布——TLS 连接策略只对
		// availableCerts 命中的规则生成，而 server 仍按端口创建且
		// automatic_https.disable=true：无证书的同端口 server 会以明文监听器
		// 对外提供该规则的后端转发（ACME 首签窗口，签发失败时持续）。证书
		// 物化后 certissuer 的 caddyReloader（强制全量重载）重新渲染并发布；
		// 在此之前整条规则 fail-closed 不产生路由（端口有其他就绪规则时仅缺
		// 本规则路由，未匹配请求不会落到后端）。单规则预览路径不受影响。
		if r.Protocol == "http" && r.EnableTLS {
			if _, ready := availableCerts[r.CaddyID]; !ready {
				Logf("warn", "规则 %s 启用 TLS 但证书尚未就绪（tls_source=%s），暂不发布该规则以避免明文降级；证书就绪后自动重载", r.CaddyID, r.TLSSource)
				continue
			}
		}

		if r.Protocol == "http" {
			httpServersByPort[r.ListenPort] = append(httpServersByPort[r.ListenPort], ru)
			publishedHTTPRules = append(publishedHTTPRules, ru)
		} else {
			tcpServersByPort[r.ListenPort] = append(tcpServersByPort[r.ListenPort], ru)
		}
	}

	for port, rules := range httpServersByPort {
		server := map[string]interface{}{
			"listen": []string{fmt.Sprintf(":%d", port)},
		}
		if err := applyTimeouts(server); err != nil {
			return generationFailure("%v", err)
		}

		var routes []interface{}

		for _, ru := range rules {
			r := ru.rule
			ups := ru.upstreams

			ruleConfig := SingleRuleConfig{
				CaddyID:                        r.CaddyID,
				Protocol:                       r.Protocol,
				Domain:                         r.Domain,
				ListenPort:                     r.ListenPort,
				Strategy:                       r.Strategy,
				DynamicDNS:                     r.DynamicDNS,
				EnableDnsServer:                r.EnableDnsServer,
				DnsServer:                      r.DnsServer,
				DnsFamily:                      r.DnsFamily,
				HealthCheckPath:                r.HealthCheckPath,
				HealthCheckInterval:            r.HealthCheckInterval,
				HealthCheckTimeout:             r.HealthCheckTimeout,
				HealthCheckUnhealthyThreshold:  r.HealthCheckUnhealthyThreshold,
				HealthCheckHealthyThreshold:    r.HealthCheckHealthyThreshold,
				TLSHTTPRedirect:                r.TLSHTTPRedirect,
				EnableCompress:                 r.EnableCompress,
				CompressTypes:                  r.CompressTypes,
				EnableActiveHealthCheck:        r.EnableActiveHealthCheck,
				HostHeader:                     r.HostHeader,
				HealthCheckHost:                r.HealthCheckHost,
				RequestBodyMaxSizeMB:           r.RequestBodyMaxSizeMB,
				UpstreamKeepaliveTimeout:       r.UpstreamKeepaliveTimeout,
				ServerTokensHidden:             r.ServerTokensHidden,
				NTLMCompatible:                 r.NTLMCompatible,
				UpstreamForceHTTP1:             r.UpstreamForceHTTP1,
				TCPTryDuration:                 r.TCPTryDuration,
				TCPTryInterval:                 r.TCPTryInterval,
				GlobalUpstreamKeepaliveTimeout: global.upstreamKeepaliveTimeout,
				GlobalServerTokensHidden:       global.serverTokensHidden,
				// 修复（2026-10-14 用户报告）：全局请求体大小此前漏填——
				// resolveRuleOverrides 恒读 0 → 兜底 128，用户设置从未生效。
				GlobalRequestBodyMaxSizeMB:       global.requestBodyMaxSizeMB,
				CustomRoutesEnabled:              r.CustomRoutesEnabled,
				PathRules:                        r.PathRules,
				ProxyDialTimeout:                 r.ProxyDialTimeout,
				ProxyResponseHeaderTimeout:       r.ProxyResponseHeaderTimeout,
				ProxyReadTimeout:                 r.ProxyReadTimeout,
				ProxyWriteTimeout:                r.ProxyWriteTimeout,
				ProxyStreamTimeout:               r.ProxyStreamTimeout,
				ProxyFlushInterval:               r.ProxyFlushInterval,
				ProxyStreamCloseDelay:            r.ProxyStreamCloseDelay,
				GlobalProxyDialTimeout:           global.proxyDialTimeout,
				GlobalProxyResponseHeaderTimeout: global.proxyResponseHeaderTimeout,
				GlobalProxyReadTimeout:           global.proxyReadTimeout,
				GlobalProxyWriteTimeout:          global.proxyWriteTimeout,
				GlobalProxyStreamTimeout:         global.proxyStreamTimeout,
				GlobalProxyFlushInterval:         global.proxyFlushInterval,
				GlobalProxyStreamCloseDelay:      global.proxyStreamCloseDelay,
				BlockPageStage1ID:                r.BlockPageStage1ID,
				BlockPageStage1Status:            r.BlockPageStage1Status,
				BlockPageStage3ID:                r.BlockPageStage3ID,
				BlockPageStage3Status:            r.BlockPageStage3Status,
			}
			for _, u := range ups {
				if u.Enabled {
					// 分组层 weight==0→1 归一删除——链构建层
					// (buildHTTPHandleChain)恒有同款兜底,此处零行为变化。
					weight := u.Weight
					protocol := u.Protocol
					if protocol == "" {
						protocol = "http"
					}
					ruleConfig.Upstreams = append(ruleConfig.Upstreams, UpstreamConfig{
						Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
						MaxConnections: u.MaxConnections, OriginDomain: u.OriginDomain,
					})
				}
			}

			ruleRoutes, _, err := generateHTTPRouteObjects(ruleConfig, securityCtx)
			if err != nil {
				return generationFailure("generate HTTP routes for rule %s: %v", r.CaddyID, err)
			}
			for _, route := range ruleRoutes {
				routes = append(routes, route)
			}
		}
		server["routes"] = routes

		var errorRoutes []interface{}
		// 拦截页按触发策略归因：除每规则 403 兜底路由（buildBlockPageErrorRoute，
		// host 限定本规则域名——承接多策略 IP 预检合并中断与无页策略中断）外，
		// 本 server 覆盖规则用到的每个合成中断码各发射一条归因路由（无 host
		// 键——合成码只可能由绑定该策略的规则段产生，同 server 其他规则不会
		// 发出该码）。按策略去重：同 server 多规则绑定同一策略仅一条，路由规模
		// = 每规则 1 条兜底（现状）+ 每有页策略 1 条（数十条级，不膨胀）。
		emittedSynthetic := make(map[string]struct{})
		for _, ru := range rules {
			r := ru.rule
			// nil 上下文门必须在两个拦截页构建器之前——二者内部直接
			// 解引用 securityCtx.blockPageByID（policiesForRule 虽支持 nil，但
			// 页面查找不支持）。当前生产路径 loadSecurityPolicyContext 失败即
			// generationFailure（ctx 恒非 nil），此门是未来调用点的 fail-safe。
			if securityCtx == nil {
				continue
			}
			if errorRoute := buildBlockPageErrorRoute(r.CaddyID, splitAndTrim(r.Domain), securityCtx); errorRoute != nil {
				errorRoutes = append(errorRoutes, errorRoute)
			}
			if errorRoute := buildRateLimitErrorRoute(r.CaddyID, splitAndTrim(r.Domain), securityCtx); errorRoute != nil {
				errorRoutes = append(errorRoutes, errorRoute)
			}
			// 阶段拦截页（规则级覆盖层）：规则配了阶段页（id>0 且页内容非空）→
			// 发射 host 限定的阶段路由（481/482 + interruption 消息；terminal；
			// status 0 归一 403）。阶段码是规则级覆盖，不同域名的规则必须各得
			// 一条路由；去重键=(code, host-set)，避免同端口多规则串用页面。
			// 逐策略码（483+）仍按策略身份全局唯一、不带 host。
			for _, stage := range []struct {
				code   int
				pageID int
				status int
			}{
				{blockPageStage1Code, r.BlockPageStage1ID, r.BlockPageStage1Status},
				{blockPageStage3Code, r.BlockPageStage3ID, r.BlockPageStage3Status},
			} {
				if stage.pageID <= 0 {
					continue
				}
				content := securityCtx.blockPageByID[stage.pageID]
				if content == "" {
					continue
				}
				hosts := splitAndTrim(r.Domain)
				key := fmt.Sprintf("stage:%d:%s", stage.code, strings.Join(hosts, "\x00"))
				if _, done := emittedSynthetic[key]; done {
					continue
				}
				emittedSynthetic[key] = struct{}{}
				errorRoutes = append(errorRoutes, buildBlockPageAttributionRoute(stage.code, hosts, content, stage.status, securityCtx.blockPageTypeByID[stage.pageID]))
			}
			// 阶段 3 覆盖层在场时该规则所有策略段恒抬 482，483+ 归因路由
			// 对本规则不可达；若策略共享给未覆盖规则，后者仍会按需发射。
			if r.BlockPageStage3ID == 0 || securityCtx.blockPageByID[r.BlockPageStage3ID] == "" {
				for _, policy := range policiesForRule(securityCtx, r.CaddyID) {
					code := securityCtx.policySynthetic[policy.ID]
					if code == 0 {
						continue
					}
					key := fmt.Sprintf("policy:%d", code)
					if _, done := emittedSynthetic[key]; done {
						continue
					}
					emittedSynthetic[key] = struct{}{}
					errorRoutes = append(errorRoutes, buildBlockPageAttributionRoute(code, nil, securityCtx.blockPageByID[policy.BlockPageID], policy.BlockStatusCode, securityCtx.blockPageTypeByID[policy.BlockPageID]))
				}
			}
		}
		if len(errorRoutes) > 0 {
			server["errors"] = map[string]interface{}{"routes": errorRoutes}
		}

		// Configure TLS for manual and ACME certificates
		var tlsPolicies []interface{}
		for _, ru := range rules {
			r := ru.rule
			if _, hasCert := availableCerts[r.CaddyID]; hasCert {
				domainHosts := splitAndTrim(r.Domain)
				tlsPolicies = append(tlsPolicies, map[string]interface{}{
					"match": map[string]interface{}{
						"sni": domainHosts,
					},
					"certificate_selection": map[string]interface{}{
						"any_tag": []string{r.CaddyID},
					},
				})
			}
		}
		if len(tlsPolicies) > 0 {
			server["tls_connection_policies"] = tlsPolicies
		}

		// 证书签发/续期由 cert_jobs（DNS-01）全权管理：禁止 Caddy 自动 HTTPS 的
		// 一切行为（v2.11.4 autohttps.go）。此前 80/443 仅
		// disable_certificates,但引擎在 DisableCerts=true 时仍无条件向 http_80
		// 追加 catch-all 308(autohttps.go appendCatchAll,无 host matcher)——被
		// 项目落地页遮蔽成死路由,每个未匹配 :80 请求产生 superfluous
		// WriteHeader 错误日志,且是未来落地页 terminal 化后盲导 443 的地雷。
		// HTTP→HTTPS 跳转完全由项目自有 redirectRoutes 管理(TLSHTTPRedirect,
		// 覆盖任意端口,含证书就绪复核与遮蔽检查),引擎侧整体关闭。
		server["automatic_https"] = map[string]interface{}{"disable": true}

		servers[fmt.Sprintf("http_%d", port)] = server
	}

	// Collect HTTP->HTTPS redirect routes from all TLS-enabled rules and place them on the HTTP (port 80) server.
	var redirectRoutes []interface{}
	// 判定提为闭包，供 r 自身与下方 other 遮蔽复核共用同款口径。
	// 提出循环外——闭包捕获空、无状态，每迭代重建纯属浪费。
	hasEnabledUpstream := func(ups []upstream) bool {
		for _, u := range ups {
			if u.Enabled {
				return true
			}
		}
		return false
	}
	// 遮蔽复核索引一次构建——旧实现对每条跳转规则遍历
	// 全部规则并逐条 normalizedDomainSet（每次含 db.CanonicalDomains 规范化），
	// R 条跳转 × N 条规则约 R×N 次规范化。索引只规范化 80 端口候选项一次（O(N)），
	// 跳转循环内退化为 O(1) 域名查表；比较口径与完全不变。
	port80Candidates := make([]port80RuleCandidate, 0, len(allRules))
	for _, other := range allRules {
		otherRule := other.rule
		if otherRule.Protocol != "http" || otherRule.ListenPort != 80 {
			continue
		}
		// （审计）：遮蔽复核的比对方也过启用上游门——零启用上游的规则不生成
		// 80 端口路由（死规则），不得作为遮蔽方压制兄弟域名的 HTTPS 跳转。
		if !hasEnabledUpstream(other.upstreams) {
			continue
		}
		port80Candidates = append(port80Candidates, port80RuleCandidate{caddyID: otherRule.CaddyID, domain: otherRule.Domain})
	}
	port80DomainOwners := buildPort80DomainOwners(port80Candidates)
	for _, ru := range allRules {
		r := ru.rule
		// 与规则渲染跳过同口径（上方按启用上游数 continue）——全部上游
		// 被禁用的启用规则不生成任何端口路由，同样不得生成 301 跳转，否则域名
		// 被跳到无服务的 TLS 端口（此前按上游裸计数，禁用上游也被计入）。
		if !hasEnabledUpstream(ru.upstreams) {
			continue
		}
		if r.Protocol == "http" && r.EnableTLS && r.TLSHTTPRedirect {
			// 跳转与 server 同判据——
			// 证书未就绪（availableCerts 未命中）即不发射 301，不分 tls_source。
			// 旧判据只门 acme_dns：manual 脏行（空证书）形态下 server 按
			// 跳过而 80 跳转仍发射，域名被 301 到无服务的 TLS 端口。
			if _, hasCert := availableCerts[r.CaddyID]; !hasCert {
				continue
			}
			domainHosts := splitAndTrim(r.Domain)
			if len(domainHosts) > 0 {
				// 签发完成/重载时刻复核——acme_dns 规则在证书签发前不生成
				// 跳转（上方 continue），签发后跳转才出现；若此刻存在同域名直接监听 80 的
				// 启用规则，terminal 301 会将其静默遮蔽为死规则。保存/启用路径已由
				// queryRedirectShadowConflict 拦截，此处纯内存复核兜住存量/导入/签发迟滞
				// 窗口，命中即跳过该域名跳转生成。
				// 比较双方均过规范化（db.CanonicalDomains 同源口径），
				// 导入态非规范化域名（"Example.COM"）不再失配。
				// 按域名粒度过滤——仅跳过与 80 端口规则冲突的域名，
				// 其余兄弟域名仍生成跳转（保存侧 queryRedirectShadowConflict 保持整规则
				// 400 语义，报错含冲突域名，用户可拆规则）。
				wantedDomains := normalizedDomainSet(r.Domain)
				blockedDomains := make(map[string]struct{})
				shadowedBy := ""
				// 索引查表替代 R×N 次规范化；自排除语义与旧实现
				// otherRule.CaddyID == r.CaddyID 一致（仅自身拥有该域名不算遮蔽）。
				// shadowedBy 取字典序最小命中域名，日志内容因此确定（旧实现取
				// map 遍历首个命中，无序）。
				for existingDomain := range wantedDomains {
					for _, ownerID := range port80DomainOwners[existingDomain] {
						if ownerID == r.CaddyID {
							continue
						}
						blockedDomains[existingDomain] = struct{}{}
						if shadowedBy == "" || existingDomain < shadowedBy {
							shadowedBy = existingDomain
						}
						break
					}
				}
				if len(blockedDomains) > 0 {
					filtered := make([]string, 0, len(domainHosts))
					for _, host := range domainHosts {
						if _, isBlocked := blockedDomains[normalizeHostForMatcher(host)]; !isBlocked {
							filtered = append(filtered, normalizeHostForMatcher(host))
						}
					}
					if len(filtered) == 0 {
						Logf("warn", "跳转规则 %s（%s）的域名 %s 已有启用规则直接监听 80 端口，该规则所有域名的 HTTPS 跳转均被遮蔽，整条跳转不生成（避免遮蔽 80 端口规则）", r.Name, r.CaddyID, shadowedBy)
						continue
					}
					Logf("warn", "跳转规则 %s（%s）的域名 %s 已有启用规则直接监听 80 端口，已从跳转中移除（其余域名仍生成跳转）", r.Name, r.CaddyID, shadowedBy)
					domainHosts = filtered
				}
				redirectRoutes = append(redirectRoutes, map[string]interface{}{
					"@id":      r.CaddyID + "_redirect",
					"terminal": true,
					"match": []interface{}{
						map[string]interface{}{
							"host": domainHosts,
						},
					},
					"handle": []interface{}{
						map[string]interface{}{
							"handler":     "static_response",
							"status_code": 301,
							"headers": map[string]interface{}{
								"Location": []string{httpsRedirectLocation(r.ListenPort)},
							},
						},
					},
				})
			}
		}
	}

	// Collect TLS certificate file paths for all rules (manual + ACME from cert_jobs)
	var tlsCertFiles []map[string]interface{}
	for _, ru := range allRules {
		r := ru.rule
		// 同上方 materials 循环：TCP 规则不参与 TLS 材料（带外 enable_tls 不得
		// 把私钥列进 load_files）。
		if r.Protocol != "http" || !r.EnableTLS {
			continue
		}
		if _, hasCert := availableCerts[r.CaddyID]; hasCert {
			certPath, keyPath := CertFilePaths(r.CaddyID)
			tlsCertFiles = append(tlsCertFiles, map[string]interface{}{
				"certificate": certPath,
				"key":         keyPath,
				"tags":        []string{r.CaddyID},
			})
		}
	}

	layer4Servers := make(map[string]interface{})

	for port, rules := range tcpServersByPort {
		// DynamicDNS 检测改为逐规则跳过。
		filtered := rules[:0]
		for _, ru := range rules {
			if ru.rule.DynamicDNS {
				Logf("warn", "警告：TCP 规则 %s 启用了动态 DNS，但 TCP 协议暂不支持动态解析，已跳过该规则（不影响同端口其他规则）",
					ru.rule.CaddyID)
				continue
			}
			filtered = append(filtered, ru)
		}
		if len(filtered) == 0 {
			continue
		}
		rules = filtered

		// TCP 同端口多规则禁止（用户决策）。历史 检测配置冲突跳过整个端口，
		// 但 upstreams 仍被盲目合并导致重复 upstream 双倍权重。改为直接拒绝并记告警。
		if len(rules) > 1 {
			ids := make([]string, 0, len(rules))
			for _, ru := range rules {
				ids = append(ids, ru.rule.CaddyID)
			}
			Logf("warn", "警告：端口 %d 上存在多条 TCP 规则（%s），TCP 协议要求每端口唯一规则，全部跳过。请删除多余规则或使用不同端口",
				port, strings.Join(ids, ", "))
			continue
		}

		r := rules[0].rule
		ruleConfig := SingleRuleConfig{
			CaddyID:                       r.CaddyID,
			Protocol:                      "tcp",
			ListenPort:                    r.ListenPort,
			Strategy:                      r.Strategy,
			HealthCheckInterval:           r.HealthCheckInterval,
			HealthCheckTimeout:            r.HealthCheckTimeout,
			HealthCheckUnhealthyThreshold: r.HealthCheckUnhealthyThreshold,
			HealthCheckHealthyThreshold:   r.HealthCheckHealthyThreshold,
			EnableActiveHealthCheck:       r.EnableActiveHealthCheck,
			TCPHealthCheckPort:            r.TCPHealthCheckPort,
			TCPProxyProtocol:              r.TCPProxyProtocol,
			TCPTryDuration:                r.TCPTryDuration,
			TCPTryInterval:                r.TCPTryInterval,
		}
		// 外层循环恒单轮（上方 len(rules)>1 已 continue 跳过全部）——
		// 直接取 rules[0] 避免无意义的循环语法暗示多规则可能。
		for _, u := range rules[0].upstreams {
			if !u.Enabled {
				continue
			}
			weight := u.Weight
			if weight <= 0 {
				weight = 1
			}
			ruleConfig.Upstreams = append(ruleConfig.Upstreams, UpstreamConfig{
				Host: u.Host, Port: u.Port, Weight: weight, Protocol: u.Protocol, Enabled: u.Enabled,
				MaxConnections: u.MaxConnections,
			})
		}
		tcpServer, tcpErr := buildTCPServer(ruleConfig)
		if tcpErr != nil {
			return generationFailure("build TCP server for rule %s: %v", ruleConfig.CaddyID, tcpErr)
		}
		layer4Servers[fmt.Sprintf("tcp_%d", port)] = tcpServer
	}

	defaultSite := map[string]interface{}{
		"listen": []string{":80"},
		"routes": []interface{}{
			map[string]interface{}{
				"handle": []interface{}{
					map[string]interface{}{
						"handler": "static_response",
						"body":    DefaultLandingBody(),
					},
				},
			},
		},
		// 与规则 server 同构：引擎 autoHTTPS 整体关闭（证书签发/续期由
		// cert_jobs 全权管理，HTTP→HTTPS 跳转由项目自有 redirectRoutes 管理）。
		// 默认站只管落地页/跳转路由，若漏写该键，Caddy 会对 :80 请求追加
		// 引擎侧 catch-all 308，与上方落地页路由形成 superfluous WriteHeader。
		"automatic_https": map[string]interface{}{"disable": true},
	}
	if err := applyTimeouts(defaultSite); err != nil {
		return generationFailure("%v", err)
	}

	if _, exists := servers["http_80"]; !exists {
		if len(redirectRoutes) > 0 {
			defaultSite["routes"] = append(redirectRoutes, defaultSite["routes"].([]interface{})...)
		}
		servers["http_80"] = defaultSite
	} else {
		server := servers["http_80"].(map[string]interface{})
		// 不再重复 applyTimeouts——server 在:1456 创建时已
		// 应用,两处之间无超时值变异,重复调用是幂等同值覆写。
		routes, ok := server["routes"].([]interface{})
		if !ok {
			routes = []interface{}{}
		}
		defaultRoute := map[string]interface{}{
			"handle": []interface{}{
				map[string]interface{}{
					"handler": "static_response",
					"body":    DefaultLandingBody(),
				},
			},
		}
		// Ensure redirect routes come before the default catch-all route.
		if len(redirectRoutes) > 0 {
			routes = append(redirectRoutes, routes...)
		}
		routes = append(routes, defaultRoute)
		server["routes"] = routes
		servers["http_80"] = server
	}

	// logger_names 按 server（端口）拆分——同域名跨端口双规则时全局
	// 共享映射会让后写覆盖先写（先建规则的日志文件永无条目），且任一端口上的
	// 同域名请求（含 80 默认站跳转）都被误记入映射命中规则的日志。
	//
	// 发射面随发布集收窄：只有真正进入 servers 的 HTTP 规则（零启用上游跳过 /
	// TLS 证书未就绪整条跳过）才建 logger 与 logs 条目。未发布规则没有任何
	// 路由，为其注册 logger_names 只会得到永不命中的日志器与 logs map 项
	// （日志写盘面虚增、配置噪声）；规则恢复发布时下一次渲染自然恢复条目。
	// 发布集（publishedHTTPRules）已在主循环内按 allRules 顺序收集——
	// 不再由 httpServersByPort（map 遍历）重建，见其声明处注释。
	loggerNamesByPort := map[int]map[string]interface{}{}
	for _, ru := range publishedHTTPRules {
		r := ru.rule
		if !r.LogEnabled || r.Protocol != "http" || r.Domain == "" {
			continue
		}
		perPort := loggerNamesByPort[r.ListenPort]
		if perPort == nil {
			perPort = map[string]interface{}{}
			loggerNamesByPort[r.ListenPort] = perPort
		}
		for _, d := range splitAndTrim(r.Domain) {
			// 键按 host matcher 口径规范化（规则域名写侧已由 db.CanonicalDomains
			// 规范为小写，本归一基本是 no-op）。Caddy 的日志器查找用**原始
			// Host**做区分大小写精确匹配（modules/caddyhttp/logging.go）：大写
			// Host（curl -H 'Host: Example.COM'、脚本、扫描器）查不到小写键，
			// 落默认 logger http.log.access；而 default writer 的 exclude 含
			// `http` 前缀、caddy_server 亦显式排除 —— 这**不是归属错位，是
			// 零落盘**。可观测边界：规则访问日志仅覆盖小写规范 Host；不枚举
			// 大小写变体（组合不可枚举），也不移除 default 的 http 排除
			// （会让规则行在 caddy.log 重复，推翻日志收窄）。转发、安全事件与
			// 指标不受影响（走请求链）。
			perPort[normalizeHostForMatcher(d)] = "rule_" + r.CaddyID
		}
	}
	if len(loggerNamesByPort) > 0 {
		for serverName, serverVal := range servers {
			srv, _ := serverVal.(map[string]interface{})
			if srv == nil || !strings.HasPrefix(serverName, "http_") {
				continue
			}
			port, err := strconv.Atoi(strings.TrimPrefix(serverName, "http_"))
			if err != nil {
				continue
			}
			if perPort, ok := loggerNamesByPort[port]; ok && len(perPort) > 0 {
				srv["logs"] = map[string]interface{}{"logger_names": perPort}
			}
		}
	}

	// 受信代理（CDN 真实 IP）：每个 HTTP server（含 :80 默认站）注入；
	// 未启用时零字段（行为不变）。降级说明随配置图携带。
	trustedProxyDegraded := mergeTrustedProxyServerFields(servers, store)

	apps := map[string]interface{}{
		// observe_catchall_hosts：Host 头驱动标签基数面——任意 Host 命中落地页
		// 都会产出新指标序列，公网部署下 Caddy 内存基数由客户端控制。
		// 2026-09-19 用户裁定接受该权衡（收益=未知域流量可观测），仅文档明示。
		"http": map[string]interface{}{
			"metrics": map[string]interface{}{
				"per_host":               true,
				"observe_catchall_hosts": true,
			},
			"servers": servers,
		},
	}

	if len(layer4Servers) > 0 {
		apps["layer4"] = map[string]interface{}{
			"servers": layer4Servers,
		}
	}

	// TLS app: load certificates from database (manual + ACME), no Caddy ACME automation.
	if len(tlsCertFiles) > 0 {
		tlsApp := map[string]interface{}{
			"certificates": map[string]interface{}{
				"load_files": tlsCertFiles,
			},
		}
		apps["tls"] = tlsApp
	}

	// 库值唯一真相（批 1+2）：caddy_log_size_mb 为类型①值型列，<=0 显性报错
	// （buildCaddyLogging 的写死 100 兜底废除）；caddy_log_level 非本批治理
	// 字段，空串=「未配置」语义在 buildCaddyLogging 内归 info（白名单披露）。
	if caddyLogSizeMB <= 0 {
		return generationFailure("Caddy 日志轮转大小无效（caddy_log_size_mb=%d <=0）", caddyLogSizeMB)
	}
	logging := buildCaddyLogging(caddyLogLevel, caddyLogSizeMB)

	if logsMap, ok := logging["logs"].(map[string]interface{}); ok {
		encoder := buildAccessLogEncoder(accessLogJSON, accessLogFormat)
		// ruleLogDir 创建移出逐规则循环（此前每条规则一次
		// 重复 syscall 且错误被丢弃）——有任一启用日志的 http 规则时创建一次，
		// 失败记日志（writer 落不了盘会体现为 caddy 配置应用错误，此处点名目录）。
		// 日志发射面随发布集收窄（同 logger_names）：未发布规则不建 logs 项，
		// 否则 logs map 会为永不产生日志的 logger 分配 writer/encoder。
		ruleLoggerNeeded := false
		for _, ru := range publishedHTTPRules {
			if r := ru.rule; r.LogEnabled && r.Protocol == "http" {
				ruleLoggerNeeded = true
				break
			}
		}
		if ruleLoggerNeeded {
			if err := os.MkdirAll(ruleLogDir, 0755); err != nil {
				Logf("error", "创建规则日志目录 %s 失败: %v", ruleLogDir, err)
			}
		}
		for _, ru := range publishedHTTPRules {
			r := ru.rule
			if !r.LogEnabled || r.Protocol != "http" {
				continue
			}
			logsMap["rule_"+r.CaddyID] = map[string]interface{}{
				"writer":  caddyLogFileWriter(RuleLogPath(r.CaddyID), caddyLogSizeMB),
				"encoder": encoder,
				"include": []string{"http.log.access.rule_" + r.CaddyID},
			}
		}
	}

	// （2026-09-19 历史裁定）：Caddy admin 恒 CaddyAdminListenAddr（127.0.0.1:2019）。
	// cfg.CaddyAdminURL 只是首次 /load 之前的引导端点（面板经它把首份配置推给
	// Caddy）——首次成功 /load 后 admin 监听即被本渲染产物迁到 127.0.0.1:2019，
	// 此后一切 admin 请求（含 cfg.CaddyAdminURL 指向的客户端）必须打同一地址。
	// caddy_admin_url 配成其他地址的部署会在首次 /load 后失联，启动期
	// config.LoadCollectWarnings 对此发 WARN（fail-visible）。

	conf := map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": CaddyAdminListenAddr,
		},
		"apps":    apps,
		"logging": logging,
	}
	if trustedProxyDegraded != "" {
		conf[caddyConfigDegradationKey] = trustedProxyDegraded
	}
	if filesSnapshot != nil {
		conf[caddyCertFilesSnapshotKey] = filesSnapshot
	}

	return conf
}

// buildAccessLogEncoder 生成访问日志 encoder（全局日志与规则日志共用单源）。
// 三条形态全部经 filter+wrap json，且恒注入 API Key 删除：
//   - 自定义格式（access_log_json=true）：用户行映射之上强制覆盖该头；
//   - 空格式（默认库值）：fields 仅含脱敏行，其余字段保持原生 JSON；
//   - access_log_json=false（Caddy 原生 JSON）：仍走 filter+wrap json——纯 json
//     编码器没有任何删除通道，会把 API Key 原样写出。
//
// 删除键必须取 accesslog.APIKeyHeaderPaths()（规范 MIME 头名 + 字面量兜底）：
// 引擎 filter 是精确字符串查表，而日志里的头键是 http.Header 的规范化键
// （"X-Api-Key"）——手写字面量拼写恒不命中，脱敏空转且无任何告警。
//
// 用户若对同一路径写了 rename/delete，map 同键覆盖为 delete（恒脱敏优先）。
func buildAccessLogEncoder(accessLogJSON bool, format string) map[string]interface{} {
	fields := map[string]interface{}{}
	if accessLogJSON {
		fields = accessLogEncoderFields(format)
	}
	for _, path := range accesslog.APIKeyHeaderPaths() {
		fields[path] = map[string]interface{}{"filter": "delete"}
	}
	return map[string]interface{}{
		"format": "filter",
		"wrap":   map[string]interface{}{"format": "json"},
		"fields": fields,
	}
}

// accessLogEncoderFields 渲染侧 DSL 消费：把单源 ParseAccessLogFormat 的合法行
// 转成 encoder fields（非法行=写侧 400 拒绝；带外写入的存量非法行在此容忍
// 跳过，不阻断渲染）。命名与引擎侧解析器（ParseAccessLogFormat）区分——本函数
// 只做「解析结果 → fields」投影，不解析格式串本身。
func accessLogEncoderFields(format string) map[string]interface{} {
	fields := map[string]interface{}{}
	for _, rule := range ParseAccessLogFormat(format).Rules {
		if rule.Action == "delete" {
			fields[rule.Path] = map[string]interface{}{"filter": "delete"}
		} else {
			fields[rule.Path] = map[string]interface{}{"filter": "rename", "name": rule.Action}
		}
	}
	return fields
}

// caddyLogFileWriter Caddy 日志文件 writer 的唯一构造点（全局 logging 与规则级
// logger 共用）。键集决定 timberjack 的轮转 reason 家族（roll_size_mb =>
// rotate("size")），删除侧白名单（rulelog.go 的 timberjackRotationReasons）与
// 本键集由 rulelog_rotation_naming_test.go 的双向门禁绑定——新增轮转触发键
// 必须先登记对应 reason。
func caddyLogFileWriter(filename string, sizeMB int) map[string]interface{} {
	return map[string]interface{}{
		"output":       "file",
		"filename":     filename,
		"roll_size_mb": sizeMB,
		"roll_keep":    caddyLogRollKeep,
	}
}

func buildCaddyLogging(level string, sizeMB int) map[string]interface{} {
	// sizeMB 由调用方校验恒 >0（库值唯一真相批 1+2：caddy_log_size_mb 类型①
	// 值型列直读，无效值在调用点显性报错）；level 空串=「未配置」语义归 info
	//（字符串缺省，非本批治理范围）。
	if level == "" {
		level = "info"
	}
	level = strings.ToUpper(level)
	consoleEncoder := map[string]interface{}{"format": "console"}
	return map[string]interface{}{
		"logs": map[string]interface{}{
			"default": map[string]interface{}{
				"level":   level,
				"writer":  caddyLogFileWriter("/app/logs/caddy.log", sizeMB),
				"encoder": consoleEncoder,
				// exclude 是命名空间前缀匹配："http" 已覆盖 http.log.access
				// （重复项只增加配置字节噪声）。
				"exclude": []string{"http", "tls"},
			},
			"caddy_tls": map[string]interface{}{
				"level":   level,
				"writer":  caddyLogFileWriter("/app/logs/caddy-tls.log", sizeMB),
				"encoder": consoleEncoder,
				"include": []string{"tls"},
			},
			"caddy_server": map[string]interface{}{
				"level":   level,
				"writer":  caddyLogFileWriter("/app/logs/caddy-server.log", sizeMB),
				"encoder": consoleEncoder,
				// 2026-09-17 用户裁定:http.handlers.waf 命名空间排除——WAF 按请求
				// 量的拦截日志(coraza 引擎 debug WARN 行 + coraza-caddy 插件
				// 硬编码 ERROR 行,同属该空间)不写入服务器运行日志;事件采集走
				// SecAuditLog → 安全事件页(独立链路,不受影响)。
				"exclude": []string{"admin", "tls", "events", "http.log.access", "http.handlers.reverse_proxy", "http.handlers.waf"},
			},
			"caddy_proxy": map[string]interface{}{
				"level":   level,
				"writer":  caddyLogFileWriter("/app/logs/caddy-proxy.log", sizeMB),
				"encoder": consoleEncoder,
				"include": []string{"http.handlers.reverse_proxy"},
			},
		},
	}
}

// acmeCertCandidatesForRule 查询指定规则的 ACME 证书候选（PEM 非空行，
// updated_at/id 倒序）。谓词 miss 补查与 loadACMECertificateFromStore
// 共用本查询体（去重——此前两处同一 SELECT+扫描循环逐字
// 重复）；status 过滤由调用方 selectCertificate 后置执行。查询/解析失败仅记
// 日志返回 nil（调用点按无证书渲染/判定，语义不变）。
func acmeCertCandidatesForRule(store caddyConfigStore, ruleID string) []CertificateCandidate {
	rows, err := store.Query(`
		SELECT id, domain, status, cert_pem, key_pem,
		       COALESCE(julianday(COALESCE(updated_at, created_at)), 0)
		FROM cert_jobs
		WHERE rule_id=?
		  AND `+certJobCandidatePredicateSQL("")+`
		ORDER BY updated_at DESC, id DESC`, ruleID)
	if err != nil {
		Logf("warn", "ACME 证书候选查询失败（规则 %s，按无证书处理）: %v", ruleID, err)
		return nil
	}
	defer rows.Close()
	candidates := make([]CertificateCandidate, 0)
	for rows.Next() {
		var candidate CertificateCandidate
		if err := rows.Scan(&candidate.ID, &candidate.Domain, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt); err != nil {
			Logf("warn", "ACME 证书候选解析失败（规则 %s）: %v", ruleID, err)
			return nil
		}
		// 与批量装载同口径预解析 Leaf（规则候选可能被
		// loadACMECertificateFromStore 的多个消费点多轮选择）。
		if candidate.Status != "disabled" {
			candidate.Leaf = ParseCertificateLeaf(candidate.CertPEM, candidate.KeyPEM)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		Logf("warn", "ACME 证书候选遍历失败（规则 %s）: %v", ruleID, err)
		return nil
	}
	return candidates
}

// loadACMECertificateFromStore reads the issued ACME certificate and key from
// cert_jobs (via store) for the given rule and domain. Returns
// (certPEM, keyPEM, true) if issued.
// 查询体委托 acmeCertCandidatesForRule，本函数只做
// selectCertificate 择优（此前两函数 SELECT+扫描循环逐字重复）。
func loadACMECertificateFromStore(store caddyConfigStore, caddyID, domain string) (string, string, bool) {
	selected, ok := selectCertificate(acmeCertCandidatesForRule(store, caddyID), domain, time.Now())
	if ok {
		return selected.Candidate.CertPEM, selected.Candidate.KeyPEM, true
	}
	return "", "", false
}

// IsACMECertIssued returns true if cert_jobs has an issued certificate for the
// given rule (by caddy_id) and domain.
func IsACMECertIssued(caddyID, domain string) bool {
	return isACMECertIssuedFromStore(db.DB, caddyID, domain)
}

func isACMECertIssuedFromStore(store caddyConfigStore, caddyID, domain string) bool {
	_, _, issued := loadACMECertificateFromStore(store, caddyID, domain)
	return issued
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// normalizedDomainSet 返回逗号分隔域名的规范化集合（小写+punycode），与保存侧
// db.CanonicalDomains（normalizedRuleDomains）同源。渲染层遮蔽比较
// 必须与保存侧口径一致，否则导入态非规范化域名（"Example.COM" vs "example.com"）
// 比较失配——Caddy host matcher 大小写不敏感，遮蔽问题会经导入路径复发。
// 整串无法规范化（手造脏数据）时回退小写拆分结果，渲染不因脏数据中断。
func normalizedDomainSet(value string) map[string]struct{} {
	if canonical, err := db.CanonicalDomains(value); err == nil {
		result := make(map[string]struct{})
		for _, domain := range strings.Split(canonical, ",") {
			result[domain] = struct{}{}
		}
		return result
	}
	result := make(map[string]struct{})
	for _, domain := range splitAndTrim(value) {
		result[strings.ToLower(domain)] = struct{}{}
	}
	return result
}

// normalizeHostForMatcher 将单个域名规范化后用于 host matcher；无法规范化时
// 回退小写原值，保证 matcher 仍按 Caddy 大小写不敏感语义工作。
func normalizeHostForMatcher(host string) string {
	if canonical, err := db.CanonicalDomains(host); err == nil {
		return canonical
	}
	return strings.ToLower(host)
}

// port80RuleCandidate 一条「直接监听 80 端口」的候选规则（调用方已按协议/
// 端口/启用上游过滤）。
type port80RuleCandidate struct {
	caddyID string
	domain  string
}

// buildPort80DomainOwners 一次性规范化候选域名，返回 域名→规则 ID 列表 索引。
// 渲染期 HTTP→HTTPS 跳转遮蔽复核原为每条跳转规则
// 对全部规则逐对 normalizedDomainSet（每次含 db.CanonicalDomains），大规则量
// 下约 R×N 次规范化；索引把规范化收敛为 O(N)，逐跳转规则只做 O(1) 域名查表。
// 同一域名被多条 80 端口规则拥有时按 allRules 顺序追加 ID，供调用方做自排除
// （仅自身拥有该域名不算遮蔽）。
func buildPort80DomainOwners(candidates []port80RuleCandidate) map[string][]string {
	owners := make(map[string][]string, len(candidates))
	for _, candidate := range candidates {
		for domain := range normalizedDomainSet(candidate.domain) {
			owners[domain] = append(owners[domain], candidate.caddyID)
		}
	}
	return owners
}

// httpsRedirectLocation 构造 HTTP→HTTPS 跳转的 Location 头。
// 使用 {http.request.host} 占位符而非首个域名字面量：Caddy static_response
// 的 headers 会在运行时经过 replacer 替换（v2.11.4 modules/caddyhttp/staticresp.go），
// 因此多域名规则（a.com,b.com）访问 b.com 时会跳回 b.com，而不是被劫持到首个域名。
func httpsRedirectLocation(listenPort int) string {
	// （补正重写）：Location 必须追加 {http.request.uri}（path+query）
	// ——Caddy static_response 不会自动保留原 URI（原生 auto-HTTPS 重定向会保留），
	// 缺失时 http://a.com/page?x=1 会被跳到根路径。首版实施因脚本断言中止丢失。
	if listenPort != 443 {
		return fmt.Sprintf("https://{http.request.host}:%d{http.request.uri}", listenPort)
	}
	return "https://{http.request.host}{http.request.uri}"
}

type SingleRuleConfig struct {
	CaddyID                       string
	Protocol                      string
	Domain                        string
	ListenPort                    int
	Strategy                      string
	DynamicDNS                    bool
	EnableDnsServer               bool
	DnsServer                     string
	DnsFamily                     string
	HealthCheckPath               string
	HealthCheckInterval           int
	HealthCheckTimeout            int
	HealthCheckUnhealthyThreshold int
	HealthCheckHealthyThreshold   int
	// 单规则渲染不承载 TLS 材料：EnableTLS/TLSSource/TLSCert/TLSKey 曾在此
	// 结构上但无任何读者（预检不填、全量渲染的消费者只读路由字段），
	// 保留即暗示单规则路径支持 TLS 并可能把私钥 PEM 带进渲染载荷。
	TLSHTTPRedirect                bool
	EnableCompress                 bool
	CompressTypes                  string
	EnableActiveHealthCheck        bool
	TCPHealthCheckPort             int
	TCPProxyProtocol               bool
	TCPTryDuration                 int
	TCPTryInterval                 int
	RequestBodyMaxSizeMB           int
	UpstreamKeepaliveTimeout       int
	ServerTokensHidden             int
	NTLMCompatible                 int
	UpstreamForceHTTP1             int
	GlobalRequestBodyMaxSizeMB     int
	GlobalUpstreamKeepaliveTimeout int
	GlobalServerTokensHidden       bool
	HostHeader                     string
	// 健康检查域名：主动健康检查 probe 的 Host 头（health_checks.active.headers.Host
	// 特判实证，healthchecks.go:453-458）；空=跟随 HostHeader。
	HealthCheckHost                  string
	CustomRoutesEnabled              bool
	PathRules                        []PathRuleConfig
	ProxyDialTimeout                 int
	ProxyResponseHeaderTimeout       int
	ProxyReadTimeout                 int
	ProxyWriteTimeout                int
	ProxyStreamTimeout               int
	ProxyFlushInterval               int
	ProxyStreamCloseDelay            int
	GlobalProxyDialTimeout           int
	GlobalProxyResponseHeaderTimeout int
	GlobalProxyReadTimeout           int
	GlobalProxyWriteTimeout          int
	GlobalProxyStreamTimeout         int
	GlobalProxyFlushInterval         int
	GlobalProxyStreamCloseDelay      int
	Upstreams                        []UpstreamConfig
	// 阶段拦截页覆盖层（0=跟随策略）：渲染侧判定需页内容非空
	// （securityPolicyContext.blockPageByID），空内容=未配。
	BlockPageStage1ID     int
	BlockPageStage1Status int
	BlockPageStage3ID     int
	BlockPageStage3Status int
}

type PathRuleConfig struct {
	SortOrder int
	MatchType string
	Path      string
	// 上游 path 改写：空串=原样转发（零插入）；非空前缀匹配剥前缀后前置、
	// 精确匹配整体替换（引擎实证形状，见 upstreamPathRewriteHandlers）。
	UpstreamPath string
	Upstreams    []UpstreamConfig
	// 直接返回/301 跳转（2026-10-10 用户裁定）：ResponseMode ''=转发上游
	// （现状，全链渲染）/static=静态响应/redirect=301 跳转——后两者不经
	// 安全链与 reverse_proxy；自此链首带 lb_rule_metrics
	// 纯计数（指标不属于安全链）。
	ResponseMode        string
	ResponseStatus      int
	ResponseBody        string
	ResponseContentType string
	RedirectTo          string
}

type proxyTimeouts struct {
	dial             int
	responseHeader   int
	read             int
	write            int
	stream           int
	flushInterval    int
	streamCloseDelay int
}

type UpstreamConfig struct {
	Host           string
	Port           int
	Weight         int
	Protocol       string
	Enabled        bool
	MaxConnections int
	// 逐上游回源域名：非空时经 map 处理器（{lb.upstream_host}/{lb.upstream_sni}）
	// 驱动该上游回源 Host 头与 HTTPS SNI；空=跟随 HostHeader/现状默认。
	OriginDomain string
}

// resolveRuleOverrides 规则级覆盖解析（库值唯一真相批 1+2 改造）：
//   - 请求体上限：规则级>0 用规则级，否则全局值。全局 request_body_max_size_mb
//     为类型①值型列（NOT NULL DEFAULT 128+启动回填），恒有效——原「仍 <=0 则
//     写死 128」兜底废除：库值无效（<=0）即渲染显性报错
//     （fail-visible），错误经 buildHTTPHandleChain→generationFailure 使配置
//     生成失败、旧配置保留。
//   - keepalive：规则级>0 否则全局值；类型②省略型（0=省略=继承 Caddy/Go
//     Transport 默认 2 分钟，用户裁定），渲染不发 keep_alive。
//     Server 头隐藏：2026-09-06 裁定仅暴露全局开关（基础设置），规则级
//     server_tokens_hidden 0/1/2 覆盖为 API/MCP 预留字段——无 UI 入口、不作为
//     产品功能维护，UI 编辑透传保留 API 已设值。
func resolveRuleOverrides(rule SingleRuleConfig) (requestBodyMaxSizeMB int, upstreamKeepalive int, hideServer bool, err error) {
	requestBodyMaxSizeMB = rule.RequestBodyMaxSizeMB
	if requestBodyMaxSizeMB <= 0 {
		requestBodyMaxSizeMB = rule.GlobalRequestBodyMaxSizeMB
	}
	if requestBodyMaxSizeMB <= 0 {
		return 0, 0, false, fmt.Errorf("规则 %s 请求体大小限制无效（规则级与全局 request_body_max_size_mb 均 <=0，库值治理被带外写入破坏）", rule.CaddyID)
	}

	upstreamKeepalive = rule.UpstreamKeepaliveTimeout
	if upstreamKeepalive <= 0 {
		upstreamKeepalive = rule.GlobalUpstreamKeepaliveTimeout
	}

	hideServer = rule.GlobalServerTokensHidden
	if rule.ServerTokensHidden == 1 {
		hideServer = true
	} else if rule.ServerTokensHidden == 2 {
		hideServer = false
	}

	return requestBodyMaxSizeMB, upstreamKeepalive, hideServer, nil
}

func resolveProxyTimeouts(rule SingleRuleConfig) proxyTimeouts {
	resolve := func(ruleValue, globalValue int) int {
		if ruleValue > 0 {
			return ruleValue
		}
		if globalValue > 0 {
			return globalValue
		}
		return 0
	}
	// flush_interval treats -1 as a meaningful "immediate flush" sentinel, not "unset".
	// Any non-zero rule value wins; otherwise fall back to a non-zero global value.
	resolveFlush := func(ruleValue, globalValue int) int {
		if ruleValue != 0 {
			return ruleValue
		}
		if globalValue != 0 {
			return globalValue
		}
		return 0
	}

	return proxyTimeouts{
		dial:             resolve(rule.ProxyDialTimeout, rule.GlobalProxyDialTimeout),
		responseHeader:   resolve(rule.ProxyResponseHeaderTimeout, rule.GlobalProxyResponseHeaderTimeout),
		read:             resolve(rule.ProxyReadTimeout, rule.GlobalProxyReadTimeout),
		write:            resolve(rule.ProxyWriteTimeout, rule.GlobalProxyWriteTimeout),
		stream:           resolve(rule.ProxyStreamTimeout, rule.GlobalProxyStreamTimeout),
		flushInterval:    resolveFlush(rule.ProxyFlushInterval, rule.GlobalProxyFlushInterval),
		streamCloseDelay: resolve(rule.ProxyStreamCloseDelay, rule.GlobalProxyStreamCloseDelay),
	}
}

// formatFlushInterval renders proxy_flush_interval for Caddy JSON:
// -1 → "-1s" (immediate flush, disables buffering); N>0 → "Ns".
func formatFlushInterval(v int) string {
	if v < 0 {
		return "-1s"
	}
	return fmt.Sprintf("%ds", v)
}

func GenerateSingleRuleCaddyConfig(rule SingleRuleConfig) map[string]interface{} {
	// 与单规则渲染路径的硬错误对齐——https 等
	// 非法协议不再静默按 TCP 渲染（遗留 https 行由 db 迁移归一为 http）。
	if rule.Protocol != "http" && rule.Protocol != "tcp" {
		return map[string]interface{}{
			"error": fmt.Errorf("unsupported protocol: %s", rule.Protocol),
		}
	}
	if rule.Strategy == "" {
		rule.Strategy = "weighted_round_robin"
	}

	enabledUpstreams := make([]UpstreamConfig, 0)
	for _, u := range rule.Upstreams {
		if u.Enabled {
			enabledUpstreams = append(enabledUpstreams, u)
		}
	}

	if len(enabledUpstreams) == 0 {
		return map[string]interface{}{
			"error": ErrNoEnabledUpstreams,
		}
	}
	if rule.DynamicDNS && len(enabledUpstreams) > 1 {
		return map[string]interface{}{
			"error": fmt.Errorf("%w, got %d", ErrDynamicDNSUpstreamCount, len(enabledUpstreams)),
		}
	}

	servers := make(map[string]interface{})

	if rule.Protocol == "http" {
		// 委托生产路径的构建器生成路由对象（GeoIP + 路径路由 + 主路由），
		// 避免与 generateCaddyConfigFromStore 的逻辑分叉。
		routes, _, err := generateHTTPRouteObjects(rule)
		if err != nil {
			return map[string]interface{}{"error": err}
		}

		// 单规则形态仅服务 TCP/HTTP 预检（rule_features.go precheckRuleConfig
		// 不填 EnableTLS/TLSHTTPRedirect）——HTTP→HTTPS 跳转路由由全量渲染的
		// redirectRoutes 统一生成，此处不插跳转分支。automatic_https 与全量
		// 渲染同判据（恒 disable，见下方发射点）。
		//
		// 本函数**不发射任何 TLS 配置**：单规则渲染曾带
		// tls_connection_policies（manual 证书）与 apps.tls.load_pem（内联私钥）
		// 两个分支，但唯一生产调用方（预检）刻意不填 TLS 字段，分支恒不可达；
		// 若未来回填 TLS 字段即把私钥 PEM 写进渲染载荷/转储。TLS 材料只经
		// 全量渲染（availableCerts → MaterializeCertPairs → load_files）。
		routeValues := make([]interface{}, len(routes))
		for i, r := range routes {
			routeValues[i] = r
		}

		serverName := fmt.Sprintf("http_%d", rule.ListenPort)

		server := map[string]interface{}{
			"listen": []string{fmt.Sprintf(":%d", rule.ListenPort)},
			"routes": routeValues,
		}

		// 与全量渲染同判据：引擎 auto-HTTPS 一律关闭（证书签发/续期由
		// cert_jobs 全权管理，跳转由 redirectRoutes 管理）。此前仅对非 80/443
		// 端口发射 disable，是第二套约定——一旦该函数被用于真实应用（或补上
		// EnableTLS 回填），443 服务器会重新打开引擎 ACME，与项目证书链分叉。
		server["automatic_https"] = map[string]interface{}{
			"disable": true,
		}

		servers[serverName] = server
	} else {
		tcpServer, tcpErr := buildTCPServer(rule)
		if tcpErr != nil {
			return map[string]interface{}{"error": tcpErr}
		}
		apps := map[string]interface{}{
			"layer4": map[string]interface{}{
				"servers": map[string]interface{}{
					fmt.Sprintf("tcp_%d", rule.ListenPort): tcpServer,
				},
			},
		}

		conf := map[string]interface{}{
			"admin": map[string]interface{}{
				"listen": CaddyAdminListenAddr,
				// 流量统计走 caddygeoip admin.api 全量自动挂载（无需配置启用）。
			},
			"apps": apps,
		}

		return conf
	}

	// 受信代理（CDN 真实 IP）：单规则预览路径同样注入（读已提交库，
	// 与 GenerateSingleRuleCaddyConfig 的只读语义一致）。db.DB 缺失
	//（纯内存单规则测试等）时跳过——与「读错按未启用渲染」同口径。
	trustedProxyDegraded := ""
	if db.DB != nil {
		trustedProxyDegraded = mergeTrustedProxyServerFields(servers, db.DB)
	}

	apps := map[string]interface{}{
		"http": map[string]interface{}{
			"servers": servers,
		},
	}
	// 此处不注入 apps.tls：单规则渲染不承载证书材料（见上方注释），
	// 私钥只经全量渲染物化到文件并由 load_files 引用。

	conf := map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": CaddyAdminListenAddr,
		},
		"apps": apps,
	}
	if trustedProxyDegraded != "" {
		conf[caddyConfigDegradationKey] = trustedProxyDegraded
	}

	return conf
}

func generateHTTPRouteObjects(rule SingleRuleConfig, securityCtx ...*securityPolicyContext) ([]map[string]interface{}, map[string]interface{}, error) {
	if rule.Strategy == "" {
		rule.Strategy = "weighted_round_robin"
	}
	var ctx *securityPolicyContext
	if len(securityCtx) > 0 {
		ctx = securityCtx[0]
	}
	domainHosts := splitAndTrim(rule.Domain)
	mainHandle, err := buildHTTPHandleChain(rule, rule.Upstreams, ctx)
	if err != nil {
		return nil, nil, err
	}

	mainMatcher := map[string]interface{}{"host": domainHosts}
	mainRoute := map[string]interface{}{
		"match":    []interface{}{mainMatcher},
		"handle":   mainHandle,
		"terminal": true,
	}
	if rule.CaddyID != "" {
		mainRoute["@id"] = rule.CaddyID
	}

	routes := make([]map[string]interface{}, 0, len(rule.PathRules)+2)
	// GeoIP pass route runs before path rules and the main route: it resolves the
	// client region into {http.vars.geoip.*} placeholders AND X-LB-GeoIP-* request
	// headers. v2.2.0 地域拦截改走 coraza——BuildCorazaDirectives 的 GeoIP
	// SecRule（id:8）读取 X-LB-GeoIP-Loc，被拦请求产生 audit.log → 安全事件管线
	// （此前 Caddy 原生 block 路由 CEL+static_response 完全绕过 coraza，事件
	// 盲区）。pass 路由必须保留且先于主路由的 coraza 处理器执行，否则 headers
	// 未设置、地域规则恒不命中。至多一条（任一绑定启用策略带 geoip 即存在，
	// v2.2.0 多策略语义）。
	var geoipPassPolicy *models.SecurityPolicy
	crawlerExempt := false
	for _, policy := range policiesForRule(ctx, rule.CaddyID) {
		if PolicyHasGeoIP(policy) {
			if geoipPassPolicy == nil {
				geoipPassPolicy = policy
			}
			// 渲染门控——任一绑定策略启用爬虫豁免时，geoip handler 才
			// 做 PTR/DNS 验证（豁免/伪装规则只在该策略链上发射）。
			if policy.GeoIPCrawlerExempt {
				crawlerExempt = true
			}
		}
	}
	if geoipPassPolicy != nil {
		// GeoIP pass 路由补挂 @id（caddyID_geoip）——此前无 @id，
		// GetRuleCaddyConfig 的兄弟路由收集与规则删除清理均无法识别。
		geoipRoute := buildGeoipPassRoute(domainHosts, crawlerExempt)
		tagRuleRoute(geoipRoute, rule.CaddyID, "geoip")
		routes = append(routes, geoipRoute)
	}
	if rule.CustomRoutesEnabled {
		pathRules := append([]PathRuleConfig(nil), rule.PathRules...)
		sort.SliceStable(pathRules, func(i, j int) bool {
			return pathRules[i].SortOrder < pathRules[j].SortOrder
		})
		for pathIndex, pathRule := range pathRules {
			// 直接返回/301 跳转（2026-10-10 用户裁定）：不经安全链/改写/reverse_proxy
			// （无上游可代理，静态响应天然无后端攻击面；安全策略不覆盖此类路径）。
			// 链首补 lb_rule_metrics 纯计数——指标不属于
			// 安全链，不修时规则全量流量指标漏计该类路径流量（指标页失真）。
			if pathRule.ResponseMode == "static" || pathRule.ResponseMode == "redirect" {
				staticRoute := map[string]interface{}{
					"match": []interface{}{map[string]interface{}{"host": domainHosts, "path": pathMatcherSpecs(pathRule)}},
					"handle": []interface{}{
						map[string]interface{}{"handler": "lb_rule_metrics", "rule": rule.CaddyID},
						buildStaticResponseHandler(pathRule),
					},
					"terminal": true,
				}
				tagRuleRoute(staticRoute, rule.CaddyID, fmt.Sprintf("path_%d", pathIndex))
				routes = append(routes, staticRoute)
				continue
			}
			upstreams := pathRule.Upstreams
			// 空数组与 nil 统一回退主上游——DB 中 upstreams_json="[]"
			// 的存量路径规则此前因 `upstreams == nil` 不成立而走 buildHTTPHandleChain
			// 硬失败（预校验特判放行、全量渲染失败的不对称），修复后两者语义一致。
			if len(upstreams) == 0 {
				upstreams = rule.Upstreams
			}
			handle, handleErr := buildHTTPHandleChain(rule, upstreams, ctx)
			if handleErr != nil {
				return nil, nil, handleErr
			}
			handle = insertUpstreamPathRewrites(handle, pathRule)
			matcher := map[string]interface{}{
				"host": domainHosts,
				"path": pathMatcherSpecs(pathRule),
			}
			pathRoute := map[string]interface{}{
				"match":    []interface{}{matcher},
				"handle":   handle,
				"terminal": true,
			}
			tagRuleRoute(pathRoute, rule.CaddyID, fmt.Sprintf("path_%d", pathIndex))
			routes = append(routes, pathRoute)
		}
	}
	routes = append(routes, mainRoute)
	return routes, mainRoute, nil
}

func tagRuleRoute(route map[string]interface{}, ruleID, suffix string) {
	if ruleID != "" {
		route["@id"] = ruleID + "_" + suffix
	}
}

func pathMatcherSpecs(pathRule PathRuleConfig) []string {
	if pathRule.MatchType != "prefix" {
		return []string{pathRule.Path}
	}
	root := pathPrefixRoot(pathRule.Path)
	if root == "" {
		return []string{"/*"}
	}
	return []string{root, root + "/*"}
}

// pathPrefixRoot 归一路径规则前缀根（剥尾部 / 与 *，与校验侧 canonicalPath
// 同源）；root 为空即「匹配一切」形态（path / 或 /*）。
func pathPrefixRoot(path string) string {
	return strings.TrimRight(path, "/*")
}

// insertUpstreamPathRewrites 在链内最后一个 reverse_proxy 之前插入上游 path
// 改写 handler。形状经 caddy 2.11.4 容器行为实证：
//   - 前缀匹配：先 strip_path_prefix 剥匹配前缀根（root 空则无可剥，跳过），
//     再 rewrite uri 前置 upstream_path——/api/users?x=1 → /v1/users?x=1；
//   - 精确匹配：单一 rewrite uri 整体替换——/old?a=b → /new?a=b（引擎保留
//     query；strip+前置形态会产生多余尾斜杠，实证后弃用）；
//
// 两个 rewrite 均插在 reverse_proxy 之前：安全段（预检/压缩/限流/WAF）与
// 指标计数仍检原始 URI。空 upstream_path 零插入（链与现状逐字节一致）。
func insertUpstreamPathRewrites(handle []interface{}, pathRule PathRuleConfig) []interface{} {
	rewrites := upstreamPathRewriteHandlers(pathRule)
	if len(rewrites) == 0 {
		return handle
	}
	proxyIndex := -1
	for index := len(handle) - 1; index >= 0; index-- {
		if handler, ok := handle[index].(map[string]interface{}); ok && handler["handler"] == "reverse_proxy" {
			proxyIndex = index
			break
		}
	}
	if proxyIndex < 0 {
		// 链尾恒为 reverse_proxy（buildHTTPHandleChain 契约）；无 proxy 时
		// 原样返回，不产生无法执行的改写链。
		return handle
	}
	rewritten := make([]interface{}, 0, len(handle)+len(rewrites))
	rewritten = append(rewritten, handle[:proxyIndex]...)
	rewritten = append(rewritten, rewrites...)
	rewritten = append(rewritten, handle[proxyIndex:]...)
	return rewritten
}

// buildStaticResponseHandler 渲染路径规则的直接返回/301 跳转 handler（全原生
// http.handlers.static_response）：redirect=301+Location（目标经校验侧形状门）；
// static=status_code+body+，缺省兜底 200/text/plain。
// static_response 的 headers 值与 body 在
// 运行时经 Caddy replacer 展开已知占位符（v2.11.6 staticresp.go:193-208 实证，
// ReplaceKnown）——redirect_to/body 中的 {http.request.uri} 等会被改写为请求
// 值（与 httpsRedirectLocation 的占位符用法同引擎机制）。校验侧有意不拒 '{'
// （保路径跳转的合法占位符用法），审计不重报。
func buildStaticResponseHandler(pathRule PathRuleConfig) map[string]interface{} {
	if pathRule.ResponseMode == "redirect" {
		return map[string]interface{}{
			"handler":     "static_response",
			"status_code": 301,
			"headers":     map[string]interface{}{"Location": []string{pathRule.RedirectTo}},
		}
	}
	status := pathRule.ResponseStatus
	if status <= 0 {
		status = 200
	}
	contentType := pathRule.ResponseContentType
	if contentType == "" {
		contentType = "text/plain"
	}
	return map[string]interface{}{
		"handler":     "static_response",
		"status_code": status,
		"body":        pathRule.ResponseBody,
		"headers":     map[string]interface{}{"Content-Type": []string{contentType}},
	}
}

func upstreamPathRewriteHandlers(pathRule PathRuleConfig) []interface{} {
	if pathRule.UpstreamPath == "" {
		return nil
	}
	rewrites := make([]interface{}, 0, 2)
	if pathRule.MatchType == "prefix" {
		if root := pathPrefixRoot(pathRule.Path); root != "" {
			rewrites = append(rewrites, map[string]interface{}{
				"handler":           "rewrite",
				"strip_path_prefix": root,
			})
		}
	}
	// 前缀分支的 upstream_path 尾斜杠会与剥前缀后的原 URI
	// （以 / 开头）拼成双斜杠（`/v1/` + `/users` = `/v1//users`）——Go ServeMux
	// 301 清洗、严格框架 404；校验侧允许尾斜杠（仅要求前导 / 且无空白?#），故在
	// 拼接前剥除。精确匹配为整体替换、尾斜杠有目录语义，保持原样。
	base := pathRule.UpstreamPath
	if pathRule.MatchType == "prefix" {
		base = strings.TrimRight(base, "/")
	}
	rewrites = append(rewrites, map[string]interface{}{
		"handler": "rewrite",
		"uri":     base + prefixURIPlaceholder(pathRule),
	})
	return rewrites
}

// prefixURIPlaceholder 前缀匹配把剥前缀后的原始 URI（含 query）接到
// upstream_path 之后；精确匹配整体替换，无占位符（query 由引擎保留）。
func prefixURIPlaceholder(pathRule PathRuleConfig) string {
	if pathRule.MatchType == "prefix" {
		return "{http.request.uri}"
	}
	return ""
}

// SplitDnsAddresses 把 dns_server 字段按逗号（含中文逗号）拆分为多地址——
// 用户输入 "10.50.29.3,10.50.15.4" 曾渲染为单元素数组导致 Caddy 解析失败。
func SplitDnsAddresses(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == ' ' || r == ';'
	}) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinUpstreamAddress(host string, port int) string {
	// 渲染侧与写侧同口径归一首尾空白——历史行/直改 DB 的
	// " up.test" 会渲染成非法 dial（该上游恒 502）。主机名/IP 字面量不含
	// 有意义空白，TrimSpace 不改变合法配置。
	return net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))
}

// stripOriginPort 剥离 host:port 形态的端口（SNI 不得含端口）；无端口形态
// （含裸 IPv6 字面量）原样返回。渲染期预计算 map outputs 第二值专用。
func stripOriginPort(host string) string {
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		return hostOnly
	}
	return host
}

// blockStatusForPolicy 返回策略段的中断抬码（阶段化模型）：规则配了阶段 3
// 拦截页（id>0 且页内容非空）→ 恒 482（规则级覆盖层压过逐策略归因）；否则
// 该策略在生成上下文中的合成中断码（483+，拦截页逐策略归因默认层）；无批量
// 上下文（非批量生成路径）或策略未分配（无有效页/超区间上限）时返回 0——
// BuildCorazaDirectives 逐字节保持现状（403/缺省）。
func blockStatusForPolicy(securityCtx *securityPolicyContext, rule SingleRuleConfig, policy *models.SecurityPolicy) int {
	if securityCtx == nil || policy == nil {
		return 0
	}
	if rule.BlockPageStage3ID > 0 && securityCtx.blockPageByID[rule.BlockPageStage3ID] != "" {
		return blockPageStage3Code
	}
	return securityCtx.policySynthetic[policy.ID]
}

// stage1BlockStatus 返回阶段 1（预检）的中断抬码：规则配了阶段 1 拦截页
// （id>0 且页内容非空）→ 481，否则 0（预检保持 403 兜底归因边界）。
func stage1BlockStatus(securityCtx *securityPolicyContext, rule SingleRuleConfig) int {
	if securityCtx == nil || rule.Protocol != "http" {
		return 0
	}
	if rule.BlockPageStage1ID > 0 && securityCtx.blockPageByID[rule.BlockPageStage1ID] != "" {
		return blockPageStage1Code
	}
	return 0
}

// blockPageContentType 渲染处归一：空值回退默认 html；白名单
// 双保险——带外通道（备份导入/集群快照）落库的
// 白名单外值同样归一默认，杜绝 CRLF 等脏值原样渲染进响应头。
func blockPageContentType(contentType string) string {
	if contentType == "" || !models.ValidBlockPageContentType(contentType) {
		return models.DefaultBlockPageContentType
	}
	return contentType
}

// buildBlockPageAttributionRoute 返回一条按策略/规则归因的错误路由：matcher
// 为合成中断码 + interruption 消息，hosts 非空时追加 host 限定（规则级 481/482
// 必须按规则域名隔离；逐策略 483+ 传 nil，保持全局唯一）。static_response
// 渲染对应拦截页内容与配置状态码（0 归一 403）。
func buildBlockPageAttributionRoute(synthetic int, hosts []string, content string, statusCode int, contentType string) map[string]interface{} {
	if statusCode == 0 {
		statusCode = 403
	}
	matcher := map[string]interface{}{
		"expression": fmt.Sprintf("({http.error.status_code} == %d && {http.error.message} == 'interruption triggered')", synthetic),
	}
	if len(hosts) > 0 {
		matcher["host"] = hosts
	}
	return map[string]interface{}{
		"match": []interface{}{matcher},
		"handle": []interface{}{
			map[string]interface{}{
				"handler":     "static_response",
				"body":        content,
				"status_code": statusCode,
				"headers": map[string]interface{}{
					"Content-Type": []string{blockPageContentType(contentType)},
				},
			},
		},
		"terminal": true,
	}
}

func decodePathUpstreams(raw string) ([]UpstreamConfig, error) {
	var stored []struct {
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Weight   int    `json:"weight"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return nil, err
	}
	upstreams := make([]UpstreamConfig, 0, len(stored))
	for _, item := range stored {
		protocol := item.Protocol
		if protocol == "" {
			protocol = "http"
		}
		upstreams = append(upstreams, UpstreamConfig{
			Host: strings.TrimSpace(item.Address), Port: item.Port, Weight: item.Weight, Protocol: protocol, Enabled: true,
		})
	}
	return upstreams, nil
}

// buildBlockPageErrorRoute 是拦截页归因后的**兜底**错误路由（403 通用，
// host 限定本规则域名）：渲染首绑定（最低 policy_id）配置了拦截页的启用
// 策略的页面。承接两类无法归因到单策略的中断——多策略 IP 预检的合并拦截
// （buildIPPrecheckDirectives 保持 status:403，见该函数注释）与未分配合成
// 码策略（无有效页/超区间上限）的 deny 中断；已分配合成码策略的中断由
// buildBlockPageAttributionRoute 的逐策略路由承接。无绑定启用策略配置
// 拦截页或页内容为空时返回 nil。策略与页内容来自批量预载 securityCtx，
// 事务内生成可见未提交的策略变更。
func buildBlockPageErrorRoute(ruleCaddyID string, domainHosts []string, securityCtx *securityPolicyContext) map[string]interface{} {
	policies := policiesForRule(securityCtx, ruleCaddyID)
	// 首个绑定拦截页的策略若页面内容为空（页面行已
	// 删除），不得遮蔽后续仍有效页的策略——按绑定序取首个「内容非空」的页。
	var pagePolicy *models.SecurityPolicy
	var content string
	for _, policy := range policies {
		if policy.BlockPageID > 0 {
			if c := securityCtx.blockPageByID[policy.BlockPageID]; c != "" {
				pagePolicy = policy
				content = c
				break
			}
		}
	}
	if pagePolicy == nil {
		return nil
	}
	statusCode := pagePolicy.BlockStatusCode
	if statusCode == 0 {
		statusCode = 403
	}
	// 全部 coraza 命中（CRS/自定义/IP ACL/GeoIP 地域拦截）恒以 403 +
	// "interruption triggered" 中断，共用本子句 → 品牌拦截页按策略配置状态码
	// 渲染（v2.2.0 GeoIP 改走 coraza 后不再有独立的 "GeoIP blocked" 中断形态，
	// 逐策略 geoip 状态码并集子句随之移除）。
	expression := "({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered')"
	return map[string]interface{}{
		"match": []interface{}{
			map[string]interface{}{
				"host":       domainHosts,
				"expression": expression,
			},
		},
		"handle": []interface{}{
			map[string]interface{}{
				"handler":     "static_response",
				"body":        content,
				"status_code": statusCode,
				"headers": map[string]interface{}{
					"Content-Type": []string{blockPageContentType(securityCtx.blockPageTypeByID[pagePolicy.BlockPageID])},
				},
			},
		},
		"terminal": true,
	}
}

// buildRateLimitErrorRoute returns a server-level error route rendering the
// block page of the rule's first-bound enabled policy that configures one for
// rate-limited (429) requests, or nil when no bound enabled policy enables
// rate limiting or none has a block page.
// caddy-ratelimit rejects via caddyhttp.Error(429), so handle_errors fires.
func buildRateLimitErrorRoute(ruleCaddyID string, domainHosts []string, securityCtx *securityPolicyContext) map[string]interface{} {
	policies := policiesForRule(securityCtx, ruleCaddyID)
	rateLimited := false
	// 同 buildBlockPageErrorRoute——空内容页不遮蔽
	// 后续有效页。
	var pagePolicy *models.SecurityPolicy
	var content string
	for _, policy := range policies {
		if policy.RateLimitEnabled {
			rateLimited = true
		}
		if pagePolicy == nil && policy.BlockPageID > 0 {
			if c := securityCtx.blockPageByID[policy.BlockPageID]; c != "" {
				pagePolicy = policy
				content = c
			}
		}
	}
	if !rateLimited || pagePolicy == nil {
		return nil
	}
	// 限流拦截恒 429（不再取策略 BlockStatusCode）：429 Too Many Requests 是
	// 限流的语义正确状态码，且使 caddy_http_requests_total{code="429"} 可单独
	// 计量——Wave 6 状态统一后 403 与 WAF 拦截在指标中同形不可区分（实测：
	// 错误路由响应继承主路由 handler 标签，无任何其他区分维度）。拦截页正文
	// 不变（客户端体验一致），按限流 1s 窗口给出重试契约。
	return map[string]interface{}{
		"match": []interface{}{
			map[string]interface{}{
				"host":       domainHosts,
				"expression": "{http.error.status_code} == 429",
			},
		},
		"handle": []interface{}{
			map[string]interface{}{
				"handler":     "static_response",
				"body":        content,
				"status_code": 429,
				"headers": map[string]interface{}{
					"Content-Type": []string{blockPageContentType(securityCtx.blockPageTypeByID[pagePolicy.BlockPageID])},
					"Retry-After":  []string{"1"},
				},
			},
		},
		"terminal": true,
	}
}

// buildRateLimitHandler returns the rate_limit handler for one bound policy of
// a rule, or nil when that policy does not enable rate limiting. Zones are
// logical AND: with burst > 0 a per-second zone caps instantaneous rate at
// rps+burst while a per-minute zone caps sustained rate at rps; without burst a
// single per-second zone caps at rps.
// zone 键必须嵌入 policy_id：caddy-ratelimit 的 UsagePool 按 zone 名进程级共享
// 计数器，同规则多策略（v2.2.0）若共用 {ruleID} 前缀会静默合并计数。
// 库值唯一真相（批 3）：rate_limit_rps 类型①值型列（条件消费——rate_limit_
// enabled 独立开关）写侧 400（rps>=1，validateRateLimitShape）+ 导入门 400
// 保证 enabled 行恒有效；enabled=1 且 rps<=0（带外/旧数据）显性报错，废除原
// 「rps<=0 静默 return nil」的 fail-open——UI 宣称限流启用而实际零强制。
func buildRateLimitHandler(ruleCaddyID string, policy *models.SecurityPolicy) (map[string]interface{}, error) {
	if policy == nil || !policy.RateLimitEnabled {
		return nil, nil
	}
	if policy.RateLimitRPS <= 0 {
		return nil, fmt.Errorf("规则 %s 绑定策略 %q 限流已启用但 rate_limit_rps 无效（%d <=0）：该列为类型①值型列（写侧 rps>=1 校验+导入门 400 拒收+启动归一关停 enabled=1&rps<1 的历史脏行），疑似带外直写或旧备份绕过导入门", ruleCaddyID, policy.Name, policy.RateLimitRPS)
	}
	// sweep_interval 是 caddy-ratelimit Handler 层字段（默认 1m），
	// 不是 zone 字段——Caddy v2.11.4 对模块载荷 StrictUnmarshalJSON+
	// DisallowUnknownFields，zone 级未知字段会使整个配置加载 400（开启限流
	// 即配置停摆）。移到 handler 层（合法字段，10m 扫描周期语义保留）。
	zonePrefix := fmt.Sprintf("%s-p%d", ruleCaddyID, policy.ID)
	rateLimits := map[string]interface{}{
		zonePrefix: map[string]interface{}{
			// v2.3.x：{http.vars.client_ip}（受信代理启用时=真实 IP，未启用=socket IP，行为不变）。
			"key":        "{http.vars.client_ip}",
			"window":     "1s",
			"max_events": policy.RateLimitRPS,
		},
	}
	if policy.RateLimitBurst > 0 {
		rateLimits = map[string]interface{}{
			// v2.3.x：key 同为 {http.vars.client_ip}（与单 zone 分支同口径）。
			zonePrefix + "-sec": map[string]interface{}{
				"key":        "{http.vars.client_ip}",
				"window":     "1s",
				"max_events": policy.RateLimitRPS + policy.RateLimitBurst,
			},
			zonePrefix + "-min": map[string]interface{}{
				"key":        "{http.vars.client_ip}",
				"window":     "60s",
				"max_events": policy.RateLimitRPS * 60,
			},
		}
	}
	return map[string]interface{}{
		"handler":        "rate_limit",
		"rate_limits":    rateLimits,
		"sweep_interval": "10m",
	}, nil
}

// buildGeoipHandler returns the geoip2region handler, or nil when geoip is disabled.
// buildGeoipHandler 渲染 geoip2region handler；crawlerExempt 为规则级门控
// （任一绑定策略 GeoIPCrawlerExempt）——caddygeoip 在 false 时只剥
// 客户端伪造的验证头、不做 PTR/DNS 验证。
// xdb 与爬虫快照路径随 data_dir 派生（ConfigureWafDirs
// 单点真源），仅在派生值不同于插件 Provision 兜底默认时显式发射对应键——
// 容器默认形态渲染字节不变（loadConfig 同字节短路依赖 handler 字节稳定，
// 见 errSameConfig 注释），插件默认即生效；自定义 data_dir 形态显式发射，
// 否则插件恒读 /app/data/...（写读分叉，GeoIP/爬虫豁免静默失效）。
func buildGeoipHandler(crawlerExempt bool) map[string]interface{} {
	h := map[string]interface{}{"handler": "geoip2region", "crawler_exempt": crawlerExempt}
	if ip2regionLivePath != defaultIP2RegionLivePath {
		h["xdb_path"] = ip2regionLivePath
	}
	if crawlerIPListFile != defaultCrawlerIPListFile {
		h["crawler_ip_list_file"] = crawlerIPListFile
	}
	return h
}

// buildGeoipPassRoute populates the region placeholders before the block matcher evaluates.
func buildGeoipPassRoute(domainHosts []string, crawlerExempt bool) map[string]interface{} {
	return map[string]interface{}{
		"match":  []interface{}{map[string]interface{}{"host": domainHosts}},
		"handle": []interface{}{buildGeoipHandler(crawlerExempt)},
	}
}

// geoipPrivateRanges 内网/回环/链路本地 CIDR 集合。这些地址无法经 ip2region 解析到国家，
// fail-closed 会将其误判为“海外”而拦截，故在 GeoIP 拦截中一律放行（无论 deny/allow 模式）。
// v2.2.0 地域拦截改走 coraza 后由 BuildCorazaDirectives 的 GeoIP SecRule 链首
// REMOTE_ADDR !@ipMatch 引用（语义不变）。
// ::ffff: 前缀条目仅为 IPv4 映射的私网/回环/链路本地地址（双栈 RemoteAddr 的 16 字节形态），
// 而非整个 ::ffff:0:0/96 映射空间——否则公网映射地址（如 ::ffff:8.8.8.8）也会被误放行。
var geoipPrivateRanges = []string{
	"10.0.0.0/8",             // RFC1918 私网 A 类
	"172.16.0.0/12",          // RFC1918 私网 B 类
	"192.168.0.0/16",         // RFC1918 私网 C 类
	"127.0.0.0/8",            // IPv4 回环
	"169.254.0.0/16",         // IPv4 链路本地
	"::ffff:10.0.0.0/104",    // IPv4 映射私网 A 类（10.0.0.0/8）
	"::ffff:172.16.0.0/108",  // IPv4 映射私网 B 类（172.16.0.0/12）
	"::ffff:192.168.0.0/112", // IPv4 映射私网 C 类（192.168.0.0/16）
	"::ffff:127.0.0.0/104",   // IPv4 映射回环（127.0.0.0/8）
	"::ffff:169.254.0.0/112", // IPv4 映射链路本地（169.254.0.0/16）
	"::1/128",                // IPv6 回环
	"fc00::/7",               // IPv6 唯一本地地址 (ULA)
	"fe80::/10",              // IPv6 链路本地
}

func buildHTTPHandleChain(rule SingleRuleConfig, upstreams []UpstreamConfig, securityCtx ...*securityPolicyContext) ([]interface{}, error) {
	var ctx *securityPolicyContext
	if len(securityCtx) > 0 {
		ctx = securityCtx[0]
	}
	enabledUpstreams := make([]UpstreamConfig, 0, len(upstreams))
	for _, upstream := range upstreams {
		if upstream.Enabled {
			enabledUpstreams = append(enabledUpstreams, upstream)
		}
	}
	if len(enabledUpstreams) == 0 {
		return nil, fmt.Errorf("%w", ErrNoEnabledUpstreams)
	}
	if rule.DynamicDNS && len(enabledUpstreams) > 1 {
		return nil, fmt.Errorf("%w, got %d", ErrDynamicDNSUpstreamCount, len(enabledUpstreams))
	}

	policies := policiesForRule(ctx, rule.CaddyID)
	// WAF 发射读取 security_custom_rules 必须与策略预载同 store——
	// 无 ctx（非批量路径）时传 nil，由 resolvePolicyCustomRules 回退 db.DB。
	var policyStore caddyConfigStore
	var scopedCache scopedCRSListCache
	if ctx != nil {
		policyStore = ctx.store
		scopedCache = ctx.scopedListCache
	}
	var handleChain []interface{}
	// （v2.2.3）：链首注入 X-LB-Rule-ID——安全事件归因的一等信号（摄入侧优先
	// 读头、回退 host 反查，同域名多规则/通配符场景归因从概率正确到确定正确）。
	// 置于 IP 预检之前，预检与各策略 coraza 事务均可见；set 覆盖客户端伪造值；
	// reverse_proxy 前无条件剥离（见 proxyRequestHeaders 删除清单），不直达上游。
	if rule.Protocol == "http" && len(policies) > 0 {
		handleChain = append(handleChain, map[string]interface{}{
			"handler": "headers",
			"request": map[string]interface{}{"set": map[string]interface{}{"X-LB-Rule-ID": []string{rule.CaddyID}}},
		})
	}
	// 规则级全量流量指标(2026-09-15 用户裁定):lb_rule_metrics 置于链首
	// (headers 之后,blocked counter/预检/压缩/限流/全部策略 waf 之前)——
	// 包装链全流量,caddy_id 直接作 label(替代域名/host 匹配,通配符/
	// 大小写/IDNA/多域名/空域名全部天然正确);全 HTTP 规则覆盖(不限策略)。
	if rule.Protocol == "http" {
		handleChain = append(handleChain, map[string]interface{}{
			"handler": "lb_rule_metrics",
			"rule":    rule.CaddyID,
		})
	}
	// 安全拦截计数(2026-09-15 用户裁定,方案 B):lb_security_blocked_counter
	// 置于链首(headers 之后,IP 预检/压缩/限流/全部策略 waf 之前)——包装
	// 全部 coraza handler(IP 预检的 IP ACL/GeoIP 中断也在内),检测 coraza
	// 中断(HandlerError 携 ID+4xx)按规则计数;限流 429 经 status==429
	// 分支计入(424a400e 后;非 coraza tx.ID 但 caddyhttp.Error 生成 ID)。
	// 可用性与缺失描述必须复用同一次探测：SecurityLibraryStatus 含 rules 树
	// WalkDir + xdb stat，此前无条件先探一次（批量路径随即用 ctx 结论覆盖，
	// 白跑 N 次；单规则路径再经缺失描述重探 1~2 次）。
	var securityLibsOK bool
	var securityLibsMissing string
	if ctx != nil {
		// 批量路径：随生成上下文一次计算的结论（同一份配置内全部规则
		// 共享同一可用性判定，消除逐规则重探与半链窗口）。
		securityLibsOK = ctx.securityLibsOK
		securityLibsMissing = ctx.securityLibsMissingDesc()
	} else {
		crsOK, ip2regionOK := SecurityLibraryStatus()
		securityLibsOK = crsOK && ip2regionOK
		if !securityLibsOK {
			securityLibsMissing = securityLibrariesMissingDesc(crsOK, ip2regionOK)
		}
	}
	// 补 securityLibsOK(与 timing_pre/end 同口径)——库缺失时
	// 链上无 coraza 收点,counter 的 timing ID 注入与拦截计数均无意义。
	if securityLibsOK && rule.Protocol == "http" && len(policies) > 0 {
		handleChain = append(handleChain, map[string]interface{}{
			"handler": "lb_security_blocked_counter",
			"rule":    rule.CaddyID,
		})
	}
	// 阶段 1（IP 访问控制+地域拦截）：合并预检 coraza 置于链首（先于全部
	// rate_limit/waf）——被拒 IP/区域在任何策略的 CRS/自定义规则评估前即中断，
	// 不再产生前置策略的检测事件。阶段化模型（2026-09-20）：单策略同构走预检
	// （GeoIP 已迁入预检 800000+ 段；ACL 并集与策略引擎 id:2/4 幂等重复无害——
	// 预检先拦，引擎内不再命中；信任 IP 在预检 DetectionOnly 后到策略引擎按
	// 现状记录）。预检仍是 coraza 拒绝：audit log 留痕供安全事件管线归因；
	// 规则配了阶段 1 拦截页时全部 deny 抬码 481（stage1BlockStatus），否则
	// 403 → errors 路由 → 拦截页。
	// 阶段 0 信任名单（2026-09-20 用户裁定）：直通（trust_detection=0）时安全
	// 段（预检/压缩/请求体限额/限流/全部 WAF 引擎）整体包进
	// 「not remote_ip ∈ 信任并集」的 subroute——信任 IP 流程
	// headers→metrics→counter→(subroute 跳过)→reverse_proxy 直达上游，
	// 零安全事件（不产生任何 coraza 事务）；保留检测（trust_detection=1）
	// 无此包裹，信任 IP 经预检/引擎 id:12 DetectionOnly 全评估全记录。
	// 缺库降级（2026-09-24 用户裁定）：CRS/IP2Region 库缺失时全部安全规则不
	// 渲染（预检/ACL/限流/WAF/GeoIP 一并缺席），告警日志提示补库——coraza
	// Include 缺失文件会使整份配置被 caddy validate 拒绝，负载均衡也被拖死。
	var detectionTrust []string
	var passthroughUnion []string
	if securityLibsOK {
		detectionTrust, passthroughUnion = stage0TrustSets(policies)
		// 始终发射收敛（2026-10-15）：id:12 发射面 flag 以 hasStage0TrustDetection
		// 为准（AggregateIPEntries 空输入返回非 nil 空切片，nil-ness 不可作
		// flag）——保留检测策略在而并集为空时以非 nil 空切片传递（id:12 恒
		// 发射，空文件算子永不命中，空↔非空纯内容变化走热路径）；无保留检测
		// 策略强制 nil（不发射）。
		if hasStage0TrustDetection(policies) {
			if len(detectionTrust) == 0 {
				detectionTrust = []string{}
			}
		} else {
			detectionTrust = nil
		}
	} else if rule.Protocol == "http" && len(policies) >= 1 {
		if ctx != nil {
			// 每次生成一条（而非逐规则一条）：描述来自生成上下文的一次探测。
			ctx.securityLibsWarnOnce.Do(func() {
				Logf("warn", "安全规则库缺失（%s），本次生成的全部规则安全链不渲染", securityLibsMissing)
			})
		} else {
			Logf("warn", "安全规则库缺失（%s），规则 %s 的所有安全规则本次渲染不生效", securityLibsMissing, rule.CaddyID)
		}
	}
	var securityChain []interface{}
	if securityLibsOK && rule.Protocol == "http" && len(policies) >= 1 {
		// 单行护栏错误（48KiB 超限）向上传播——保存侧经 CLI 校验/事务门控回滚。
		// rule.CaddyID：u-* 投影 scope 编入规则身份。
		precheckHandler, err := buildIPPrecheckHandler(policies, stage1BlockStatus(ctx, rule), rule.CaddyID, ctx)
		if err != nil {
			return nil, err
		}
		if precheckHandler != nil {
			securityChain = append(securityChain, precheckHandler)
		}
		// 预检段耗时收点(2026-09-27 分段计时):预检之后、body/限流/WAF 之前——
		// 摄取管道预检段事件取 :pre,WAF 段取 :end-:pre(隔离 WAF 评估成本)。
		// 外层门已含 rule.Protocol=="http"，原嵌套同条件恒真已删；
		// 未来若新增非 http 链，由外层门统一守卫。
		securityChain = append(securityChain, map[string]interface{}{
			"handler": "lb_security_timing_pre",
		})
	}

	// (2026-09-10 审计):规则级压缩必须位于全部 waf 处理器之外侧(链序在前)
	// ——coraza 的响应拦截器包在 coraza handler 外层,encode 若在 waf 内侧,
	// 响应体规则(95x 响应检查)扫描的是压缩后字节,≥512B 可压缩响应恒不匹配
	// (coraza 全库无检查,grep 实证)。置于 headers/预检之后、
	// 策略组之前:请求向处理不受影响,响应向 encode 包在所有 coraza 拦截器外。
	if rule.EnableCompress && rule.CompressTypes != "" {
		encodings := make(map[string]interface{})
		for _, contentType := range splitAndTrim(rule.CompressTypes) {
			if contentType == "gzip" || contentType == "zstd" {
				encodings[contentType] = map[string]interface{}{}
			}
		}
		if len(encodings) > 0 {
			securityChain = append(securityChain, map[string]interface{}{
				"handler":        "encode",
				"encodings":      encodings,
				"minimum_length": 512,
			})
		}
	}
	// request_body 限额必须先于「会读取请求体的 waf 处理器」——策略级 coraza
	// 引擎在 phase:2 用 io.Copy 读体（自定义 body 规则 / CRS），受 coraza 默认
	// 128MiB 上限约束：用户限额 >128MiB 时该上限先于用户限额生效（128MiB 内
	// 全量缓冲后受限额拒绝，超大 body DoS 面收敛）。预检层（阶段 0/ACL/GeoIP 的
	// phase:1 REMOTE_ADDR 规则）本就先于本 handler，且其 directives 恒发
	// SecRequestBodyAccess Off、不读体，与本限额的相对顺序无关（注释不宣称
	// 「先于全部 waf 处理器」——预检是 WAF 处理器但不读体）。
	// 库值唯一真相（批 1+2）：有效值恒 >0（写侧 400+回填报证），无条件发射；
	// 无效即上方向错误。
	effectiveRequestBodyMaxSizeMB, effectiveUpstreamKeepaliveTimeout, effectiveServerTokensHidden, overridesErr := resolveRuleOverrides(rule)
	if overridesErr != nil {
		return nil, overridesErr
	}
	securityChain = append(securityChain, map[string]interface{}{
		"handler":  "request_body",
		"max_size": int64(effectiveRequestBodyMaxSizeMB) * 1024 * 1024,
	})
	// 阶段 2（限流）→ 阶段 3（WAF）：全部绑定启用策略（policy_id ASC）的
	// rate_limit 集中在所有 WAF 引擎之前（限流恒 429；被前位 WAF 拦的请求也
	// 消耗后位策略配额为已裁定口径），随后每策略独立 coraza 引擎（自定义规则
	// 审计 +：CRS 池指纹按渲染批次缓存——批量预载上下文在场时一次求值
	// 全批透传（同轮内 CRS 文件不会变，正确性零变化；R 条有策略规则从
	// R 次 SELECT+stat 收敛到 1 次）；无上下文路径（单规则预检等）退化为
	// 链内闭包缓存（每链至多一次——零安全策略/非 http 链零开销；http 链
	// 首个策略求值时计算（全 off 策略的 http 链
	// 仍付一次 SELECT+2×stat——实参求值在 buildWafHandlerWithPolicy 调用前，
	// 真惰性需改 BuildCorazaDirectives 签名,安全关键函数不值,裁定接受））。
	var chainFingerprint string
	needFingerprint := func() string {
		if ctx != nil {
			return ctx.crsPoolFingerprintCached()
		}
		if chainFingerprint == "" {
			chainFingerprint = crsPoolFingerprintForChain()
		}
		return chainFingerprint
	}
	if securityLibsOK {
		for _, policy := range policies {
			rateLimitHandler, rateLimitErr := buildRateLimitHandler(rule.CaddyID, policy)
			if rateLimitErr != nil {
				return nil, rateLimitErr
			}
			if rateLimitHandler != nil {
				securityChain = append(securityChain, rateLimitHandler)
			}
		}
	}
	for _, policy := range policies {
		if securityLibsOK && rule.Protocol == "http" {
			// 多策略时传
			// multiPolicy=true——策略层 IP ACL 改链式自排除本策略信任集:
			// 本策略信任 IP 由预检统一记录(事件去重),他策略信任 IP 照常拦截
			// (「信任仅豁免所属策略」边界);单策略保持平原形态(预检虽同构存在,
			// 但策略层自身信任 DetectionOnly 已正确处理,无跨策略信任边界)。
			wafHandler, err := buildWafHandlerWithIndex(rule.CaddyID, policy, policyStore, needFingerprint(), len(policies) > 1, blockStatusForPolicy(ctx, rule, policy), effectiveRequestBodyMaxSizeMB, detectionTrust, ctx.crsRuleIndex(), scopedCache)
			if err != nil {
				return nil, err
			}
			if wafHandler != nil {
				securityChain = append(securityChain, wafHandler)
			}
		}
	}
	// 安全处理耗时收点(2026-09-27 双点计时):放行事件的纯评估耗时在此记录
	// (blocked_counter 只计拦截事件——其 next 返回值混入上游代理往返不可用)。
	// 置于安全链末尾、reverse_proxy 之前;信任直通时随 subroute 整体跳过。
	// 发射面从「链非空」收窄为「有策略」（=counter
	// 在场同判据）——request_body 恒发射使旧判据对无策略规则也产 timing_end，
	// 而无 counter 的路由无服务端 timing ID 注入/覆盖，客户端伪造的计时头会
	// 直进进程内注册表（内存 DoS 面）；无 counter 即无任何计时写点。
	if securityLibsOK && rule.Protocol == "http" && len(policies) > 0 {
		securityChain = append(securityChain, map[string]interface{}{
			"handler": "lb_security_timing_end",
		})
	}
	// 直通包裹（阶段 0）：subroute 内层顺序与展平形态逐字节一致——非信任
	// 流量行为零漂移，信任流量短路到 reverse_proxy。
	if rule.Protocol == "http" && len(passthroughUnion) > 0 && len(securityChain) > 0 {
		handleChain = append(handleChain, map[string]interface{}{
			"handler": "subroute",
			"routes": []interface{}{map[string]interface{}{
				"match": []interface{}{map[string]interface{}{
					"not": []interface{}{map[string]interface{}{
						// v2.3.x：client_ip（受信代理启用时=真实 IP）替代
						// remote_ip（socket）——CDN 回源下信任名单按真实 IP 判定；
						// 未启用受信代理时二者同值，行为零变化。
						"client_ip": map[string]interface{}{"ranges": passthroughUnion},
					}},
				}},
				"handle": securityChain,
			}},
		})
	} else {
		handleChain = append(handleChain, securityChain...)
	}

	upstreamList := make([]interface{}, 0, len(enabledUpstreams))
	upstreamWeights := make([]int, 0, len(enabledUpstreams))
	hasHTTPSUpstream := false
	// 逐上游回源域名（2026-10-10，原生 map 方案）：dial→origin_domain 收敛表。
	// 仅静态模式收录——dynamic_dns 池 dial=解析后 IP（请求期才确定），静态映射
	// 永不命中（校验侧另 400 拒绝，此处为渲染守卫）；同 dial 重复条目首现生效
	// （map Validate 拒绝重复 input，map.go:107-115——保存侧查重之外的防御）。
	originDomains := make(map[string]string, len(enabledUpstreams))
	originDialOrder := make([]string, 0, len(enabledUpstreams))
	for _, upstream := range enabledUpstreams {
		weight := upstream.Weight
		if weight <= 0 {
			weight = 1
		}
		upstreamWeights = append(upstreamWeights, weight)
		if rule.DynamicDNS {
			versions := map[string]bool{"ipv4": false, "ipv6": false}
			switch rule.DnsFamily {
			case "ipv4":
				versions["ipv4"] = true
			case "ipv6":
				versions["ipv6"] = true
			case "both":
				versions["ipv4"] = true
				versions["ipv6"] = true
			}
			upstreamEntry := map[string]interface{}{
				"source":   "a",
				"name":     upstream.Host,
				"port":     fmt.Sprintf("%d", upstream.Port),
				"versions": versions,
			}
			if rule.EnableDnsServer && rule.DnsServer != "" {
				upstreamEntry["resolver"] = map[string]interface{}{
					"addresses": SplitDnsAddresses(rule.DnsServer),
				}
			}
			upstreamList = append(upstreamList, upstreamEntry)
		} else {
			dial := joinUpstreamAddress(upstream.Host, upstream.Port)
			entry := map[string]interface{}{"dial": dial}
			if upstream.MaxConnections > 0 {
				entry["max_requests"] = upstream.MaxConnections
			}
			if upstream.OriginDomain != "" {
				if _, dup := originDomains[dial]; !dup {
					originDomains[dial] = upstream.OriginDomain
					originDialOrder = append(originDialOrder, dial)
				}
			}
			upstreamList = append(upstreamList, entry)
		}
		if upstream.Protocol == "https" {
			hasHTTPSUpstream = true
		}
	}

	proxyConfig := map[string]interface{}{"handler": "reverse_proxy"}
	if rule.DynamicDNS {
		proxyConfig["dynamic_upstreams"] = upstreamList[0]
	} else {
		proxyConfig["upstreams"] = upstreamList
	}
	if rule.Strategy != "" {
		selectionPolicy := map[string]interface{}{"policy": rule.Strategy}
		if rule.Strategy == "cookie" {
			selectionPolicy["name"] = "lb_sticky"
		}
		// DynamicDNS 规则恰有 1 个启用上游（保存/启用/导入三链强制），
		// weighted_round_robin 会发射 weights=[1]——Caddy 的 WeightedRoundRobinSelection
		// 对 len(Weights)<2 直接早退返回 pool[0]（不做可用性检查，reverseproxy.go:637
		// 传入的动态解析池亦不过滤不可用主机，重试无失败记忆）→ 流量恒打解析列表
		// 首个 IP，其余 A 记录零流量、首 IP 宕机时 try_duration 内重试全撞同一 IP
		// 后 502。动态解析池与静态权重表天然错配——改用内建 random（按 Available()
		// 过滤后蓄水池随机），多 A 记录均衡与跨记录故障切换真正生效。
		if rule.DynamicDNS && rule.Strategy == "weighted_round_robin" {
			selectionPolicy = map[string]interface{}{"policy": "random"}
		} else if rule.Strategy == "weighted_round_robin" {
			selectionPolicy["weights"] = normalizeWeights(upstreamWeights)
		}
		// 重试窗口（方案 C，2026-10-12 裁定——HTTP 与 TCP 值域通用（[-1,60000]），
		// 但 td==0/-1 渲染语义按协议分叉）：td>0 → 按值发射窗口+间隔（tcp_try_interval
		// 为类型①值型列，<=0 即库值治理被带外写入破坏→显性报错，原 250ms 写死
		// 兜底废除）；HTTP 侧 td==0 → 保持现状兜底 5s/250ms（存量 HTTP 行恒 0，
		// 行为不变；反兜底扫描 allowlist 携 Ruling——render_anti_fallback_scan_test.go
		// buildHTTPHandleChain 条目）；HTTP 侧 td==-1 → 显式禁用重试——发射 retries=0 且不发射
		// try_duration/try_interval；TCP 侧 td==0/-1 均零窗口不发射（l4 proxy 无
		// retries 字段）。NTLM 接管态由 UI 修改器落 -1，渲染对 ntlm_compatible 零感知。
		loadBalancing := map[string]interface{}{
			"selection_policy": selectionPolicy,
		}
		if rule.TCPTryDuration > 0 {
			if rule.TCPTryInterval <= 0 {
				return nil, fmt.Errorf("规则 %s 重试间隔无效（tcp_try_interval=%d <=0，重试窗口 >0 时为必填值）", rule.CaddyID, rule.TCPTryInterval)
			}
			loadBalancing["try_duration"] = fmt.Sprintf("%dms", rule.TCPTryDuration)
			loadBalancing["try_interval"] = fmt.Sprintf("%dms", rule.TCPTryInterval)
		} else if rule.TCPTryDuration == -1 {
			loadBalancing["retries"] = 0
		} else {
			loadBalancing["try_duration"] = "5s"
			loadBalancing["try_interval"] = "250ms"
		}
		proxyConfig["load_balancing"] = loadBalancing
	}

	if rule.Protocol == "http" {
		// 库值唯一真相（批 1+2）：健康检查族为类型①值型列（NOT NULL DEFAULT+启动
		// 回填+写侧 400+导入归一门），渲染直读零兜底——<=0 即库值治理被带外写入
		// 破坏，显性报错使配置生成失败、旧配置保留（原 10s/3s/2s/2s 写死兜底废除）。
		if rule.HealthCheckInterval <= 0 {
			return nil, fmt.Errorf("规则 %s 健康检查间隔无效（health_check_interval=%d <=0）", rule.CaddyID, rule.HealthCheckInterval)
		}
		hcInterval := rule.HealthCheckInterval
		if rule.HealthCheckUnhealthyThreshold <= 0 {
			return nil, fmt.Errorf("规则 %s 健康检查失败阈值无效（health_check_unhealthy_threshold=%d <=0）", rule.CaddyID, rule.HealthCheckUnhealthyThreshold)
		}
		hcThreshold := rule.HealthCheckUnhealthyThreshold
		healthChecks := map[string]interface{}{
			"passive": map[string]interface{}{
				// 披露：被动熔断窗口复用主动探测间隔（fail_duration=interval*3），
				// 无独立配置项——interval=60s 时失败上游被熔断 180s，interval=1s
				// 时仅 3s。UI/文档未声明该耦合；如需独立控制需新增值型列
				// （schema+写侧+渲染三件套），当前裁定仅披露不新增。
				"fail_duration": fmt.Sprintf("%ds", hcInterval*3),
				"max_fails":     hcThreshold,
				// 5 是 Caddy 官方类码语义（StatusCodeMatches：configured<100 匹配整百段，
				// Caddyfile "5xx" 亦折叠为 5）——覆盖全部 500-599 服务端错误计入被动失败。
				// 2026-09 复审裁定 1：曾误改为显式 [500..504] 收窄覆盖（505-599 漏计），已恢复。
				"unhealthy_status": []int{5},
			},
		}
		if rule.EnableActiveHealthCheck {
			// hcPath 空串=「未配置路径」语义（渲染 /），字符串缺省非本批治理范围。
			hcPath := rule.HealthCheckPath
			if hcPath == "" {
				hcPath = "/"
			}
			if rule.HealthCheckHealthyThreshold <= 0 {
				return nil, fmt.Errorf("规则 %s 健康检查恢复阈值无效（health_check_healthy_threshold=%d <=0）", rule.CaddyID, rule.HealthCheckHealthyThreshold)
			}
			hcPasses := rule.HealthCheckHealthyThreshold
			if rule.HealthCheckTimeout <= 0 {
				return nil, fmt.Errorf("规则 %s 健康检查超时无效（health_check_timeout=%d <=0）", rule.CaddyID, rule.HealthCheckTimeout)
			}
			hcTimeout := rule.HealthCheckTimeout
			active := map[string]interface{}{
				"uri":      hcPath,
				"timeout":  fmt.Sprintf("%ds", hcTimeout),
				"interval": fmt.Sprintf("%ds", hcInterval),
				"passes":   hcPasses,
				"fails":    hcThreshold,
			}
			// 健康检查域名优先于规则级后端域名（probe Host 头特判实证，
			// healthchecks.go:453-458）；皆空则不输出 headers 键（现状不变）。
			probeHost := rule.HealthCheckHost
			if probeHost == "" {
				probeHost = rule.HostHeader
			}
			if probeHost != "" {
				active["headers"] = map[string]interface{}{"Host": []string{probeHost}}
			}
			healthChecks["active"] = active
		}
		proxyConfig["health_checks"] = healthChecks
	}

	timeouts := resolveProxyTimeouts(rule)
	if timeouts.stream > 0 {
		proxyConfig["stream_timeout"] = fmt.Sprintf("%ds", timeouts.stream)
	}
	if timeouts.flushInterval != 0 {
		proxyConfig["flush_interval"] = formatFlushInterval(timeouts.flushInterval)
	}
	if timeouts.streamCloseDelay > 0 {
		proxyConfig["stream_close_delay"] = fmt.Sprintf("%ds", timeouts.streamCloseDelay)
	}
	needsTransport := hasHTTPSUpstream || rule.EnableDnsServer || effectiveUpstreamKeepaliveTimeout > 0 || timeouts.dial > 0 || timeouts.responseHeader > 0 || timeouts.read > 0 || timeouts.write > 0
	if needsTransport {
		transportConfig := map[string]interface{}{"protocol": "http"}
		if hasHTTPSUpstream {
			// 逐上游回源域名在场时 SNI 改走占位符（server_name 占位符逐连接展开
			// 实证，httptransport.go:427-446）。已知限制：主动健康检查 probe 用
			// 全新 replacer（healthchecks.go:442），占位符不展开→probe 不发 SNI；
			// 项目恒 insecure_skip_verify，TLS 层不断（严格 SNI 多租户上游为边角）。
			// 静态路径同样剥端口（2026-10-10 用户裁定）：SNI 无端口语义（RFC 6066），
			// host_header 带端口时原样透传是畸形值；Host 头侧（:3760+）保留端口原样。
			serverName := stripOriginPort(rule.HostHeader)
			if len(originDomains) > 0 {
				serverName = "{lb.upstream_sni}"
			}
			transportConfig["tls"] = map[string]interface{}{
				"insecure_skip_verify": true,
				"server_name":          serverName,
			}
			if rule.UpstreamForceHTTP1 == 1 {
				// 上游强制 HTTP/1.1（通用列，2026-10-12）：Caddy HTTPTransport.Versions
				// （modules/caddyhttp/reverseproxy/httptransport.go）——限定协议版本集即
				// 禁用 h2（TLS 上游同时从 ALPN 剔除 h2）。语义比 tls.alpn_protocols 准确
				// （后者只影响 ALPN 握手、不管 h2c 协商）。仅 https 上游输出：
				// http 明文无 ALPN/协商面（用户裁定）。
				transportConfig["versions"] = []string{"1.1"}
			}
		}
		if rule.EnableDnsServer && rule.DnsServer != "" {
			transportConfig["resolver"] = map[string]interface{}{"addresses": SplitDnsAddresses(rule.DnsServer)}
		}
		if timeouts.dial > 0 {
			transportConfig["dial_timeout"] = fmt.Sprintf("%ds", timeouts.dial)
		}
		if timeouts.responseHeader > 0 {
			transportConfig["response_header_timeout"] = fmt.Sprintf("%ds", timeouts.responseHeader)
		}
		if timeouts.read > 0 {
			transportConfig["read_timeout"] = fmt.Sprintf("%ds", timeouts.read)
		}
		if timeouts.write > 0 {
			transportConfig["write_timeout"] = fmt.Sprintf("%ds", timeouts.write)
		}
		if effectiveUpstreamKeepaliveTimeout > 0 {
			transportConfig["keep_alive"] = map[string]interface{}{
				"idle_timeout": fmt.Sprintf("%ds", effectiveUpstreamKeepaliveTimeout),
			}
		}
		proxyConfig["transport"] = transportConfig
	}
	// X-LB-GeoIP-* 是 caddygeoip→coraza 的进程内控制头（coraza 在本 handler 之前
	// 执行，已消费完毕），绝不允许透传上游后端。无条件剥离：geoip 关闭的规则
	// 同时防客户端伪造同名头直达后端。头名清单与 caddygeoip/handler.go 的
	// geoipCorazaHeaders(caddygeoip/handler.go) 同源，变更需双侧同步。X-LB-Rule-ID 同型：链首注入的归因头
	//仅供 coraza 事务内消费，同口径无条件剥离。
	// 爬虫验证控制头（X-LB-Crawler-Verified / X-LB-Crawler-Spoof）
	// 同样由 caddygeoip 在 coraza phase:1 之前注入、coraza 预检规则已消费；
	// 与 geoip 头同口径**无条件**剥离——无 GeoIP 策略的规则（handler 不在场）
	// 下客户端伪造的同名头也绝不能直达上游。常量名与 caddygeoip/handler.go
	// 的 crawlerHeaderVerified/crawlerHeaderSpoof 同源。
	proxyRequestHeaders := map[string]interface{}{
		"delete": []string{
			"X-LB-GeoIP-Country", "X-LB-GeoIP-Country-Code", "X-LB-GeoIP-Region",
			"X-LB-GeoIP-Province", "X-LB-GeoIP-City", "X-LB-GeoIP-Loc",
			"X-LB-Rule-ID",
			"X-LB-Crawler-Verified", "X-LB-Crawler-Spoof",
			// 安全处理耗时关联头（v2.3.3）：blocked_counter 注入，coraza 审计
			// 日志收录后由审计写插件作进程内计时注册表关联键（耗时随
			// 审计行内嵌 lb_timing 流转）——coraza 之后链路不再需要,与
			// X-LB-Rule-ID 同机制剥离,不上泄上游。
			"X-Lb-Security-Timing-Id",
			"X-Lb-Security-Timing-Start-Ns",
		},
	}
	// 回源域名在场时 Host 头改走 map 占位符（defaults 已烘焙 host_header/透传
	// 回退链）；否则维持静态 host_header 或透传现状。
	if len(originDomains) > 0 {
		proxyRequestHeaders["set"] = map[string]interface{}{"Host": []string{"{lb.upstream_host}"}}
	} else if rule.HostHeader != "" {
		proxyRequestHeaders["set"] = map[string]interface{}{"Host": []string{rule.HostHeader}}
	}
	proxyConfig["headers"] = map[string]interface{}{"request": proxyRequestHeaders}
	if effectiveServerTokensHidden {
		handleChain = append(handleChain, map[string]interface{}{
			"handler": "headers",
			// deferred 必须为 true：非 deferred 的 response 头操作在路由调度阶段
			// （reverse_proxy 执行之前）应用，reverseproxy 的 copyHeader 复制上游
			// 响应头时会把上游的 Server 头重新写回，隐藏永远不生效；deferred 使
			// 删除推迟到上游响应写入之后（Caddy v2.11.4 headers.go + reverseproxy.go）。
			"response": map[string]interface{}{"deferred": true, "delete": []string{"Server"}},
		})
	}
	// 逐上游回源域名（2026-10-10）：内建 http.handlers.map 晚绑定查表——Source
	// {http.reverse_proxy.upstream.hostport} 在占位符被使用时才求值（map.go:138），
	// 恰为 reverse_proxy 选中上游后（reverseproxy.go:663-692：每次 attempt 先 Set
	// 上游占位符再展开 headers/transport，重试换上游逐次重展开）。defaults 回退链
	// 精确复现现状：Host=host_header 或池形态回退；SNI=host_header 剥端口或 dial
	// 主机名（stdlib 空 server_name 默认）。originDialOrder 保持上游 SELECT 序。
	// Host 回退按池形态分流——{http.request.
	// hostport} 绑原始请求（replacer.go:128-129），在 TLS 池恒为客户端 Host，
	// 不等于现状的 transport 注入 hostport；TLS 池改 {http.reverse_proxy.
	// upstream.hostport}（reverseproxy.go:664-668 先于 userOps 设置，可用）。
	if len(originDialOrder) > 0 {
		hostFallback := rule.HostHeader
		if hostFallback == "" {
			if hasHTTPSUpstream {
				hostFallback = "{http.reverse_proxy.upstream.hostport}"
			} else {
				hostFallback = "{http.request.hostport}"
			}
		}
		sniFallback := stripOriginPort(rule.HostHeader)
		if sniFallback == "" {
			sniFallback = "{http.reverse_proxy.upstream.host}"
		}
		mappings := make([]map[string]interface{}, 0, len(originDialOrder))
		for _, dial := range originDialOrder {
			origin := originDomains[dial]
			mappings = append(mappings, map[string]interface{}{
				"input":   dial,
				"outputs": []string{origin, stripOriginPort(origin)},
			})
		}
		handleChain = append(handleChain, map[string]interface{}{
			"handler":      "map",
			"source":       "{http.reverse_proxy.upstream.hostport}",
			"destinations": []string{"{lb.upstream_host}", "{lb.upstream_sni}"},
			"mappings":     mappings,
			"defaults":     []string{hostFallback, sniFallback},
		})
	}
	handleChain = append(handleChain, proxyConfig)
	return handleChain, nil
}

// ApplyConfigFromTx renders the Caddy config from an uncommitted transaction
// and applies it, keeping the database unchanged when Caddy rejects the config.
// rulesWrittenInTx：调用方事务是否写过 lb_rules（ACME 谓词 miss 补查门控）。
//
// 返回本次真实下发到 /load 的载荷字节（nil=同字节短路，无真实重载）。事务内
// apply 不写 last-known-good——apply 发生在 commit 之前，进程若在该窗口中断，
// 启动兜底会回放从未提交的配置；调用方必须在 tx.Commit() 成功后调
// PersistLastGoodBytesInLock(data) 补齐（零额外渲染）。
func (s *CaddyService) ApplyConfigFromTx(tx *sql.Tx, rulesWrittenInTx bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigWithOptions(generateCaddyConfigWithCertSource(tx, db.DB, rulesWrittenInTx), caddyApplyOptions{
		persistDegradation: false,
		persistLastGood:    false,
	})
}

// RefreshIPListProjectionsFromTxInLock 投影热路径（2026-10-15 用户裁定）：
// 名单-only 变更的零 /load 收敛——以事务视图全量渲染（投影文件为渲染副作用，
// 原子落盘新内容）后与运行配置做结构级比对：
//   - (Converged, nil)  字节一致且本轮渲染未物化证书 → 零发射面变化，投影已
//     落盘即收敛。零 /load，@ipListFast 匹配器按 mtime+size ≤1s stat 热感知
//     新内容。调用方提交后直接成功收尾，不落「重载」审计（审计真实性）。
//   - (NeedForce, nil)  字节一致但本轮渲染经 MaterializeCertPairs 物化了证书
//     文件（快照非空）——配置 JSON 因证书路径确定性而字节相同，errSameConfig
//     短路会让 Caddy 内存停留旧证书（「物化即有变⇒强制重载」在热路径
//     失守）。调用方必须走强制重载收敛
//     （GenerateAndApplyConfigForceInLock / ApplyConfigFromTxCertAwareForce）。
//   - (Fallback, nil)   字节不一致（发射面变化：仅剩否定算子/非投影面形态）或
//     运行配置不可读（无法证实零变化）→ 调用方回退既有全量渲染+应用链
//     （fail-open 与同字节短路同向：不轻率跳过 /load）。
//   - (_, err)          事务视图渲染被拒（生成失败）→ 调用方回退全量链得到
//     同口径拒绝（400+回滚，fail-closed 与 ApplyConfigFromTx 一致）。
//
// 始终发射收敛（2026-10-15 用户裁定）：空名单也投影空文件并恒发射 @ipListFast
// （空集=匹配器永不命中，与无规则语义等价）——收敛范围=发射面 flag 为真实
// opt-in 的名单（deny·绕过 ACL、stage0 保留检测），空↔非空与中段同为纯
// 内容变化全走热路径。信任名单（ip_whitelist_enabled 表默认值=1）、allow 模式
// （否定算子）、遗留黑名单维持内容门控。存量运行配置升级后首次渲染因发射面
// 新增触发一次全量重载，自愈收敛。
//
// 已持 caddyOpMu（=CaddyOpLock）的调用方使用（handlers 名单写路径全程持锁）；
// 锁内渲染与 ApplyConfigFromTx 同序，投影写盘与 /load 永不交错。
func (s *CaddyService) RefreshIPListProjectionsFromTxInLock(tx *sql.Tx) (IPListProjectionOutcome, error) {
	return s.refreshIPListProjectionsInLock(tx)
}

// RefreshIPListProjections 投影热路径的 DB 视图变体（后台任务用，威胁库更新
// 收敛——写库已完成，按已提交视图渲染）：自取 CaddyOpLock。返回语义同
// RefreshIPListProjectionsFromTxInLock。
func (s *CaddyService) RefreshIPListProjections() (IPListProjectionOutcome, error) {
	CaddyOpLock.Lock()
	defer CaddyOpLock.Unlock()
	return s.refreshIPListProjectionsInLock(db.DB)
}

// RefreshIPListProjectionsInLock 投影热路径的 DB 视图 InLock 变体（自动封禁
// merge 收敛用，契约：名单读改写+收敛同一 CaddyOpLock 临界区，本变体
// 不得自取锁——调用方已持锁，自取=重入死锁）。返回语义同
// RefreshIPListProjections。
func (s *CaddyService) RefreshIPListProjectionsInLock() (IPListProjectionOutcome, error) {
	return s.refreshIPListProjectionsInLock(db.DB)
}

// IPListProjectionOutcome 投影热路径三态
//   - ProjectionConverged：投影已落盘 ∧ 与运行配置字节一致 ∧ 本轮渲染未物化
//     证书 → 调用方零 /load 收尾；
//   - ProjectionNeedForce：字节一致但本轮渲染物化了证书文件（快照非空）→
//     调用方走强制重载收敛（errSameConfig 必须被击穿）；
//   - ProjectionFallback：无法证实收敛（发射面变化/运行配置不可读）→ 调用方
//     回退既有全量链。
type IPListProjectionOutcome int

const (
	ProjectionConverged IPListProjectionOutcome = iota
	ProjectionNeedForce
	ProjectionFallback
)

func (s *CaddyService) refreshIPListProjectionsInLock(store caddyConfigStore) (IPListProjectionOutcome, error) {
	// rulesWrittenInTx=false：本路径全部调用方（名单写路径 tx / 后台任务 db.DB）
	// 均不触碰 lb_rules——名单-only 变更的规则视图与已提交视图恒一致，
	// ACME 谓词 miss 补查在本路径是纯冗余。
	config := generateCaddyConfigWithCertSource(store, db.DB, false)
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		// 生成失败 = 该视图渲染不出合法配置——回退全量链按「配置被拒」拒绝
		//（同 applyConfigLockedOpt 口径，调用方回退后得到一致错误语义）。
		return ProjectionFallback, &ConfigRejectedError{Err: errors.New(message)}
	}
	// 快照键仅在 MaterializeCertPairs 实际写盘了证书文件时
	// 才入配置图（generateCaddyConfigWithCertSource）——先记下物化事实，字节
	// 一致时据此返回 NeedForce（否则快照随本函数局部配置图被丢弃，磁盘新证书
	// 与 Caddy 内存旧证书静默分叉）。
	_, certMaterialized := config[caddyCertFilesSnapshotKey].(CertFilesSnapshot)
	data, err := json.Marshal(caddyPayload(config))
	if err != nil {
		return ProjectionFallback, fmt.Errorf("failed to marshal config: %w", err)
	}
	running, err := s.getRunningConfigBytes()
	if err != nil {
		return ProjectionFallback, nil // 未知 → 不轻率宣称零变化，回退全量链
	}
	if !caddyConfigJSONEqual(running, data) {
		return ProjectionFallback, nil // 发射面变化（规则增减/路径变化）→ 全量链收敛
	}
	if certMaterialized {
		return ProjectionNeedForce, nil // 字节一致但证书已物化 → 强制重载收敛
	}
	// Converged 零 /load 收尾同样必须收敛渲染降级状态——降级键经
	// caddyPayload 剔除、不参与字节比较；调用方 recordCaddyApplyResult(nil)
	// 仅在 applyRenderDegradationState 已执行时才持久化横幅，漏此步会让「受信代理
	// 引用名单缺失/损坏」这类渲染降级的审计与横幅在热路径上完全丢失。
	// 事务视图（未提交）不写主库（避免与写锁争用），交给 commit 后的
	// recordCaddyApplyResult(nil)；DB 视图直接持久化。
	_, inTx := store.(*sql.Tx)
	applyRenderDegradationState(config, !inTx)
	return ProjectionConverged, nil
}

// RollbackIPListProjectionsToCommittedInLock 拒绝/回滚分支的磁盘回退（历史
// 用户裁定：拒绝=磁盘回滚到已提交态）：以已提交库值（db.DB）
// 重渲染一次全量配置——投影文件经渲染副作用原子重写为已提交内容（同字节跳写
// 保护在役文件），MaterializeCertPairs 把证书文件物化回归已提交 PEM——全程零
// /load（不做运行配置读取与比对，不发射任何 admin 请求）。
//
// 语义披露（方案选型裁定）：
//   - 「快照/恢复」方案（渲染前快照被覆写文件）被否：一次写请求内渲染发生
//     多轮（CLI 预检/热路径 refresh/事务内 apply），快照需跨轮贯穿且逐写点
//     钩挂，侵入面大；重渲染方案单点复用 generateCaddyConfigFromStore 的
//     既有原子写+同字节跳写，语义即「磁盘=已提交库值」，与 TTSR 渲染「库值
//     唯一真相」铁律同构。
//   - 从未提交的渲染中新生成的投影文件（已提交态不引用该 scope，如 allow
//     空集→非空的发射面出现形态）不删除——它们不被运行配置引用（零控制面
//     效果的惰性孤儿），由既有 24h GC 回收；内容级回滚由在役投影形状承载。
//   - NeedForce 强制被拒时，证书物化内容本就是已提交 PEM（物化=已提交态），
//     需回退的是投影与 DB 侧（本方法覆盖）；「磁盘新证书 × Caddy 内存旧证书」
//     的债务在拒绝后依然存在，与一切 apply 被拒形态同边界，由下次成功
//     渲染/手动重载收敛（非本方法职责）。
//   - 已提交视图渲染失败（数据损坏等）→ 仅 warn 不阻断拒绝收尾——拒绝分支
//     的主语义（400/回滚）优先，磁盘分叉由下次成功渲染收敛（与修复前等同，
//     双重故障才可达）。
//
// 锁契约：调用方必须已持 CaddyOpLock（=caddyOpMu，拒绝分支全部处于写路径
// 临界区内），与 RefreshIPListProjectionsInLock 同约束。db.DB 只读，不触碰
// 调用方未提交事务。
func (s *CaddyService) RollbackIPListProjectionsToCommittedInLock() {
	config := generateCaddyConfigFromStore(db.DB)
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		// 已提交视图渲染失败（非常态）——拒绝主流程不受影响，留 warn 痕迹。
		Logf("warn", "拒绝回滚：已提交视图重渲染失败，投影文件维持现状（下次成功渲染收敛）: %s", message)
		return
	}
	// 投影写盘与证书物化发生在生成期；配置图就地丢弃——本方法只消费副作用，
	// 不做运行配置比对、零 /load（拒绝语义：运行配置本就未被改动）。
}

// RestoreRuntimeToCommittedInLock 是提交失败分支的运行配置恢复
// 事务内 apply 已按未提交视图 /load（事务内 apply 不写 LKG，LKG 仍停留在
// 上一份已提交配置），commit 失败只回退投影会让数据面继续生效未提交内容。
// 本方法以已提交库值（db.DB）重渲染并 /load：运行配置、
// LKG（成功 /load 经 persistLastGoodLocked 写回）、投影与证书物化副作用全部
// 收敛到「已提交视图」。
//
// 语义披露：
//   - 已提交视图生成失败（数据损坏等）→ 返回 ConfigRejectedError，不 /load、
//     不改 LKG（此时无从判断什么是正确配置；调用方按双故障留痕）。
//   - /load 恢复失败 → 仍然把已提交视图字节写入 LKG（marshal 成功时）：
//     LKG 是启动兜底通道，绝不可停留在未提交配置；运行配置恢复失败本身作为
//     error 上抛，由调用方并入 500 响应。
//   - 同字节短路（errSameConfig）= 运行配置已是已提交内容（如未提交变更渲染
//     结果与运行配置一致），无需任何动作。
//
// 锁契约：调用方必须已持 CaddyOpLock（=caddyOpMu 写路径临界区）；本方法只取
// s.mu（与 ApplyConfigFromTx 同序）。调用方须先 Rollback 释放未提交事务的
// 写锁，否则 db.DB 读可能被 SQLite 写锁阻塞。
func (s *CaddyService) RestoreRuntimeToCommittedInLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := generateCaddyConfigFromStore(db.DB)
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		return &ConfigRejectedError{Err: errors.New(message)}
	}
	data, marshalErr := json.Marshal(caddyPayload(config))
	applyErr := s.applyConfigLocked(config, true)
	if IsSameConfig(applyErr) {
		return nil
	}
	if applyErr != nil {
		if marshalErr == nil {
			s.persistLastGoodLocked(data)
		}
		return errors.Join(applyErr, marshalErr)
	}
	return marshalErr
}

// PersistLastGoodBytesInLock 把事务内 apply 返回的已下发字节写入
// last-known-good（零 /load、零渲染）。调用契约：必须是 commit 成功之后的
// 首次落盘——事务内 apply 有意不写 LKG（见 caddyApplyOptions.persistLastGood），
// 这里的字节就是刚刚被 Caddy 接受且已成为已提交视图的配置。空字节（同字节
// 短路，无真实 /load）为 no-op：运行配置与 LKG 都不需要变化。
func (s *CaddyService) PersistLastGoodBytesInLock(data []byte) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistLastGoodLocked(data)
}

// PersistCommittedViewAsLastGoodInLock 以已提交库值重渲染并把字节写入
// last-known-good（零 /load——运行配置恢复由调用方的快照回退承担，同字节
// 短路语义不破）。apply 失败分支的 LKG 收口：任何回弹（快照重放/传输失败后
// 的恢复尝试）都可能让 LKG 偏离已提交视图，本方法把它钉回「LKG=已提交库视图」
// 这一全族不变量，与恢复成败解耦。
//
// 锁契约：调用方须已持 CaddyOpLock（=caddyOpMu 写路径临界区）；渲染读
// db.DB，调用方须先回滚未提交事务（SQLite 写锁会阻塞渲染读取）。
func (s *CaddyService) PersistCommittedViewAsLastGoodInLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := generateCaddyConfigFromStore(db.DB)
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		return &ConfigRejectedError{Err: errors.New(message)}
	}
	data, err := json.Marshal(caddyPayload(config))
	if err != nil {
		return err
	}
	s.persistLastGoodLocked(data)
	return nil
}

// ApplyConfigFromTxCertAwareForce：证书候选改读事务自身（restoreTable
// 保留原 id 重插证书行，已提交视图的旧行会经 MaterializeCertPairs 用旧 PEM 覆写
// 导入刚落盘的新证书文件）+ 强制重载（v2 导入在 apply 之前
// 已把新 PEM 落盘，生成期 MaterializeCertPairs 内容比对相等 → 快照为空 → 自动
// 强制不触发，必须显式强制，否则同 JSON 导入新证书会被 errSameConfig 短路、
// 旧证书继续服务）。非强制的 ApplyConfigFromTxCertAware 已于删除
// （唯一生产调用方即本函数的调用点，保留旧版只会让未来调用方重新引入静默
// 旧证书缺陷）。
// ApplyConfigFromTxCertAwareForce 的返回语义同 ApplyConfigFromTx：返回真实
// 下发字节供 commit 成功后补写 last-known-good（事务内不落 LKG）。
func (s *CaddyService) ApplyConfigFromTxCertAwareForce(tx *sql.Tx) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigWithOptions(generateCaddyConfigWithCertSource(tx, tx, true), caddyApplyOptions{
		force:              true,
		persistDegradation: false,
		persistLastGood:    false,
	})
}

// normalizeWeights 按 gcd 约分权重表（Caddy WRR 权重越小越高效）。
// 可达性披露：当前唯一调用点（HTTP 代理链构建）的上游权重已在收集层
// 归一（weight<=0→1），输入恒 ≥1——g==0（全零输入）与 w<=0 跳过两分支
// 对当前调用方不可达，属防未来调用方绕过收集层的防御性保留（删除会削弱
// 防御，有意保留）。
func normalizeWeights(weights []int) []int {
	g := 0
	for _, w := range weights {
		if w <= 0 {
			continue
		}
		if g == 0 {
			g = w
		} else {
			for w > 0 {
				g, w = w, g%w
			}
		}
	}
	if g <= 1 {
		return weights
	}
	out := make([]int, len(weights))
	for i, w := range weights {
		if w > 0 {
			out[i] = w / g
		}
	}
	return out
}

// buildTCPProxyRoute generates the layer4 proxy handler and route for a TCP rule.
// 库值唯一真相（批 1+2）：健康检查族与 tcp_try_interval 为类型①值型列，渲染
// 直读零兜底——<=0 返回显性错误（调用方 generationFailure/单规则 error 形态），
// 原 10s/3s/2s/2s/250ms 写死兜底废除。
func buildTCPProxyRoute(rule SingleRuleConfig) (map[string]interface{}, error) {
	upstreamList := make([]interface{}, 0)
	for _, u := range rule.Upstreams {
		if !u.Enabled {
			continue
		}
		dial := joinUpstreamAddress(u.Host, u.Port)
		upstreamEntry := map[string]interface{}{
			"dial": []string{dial},
		}
		// TCP 权重不约分（layer4 WRR 直接接受正权重比例，与 HTTP 侧
		// normalizeWeights 的 gcd 约分路径不同——如实标注）。
		weight := u.Weight
		if weight > 1 {
			upstreamEntry["weight"] = weight
		}
		if u.Protocol == "https" || u.Protocol == "tls" {
			upstreamEntry["tls"] = map[string]interface{}{
				"insecure_skip_verify": true,
			}
		}
		if u.MaxConnections > 0 {
			upstreamEntry["max_connections"] = u.MaxConnections
		}
		upstreamList = append(upstreamList, upstreamEntry)
	}

	strategy := rule.Strategy
	if strategy == "" {
		strategy = "weighted_round_robin"
	}
	if strategy == "cookie" {
		strategy = "weighted_round_robin"
	}

	proxyHandler := map[string]interface{}{
		"handler":   "proxy",
		"upstreams": upstreamList,
	}
	if rule.TCPProxyProtocol {
		proxyHandler["proxy_protocol"] = "v2"
	}

	loadBalancing := map[string]interface{}{
		"selection": map[string]interface{}{
			"policy": strategy,
		},
	}
	// Default to retrying on other upstreams so a connection routed to a
	// dead upstream fails over transparently instead of erroring to the
	// client; rule-level values override when set.
	// 2026-09 渲染审计：UI 语义「重试窗口 0=不重试」——0 不再兜底 5s，直接
	// 不发射 try_duration/try_interval（故障切换窗口关闭）；>0 时 tcp_try_interval
	// 为类型①值型列直读，<=0 显性报错（原 250ms 写死兜底废除）。
	tryDuration := rule.TCPTryDuration
	if tryDuration > 0 {
		if rule.TCPTryInterval <= 0 {
			return nil, fmt.Errorf("规则 %s 重试间隔无效（tcp_try_interval=%d <=0，重试窗口 >0 时为必填值）", rule.CaddyID, rule.TCPTryInterval)
		}
		loadBalancing["try_duration"] = fmt.Sprintf("%dms", tryDuration)
		loadBalancing["try_interval"] = fmt.Sprintf("%dms", rule.TCPTryInterval)
	}
	if len(upstreamList) > 1 || rule.TCPTryDuration > 0 || rule.TCPTryInterval > 0 {
		proxyHandler["load_balancing"] = loadBalancing
	}

	// 健康检查族（批 1+2）：类型①值型列直读，<=0 显性报错。
	if rule.HealthCheckInterval <= 0 {
		return nil, fmt.Errorf("规则 %s 健康检查间隔无效（health_check_interval=%d <=0）", rule.CaddyID, rule.HealthCheckInterval)
	}
	healthCheckInterval := rule.HealthCheckInterval
	if rule.HealthCheckUnhealthyThreshold <= 0 {
		return nil, fmt.Errorf("规则 %s 健康检查失败阈值无效（health_check_unhealthy_threshold=%d <=0）", rule.CaddyID, rule.HealthCheckUnhealthyThreshold)
	}
	unhealthyThreshold := rule.HealthCheckUnhealthyThreshold
	healthChecks := map[string]interface{}{
		"passive": map[string]interface{}{
			// 披露（与 HTTP 侧同口径）：被动熔断窗口=health_check_interval*3，
			// 复用主动探测间隔、无独立配置项（interval 越小熔断窗口越短）。
			"fail_duration": fmt.Sprintf("%ds", healthCheckInterval*3),
			"max_fails":     unhealthyThreshold,
		},
	}
	if rule.EnableActiveHealthCheck {
		if rule.HealthCheckTimeout <= 0 {
			return nil, fmt.Errorf("规则 %s 健康检查超时无效（health_check_timeout=%d <=0）", rule.CaddyID, rule.HealthCheckTimeout)
		}
		healthCheckTimeout := rule.HealthCheckTimeout
		if rule.HealthCheckHealthyThreshold <= 0 {
			return nil, fmt.Errorf("规则 %s 健康检查恢复阈值无效（health_check_healthy_threshold=%d <=0）", rule.CaddyID, rule.HealthCheckHealthyThreshold)
		}
		healthyThreshold := rule.HealthCheckHealthyThreshold
		active := map[string]interface{}{
			"interval": fmt.Sprintf("%ds", healthCheckInterval),
			"timeout":  fmt.Sprintf("%ds", healthCheckTimeout),
			"rise":     healthyThreshold,
			"fall":     unhealthyThreshold,
		}
		if rule.TCPHealthCheckPort > 0 {
			active["port"] = rule.TCPHealthCheckPort
		}
		healthChecks["active"] = active
	}
	proxyHandler["health_checks"] = healthChecks

	route := map[string]interface{}{
		"handle": []interface{}{proxyHandler},
	}
	if rule.CaddyID != "" {
		route["@id"] = rule.CaddyID
	}
	return route, nil
}

// buildTCPServer generates a layer4 server entry (listen + routes) for a TCP rule.
func buildTCPServer(rule SingleRuleConfig) (map[string]interface{}, error) {
	proxyRoute, err := buildTCPProxyRoute(rule)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"listen": []string{fmt.Sprintf(":%d", rule.ListenPort)},
		"routes": []interface{}{proxyRoute},
	}, nil
}
