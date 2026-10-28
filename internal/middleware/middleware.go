package middleware

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lazy-balancer-v2/internal/models"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/apikey"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
)

var internalMCPAuthSecret = rand.Text()

// jwtAuthenticationQuery 是认证状态查询的测试注入点：生产默认 nil（查询走
// 装配期传入的库句柄，与 readOnlyGuard/clusterVersionMiddleware 同源）；
// 测试可覆盖它以模拟瞬时 DB 失败。
var jwtAuthenticationQuery func(database *sql.DB, query string, args ...any) *sql.Row

// mfaUserEnabledCheckWith：MFA 启用态查询的测试注入点（与 jwtAuthenticationQuery
// 同模式）——fail-closed 回归测试需要模拟「瞬时 DB 失败」，真实关闭 DB 会
// 连带让 jwtAuth 的会话校验先失败（401），无法单独触发守卫分支。
// 句柄首参：守卫链上必须读装配期注入的库（与角色读取同源），不得回落到包级 db.DB。
var mfaUserEnabledCheckWith = services.MFAUserEnabledWith

var recordAuthenticationSecurityAudit = services.RecordAuditLog
var authenticationSecurityAuditNow = time.Now

var securityAuditLimiter = authenticationAuditLimiter{events: make(map[string]time.Time)}

// 认证审计限流器的容量/回收参数。
const (
	// authenticationAuditReclaimThreshold：键数超过该值才启动回收。
	// 唯一键 = reason+path+ip，正常认证拒绝规模远低于此，阈值以下不做任何
	// 回收工作（陈旧键留在表内不影响语义：再次命中时仍按 1min 去重窗判定）。
	authenticationAuditReclaimThreshold = 1024
	// authenticationAuditReclaimBatch：单次 allow 最多回收的陈旧键数。
	// 有界批次是本限流器的核心约束——回收量不随表规模增长，锁持有时间恒定
	// （旧实现按阈值触发整表遍历，洪水期锁内工作量与键数成正比）。
	authenticationAuditReclaimBatch = 64
	// authenticationAuditReclaimTTL：键空闲超过该时长才可回收。必须大于 1min
	// 去重窗，否则回收会让同一键在窗内被再次记审计（去重契约失效）。
	authenticationAuditReclaimTTL = 2 * time.Minute
	// authenticationAuditHardCap：键表硬上限。回收后仍满则丢弃新键（不进表也
	// 不记审计——审计丢失可接受，内存必须有界）。
	authenticationAuditHardCap = 4096
	// authenticationAuditQueueCapacity：回收队列容量。键被刷新时会在队尾追加
	// 带新时间戳的条目、旧条目退化为「被替代」（出队即丢弃），最坏情形同时存在
	// 两代条目，故取硬上限的两倍；真被填满（边界不可达）则覆盖队头，保证有界。
	authenticationAuditQueueCapacity = 2 * authenticationAuditHardCap
)

// authenticationAuditEvent 是回收队列条目：键 + 登记时的最后命中时间。
// 键被刷新时旧条目留在原处但时间戳落后于表内值，回收时以表内值比对即可识别
// 这种「被替代」条目（出队即丢弃，不删键）。
type authenticationAuditEvent struct {
	key string
	at  time.Time
}

type authenticationAuditLimiter struct {
	mu     sync.Mutex
	events map[string]time.Time
	// reclaim 是按最后命中时间升序的定容环形队列（最久未命中在前）——
	// 回收只从队头取有界批次，永不遍历全表。升序保证「队头都未过回收线时
	// 队内没有可回收键」，于是繁忙期回收工作量恒为零。
	reclaim      []authenticationAuditEvent
	reclaimHead  int
	reclaimCount int
}

// reclaimNeedsOrderingLocked 检查新时间戳是否会破坏逻辑队尾升序
// （调用方须持有 mu）。直接检查队列不变量可同时覆盖首次回拨和回拨后
// 沿旧时间线继续写入，不依赖跨请求 lastNow 比较。
func (limiter *authenticationAuditLimiter) reclaimNeedsOrderingLocked(at time.Time) bool {
	if limiter.reclaimCount == 0 {
		return false
	}
	tail := (limiter.reclaimHead + limiter.reclaimCount - 1) % len(limiter.reclaim)
	return at.Before(limiter.reclaim[tail].at)
}

// enqueueLocked 把键登记到回收队列尾部（调用方须持有 mu）。调用方先用
// reclaimNeedsOrderingLocked 检查队尾；需要时在登记后重建升序，避免新鲜
// 队头挡住其后已经过期的回拨条目。
//
// 环满时覆盖队头，被覆盖条目的「回收点」随之消失：若它恰是表内该键仅存的
// 登记（时间戳一致），该键从此进不了回收视野——表会撑到硬上限并永久丢弃新
// 审计（只有重启才恢复）。故覆盖时同步删除这样的键（「覆盖即淘汰」），把
// 丢掉的回收点补回来：被淘汰的是队内最久未命中的键，其代价仅是去重窗提前
// 结束（洪水量级下的最佳努力留痕优先于「每条只记一次」）。
func (limiter *authenticationAuditLimiter) enqueueLocked(key string, at time.Time) {
	if len(limiter.reclaim) == 0 {
		limiter.reclaim = make([]authenticationAuditEvent, authenticationAuditQueueCapacity)
	}
	if limiter.reclaimCount == len(limiter.reclaim) {
		// 环满：覆盖队头（最旧条目退化为可丢弃），队列长度恒有界。
		if overwritten := limiter.reclaim[limiter.reclaimHead]; overwritten.key != key {
			if last, live := limiter.events[overwritten.key]; live && last.Equal(overwritten.at) {
				delete(limiter.events, overwritten.key)
			}
		}
		limiter.reclaim[limiter.reclaimHead] = authenticationAuditEvent{key: key, at: at}
		limiter.reclaimHead = (limiter.reclaimHead + 1) % len(limiter.reclaim)
		return
	}
	tail := (limiter.reclaimHead + limiter.reclaimCount) % len(limiter.reclaim)
	limiter.reclaim[tail] = authenticationAuditEvent{key: key, at: at}
	limiter.reclaimCount++
}

// rebuildReclaimQueueLocked 从 events 重建升序回收队列（调用方须持有 mu）。
// 仅在新条目时间戳小于逻辑队尾时执行；此时允许一次 O(n log n) 重建，换取
// 正常路径继续使用有界队头回收，不让旧时间线条目失去回收视野。
func (limiter *authenticationAuditLimiter) rebuildReclaimQueueLocked() {
	if len(limiter.reclaim) == 0 {
		limiter.reclaim = make([]authenticationAuditEvent, authenticationAuditQueueCapacity)
	}
	ordered := limiter.reclaim[:len(limiter.events)]
	i := 0
	for key, at := range limiter.events {
		ordered[i] = authenticationAuditEvent{key: key, at: at}
		i++
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].at.Before(ordered[j].at) })
	limiter.reclaimHead = 0
	limiter.reclaimCount = len(ordered)
}

// headLocked 读取队头条目（不出队，调用方须持有 mu）。
func (limiter *authenticationAuditLimiter) headLocked() (authenticationAuditEvent, bool) {
	if limiter.reclaimCount == 0 {
		return authenticationAuditEvent{}, false
	}
	return limiter.reclaim[limiter.reclaimHead], true
}

// dropHeadLocked 出队丢弃队头条目（调用方须持有 mu）。
func (limiter *authenticationAuditLimiter) dropHeadLocked() {
	limiter.reclaimHead = (limiter.reclaimHead + 1) % len(limiter.reclaim)
	limiter.reclaimCount--
}

// reclaimExpiredLocked 从队头回收至多 authenticationAuditReclaimBatch 条过期
// 键——每次调用常数级工作量（含出队丢弃被替代的旧条目），摊销完成回收。
//
// 队列按最后命中时间升序：队头就是最久未命中的键。它若仍未过回收线，队内
// 不可能有可回收键，直接停止（繁忙期零工作量）；它已过线则删除并继续下一条。
// 条目时间戳与表内值不一致说明键在登记后被刷新过（尾部有更新的条目），本条
// 丢弃即可，键不受影响——去重窗语义不被回收改变。
// protect 是本次请求正在刷新的键：已过线的它也跳过（刷新既有键不占新键额），
// 本次 allow 会在队尾为它登记带新时间戳的条目。
func (limiter *authenticationAuditLimiter) reclaimExpiredLocked(now time.Time, protect string) {
	for range authenticationAuditReclaimBatch {
		event, ok := limiter.headLocked()
		if !ok {
			return
		}
		last, live := limiter.events[event.key]
		if !live || !last.Equal(event.at) || event.key == protect {
			// 已被删除 / 已被刷新替代 / 本次请求的键：只丢条目，不删键。
			limiter.dropHeadLocked()
			continue
		}
		if now.Sub(last) < authenticationAuditReclaimTTL {
			return
		}
		limiter.dropHeadLocked()
		delete(limiter.events, event.key)
	}
}

func (limiter *authenticationAuditLimiter) allow(key string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if last, exists := limiter.events[key]; exists && now.Sub(last) < time.Minute {
		return false
	}
	// 规模超阈值才启动回收，且每次调用只回收有界批次（常数级、摊销）——
	// 回收量不随表规模增长，锁持有时间恒定。阈值以下不做任何回收工作，
	// 陈旧键留在表内不影响语义：再次命中时上方 1min 去重窗照常生效。
	if len(limiter.events) > authenticationAuditReclaimThreshold {
		limiter.reclaimExpiredLocked(now, key)
	}
	// 硬上限：回收后仍满则丢弃新键，不进表也不记审计（审计丢失可接受，
	// 内存必须有界）。与 loginRateBuckets 不同——限流桶必须保持强制力，
	// 容量满走 LRU 淘汰而非丢键放行；审计限流丢弃只损失一条告警、不放行。
	// 既有键超窗刷新不占新键额：reclaimExpiredLocked 保护本次键不回收。
	if _, exists := limiter.events[key]; !exists && len(limiter.events) >= authenticationAuditHardCap {
		return false
	}
	// 新键与刷新都登记（刷新把新时间戳登记到队尾，旧条目出队即丢弃）。
	// 若新时间戳小于逻辑队尾，登记后重建升序；events 必须先更新，重建
	// 才能纳入本次键并正确淘汰环满覆盖的旧回收点。
	needsOrdering := limiter.reclaimNeedsOrderingLocked(now)
	limiter.enqueueLocked(key, now)
	limiter.events[key] = now
	if needsOrdering {
		limiter.rebuildReclaimQueueLocked()
	}
	return true
}

func (limiter *authenticationAuditLimiter) reset() {
	limiter.mu.Lock()
	limiter.events = make(map[string]time.Time)
	// 队列与表同生命周期：清表而不清队列会让旧条目的时间戳与新键误匹配。
	limiter.reclaim = nil
	limiter.reclaimHead = 0
	limiter.reclaimCount = 0
	limiter.mu.Unlock()
}

// apiKeyWhitelistCache：API Key IP 白名单的
// CIDR 解析结果缓存——原实现每请求对每条 CIDR 调 net.ParseCIDR。
// 键 = keyID + "|" + 白名单原串：键含白名单内容，白名单变更自动产生新键，
// 无需失效；旧键规模有界（Key 数 × 历史白名单版本数）。解析失败不缓存
// （下次请求仍重新解析并 500），保持「白名单配置无效→500」语义不变。
var apiKeyWhitelistCache sync.Map

// PurgeAPIKeyWhitelistCache 按 keyID 前缀清扫白名单 CIDR 解析缓存
// 删除/禁用 Key 后其历史白名单版本条目永不再命中却永久
// 驻留——无界累积。键形 = keyID+"|"+白名单原串，"|" 分隔使 keyID=3 不误伤
// "30|…" 前缀。由 handlers 侧删除/禁用点经 SetAPIKeyWhitelistCachePurge
// 注入的钩子调用（middleware 导入 handlers，反向会成环，故钩子倒置装配）。
func PurgeAPIKeyWhitelistCache(keyID int) {
	prefix := strconv.Itoa(keyID) + "|"
	apiKeyWhitelistCache.Range(func(key, _ any) bool {
		if cacheKey, ok := key.(string); ok && strings.HasPrefix(cacheKey, prefix) {
			apiKeyWhitelistCache.Delete(cacheKey)
		}
		return true
	})
}

// PurgeAllAPIKeyWhitelistCache 清空全部白名单 CIDR 解析缓存：配置备份导入与集群快照应用都整体替换 api_keys 表——键含 keyID
// 前缀无法枚举存活 Key，逐 Key 清扫不可行，必须全清（解析缓存重建廉价）。
func PurgeAllAPIKeyWhitelistCache() {
	apiKeyWhitelistCache.Range(func(key, _ any) bool {
		apiKeyWhitelistCache.Delete(key)
		return true
	})
}

func init() {
	handlers.SetAPIKeyWhitelistCachePurge(PurgeAPIKeyWhitelistCache)
	handlers.SetAPIKeyWhitelistCachePurgeAll(PurgeAllAPIKeyWhitelistCache)
	services.SetAPIKeyWhitelistCachePurgeAll(PurgeAllAPIKeyWhitelistCache)
}

// auditClientIP 审计源 IP：内部 MCP 转发请求（本机回环
// 自调用）携带网关注入的真实客户端 IP 头；仅当内部认证密钥匹配（与
// apiKeyAuth 的 trustedInternalMCP 判定同口径）时采信，外部请求伪造该头不
// 产生任何效果，其余请求沿用 gin ClientIP。
func auditClientIP(c *gin.Context) string {
	if secret := c.GetHeader(mcpserver.InternalAuthHeader); secret != "" &&
		subtle.ConstantTimeCompare([]byte(secret), []byte(internalMCPAuthSecret)) == 1 {
		if clientIP := c.GetHeader(mcpserver.InternalClientIPHeader); clientIP != "" {
			return clientIP
		}
	}
	return c.ClientIP()
}

func recordAuthenticationRejection(c *gin.Context, reason string) {
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	ipAddress := auditClientIP(c)
	if !securityAuditLimiter.allow(reason+"\x00"+path+"\x00"+ipAddress, authenticationSecurityAuditNow()) {
		return
	}
	detail := services.FormatAuditDetail("路径："+path, "原因类别："+reason)
	recordAuthenticationSecurityAudit("system", "认证拒绝", "安全审计", detail, ipAddress)
}

type loginRateBucket struct {
	mu         sync.Mutex
	count      int
	until      time.Time
	generation uint64
	// lastUsed 是最近一次命中的 UnixNano，供容量满时 LRU 淘汰。
	// 原子读写：淘汰在 map 锁内扫描，命中路径不额外获取 bucket.mu。
	lastUsed atomic.Int64
}

// rateLimitBucketCapacity 是共享桶表硬上限（内存必须有界）。
const rateLimitBucketCapacity = 1024

// evictLeastRecentlyUsedRateLimitBucketLocked 淘汰最久未命中的桶为新键腾位。
// 修复前容量满时新键 fail-open 放行（不建桶=本分钟对分布式来源
// 零限流）——攻击者可推满桶表形成暴力尝试窗口。改为有界 LRU：新来源仍拿到
// 自己的计数桶（照常 10/min 限流），内存上限不变。
// 淘汰次序 credential → 非受保护匿名桶 → 受保护桶。
// 只保护了「非 credential 桶」集合，但匿名端点
// （oidc-callback / service-control / 机器 scope 的 |ip 桶）同样无需凭证即可
// 每源 IP 建桶——约 147 个源 IP 就能把 1024 容量填成全匿名桶，回退全表 LRU
// 时最旧的 ip|login / ip|register 被淘汰 = 爆破/审计放大窗口被重置且可循环。
// 受保护桶仅在「表内只剩受保护桶」时才可能被淘汰（仍保证新键必建桶）。
//
// 残留风险（如实化）：表被受保护桶填满时（攻击者以 ≥1024 个源 IP 建立
// login/register 桶），victim 的受保护桶仍会被淘汰——该键当窗计数归零，
// 等效窗口被外部重置。这是「内存有界 + 新键必建桶」与「受保护窗口不可重置」
// 之间的取舍：拒绝新键会让合法新来源在表满时被永久限流（DoS 面更大）。
// 淘汰只发生在攻击者已能制造 1024 个受保护键的前提下，故不改变 tier 次序。
// 跨实例在途释放不需要额外身份校验：release 持有 reserve 返回的桶指针，
// 淘汰后重建的是新对象，旧指针的 count-- 只作用于已脱表实例。
// 调用方须持有 loginRateBuckets.Lock。
func evictLeastRecentlyUsedRateLimitBucketLocked() {
	victim := lruVictimLocked(rateLimitEvictCredentialOnly)
	if victim == "" {
		victim = lruVictimLocked(rateLimitEvictUnprotected)
	}
	if victim == "" {
		victim = lruVictimLocked(rateLimitEvictAny)
	}
	if victim != "" {
		delete(loginRateBuckets.entries, victim)
	}
}

type rateLimitEvictTier int

const (
	// rateLimitEvictCredentialOnly：未认证机器端点的 credential 桶可由攻击者
	// 用任意令牌无限生成，属于最可牺牲的一类。
	rateLimitEvictCredentialOnly rateLimitEvictTier = iota
	// rateLimitEvictUnprotected：其余非受保护键（匿名回调/机器 |ip 桶）。
	rateLimitEvictUnprotected
	// rateLimitEvictAny：别无选择时回退全表（受保护桶也只剩它们时）。
	rateLimitEvictAny
)

// isProtectedRateLimitKey 报告键是否承载登录/注册类爆破防护窗口：键形为
// <ip>|login（登录/MFA/setup 建号/OIDC 登录共桶）与 <ip>|register（公开注册端点）。
func isProtectedRateLimitKey(key string) bool {
	return strings.HasSuffix(key, "|login") || strings.HasSuffix(key, "|register")
}

// lruVictimLocked 返回该档位下最久未命中的键（无候选返回空串）。年龄只用于
// 比较，调用方只需键名——不返回最老时间戳，避免第二个事实源。
func lruVictimLocked(tier rateLimitEvictTier) string {
	var victim string
	oldest := int64(1<<63 - 1)
	for key, bucket := range loginRateBuckets.entries {
		switch tier {
		case rateLimitEvictCredentialOnly:
			if !strings.Contains(key, "|credential:") {
				continue
			}
		case rateLimitEvictUnprotected:
			if isProtectedRateLimitKey(key) {
				continue
			}
		}
		if used := bucket.lastUsed.Load(); used < oldest {
			oldest = used
			victim = key
		}
	}
	return victim
}

var loginRateBuckets = struct {
	sync.Mutex
	entries map[string]*loginRateBucket
}{entries: make(map[string]*loginRateBucket)}

// loginRateLimit 登录族端点限流（10/min/IP：login/ticket-login/mfa-verify/
// setup 建号/oidc-login 共用同一桶）。与 clusterRateLimit
// 桶机制收敛——共享 loginRateBuckets map、1024 容量上限、分钟窗、429 形态全同，
// 差异仅键形（ip|scope）/限额/文案三个参数；五端点同 scope="login" 共桶语义
// 不变（内存态无迁移面），oidc-login 共桶钉测试为回归钉。只读的 GET /auth/setup
// 不在本桶（独立 setup-status 宽桶，见注册处注释）。
func loginRateLimit() gin.HandlerFunc {
	return clusterRateLimit("login", 10, "登录尝试过于频繁，请稍后再试")
}

// acquireRateLimitBucket 在首次记账时创建；容量满按 LRU 淘汰最久未命中的
// 桶腾位（不再 fail-open——新来源照常限流且内存有界）。
func acquireRateLimitBucket(ip, scope string, now time.Time) *loginRateBucket {
	loginRateBuckets.Lock()
	defer loginRateBuckets.Unlock()
	key := ip + "|" + scope
	if bucket, ok := loginRateBuckets.entries[key]; ok {
		bucket.lastUsed.Store(now.UnixNano())
		return bucket
	}
	if len(loginRateBuckets.entries) >= rateLimitBucketCapacity {
		evictLeastRecentlyUsedRateLimitBucketLocked()
	}
	bucket := &loginRateBucket{until: now.Add(time.Minute)}
	bucket.lastUsed.Store(now.UnixNano())
	loginRateBuckets.entries[key] = bucket
	return bucket
}

// clusterRegisterRateLimit 注册端点限流:唯一公开、
// 未认证、无速率限制的写端点——每次无效令牌尝试 16KB 体读+条件 UPDATE+
// 审计 INSERT,互联网可达主节点可被线速打审计库。同威胁模型的 login/setup
// 均有限流,此处补同等待遇(宽桶:注册属低频管理操作,30/min/IP)。
// clusterRateLimit 是共享桶限流的统一实现（收敛，登录族
// loginRateLimit 亦为薄包装）：键=ip|scope 按 scope 分桶，桶间独立。
// 集群公开写端点:register(无效令牌尝试=16KB 体读+条件
// UPDATE+审计 INSERT)与 service-control(匿名可达,每尝试 BEGIN IMMEDIATE 写锁+
// 恒审计 INSERT,写放大更强)——同威胁模型的 login/setup 均有限流,补同等待遇。
// 按端点独立分桶,宽桶(低频管理操作)。
func clusterRateLimit(scope string, limit int, message string) gin.HandlerFunc {
	return func(c *gin.Context) {
		now := time.Now()
		ip := c.ClientIP()

		bucket := acquireRateLimitBucket(ip, scope, now)
		bucket.mu.Lock()
		if now.After(bucket.until) {
			bucket.count = 0
			bucket.until = now.Add(time.Minute)
		}
		bucket.count++
		exceeded := bucket.count > limit
		bucket.mu.Unlock()

		if exceeded {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"code": http.StatusTooManyRequests, "message": message})
			return
		}
		c.Next()
	}
}

func clusterRegisterRateLimit() gin.HandlerFunc {
	return clusterRateLimit("register", 30, "注册请求过于频繁，请稍后再试")
}

// mcpRateLimitPerMinute 是 MCP 端点的按 IP 额度。MCP 是机器接口（LLM 工具
// 调用一次会话内连续多次往返），比人工写端点频繁得多，故取公开只读宽桶的
// 量级（120/min，与 branding 桶同档）；同时仍是每秒级上限，单个身份无法线速
// 灌满内部 API 与审计库。
const mcpRateLimitPerMinute = 120

// noStoreResponse 让响应不可被任何缓存留存（浏览器回退缓存、中间反代）。
// 只挂在返回会话令牌、身份/MFA 秘密或一次性明文凭据的路由上——不是全局头：
// 静态资源与业务数据各有自己的缓存策略，全局 no-store 会把它们一并降级为
// 每次重新取数。
func noStoreResponse() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}

type clusterCredentialSource int

const (
	clusterCredentialFromToken clusterCredentialSource = iota
	clusterCredentialFromRegistration
)

// clusterMachineRateLimit 在 token/registration 认证与 DB 查询之前预占额度：
// 同一凭证最多 30 次/分钟，同一 IP 全凭证合计最多 300 次/分钟。凭证来源
// 必须与对应路由认证中间件一致，防止攻击者用无关头打散凭证桶。预占在锁内
// 原子完成，401 保留额度、非 401 回滚——并发无效请求不能击穿 check-then-act
// 窗口；合法节点（含同一 NAT 出口）成功请求不消耗失败预算。窗口换代编号
// 防止旧窗口在途请求污染新窗口。
func clusterMachineRateLimit(scope string, source clusterCredentialSource) gin.HandlerFunc {
	const (
		credentialLimit = 30
		ipLimit         = 300
	)
	return func(c *gin.Context) {
		now := time.Now()
		ip := c.ClientIP()
		fingerprint := clusterCredentialFingerprint(c, source)
		var credentialBucket *loginRateBucket
		var credentialGeneration uint64
		if fingerprint != "" {
			var allowed bool
			credentialBucket, credentialGeneration, allowed = reserveRateLimitBucket(ip, scope+"|credential:"+fingerprint, now, credentialLimit)
			if !allowed {
				abortClusterMachineRateLimit(c)
				return
			}
		}
		ipBucket, ipGeneration, ipAllowed := reserveRateLimitBucket(ip, scope+"|ip", now, ipLimit)
		if !ipAllowed {
			releaseRateLimitReservation(credentialBucket, credentialGeneration, false)
			abortClusterMachineRateLimit(c)
			return
		}
		// 归还必须写在 defer 里：handler panic 时控制流不经过 c.Next() 之后的
		// 语句（gin.Recovery 直接写 500 并终止链路），预占的两个桶各泄漏 1 次
		// 额度到分钟窗滚动为止。失败判据仍是「已写出 401」——panic 轮的最终
		// 状态码是 500，按成功语义归还，与「成功不消耗失败预算」的契约一致。
		defer func() {
			failed := c.Writer.Status() == http.StatusUnauthorized
			releaseRateLimitReservation(credentialBucket, credentialGeneration, failed)
			releaseRateLimitReservation(ipBucket, ipGeneration, failed)
		}()
		c.Next()
	}
}

func clusterCredentialFingerprint(c *gin.Context, source clusterCredentialSource) string {
	var credential string
	switch source {
	case clusterCredentialFromRegistration:
		credential = c.GetHeader("X-Registration-Secret")
	default:
		credential = c.GetHeader("X-Cluster-Token")
	}
	if credential == "" {
		credential = bearerToken(c.GetHeader("Authorization"))
	}
	if credential == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(hash[:])
}

func reserveRateLimitBucket(ip, scope string, now time.Time, limit int) (*loginRateBucket, uint64, bool) {
	key := ip + "|" + scope
	loginRateBuckets.Lock()
	bucket, exists := loginRateBuckets.entries[key]
	if !exists {
		// 容量满不再 fail-open 跳过限流——LRU 淘汰腾位后照常预占。
		if len(loginRateBuckets.entries) >= rateLimitBucketCapacity {
			evictLeastRecentlyUsedRateLimitBucketLocked()
		}
		bucket = &loginRateBucket{until: now.Add(time.Minute)}
		loginRateBuckets.entries[key] = bucket
	}
	bucket.lastUsed.Store(now.UnixNano())
	bucket.mu.Lock()
	loginRateBuckets.Unlock()
	defer bucket.mu.Unlock()
	if now.After(bucket.until) {
		bucket.count = 0
		bucket.until = now.Add(time.Minute)
		bucket.generation++
	}
	if bucket.count >= limit {
		return bucket, bucket.generation, false
	}
	bucket.count++
	return bucket, bucket.generation, true
}

func releaseRateLimitReservation(bucket *loginRateBucket, generation uint64, failed bool) {
	if bucket == nil {
		return
	}
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	if bucket.generation != generation {
		return
	}
	if !failed {
		bucket.count--
	}
}

func abortClusterMachineRateLimit(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"code": http.StatusTooManyRequests, "message": "集群机器接口请求过于频繁，请稍后再试"})
}

var loginRateLimitCleanupOnce sync.Once

// sweepExpiredRateLimitBuckets 删除已过窗（until 早于 now）的限流桶，返回删除
// 数量。锁序与调用链一致：先 map 锁、再逐桶锁；桶在两次加锁之间被淘汰是良性的
// ——本次请求的计数落在已脱表桶上，本分钟该来源少记 1 次（下一请求新建桶
// count=1），不构成限流绕过。
func sweepExpiredRateLimitBuckets(now time.Time) int {
	removed := 0
	loginRateBuckets.Lock()
	defer loginRateBuckets.Unlock()
	for ip, bucket := range loginRateBuckets.entries {
		bucket.mu.Lock()
		if now.After(bucket.until) {
			delete(loginRateBuckets.entries, ip)
			removed++
		}
		bucket.mu.Unlock()
	}
	return removed
}

func startLoginRateLimitCleanup() {
	loginRateLimitCleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				sweepExpiredRateLimitBuckets(time.Now())
			}
		}()
	})
}

// requestLogFormatter 请求日志行格式（独立函数以便格式钉测试消费）。
// 列结构对齐 gin 默认约定：[time] status | latency | clientIP | METHOD "path"
// 修复前 method 传入两次（| GET | GET "/path"）。
// c.Error() 附带的错误（param.ErrorMessage）有值时追加尾部列——
// 无消费者时 c.Error 等同死调用（v2.3.8 formatter 重写曾丢失该列）。
func requestLogFormatter(param gin.LogFormatterParams) string {
	line := fmt.Sprintf("[%s] %3d | %13v | %15s | %-7s %#v",
		param.TimeStamp.In(services.CurrentLocation()).Format("2006/01/02 15:04:05"),
		param.StatusCode, param.Latency, param.ClientIP, param.Method, param.Path)
	if msg := strings.TrimSpace(param.ErrorMessage); msg != "" {
		line += " | " + msg
	}
	return line + "\n"
}

// recordingRouterGroup 在注册 admin 组路由的同时记录「METHOD + 完整 gin 路径」
// 到 recorded：mcpserver 的 tools/list 可见性必须与 adminOnly 守卫
// 同口径隐藏恒 403 的工具。清单与注册点同源，新增 admin 路由自动同步，不存在
// 第二份手工清单漂移（区别于只读探测集等显式白名单）。
type recordingRouterGroup struct {
	*gin.RouterGroup
	recorded map[string]struct{}
}

func (g recordingRouterGroup) record(method, path string) {
	g.recorded[method+" "+g.BasePath()+path] = struct{}{}
}

func (g recordingRouterGroup) GET(path string, handlers ...gin.HandlerFunc) {
	g.RouterGroup.GET(path, handlers...)
	g.record(http.MethodGet, path)
}

func (g recordingRouterGroup) POST(path string, handlers ...gin.HandlerFunc) {
	g.RouterGroup.POST(path, handlers...)
	g.record(http.MethodPost, path)
}

func (g recordingRouterGroup) PUT(path string, handlers ...gin.HandlerFunc) {
	g.RouterGroup.PUT(path, handlers...)
	g.record(http.MethodPut, path)
}

func (g recordingRouterGroup) PATCH(path string, handlers ...gin.HandlerFunc) {
	g.RouterGroup.PATCH(path, handlers...)
	g.record(http.MethodPatch, path)
}

func (g recordingRouterGroup) DELETE(path string, handlers ...gin.HandlerFunc) {
	g.RouterGroup.DELETE(path, handlers...)
	g.record(http.MethodDelete, path)
}

func SetupRouter(h *handlers.Handlers, cfg *config.Config) *gin.Engine {
	startLoginRateLimitCleanup()
	services.ApplyLogLevel()

	r := gin.New()
	// 受信代理三判据的口径裁定（2026-10-22）：三 surface 有意分离，不合并——
	// ① 面板管理面（本路由）：仅支持直连部署，SetTrustedProxies(nil) 使
	//   ClientIP 恒为 RemoteAddr；登录限流桶/API Key IP 白名单/审计源 IP 均以此
	//   为准。面板置于反代后时限流退化为全站共享桶、白名单只能写代理 IP——
	//   部署约束，需在反代上不做源地址伪装或直连面板端口。
	// ② OIDC 回调基址（auth_oidc.go trustedProxyRemoteAddr）：面板侧唯一例外，
	//   仅当直连对端为回环/私网（可信反代）时采信 X-Forwarded-Proto/Host。
	// ③ global_config.trusted_proxy_*：数据面（CDN 真实 IP，规则渲染侧）专用，
	//   与面板管理面语义不同（CDN 网段不是面板反代），不得接入 gin。
	r.SetTrustedProxies(nil)
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		if !shouldLogRequest(param.StatusCode, param.Latency) {
			return ""
		}
		return requestLogFormatter(param)
	}), gin.Recovery())

	// 全局安全响应头——面板页面与 API 响应恒施加
	// nosniff+DENY（点击劫持/MIME 嗅探表面；认证走 Authorization 头无
	// cookie 向量，此为纵深加固）。
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Next()
	})

	// CORS
	r.Use(corsMiddleware())
	// 压缩中间件为本项目实现（internal/middleware/gzip.go）：错误/无体响应保留
	// Vary，避免把 CORS 的 Vary: Origin 一起删掉。
	r.Use(gzipMiddleware())
	r.Use(auditMiddleware())
	r.Use(clusterVersionMiddleware(db.DB))

	// Serve static files
	r.Use(func(c *gin.Context) {
		// /ui 挂载同源同产物——两侧 assets 前缀都按内容哈希长缓存
		// (保守保留 /ui 挂载不删)。
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/ui/assets/") {
			// Vite 产物文件名带内容哈希，可长期缓存
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		} else if path == "/ui" || path == "/ui/" || path == "/ui/index.html" {
			// /ui 壳 index.html 与根路径 GET / 同策略
			// no-cache——FileServer 直出只有，浏览器启发式缓存
			// （10% 规则）会让升级后的旧壳引用已删哈希资产白屏。裸 /ui 实际
			// 由 gin 尾斜杠 301 重定向先行应答（不经本链），列入仅作防御。
			c.Header("Cache-Control", "no-cache")
		}
		c.Next()
	})
	r.Static("/assets", cfg.StaticDir+"/assets")
	r.GET("/", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache")
		c.File(cfg.StaticDir + "/index.html")
	})
	r.Static("/ui", cfg.StaticDir)

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// API routes
	v1 := r.Group("/api/v1")
	{
		mcpHandler := mcpserver.NewWithInternalAuth(fmt.Sprintf("http://127.0.0.1:%d/api/v1", cfg.Port), LoopbackAPIClient(), internalMCPAuthSecret)
		// /mcp：限流先于认证与请求体读取——未认证流量不得先花掉 1 MiB 体读
		// 与一次密钥点查（此前该端点唯一无限流，单个 IP 可线速灌内部 API 与
		// 审计库）。apiKeyAuth → mcpAccessGuard 的次序不变。
		v1.POST("/mcp", clusterRateLimit("mcp", mcpRateLimitPerMinute, "MCP 请求过于频繁，请稍后再试"), apiKeyAuth(db.DB), mcpAccessGuard(), func(c *gin.Context) {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
			body, err := io.ReadAll(c.Request.Body)
			if err != nil {
				var maxBytesError *http.MaxBytesError
				if errors.As(err, &maxBytesError) {
					c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"code": http.StatusRequestEntityTooLarge, "message": "请求体过大"})
					return
				}
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"code": http.StatusBadRequest, "message": "请求体无效"})
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
			// 历史 把真实客户端 IP 注入 MCP 转发 context——内部
			// 转发是本机回环自调用，不注入则 MCP 操作的审计源 IP 恒为
			// 127.0.0.1（接收端 auditClientIP 凭内部认证密钥采信）。
			ctx := mcpserver.WithClientIP(c.Request.Context(), c.ClientIP())
			// 请求体已在上方读完：顺手解析 JSON-RPC 定位字段（method/id）随 context
			// 传入，tools/list 可见性过滤不再对同一 1 MiB 请求体做第二次读取+解析。
			// 解析失败不注入 method（下游按非 tools/list 放行，MCP 协议层自会 400）。
			var rpcMeta struct {
				Method string          `json:"method"`
				ID     json.RawMessage `json:"id"`
			}
			meta := mcpserver.RequestMeta{}
			if json.Unmarshal(body, &rpcMeta) == nil {
				meta = mcpserver.RequestMeta{Method: rpcMeta.Method, ID: rpcMeta.ID}
			}
			ctx = mcpserver.WithRequestMeta(ctx, meta)
			// API Key 身份已在 apiKeyAuth 中解析（同一次 db.ResolveAPIKeyIdentity）：
			// 属主属性随 context 复用，可见性判定不再重复点查。
			if c.GetString("auth_type") == "api_key" {
				ctx = mcpserver.WithAPIKeyVisibility(ctx, c.GetBool("api_key_read_only"), c.GetString("role") == "admin")
			}
			c.Request = c.Request.WithContext(ctx)
			gin.WrapH(mcpHandler)(c)
		})
		v1.GET("/docs", h.GetAPIDocs)
		// 认证入口的响应体带会话令牌/MFA 判定结果：逐条标记不可缓存。
		v1.POST("/auth/login", noStoreResponse(), loginRateLimit(), h.Login)
		v1.POST("/auth/ticket-login", noStoreResponse(), loginRateLimit(), h.TicketLogin)
		v1.POST("/auth/mfa/verify", noStoreResponse(), loginRateLimit(), h.MFAVerifyLogin)
		// GET /auth/setup 是登录页挂载即调用的只读探测（登录页每次打开一次，
		// 403 分支复探）——与登录写共用 10/min 桶会让同一出口 IP 打开 10 次
		// 登录页就耗尽登录预算（企业 NAT/反代后共享地址场景），正常用户随即
		// 收到「登录尝试过于频繁」。改为独立宽桶（与 oidc-status 同口径
		// 60/min/IP），POST /auth/setup（真实建号=爆破相关面）仍留登录桶。
		v1.GET("/auth/setup", clusterRateLimit("setup-status", 60, "初始化状态查询过于频繁，请稍后再试"), h.GetSetupStatus)
		v1.POST("/auth/setup", noStoreResponse(), loginRateLimit(), h.SetupAdmin)
		// OIDC 公开链路(v2.3.0):status=登录页按钮显隐;login=跳转;
		// callback=授权码回调(失败 302 回前端错误页)。均登录前可达,
		// 回调校验失败拒绝即止,不计入登录锁定(防伪造回调 DoS 锁号);
		// login 的 state 表在册封顶;
		// login 与 /auth/login 共用 IP 限流桶(callback 不挂——回调由 state
		// 表门控,伪造回调不应消耗真实登录额度)。
		// status 此前无任何限流——公开端点每请求 1 次 global_config 读+
		// JSON 反序列化，分布式探测可放大 DB 读；挂独立宽桶（60/min/IP，
		// 不消耗登录额度）。
		v1.GET("/auth/oidc/status", clusterRateLimit("oidc-status", 60, "OIDC 状态查询过于频繁，请稍后再试"), h.OIDCStatus)
		v1.GET("/auth/oidc/login", noStoreResponse(), loginRateLimit(), h.OIDCLogin)
		// callback 匿名可达且失败分支会写审计行；独立桶限流（不消耗登录
		// 额度），防止伪造回调线速灌审计库。
		v1.GET("/auth/oidc/callback", noStoreResponse(), clusterRateLimit("oidc-callback", 60, "OIDC 回调请求过于频繁，请稍后再试"), h.OIDCCallback)
		// 品牌配置公开读取：每请求至少 1 次 stat+序列化，指纹变化后的首个
		// 通过门控请求还会同步做多次 DB 写——匿名方无限速刷会把「每分钟一次」
		// 的门控放大成并发写尝试。挂独立宽桶（120/min/IP，前端首屏只读一次，
		// 不受影响），与 oidc 两条公开端点同口径。
		v1.GET("/branding", clusterRateLimit("branding", 120, "品牌配置查询过于频繁，请稍后再试"), h.GetBranding)
		v1.POST("/cluster/register", clusterRegisterRateLimit(), h.RegisterClusterNode)
		v1.GET("/cluster/register/:id/status", clusterMachineRateLimit("registration-status", clusterCredentialFromRegistration), registrationAuth(db.DB), h.GetClusterRegistrationStatus)
		v1.GET("/cluster/sync/snapshot", clusterMachineRateLimit("sync-snapshot", clusterCredentialFromToken), clusterTokenAuth(db.DB), h.GetClusterSnapshot)
		v1.GET("/cluster/sync/waf-files", clusterMachineRateLimit("sync-waf-files", clusterCredentialFromToken), clusterTokenAuth(db.DB), h.GetClusterWafFiles)
		v1.POST("/cluster/registration/confirm", clusterMachineRateLimit("registration-confirm", clusterCredentialFromToken), clusterTokenAuth(db.DB), h.ConfirmClusterRegistration)
		v1.POST("/cluster/nodes/report", clusterMachineRateLimit("node-report", clusterCredentialFromToken), clusterTokenAuth(db.DB), h.ReportClusterNode)
		// 从节点服务控制：票据即凭证（主节点签发的一次性 HMAC，与登录票据同
		// 机制），不走 clusterTokenAuth——主节点无法取回令牌明文（仅存哈希）。
		v1.POST("/cluster/service-control", clusterRateLimit("service-control", 20, "服务控制请求过于频繁，请稍后再试"), h.ClusterServiceControl)

		v1.Use(apiKeyAuth(db.DB))
		v1.Use(jwtAuth(db.DB, cfg))
		// apiKeyReadOnlyGuard 挂 v1 级——**正覆盖**下方直挂在 v1 上的路由
		// （openapi/caddy/metrics/logout 等），与 admin/business 组级
		// mfaStepUpGuard 的覆盖面不同（后者只管两组内路由）。新增 v1 直挂写
		// 路由时两守卫的覆盖差异须逐一确认，不能假定「组级守卫已覆盖」。
		v1.Use(apiKeyReadOnlyGuard())
		// mfaStepUpGuard 不在 v1 级挂载——admin 组内
		// adminOnly 必须先于 step-up（非管理员先见 403 角色真因，而非 428 后
		// 输码重试才见真因）；守卫改在 admin/business 两组级挂载（见下方组装配，
		// 组内次序 adminOnly → mfaStepUpGuard → readOnlyGuard）。
		// (2026-09-10 审计):把 auditClientIP(内部 MCP 转发采信头)结果
		// 注入 context,handlers 侧 recordAudit 优先读取——此前 handler 审计
		// 路径的 c.ClientIP() 对回环自调用恒 127.0.0.1,来源 IP 取证断裂。
		v1.Use(func(c *gin.Context) {
			c.Set("audit_ip", auditClientIP(c))
			c.Next()
		})
		{
			// OpenAPI 规格移入已认证区——此前置于公开块
			// 使完整 API 目录（路径/载荷示例/错误码说明）可被匿名枚举（实测 200）。
			// /docs 仅 HTML 壳保持公开：壳内 Swagger 用 localStorage.token 注入
			// Authorization 头取本路径，未认证者拿到壳也取不到规格（见 apidocs.go）。
			v1.GET("/openapi.yaml", h.GetOpenAPIYAML)
			v1.GET("/caddy/metrics", h.GetCaddyMetrics)
			v1.POST("/auth/logout", noStoreResponse(), h.Logout)
			// User management (admin only)
			adminGroup := v1.Group("")
			// adminOnly 先于 mfaStepUpGuard——非管理员打 admin 端点
			// 先见 403 角色真因；step-up 仍在 readOnlyGuard 之前（从节点
			// 403 先于 428 的守卫内短路口径不变）。
			adminGroup.Use(adminOnly(), mfaStepUpGuard(db.DB), readOnlyGuard(db.DB))
			admin := recordingRouterGroup{RouterGroup: adminGroup, recorded: make(map[string]struct{})}
			{
				admin.POST("/users", h.CreateUser)
				admin.PUT("/users/:id/status", h.ToggleUserStatus)
				admin.DELETE("/users/:id", h.DeleteUser)
				admin.POST("/users/:id/mfa/reset", noStoreResponse(), h.MFAResetByAdmin)

				// 管理语义端点收紧至 admin 组——服务重启/管理面板
				// TLS/原始 Caddy 配置覆写/Caddy 进程启停均为管理员级操作；此前挂在
				// business 组（仅 readOnlyGuard），apidocs 承诺的 403 admin_required
				// 实际不存在（PutCaddyConfig/StartCaddy/RestartService/UpdateAdminTLS
				// handler 内部均无角色检查）。读取类端点（GET/inspect）保留 business。
				admin.PUT("/admin-tls", h.UpdateAdminTLS)
				admin.POST("/system/restart", h.RestartService)
				admin.PUT("/caddy/config", h.PutCaddyConfig)
				admin.GET("/caddy/config", h.GetCaddyConfig)
				admin.POST("/caddy/start", h.StartCaddy)
				admin.POST("/caddy/stop", h.StopCaddy)
				admin.POST("/caddy/restart", h.RestartCaddy)

				// API Keys（创建与自助同实现：属主恒为当前认证身份）
				admin.POST("/api-keys", noStoreResponse(), h.CreateCurrentUserAPIKey)
				admin.PATCH("/api-keys/:id/status", h.UpdateAPIKeyStatus)
				admin.DELETE("/api-keys/:id", h.DeleteAPIKey)

				// CA Providers (admin only for update/test)
				admin.PUT("/ca-providers/:id", h.UpdateCAProvider)
				admin.POST("/ca-providers/:id/test", h.TestCAProvider)

				admin.POST("/cluster/register-tokens", h.GenerateClusterRegisterToken)
				admin.POST("/cluster/nodes/:id/approve", h.ApproveClusterNode)
				admin.POST("/cluster/nodes/:id/reject", h.RejectClusterNode)
				admin.POST("/cluster/nodes/:id/login-ticket", h.GenerateClusterLoginTicket)
				admin.PUT("/cluster/nodes/:id/access-url", h.UpdateClusterNodeAccessURL)
				admin.PUT("/cluster/nodes/:id/site", h.UpdateClusterNodeSiteCoordinates)
				admin.POST("/cluster/nodes/:id/service", h.ControlClusterNodeService)
				// 主节点侧单节点 TOFU 指纹钉重置——从节点更换管理面板证书后
				// 服务控制持续 PinMismatch 的补救通道（与 forget-pins 对称）。
				admin.POST("/cluster/nodes/:id/forget-pin", h.ForgetClusterNodePin)
				admin.DELETE("/cluster/nodes/:id", h.DeleteClusterNode)
				admin.POST("/cluster/mode", h.SetClusterMode)
				admin.POST("/cluster/promote", h.PromoteClusterNode)
				admin.POST("/cluster/sync/pull", h.PullClusterSnapshot)
				admin.PUT("/cluster/settings", h.UpdateClusterSettings)
				// 从节点管理员 PinMismatch 补救——清空 TOFU 指纹钉（内存+磁盘），
				// 下次同步重新钉扎；/cluster/* 前缀在 readOnlyGuard 白名单内，从节点可用。
				admin.POST("/cluster/forget-pins", h.ForgetClusterPins)

				// Config
				admin.POST("/config/preview", h.PreviewConfigUpdate)
				admin.PUT("/config", h.UpdateConfig)
				admin.POST("/config/reload", h.ReloadCaddy)
				admin.POST("/config/validate", h.ValidateConfig)
				admin.GET("/config/export", h.ExportConfigBackup)
				admin.POST("/config/import", h.ImportConfigBackup)
				admin.POST("/config/import/validate", h.ValidateConfigImport)
				admin.POST("/config/import/v1", h.ImportV1Config)

				// 自动备份（v2.3.x）：设置/手动备份/删除/还原/下载（handler 内均含
				// IsMaster 门，与 ExportConfigBackup 同口径——仅主节点）
				admin.GET("/settings/auto-backup", h.AutoBackupSettings)
				admin.PUT("/settings/auto-backup", h.UpdateAutoBackupSettings)
				admin.POST("/auto-backup/run", h.RunAutoBackupNow)
				// 任务监控（v2.3.4）：聚合视图全员可见（business 组），操作管理员
				admin.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
				admin.POST("/system/tasks/:id/toggle", h.ToggleSystemTask)
				admin.POST("/system/tasks/:id/cancel", h.CancelSystemTask)
				admin.POST("/system/tasks/:id/control", h.ControlSystemTask)
				admin.DELETE("/auto-backup/:id", h.DeleteAutoBackup)
				admin.POST("/auto-backup/:id/restore", h.RestoreAutoBackup)
				admin.GET("/auto-backup/:id/download", h.DownloadAutoBackup)

				// OIDC 认证集成(v2.3.0):显示/测试/修改/删除。
				admin.GET("/settings/oidc", h.OIDCSettings)
				admin.PUT("/settings/oidc", h.OIDCSettingsUpdate)
				admin.POST("/settings/oidc/test", h.OIDCSettingsTest)
				admin.DELETE("/settings/oidc", h.OIDCSettingsDelete)

				// Security (admin write)
				admin.POST("/security/policies", h.CreateSecurityPolicy)
				admin.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
				admin.DELETE("/security/policies/:id", h.DeleteSecurityPolicy)
				admin.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
				admin.POST("/security/policies/:id/bindings/bulk", h.BulkUpdatePolicyBindings)
				admin.DELETE("/security/policies/:id/bind/:caddy_id", h.UnbindRuleFromPolicy)
				admin.PUT("/security/rules/:caddy_id/policies", h.SetRuleSecurityPolicies)
				admin.POST("/security/policies/batch-bind", h.BatchBindSecurityPolicies)
				admin.POST("/security/policies/:id/split", h.SplitSecurityPolicy)
				admin.PUT("/security/crs/auto-update", h.UpdateCRSAutoUpdate)
				admin.PUT("/security/crs/schedule", h.UpdateCRSSchedule)
				admin.POST("/security/crs/update", h.StartCRSUpdate)
				admin.PUT("/security/ip2region/auto-update", h.UpdateIP2RegionAutoUpdate)
				admin.PUT("/security/ip2region/schedule", h.UpdateIP2RegionSchedule)
				admin.POST("/security/ip2region/update", h.StartIP2RegionUpdate)
				admin.PUT("/security/threat-lib/auto-update", h.UpdateThreatAutoUpdate)
				admin.PUT("/security/threat-lib/schedule", h.UpdateThreatSchedule)
				admin.PUT("/security/threat-lib/:id/flags", h.UpdateThreatSourceFlags)
				admin.POST("/security/threat-lib/update", h.StartThreatLibUpdate)
				admin.PUT("/security/crawler-lib/:id/flags", h.UpdateCrawlerLibFlags)
				admin.PUT("/security/crawler-lib/auto-update", h.UpdateCrawlerAutoUpdate)
				admin.PUT("/security/crawler-lib/schedule", h.UpdateCrawlerSchedule)
				admin.POST("/security/crawler-lib/update", h.StartCrawlerLibUpdate)
				admin.POST("/security/custom-rules", h.CreateSecurityCustomRule)
				admin.PUT("/security/custom-rules/:id", h.UpdateSecurityCustomRule)
				admin.DELETE("/security/custom-rules/:id", h.DeleteSecurityCustomRule)
				admin.POST("/security/block-pages", h.CreateSecurityBlockPage)
				admin.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
				admin.DELETE("/security/block-pages/:id", h.DeleteSecurityBlockPage)
				admin.POST("/security/ip-lists", h.CreateIPList)
				admin.PUT("/security/ip-lists/:id", h.UpdateIPList)
				admin.DELETE("/security/ip-lists/:id", h.DeleteIPList)
				admin.POST("/security/ip-lists/:id/ips", h.AddIPToList)
				admin.POST("/security/ip-lists/:id/remove-ip", h.RemoveIPFromList)
				// 自动封禁：配置写（主节点门在 handler 内；保存联动
				// 调度启停——2026-10-14 裁定，/run 端点已废除）
				admin.PUT("/security/autoban", h.UpdateAutobanConfig)
			}
			// admin 组路由集合注入 MCP 工具可见性——非管理员属主的 Key
			// 不应在 tools/list 看到恒 403 的工具（get_caddy_config / preview_config /
			// validate_import 等）。business 组写路由同门，合并后一次注入（见下方
			// business 组注册完成处）。清单即注册记录，无第二份手工维护。

			// User + Admin
			business := recordingRouterGroup{RouterGroup: v1.Group(""), recorded: make(map[string]struct{})}
			// business 组次序对称 ——readOnlyGuard
			// 先于 mfaStepUpGuard：非管理员打管理写端点直见 403 角色真因（旧次序
			// step-up 在前，验码重试后才见 403，与 admin 组已修的误导链同型）。
			// 自助路径经 isSelfServicePath 放行后照常进 step-up（428 链不变）；
			// 从节点 403 先于 428 由只读门直接达成。
			business.Use(readOnlyGuard(db.DB), mfaStepUpGuard(db.DB))
			{
				// 任务监控聚合视图（全员可见；从节点经 readOnlyGuard 只读可用）
				business.GET("/system/tasks", h.ListSystemTasks)
				business.GET("/system/tasks/stats-24h-series", h.GetSystemTaskStats24hSeries)
				business.GET("/system/tasks/:id/history", h.GetSystemTaskHistory)
				business.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
				// Current user (self)——身份与 MFA 秘密同属不可缓存响应。
				business.GET("/users/me", noStoreResponse(), h.GetCurrentUser)
				business.PATCH("/users/me", noStoreResponse(), h.UpdateCurrentUser)
				business.PUT("/users/:id", noStoreResponse(), adminOrSelfParam(), h.UpdateUser)
				business.POST("/users/:id/reset-password", noStoreResponse(), adminOrSelfParam(), h.ResetUserPassword)
				// v2.1.8 MFA 自助端点（JWT 用户）
				business.GET("/auth/mfa/status", noStoreResponse(), h.MFAStatus)
				business.POST("/auth/mfa/setup", noStoreResponse(), h.MFASetup)
				business.POST("/auth/mfa/activate", noStoreResponse(), h.MFAActivate)
				business.POST("/auth/mfa/disable", noStoreResponse(), h.MFADisable)
				business.POST("/auth/mfa/recovery-codes", noStoreResponse(), h.MFARecoveryCodes)
				business.POST("/auth/mfa/verify-step", noStoreResponse(), h.MFAVerifyStep)
				business.GET("/users/me/api-keys", noStoreResponse(), h.ListCurrentUserAPIKeys)
				business.POST("/users/me/api-keys", noStoreResponse(), h.CreateCurrentUserAPIKey)
				business.PATCH("/users/me/api-keys/:id", h.UpdateCurrentUserAPIKeyStatus)
				business.DELETE("/users/me/api-keys/:id", h.DeleteCurrentUserAPIKey)

				// lists (all authenticated users)
				business.GET("/mcp/tools", h.GetMCPTools)
				business.GET("/mcp/ops-playbook", h.GetMCPOpsPlaybook)
				business.GET("/users", h.ListUsers)
				business.GET("/api-keys", noStoreResponse(), h.ListAPIKeys)
				business.GET("/cluster/nodes", h.ListClusterNodes)
				business.GET("/config/health", h.GetUpstreamHealth)

				// Rules
				business.GET("/rules", h.ListRules)
				business.GET("/rules/:caddy_id", h.GetRule)
				business.GET("/rules/:caddy_id/caddy-config", h.GetRuleCaddyConfig)
				business.GET("/rules/:caddy_id/metrics-history", h.GetRuleMetricsHistory)
				business.GET("/rules/:caddy_id/log-stream", h.GetRuleLogStream)
				business.GET("/rules/:caddy_id/logs", h.GetRuleLogs)
				business.GET("/logs/stats", h.GetLogStats)
				business.GET("/rules/:caddy_id/cert-info", h.GetRuleCertInfo)
				business.POST("/rules/cert-info", h.GetRulesCertInfo)
				business.POST("/rules/batch-block-pages", h.BatchRuleBlockPages)
				business.POST("/rules", h.CreateRule)
				business.PUT("/rules/:caddy_id", h.UpdateRule)
				business.DELETE("/rules/:caddy_id", h.DeleteRule)
				business.POST("/rules/:caddy_id/enable", h.EnableRule)
				business.POST("/rules/:caddy_id/disable", h.DisableRule)
				business.POST("/rules/:caddy_id/duplicate", h.DuplicateRule)

				// Certificate Configs
				business.GET("/certificate-configs", h.ListCertificateConfigs)
				business.POST("/certificate-configs", h.CreateCertificateConfig)
				business.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
				business.DELETE("/certificate-configs/:id", h.DeleteCertificateConfig)
				business.GET("/dns-providers", h.ListDNSProviders)
				business.GET("/ca-providers", h.ListCAProviders)
				business.GET("/ca-providers/:id", h.GetCAProvider)
				business.POST("/certificate-configs/test", h.TestCertificateConfig)
				business.POST("/certificate-configs/:id/test", h.TestCertificateConfig)

				// Security (read for all, write for admin)
				business.GET("/security/policies", h.ListSecurityPolicies)
				business.GET("/security/policies/:id", h.GetSecurityPolicy)
				business.GET("/security/overview", h.GetSecurityOverview)
				// 威胁大屏：聚合 + 增量事件流（只读，从节点可读）
				business.GET("/security/overview/threat-screen", h.GetSecurityThreatScreen)
				// 实时流量快照代理（Plan B 全请求光流数据源，1-2s 轮询）
				business.GET("/security/overview/threat-screen/traffic", h.GetThreatScreenTraffic)
				// 大屏流量采集租约：打开屏幕申请、关闭释放；无租约时 Caddy 跳过采集。
				business.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
				business.DELETE("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
				business.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)
				business.GET("/security/overview/threat-screen/attack-flow", h.GetThreatScreenAttackFlow)
				business.GET("/security/events/feed", h.GetSecurityEventFeed)
				business.GET("/security/events/toast-summary", h.GetSecurityEventToastSummary)
				business.GET("/security/rate-limit-blocks", h.GetSecurityRateLimitBlocks)
				business.GET("/security/events", h.ListSecurityEvents)
				business.GET("/security/events/count", h.GetIPEventCount)
				business.GET("/security/crs", h.GetCRSInfo)
				business.GET("/security/crs/update/status", h.GetCRSUpdateStatus)
				business.GET("/security/crs/update/logs", h.GetCRSUpdateLogs)
				business.GET("/security/ip2region", h.GetIP2RegionInfo)
				business.GET("/security/ip2region/regions", h.GetIP2RegionRegions)
				business.GET("/security/ip2region/update/status", h.GetIP2RegionUpdateStatus)
				business.GET("/security/ip2region/update/logs", h.GetIP2RegionUpdateLogs)
				business.GET("/security/threat-lib", h.GetThreatLib)
				business.GET("/security/threat-lib/update/status", h.GetThreatLibUpdateStatus)
				business.GET("/security/threat-lib/update/logs", h.GetThreatLibUpdateLogs)
				business.GET("/security/crawler-lib", h.GetCrawlerLib)
				business.GET("/security/crawler-lib/update/status", h.GetCrawlerLibUpdateStatus)
				business.GET("/security/crawler-lib/update/logs", h.GetCrawlerLibUpdateLogs)
				business.GET("/security/rules/:caddy_id/policy", h.GetSecurityPolicyBindings)
				business.GET("/security/rules/:caddy_id/stage-stats", h.GetRuleStageStats)
				business.GET("/security/bindings", h.GetAllSecurityBindings)
				business.GET("/security/custom-rules", h.ListSecurityCustomRules)
				business.GET("/security/block-pages", h.ListSecurityBlockPages)
				business.GET("/security/ip-lists", h.ListIPLists)
				business.GET("/security/ip-lists/:id", h.GetIPList)
				business.GET("/security/ip-lists/:id/export", h.ExportIPList)
				// 自动封禁：配置/状态读（全员可见，状态卡数据源）
				business.GET("/security/autoban", h.GetAutobanConfig)
				business.GET("/security/autoban/status", h.GetAutobanStatus)
				business.GET("/security/crs/rules", h.ListCRSRules)
				business.GET("/security/crs/rule-index", h.GetCRSRuleIndex)
				business.GET("/security/crs/rules/:filename", h.GetCRSRuleContent)
				business.GET("/security/crs/setup", h.GetCRSSetupConfig)

				// Config (read only for non-admin)
				business.GET("/config", h.GetConfig)
				business.GET("/cluster/status", h.GetClusterStatus)

				// Metrics
				business.GET("/metrics/dashboard", h.GetMetricsDashboard)
				business.GET("/metrics/overview", h.GetMetricsOverview)
				business.GET("/metrics/rule/:caddy_id", h.GetRuleMetrics)
				business.GET("/metrics/history", h.GetMetricsHistory)
				business.GET("/metrics/realtime", h.GetRealtimeTraffic)
				business.GET("/metrics/connections", h.GetConnectionStats)

				// System
				business.GET("/system/info", h.GetSystemInfo)
				business.GET("/admin-tls", h.GetAdminTLS)
				business.POST("/admin-tls/inspect", h.InspectAdminTLSCert)
				business.GET("/system/metrics", h.GetSystemMetrics)
				business.GET("/system/logs", h.GetAppLogs)

				// Caddy
				business.GET("/caddy/status", h.GetCaddyStatus)
				business.GET("/caddy/logs", h.GetCaddyLogs)
				business.GET("/caddy/host-metrics", h.GetHostMetrics)

				// Certificates
				business.GET("/certificates", h.ListCertificates)
				business.POST("/certificates/issue", h.IssueCertificate)
				business.POST("/certificates/parse", h.ParseCertificate)
				business.GET("/certificates/jobs", h.ListCertJobs)
				business.POST("/certificates/jobs/current", h.GetCurrentCertJobs)
				business.GET("/certificates/jobs/:id", h.GetCertJob)
				business.GET("/certificates/jobs/:id/logs", h.GetCertJobLogs)
				business.POST("/certificates/jobs/:id/retry", h.RetryCertJob)
				business.DELETE("/certificates/jobs/:id", h.DeleteCertJob)

				business.GET("/audit-logs", h.GetAuditLogs)
				business.GET("/audit-logs/options", h.GetAuditLogOptions)
			}

			// 「非管理员恒 403」路由集合注入 MCP 工具可见性——两份集合都来自
			// 守卫同源的注册记录：admin 组全部路由（adminOnly），加 business
			// 组写方法中既不受只读白名单豁免、也不属自助路径者
			// （readOnlyGuard 只对这部分返回 403）。非管理员属主的 Key 在
			// tools/list 只会看到真能调用的工具。
			nonAdminForbidden := make(map[string]struct{}, len(admin.recorded)+len(business.recorded))
			for route := range admin.recorded {
				nonAdminForbidden[route] = struct{}{}
			}
			for route := range business.recorded {
				method, path, _ := strings.Cut(route, " ")
				if !writeMethods[method] || services.IsReadOnlyWriteRoute(method, path) || isSelfServicePath(path) {
					continue
				}
				nonAdminForbidden[route] = struct{}{}
			}
			// mcpserver 的可见性名单是进程级全局（最后一次 SetupRouter 覆写）：
			// 生产单例无碍；测试/嵌入同时装配两个 router 时后者生效。名单内容
			// 只取决于路由注册记录，单例部署下不存在跨实例污染。
			mcpserver.SetNonAdminForbiddenRoutes(nonAdminForbidden)
		}
	}

	return r
}

func shouldLogRequest(statusCode int, latency time.Duration) bool {
	switch services.CurrentLogLevel() {
	case "warn":
		return statusCode >= http.StatusBadRequest || latency >= time.Second
	case "error":
		return statusCode >= http.StatusInternalServerError
	default:
		return true
	}
}

func auditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if !writeMethods[c.Request.Method] {
			return
		}
		path := c.FullPath()
		policy := services.ClassifyAuditRoute(c.Request.Method, path)
		if policy == services.AuditPolicySkip || services.HasExplicitAuditEvent(c.Request.Method, path) {
			return
		}
		if c.Writer.Status() >= 400 && c.Writer.Status() < 500 {
			return
		}

		action, resource, detail := services.FormatAuditAction(path)
		if action == "" {
			return
		}
		if c.Writer.Status() >= 500 {
			detail = detail + "；结果：失败"
		}

		username, _ := c.Get("username")
		usernameStr, _ := username.(string)
		if c.GetString("auth_type") == "api_key" {
			detail = services.AppendAPIKeyAuditDetail(detail, c.GetInt("api_key_id"), c.GetString("api_key_name"))
		}

		services.RecordAuditLog(usernameStr, action, resource, detail, auditClientIP(c))
	}
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if origin := c.Request.Header.Get("Origin"); origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Cluster-Token, X-Registration-Secret")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// jwtAuth 的库读取走装配期传入的句柄（与同组 readOnlyGuard/mfaStepUpGuard 同源），
// 不再读包级 db.DB——两处句柄来源不同会让「认证读主库、授权读注入库」在测试与
// 嵌入形态下分叉。
func jwtAuth(database *sql.DB, cfg *config.Config) gin.HandlerFunc {
	queryAuthenticationState := func(query string, args ...any) *sql.Row {
		if jwtAuthenticationQuery != nil {
			return jwtAuthenticationQuery(database, query, args...)
		}
		return database.QueryRow(query, args...)
	}
	return func(c *gin.Context) {
		if c.GetString("auth_type") == "api_key" {
			c.Next()
			return
		}
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			recordAuthenticationRejection(c, "jwt_missing")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "缺少认证信息"})
			c.Abort()
			return
		}

		// Bearer scheme 大小写不敏感（RFC 7235 §2.1）——解析与集群/注册鉴权
		// 共用 bearerToken 单源；空值/裸 token/其它 scheme 一律「认证格式无效」。
		tokenString := bearerToken(authHeader)
		if tokenString == "" {
			recordAuthenticationRejection(c, "jwt_format_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "认证格式无效"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		}, jwt.WithExpirationRequired(), jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

		if err != nil || !token.Valid {
			// 历史 过期与无效分判——过期是自然态（重登即可），签名
			// 无效/格式损坏是凭证问题；旧代码两类同发「登录状态已过期」，把无效
			// 凭证误导成「重新登录就能好」。401 状态码不变，仅消息分语义。
			if errors.Is(err, jwt.ErrTokenExpired) {
				recordAuthenticationRejection(c, "jwt_expired")
				c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录状态已过期，请重新登录"})
			} else {
				recordAuthenticationRejection(c, "jwt_invalid")
				c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			}
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			recordAuthenticationRejection(c, "jwt_claims_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			c.Abort()
			return
		}
		now := time.Now().UTC()
		revocationSource := tokenString
		if jti, exists := claims["jti"].(string); exists && jti != "" {
			revocationSource = jti
			c.Set("token_jti", jti)
		}
		revocationHash := sha256.Sum256([]byte(revocationSource))
		encodedRevocationHash := hex.EncodeToString(revocationHash[:])
		if exp, valid := claims["exp"].(float64); valid {
			c.Set("token_revocation_hash", encodedRevocationHash)
			c.Set("token_expires_at", time.Unix(int64(exp), 0).UTC())
		}

		// Resolve the current role and enabled state from the database so that
		// demotion or disabling takes effect immediately, not at token expiry.
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			recordAuthenticationRejection(c, "jwt_subject_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			c.Abort()
			return
		}
		var dbUsername, dbRole sql.NullString
		var dbEnabled sql.NullBool
		var passwordVersion sql.NullInt64
		var revoked bool
		queryErr := queryAuthenticationState(`WITH auth_state AS (
			SELECT EXISTS(SELECT 1 FROM revoked_jti WHERE jti_hash=? AND expires_at>?) AS revoked
		)
		SELECT auth_state.revoked, u.username, u.role, COALESCE(u.is_enabled,0), u.password_version
		FROM auth_state LEFT JOIN users u ON u.id=?`, encodedRevocationHash, now.Format(models.RevokedTokenTimeFormat), int64(userIDFloat)).Scan(&revoked, &dbUsername, &dbRole, &dbEnabled, &passwordVersion)
		if queryErr == nil && revoked {
			recordAuthenticationRejection(c, "jwt_revoked")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录状态已失效，请重新登录"})
			c.Abort()
			return
		}
		// DB 故障不得折叠成「用户不存在或已禁用」——
		// 否则库锁/IO 故障期间全站表现为凭据问题（客户端被诱导重登），运维
		// 日志也拿不到底层错误、无法与真实凭据攻击区分。基础设施错误 → 500
		// （与 readOnlyGuard/clusterTokenAuth 口径一致）。
		if queryErr != nil {
			services.Logf("error", "jwt auth state query failed: %v", queryErr)
			c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "认证状态查询失败"})
			c.Abort()
			return
		}
		if !dbUsername.Valid || !dbRole.Valid || !dbEnabled.Valid || !dbEnabled.Bool || !passwordVersion.Valid {
			recordAuthenticationRejection(c, "jwt_user_unavailable")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "用户不存在或已禁用"})
			c.Abort()
			return
		}
		claimUsername, valid := claims["username"].(string)
		if !valid || claimUsername != dbUsername.String {
			recordAuthenticationRejection(c, "jwt_identity_mismatch")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			c.Abort()
			return
		}
		if claim, exists := claims["pwd_ver"]; exists {
			claimVersion, valid := claim.(float64)
			if !valid || claimVersion != float64(passwordVersion.Int64) {
				recordAuthenticationRejection(c, "jwt_password_changed")
				c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "密码已修改，请重新登录"})
				c.Abort()
				return
			}
		} else if passwordVersion.Int64 != 0 {
			recordAuthenticationRejection(c, "jwt_password_changed")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "密码已修改，请重新登录"})
			c.Abort()
			return
		}

		c.Set("user_id", claims["user_id"])
		c.Set("username", claims["username"])
		c.Set("role", dbRole.String)
		// JWT 成功路径补 auth_type——全仓此前只有 apiKeyAuth 设置该值，
		// mfaStepUpGuard 的 != "jwt" 对 JWT 用户恒真（守卫整体死代码）。
		c.Set("auth_type", "jwt")
		// v2.3.0 OIDC：auth_method 声明透传（local/oidc,缺省=local）——
		// 写保护矩阵分支依据（绑本地 MFA→TOTP;未绑 OIDC 会话→IdP 重认证）。
		if am, ok := claims["auth_method"].(string); ok && am != "" {
			c.Set("auth_method", am)
		}
		// v2.1.8 MFA mfa_ts 声明透传（无声明=0，guard 视为过期）
		if ts, ok := claims["mfa_ts"].(float64); ok {
			c.Set("mfa_ts", ts)
		}

		c.Next()
	}
}

// apiKeyAuth 的 Key 解析与身份查询共用单源：凭据提取走 internal/apikey（与 MCP
// 转发侧同一实现），身份查询走装配期传入的库句柄（与 readOnlyGuard 同源）。
func apiKeyAuth(database *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 历史 原「JWT 已认证则跳过」首行分支删除——生产链
		// 不可达（挂载次序固定：v1.Use(apiKeyAuth) 先于 v1.Use(jwtAuth)，/mcp
		// 路由仅 apiKeyAuth；全链无更早 user_id 写者），user_id 在本中间件
		// 之前恒不存在。删除后不改变任何可达请求的判定路径。
		apiKey := apikey.FromHeader(c.Request.Header)
		if apiKey == "" {
			c.Next()
			return
		}
		if len(apiKey) < 13 {
			if hasJWTBearer(c) {
				c.Next()
				return
			}
			recordAuthenticationRejection(c, "api_key_invalid")
			// 历史 MCP/Key 认证链的通用 401 消息此前为英文
			// "Invalid API key"，与本认证链其余消息（缺少认证信息/认证格式无效/
			// 登录状态已过期等）及 serverInstructions 的中文错误约定不一致——
			// Agent 与前端按中文解析。
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "API 密钥无效"})
			c.Abort()
			return
		}
		// 认证查询收敛到 db.ResolveAPIKeyIdentity 单源（prefix + sha256
		// + 有效性条件），与 mcpserver 只读可见性共用——此前两处手写同形 SQL，
		// 认证条件变更时可见性会静默漂移。
		identity, err := db.ResolveAPIKeyIdentity(database, apiKey)
		if err != nil {
			if hasJWTBearer(c) {
				c.Next()
				return
			}
			// 区分「Key 无效」与基础设施故障——
			// ResolveAPIKeyIdentity 已给出 ErrAPIKeyNotFound 分类，此前全部
			// 折叠成 401，DB 故障期间表现为密钥无效且日志零线索。
			if !errors.Is(err, db.ErrAPIKeyNotFound) {
				services.Logf("error", "api key identity query failed: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "API 密钥校验失败"})
				c.Abort()
				return
			}
			recordAuthenticationRejection(c, "api_key_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "API 密钥无效"})
			c.Abort()
			return
		}
		keyID := identity.ID
		userID := identity.UserID
		keyName := identity.Name
		username := identity.Username
		role := identity.Role
		mcpEnabled := identity.MCPEnabled
		readOnly := identity.ReadOnly
		mcpIPWhitelist := identity.MCPIPWhitelist
		trustedInternalMCP := subtle.ConstantTimeCompare([]byte(c.GetHeader(mcpserver.InternalAuthHeader)), []byte(internalMCPAuthSecret)) == 1
		if mcpIPWhitelist != "" && !trustedInternalMCP {
			var whitelist []string
			if err := json.Unmarshal([]byte(mcpIPWhitelist), &whitelist); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "API Key IP 白名单配置无效"})
				return
			}
			cacheKey := strconv.Itoa(keyID) + "|" + mcpIPWhitelist
			var networks []*net.IPNet
			cached, ok := apiKeyWhitelistCache.Load(cacheKey)
			if ok {
				networks, ok = cached.([]*net.IPNet)
			}
			if !ok {
				// 异构缓存值视为未命中，重新解析并回写正确类型。
				parsed := make([]*net.IPNet, 0, len(whitelist))
				for _, cidr := range whitelist {
					_, network, err := net.ParseCIDR(cidr)
					if err != nil {
						c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "API Key IP 白名单配置无效"})
						return
					}
					parsed = append(parsed, network)
				}
				apiKeyWhitelistCache.Store(cacheKey, parsed)
				networks = parsed
			}
			clientIP := net.ParseIP(c.ClientIP())
			allowed := false
			for _, network := range networks {
				if network.Contains(clientIP) {
					allowed = true
					break
				}
			}
			if !allowed {
				recordAuthenticationRejection(c, "api_key_ip_denied")
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "来源 IP 不在白名单"})
				return
			}
		}

		db.MarkAPIKeyUsed(keyID)
		c.Set("user_id", userID)
		c.Set("username", username)
		c.Set("role", role)
		c.Set("auth_type", "api_key")
		c.Set("api_key_id", keyID)
		c.Set("api_key_name", keyName)
		c.Set("api_key_mcp_enabled", mcpEnabled)
		c.Set("api_key_read_only", readOnly)

		c.Next()
	}
}

// sensitiveExportGetRoutes 与写操作同敏感级的导出类 GET（2026-09-24 用户裁定：
// 导入导出/备份视为写入操作）——产物均含私钥/凭证明文。apiKeyReadOnlyGuard
// （只读 Key 403）与 mfaStepUpGuard（JWT step-up 428）共用同一名单，任一侧
// 新增敏感 GET 必须登记于此（download 曾只在 step-up 侧在列，只读
// Key 侧漏网）。
var sensitiveExportGetRoutes = map[string]bool{
	"/api/v1/config/export":            true,
	"/api/v1/auto-backup/:id/download": true,
}

// writeMethods 写方法集合（收敛：auditMiddleware/
// apiKeyReadOnlyGuard/mfaStepUpGuard 三处字面量与 readonly.go 的 switch 四形态
// 并存）——四处守卫共用同一事实源。包级只读使用，无写入者。
var writeMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

func apiKeyReadOnlyGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("auth_type") != "api_key" || !c.GetBool("api_key_read_only") {
			c.Next()
			return
		}
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		// 登出是会话自助语义（无同步表写）：三守卫（apiKeyReadOnlyGuard /
		// mfaStepUpGuard 的 DecideMFAStepUp / readOnlyGuard 白名单）统一放行
		// 到 handler，由其返回统一 404「无会话令牌可吊销」——只读 Key 此前
		// 得 403，与 JWT/从节点口径不一致。
		if c.Request.Method == http.MethodPost && path == "/api/v1/auth/logout" {
			c.Next()
			return
		}
		// （2026-09 审计）：导出类 GET 敏感度等同写操作（完整备份含全部用户/
		// 密钥哈希与私钥明文）——只读 Key 不得经 GET 旁路导出，单独设卡。
		if c.Request.Method == http.MethodGet && sensitiveExportGetRoutes[path] {
			recordAuthenticationRejection(c, "api_key_read_only")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "只读 API Key 不能导出配置备份"})
			return
		}
		if !writeMethods[c.Request.Method] {
			c.Next()
			return
		}
		if services.IsReadOnlyWriteRoute(c.Request.Method, path) {
			c.Next()
			return
		}
		recordAuthenticationRejection(c, "api_key_read_only")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "只读 API 密钥禁止写操作"})
	}
}

// 挂载面：admin/business 两组级——admin 组内 adminOnly
// 先于本守卫（非管理员先见 403 角色真因），business 组内 readOnlyGuard 先于本
// 守卫（对称同口径；从节点短路保留在守卫内作兜底）。
// v1 级直挂路由（openapi.yaml/caddy/metrics/logout）本就不在覆盖面（GET 非敏感
// 导出、logout 豁免），下沉无行为变化。

// mfaStepUpGuard v2.1.8：MFA 写操作验证（全局开关，默认关；五次：60 秒窗）。开启时，启用 MFA
// 的 JWT 用户执行写操作（readOnlyWriteRoutes 判定源——与只读密钥同一事实源，契约
// 绊线自动覆盖两侧）且 mfa_ts 距今超过 60 秒 → 428，前端全局弹码验证后携新
// JWT 重试。API Key/MCP 认证豁免（机器身份无 MFA 概念）。（2026-09 审计）
// GET /config/export 与写操作同级（导出含全部用户/密钥哈希的完整备份），一并
// 纳入 step-up 覆盖。
//
// database 由装配期捕获（与 readOnlyGuard/clusterVersionMiddleware 同口径）：
// 此前后备角色读取走包级 db.GetDB()，成为本包唯一「句柄来源第三态」——测试
// 注入/多库形态下与同请求上的只读门可能读到不同库（一处 403、一处 428/放行）。
func mfaStepUpGuard(database *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		covered := writeMethods[c.Request.Method] ||
			// 敏感 GET(与写操作同门)：名单与 apiKeyReadOnlyGuard 共用同一事实源
			(c.Request.Method == http.MethodGet && sensitiveExportGetRoutes[path])
		// 判定单源（handlers.DecideMFAStepUp）：覆盖面、机器身份、机制本体/
		// 只读语义写路由豁免、OIDC 会话短路、开关与 MFA 状态读取、宽限窗全部
		// 只有一份——handler 内联副本（特权 API Key 创建）共用同一实现。
		decision, decisionErr := handlers.DecideMFAStepUp(c, covered, database, func(userID int) (bool, error) {
			return mfaUserEnabledCheckWith(database, userID)
		})
		if decisionErr != nil {
			if errors.Is(decisionErr, handlers.ErrMFAStepUpGuardUnreadable) {
				// 2026-09-08 裁定维持：DB 读失败时守卫关闭是
				// 有意设计——step-up 是第二因子便利层（jwtAuth 已在前序 fail-closed
				// 把关），DB 故障时锁死全部写操作不可取。显式留痕（口径与
				// MFALockoutEnabled 的读失败显性错误一致）。
				services.Logf("warn", "MFA 写操作验证开关读取失败，按关闭处理（fail-open，第二因子便利层）: %v", decisionErr)
				c.Next()
				return
			}
			// DB 错误与「MFA 未启用」必须分判——未启用是合理直通；
			// DB 错误必须 fail-closed（与本文件同类守卫的基建错误 500 中止同口径，
			// 如 apiKeyAuth 的白名单解析失败）：瞬时 DB 失败落穿此处会让已启用
			// MFA 的用户整体绕过 step-up（fail-open），等同二因子静默旁路。
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "MFA 状态查询失败"})
			return
		}
		if !decision.Applies {
			c.Next()
			return
		}
		if decision.Verified {
			// 守卫验码放行路径置标记——handler(MFAResetByAdmin)采信标记而非
			// 重读开关，消除开关在中间件后翻转的毫秒窗 TOCTOU。置位必须在
			// 放行分支内：428 拒绝路径不得留下「假已验证」标记。
			c.Set("mfa_stepup_verified", true)
			// 验码年龄随标记注入——拆除/重绑 MFA 的 handler 据此把免验收窄到
			// ≤15s 窄窗（mfaDestructiveStepUpWindow），通用宽限窗语义不变。
			c.Set("mfa_stepup_seconds_ago", decision.SecondsAgo)
			// 宽限窗内静默放行时告知用户（TOTP 同片不可重用，窗口内的操作
			// 没有可用码也照常执行），前端据此提示「xx 秒内已验证」。
			c.Header("X-Mfa-Verified-Seconds-Ago", strconv.FormatInt(decision.SecondsAgo, 10))
			c.Next()
			return
		}
		// 从节点短路先于 428——只读门（readOnlyGuard）挂载
		// 在本守卫之后的 admin 组，从节点 MFA 用户此前先收 428、输码重试后才见
		// 403 真因。此处按只读门同法查询（COALESCE 兜底）；从节点直接 403，
		// 查询失败与只读门同语义 fail-closed 500。verify-step/logout 已在上游
		// 豁免，本判定影响本将收到 428 的写请求与敏感 GET 导出（从节点敏感 GET 导出现同此短路，直收 403，不再先 428——注释勘正）。
		var isMaster bool
		if database == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "节点角色查询失败"})
			return
		}
		var roleErr error
		if isMaster, roleErr = services.RoleOf(c.Request.Context(), database); roleErr != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "节点角色查询失败"})
			return
		}
		// 从节点短路排除只读门白名单路径——/cluster/*
		// 补救端点（forget-pins/promote 等仅能从节点执行，主节点 handler 拒绝）
		// 若短路 403「请在主节点操作」则前端弹码链（仅 428 触发）断裂、补救
		// 实质不可达。白名单路径落穿至 428：弹码→verify-step 刷新 mfa_ts→重试
		// →readOnlyGuard 白名单放行（readonly.go:68-74），链路恢复。
		if !isMaster && !isReadOnlyGuardWhitelisted(c.Request.URL.Path) {
			recordAuthenticationRejection(c, "slave_write_denied")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "从节点只读，请在主节点操作"})
			return
		}
		c.AbortWithStatusJSON(http.StatusPreconditionRequired, gin.H{"code": 428, "message": "MFA_STEP_UP_REQUIRED", "detail": "此操作需要 MFA 验证"})
	}
}

func hasJWTBearer(c *gin.Context) bool {
	authHeader := c.GetHeader("Authorization")
	return bearerToken(authHeader) != "" && !apikey.IsAPIKeyAuthorization(authHeader)
}

func adminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			recordAuthenticationRejection(c, "admin_required")
			c.JSON(http.StatusForbidden, gin.H{"code": 403, "message": "需要管理员权限"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// selfServiceUserTarget 是「本人用户行」target/actor 判定的单源。
// 返回归一后的 target 供调用方区分无效 ID（400）与非本人（403）。
// user_id 类型归一复用 handlers.ContextUserID：jwtAuth 存 float64、apiKeyAuth
// 存 int、MCP 内部转发可能存 string 数字，两个守卫不得各写一份类型 switch。
func selfServiceUserTarget(c *gin.Context, rawTarget string) (int, bool) {
	target, err := strconv.Atoi(rawTarget)
	if err != nil || target <= 0 {
		return 0, false
	}
	actor := int(handlers.ContextUserID(c))
	return target, actor > 0 && actor == target
}

// adminOrSelfParam 允许管理员操作任意用户，非管理员仅允许操作自己的用户行
// （路径 :id == JWT user_id）。用于用户管理页「本人编辑/重置密码」自助路径；
// 该页的编辑/重置为重置语义（不验当前密码），正常改密仍走个人资料弹框。
// 角色/用户名的自助限制由 handler 二次守卫。
func adminOrSelfParam() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("role") == "admin" {
			c.Next()
			return
		}
		target, self := selfServiceUserTarget(c, c.Param("id"))
		if target <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "用户 ID 无效"})
			c.Abort()
			return
		}
		if !self {
			recordAuthenticationRejection(c, "admin_required")
			c.JSON(http.StatusForbidden, gin.H{"code": 403, "message": "需要管理员权限"})
			c.Abort()
			return
		}
		c.Next()
	}
}
