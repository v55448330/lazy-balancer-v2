package models

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidClusterAccessURL = errors.New("访问地址必须是无凭证、查询参数或片段的 HTTP 或 HTTPS URL")

// ErrInvalidClusterNodeName 归一后为空的节点名（仅含空白/控制字符）——handler
// 映射 400（客户端可修正），区别于服务端故障。
var ErrInvalidClusterNodeName = errors.New("节点名不能为空")

// ErrMissingClusterNodeIP 自述地址缺失且注册来源地址不可用（非 IP 字面量）——
// 无法确定节点身份时拒绝注册，而不是写入回环地址与既有节点互相覆盖。
var ErrMissingClusterNodeIP = errors.New("无法确定节点地址，请在节点设置中配置访问地址后重试")

// ClusterNodeNameMaxLen 节点名长度上限（与 nodes.name VARCHAR(100) 一致）。
// HTTP 入口由 binding max=100 拦截，服务层落库前经 NormalizeClusterNodeName
// 再归一（控制字符剥离 + 截断），两侧共用同一上限。
const ClusterNodeNameMaxLen = 100

type ClusterRegisterRequest struct {
	Token string `json:"token" binding:"required"`
	Name  string `json:"name" binding:"required,max=100"`
	// IPAddress 是自述机器地址：出口 IP 探测失败的从节点按空串上报，由主节点
	// 以服务端观测到的注册来源地址落库（空值若被 binding 拒绝，两台无默认路由
	// 的从节点只能回退 127.0.0.1，命中 UNIQUE(ip_address,port) 互相覆盖）。
	IPAddress string `json:"ip_address" binding:"omitempty,ip"`
	Port      int    `json:"port" binding:"omitempty,min=1,max=65535"`
	Protocol  string `json:"protocol" binding:"omitempty,oneof=http https"`
	AccessURL string `json:"access_url"`
}

type ClusterNodeAccessURLRequest struct {
	AccessURL string `json:"access_url"`
}

// ClusterNodeSiteRequest 主节点为指定从节点配置大屏站点坐标（node-local 下发）。
type ClusterNodeSiteRequest struct {
	ServerMapLat *float64 `json:"server_map_lat"`
	ServerMapLon *float64 `json:"server_map_lon"`
}

func ValidateClusterAccessURL(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidClusterAccessURL
	}
	return nil
}

// clusterNodeNameBlankGlyphs 是「视觉空白」字形集：渲染为空但既非 Cf 也非
// unicode.IsSpace（U+2800 盲文空白属 So、U+3164/U+115F/U+1160/U+FFA0 属韩文
// 填充字符）。整名只由它们组成时，集群列列表/切换节点选择器/审计详情的节点列
// 都显示为空白，管理员无法辨认是哪台机器、也对不上审计——与 Cf 同处置直接
// 剥离，而不是只做空白态判定。
var clusterNodeNameBlankGlyphs = map[rune]struct{}{
	'\u115f': {}, // HANGUL CHOSEONG FILLER
	'\u1160': {}, // HANGUL JUNGSEONG FILLER
	'\u2800': {}, // BRAILLE PATTERN BLANK
	'\u3164': {}, // HANGUL FILLER
	'\uffa0': {}, // HALFWIDTH HANGUL FILLER
}

// NormalizeClusterNodeName 节点名落库侧单源归一：去首尾空白、
// 剥离控制字符、Unicode 格式字符（Cf，保留 ZWJ）与视觉空白填充字形、
// 按 schema VARCHAR(100) 上限截断到合法 UTF-8 边界。HTTP 入口
// 由 binding max=100 拦截；服务层直调与旧客户端仍需同一兜底（SQLite 不强制
// VARCHAR 长度），否则 16KB 注册体可把超长/带换行的名字写进 nodes 并回显。
func NormalizeClusterNodeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Map(func(r rune) rune {
		// C0、DEL 与 C1（0x80-0x9F）均为控制字符；旧实现漏 C1，注释口径
		// 与行为不一致。
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		// Unicode Cf（格式字符）：双向覆盖/重排（U+202A-202E、U+2066-2069）、
		// 零宽与方向标记、BOM 等。节点名进入集群列表与审计详情，格式字符
		// 可让显示名视觉重排、与真实节点名混淆（「哪个是主节点」被污染）。
		// ZWJ（U+200D）保留——emoji 组合的合法组成，删除会破坏名称显示。
		if r != '\u200d' && unicode.Is(unicode.Cf, r) {
			return -1
		}
		// 视觉空白填充字形：非 Cf、非空白，但渲染上是空的（见上表）。
		if _, blank := clusterNodeNameBlankGlyphs[r]; blank {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	// 截断在前、空白态判定在后：截断可能把「可见字符位于上限之后」的名字
	// 裁成纯隐形字符（100 个 ZWJ + 可见字符 → 100 个 ZWJ），判据若在截断
	// 之前运行就已错过，落库值仍是视觉空名。
	if utf8.RuneCountInString(name) > ClusterNodeNameMaxLen {
		name = string([]rune(name)[:ClusterNodeNameMaxLen])
	}
	// ZWJ 例外只服务 emoji 组合：整名仅由 ZWJ 与空白构成时它不携带任何可见
	// 字符，归一到空（由调用方按 ErrInvalidClusterNodeName 拒绝），否则会落成
	// 视觉空名（集群列表/审计详情的节点列显示空白）。
	if name != "" && strings.TrimFunc(name, func(r rune) bool { return r == '\u200d' || unicode.IsSpace(r) }) == "" {
		return ""
	}
	return name
}

// ClusterAccessURLHostMatchesIP 判定自述访问地址的主机是否即注册来源 IP。
// access_url 是能力票据（服务控制/登录票据）的投递地址，注册方自述值只在与
// **服务端观测到的来源地址**一致时可信；其余必须由管理员经节点访问地址端点
// 显式配置，避免已发注册令牌把票据引向任意第三方主机。
//
// ipAddress 必须是 IP 字面量：主机名/空串/非法串不构成可比的信任锚（曾以
// 请求体自述 ip_address 传入，比较双方同源等于未校验；主机名分支还会让
// 「URL 主机 == 自述主机名」这类同源比较成立，故整条按不可信处理）。
func ClusterAccessURLHostMatchesIP(accessURL, ipAddress string) bool {
	if accessURL == "" {
		return true
	}
	sourceIP := net.ParseIP(strings.TrimSpace(ipAddress))
	if sourceIP == nil {
		return false
	}
	parsed, err := url.Parse(accessURL)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "" {
		return false
	}
	parsedIP := net.ParseIP(host)
	return parsedIP != nil && parsedIP.Equal(sourceIP)
}

// ClusterAccessURLTargetsNode 尽力识别主节点地址是否指向本机监听端口。
// 仅接受明确的 loopback/localhost 或本机出口 IP，不做 DNS 解析；主机别名与
// 反向代理后的自环无法可靠识别，调用方不得把 false 当作安全保证。
func ClusterAccessURLTargetsNode(accessURL, ipAddress string, port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	parsed, err := url.Parse(accessURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return false
	}
	targetPort := parsed.Port()
	if targetPort == "" {
		switch parsed.Scheme {
		case "http":
			targetPort = "80"
		case "https":
			targetPort = "443"
		}
	}
	if targetPort != strconv.Itoa(port) {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return ClusterAccessURLHostMatchesIP(accessURL, ipAddress)
}

type ClusterLoginTicketRequest struct {
	Ticket string `json:"ticket" binding:"required"`
}

type ClusterLoginTicketClaims struct {
	UserID     int    `json:"user_id"`
	Username   string `json:"username"`
	AuthMethod string `json:"auth_method,omitempty"`
	NodeID     int    `json:"node_id"`
	JTI        string `json:"jti"`
	ExpiresAt  int64  `json:"expires_at"`
}

// 集群服务控制动作（主节点 → 从节点）：Caddy 进程启停与应用进程重启。
const (
	ClusterServiceActionStartCaddy   = "start_caddy"
	ClusterServiceActionStopCaddy    = "stop_caddy"
	ClusterServiceActionRestartCaddy = "restart_caddy"
	ClusterServiceActionRestartApp   = "restart_app"
)

// IsValidClusterServiceAction 判定动作是否在受控集合内（主从两侧共用同一口径）。
func IsValidClusterServiceAction(action string) bool {
	switch action {
	case ClusterServiceActionStartCaddy, ClusterServiceActionStopCaddy, ClusterServiceActionRestartCaddy, ClusterServiceActionRestartApp:
		return true
	}
	return false
}

// ClusterNodeServiceRequest 主节点服务控制端点请求体。
type ClusterNodeServiceRequest struct {
	Action string `json:"action" binding:"required"`
}

// ClusterServiceControlRequest 从节点服务控制端点请求体：票据即凭证
// （HMAC-SHA256，密钥为集群令牌哈希，90 秒一次性，与动作绑定）。
type ClusterServiceControlRequest struct {
	Action string `json:"action" binding:"required"`
	Ticket string `json:"ticket" binding:"required"`
	// Operator 是主节点侧实际操作人用户名。已知边界：该字段不在签名载荷内
	// （票据只绑定 node/action/jti/expiry），属持票方可自述的未认证字段——
	// 从节点审计据此显示操作人，不改变可执行动作；TLS/TOFU 通道下无外部
	// 伪造面。空串回退「主节点」。
	Operator string `json:"operator,omitempty"`
}

// ClusterServiceControlClaims 服务控制票据载荷。
type ClusterServiceControlClaims struct {
	NodeID    int    `json:"node_id"`
	Action    string `json:"action"`
	JTI       string `json:"jti"`
	ExpiresAt int64  `json:"expires_at"`
}

// ClusterServiceControlIssue 主节点签发结果：票据 + 目标从节点信息（不跨网络传输）。
type ClusterServiceControlIssue struct {
	Ticket   string
	NodeName string
	URL      string
}

type ClusterLoginTicketResponse struct {
	Ticket string `json:"ticket"`
	URL    string `json:"url"`
	// NodeName 仅供主端本地使用(审计事件带节点名),不随响应下发。
	NodeName string `json:"-"`
}

type ClusterModeRequest struct {
	Mode          string `json:"mode" binding:"required,oneof=master slave"`
	MasterURL     string `json:"master_url"`
	RegisterToken string `json:"register_token"`
	NodeName      string `json:"node_name" binding:"omitempty,max=100"`
}

type ClusterSettingsRequest struct {
	// SyncInterval 范围校验（10-86400）在 ClusterService.UpdateSettings 完成，
	// 以便返回「同步间隔需在 10-86400 秒之间」的具体文案；binding 层不再拦截。
	// 三分类合并(2026-09-19):sync_global_config/sync_waf_files 字段随开关
	// 列删除(全局配置并入系统数据、规则库并入安全防护)。
	SyncInterval *int  `json:"sync_interval"`
	SyncUsers    *bool `json:"sync_users"`
	SyncRules    *bool `json:"sync_rules"`
	SyncSecurity *bool `json:"sync_security"`
}

type ClusterRegistration struct {
	RegistrationID     int    `json:"registration_id"`
	RegistrationSecret string `json:"registration_secret"`
	// OverwrittenNodeID/OverwrittenNodeName 在重复 ip:port 注册命中「已批准」
	// 节点时回填：upsert 是既有兼容路径，但静默重置审批
	// 与令牌会让运营方误以为是新节点——响应与审计必须点名被覆盖的节点。
	OverwrittenNodeID   int    `json:"overwritten_node_id,omitempty"`
	OverwrittenNodeName string `json:"overwritten_node_name,omitempty"`
	// AccessURLIgnored 表示注册请求自述的 access_url 与来源 IP 不一致而被忽略
	// （access_url 是能力票据投递地址，只接受与注册来源一致的
	// 自述值；其余必须由管理员经节点访问地址端点显式配置）。
	AccessURLIgnored bool `json:"access_url_ignored,omitempty"`
}

type ClusterRegistrationStatus struct {
	Status       string `json:"status"`
	ClusterToken string `json:"cluster_token,omitempty"`
}

// SyncErrorCode 的取值与 ClusterReport.SyncErrorCode 上的 binding oneof 标签
// 是同一集合的两个事实源（struct tag 无法由常量拼出）：新增/改名错误码必须
// 同时改标签，TestSyncErrorCodeMatchesBindingOneof 会钉住两侧一致。
type SyncErrorCode string

const (
	SyncErrorCodeSchemaTooNew     SyncErrorCode = "schema_too_new"
	SyncErrorCodeSchemaTooOld     SyncErrorCode = "schema_too_old"
	SyncErrorCodeSignatureInvalid SyncErrorCode = "signature_invalid"
	SyncErrorCodePinMismatch      SyncErrorCode = "pin_mismatch"
	SyncErrorCodeValidationFailed SyncErrorCode = "validation_failed"
	SyncErrorCodeApplyFailed      SyncErrorCode = "apply_failed"
	SyncErrorCodeTransportError   SyncErrorCode = "transport_error"
)

type ClusterHealth struct {
	CaddyOK          bool          `json:"caddy_ok"`
	RulesCount       int           `json:"rules_count"`
	CertsExpiring30d int           `json:"certs_expiring_30d"`
	LastSyncAt       string        `json:"last_sync_at"`
	LastSyncError    string        `json:"last_sync_error"`
	SyncErrorCode    SyncErrorCode `json:"sync_error_code,omitempty"`
	UptimeSec        int64         `json:"uptime_sec"`
	// v2.3.0(2026-09-18 用户裁定):从节点规则库版本随上报上送——主节点集群
	// 管理节点列表状态列 hover 可见,替代登录从节点查看。
	CRSVersion   string `json:"crs_version,omitempty"`
	IP2RegionTag string `json:"ip2region_version,omitempty"`
	// 多源规则库版本（威胁情报库 / 爬虫地址库）随上报上送：主节点集群列表
	// hover 与从节点本地展示同口径——各源 version 取最近（日期/semver 通用），
	// 空源或全部为空版本时为空串（前端按「未更新」显示）。
	ThreatVersion  string `json:"threat_version,omitempty"`
	CrawlerVersion string `json:"crawler_version,omitempty"`
}

type ClusterReport struct {
	AppliedVersion int `json:"applied_version" binding:"min=0"`
	// ServiceStatus 保留：主节点
	// 当前不消费该字段（cluster_status.go 的节点视图不读它，前端亦无渲染点），
	// 但 binding 强校验仍要求从节点上报 ok/degraded。删除会破坏旧主/旧从
	// 滚动升级期的上报契约（旧主节点对缺字段的绑定校验直接 400），故保留到
	// 协议版本升级时再清理。
	ServiceStatus string        `json:"service_status" binding:"required,oneof=ok degraded"`
	Health        ClusterHealth `json:"health"`
	LastSyncAt    string        `json:"last_sync_at"`
	LastSyncError string        `json:"last_sync_error"`
	SyncErrorCode SyncErrorCode `json:"sync_error_code,omitempty" binding:"omitempty,oneof=schema_too_new schema_too_old signature_invalid pin_mismatch validation_failed apply_failed transport_error"`
	// SectionHashes 携带从节点 cluster_applied_sections 的已应用节哈希（本地
	// 当前已落库口径），供主节点聚合 per-section 同步状态。旧版本从节点不上
	// 报（nil，omitempty 省略字段），主节点据此展示「旧版本从节点」占位。
	SectionHashes map[string]string `json:"section_hashes,omitempty"`
	// SectionHashesUnavailable 为真表示本节点本轮**读取失败**（瞬时 IO 抖动，
	// 如 SQLITE_BUSY）而非「没有记录」：此时 SectionHashes 缺省不代表旧版本从
	// 节点，主节点必须保留该节点历史分区状态——否则节点列表的分区同步列会整体
	// 消失，运维信号从「某节滞后」退化为「无数据」。旧版本从节点两个字段都不
	// 携带，仍走清理语义。
	SectionHashesUnavailable bool `json:"section_hashes_unavailable,omitempty"`
	// Detached 为真表示从节点已提升脱离，请求主节点删除本节点记录（令牌随行撤销）。
	Detached bool `json:"detached"`
}

// ClusterSectionSyncStatus 是主节点状态端点聚合的单个同步节比对结果：
// Hash 为从节点上报的本地哈希，MasterHash 为主节点自身快照节哈希，
// Synced 仅在两者非空且一致时为真（从节点缺记录按滞后处理）。
type ClusterSectionSyncStatus struct {
	Section    string `json:"section"`
	Label      string `json:"label"`
	Hash       string `json:"hash"`
	MasterHash string `json:"master_hash"`
	Synced     bool   `json:"synced"`
}

type ClusterBasicSettings struct {
	LogLevel *string `json:"log_level,omitempty"`
	// BrandingJSON 是主节点 branding.json 原文镜像(2026-09-11 裁定):随
	// 快照下发,从节点落盘本地文件后生效。三分类合并后随系统数据节
	// (恒同步)恒携带。指针区分旧主端缺席与显式空串。
	BrandingJSON         *string `json:"branding_json,omitempty"`
	AccessLogJSON        *bool   `json:"access_log_json,omitempty"`
	AccessLogFormat      *string `json:"access_log_format,omitempty"`
	TaskLogSizeMB        *int    `json:"task_log_size_mb,omitempty"`
	AuditLogSizeMB       *int    `json:"audit_log_size_mb,omitempty"`
	RuntimeLogSizeMB     *int    `json:"runtime_log_size_mb,omitempty"`
	AuditRetentionMonths *int    `json:"audit_retention_months,omitempty"`
	// v2.3.8 安全事件保留与光流采样：随 users 节同步（从节点/升主后
	// 保留策略与大屏采样口径与主节点一致）；指针+omitempty 用于旧主端
	// 快照缺席时保留从端本地值。ThreatTrafficSampleN：-1=自适应 / 0=关闭；
	// 全量与固定 2..64 已废除，旧快照/库值由读侧/迁移归 -1。
	SecurityEventsRetentionDays *int `json:"security_events_retention_days,omitempty"`
	SecurityEventsRowCap        *int `json:"security_events_row_cap,omitempty"`
	ThreatTrafficSampleN        *int `json:"threat_traffic_sample_n,omitempty"`
	// ThreatScreenMode 大屏中央视觉模式（map/globe）：与同组大屏口径列一并
	// 随 users 节同步——从节点只读（写入口在从节点被只读门拒绝），配置
	// 必须由主节点经快照下发，否则从端永远停留在默认视觉。指针+omitempty
	// 用于旧主端快照缺席时保留从端本地值；apply 侧按 models 枚举归一
	// （非法值回默认，与写侧 400 白名单同源）。
	ThreatScreenMode           *string `json:"threat_screen_mode,omitempty"`
	JWTExpireMinutes           *int    `json:"jwt_expire_minutes,omitempty"`
	Timezone                   *string `json:"timezone,omitempty"`
	ACMEEmail                  *string `json:"acme_email,omitempty"`
	CertExpiryDays             *int    `json:"cert_expiry_days,omitempty"`
	CertRenewalDays            *int    `json:"cert_renewal_days,omitempty"`
	CertRenewalAttempts        *int    `json:"cert_renewal_attempts,omitempty"`
	DefaultCAProviderID        *int    `json:"default_ca_provider_id,omitempty"`
	SyncInterval               *int    `json:"sync_interval,omitempty"`
	CaddyLogLevel              *string `json:"caddy_log_level,omitempty"`
	CaddyLogSizeMB             *int    `json:"caddy_log_size_mb,omitempty"`
	RequestBodyMaxSizeMB       *int    `json:"request_body_max_size_mb,omitempty"`
	HTTPReadTimeout            *int    `json:"http_read_timeout,omitempty"`
	HTTPWriteTimeout           *int    `json:"http_write_timeout,omitempty"`
	HTTPIdleTimeout            *int    `json:"http_idle_timeout,omitempty"`
	UpstreamKeepaliveTimeout   *int    `json:"upstream_keepalive_timeout,omitempty"`
	ProxyDialTimeout           *int    `json:"proxy_dial_timeout,omitempty"`
	ProxyResponseHeaderTimeout *int    `json:"proxy_response_header_timeout,omitempty"`
	ProxyReadTimeout           *int    `json:"proxy_read_timeout,omitempty"`
	ProxyWriteTimeout          *int    `json:"proxy_write_timeout,omitempty"`
	ProxyStreamTimeout         *int    `json:"proxy_stream_timeout,omitempty"`
	ProxyFlushInterval         *int    `json:"proxy_flush_interval,omitempty"`
	ProxyStreamCloseDelay      *int    `json:"proxy_stream_close_delay,omitempty"`
	GitHubProxyURL             *string `json:"github_proxy_url,omitempty"`
	ServerTokensHidden         *bool   `json:"server_tokens_hidden,omitempty"`
	// v2.3.x 受信代理（CDN 真实 IP）：随 Caddy 全局轴同步——从节点渲染层
	// （servers.trusted_proxies）与数据面取值与主节点一致。range_refs 为
	// 引用的 IP 地址列表 id（JSON 数组文本，2026-10-12），引用的名单本体
	// 在 security 节同步——从端渲染同样投影（tp.txt/lb_file 热路径，2026-10-15）。
	TrustedProxyEnabled   *bool   `json:"trusted_proxy_enabled,omitempty"`
	TrustedProxyRanges    *string `json:"trusted_proxy_ranges,omitempty"`
	TrustedProxyRangeRefs *string `json:"trusted_proxy_range_refs,omitempty"`
	TrustedProxyHeaders   *string `json:"trusted_proxy_headers,omitempty"`
	TrustedProxyStrict    *bool   `json:"trusted_proxy_strict,omitempty"`
	AdminTLSEnabled       *bool   `json:"admin_tls_enabled,omitempty"`
	AdminTLSMode          *string `json:"admin_tls_mode,omitempty"`
	AdminTLSCert          *string `json:"admin_tls_cert,omitempty"`
	AdminTLSKey           *string `json:"admin_tls_key,omitempty"`
	// v2.1.8 MFA 全局开关（决策3：从节点行为与主节点一致）。
	MFAWriteGuard *bool `json:"mfa_write_guard,omitempty"`
	// v2.3.0:OIDC 配置(原样 JSON 字符串)随 global 节同步——从节点回调独立
	// 闭环需要本地可读 issuer/client 凭证(JWKS 验签在从节点本地完成)。
	OIDCConfig        *string `json:"oidc_config,omitempty"`
	MFALockoutEnabled *bool   `json:"mfa_lockout_enabled,omitempty"`
	// v2.3.x:自动备份设置随 users 节同步——从节点提升为主节点后调度
	// 直接生效,无需重启。指针+omitempty 缺席语义(镜像 branding_json
	// d55a675 偏斜处理):旧主端快照缺该组字段时从端 apply 跳过写入、保留
	// 本地设置,不清零;新主端装载恒非 nil(COALESCE 兜底),快照恒携带。
	// last_run 为节点本地运行态,不在同步列(调度器每次备份推进,入列会让
	// 触发器每轮备份 bump cluster_version)。
	AutoBackupEnabled   *bool   `json:"auto_backup_enabled,omitempty"`
	AutoBackupFrequency *string `json:"auto_backup_frequency,omitempty"`
	AutoBackupTime      *string `json:"auto_backup_time,omitempty"`
	AutoBackupDay       *int    `json:"auto_backup_day,omitempty"`
	AutoBackupKeep      *int    `json:"auto_backup_keep,omitempty"`
	AutoBackupSections  *string `json:"auto_backup_sections,omitempty"`
	// 威胁库任务级排程三列随 users 节同步——从节点
	// 提升为主后调度直接生效（镜像自动备份组）。指针+omitempty 缺席
	// 语义：旧主端快照缺该组时从端 apply 跳过写入、保留本地设置，不清零；
	// 新主端装载恒非 nil（COALESCE 兜底），快照恒携带。
	ThreatAutoUpdate   *bool   `json:"threat_auto_update,omitempty"`
	ThreatScheduleDays *string `json:"threat_schedule_days,omitempty"`
	ThreatScheduleTime *string `json:"threat_schedule_time,omitempty"`
	// 爬虫地址库独立总闸与排程三列（与 threat_* 完全分离）。
	CrawlerAutoUpdate   *bool   `json:"crawler_auto_update,omitempty"`
	CrawlerScheduleDays *string `json:"crawler_schedule_days,omitempty"`
	CrawlerScheduleTime *string `json:"crawler_schedule_time,omitempty"`
	// 自动封禁六项配置随 users 节同步——从节点提升为主节点
	// 后调度按主端配置直接生效（镜像自动备份组/ 威胁排程组）。
	// 指针+omitempty 缺席语义：旧主端快照缺该组时从端 apply 跳过写入、保留本地
	// 设置，不清零；新主端装载恒非 nil（COALESCE 兜底），快照恒携带。此前六列
	// 不入快照：从端恒默认值（名单传播而配置不传播），升主后按陈旧配置静默运行。
	AutobanEnabled       *bool   `json:"autoban_enabled,omitempty"`
	AutobanThreshold     *int    `json:"autoban_threshold,omitempty"`
	AutobanWindowMinutes *int    `json:"autoban_window_minutes,omitempty"`
	AutobanDuration      *string `json:"autoban_duration,omitempty"`
	AutobanScope         *string `json:"autoban_scope,omitempty"`
	AutobanDryRun        *bool   `json:"autoban_dry_run,omitempty"`
}

type ClusterUser struct {
	ID                int          `json:"id"`
	Username          string       `json:"username"`
	PasswordHash      string       `json:"password_hash"`
	Role              string       `json:"role"`
	DisplayName       string       `json:"display_name"`
	IsEnabled         bool         `json:"is_enabled"`
	PasswordVersion   int64        `json:"password_version"`
	PasswordChangedAt *string      `json:"password_changed_at"`
	CreatedAt         time.Time    `json:"created_at"`
	LastLogin         JSONNullTime `json:"last_login"`
	// v2.1.8 MFA（决策3）：随快照同步——从节点本地验证 TOTP，无需回主节点。
	MFAEnabled       bool   `json:"mfa_enabled"`
	MFASecret        string `json:"mfa_secret"`
	MFARecoveryCodes string `json:"mfa_recovery_codes"`
	MFALastTimestep  int64  `json:"mfa_last_timestep"`
	// v2.3.0 OIDC:身份三列随快照同步——缺列会让从节点把 OIDC 用户当本地账号
	// (空 password_hash 在本地语义=不可登录,OIDC 登录也因 auth_provider 丢失而失效)。
	AuthProvider string `json:"auth_provider,omitempty"`
	OIDCSubject  string `json:"oidc_subject,omitempty"`
	OIDCIssuer   string `json:"oidc_issuer,omitempty"`
	// IsSetupAdmin 标记 break-glass 管理入口：**不随快照同步**——users 节在
	// canonical 载荷里由 sanitizeUsersForHash 清零，本字段的下发值恒为 false
	// （JSON 形状保留以兼容旧协议解析）。从节点落库后按「最低 id 的启用管理员」
	// 本地归一（db.EnsureSetupAdminFlag），故保护对象由各节点按本地用户表现算：
	// 主端标记若带外落在非最低 id 的管理员上，从节点会保护另一行。备份导出/
	// 还原走独立载荷，标记在其中如实落库。
	IsSetupAdmin bool `json:"is_setup_admin,omitempty"`

	// pending 密钥不跨节点（绑定向导是节点本地交互；半途切换面板属可重做流程）。
}

// ClusterLockedUser 是主节点活跃登录锁的同步载荷：主节点账号被锁
// 状态必须传播到从节点（从节点本地锁定独立生效）。走快照独立顶层载荷
// locked_users，而**不**进入 users 载荷/节哈希/漂移守卫——注意这不等于
// 「login_locked_until 不参与触发」：该列在 cluster_version.go 的 users
// snapshotColumns 内，值变化（置锁/解锁）照常 bump 集群版本（值变化守卫保证
// 登录热路径的保值写零抖动），从节点 304 门因此失效并拿到携带新锁状态的整体
// 快照；锁状态本身经本顶层载荷下发。仅 login_failed_attempts（失败计数）不入列。
// 若把该列从 snapshotColumns 移除，锁将永不传播（从节点对已锁定账号仍可登录），
// 且无测试会红——改动该列前先读本节与 cluster_version.go 同处的修订说明。
// 只携带未来时间的活跃锁（与 loginLockedNow 同口径），自然过期后条目自动从
// 快照消失。
type ClusterLockedUser struct {
	Username    string `json:"username"`
	LockedUntil string `json:"locked_until"`
}

type ClusterAPIKey struct {
	ID             int          `json:"id"`
	Name           string       `json:"name"`
	KeyHash        string       `json:"key_hash"`
	KeyPrefix      string       `json:"key_prefix"`
	CreatedBy      int          `json:"created_by"`
	LastUsed       JSONNullTime `json:"last_used"`
	ExpiresAt      string       `json:"expires_at"`
	IsEnabled      bool         `json:"is_enabled"`
	MCPEnabled     bool         `json:"mcp_enabled"`
	ReadOnly       bool         `json:"read_only"`
	MCPIPWhitelist []string     `json:"mcp_ip_whitelist"`
	CreatedAt      time.Time    `json:"created_at"`
}

type ClusterCertificate struct {
	RuleID           string       `json:"rule_id"`
	Domain           string       `json:"domain,omitempty"`
	CertPEM          string       `json:"cert_pem"`
	KeyPEM           string       `json:"key_pem"`
	ExpiresAt        string       `json:"expires_at"`
	CAProviderID     int          `json:"ca_provider_id,omitempty"`
	SourceStatus     string       `json:"source_status,omitempty"`
	RenewalAttempts  int          `json:"renewal_attempts,omitempty"`
	CAAvailableAfter JSONNullTime `json:"ca_available_after"`
	LastErrorCode    string       `json:"last_error_code,omitempty"`
	// 源 row 的时间轴（平面 UTC 串）：从端镜像行若不自带时间，任务行时间会归零
	// 为「同步时刻」，升主后历史时间线失真。旧主端快照缺省时 apply 回落既有
	// DB 默认（created_at=CURRENT_TIMESTAMP/updated_at=NULL）。
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type ClusterACMEState struct {
	CAProviders        []CAProvider        `json:"ca_providers"`
	CertificateConfigs []CertificateConfig `json:"certificate_configs"`
	DNSOwnership       json.RawMessage     `json:"dns_ownership"`
}

type ClusterSnapshot struct {
	Version             int                  `json:"version"`
	SchemaVersion       int                  `json:"schema_version,omitempty"`
	MinReaderVersion    int                  `json:"min_reader_version,omitempty"`
	Fingerprint         string               `json:"fingerprint"`
	Signature           string               `json:"signature,omitempty"`
	CanonicalPayload    json.RawMessage      `json:"canonical_payload,omitempty"`
	Rules               []LbRule             `json:"rules"`
	Users               []ClusterUser        `json:"users"`
	APIKeys             []ClusterAPIKey      `json:"api_keys"`
	BasicSettings       ClusterBasicSettings `json:"basic_settings"`
	CaddyConfig         *string              `json:"caddy_config,omitempty"`
	Certs               []ClusterCertificate `json:"certs"`
	ACME                *ClusterACMEState    `json:"acme,omitempty"`
	SecurityPolicies    json.RawMessage      `json:"security_policies,omitempty"`
	SecurityBindings    json.RawMessage      `json:"security_bindings,omitempty"`
	SecurityCustomRules []SecurityCustomRule `json:"security_custom_rules,omitempty"`
	SecurityBlockPages  []SecurityBlockPage  `json:"security_block_pages,omitempty"`
	// SecurityIPLists（v2.3.0）：可复用 IP 地址列表全量 dump（行结构与
	// security_policies 同款 map 形态）；策略 ip_acl_list_refs/
	// ip_whitelist_refs 以 id 引用本表。缺席=旧主端（v2.3.0-）未携带，
	// 从端保留本地；携带空数组 [] = 显式清空；携带即全量替换。
	SecurityIPLists          json.RawMessage                   `json:"security_ip_lists,omitempty"`
	SecurityCRSVersion       []ClusterSecurityCRSVersion       `json:"security_crs_version,omitempty"`
	SecurityIP2RegionVersion []ClusterSecurityIP2RegionVersion `json:"security_ip2region_version,omitempty"`
	WafFiles                 *ClusterWafFilesRef               `json:"waf_files,omitempty"`
	// 威胁情报库源行（v2.3.x）：随 security 节同步（多行状态机表，
	// 开关/计数/版本全量镜像）。
	SecurityThreatSources json.RawMessage `json:"security_threat_sources,omitempty"`
	// 爬虫地址库独立源行（v2.3.8）：随 security 节同步，不再借威胁源表通道。
	SecurityCrawlerSources json.RawMessage   `json:"security_crawler_sources,omitempty"`
	SectionHashes          map[string]string `json:"section_hashes,omitempty"`
	// MasterSyncSwitches 为主节点三类同步开关（users/rules/security，2026-09-19
	// 三分类归一；修正「五类」陈旧注释），随快照下发；从节点跳过判定
	// 以此为准（从节点本地开关列不参与，避免永远默认全开导致开关失效）。
	MasterSyncSwitches *ClusterSyncSwitchesPayload `json:"master_sync_switches,omitempty"`
	// LockedUsers：主节点活跃登录锁，独立顶层载荷——不参与任何
	// 节哈希/漂移守卫（避免登录失败触发 users 全量重放）；从端只延长不清除。
	// 加性可选字段、omitempty：旧主端缺省 → 从端 no-op；旧从端忽略未知字段
	// （先例：MasterSyncSwitches/WafFiles），故不 bump CurrentSnapshotSchema。
	LockedUsers []ClusterLockedUser `json:"locked_users,omitempty"`
	// NodeSites 为主节点为每个从节点配置的大屏站点坐标（node_id → 坐标）。
	// 从节点按本地 registration_id 取自己的一项应用；加性可选字段，旧从端
	// 忽略未知字段，旧主端缺省时新从端保持本地现值（先例 LockedUsers）。
	NodeSites map[int]ClusterNodeSite `json:"node_sites,omitempty"`
}

// ClusterNodeSite 是单节点的威胁大屏站点坐标（0,0=未设置）。
type ClusterNodeSite struct {
	ServerMapLat float64 `json:"server_map_lat"`
	ServerMapLon float64 `json:"server_map_lon"`
}

// ClusterSyncSwitchesPayload 是主节点同步开关随快照下发的形态(三分类合并
// 后仅 users/rules/security 三键;集群双端同版本升级,不做旧版从节点兼容)。
type ClusterSyncSwitchesPayload struct {
	Users    bool `json:"users"`
	Rules    bool `json:"rules"`
	Security bool `json:"security"`
}

// ClusterWafFilesRef 是快照携带的 WAF 规则文件哈希引用（不含内容）：
// 从节点比对本地哈希，不一致才向主节点 /cluster/sync/waf-files 拉取，
// 规则等 DB 变更引发的快照传输不再搭车 MB 级文件内容。
type ClusterWafFilesRef struct {
	CRSVersion   string `json:"crs_version"`
	CRSSha256    string `json:"crs_sha256"`
	IP2RegionTag string `json:"ip2region_version"`
	IP2RegionSha string `json:"ip2region_sha256"`
	// RDB 文件化：威胁库 .fast 二进制文件哈希（源名 → sha256）
	ThreatSha256s map[string]string `json:"threat_sha256s,omitempty"`
}

// ThreatFileEntry 是单个威胁库 .fast 文件条目（bundle 内嵌传输用）。
type ThreatFileEntry struct {
	Name    string `json:"name"` // 源名（ustc/firehol1/et_compromised）
	Sha256  string `json:"sha256"`
	Content []byte `json:"content,omitempty"` // .fast 二进制内容
}

type ClusterSecurityCRSVersion struct {
	ID           int    `json:"id"`
	Version      string `json:"version"`
	UpdatedAt    string `json:"updated_at"`
	AutoUpdate   bool   `json:"auto_update"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	LastChecked  string `json:"last_checked"`
	NextUpdate   string `json:"next_update"`
	Trigger      string `json:"trigger"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	// 定时更新排程两列随版本行同步（升主即生效）。
	ScheduleDays string `json:"schedule_days"`
	ScheduleTime string `json:"schedule_time"`
}

type ClusterSecurityIP2RegionVersion struct {
	ID           int    `json:"id"`
	Version      string `json:"version"`
	UpdatedAt    string `json:"updated_at"`
	AutoUpdate   bool   `json:"auto_update"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	LastChecked  string `json:"last_checked"`
	NextUpdate   string `json:"next_update"`
	Trigger      string `json:"trigger"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	// 定时更新排程两列随版本行同步（升主即生效）。
	ScheduleDays string `json:"schedule_days"`
	ScheduleTime string `json:"schedule_time"`
}

func (snapshot ClusterSnapshot) MarshalJSON() ([]byte, error) {
	type snapshotAlias ClusterSnapshot
	if snapshot.SchemaVersion < 3 || len(snapshot.CanonicalPayload) == 0 {
		return json.Marshal(snapshotAlias(snapshot))
	}
	return json.Marshal(struct {
		SchemaVersion    int             `json:"schema_version"`
		MinReaderVersion int             `json:"min_reader_version"`
		Version          int             `json:"version"`
		Fingerprint      string          `json:"fingerprint"`
		Signature        string          `json:"signature"`
		CanonicalPayload json.RawMessage `json:"canonical_payload"`
	}{
		SchemaVersion:    snapshot.SchemaVersion,
		MinReaderVersion: snapshot.MinReaderVersion,
		Version:          snapshot.Version,
		Fingerprint:      snapshot.Fingerprint,
		Signature:        snapshot.Signature,
		CanonicalPayload: snapshot.CanonicalPayload,
	})
}

type ClusterNodeView struct {
	ID              int            `json:"id"`
	Name            string         `json:"name"`
	IPAddress       string         `json:"ip_address"`
	Port            int            `json:"port"`
	Protocol        string         `json:"protocol"`
	AccessURL       string         `json:"access_url"`
	Status          string         `json:"status"`
	IsApproved      bool           `json:"is_approved"`
	ReportedVersion int            `json:"reported_version"`
	CurrentVersion  int            `json:"current_version"`
	Health          *ClusterHealth `json:"health"`
	LastSeen        string         `json:"last_seen"`
	CreatedAt       string         `json:"created_at"`
	ServerMapLat    float64        `json:"server_map_lat"`
	ServerMapLon    float64        `json:"server_map_lon"`
	// SiteInherited 表示该节点未单独配置坐标，当前展示的是主节点默认坐标。
	SiteInherited bool `json:"site_inherited"`
	// SectionSync 为主节点聚合的 per-section 同步状态，仅包含主节点同步开关
	// 开启的节；旧版本从节点无上报时为 nil（JSON 省略），前端展示占位文案。
	SectionSync []ClusterSectionSyncStatus `json:"section_sync,omitempty"`
}

type ClusterStatus struct {
	NodeMode       string        `json:"node_mode"`
	ClusterVersion int           `json:"cluster_version"`
	MasterURL      string        `json:"master_url"`
	SyncInterval   int           `json:"sync_interval"`
	SyncUsers      bool          `json:"sync_users"`
	SyncRules      bool          `json:"sync_rules"`
	SyncSecurity   bool          `json:"sync_security"`
	ClusterActive  bool          `json:"cluster_active"`
	AppliedVersion int           `json:"applied_version"`
	LastSyncAt     string        `json:"last_sync_at"`
	LastSyncError  string        `json:"last_sync_error"`
	SyncErrorCode  SyncErrorCode `json:"sync_error_code,omitempty"`
	PendingCount   int           `json:"pending_count"`
	ApprovedCount  int           `json:"approved_count"`
	// TransportInsecure 表示从节点→主节点链路为明文 HTTP（快照承载证书私钥
	// 与 CA/DNS 凭据、服务控制票据为 Bearer，且 HTTP 下无 TOFU 指纹防护）。
	// 注册时刻的一次性告警之外，UI 据此常驻提示。
	TransportInsecure bool `json:"transport_insecure"`
}
