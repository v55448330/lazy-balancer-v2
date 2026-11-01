package services

// 规则传输规范（2026-10-11 用户裁定「如果没有就都应该没有，同步后就应该一致」）：
// 单一事实源 normalizeRuleForTransport——主端快照导出（snapshotRules）、从端快照
// 应用（insertSnapshotRules）、备份导入后置归一共用的规则归一函数。
//
// 历史事故根因：从端 insertSnapshotRules 新增 TCP 七字段归零时，导出侧
// snapshotRules 的平行手写归一块未同步——主端 canonical 与从端落库数据不同形，
// 从端本地重建哈希（56e3）≠主端快照哈希（9855），drifted 分支落本地口径后面板
// 「分区滞后」在版本相同、fingerprint 304 稳态下永不自愈。
// 结构性防治：归一逻辑只此一份，任何消费方（导出/应用/导入）都调它。
//
// 时间戳说明：快照模型时间为 time.Time——主从 DB 字符串（RFC3339 Z / Go time
// +00:00 / SQLite 平面）解析为同一 UTC 时刻后 json.Marshal 输出相同，天然同构；
// DB 存储格式的统一（消除三种并存）由迁移层 normalizeRuleTimestampsMigration
// 与从端写入侧（平面格式直写）承担，与本函数正交。

import (
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// normalizeRuleForTransport 规则传输归一（单一事实源）：
// ① body 上限钳 [0,4096]；
// ② TCP+TLS 死形态清除；
// ③ TCP 行 HTTP 专属字段归零（含代理超时族、自定义路由、动态上游与
//
//	cookie 策略；health_check_host 同族清零）。
//
// ④ 健康检查族/tcp_try_interval 值型列回填（库值唯一真相批 1+2，2026-10-14
//
//	用户裁定）：<=0 归治理默认（db.Default* 常量）——主端带外脏行/旧版本
//	主端快照在传输门归一，三面（导出/从端落库/备份导入）同构，rules 节哈希
//	主从相等的不变量基础；渲染层对这批列已零兜底，脏值不允许越过本门。
//
// 调用方：snapshotRules（主端导出）、insertSnapshotRules（从端落库）、
// 备份导入后置归一——三面同构是 rules 节哈希主从相等的不变量基础。
//
// 传输族刻意窄于保存族
// （rules.go 保存/更新路径的 TCP 零值化清单还含 tls_source/acme_config_id/
// ca_provider_id/tls_http_redirect 与 stage 拦截页 4 列）——传输/导入/迁移产生
// 的 TCP 行残留这些列已推演为惰性无害：全部 ACME 消费方（签发/续签/证书
// 回插）都以 enable_tls=1 联合门控，而 enable_tls 在本函数与迁移侧恒归 0，
// 残留引用不可达；stage 页 4 列同理仅 HTTP 渲染消费。不为清单收敛而扩面
// （扩面会改变 canonical 哈希基线，触发一轮全量重放），残留列由下次规则
// 编辑经保存族归一自愈。
func normalizeRuleForTransport(rule *models.LbRule) {
	if rule.RequestBodyMaxSizeMB < 0 {
		rule.RequestBodyMaxSizeMB = 0
	} else if rule.RequestBodyMaxSizeMB > 4096 {
		rule.RequestBodyMaxSizeMB = 4096
	}
	// ④ 健康检查族/tcp_try_interval 值型列回填（库值唯一真相批 1+2）：渲染层
	// 零兜底，脏值在传输门归治理默认。仅规范 <=0；用户已设有效值不触碰。
	if rule.HealthCheckInterval <= 0 {
		rule.HealthCheckInterval = db.DefaultHealthCheckInterval
	}
	if rule.HealthCheckTimeout <= 0 {
		rule.HealthCheckTimeout = db.DefaultHealthCheckTimeout
	}
	if rule.HealthCheckUnhealthyThreshold <= 0 {
		rule.HealthCheckUnhealthyThreshold = db.DefaultHealthCheckUnhealthyThreshold
	}
	if rule.HealthCheckHealthyThreshold <= 0 {
		rule.HealthCheckHealthyThreshold = db.DefaultHealthCheckHealthyThreshold
	}
	if rule.TCPTryInterval <= 0 {
		rule.TCPTryInterval = db.DefaultTCPTryInterval
	}
	// 认证网关（forward_auth）与启动回填迁移同构的传输面归一：
	// ① uri/身份头清单空值回填确定默认（全表 concrete 形态，canonical 稳定）；
	// ② enabled=1 而 upstream 缺失 → 关闭（渲染必败形态，网关地址无默认可回填，
	//    与启动迁移同判据）——主端带外写入不随快照放大到从端。
	if rule.ForwardAuthURI == "" {
		rule.ForwardAuthURI = db.DefaultForwardAuthURI
	}
	if rule.ForwardAuthCopyHeaders == "" {
		rule.ForwardAuthCopyHeaders = db.DefaultForwardAuthCopyHeaders
	}
	if rule.ForwardAuthEnabled == 1 && strings.TrimSpace(rule.ForwardAuthUpstream) == "" {
		rule.ForwardAuthEnabled = 0
	}
	if rule.Protocol == "tcp" {
		// TLS 材料的存在性同样入选（不只 enable_tls=1）：TCP+enable_tls=0 的
		// 存量行可携带私钥 PEM（保存族无条件清零、迁移 SQL 以证书列触发），
		// 传输归一若只看 EnableTLS 会让该形态在主端导出/从端落库/备份导入三面
		// 之间分叉，并让私钥正文随快照/备份放大。
		if rule.EnableTLS || rule.TLSCert != "" || rule.TLSKey != "" {
			rule.EnableTLS = false
			rule.TLSCert, rule.TLSKey = "", ""
		}
		// TCP 渲染零消费字段族（buildTCPServer/buildTCPProxyRoute）——
		// 「没有就都应该没有」：主端存储、导出、从端落库三面全零。
		rule.HostHeader = ""
		rule.HealthCheckPath = ""
		// 健康检查域名同为 HTTP-only（TCP 探针走端口）——
		// 保存族（tcpDeadFieldReset）已清，传输族补齐，避免主从/导入面分叉。
		rule.HealthCheckHost = ""
		rule.EnableCompress = false
		rule.CompressTypes = ""
		rule.RequestBodyMaxSizeMB = 0
		rule.UpstreamKeepaliveTimeout = 0
		rule.ServerTokensHidden = 0
		// NTLM 兼容仅 HTTP 语义（2026-10-12）——与保存族/迁移族同一归一口径。
		rule.NTLMCompatible = 0
		rule.UpstreamForceHTTP1 = 0
		// 认证网关仅 HTTP 语义：开关/网关地址归零（uri/身份头清单已在上文
		// 与启动迁移同构回填确定默认）。
		rule.ForwardAuthEnabled = 0
		rule.ForwardAuthUpstream = ""
		rule.ProxyDialTimeout = 0
		rule.ProxyResponseHeaderTimeout = 0
		rule.ProxyReadTimeout = 0
		rule.ProxyWriteTimeout = 0
		rule.ProxyStreamTimeout = 0
		rule.ProxyFlushInterval = 0
		rule.ProxyStreamCloseDelay = 0
		rule.CustomRoutesEnabled = false
		rule.DynamicDNS = false
		// domain / log_enabled / dns_family 与保存族、迁移 SQL 同口径归零：
		// 三者对 TCP 均零消费（domain 仅 HTTP 域名/证书，log_enabled 仅 HTTP
		// logger_names，dns_family 仅动态上游解析）。带外直改库/外来写入的
		// TCP 行此前会把死值经快照长期带到从端。
		rule.Domain = ""
		rule.LogEnabled = false
		rule.DnsFamily = "ipv4"
		if rule.Strategy == "cookie" || rule.Strategy == "" {
			rule.Strategy = "weighted_round_robin"
		}
		return
	}
	// HTTP 跨模式 TLS 残留（与保存族 / 导入后置归一 / 启动迁移同一不变量）：
	// 生效来源非 manual 不保留证书材料（私钥正文随快照/备份放大）；非
	// acme_dns 不保留 CA 提供商引用与 ACME 配置引用（ResolveCAProviderID 对
	// 非 0 不校验存在性，残留死引用签发期才暴露；空来源与 manual 同理）。
	// 渲染侧按来源分流，残留列零消费——不回填只会让主端存储/导出/从端落库
	// 三面分叉。
	if rule.TLSSource != "manual" {
		rule.TLSCert, rule.TLSKey = "", ""
	}
	if rule.TLSSource != "acme_dns" {
		rule.CAProviderID = 0
		rule.ACMEConfigID = 0
	}
}

// normalizeUpstreamForTransport 上游传输归一（单一事实源）：upstreams.dynamic_dns
// 是废弃列（渲染只读规则级 DynamicDNS，保存/复制/集群落库写侧恒 0）。主端导出
// 若直读存量 1 值，快照 canonical 与从端落库（恒 0）不同形——rules 节哈希每次
// 主端 bump 恒不等，每版本一轮全量重拉。导出与从端本地重建共用本函数，
// 三面（主端导出/从端落库/从端重建）同 0。
//
// TCP 规则的上游 origin_domain 同属死值（回源域名仅 HTTP 回源使用，保存族
// 自引入起即拒绝 TCP 携带）——存储/传输面残留会让主端备份在导入校验被整包
// 拒绝（备份自毒），且随 rules 节同步到从端；故按 ruleProtocol 一并清零。
func normalizeUpstreamForTransport(upstream *models.Upstream, ruleProtocol string) {
	upstream.DynamicDNS = false
	if ruleProtocol == "tcp" {
		upstream.OriginDomain = ""
	}
}
