package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/services/dnsproviders"
)

var configBackupTables = []string{"lb_rules", "upstreams", "path_rules", "users", "api_keys", "ca_providers", "certificate_configs", "cert_jobs", "security_policies", "security_policy_bindings", "security_custom_rules", "security_block_pages", "security_ip_lists", "security_crs_version", "security_ip2region_version", "security_threat_sources", "security_crawler_sources", "nodes"}

// importVersionSeedSentinel 标记本次导入为「未导入版本表且导入前无行」临时
// 插入的占位行：rearm 看到 id=1 已存在便不再补真实种子；提交后仅以该哨兵
// 版本+CAS 条件删除，绝不按「导入前不存在」的无条件 DELETE 误删并发更新行。
// 值与启动自愈侧同源于 services.SecurityVersionImportSentinel（崩溃窗口：
// 提交后清理前被杀 → 下次启动由 armSecurityLibraryFirstSlots 改写为真实种子）。
const importVersionSeedSentinel = services.SecurityVersionImportSentinel

// 迟到表容缺清单——Version=2 导出清单首发(ff632cd,
// v2.0.10,8 表)与安全族并入(4e46f85,v2.1.1,12 表)之后才加入导出清单的表:
//
//	security_crs_version / security_ip2region_version — v2.1.10(76f616a)起
//	security_ip_lists — v2.2.1(6bf0bf5)起
//
// v2.1.2-v2.1.9(12 表)与 v2.1.10-v2.2.13(14 表)全量备份是合法 Version=2
// 文件,必需表门不得因缺迟到表硬拒;缺席表由导入链「缺席=保留本地」语义承接
// (校验链完整性校验门内补空表仅供校验均匀性,importConfigBackupCore 将未实际
// 导出的表还原为缺席,restore 跳过未携带表)。v2.1.1 及更早的文件在完整性
// 校验和门已被拒,与本清单无关。
var configBackupLateTables = map[string]struct{}{
	"security_crs_version":       {},
	"security_ip2region_version": {},
	"security_ip_lists":          {},
	// 威胁情报库（v2.3.x 起入导出清单）——更早版本的备份缺席由
	// 「缺席=保留本地」语义承接。
	"security_threat_sources": {},
	// 爬虫地址库（v2.3.8 起入导出清单）——更早备份缺席=保留本地。
	"security_crawler_sources": {},
	// 节点拓扑（本轮起入导出清单）——更早备份缺席=保留本地节点表。
	"nodes": {},
}

// 分类(2026-09-19 三分类合并；本轮新增节点拓扑)：备份分类与集群同步节同构——
// 全局配置并入「系统数据」（单行键值表单独成类必产无法导入的死备份），
// 规则库数据库并入「安全防护」(CRS/IP2Region 文件与引用它的安全策略同属
// 一个防护域)。导出/导入可按分类选择,默认全选;表→分类映射与
// cluster_sections.go 的节语义一致。
var configBackupSections = []struct {
	Key    string
	Label  string
	Tables []string
	Global bool
}{
	{Key: "users", Label: "系统数据", Tables: []string{"users", "api_keys", "ca_providers", "certificate_configs"}, Global: true},
	{Key: "rules", Label: "负载规则", Tables: []string{"lb_rules", "upstreams", "path_rules", "cert_jobs"}},
	{Key: "security", Label: "安全防护", Tables: []string{"security_policies", "security_policy_bindings", "security_custom_rules", "security_block_pages", "security_ip_lists", "security_crs_version", "security_ip2region_version", "security_threat_sources", "security_crawler_sources"}},
	{Key: "cluster", Label: "节点拓扑", Tables: []string{"nodes"}},
}

// configBackupSectionKeysText / configBackupSectionsDocText 由
// configBackupSections 单一事实源派生文档文案
// apidocs 的导出 query 枚举与自动备份设置说明此前手工维护分类清单，
// 第四分类「cluster=节点拓扑」上线后文档漂移为三分类。键与标签一律取自
// 结构体，分类增删时文档自动跟随；钉测
// TestApiDocsBackupSectionsMatchSingleSource 逐键核对。
func configBackupSectionKeysText() string {
	keys := make([]string, 0, len(configBackupSections))
	for _, sec := range configBackupSections {
		keys = append(keys, sec.Key)
	}
	return strings.Join(keys, "、")
}

func configBackupSectionsDocText() string {
	parts := make([]string, 0, len(configBackupSections))
	for _, sec := range configBackupSections {
		note := sec.Label
		switch sec.Key {
		case "users":
			note += "含全局配置"
		case "security":
			note += "含 CRS/IP2Region 规则库"
		}
		parts = append(parts, sec.Key+"="+note)
	}
	return strings.Join(parts, "、")
}

// normalizeBackupSectionKeys 归一 legacy 分类键:三分类合并前的
// global_config(并入系统数据)与 waf_files(并入安全防护)在导出 query、
// 旧备份体内 sections、auto_backup_sections 存量存储值三处长期存在
// (旧备份必须永久可导入,不设淘汰期)——读侧一律先归一到当前分类再消费,
// 去重保序;未知键原样透传(由 configBackupSectionTables 400)。
func normalizeBackupSectionKeys(sections []string) []string {
	aliases := map[string]string{"global_config": "users", "waf_files": "security"}
	seen := map[string]bool{}
	out := make([]string, 0, len(sections))
	for _, key := range sections {
		if mapped, ok := aliases[key]; ok {
			key = mapped
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// configBackupSectionTables 返回选中分类覆盖的表集合与是否含全局配置
// (全局配置区随「系统数据」分类);sections 为空=全选(默认),legacy 键
// 先归一。未知分类名 → nil(调用方 400)。
func configBackupSectionTables(sections []string) (map[string]bool, bool, bool) {
	sections = normalizeBackupSectionKeys(sections)
	if len(sections) == 0 {
		tables := map[string]bool{}
		for _, sec := range configBackupSections {
			for _, t := range sec.Tables {
				tables[t] = true
			}
		}
		return tables, true, true
	}
	selected := map[string]bool{}
	for _, key := range sections {
		found := false
		for _, sec := range configBackupSections {
			if sec.Key == key {
				found = true
				break
			}
		}
		if !found {
			return nil, false, false
		}
		selected[key] = true
	}
	tables := map[string]bool{}
	includeGlobal := false
	for _, sec := range configBackupSections {
		if !selected[sec.Key] {
			continue
		}
		if sec.Global {
			includeGlobal = true
		}
		for _, t := range sec.Tables {
			tables[t] = true
		}
	}
	return tables, includeGlobal, true
}

// parseSectionsParam:解析?sections= query——逐段 TrimSpace、跳空段,
// 导出与 lbbak 导入两侧共用(尾逗号/空白段宽容;JSON 备份体内 sections 由
// ShouldBindJSON 解析,不受此影响)。
func parseSectionsParam(qs string) []string {
	sel := []string{}
	for _, p := range strings.Split(qs, ",") {
		if p = strings.TrimSpace(p); p != "" {
			sel = append(sel, p)
		}
	}
	return sel
}

// resolveImportSectionSelection 解析本次导入/预览的有效分类选择——单源，
// 两条路径各调一次，保证「预览通过=导入可提交」。
// 分类选择经 ?sections= query 传输（与导出对称），体内 sections 是打包时的
// 分类记录：两者同时给值时取交集——query 选到备份未含的分类会过滤掉全部表，
// 替换式覆盖会让「零导入」冒充成功；只缩不扩，绝不改写体内值（v3 纯 JSON 的
// 体内 sections 参与校验和，改写会被判成「已篡改」）。
//
// 交集为空返回与导入 400 完全一致的文案错误（预览以 valid=false 呈现）。
func resolveImportSectionSelection(backup *configBackup, queryRaw string) error {
	bodySections := normalizeBackupSectionKeys(backup.Sections)
	querySections := normalizeBackupSectionKeys(parseSectionsParam(queryRaw))
	switch {
	case len(querySections) == 0:
		// query 未指定：沿用体内 sections（打包时的分类记录）。
		backup.Sections = bodySections
		return nil
	case len(bodySections) == 0:
		backup.Sections = querySections
		return nil
	}
	allowed := make(map[string]bool, len(bodySections))
	for _, key := range bodySections {
		allowed[key] = true
	}
	intersection := make([]string, 0, len(querySections))
	for _, key := range querySections {
		if allowed[key] {
			intersection = append(intersection, key)
		}
	}
	if len(intersection) == 0 {
		return fmt.Errorf("所选分类与备份内容无交集（请求：%s；备份：%s），未导入任何数据",
			strings.Join(querySections, ","), strings.Join(bodySections, ","))
	}
	backup.Sections = intersection
	return nil
}

// assertImportScopeHasContent 校验分类过滤（以及其后的软跳过/剔除步）之后
// 本次导入仍有内容可落库——预览/导入共用同一判据与文案，杜绝「什么都没导入
// 但提示成功」。判据：任一待导表存在（空表也算内容——导入=清空本地表），或
// 选中了全局配置区。
//
// stage 区分两种成因，文案不混用：
//   - importScopeFiltered：仅完成分类过滤（请求选择与备份内容无交集）；
//   - importScopeSkipped：已执行软跳过/剔除步（分类内容被全部跳过或保留本地）。
func assertImportScopeHasContent(tables map[string][]map[string]any, includeGlobal bool, sections []string, stage importScopeStage) error {
	if includeGlobal || len(tables) > 0 {
		return nil
	}
	requested := strings.Join(normalizeBackupSectionKeys(sections), ",")
	if stage == importScopeSkipped {
		return fmt.Errorf("所选分类内容均被跳过或保留本地，未导入任何数据（请求：%s）", requested)
	}
	return fmt.Errorf("所选分类与备份内容无交集（请求：%s），未导入任何数据", requested)
}

type importScopeStage int

const (
	importScopeFiltered importScopeStage = iota
	importScopeSkipped
)

var configBackupV1Tables = []string{"lb_rules", "upstreams", "users", "api_keys", "ca_providers", "certificate_configs", "cert_jobs"}

// configBackupCertJobStatuses 备份导入的证书任务状态白名单——单一
// 真源 services.AllJobStatuses()（内部 db.CertJobStatuses 规范枚举），此处
// 仅展开为集合；新增/重命名状态只改真源即自动覆盖，杜绝第二份字面量漂移。
var configBackupCertJobStatuses = func() map[string]struct{} {
	statuses := services.AllJobStatuses()
	set := make(map[string]struct{}, len(statuses))
	for _, status := range statuses {
		set[status] = struct{}{}
	}
	return set
}()

var configBackupProtectedConfigKeys = map[string]bool{
	"id": true, "is_master": true, "master_url": true, "cluster_token": true,
	"registration_id": true, "registration_secret": true, "applied_version": true,
	"sync_fingerprint": true, "last_sync": true, "last_sync_error": true, "cluster_version": true,
	// 本地节点运行态标记，非配置——导入时跳过，避免旧备份先复活陈旧横幅；
	// 成功提交路径另由 recordCaddyApplyResult(nil) 显式清空既有失败状态。
	"caddy_apply_error": true, "registration_confirm_failures": true,
	// 自动备份节点本地运行态（下次槽追补基准），
	// 非配置——还原旧备份会让基准回跳、立即多跑一次自动备份；导出剔除+
	// 导入跳过（保护键双消费点同口径）。运行态字段参照 caddy_apply_error。
	"auto_backup_last_run": true,
	// WAF 文件态记账（哈希+版本标签）是节点本地状态，
	// 集群快照不携带；导入不得用另一节点的值覆盖——否则降级回从节点后
	// wafFilesDrifted 误判并触发一次不必要的全量重拉。
	"applied_waf_ref_hash": true, "applied_waf_ref_version": true,
	// 新1:恒同步列排除出备份——现行导出恒 1(UpdateSettings
	// 拒绝禁用+启动迁移回填),排除无信息损失;防 v2.2.7 前存量备份携带 0 值
	// 直写,致节点页「系统数据同步=关闭」假状态至重启(同步行为四个在线强制点
	// 不受影响,纯展示层)。
	"sync_users": true,
	// 同门：auto_backup_sections_version 是
	// 节点本地的备份范围迁移标记（db.go 启动迁移写入），非配置——随备份搬运
	// 会让目标节点的存量 sections 迁移状态被源节点覆盖；且该列无导入类型门，
	// 文本形态落库后下次启动迁移 Scan int 硬失败。导出剔除+导入跳过。
	"auto_backup_sections_version": true,
	// 同族收敛：threat_traffic_sample_unified_migrated /
	// security_events_retention_migrated 同型（节点本地一次性迁移标记，
	// db.go:2285/2346 启动迁移 Scan int）——同口径纳入保护。
	"threat_traffic_sample_unified_migrated": true,
	"security_events_retention_migrated":     true,
	// global_config.dns_provider/dns_credentials 为退役列：导出剔除 + 导入跳过，
	// 避免旧备份把零运行时消费的配置写回并继续传播。
	"dns_provider":    true,
	"dns_credentials": true,
}

// 规则库跳过警告统一文案(审计侧与响应侧共用,全角括号口径)。
const (
	warningWafMetadataSkipped    = "备份不含规则库数据文件——规则库版本记录已跳过（仅 lbbak 完整备份可导入该类）"
	warningWafCRSMetadataSkipped = "备份不含 CRS 数据文件——CRS 版本记录已跳过（仅含该文件的 lbbak 备份可导入）"
	warningWafXdbMetadataSkipped = "备份不含 IP2Region 数据文件——IP2Region 版本记录已跳过（仅含该文件的 lbbak 备份可导入）"
	// 导入同时替换 CRS 规则树时的校验基准降级说明。
	warningCRSTreeReplaced = "备份同时替换 CRS 规则树：安全策略中的 CRS 组号/规则 ID 未按当前规则库做存在性校验（落地基准以备份内规则树为准）——导入后请在安全策略页复核选组，避免空 Include 静默失效"
	// 无任何校验和的史前 v1 备份：结构门照常执行，但内容未经摘要校验。
	warningNoIntegrityChecksum = "备份不含完整性校验和（史前版本导出），已按结构性校验导入——文件内容未经摘要校验，建议尽快用当前版本重新导出备份"
)

var requeueNonTerminalCertJobs = services.RequeueNonTerminalCertJobs

// configImportBeforeLock 仅测试注入：在导入取得 caddyOpMu/开启事务前触发，
// 用于构造「预锁读与加锁之间 live 状态变化」的 TOCTOU 回归。
var configImportBeforeLock func()

// configImportAfterSessionHook 仅测试注入：会话建立（引擎已暂停、CA 队列已
// hold、caddyOpMu 已取、事务已开）之后、核心体第一条语句之前触发，用于断言
// 「此后的写入不再受请求取消影响」。
var configImportAfterSessionHook func()

// configBackupExportAfterDBSnapshot 仅测试注入：DB 快照读取完成、WAF bundle
// 构建之前触发，用于断言文件锁在快照期间已持有。
var configBackupExportAfterDBSnapshot func()

// invalidateImportTaskLogCache 测试缝：导入落库 task_log_size_mb 后必须立即
// 失效服务端 5 分钟 TTL 缓存。
var invalidateImportTaskLogCache = services.InvalidateTaskLogSizeCache

// 备份 schema 布尔列全量枚举（校验门与恢复归一双侧共用）。
// 类型绕过的影响面是整个枚举而非单个字段——校验侧 backupBooleanEnabled 此前
// 无 string 分支，"1"/"true" 文本在校验期被读为 false，而 SQLite 列亲和性在
// 恢复期把同一文本转存为 INTEGER 1，同一值在校验期与存储期含义相反（不变量：
// 含义必须两期一致），全部校验门（admin_tls 崩溃循环门、TLSShape 白名单、
// 冲突矩阵）均可被字符串形态击穿。
// 枚举含 INTEGER 声明的 0/1 语义列（api_keys.mcp_enabled/read_only、
// security_policies.waf_check_response）；lb_rules.server_tokens_hidden 是
// 有意的 0/1/2 三态列（rules.go 保存侧允许 2），不在其列。
var backupBooleanTableColumns = map[string][]string{
	// ntlm_compatible / upstream_force_http1 为 NOT NULL
	// DEFAULT 0 的 INTEGER 0/1 语义列——此前漏列，字符串形态可绕过布尔类型门。
	"lb_rules":              {"dynamic_dns", "enable_dns_server", "enable_active_health_check", "tcp_proxy_protocol", "custom_routes_enabled", "enable_tls", "tls_http_redirect", "enable_compress", "enabled", "log_enabled", "ntlm_compatible", "upstream_force_http1"},
	"upstreams":             {"dynamic_dns", "enabled"},
	"users":                 {"is_enabled", "mfa_enabled", "is_setup_admin"},
	"api_keys":              {"is_enabled", "mcp_enabled", "read_only"},
	"ca_providers":          {"enabled"},
	"certificate_configs":   {"enabled"},
	"security_policies":     {"ip_acl_enabled", "ip_whitelist_enabled", "rate_limit_enabled", "enabled", "waf_check_response", "log_request_body", "trust_detection", "geoip_crawler_exempt"},
	"security_custom_rules": {"enabled"},
	// is_builtin（INTEGER DEFAULT 0）为内置页语义布尔列。
	"security_block_pages":       {"is_default", "is_builtin"},
	"security_crs_version":       {"auto_update"},
	"security_ip2region_version": {"auto_update"},
	"security_threat_sources":    {"update_enabled", "apply_enabled"},
	// v2.3.8 爬虫源表新增时漏登记——字符串 "true" 可
	// 落库为 TEXT，调度 SQL WHERE update_enabled=1 不再命中（静默停更）。
	"security_crawler_sources": {"update_enabled"},
	// system（NOT NULL DEFAULT 0）为系统预置名单语义布尔列。
	"security_ip_lists": {"system"},
	// 节点拓扑：is_approved / cluster_token_delivered 为 BOOLEAN 语义列。
	"nodes": {"is_approved", "cluster_token_delivered"},
}

// 备份表 NULL→默认值归一映射（restoreTable 写入侧，覆盖除
// security_policy_bindings 外的 16 表——绑定表为派生数据，无 NULL 归一列）。
// 默认值与集群快照 dump 侧逐列对齐（cluster_snapshot.go 各 snapshot* 函数的
// COALESCE 表达式）——「全量替换」两条通道（备份导入/集群快照）对同一 NULL
// 行必须产出同一落库值。
// 仅收录「集群 dump 侧已 COALESCE 硬化」或「NULL 命中 raw-scan 消费点」的
// 可空列；生命周期合法可空列（cert_jobs key_pem/message/ca_available_after/
// deployment_available_after/updated_at、users.last_login/password_changed_at、
// api_keys.expires_at/last_used、path_rules.upstreams_json、lb_rules.updated_at、
// certificate_configs.updated_at）保持可空，不入映射。时间列读侧消费类型
// 逐列核实（旧注释「lb_rules 及 ca_providers/certificate_configs 的
// created_at/updated_at 读侧均为 NullTime/NullString」对集群 dump 通道不成立）
// ——lb_rules/ca_providers/certificate_configs 的 created_at 及
// ca_providers.updated_at 在 snapshotRules/snapshotACME 为裸列直扫 models 的
// time.Time 字段（LbRule.CreatedAt、CAProvider 双列、
// CertificateConfig.CreatedAt），NULL→快照构建失败→整集群同步中断，归一
// epoch 文本入映射；lb_rules.updated_at 与 certificate_configs.updated_at
// 扫描目标为 JSONNullTime（内嵌 sql.NullTime，NULL→Valid=false 安全），
// 保持可空。NOT NULL 无默认列（name/username/rule_id 等，及
// security_policy_bindings 两列）不入映射：NULL 由列约束响亮失败（500
// 回滚），不属于静默毒化。例外 lb_rules.id：列为可空普通 INTEGER（db.go
// schema 非 NOT NULL），生产 INSERT 不写 id（新规则恒为 NULL），NULL 静默
// 落库且无害——dump 侧 COALESCE(id,0) 兜底；排序消费点（rules.go ListRules
// 与 services/caddy.go 渲染查询）已显式 ORDER BY rowid（恒 NULL 列
// 排序本退化，rowid 化行为等价），无裸读 id 的消费点，同样不入映射。
// 各表归一列与消费点：
//
//	users                created_at 为 epoch 文本——auth.go Login 的 time.Time
//	                     raw 扫描对 NULL/'' 均报错（'' 驱动回退字符串不可扫），
//	                     NULL→500→永久锁死；其余列对齐 snapshotUsers（is_enabled 1、
//	                     mfa_recovery_codes '[]' 等）
//	api_keys             created_at epoch（apikeys.go scanAPIKeys time.Time raw
//	                     扫描）；布尔列 NULL 同路径 500；其余对齐 snapshotAPIKeys
//	lb_rules             对齐 snapshotRules（strategy/tls_source/dns_family 等文本、
//	                     tcp_try_interval 250/enable_compress 1 等）；读侧
//	                     lbRuleColumns 已 COALESCE，此处保证两通道落库一致；
//	                     created_at epoch——snapshotRules 裸列直扫 time.Time
//	upstreams            对齐 snapshotAllUpstreams（weight 1/protocol 'http'/
//	                     enabled 0）
//	ca_providers         对齐 snapshotACME 的 ca_providers 查询；
//	                     max_concurrent/min_interval_ms/enabled NULL→caproviders.go
//	                     raw 扫描 500→ACME 签发链断裂；created_at/updated_at
//	                     epoch——snapshotACME 裸列直扫 time.Time，NULL→快照构建
//	                     失败→集群同步中断
//	certificate_configs  对齐 snapshotACME 的 certificate_configs 查询
//	                     （dns_provider 'dnspod'）；created_at epoch——
//	                     snapshotACME 裸列直扫 time.Time（updated_at 为
//	                     JSONNullTime 扫描，NULL 安全，不入映射）
//	cert_jobs            备份通道专属（集群 dump 仅覆盖 TLS 材料子集）：
//	                     ca_provider_id/renewal_attempts/deployment_attempts NULL→
//	                     certificates.go 补偿扫描硬失败/续签扫描静默跳行；
//	                     created_at epoch（certjobs.go raw 扫描）
//	path_rules           备份通道专属：created_at epoch——snapshotAllPathRules
//	                     的快照 dump 的 time.Time raw 扫描对 NULL 失败→整集群
//	                     同步中断
//	security_crs_version / security_ip2region_version  对齐
//	                     snapshotSecurityCRSVersion / snapshotSecurityIP2RegionVersion；
//	                     auto_update NULL→自动更新静默失效；consecutive_failures
//	                     NULL→crsupdate.go/crsscheduler.go readConsecutiveFailures
//	                     raw int 扫描（读取失败优雅回退 0，退避退化为固定 1h），
//	                     收录以维持映射判据一致，NULL→0
//	security_policies / security_custom_rules / security_block_pages /
//	security_ip_lists（v2.3.0，entries '[]' 对齐 dump 侧 COALESCE）
//	                     分别对齐 snapshotSecurityPolicies /
//	                     snapshotSecurityCustomRules / snapshotSecurityBlockPages /
//	                     snapshotSecurityIPLists
var backupTableNullDefaults = map[string]map[string]any{
	"lb_rules": {
		"description": "", "domain": "", "strategy": "weighted_round_robin",
		"dynamic_dns": int64(0), "enable_dns_server": int64(0), "dns_server": "", "dns_family": "ipv4",
		"health_check_path": "", "health_check_interval": int64(10), "health_check_timeout": int64(2),
		"health_check_unhealthy_threshold": int64(3), "health_check_healthy_threshold": int64(2),
		"enable_active_health_check": int64(0), "tcp_health_check_port": int64(0), "tcp_proxy_protocol": int64(0),
		"tcp_try_duration": int64(0), "tcp_try_interval": int64(250),
		"request_body_max_size_mb": int64(0), "upstream_keepalive_timeout": int64(0),
		"server_tokens_hidden": int64(0), "custom_routes_enabled": int64(0),
		"ntlm_compatible": int64(0), "upstream_force_http1": int64(0),
		"proxy_dial_timeout": int64(0), "proxy_response_header_timeout": int64(0), "proxy_read_timeout": int64(0),
		"proxy_write_timeout": int64(0), "proxy_stream_timeout": int64(0), "proxy_flush_interval": int64(0),
		"proxy_stream_close_delay": int64(0), "host_header": "", "health_check_host": "",
		"enable_tls": int64(0), "tls_source": "manual", "acme_config_id": int64(0), "ca_provider_id": int64(0),
		"tls_cert": "", "tls_key": "", "tls_http_redirect": int64(0),
		"enable_compress": int64(1), "compress_types": "gzip",
		"enabled": int64(0), "log_enabled": int64(0), "created_by": int64(0), "updated_by": int64(0),
		"block_page_stage1_id": int64(0), "block_page_stage1_status": int64(0),
		"block_page_stage3_id": int64(0), "block_page_stage3_status": int64(0),
		"created_at": "1970-01-01 00:00:00",
	},
	"upstreams": {
		"weight": int64(1), "dynamic_dns": int64(0), "enabled": int64(0),
		"protocol": "http", "max_connections": int64(0),
		// 逐上游回源域名（db.go upstreams DDL）：NOT NULL DEFAULT ''。
		"origin_domain": "",
	},
	"users": {
		"role": "user", "display_name": "", "is_enabled": int64(1), "is_setup_admin": int64(0),
		"password_version": int64(0),
		"created_at":       "1970-01-01 00:00:00",
		"mfa_enabled":      int64(0), "mfa_secret": "", "mfa_recovery_codes": "[]",
		"mfa_last_timestep": int64(0),
		// 登录记账/来源标记（db.go users DDL）：NOT NULL DEFAULT 0 / 'local'。
		"login_failed_attempts": int64(0), "auth_provider": "local",
	},
	"api_keys": {
		"is_enabled": int64(1), "mcp_enabled": int64(0), "read_only": int64(0),
		"mcp_ip_whitelist": "", "created_at": "1970-01-01 00:00:00",
	},
	"ca_providers": {
		"credentials": "", "max_concurrent": int64(db.DefaultCAProviderMaxConcurrent),
		"min_interval_ms": int64(db.DefaultCAProviderMinIntervalMS), "enabled": int64(1),
		"created_at": "1970-01-01 00:00:00", "updated_at": "1970-01-01 00:00:00",
	},
	"certificate_configs": {
		"dns_provider": "dnspod", "dns_credentials": "", "enabled": int64(1),
		"created_at": "1970-01-01 00:00:00",
	},
	"cert_jobs": {
		"ca_provider_id": int64(0), "renewal_attempts": int64(0), "deployment_attempts": int64(0),
		"created_at": "1970-01-01 00:00:00",
	},
	"path_rules": {
		"created_at": "1970-01-01 00:00:00", "sort_order": int64(0), "match_type": "prefix",
		// 上游 path 改写：NOT NULL 且默认空串的列——NULL 行归一空串（原样转发），
		// 防手造备份 NULL 撞列约束响亮 500；缺键行由列 DEFAULT 兜底。
		"upstream_path": "",
		// 自定义路由静态响应/301 跳转（2026-10-10，db.go path_rules DDL）：
		// 五列 NOT NULL，response_status DEFAULT 200，其余 DEFAULT ''——
		// NULL 行按 schema DEFAULT 逐字归一。
		"response_mode": "", "response_status": int64(200), "response_body": "",
		"response_content_type": "", "redirect_to": "",
	},
	"security_policies": {
		"description": "", "mode": "off", "anomaly_threshold": int64(db.DefaultAnomalyThreshold),
		"ip_acl_mode": "", "ip_acl_list": "[]", "ip_acl_enabled": int64(0),
		"ip_whitelist": "[]", "ip_whitelist_enabled": int64(1), "ip_blacklist": "[]",
		"rate_limit_enabled": int64(0), "rate_limit_rps": int64(0), "rate_limit_burst": int64(0),
		"crs_rule_groups": "[]", "crs_excluded_rules": "[]", "custom_rules": "[]",
		"block_page_id": int64(0), "block_status_code": int64(0), "enabled": int64(0),
		"updated_by": int64(0), "created_at": "", "updated_at": "",
		"geoip_countries": "[]", "geoip_mode": "deny", "waf_check_response": int64(0), "policy_type": "", "trust_detection": int64(0),
		"log_request_body": int64(0), "geoip_crawler_exempt": int64(0), "geoip_crawler_engines": "[]",
		"ip_acl_list_refs": "[]", "ip_whitelist_refs": "[]",
	},
	"security_custom_rules": {
		"description": "", "conditions": "[]", "condition_logic": "and", "action": "block", "score": int64(5),
		"enabled": int64(1), "updated_by": int64(0), "created_at": "", "updated_at": "",
	},
	"security_block_pages": {
		"description": "", "content": "", "content_type": "text/html; charset=utf-8", "is_default": int64(0),
		"created_by": int64(0), "created_at": "", "updated_by": int64(0), "updated_at": "",
	},
	// v2.3.0 security_ip_lists：默认值与集群 dump 侧 COALESCE 口径逐列对齐
	// （cluster_snapshot.go snapshotSecurityIPLists——entries '[]'、审计 0/''）。
	"security_ip_lists": {
		"description": "", "category": "", "entries": "[]",
		"created_by": int64(0), "created_at": "", "updated_by": int64(0), "updated_at": "",
		"system": int64(0), // v2.3.2 名单化：NULL 归一 0（非内置）
	},
	"security_crs_version": {
		"updated_at": "", "auto_update": int64(1), "schedule_days": "1,2,3,4,5,6,7", "schedule_time": "04:00", "update_status": "idle", "message": "",
		"last_checked": "", "next_update": "", "trigger": "", "started_at": "", "finished_at": "",
		"consecutive_failures": int64(0),
	},
	"security_ip2region_version": {
		"updated_at": "", "auto_update": int64(1), "schedule_days": "1,2,3,4,5,6,7", "schedule_time": "04:00", "update_status": "idle", "message": "",
		"last_checked": "", "next_update": "", "trigger": "", "started_at": "", "finished_at": "",
		"consecutive_failures": int64(0),
	},
	// v2.3.x 威胁情报库：与集群 dump 侧 COALESCE 口径对齐。
	"security_threat_sources": {
		"display_name": "", "url": "", "format": "plain",
		"update_enabled": int64(1), "apply_enabled": int64(1), "entry_count": int64(0),
		"version": "", "update_status": "idle", "message": "",
		"last_checked": "", "next_update": "", "trigger": "", "started_at": "", "finished_at": "",
		"consecutive_failures": int64(0), "created_at": "", "updated_at": "",
	},
	// 爬虫地址库：与集群 dump 侧 COALESCE 口径对齐（无 apply_enabled）。
	"security_crawler_sources": {
		"display_name": "", "url": "", "format": "plain",
		"update_enabled": int64(1), "entry_count": int64(0),
		"version": "", "update_status": "idle", "message": "",
		"last_checked": "", "next_update": "", "trigger": "", "started_at": "", "finished_at": "",
		"consecutive_failures": int64(0), "created_at": "", "updated_at": "",
	},
	// 节点拓扑表写入侧 NULL 归一，与 schema DEFAULT
	// 逐列对齐——NOT NULL 列（server_map_lat/lon/mode 等）NULL 直写撞约束
	// 500；port/sync_interval NULL 落库后 cluster_status 节点列表裸扫 500。
	// name/ip_address 为无默认 NOT NULL 列，由行级门 validateV2BackupNodeRows
	// 先行 400 点名（不静默造默认值）；registration_secret/health_json/last_*
	// 瞬态列由 sanitizeNodeRowsForRestore 在更上游删除。
	"nodes": {
		"mode": "slave", "port": int64(8000), "protocol": "http", "access_url": "",
		"is_approved": int64(0),
		// sync_interval 是 legacy 死列（见 db.go nodes 表头注释）：运行期写侧
		// 从不写、读侧零消费（离线阈值统一读 global_config.sync_interval）。此处
		// 只为旧备份回放按列名对齐而保留默认值——新增代码不得读取本列。
		"sync_interval": int64(60), "status": "offline",
		"cluster_token_delivered": int64(0), "reported_version": int64(0),
		"server_map_lat": float64(0), "server_map_lon": float64(0),
		"created_at": "1970-01-01 00:00:00",
	},
}

// 全局配置区布尔键（global_config）。protected 键（is_master/sync_users 等）
// 恢复时不写入；sync_users 虽入 protected（导出剔除）但仍在本布尔键列表中
// 参与类型校验（v2 导入对非布尔形态整包 400 点名拒绝——防御纵深,与归一无关）；
// sync_switches_migrated 为内部迁移标记随导出携带、恢复时写入，同属布尔语义。
var backupBooleanConfigKeys = []string{
	"server_tokens_hidden", "access_log_json", "admin_tls_enabled",
	"sync_global_config", "sync_users", "sync_rules", "sync_waf_files", "sync_security",
	"sync_switches_migrated", "waf_mode4_migrated", // waf_mode4_migrated 补入
	"mfa_write_guard", "mfa_lockout_enabled",
	"trusted_proxy_enabled", "trusted_proxy_strict", // v2.3.x 受信代理
	"autoban_enabled", "autoban_dry_run", // D2:自动封禁布尔两键——非布尔形态经 v2 类型门整包 400 点名
	// 自动备份开关为 INTEGER 0/1 语义列，补入配置键枚举。
	"auto_backup_enabled",
	// 威胁库/爬虫库任务总闸同为 INTEGER 0/1 语义列——
	// 字符串形态落库后被 Scan(&int) fail-closed 关闭，UI 却显示启用。
	"threat_auto_update", "crawler_auto_update",
}

func isBackupBooleanColumn(table, column string) bool {
	for _, booleanColumn := range backupBooleanTableColumns[table] {
		if booleanColumn == column {
			return true
		}
	}
	return false
}

func isBackupBooleanConfigKey(key string) bool {
	for _, booleanKey := range backupBooleanConfigKeys {
		if booleanKey == key {
			return true
		}
	}
	return false
}

// isBackupBooleanValue 判定备份中的布尔列值是否为规范形态：JSON 布尔或 0/1 数值
// （含 JSON 反序列化的 float64 形态）。nil 由 normalizeBackupBooleanNulls 归一，
// 不在此判定（调用方先行跳过）。
func isBackupBooleanValue(value any) bool {
	switch v := value.(type) {
	case bool:
		return true
	case float64:
		return v == 0 || v == 1
	case int:
		return v == 0 || v == 1
	case int64:
		return v == 0 || v == 1
	}
	return false
}

// validateV2BackupBooleanTypes 布尔列类型门：备份中布尔列的
// JSON 值只能是布尔或 0/1 数值，其余形态（字符串 "1"/"true"、数值 2、数组等）
// 整包拒绝并点名 表/行/字段——与 CRS 字段非字符串拒绝同口径。字符串
// 形态在校验期被读为 false、恢复期被 SQLite 亲和性转存为 INTEGER 1，同一值
// 两期含义相反，会击穿全部依赖布尔读取的校验门（admin_tls/TLSShape/冲突矩阵）。
// legacy（仅 tables 校验和）只豁免新版 checksum 形态，不豁免本门；
// verifyBackupIntegrity 之后的生产导入/预览均调用 validateV2BackupRows。
func validateV2BackupBooleanTypes(backup configBackup) error {
	for _, table := range configBackupTables {
		columns := backupBooleanTableColumns[table]
		if len(columns) == 0 {
			continue
		}
		for index, row := range backup.Tables[table] {
			for _, column := range columns {
				raw, exists := row[column]
				if !exists || raw == nil {
					continue
				}
				if !isBackupBooleanValue(raw) {
					return fmt.Errorf("备份校验失败：%s 第 %d 行 %s 需为布尔值（true/false 或 0/1），实际类型 %T", table, index+1, column, raw)
				}
			}
		}
	}
	for _, key := range backupBooleanConfigKeys {
		raw, exists := backup.Config[key]
		if !exists || raw == nil {
			continue
		}
		if !isBackupBooleanValue(raw) {
			return fmt.Errorf("备份校验失败：全局配置 %s 需为布尔值（true/false 或 0/1），实际类型 %T", key, raw)
		}
	}
	return nil
}

// backupTimeColumns 备份中按 time.Time / sql.NullTime 消费的时间列
// 这些列的值必须是驱动可解析的时间串——空串或不可解析文本
// 落库后不是「空值」而是每次扫描都报错（登录读取 users.created_at、规则列表
// 读取 lb_rules.created_at、证书任务读取 cert_jobs.created_at、主节点集群
// 快照读取 path_rules.created_at 全线 500，且无 UI 自愈路径）。NULL 不在此门
// 范围：写入侧 restoreTable 按 backupTableNullDefaults 归一为可解析 epoch。
// 可空时间列（users.last_login、api_keys.last_used/expires_at、cert_jobs.expires_at）
// 同在大门内：NULL 合法（导入后按 sql.NullTime/JSONNullTime 消费），非 NULL 的
// 不可解析文本在列表/登录扫描时同样 500——门覆盖面必须等于声明面。
var backupTimeColumns = map[string][]string{
	"lb_rules":            {"created_at", "updated_at"},
	"path_rules":          {"created_at", "updated_at"},
	"users":               {"created_at", "last_login"},
	"api_keys":            {"created_at", "last_used", "expires_at"},
	"ca_providers":        {"created_at", "updated_at"},
	"certificate_configs": {"created_at", "updated_at"},
	"cert_jobs":           {"created_at", "updated_at", "expires_at"},
	// nodes.created_at 同族——垃圾文本落库后节点列表时间扫描失败；
	// 其余 nodes 时间列（last_seen/last_sync_at）由 sanitizeNodeRowsForRestore
	// 在更上游删除，不进门。
	"nodes": {"created_at"},
}

// backupTimeFormats 与 modernc.org/sqlite 驱动 parseTime 的布局同集
// （sqlite.go parseTimeFormats；另含 "Z" 后缀与 time.String 形态的容忍）。
// 导入后的 raw time 扫描必须能被同一组布局解析，故校验侧逐字对齐。
var backupTimeFormats = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02T15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04",
	"2006-01-02T15:04",
	"2006-01-02",
	// 驱动 parseTimeString 的 time.String() 形态（"…-0700 MST"）。
	"2006-01-02 15:04:05.999999999 -0700 MST",
}

func backupTimeValueParseable(value any) bool {
	switch v := value.(type) {
	case nil:
		return true // NULL 由写入侧默认值归一
	case time.Time:
		return true // 程序化构造的行（v1 转换）可能已是 time.Time
	case string:
		// 逐字（不 TrimSpace）校验：驱动 parseTime 只对 time.String 分支 trim，
		// 常规布局直接 time.Parse——" 2026-01-01 00:00:00" 这类首尾空白串若在
		// 校验期被宽松放行，落库后每次扫描都报错且无 UI 自愈路径。此处不得
		// 改写值（会与已验摘要脱钩），只拒绝。
		if v == "" {
			return false
		}
		trimmed := strings.TrimSuffix(v, "Z")
		for _, layout := range backupTimeFormats {
			if _, err := time.Parse(layout, trimmed); err == nil {
				return true
			}
		}
		return false
	default:
		return false // 数值/布尔等形态同样无法被 *time.Time 扫描
	}
}

func validateV2BackupTimestamps(tables map[string][]map[string]any) error {
	for table, columns := range backupTimeColumns {
		rows, ok := tables[table]
		if !ok {
			continue
		}
		for index, row := range rows {
			for _, column := range columns {
				value, exists := row[column]
				if !exists {
					continue
				}
				if !backupTimeValueParseable(value) {
					// 可接受布局以 backupTimeFormats 为准（含分钟精度、小数秒与
					// 仅日期形态）——报错文案不得只列其中两种，否则用户按文案
					// 修正后仍被拒。
					return fmt.Errorf("备份校验失败：%s 第 %d 行 %s 时间戳为空或不可解析（须为 YYYY-MM-DD HH:MM[:SS[.fffffffff]]、带时区的 RFC3339 或仅日期 YYYY-MM-DD）——该形态落库会使登录、规则/证书任务列表与集群快照扫描持续失败", table, index+1, column)
				}
			}
		}
	}
	return nil
}

// isBackupIntegerValue 判定备份值能否安全落入 INTEGER 声明列。允许整数数值、
// 布尔（落库为 1/0）与整数形字符串（无首尾空白）；拒绝 "abc"、小数、数组等
// ——它们落库后保留 TEXT/REAL 存储类，读侧 raw int/int64 扫描持续 500。
func isBackupIntegerValue(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case bool:
		return true
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32:
		return true
	case uint64:
		return v <= uint64(math.MaxInt64)
	case float32:
		f := float64(v)
		return f == math.Trunc(f) && f >= math.MinInt64 && f <= math.MaxInt64
	case float64:
		return v == math.Trunc(v) && v >= math.MinInt64 && v <= math.MaxInt64
	case json.Number:
		_, err := v.Int64()
		return err == nil
	case string:
		// 逐字校验（不 TrimSpace）：首尾空白串在驱动扫描时不可解析，校验期
		// 宽松放行只会把失败推迟到读侧。
		if v == "" || strings.TrimSpace(v) != v {
			return false
		}
		_, err := strconv.ParseInt(v, 10, 64)
		return err == nil
	default:
		return false
	}
}

// backupIntegerColumnsForTable 返回实时 schema 中声明 INTEGER 的列名。
// 判据取 PRAGMA（列声明事实），不维护静态清单——新增 INTEGER 列自动纳入，
// 不会像静态表那样随 schema 漂移。
func backupIntegerColumnsForTable(ctx context.Context, database *sql.DB, table string) ([]string, error) {
	rows, err := database.QueryContext(ctx, `SELECT name, type FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name, declType string
		if err := rows.Scan(&name, &declType); err != nil {
			return nil, err
		}
		if strings.Contains(strings.ToUpper(declType), "INT") {
			columns = append(columns, name)
		}
	}
	return columns, rows.Err()
}

// validateV2BackupIntegerTypes 数值列类型门：声明 INTEGER 的列只接受整数形态。
// 与布尔/时间门同位（写入侧 restoreTable 只做布尔归一与 NULL 默认，其余值原样
// 绑定），否则文本值落库保留 TEXT 存储类，MFA 校验（users.mfa_last_timestep）、
// 证书任务列表（cert_jobs.renewal_attempts）等 raw int 扫描持续 500。
// database==nil（旧脚手架）跳过——写入侧列约束兜底。
func validateV2BackupIntegerTypes(ctx context.Context, database *sql.DB, tables map[string][]map[string]any) error {
	if database == nil {
		return nil
	}
	for table, rows := range tables {
		if len(rows) == 0 {
			continue
		}
		columns, err := backupIntegerColumnsForTable(ctx, database, table)
		if err != nil {
			// 基础设施读失败（PRAGMA/IO）：映射 500 而非「备份内容非法」400。
			return importInfraReadFailure(fmt.Errorf("读取 %s 列类型失败: %w", table, err))
		}
		if len(columns) == 0 {
			continue
		}
		for index, row := range rows {
			for _, column := range columns {
				raw, exists := row[column]
				if !exists {
					continue
				}
				if !isBackupIntegerValue(raw) {
					return fmt.Errorf("备份校验失败：%s 第 %d 行 %s 需为整数（整数数值或整数形字符串），实际类型 %T", table, index+1, column, raw)
				}
			}
		}
	}
	return nil
}

// normalizeBackupBooleanValue 把已通过行级门的布尔列值归一为 INTEGER 0/1。
// 规范与 legacy 导入都会先经 validateV2BackupBooleanTypes，字符串、数值 2
// 及其他畸形形态均在到达写入侧前拒绝；这里不保留第二套字符串解释语义。
func normalizeBackupBooleanValue(value any) any {
	switch v := value.(type) {
	case bool:
		if v {
			return int64(1)
		}
		return int64(0)
	case float64:
		if v == 0 || v == 1 {
			return int64(v)
		}
	case int:
		if v == 0 || v == 1 {
			return int64(v)
		}
	case int64:
		if v == 0 || v == 1 {
			return v
		}
	}
	return value
}

type importQueueRecovery struct {
	manager   *services.CAQueueManager
	wasActive bool
	// hold 标记本会话持有配置导入队列屏障（BeginConfigImportHold 已调用）：
	// finish 先解除屏障再按原活动态恢复，保证导入窗口内被延迟的启动意图
	// 只在此刻兑现。
	hold bool
	done bool
	// stalledNonTerminal / stalledUnknown 是「队列未激活 → 非终态证书任务
	// 本窗口不重排」的披露载荷（finish 采样，队列激活或零任务时为零值）。
	// 不越过用户「停止签发」的意图是 fail-safe 的**有意设计**，缺的只是可
	// 观测性：任务列表显示进行中而实际没有 worker 才是缺陷。
	stalledNonTerminal int
	stalledUnknown     bool
}

func (recovery *importQueueRecovery) finish() error {
	if recovery.done {
		return nil
	}
	recovery.done = true
	if recovery.hold {
		recovery.hold = false
		services.EndConfigImportHold()
	}
	if recovery.manager == nil || !recovery.wasActive {
		recovery.stalledNonTerminal, recovery.stalledUnknown = countStalledNonTerminalCertJobs()
		return nil
	}
	recovery.manager.Resume()
	return requeueNonTerminalCertJobs()
}

// countStalledNonTerminalCertJobs 只做披露用的只读统计。统计失败不得否决
// 已提交的导入/还原（数据库已是新配置），退化为「数量未知」的披露。
func countStalledNonTerminalCertJobs() (count int, unknown bool) {
	count, err := services.CountNonTerminalCertJobs(context.Background())
	if err != nil {
		services.Logf("warn", "配置导入：统计未重排的非终态证书任务失败: %v", err)
		return 0, true
	}
	return count, false
}

// stalledWarning 是「证书任务因签发任务已停止而未重排」的披露文案单源
// （响应 warnings 与操作审计同文；空串=无需披露）。
func (recovery *importQueueRecovery) stalledWarning() string {
	if recovery.stalledUnknown {
		return "证书签发任务已停止：导入的非终态证书任务本窗口未重排（数量统计失败，请检查任务列表）——恢复该任务后才会继续推进"
	}
	if recovery.stalledNonTerminal <= 0 {
		return ""
	}
	return fmt.Sprintf("%d 个非终态证书任务因证书签发任务已停止而未重排——恢复该任务后才会继续推进", recovery.stalledNonTerminal)
}

func finishImportFailure(tx *sql.Tx, recovery *importQueueRecovery, importErr error) error {
	if tx != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			importErr = errors.Join(importErr, rollbackErr)
		}
	}
	return errors.Join(importErr, recovery.finish())
}

type configBackup struct {
	// v2.3.0 分类导入:调用方选择只覆盖哪些分类(空=全部);校验和始终验整包
	Sections []string                    `json:"sections,omitempty"`
	Meta     configBackupMeta            `json:"meta"`
	Config   map[string]any              `json:"config"`
	Tables   map[string][]map[string]any `json:"tables"`
}

// UnmarshalJSON 严格化 tables 形状：`"lb_rules": null`
// 与 `[]` 在原生解码下不可区分，前者会被当作「清空该表」而不是拒绝；行元素
// null 也会被静默丢弃。这里区分 null/非数组/非对象行并返回解析错误（调用方
// 映射 400）。
func (backup *configBackup) UnmarshalJSON(data []byte) error {
	type plain configBackup
	var envelope struct {
		*plain
		Tables map[string]json.RawMessage `json:"tables"`
	}
	envelope.plain = (*plain)(backup)
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if envelope.Tables == nil {
		return nil
	}
	backup.Tables = make(map[string][]map[string]any, len(envelope.Tables))
	for name, raw := range envelope.Tables {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
			return fmt.Errorf("备份 tables.%s 必须为数组，不能为 null", name)
		}
		if trimmed[0] != '[' {
			return fmt.Errorf("备份 tables.%s 必须为对象数组", name)
		}
		var rows []map[string]any
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return fmt.Errorf("备份 tables.%s 必须为对象数组: %w", name, err)
		}
		for index, row := range rows {
			if row == nil {
				return fmt.Errorf("备份 tables.%s 第 %d 行不能为 null", name, index+1)
			}
		}
		backup.Tables[name] = rows
	}
	return nil
}

type configBackupMeta struct {
	App        string `json:"app"`
	Version    int    `json:"version"`
	AppVersion string `json:"app_version,omitempty"`
	ExportedAt string `json:"exported_at"`
	Checksum   string `json:"checksum,omitempty"`
}

// backupProductVersionWarning 提示产品版本兼容面；结构 Meta.Version 仍负责
// 硬兼容门，本警告不替代校验也不阻断管理员明确发起的跨版本还原。
func backupProductVersionWarning(meta configBackupMeta, currentVersion string) string {
	if currentVersion == "" || meta.AppVersion == currentVersion {
		return ""
	}
	if meta.AppVersion == "" {
		return "备份未记录导出产品版本，当前运行版本为 " + currentVersion + "——跨版本还原前请确认兼容性"
	}
	return "备份导出产品版本为 " + meta.AppVersion + "，当前运行版本为 " + currentVersion + "——跨版本还原可能存在兼容性差异，请确认后继续"
}

type tableQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func dumpTable(ctx context.Context, database tableQuerier, table string) ([]map[string]any, error) {
	query := "SELECT * FROM " + table
	if table == "global_config" {
		// 导入恒更新 id=1；带外多行时导出也必须读取同一事实行，不能
		// 依赖 SQLite 当前查询计划返回的第一条物理记录。
		query += " WHERE id=1"
	}
	return queryRowsAsMaps(ctx, database, rowQuery{label: "表 " + table, query: query})
}

// sanitizeNodeRowsForExport 只导出节点拓扑与站点坐标，不导出注册明文密钥、
// 在线状态/健康等瞬态数据；cluster_token_hash 保留，灾备后旧令牌仍可认证。
func sanitizeNodeRowsForExport(rows []map[string]any) {
	for _, row := range rows {
		for _, key := range []string{
			"registration_secret", "registration_secret_expires_at",
			"status", "health_json", "last_seen", "last_sync_at", "last_sync_error", "reported_version",
		} {
			delete(row, key)
		}
		// mode 唯一的运行期写入（注册路径）恒为 slave，巡检也按 slave 过滤；
		// 旧版本遗留/带外直改的其它取值原样入包会让当前版本的导入行级门
		// 拒绝该备份（实例无法还原自己的备份），故导出即归一。
		row["mode"] = "slave"
		if hash, _ := row["cluster_token_hash"].(string); hash != "" {
			row["cluster_token_delivered"] = 1
		}
	}
}

// sanitizeNodeRowsForRestore 由预览/导入共用：即使备份来自旧版本或手工构造，
// 也强制清掉临时注册密钥与瞬态状态，避免把备份时的在线/健康数据当成当前事实。
func sanitizeNodeRowsForRestore(rows []map[string]any) {
	for _, row := range rows {
		for _, key := range []string{
			"registration_secret", "registration_secret_expires_at",
			"health_json", "last_seen", "last_sync_at", "last_sync_error",
		} {
			delete(row, key)
		}
		row["status"] = "offline"
		row["reported_version"] = 0
		if hash, _ := row["cluster_token_hash"].(string); hash != "" {
			row["cluster_token_delivered"] = 1
		} else {
			// （裁定）：无令牌哈希的节点无法通过集群认证，恢复
			// 「approved 死行」只会得到一个永不在线的假节点——一律恢复为
			// pending（重新注册语义）；同时显式清除陈旧 delivered 标记
			// （原实现只置 1 从不清 0，手造备份可造出「已下发但无令牌」）。
			row["is_approved"] = 0
			row["cluster_token_delivered"] = 0
		}
	}
}

func tableColumns(ctx context.Context, database *sql.DB, table string) (map[string]bool, error) {
	rows, err := database.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

func restoreTable(ctx context.Context, tx *sql.Tx, database *sql.DB, table string, rows []map[string]any) error {
	valid, err := tableColumns(ctx, database, table)
	if err != nil {
		return fmt.Errorf("读取表结构 %s: %w", table, err)
	}
	for _, row := range rows {
		query, values, ok := restoreRowStatement(table, row, valid)
		if !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, query, values...); err != nil {
			return fmt.Errorf("写入表 %s: %w", table, err)
		}
	}
	return nil
}

// parseImportedMCPIPWhitelist 解析并归一备份里的 api_keys.mcp_ip_whitelist 列值。
// 库内形态是 JSON 字符串数组；旧从节点备份的字面量 "null"、历史导出的裸 IP
// 与重复条目都在此归一到规范形态（裸 IP→/32 或 /128、去重、统一前缀写法）。
// 返回值：归一后的条目、无法解析的原条目（白名单语义下丢弃=收紧，但导入链
// 需要点名拒绝而不是静默收紧）、以及 JSON 形态错误。
func parseImportedMCPIPWhitelist(value any) (normalized []string, dropped []string, err error) {
	if value == nil {
		return nil, nil, nil
	}
	raw, isString := value.(string)
	if !isString {
		return nil, nil, fmt.Errorf("需为 JSON 字符串数组文本，实际类型 %T", value)
	}
	if raw == "" || raw == "null" {
		return nil, nil, nil
	}
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, nil, fmt.Errorf("不是 JSON 字符串数组: %w", err)
	}
	normalized, dropped = services.NormalizeMCPIPWhitelistStrings(entries)
	return normalized, dropped, nil
}

// validateV2BackupMCPIPWhitelist api_keys.mcp_ip_whitelist 行级门。该列以 JSON
// 数组存字符串、认证侧逐条 net.ParseCIDR：带外通道（备份还原/旧从节点备份）
// 带入畸形值时中间件每次请求解析失败 → 该 Key 恒 500（fail-closed，但永久
// 500 且面板无从自愈）。导入侧整包 400 点名该行，让操作者先修备份。
func validateV2BackupMCPIPWhitelist(rows []map[string]any) error {
	for index, row := range rows {
		raw, exists := row["mcp_ip_whitelist"]
		if !exists {
			continue
		}
		normalized, dropped, err := parseImportedMCPIPWhitelist(raw)
		if err != nil {
			return fmt.Errorf("api_keys 第 %d 行的 IP 白名单 %v 无效（%v），请修正备份中该 Key 的白名单后重试", index+1, raw, err)
		}
		if len(dropped) > 0 {
			return fmt.Errorf("api_keys 第 %d 行的 IP 白名单含无效条目 %v（需为 CIDR），请修正后重试", index+1, dropped)
		}
		if len(normalized) > apiKeyMaxWhitelistEntries {
			return fmt.Errorf("api_keys 第 %d 行的 IP 白名单最多 %d 条，实际 %d 条，请修正后重试", index+1, apiKeyMaxWhitelistEntries, len(normalized))
		}
	}
	return nil
}

// restoreRowStatement 构造单行 INSERT 语句与参数。列序确定化：Go map 迭代序
// 每轮随机，按迭代序拼 SQL 会让**每行生成不同文本**——database/sql 以 SQL 文本
// 为键缓存连接级 prepared statement 且不淘汰，万行导入即上万条预编译语句
// （内存 + SQLite 解析 CPU）并把后续真实查询挤出缓存。排序后同一表的所有行
// 共用一条语句文本。ok=false 表示该行没有任何可落库列（跳过）。
func restoreRowStatement(table string, row map[string]any, valid map[string]bool) (string, []any, bool) {
	columnNames := make([]string, 0, len(row))
	for column := range row {
		if valid[column] {
			columnNames = append(columnNames, column)
		}
	}
	if len(columnNames) == 0 {
		return "", nil, false
	}
	sort.Strings(columnNames)
	columns := make([]string, 0, len(columnNames))
	placeholders := make([]string, 0, len(columnNames))
	values := make([]any, 0, len(columnNames))
	for _, column := range columnNames {
		value := row[column]
		// 布尔列写入前把合法 bool/0/1 归一为 INTEGER。
		// 导入与预览已在行级类型门拒绝字符串等畸形形态；写入侧没有、也
		// 不得保留字符串布尔兜底路径。
		if isBackupBooleanColumn(table, column) {
			value = normalizeBackupBooleanValue(value)
		}
		// audit 全备份表可空列的 NULL 毒化归一（写入侧兜底）——布尔归一
		// 对 nil 透传，故在布尔归一之后把仍为 nil 的列替换为 dump 侧对齐默认值
		// （backupTableNullDefaults）：NULL 布尔列落到 schema/dump 默认（如
		// enabled→0）而非布尔强转；created_at 等被 raw time.Time 扫描消费的
		// 时间列归一为可解析 epoch。空串/不可解析文本
		// 由校验侧 validateV2BackupTimestamps 整包 400 先行拦截，不会到达此处。
		if value == nil {
			if columnDefault, ok := backupTableNullDefaults[table][column]; ok {
				value = columnDefault
			}
		}
		// 旧从节点库导出的备份可携带字面量 "null" 白名单——middleware 把非空串
		// 当白名单配置(Unmarshal null 成功但 0 CIDR)→ 主端全来源 403 直至重启
		// 迁移。历史导出还可能带裸 IP（无前缀）与重复条目：这里统一走
		// parseImportedMCPIPWhitelist 归一为规范 JSON 数组（与写侧
		// encodeMCPIPWhitelist 同形态）。畸形形态已由
		// validateV2BackupMCPIPWhitelist 整包 400 先行拦截，本处只做幂等归一；
		// 解析失败时保持原值（不静默丢配置）。
		if table == "api_keys" && column == "mcp_ip_whitelist" {
			if normalized, _, perr := parseImportedMCPIPWhitelist(value); perr == nil {
				if encoded, eerr := encodeMCPIPWhitelist(normalized); eerr == nil {
					value = encoded
				}
			}
		}
		columns = append(columns, `"`+column+`"`)
		placeholders = append(placeholders, "?")
		values = append(values, value)
	}
	return "INSERT INTO " + table + " (" + strings.Join(columns, ",") + ") VALUES (" + strings.Join(placeholders, ",") + ")", values, true
}

// tcpRuleDeadFieldsResetSQL：TCP 行 HTTP 专属死值清零（HTTP 头/健康检查/
// 压缩/请求体/NTLM/force_http1 + TLS 来源、跳转与材料 + 代理超时族七列 +
// 自定义路由 + dynamic_dns + strategy(cookie) + dns_family(ipv4) + 阶段页四列
// + log_enabled，共 32 列 SET）——字面量单源已下沉 db 包（启动迁移与导入归一
// 共用同一常量，消灭跨包双份逐字镜像的漂移面）；本别名仅保留 handlers 包内
// 既有引用点与派生（下方单规则变体）。
const tcpRuleDeadFieldsResetSQL = db.TCPRuleDeadFieldsResetSQL

// tcpRulePathRulesResetSQL：TCP 规则残留路径规则清理（TCP 自愈族）——
// custom_routes_enabled 归零后 path_rules 行成为孤儿（TCP 渲染零消费路径
// 分支），随导出/备份导入被引用校验放大。字面量单源=db 包导出常量（与
// 启动迁移共用）。
const tcpRulePathRulesResetSQL = db.TCPRulePathRulesResetSQL

// tcpRuleDeadFieldsResetForRuleSQL 复用同一份 SET 投影，供启用单条 TCP 规则时
// 在事务内落库归一；WHERE 收敛为单规则，避免触碰其他禁用行。
var tcpRuleDeadFieldsResetForRuleSQL = func() string {
	prefix, _, found := strings.Cut(tcpRuleDeadFieldsResetSQL, "WHERE protocol='tcp' AND (")
	if !found {
		panic("TCP 死值归一 SQL 缺少协议谓词")
	}
	return prefix + " WHERE protocol='tcp' AND caddy_id = ?"
}()

// normalizeRuleRowsForTransport：导入事务内的规则行
// 存储归一共享实现——v1 导入与 v2 备份导入两条写路径的唯一归一点：
// ① TCP 行 HTTP 专属死字段按 tcpRuleDeadFieldsResetSQL 清零（WHERE 谓词与
// normalizeRuleForTransport / db.migrateTCPRuleDeadFields 同口径——
// enable_tls=1 即入选，不要求证书材料非空）；TCP 上游回源域名按
// db.TCPRuleUpstreamOriginResetSQL 同批清零（origin_domain 仅 HTTP 消费）；
// ② lb_rules/path_rules 的 created_at/updated_at 时间戳平面格式归一
// （与启动迁移 normalizeRuleTimestampsMigration 同款 strftime/LIKE 门；
// 导出 dump 为 SELECT * 原样行，旧备份可携带 RFC3339/Go time 格式）。
// 启动迁移的 bump cluster_version 语义刻意不在此（迁移含快照缓存失效
// 收敛语义；导入事务本身即变更源，维持单独形态）。
// 返回被解除的 TCP 规则安全策略绑定条数（绑定表为派生数据，
// TCP 渲染链不消费策略；导入携带的 TCP 绑定与 live 残留均在此统一清理）。
func normalizeRuleRowsForTransport(ctx context.Context, tx *sql.Tx) (int64, error) {
	if _, err := tx.ExecContext(ctx, tcpRuleDeadFieldsResetSQL); err != nil {
		return 0, fmt.Errorf("规则 TCP 死值归一失败: %w", err)
	}
	// TCP 自愈族：TCP 残留路径规则同事务清理——custom_routes_enabled
	// 已归零，孤儿 path_rules 行随导出/备份往返被引用校验放大。
	if _, err := tx.ExecContext(ctx, tcpRulePathRulesResetSQL); err != nil {
		return 0, fmt.Errorf("规则 TCP 路径规则归一失败: %w", err)
	}
	// TCP 上游回源域名残留同族清零——origin_domain 仅 HTTP 回源消费，TCP 行
	// 携带它属死值（保存族拒绝、渲染零消费）；字面量单源=db 包常量（与启动
	// 迁移共用），使导入面与导出/从端落库/启动迁移同口径归一，而不是让该实例
	// 自己导出的备份在导入校验被整包 400（备份自毒）。校验侧已在评估前按同
	// 口径丢弃该值（config_backup.go 的 upstreams 还原循环）。
	if _, err := tx.ExecContext(ctx, db.TCPRuleUpstreamOriginResetSQL); err != nil {
		return 0, fmt.Errorf("规则 TCP 上游回源域名归一失败: %w", err)
	}
	// 非 acme_dns 来源不消费 acme_config_id——导入行清理跨模式死引用
	// （与 Create/Update/Duplicate 保存链、启动迁移、传输归一同一谓词）。
	// tls_source 的读取口径全族是 COALESCE(tls_source,'manual')（写侧列清单、
	// 值域门、启动迁移、传输归一）：NULL 视作 manual，空串同样非 acme_dns，
	// 两者都必须清零——裸比较会把 NULL/空串行排除在外，导致同一行在启动迁移
	// 被清零、在导入被保留。
	if _, err := tx.ExecContext(ctx, `UPDATE lb_rules SET acme_config_id=0 WHERE COALESCE(tls_source,'manual')<>'acme_dns' AND COALESCE(acme_config_id,0)<>0`); err != nil {
		return 0, fmt.Errorf("规则非 ACME TLS 残留 ACME 引用归一失败: %w", err)
	}
	// 跨模式残留归一——非 manual 源不保留证书材料
	// （私钥正文随导出/备份/快照放大）；非 acme_dns 源不保留 CA 提供商引用
	// （ResolveCAProviderID 对非 0 不校验存在性，残留死引用签发期才暴露）。
	if _, err := tx.ExecContext(ctx, `UPDATE lb_rules SET tls_cert='', tls_key=''
		WHERE COALESCE(tls_source,'manual')<>'manual' AND (COALESCE(tls_cert,'')<>'' OR COALESCE(tls_key,'')<>'')`); err != nil {
		return 0, fmt.Errorf("规则跨模式证书材料归一失败: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE lb_rules SET ca_provider_id=0
		WHERE COALESCE(tls_source,'manual')<>'acme_dns' AND COALESCE(ca_provider_id,0)<>0`); err != nil {
		return 0, fmt.Errorf("规则跨模式 CA 提供商引用归一失败: %w", err)
	}
	// TCP 规则的安全策略绑定不参与渲染（buildTCPProxyRoute 无策略
	// 加载），绑定写接口又拒绝 TCP——残留绑定会在策略页 rule_count/绑定视图中
	// 显示生效而运行态零防护。导入事务内按导入后规则视图清理。
	droppedBindings, err := pruneTCPRuleBindings(ctx, tx)
	if err != nil {
		return 0, err
	}
	// 时间戳归一口径单源：db.NormalizeRuleTimestamps 与启动迁移共用同一谓词
	// （「strftime 结果 ≠ 列值」而非 LIKE 启发式，覆盖导入校验接受的分钟精度与
	// 小数秒两种布局）。
	if err := db.NormalizeRuleTimestamps(ctx, tx); err != nil {
		return 0, fmt.Errorf("规则时间戳归一失败: %w", err)
	}
	return droppedBindings, nil
}

// pruneTCPRuleBindings 清理导入后规则视图中 TCP 规则的策略绑定
// 不变量：TCP 渲染链不消费策略，绑定为死绑定）。幂等——无命中返回 0。
//
// 本清理原本只随 normalizeRuleRowsForTransport
// 在「备份携带 lb_rules」时执行；仅导入「安全防护」分类（lb_rules 缺席）而
// security_policy_bindings 被携带时，指向 live TCP 规则的绑定仍会插入并存活，
// 策略页 rule_count/绑定视图宣称生效而运行态零防护。故 v2 导入把本步从
// hasRules 门中提出，无条件执行一次（与 collectPostCommitCleanup 的事务内
// 幂等重复无害同型）。
func pruneTCPRuleBindings(ctx context.Context, tx *sql.Tx) (int64, error) {
	result, err := tx.ExecContext(ctx, `DELETE FROM security_policy_bindings
		WHERE rule_caddy_id IN (SELECT caddy_id FROM lb_rules WHERE protocol='tcp')`)
	if err != nil {
		return 0, fmt.Errorf("清理 TCP 规则安全策略绑定失败: %w", err)
	}
	// DELETE 已成功：计数失败只影响审计/响应里的条数展示，不影响导入结果
	// ——按 0 计并留痕（与同文件悬挂绑定清理同口径，不得独吞错误）。
	dropped, countErr := result.RowsAffected()
	if countErr != nil {
		services.Logf("warn", "清理 TCP 规则安全策略绑定：读取影响行数失败（按 0 计，清理动作已成功）: %v", countErr)
		return 0, nil
	}
	return dropped, nil
}

type importRuntimeSnapshot struct {
	caddyConfig map[string]interface{}
	certFiles   services.CertFilesSnapshot
}

type importCertificate struct {
	ruleID  string
	certPEM string
	keyPEM  string
}

func currentRuleIDs(ctx context.Context) ([]string, error) {
	return ruleIDsFromQueryer(ctx, db.DB)
}

func (h *Handlers) snapshotImportRuntime(ruleIDs []string) (importRuntimeSnapshot, error) {
	caddyConfig, err := h.caddyService.GetConfig()
	if err != nil {
		return importRuntimeSnapshot{}, fmt.Errorf("读取当前 Caddy 配置: %w", err)
	}
	certFiles, err := services.SnapshotCertFiles(ruleIDs)
	if err != nil {
		return importRuntimeSnapshot{}, err
	}
	return importRuntimeSnapshot{caddyConfig: caddyConfig, certFiles: certFiles}, nil
}

// restoreImportRuntime 把运行配置/证书文件回退到快照。
// ApplyConfig 在「运行配置与快照字节一致」时返回 errSameConfig 哨兵——
// 这是成功的空操作（拒绝/快照失败等路径运行配置本就没变），不是恢复失败：
// 不过滤会把确定性命中的同字节短路 join 进响应/审计/失败横幅（「恢复失败」
// 假信号）。证书文件恢复仍按真实错误上报。
func (h *Handlers) restoreImportRuntime(snapshot importRuntimeSnapshot) error {
	certErr := services.RestoreCertFiles(snapshot.certFiles)
	caddyErr := h.caddyService.ApplyConfig(snapshot.caddyConfig)
	if services.IsSameConfig(caddyErr) {
		caddyErr = nil
	}
	return errors.Join(caddyErr, certErr)
}

func materializeImportCertificates(certificates []importCertificate) error {
	for _, certificate := range certificates {
		if err := validateTLSCertificate(certificate.certPEM, certificate.keyPEM); err != nil {
			return fmt.Errorf("验证规则 %s 的证书: %w", certificate.ruleID, err)
		}
		if err := services.WriteCertFiles(certificate.ruleID, certificate.certPEM, certificate.keyPEM); err != nil {
			return fmt.Errorf("写入规则 %s 的证书文件: %w", certificate.ruleID, err)
		}
	}
	return nil
}

// normalizeBackupBooleanNulls 把库导出的 NULL 布尔行归一为当前表结构
// 要求的非空值（lb_rules/upstreams.enabled NULL→0、users.is_enabled NULL→1），与
// 迁移口径一致（用户缺省启用，规则/上游缺省禁用）。
// 必须在 checksum 校验之后执行（checksum 覆盖原始内容，先归一会让自带校验和的备份
// 全部误报篡改），并在管理员校验之前执行（backupBooleanEnabled(nil)=false 会把
// 全 null 管理员备份先行 400 拦截，归一不可达）。
func normalizeBackupBooleanNulls(tables map[string][]map[string]any) {
	for _, table := range []string{"lb_rules", "upstreams"} {
		for _, row := range tables[table] {
			if enabled, exists := row["enabled"]; exists && enabled == nil {
				row["enabled"] = 0
			}
		}
	}
	for _, row := range tables["users"] {
		if enabled, exists := row["is_enabled"]; exists && enabled == nil {
			row["is_enabled"] = 1
		}
	}
}

// validateBackupRuleReferences 写入前校验跨表引用均存在于备份自带的数据：
// upstreams/path_rules 的 rule_id ∈ lb_rules（悬挂引用靠 FK 在删表后以 500 回滚兜底，
// 与 cert_jobs 的显式清理语义不一致；提前转为 400 校验错误，保证校验不过零写入），
// 以及 security_policy_bindings 的 rule_caddy_id ∈ lb_rules、policy_id ∈ security_policies
// （该表无外键，无 FK 兜底，见）。
func validateBackupRuleReferences(tables map[string][]map[string]any) error {
	ruleRows, rulesCarried := tables["lb_rules"]
	if !rulesCarried && db.DB != nil && (len(tables["upstreams"]) > 0 || len(tables["path_rules"]) > 0 || len(tables["security_policy_bindings"]) > 0) {
		// 分类备份缺少 lb_rules 时该表保持 live——引用校验必须使用
		// 「备份携带则备份行、缺席则 live 行」的导入后视图，而非空子集。
		rows, err := db.DB.Query(`SELECT caddy_id, COALESCE(protocol,''), COALESCE(dynamic_dns,0), COALESCE(health_check_host,'') FROM lb_rules`)
		if err != nil {
			return fmt.Errorf("备份校验失败：读取现有规则引用视图: %w", err)
		}
		for rows.Next() {
			var id, protocol, healthHost string
			var dynamicDNS bool
			if err := rows.Scan(&id, &protocol, &dynamicDNS, &healthHost); err != nil {
				_ = rows.Close()
				return fmt.Errorf("备份校验失败：读取现有规则引用视图: %w", err)
			}
			ruleRows = append(ruleRows, map[string]any{"caddy_id": id, "protocol": protocol, "dynamic_dns": dynamicDNS, "health_check_host": healthHost})
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("备份校验失败：读取现有规则引用视图: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("备份校验失败：关闭现有规则引用视图: %w", err)
		}
	}
	ruleIDs := make(map[string]struct{}, len(ruleRows))
	for _, row := range ruleRows {
		if id, ok := row["caddy_id"].(string); ok {
			ruleIDs[id] = struct{}{}
		}
	}
	for _, table := range []string{"upstreams", "path_rules"} {
		for i, row := range tables[table] {
			ruleID, _ := row["rule_id"].(string)
			if _, exists := ruleIDs[ruleID]; !exists {
				return fmt.Errorf("备份校验失败：%s 第 %d 行引用了不存在的规则 %q", table, i+1, ruleID)
			}
		}
	}
	// 保存侧上游单源校验：host/port/weight/max_connections/协议/查重/
	// 回源域名与混布全部同门。v2 是存量行还原，仅保留零上游/零启用兼容。
	ruleProtocols := make(map[string]string, len(ruleRows))
	ruleDynamicDNS := make(map[string]bool, len(ruleRows))
	for _, row := range ruleRows {
		id, _ := row["caddy_id"].(string)
		ruleProtocols[id], _ = row["protocol"].(string)
		ruleDynamicDNS[id] = backupBooleanEnabled(row["dynamic_dns"])
		if host := backupString(row["health_check_host"]); host != "" {
			if ruleProtocols[id] == "tcp" {
				return fmt.Errorf("备份校验失败：规则 %q 的健康检查域名仅 HTTP 规则支持", id)
			}
			if !isValidHost(host) {
				return fmt.Errorf("备份校验失败：规则 %q 的健康检查域名 %q 无效（仅支持主机名，不带端口）", id, host)
			}
		}
	}
	upstreamsByRule := make(map[string][]models.Upstream)
	for index, row := range tables["upstreams"] {
		ruleID := backupString(row["rule_id"])
		// （裁定）：显式 weight<1 响亮拒绝，不再沿用「0→1 静默归一」
		// 兼容语义（与保存侧 validateRuleUpstreams 的门同口径——该门
		// 对模型 0 值一律拒绝，故缺键/NULL 必须先归位）。缺键/NULL 按 schema
		// DEFAULT 1 归位（backupTableNullDefaults 同值——旧库/手造备份的 NULL
		// 形态保持可导入），显式 0/负值/非整数形态整包 400 点名行号。数值
		// 字符串与既有整型门同族放行。
		rawWeight, weightExists := row["weight"]
		if !weightExists || rawWeight == nil {
			row["weight"] = int64(1)
		} else if weight, ok := backupInteger(rawWeight); !ok || weight < 1 {
			return fmt.Errorf("备份校验失败：upstreams 第 %d 行 weight 必须为不小于 1 的整数", index+1)
		}
		// TCP 规则的上游回源域名是死值（保存族自该字段引入起即拒绝 TCP 携带、
		// TCP 渲染零消费），写侧由 normalizeRuleRowsForTransport 按与启动迁移
		// 同一常量清零——校验必须先按归一后的形态评估，否则带外残留（直改库/
		// 旧版本/外来写入）会让实例自己导出的备份在导入阶段整包 400（备份自毒）。
		// HTTP 规则的回源域名仍交 validateRuleUpstreams 的值域门。
		originDomain := backupString(row["origin_domain"])
		if ruleProtocols[ruleID] == "tcp" {
			originDomain = ""
		}
		upstreamsByRule[ruleID] = append(upstreamsByRule[ruleID], models.Upstream{
			Host: backupString(row["host"]), Port: backupInt(row["port"]),
			Weight: backupInt(row["weight"]), DynamicDNS: backupBooleanEnabled(row["dynamic_dns"]),
			Enabled: backupBooleanEnabled(row["enabled"]), Protocol: backupString(row["protocol"]),
			MaxConnections: backupInt(row["max_connections"]), OriginDomain: originDomain,
		})
	}
	for _, rule := range ruleRows {
		ruleID := backupString(rule["caddy_id"])
		upstreams := upstreamsByRule[ruleID]
		if len(upstreams) == 0 {
			continue
		}
		if _, err := validateRuleUpstreams(ruleProtocols[ruleID], ruleDynamicDNS[ruleID], upstreams, false); err != nil {
			return fmt.Errorf("备份校验失败：规则 %q：%w", ruleID, err)
		}
	}
	// security_policy_bindings 无外键约束，悬挂引用可原样落库——绑定指向
	// 不存在的策略时，loadSecurityPolicyContext 查不到策略即按无策略渲染，该规则
	// WAF/限流/GeoIP 全部静默失效（与同类的静默 weakening）。保存侧绑定
	// 要求策略与规则均存在，导入校验须同严。
	policyRows, policiesCarried := tables["security_policies"]
	if !policiesCarried && db.DB != nil && len(tables["security_policy_bindings"]) > 0 {
		rows, err := db.DB.Query(`SELECT id FROM security_policies`)
		if err != nil {
			return fmt.Errorf("备份校验失败：读取现有安全策略引用视图: %w", err)
		}
		for rows.Next() {
			var id int
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return fmt.Errorf("备份校验失败：读取现有安全策略引用视图: %w", err)
			}
			policyRows = append(policyRows, map[string]any{"id": id})
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("备份校验失败：读取现有安全策略引用视图: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("备份校验失败：关闭现有安全策略引用视图: %w", err)
		}
	}
	policyIDs := make(map[int]struct{}, len(policyRows))
	for _, row := range policyRows {
		if id, ok := backupInteger(row["id"]); ok {
			policyIDs[id] = struct{}{}
		}
	}
	for i, row := range tables["security_policy_bindings"] {
		ruleID, _ := row["rule_caddy_id"].(string)
		if _, exists := ruleIDs[ruleID]; !exists {
			return fmt.Errorf("备份校验失败：security_policy_bindings 第 %d 行引用了不存在的规则 %q", i+1, ruleID)
		}
		policyID, ok := backupInteger(row["policy_id"])
		if !ok {
			return fmt.Errorf("备份校验失败：security_policy_bindings 第 %d 行 policy_id 必须为整数", i+1)
		}
		if _, exists := policyIDs[policyID]; !exists {
			return fmt.Errorf("备份校验失败：security_policy_bindings 第 %d 行引用了不存在的安全策略 %d", i+1, policyID)
		}
	}
	return nil
}

// validateImportedSources 仅允许内置源，并把 URL/format 强制归一为
// canonical 定义。合法 name 不得携带任意下载地址或解析器进入更新任务。
func validateImportedSources(rows []map[string]any, canonical func(string) (string, string, bool), label string) error {
	for _, row := range rows {
		name, _ := row["name"].(string)
		url, format, ok := canonical(name)
		if !ok {
			return fmt.Errorf("%s不受支持: %s", label, name)
		}
		row["url"] = url
		row["format"] = format
	}
	return nil
}

func canonicalThreatBackupSource(name string) (string, string, bool) {
	seed, ok := db.CanonicalThreatSource(name)
	return seed.URL, seed.Format, ok
}

func validateImportedThreatSources(rows []map[string]any) error {
	return validateImportedSources(rows, canonicalThreatBackupSource, "威胁库源")
}

func validateImportedCrawlerSources(rows []map[string]any) error {
	return validateImportedSources(rows, services.CanonicalCrawlerSource, "爬虫地址库源")
}

// validateImportedSecurityCustomRules：导入路径复用保存侧
// validateSecurityCustomRule 的行级约束——此前导入对 security_custom_rules 零验证，
// 篡改/损坏备份可带入 score=-5（coraza setvar:+-5 运行时减分，异常评分静默失真）
// 或非法 action/名称。与布尔门同位：结构性校验阶段拒绝，零写入。
func validateImportedSecurityCustomRules(rows []map[string]any) error {
	for i, row := range rows {
		// id 区间门。导入/还原经 restoreTable 按 dump 行**显式
		// 写入 id**，而自定义规则发射 id = DB id + 10000——DB id ≥ 790000 时发射 id
		// 撞入 GeoIP 预检保留段（800000-899999，geoipPrecheckRuleBase 起），渲染侧
		// security.go:670 对该形状跳过发射（仅 warn 日志），规则在 UI 显示启用却不
		// 生效 → 违反「只有可渲染配置可落库」不变量。此处拒绝（省略/NULL id 的行由
		// AUTOINCREMENT 分配，不受影响）。合法上限与渲染侧守卫同源口径。
		if rawID, ok := row["id"]; ok && rawID != nil {
			var id int
			switch v := rawID.(type) {
			case float64:
				id = int(v)
			case int:
				id = v
			case string:
				parsed, perr := strconv.Atoi(strings.TrimSpace(v))
				if perr != nil {
					return fmt.Errorf("security_custom_rules 第 %d 行 id 非数字: %q", i+1, v)
				}
				id = parsed
			default:
				return fmt.Errorf("security_custom_rules 第 %d 行 id 类型错误", i+1)
			}
			if id <= 0 {
				// 与 validateV2BackupNodeRows 同口径：显式 id 必须为正整数。
				// SQLite INTEGER PRIMARY KEY 接受 0/负 rowid，发射 id（+10000）
				// 会落在 10000/负数域，形成非预期 coraza 规则 id。
				return fmt.Errorf("security_custom_rules 第 %d 行 id=%d 非法：显式 id 必须为正整数（省略该键由自增分配）", i+1, id)
			}
			if id >= 790000 {
				return fmt.Errorf("security_custom_rules 第 %d 行 id=%d 越界：发射 id（+10000）将撞入 GeoIP 预检保留段，渲染侧会跳过该规则（可落库但不可发射）", i+1, id)
			}
		}
		// action/score 为 NULL 的可空形态按 schema/dump 默认
		// （'block'/5，cluster_snapshot.go snapshotSecurityCustomRules）看待通过
		// 校验；写入侧由 restoreTable
		// 归一为同一默认值。本校验在 checksum 之前执行，不得回写行数据（回写会让
		// 自带校验和的备份误报篡改），故只做读取侧替换。
		rule := models.SecurityCustomRule{
			Name:           fmt.Sprintf("%v", row["name"]),
			Description:    backupString(row["description"]),
			ConditionLogic: "and",
			Action:         "block",
			Score:          5,
		}
		if rawLogic := row["condition_logic"]; rawLogic != nil {
			rule.ConditionLogic = fmt.Sprintf("%v", rawLogic)
		}
		if rawAction := row["action"]; rawAction != nil {
			rule.Action = fmt.Sprintf("%v", rawAction)
		}
		// conditions 列在导出 JSON 中为字符串（DB TEXT 列承载 JSON 数组），个别
		// 历史导出可能内联为数组——两种形态都归一为 []CustomRuleCondition。
		switch raw := row["conditions"].(type) {
		case string:
			if err := json.Unmarshal([]byte(raw), &rule.Conditions); err != nil {
				return fmt.Errorf("security_custom_rules 第 %d 行 conditions 解析失败: %w", i+1, err)
			}
		default:
			reencoded, err := json.Marshal(raw)
			if err != nil {
				return fmt.Errorf("security_custom_rules 第 %d 行 conditions 解析失败: %w", i+1, err)
			}
			if err := json.Unmarshal(reencoded, &rule.Conditions); err != nil {
				return fmt.Errorf("security_custom_rules 第 %d 行 conditions 解析失败: %w", i+1, err)
			}
		}
		switch score := row["score"].(type) {
		case nil:
			// NULL 按 schema/dump 默认 5 看待（见上），写入侧归一为同值。
		case float64:
			rule.Score = int(score)
		case string:
			parsed, err := strconv.Atoi(strings.TrimSpace(score))
			if err != nil {
				return fmt.Errorf("security_custom_rules 第 %d 行 score 非数字: %q", i+1, score)
			}
			rule.Score = parsed
		default:
			return fmt.Errorf("security_custom_rules 第 %d 行 score 缺失或类型错误", i+1)
		}
		if err := validateSecurityCustomRule(&rule); err != nil {
			return fmt.Errorf("security_custom_rules 第 %d 行: %w", i+1, err)
		}
	}
	return nil
}

// configBackupChecksumPayload 序列化完整性校验和载荷——导出与校验共用的
// 单一实现，杜绝算法双份漂移。
//
// version 3 起把 meta 与体内 sections（还原范围）纳入摘要：还原范围完全取自
// sections，篡改它必须触发「已篡改」而不是静默改变还原范围。version 1/2 的
// 存量包仍按旧口径 {tables,config} 校验——改旧口径会让全部存量备份误报篡改。
func configBackupChecksumPayload(backup configBackup) ([]byte, error) {
	if backup.Meta.Version >= 3 {
		meta := backup.Meta
		meta.Checksum = "" // 校验和自身不入摘要（omitempty 保证字节稳定）
		return json.Marshal(struct {
			Meta     configBackupMeta            `json:"meta"`
			Sections []string                    `json:"sections,omitempty"`
			Tables   map[string][]map[string]any `json:"tables"`
			Config   map[string]any              `json:"config"`
		}{meta, backup.Sections, backup.Tables, backup.Config})
	}
	return json.Marshal(struct {
		Tables map[string][]map[string]any `json:"tables"`
		Config map[string]any              `json:"config"`
	}{backup.Tables, backup.Config})
}

// backupIntegrityFacts 完整性校验产出的事实位——调用方据此决定审计/预览
// 披露，不把它们塞进 error 文本（拒绝与「接受但弱」是两条路径）。
type backupIntegrityFacts struct {
	// LegacyChecksum 走了旧格式（仅数据表）校验和回退：数据表完整性成立，
	// 全局配置区不受校验和保护。
	LegacyChecksum bool
	// NoChecksum v1 史前备份，文件完全不含完整性校验和。
	NoChecksum bool
}

// verifyBackupIntegrity 整包完整性校验：结构/版本/导出口径、checksum（对全量
// tables+config 计算，未选分类同样覆盖）、布尔 NULL 归一、必需表门、管理员门。
// 在 sections 过滤之前执行。返回的事实位供调用方披露：LegacyChecksum=走了
// 旧格式（仅 tables）校验和回退，NoChecksum=v1 文件完全不含校验和；
// legacy 只跳过「checksum 不匹配即拒」，其后所有行级/白名单/凭证/管理员门
// 照常执行。
func verifyBackupIntegrity(backup configBackup) (backupIntegrityFacts, error) {
	var facts backupIntegrityFacts
	if backup.Meta.App != "lazy-balancer-v2" || backup.Tables == nil {
		return backupIntegrityFacts{}, errors.New("不是有效的 Lazy Balancer 备份文件")
	}
	if backup.Meta.Version < 1 || backup.Meta.Version > 3 {
		return backupIntegrityFacts{}, fmt.Errorf("不支持的备份版本: %d", backup.Meta.Version)
	}
	// v2.3.0 分类导出可不带全局配置区(未勾选「全局配置」):Config=nil 合法,
	// 校验和按导出时的实际内容(含 null 形态)计算仍完整覆盖;从完整导出中
	// 恶意剥离 Config 会触发校验和不一致而被拒。
	// v2/v3 备份必带导出时间戳与校验和（v2.1.1 起导出即两者齐备）。剥掉
	// exported_at 或 checksum 的文件一律按不兼容拒绝——旧格式校验和回退仅限
	// Version==1 的史前导出，防止 Config 区（dns_credentials/acme_email/管理面板
	// TLS 材料）借字段剥离绕过完整性校验。
	if backup.Meta.Version >= 2 && backup.Meta.ExportedAt == "" {
		return backupIntegrityFacts{}, errors.New("备份由 v2.1.1 或更早版本导出，校验和格式不兼容，请使用 v2.1.2 及以上版本重新导出后再导入")
	}
	if backup.Meta.Version >= 2 && backup.Meta.Checksum == "" {
		return backupIntegrityFacts{}, errors.New("备份缺少完整性校验和，请使用 v2.1.2 及以上版本重新导出后再导入")
	}
	if backup.Meta.Checksum != "" {
		checksumPayload, err := configBackupChecksumPayload(backup)
		if err != nil {
			return backupIntegrityFacts{}, fmt.Errorf("计算备份校验和失败: %w", err)
		}
		sum := sha256.Sum256(checksumPayload)
		if hex.EncodeToString(sum[:]) != backup.Meta.Checksum {
			// 旧格式（仅 tables）校验和回退仅限明确的旧格式标记
			// （Version==1 且无 exported_at 的史前导出，收紧）；新格式文件
			// （带 exported_at）校验和不匹配直接拒绝——否则仅篡改 Config 区
			// （dns_credentials/acme_email/管理面板 TLS 材料）而保留 tables 的文件
			// 可借回退通过完整性校验。
			tablesJSON, _ := json.Marshal(backup.Tables)
			oldSum := sha256.Sum256(tablesJSON)
			tablesOnlyMatch := hex.EncodeToString(oldSum[:]) == backup.Meta.Checksum
			if backup.Meta.ExportedAt == "" && backup.Meta.Version == 1 && tablesOnlyMatch {
				// legacy 形态是受支持路径——只跳过「checksum 不匹配
				// 即拒」，置标志位后继续执行布尔/cert 状态/CA 白名单/凭证/
				// 管理员门（此前 early-return 让这些门对 legacy 全失效）。
				facts.LegacyChecksum = true
				goto afterChecksum
			}
			if backup.Meta.Version == 2 && tablesOnlyMatch {
				// v2.1.1（及更早）导出即「tables-only 校验和 + exported_at
				// 非空」形态——tables 区完整性成立，是合法旧版文件而非篡改证据；
				// 但 Config 区不受旧校验和保护，仍须拒绝导入，仅改报兼容性提示。
				return backupIntegrityFacts{}, errors.New("备份由 v2.1.1 或更早版本导出，校验和格式不兼容，请使用 v2.1.2 及以上版本重新导出后再导入")
			}
			return backupIntegrityFacts{}, errors.New("备份校验和不匹配，文件可能已被篡改或损坏")
		}
	}
afterChecksum:
	// v1 史前备份可完全不含校验和（v2 及以后的强制门不覆盖它）：结构门照常
	// 执行，但文件内容未经任何摘要校验——比「仅数据表校验和」的旧格式更弱，
	// 必须由调用方显式披露（审计/预览告警）。
	if backup.Meta.Version == 1 && backup.Meta.Checksum == "" {
		facts.NoChecksum = true
	}
	// 归一须在 checksum 校验之后（避免自带校验和的备份被误判篡改）、
	// 管理员校验之前（backupBooleanEnabled(nil)=false 会先行 400 拦截全 null 管理员备份）。
	normalizeBackupBooleanNulls(backup.Tables)
	requiredTables := configBackupTables
	if backup.Meta.Version == 1 {
		requiredTables = configBackupV1Tables
	}
	// v2.3.0 分类导出只含所选分类的表:必需表清单仅对「全量形态」生效——
	// 分类(2026-09-19 三分类合并；本轮新增节点拓扑)后以表族齐备判全量(全量导出恒含
	// users/lb_rules/security;V1 恒全量)。旧判定「含 users 即全量」会把
	// users 分类备份(系统数据+全局配置)误判为全量并以缺表拒绝——正是
	// 要消灭的死备份形态。分类备份只要求至少一张已知表,完整性
	// 由校验和兜底。
	_, hasUsers := backup.Tables["users"]
	_, hasRules := backup.Tables["lb_rules"]
	_, hasSecurity := backup.Tables["security_policies"]
	if (hasUsers && hasRules && hasSecurity) || backup.Meta.Version == 1 {
		for _, required := range requiredTables {
			if _, exists := backup.Tables[required]; exists {
				continue
			}
			// 迟到表容缺(见 configBackupLateTables)——Version=2 导出
			// 清单中途新增的表,此前时代的合法全量备份不含,缺席不拒绝。
			if _, late := configBackupLateTables[required]; late {
				continue
			}
			return backupIntegrityFacts{}, errors.New("备份缺少必需的数据表: " + required)
		}
	} else {
		known := 0
		for _, table := range configBackupTables {
			if _, exists := backup.Tables[table]; exists {
				known++
			}
		}
		if known == 0 {
			return backupIntegrityFacts{}, errors.New("备份不包含任何已知数据表")
		}
	}
	for _, table := range configBackupTables {
		if _, exists := backup.Tables[table]; !exists {
			backup.Tables[table] = []map[string]any{}
		}
	}
	// v2.3.0 分类导出可不带 users 表:不含/空=本地用户不动,管理员门跳过
	// (全量导出恒有≥1 管理员;上方 normalize 已把缺失表补成空切片,故按长度判)
	if len(backup.Tables["users"]) == 0 {
		return facts, nil
	}
	// 管理员可用性门：启用且「可登录」——仅 role+is_enabled 会让空哈希/缺
	// OIDC 身份的账号名义通过；导入事务随后吊销全部会话，面板将无人可登录。
	for _, user := range backup.Tables["users"] {
		if role, _ := user["role"].(string); role == "admin" && backupBooleanEnabled(user["is_enabled"]) && backupUserLoginCapable(user) {
			return facts, nil
		}
	}
	return backupIntegrityFacts{}, errors.New("备份必须至少包含一个已启用的管理员账号，且该账号具备可用登录凭据（本地密码或完整 OIDC 身份）")
}

// validateV2BackupCertJobStatuses 在空域名规则及其任务软跳过之后执行，
// 避免将被丢弃任务的非法状态升级为整包 400。
func validateV2BackupCertJobStatuses(tables map[string][]map[string]any) error {
	for _, job := range tables["cert_jobs"] {
		status, ok := job["status"].(string)
		if !ok {
			return errors.New("证书任务状态不能为空")
		}
		if _, allowed := configBackupCertJobStatuses[status]; !allowed {
			return fmt.Errorf("无效的证书任务状态: %s", status)
		}
	}
	return nil
}

// validateV2BackupNodeRows：nodes 表行级
// 类型/必填/范围门——此前 nodes 无任何行级校验，带 port:null、
// is_approved:null、server_map_lat:"north"、越界坐标的备份可导入并提交，
// 随后节点列表每秒 500、snapshotNodeSites 失败。口径：
//   - name/ip_address：NOT NULL 无默认列，缺失/空/非字符串 400 点名
//     （不静默造默认值——备份行无身份即非法）；
//   - id/port/sync_interval：整数门，port 1-65535、sync_interval 1-86400
//     （与全局 sync_interval 门同族边界）；
//   - server_map_lat/lon：数值门 + 范围（与 validateServerMapCoordinates
//     单源同边界：-90/90、-180/180）；
//   - protocol：仅 http/https，空串归一为 http（schema DEFAULT 语义）；
//     cluster_token_hash：字符串或 NULL（NULL=待重新注册）；
//   - mode：仅 slave，空串归一为 slave（schema DEFAULT 语义）；master 行点名
//     拒绝——该列由注册路径独占写入，巡检按 slave 过滤，放行 master 行会让
//     节点静默退出离线/滞后判定。
//
// name 落库前走 models.NormalizeClusterNodeName
// 单源归一（去首尾空白/剥离控制字符/截断 100 rune），但只静默归一
// 首尾空白——控制字符或超长值 400 点名（不静默改写：篡改备份注入的换行/
// 控制字符会污染节点列表、审计与日志文本，静默剥离会让「导入成功」掩盖
// 篡改事实）；ip_address 与注册侧 binding:"required,ip" 同口径，必须是可
// 解析的 IP 字面量（net.ParseIP），拒绝首尾空白/控制字符/路径与 host:port
// 混写（这些形态在 resolveNodeAccessURL 派生 authority 时产生混淆）。
//
// access_url 是能力票据（服务控制/登录票据）
// 的投递地址——保存侧 RegisterNode/UpdateNodeAccessURL 均过
// models.ValidateClusterAccessURL，导入侧此前完全放行，可把票据引向任意
// 第三方主机（含 query/userinfo 的回传通道）。导入与保存侧同门。
//
// NULL 可空列不拒绝——写入侧 backupTableNullDefaults["nodes"] 归一；
// 布尔两列（is_approved/cluster_token_delivered）由
// validateV2BackupBooleanTypes 覆盖；created_at 由 validateV2BackupTimestamps
// 覆盖。旧备份缺席 nodes 表由迟到表「缺席=保留本地」语义承接，不进本门。
func validateV2BackupNodeRows(rows []map[string]any) error {
	// 身份唯一性行门——nodes 有 UNIQUE(ip_address, port)，
	// 重复身份行若只落到事务内才报错，会以 500「写入表 nodes…」整体回滚，
	// 与「畸形输入=400 并点名行」口径不一致。
	seenIdentity := make(map[string]int, len(rows))
	for index, row := range rows {
		line := fmt.Sprintf("备份校验失败：nodes 第 %d 行", index+1)
		rawName, exists := row["name"]
		name, ok := rawName.(string)
		if !exists || !ok || strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s name 必须为非空字符串", line)
		}
		normalized := models.NormalizeClusterNodeName(name)
		if normalized != strings.TrimSpace(name) {
			return fmt.Errorf("%s name 含控制字符或超过 %d 个字符（不支持自动改写）", line, models.ClusterNodeNameMaxLen)
		}
		row["name"] = normalized // 首尾空白归一（restoreTable 直写归一值）
		rawIP, exists := row["ip_address"]
		ip, ok := rawIP.(string)
		if !exists || !ok || strings.TrimSpace(ip) == "" {
			return fmt.Errorf("%s ip_address 必须为非空字符串", line)
		}
		if ip != strings.TrimSpace(ip) || net.ParseIP(ip) == nil {
			return fmt.Errorf("%s ip_address 必须为 IP 地址（不允许端口、路径、空白或控制字符）", line)
		}
		if raw, exists := row["access_url"]; exists && raw != nil {
			accessURL, ok := raw.(string)
			if !ok {
				return fmt.Errorf("%s access_url 必须为字符串", line)
			}
			if err := models.ValidateClusterAccessURL(accessURL); err != nil {
				return fmt.Errorf("%s access_url 无效：%w", line, err)
			}
		}
		if raw, exists := row["id"]; exists && raw != nil {
			if id, ok := backupInteger(raw); !ok || id <= 0 {
				return fmt.Errorf("%s id 必须为正整数", line)
			}
		}
		if raw, exists := row["port"]; exists && raw != nil {
			port, ok := backupInteger(raw)
			if !ok || port < 1 || port > 65535 {
				return fmt.Errorf("%s port 必须是 1-65535 的整数", line)
			}
		}
		portValue := int64(8000) // schema DEFAULT 8000
		if raw, exists := row["port"]; exists && raw != nil {
			if port, ok := backupInteger(raw); ok {
				portValue = int64(port)
			}
		}
		identity := fmt.Sprintf("%s:%d", ip, portValue)
		if firstLine, dup := seenIdentity[identity]; dup {
			return fmt.Errorf("%s 与第 %d 行身份重复（%s），nodes 表要求 (ip_address, port) 唯一", line, firstLine, identity)
		}
		seenIdentity[identity] = index + 1
		if raw, exists := row["sync_interval"]; exists && raw != nil {
			interval, ok := backupInteger(raw)
			if !ok || interval < 1 || interval > 86400 {
				return fmt.Errorf("%s sync_interval 必须是 1-86400 的整数", line)
			}
		}
		for _, item := range []struct {
			key    string
			lo, hi float64
			name   string
		}{
			{"server_map_lat", -90, 90, "站点纬度"},
			{"server_map_lon", -180, 180, "站点经度"},
		} {
			raw, exists := row[item.key]
			if !exists || raw == nil {
				continue
			}
			value, ok := backupFloat(raw)
			if !ok {
				return fmt.Errorf("%s %s必须为数值", line, item.name)
			}
			if value < item.lo || value > item.hi {
				return fmt.Errorf("%s %s必须在 %g 到 %g 之间", line, item.name, item.lo, item.hi)
			}
		}
		if raw, exists := row["protocol"]; exists && raw != nil {
			protocol, ok := raw.(string)
			if !ok {
				return fmt.Errorf("%s protocol 必须为字符串", line)
			}
			switch protocol {
			case "http", "https":
			case "":
				row["protocol"] = "http" // schema DEFAULT 语义归一
			default:
				return fmt.Errorf("%s protocol 仅支持 http/https，实际 %q", line, protocol)
			}
		}
		if raw, exists := row["mode"]; exists && raw != nil {
			mode, ok := raw.(string)
			if !ok {
				return fmt.Errorf("%s mode 必须为字符串", line)
			}
			switch mode {
			case "slave":
			case "master":
				// 节点模式列由注册路径独占写入（RegisterNode 恒写 slave），
				// nodes 表只登记从节点；巡检按 mode='slave' 过滤。放行 master
				// 行会让该节点永久退出离线/滞后判定（节点列表仍展示、上报仍
				// 被接受），故行级门直接点名拒绝，不做静默改写。
				return fmt.Errorf("%s mode=master 不受支持（nodes 只登记从节点，模式由注册路径写入）", line)
			case "":
				row["mode"] = "slave" // schema DEFAULT 语义归一
			default:
				return fmt.Errorf("%s mode 仅支持 slave，实际 %q", line, mode)
			}
		}
		if raw, exists := row["cluster_token_hash"]; exists && raw != nil {
			if _, ok := raw.(string); !ok {
				return fmt.Errorf("%s cluster_token_hash 必须为字符串或 null", line)
			}
		}
	}
	return nil
}

// validateV2BackupUserRows：users 行级「可登录凭据」门。恢复路径（restoreTable）
// 原样直插 password_hash / mfa_secret / auth_provider，行级门是登录可用性的
// 唯一提前判据——不可登录的管理员一旦落库，导入事务又会递增
// password_version 吊销全部会话，面板将永久锁死（只能改库恢复）。
//
// 口径为「最低可用门」而非 bcrypt 严格门：OIDC JIT 行必须持有空哈希，
// 防止混合身份行经密码登录取得 OIDC 会话声明并绕过本地 MFA 写门。
func validateV2BackupUserRows(rows []map[string]any) error {
	for index, row := range rows {
		line := fmt.Sprintf("备份校验失败：users 第 %d 行", index+1)
		username, ok := row["username"].(string)
		if !ok || strings.TrimSpace(username) == "" {
			return fmt.Errorf("%s username 必须为非空字符串", line)
		}
		if username != strings.TrimSpace(username) || strings.ContainsFunc(username, unicode.IsControl) {
			return fmt.Errorf("%s username 不能含首尾空白或控制字符", line)
		}
		if raw, exists := row["role"]; exists && raw != nil {
			role, ok := raw.(string)
			if !ok || (role != "admin" && role != "user") {
				return fmt.Errorf("%s role 仅支持 admin 或 user", line)
			}
		}
		provider := backupString(row["auth_provider"])
		switch provider {
		case "", "local":
			if backupString(row["password_hash"]) == "" {
				return fmt.Errorf("%s 本地用户的 password_hash 不能为空（该账号将无法登录）", line)
			}
		case "oidc":
			if backupString(row["password_hash"]) != "" {
				return fmt.Errorf("%s OIDC 用户的 password_hash 必须为空（不得携带本地密码凭据）", line)
			}
			if strings.TrimSpace(backupString(row["oidc_subject"])) == "" || strings.TrimSpace(backupString(row["oidc_issuer"])) == "" {
				return fmt.Errorf("%s OIDC 用户必须同时携带 oidc_subject 与 oidc_issuer（缺一无法登录）", line)
			}
		default:
			return fmt.Errorf("%s auth_provider 仅支持 local 或 oidc，实际 %q", line, provider)
		}
		if backupBooleanEnabled(row["mfa_enabled"]) && strings.TrimSpace(backupString(row["mfa_secret"])) == "" {
			return fmt.Errorf("%s 已启用 MFA 但 mfa_secret 为空（该账号将无法完成登录）", line)
		}
	}
	return nil
}

// backupUserLoginCapable 判定备份行是否为「可登录」账号（管理员可用性门用）：
// local 需非空 password_hash，oidc 需空密码哈希及完整 subject+issuer；启用 MFA
// 的行还需非空密钥，否则登录恒卡在 MFA 校验。
func backupUserLoginCapable(user map[string]any) bool {
	if backupBooleanEnabled(user["mfa_enabled"]) && strings.TrimSpace(backupString(user["mfa_secret"])) == "" {
		return false
	}
	switch backupString(user["auth_provider"]) {
	case "oidc":
		return backupString(user["password_hash"]) == "" &&
			strings.TrimSpace(backupString(user["oidc_subject"])) != "" &&
			strings.TrimSpace(backupString(user["oidc_issuer"])) != ""
	default:
		return backupString(user["password_hash"]) != ""
	}
}

// validateV2BackupRows 行级门（布尔类型/白名单/凭证），必须在
// sections 过滤之后执行：未选分类的坏行不误拒整包，选中分类照常
// 严格校验。checksum 已在 verifyBackupIntegrity 对全量计算。
func validateV2BackupRows(ctx context.Context, database *sql.DB, backup configBackup) error {
	// 自定义规则行级验证（保存侧同款约束）。
	if rows, ok := backup.Tables["security_custom_rules"]; ok {
		if err := validateImportedSecurityCustomRules(rows); err != nil {
			return err
		}
	}
	// 威胁情报库（v2.3.x）：内置只读三源——备份携带种子集合外的源行
	// （伪造源 URL）一律响亮拒绝，防备份通道注入任意下载地址。
	if rows, ok := backup.Tables["security_threat_sources"]; ok {
		if err := validateImportedThreatSources(rows); err != nil {
			return err
		}
	}
	// 爬虫地址库：仅允许四个内置官方源，拒绝伪造下载地址。
	if rows, ok := backup.Tables["security_crawler_sources"]; ok {
		if err := validateImportedCrawlerSources(rows); err != nil {
			return err
		}
	}
	// nodes 行级类型/必填/范围门——必须在
	// sanitizeNodeRowsForRestore（prepareV2BackupSkips）之后执行，此时瞬态列
	// 已删除、pending 语义已归一，本门只面对落库候选形态。
	if rows, ok := backup.Tables["nodes"]; ok {
		if err := validateV2BackupNodeRows(rows); err != nil {
			return err
		}
	}
	// users 行级「可登录凭据」门——管理员可用性门（verifyBackupIntegrity）只
	// 能证明存在启用管理员；空哈希/空 MFA 密钥/缺 OIDC 身份的账号导入后
	// 全站会话已吊销且无人可登录（面板永久锁死，需改库恢复）。本门按行点名：
	//   - local（含缺省 auth_provider）必须携带非空 password_hash；
	//   - oidc 必须同时携带 oidc_subject 与 oidc_issuer（登录按三元组命中身份行）；
	//   - mfa_enabled=1 必须有非空 mfa_secret（否则登录恒卡在 MFA 校验）。
	// 不做 bcrypt 形态严格门：OIDC JIT 行合法持有空哈希，历史/第三方导出的
	// 占位哈希亦不构成「不可登录」以外的数据风险（本级只堵登录失效）。
	if rows, ok := backup.Tables["users"]; ok {
		if err := validateV2BackupUserRows(rows); err != nil {
			return err
		}
	}
	// 布尔列类型门须在 normalizeBackupBooleanNulls 之后（NULL 已归一
	// 为 0/1 数值，不会被误判）、逐行校验之前（字符串布尔先行 400，不再进入下游
	// backupBooleanEnabled 读取链）。
	if err := validateV2BackupBooleanTypes(backup); err != nil {
		return err
	}
	// api_keys.mcp_ip_whitelist 行级门——与时间门同位：畸形白名单落库后该 Key
	// 每次请求都在认证中间件解析失败返回 500（fail-closed 但永久 500）。
	if rows, ok := backup.Tables["api_keys"]; ok {
		if err := validateV2BackupMCPIPWhitelist(rows); err != nil {
			return err
		}
	}
	// 时间列空串/不可解析文本门——必须在写入前拦下，
	// 否则导入后 users/lb_rules/cert_jobs/path_rules 的 raw time 扫描每次 500。
	if err := validateV2BackupTimestamps(backup.Tables); err != nil {
		return err
	}
	// 数值列类型门与布尔/时间门同位：文本形态落库后保留 TEXT 存储类，读侧
	// raw int/int64 扫描（MFA 时间步/证书任务重试计数）持续 500 且无自愈路径。
	if err := validateV2BackupIntegerTypes(ctx, database, backup.Tables); err != nil {
		return err
	}
	const invalidCredentialsMsg = "备份包含无效的凭证格式（ca_providers.credentials / certificate_configs.dns_credentials 需为 JSON 对象）"
	for _, provider := range backup.Tables["ca_providers"] {
		providerName := backupString(provider["provider"])
		rawCredentials := backupString(provider["credentials"])
		if rawCredentials != "" {
			if err := validateCredentialsJSONObject(rawCredentials); err != nil {
				return errors.New(invalidCredentialsMsg)
			}
		}
		if providerName == "" {
			// legacy/占位行：无 provider 即无专属语义，保持放行。
		} else {
			// provider 白名单与 directory_url 官方常量
			// 覆写,与保存/更新侧同口径。
			switch providerName {
			case services.ProviderLetsEncrypt:
				provider["directory_url"] = services.LetsEncryptDirectoryURL
			case services.ProviderZeroSSL:
				provider["directory_url"] = services.ZeroSSLDirectoryURL
			default:
				return fmt.Errorf("备份包含无效的 CA 提供商类型: %s（必须为 %s 或 %s）", providerName, services.ProviderLetsEncrypt, services.ProviderZeroSSL)
			}

			if providerName == services.ProviderLetsEncrypt {
				trimmed := strings.TrimSpace(rawCredentials)
				if trimmed != "" && trimmed != "{}" {
					return fmt.Errorf("备份包含无效的 Let's Encrypt 配置：凭证必须为空")
				}
				if trimmed == "" {
					provider["credentials"] = ""
				}
			} else if rawCredentials != "" {
				var credentials models.CAProviderCredentials
				if err := json.Unmarshal([]byte(rawCredentials), &credentials); err != nil {
					return errors.New(invalidCredentialsMsg)
				}
			}
		}
		for _, limit := range []struct {
			key       string
			min       int
			max       int
			tooLow    error
			tooHigh   error
			normalize func(int) int
		}{
			{
				key: "max_concurrent", min: 0, max: 100,
				tooLow:  services.ErrCAProviderMaxConcurrentTooLow,
				tooHigh: services.ErrCAProviderMaxConcurrentTooHigh,
				// 与写侧 UpdateCAProvider 同一归一：0=「未设置」→默认值。
				normalize: services.NormalizeCAProviderMaxConcurrent,
			},
			{
				key: "min_interval_ms", min: 0, max: 60000,
				tooLow:  services.ErrCAProviderMinIntervalTooLow,
				tooHigh: services.ErrCAProviderMinIntervalTooHigh,
				// 默认值单源在 db.DefaultCAProviderMinIntervalMS：导入原样落库 0
				// 会让列表/集群快照显示 0，而队列闸门按默认值执行（同一行两种
				// 口径）。负值属备份垃圾，显性拒绝而非静默归一。
				normalize: services.NormalizeCAProviderMinIntervalMS,
			},
		} {
			raw, exists := provider[limit.key]
			if !exists || raw == nil {
				continue
			}
			value, ok := backupInteger(raw)
			if !ok {
				return fmt.Errorf("备份的 ca_providers.%s 必须为整数", limit.key)
			}
			if value < limit.min {
				return fmt.Errorf("备份的 ca_providers.%s 低于下限: %w", limit.key, limit.tooLow)
			}
			if value > limit.max {
				return fmt.Errorf("备份的 ca_providers.%s 超出上限: %w", limit.key, limit.tooHigh)
			}
			provider[limit.key] = int64(limit.normalize(value))
		}
	}
	for _, certCfg := range backup.Tables["certificate_configs"] {
		rawCredentials := backupString(certCfg["dns_credentials"])
		if err := validateCredentialsJSONObject(rawCredentials); err != nil {
			return errors.New(invalidCredentialsMsg)
		}
		providerName := backupString(certCfg["dns_provider"])
		if providerName == "" {
			continue // legacy 空 provider：无专属字段契约可校验
		}
		provider, ok := dnsproviders.Get(providerName)
		if !ok {
			return fmt.Errorf("备份包含未知的 DNS 提供商: %s", providerName)
		}
		if rawCredentials == "" {
			continue // legacy 空凭证：保持原样，仅在保存时补全
		}
		credentials := map[string]string{}
		if err := json.Unmarshal([]byte(rawCredentials), &credentials); err != nil {
			return errors.New(invalidCredentialsMsg)
		}
		if len(credentials) == 0 {
			return fmt.Errorf("备份的 DNS 提供商 %s 凭证不能为空对象", providerName)
		}
		if _, hasMode := credentials["mode"]; !hasMode {
			// 旧版本凭证形状（无 mode 判别字段）保持兼容；非空对象不改变
			// 既有保存语义，下一编辑保存时由前端/provider 归一。
			continue
		}
		if _, err := provider.BuildCredentialsJSON(credentials); err != nil {
			return fmt.Errorf("备份的 DNS 提供商凭证无效: %w", err)
		}
	}
	// 主键/唯一键预检——脏备份的键冲突必须在校验期以 400 点名表与键退出；
	// 落到 restoreTable 直插时只会以 500「写入表 …」整体回滚。
	if err := validateBackupUniqueKeys(backup.Tables); err != nil {
		return err
	}
	return nil
}

// backupPartialUniqueKeyPredicates 部分唯一索引的谓词单源：SQLite 唯一索引
// 只约束满足 WHERE 的行，导入预检必须按同一谓词圈定参与比对的行。
var backupPartialUniqueKeyPredicates = map[string]func(map[string]any) bool{
	// security_ip_lists(name) WHERE system=1（内含系统名单同名唯一）。
	"u_security_ip_lists_system_name": func(row map[string]any) bool {
		return backupBooleanEnabled(row["system"])
	},
	// users(oidc_issuer, oidc_subject) WHERE auth_provider='oidc' AND oidc_subject<>''。
	"u_oidc_identity": func(row map[string]any) bool {
		return backupString(row["auth_provider"]) == "oidc" && backupString(row["oidc_subject"]) != ""
	},
}

// backupUniqueKeySpec 一条参与预检的键约束（主键或唯一索引）。
type backupUniqueKeySpec struct {
	label     string
	columns   []string
	predicate func(map[string]any) bool
}

// validateBackupUniqueKeys 按实际 schema 派生的主键/唯一键做导入前预检：
// 重复行在 restoreTable 直插时只会以 500「写入表 …」整体回滚，此处以 400
// 点名表/行/键退出，与 nodes 的 (ip_address,port) 行门同口径。
//
// 键集从 PRAGMA 派生（新增表/键自动覆盖，不形成逐表手写清单）；部分唯一索引
// 按 backupPartialUniqueKeyPredicates 谓词过滤，未注册谓词的部分索引跳过
// （保守不误拒）；含 NULL/缺列的行按 SQLite 语义不参与唯一性比对。
func validateBackupUniqueKeys(tables map[string][]map[string]any) error {
	if db.DB == nil {
		return nil
	}
	for _, table := range configBackupTables {
		rows, carried := tables[table]
		if !carried || len(rows) < 2 {
			continue
		}
		specs, err := backupUniqueKeySpecs(table)
		if err != nil {
			return err
		}
		for _, spec := range specs {
			seen := make(map[string]int, len(rows))
			for index, row := range rows {
				if spec.predicate != nil && !spec.predicate(row) {
					continue
				}
				key, ok := backupUniqueKeyValue(table, row, spec.columns)
				if !ok {
					continue
				}
				if previous, duplicate := seen[key]; duplicate {
					return fmt.Errorf("备份校验失败：%s 第 %d 行与第 %d 行 %s 重复（导入会触发唯一约束）",
						table, index+1, previous+1, spec.label)
				}
				seen[key] = index
			}
		}
	}
	return nil
}

// backupUniqueKeySpecs 读取表的键约束：主键列（PRAGMA table_info 的 pk 序号）
// 与唯一索引（PRAGMA index_list unique=1；部分索引带 partial=1）。
func backupUniqueKeySpecs(table string) ([]backupUniqueKeySpec, error) {
	specs := make([]backupUniqueKeySpec, 0, 3)
	primaryKey, err := backupPrimaryKeyColumns(table)
	if err != nil {
		return nil, err
	}
	if len(primaryKey) > 0 {
		specs = append(specs, backupUniqueKeySpec{
			label:   "主键 " + strings.Join(primaryKey, "+"),
			columns: primaryKey,
		})
	}
	indexRows, err := db.DB.Query(`PRAGMA index_list('` + table + `')`)
	if err != nil {
		return nil, fmt.Errorf("读取表 %s 索引: %w", table, err)
	}
	type indexEntry struct {
		name    string
		unique  int
		partial int
	}
	entries := make([]indexEntry, 0, 2)
	for indexRows.Next() {
		var (
			seq    int
			entry  indexEntry
			origin string
		)
		if err := indexRows.Scan(&seq, &entry.name, &entry.unique, &origin, &entry.partial); err != nil {
			return nil, fmt.Errorf("读取表 %s 索引: %w", table, err)
		}
		if entry.unique == 1 {
			entries = append(entries, entry)
		}
	}
	if err := indexRows.Err(); err != nil {
		_ = indexRows.Close()
		return nil, fmt.Errorf("读取表 %s 索引: %w", table, err)
	}
	// 显式关闭后再发起 index_info 查询——单连接池下未关闭的 Rows 会占住连接。
	if err := indexRows.Close(); err != nil {
		return nil, fmt.Errorf("读取表 %s 索引: %w", table, err)
	}
	for _, entry := range entries {
		var predicate func(map[string]any) bool
		if entry.partial == 1 {
			// 未注册谓词的部分索引无法判定圈定范围——跳过（宁可不报，不误拒）。
			predicate = backupPartialUniqueKeyPredicates[entry.name]
			if predicate == nil {
				continue
			}
		}
		columns, err := backupIndexColumns(entry.name)
		if err != nil {
			return nil, err
		}
		if len(columns) == 0 {
			continue // 表达式索引（index_info 无列名）不在预检范围
		}
		specs = append(specs, backupUniqueKeySpec{
			label:     "唯一键 " + strings.Join(columns, "+"),
			columns:   columns,
			predicate: predicate,
		})
	}
	return specs, nil
}

// backupPrimaryKeyColumns 返回主键列（按 pk 序号排列）；无主键返回 nil。
func backupPrimaryKeyColumns(table string) ([]string, error) {
	rows, err := db.DB.Query(`PRAGMA table_info('` + table + `')`)
	if err != nil {
		return nil, fmt.Errorf("读取表 %s 结构: %w", table, err)
	}
	defer rows.Close()
	ordered := map[int]string{}
	maxOrdinal := 0
	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal any
			pkOrdinal  int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pkOrdinal); err != nil {
			return nil, fmt.Errorf("读取表 %s 结构: %w", table, err)
		}
		if pkOrdinal > 0 {
			ordered[pkOrdinal] = name
			if pkOrdinal > maxOrdinal {
				maxOrdinal = pkOrdinal
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取表 %s 结构: %w", table, err)
	}
	if maxOrdinal == 0 {
		return nil, nil
	}
	columns := make([]string, 0, maxOrdinal)
	for ordinal := 1; ordinal <= maxOrdinal; ordinal++ {
		name, ok := ordered[ordinal]
		if !ok {
			return nil, nil // 异常主键序（部分列缺失）→ 预检放弃，不猜
		}
		columns = append(columns, name)
	}
	return columns, nil
}

// backupIndexColumns 返回唯一索引的列名（顺序按索引定义）。
func backupIndexColumns(indexName string) ([]string, error) {
	rows, err := db.DB.Query(`PRAGMA index_info('` + indexName + `')`)
	if err != nil {
		return nil, fmt.Errorf("读取索引 %s 列: %w", indexName, err)
	}
	defer rows.Close()
	type columnEntry struct {
		seqno int
		name  string
	}
	ordered := map[int]string{}
	maxSeqno := -1
	for rows.Next() {
		var seqno, cid int
		var name sql.NullString
		if err := rows.Scan(&seqno, &cid, &name); err != nil {
			return nil, fmt.Errorf("读取索引 %s 列: %w", indexName, err)
		}
		if !name.Valid {
			return nil, nil // 表达式索引列无名字
		}
		ordered[seqno] = name.String
		if seqno > maxSeqno {
			maxSeqno = seqno
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取索引 %s 列: %w", indexName, err)
	}
	columns := make([]string, 0, maxSeqno+1)
	for seqno := 0; seqno <= maxSeqno; seqno++ {
		name, ok := ordered[seqno]
		if !ok {
			return nil, nil
		}
		columns = append(columns, name)
	}
	return columns, nil
}

// backupUniqueNumericKey 把整数形字符串编成与数值同域的键：INTEGER 亲和性
// 会把 "5" 与 5 落成同一存储值，键值分域会让该形态逃过预检、直到直插时以
// 500「写入表 …」整体回滚——预检的声明目标正是把键冲突降到可修正的 400。
func backupUniqueNumericKey(value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return "", false
	}
	return "n:" + strconv.FormatInt(parsed, 10), true
}

// backupUniqueKeyValue 生成唯一性比对键：任一列 NULL/缺列即返回 false
// （SQLite 唯一索引对含 NULL 的行不作约束）；未知形态交给类型门，不猜。
// 整数形字符串与整数/整数值浮点统一编入数值域（"5" 与 5 在库中同值）；
// 布尔同样编入数值域（true/false 落库为 INTEGER 1/0——normalizeBackupBooleanValue
// 与 SQLite 亲和性都归一到该形态；分成独立 "b:" 域会把 true 与 1 判成不重复，
// 键冲突漏到事务内以 UNIQUE 约束 500 回滚，而预检的声明目标正是 400）。
func backupUniqueKeyValue(table string, row map[string]any, columns []string) (string, bool) {
	parts := make([]string, len(columns))
	for index, column := range columns {
		value, exists := row[column]
		if !exists || value == nil {
			return "", false
		}
		switch typed := value.(type) {
		case string:
			// cert_jobs 在唯一键预检之后才做域名规范化；若这里仍按原始
			// 字符串判重，A.com/a.com 会漏到 restoreTable 才撞唯一索引 500。
			// 只对参与键计算的本地副本规范化，不改写校验和已覆盖的行数据。
			if table == "cert_jobs" && column == "domain" {
				if canonical, err := services.CanonicalACMEDomains(typed); err == nil {
					typed = canonical
				}
			}
			if numeric, ok := backupUniqueNumericKey(typed); ok {
				parts[index] = numeric
				continue
			}
			parts[index] = "s:" + typed
		case bool:
			if typed {
				parts[index] = "n:1"
			} else {
				parts[index] = "n:0"
			}
		case float64:
			if typed == math.Trunc(typed) && typed >= math.MinInt64 && typed <= math.MaxInt64 {
				parts[index] = "n:" + strconv.FormatInt(int64(typed), 10)
				continue
			}
			parts[index] = "f:" + strconv.FormatFloat(typed, 'g', -1, 64)
		case int:
			parts[index] = "n:" + strconv.Itoa(typed)
		case int64:
			parts[index] = "n:" + strconv.FormatInt(typed, 10)
		default:
			return "", false
		}
	}
	return strings.Join(parts, "\x00"), true
}

// validateV2BackupRules 逐行校验备份 lb_rules 的端口与特性（校验侧保守口径）。
// 必须在 skipEmptyDomainHTTPRules 之后执行：空域名行无论端口/特性
// 是否非法都一律软跳过，不被逐行校验先行整包 400。
//
// portGate 为可选端口门——生产预览/导入传入
// (*Handlers).validateRuleListenPortForSave，叠加本进程实际面板监听口与
// Caddy admin 口（自定义端口部署下，导入含管理端口的规则会抢占管理面）；
// 省略时退回包级默认管理口（无进程上下文的纯校验/测试夹具）。
func validateV2BackupRules(tables map[string][]map[string]any, portGates ...func(string, int) error) error {
	validatePort := validateRuleListenPort
	if len(portGates) > 0 && portGates[0] != nil {
		validatePort = portGates[0]
	}
	rows := tables["lb_rules"]
	// 逐规则全表扫描 upstreams/path_rules 与
	// 每规则两次 live 查页在 2000 规则×10000 上游规模下是 2×10⁷ 级比较——改为
	// 一次预计算（与冲突矩阵分桶预计算同型）。谓词与语义逐项保持不变。
	enabledHostsByRule := make(map[string][]string, len(rows))
	for _, row := range tables["upstreams"] {
		if !backupBooleanEnabled(row["enabled"]) {
			continue
		}
		ruleID := backupString(row["rule_id"])
		if ruleID == "" {
			continue
		}
		enabledHostsByRule[ruleID] = append(enabledHostsByRule[ruleID], backupString(row["host"]))
	}
	pathRulesByRule, err := backupPathRulesByRule(tables["path_rules"])
	if err != nil {
		return err
	}
	// 生成式子路由 @id 命名空间保留：规则 ID 取 <另一规则ID>_path_<序号>/_geoip/
	// _redirect 形态时，两条规则拼接出的 @id 相同，Caddy /load 以 duplicate ID
	// 整份拒绝（导入事务回滚）。逐行校验前先收集全量 ID，冲突点名两条规则。
	backupRuleIDs := make([]string, 0, len(rows))
	for _, row := range rows {
		backupRuleIDs = append(backupRuleIDs, backupString(row["caddy_id"]))
	}
	// 阶段拦截页引用/状态码必须与保存侧同门。页存在性按
	// 「备份携带 security_block_pages 则备份行、缺席则 live」解析
	// 同口径）——备份行才是导入后的真实数据。
	blockPageRows, carriedBlockPages := tables["security_block_pages"]
	backupPageIDs := make(map[int]bool, len(blockPageRows))
	if carriedBlockPages {
		for _, row := range blockPageRows {
			if id, ok := backupInteger(row["id"]); ok {
				backupPageIDs[int(id)] = true
			}
		}
	}
	livePageIDs := map[int]bool{}
	if !carriedBlockPages && db.DB != nil {
		// 页表是小表（管理员配置的拦截页），一次读入即可——此前每条规则×2
		// 次 live EXISTS 查询。
		pageRows, err := db.DB.Query("SELECT id FROM security_block_pages")
		if err != nil {
			return fmt.Errorf("读取拦截页视图失败: %w", err)
		}
		for pageRows.Next() {
			var id int
			if err := pageRows.Scan(&id); err != nil {
				_ = pageRows.Close()
				return fmt.Errorf("读取拦截页视图失败: %w", err)
			}
			livePageIDs[id] = true
		}
		if err := pageRows.Err(); err != nil {
			_ = pageRows.Close()
			return fmt.Errorf("读取拦截页视图失败: %w", err)
		}
		_ = pageRows.Close()
	}
	stagePageExists := func(id int) (bool, error) {
		if carriedBlockPages {
			return backupPageIDs[id], nil
		}
		return livePageIDs[id], nil
	}
	for index, rule := range rows {
		if err := validateRuleTextLengths(backupString(rule["name"]), backupString(rule["description"])); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
		protocol, _ := rule["protocol"].(string)
		listenPort, validPort := backupInteger(rule["listen_port"])
		if !validPort {
			return fmt.Errorf("规则 #%d：监听端口必须为整数", index+1)
		}
		if err := validatePort(protocol, listenPort); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
		// （用户裁决：系统不支持通配符域名）：创建/更新（rules.go CanonicalDomains）、
		// 启用/复制（:2136/:2327 同门）、v1 导入（isValidDomain 拒绝 '*'）均拒绝通配与非法
		// 形态，v2 导入是最后一个能把它带入运行库的门（此前仅 acme_dns 行有
		// ValidateACMEDomainsForIssuance 门，manual/无 TLS 行的域名原样落库）。与保存侧 :609/:613
		// 同口径——http 规则域名必须非空且可规范化（idna 拒绝 '*'、IP 形态、超长段），
		// 否则整包 400：通配域名进入 lb_rules 后安全事件归属映射对该规则整体跳过
		// （db.CanonicalDomains 报错即 continue），Enable/Update 又被同门卡死成
		// 「永不启用」的死行。空 protocol 与 skipEmptyDomainHTTPRules 的
		// 同口径按 HTTP 处理（空域名行已在先前环节软跳过，此处非空域名必须可规范化）。
		// 合法值同时钳回规范形式（小写/punycode/去重），与行级钳制哲学一致。
		if protocol == "http" || protocol == "" {
			canonicalDomain, err := db.CanonicalDomains(backupString(rule["domain"]))
			if err != nil {
				return fmt.Errorf("规则 #%d（%s）：域名格式无效（系统不支持通配符域名）: %w", index+1, backupString(rule["name"]), err)
			}
			rule["domain"] = canonicalDomain
		}
		// 补传 ListenPort/EnableTLS/TLSHTTPRedirect 等字段，启用
		// validateRuleFeatures 的 80 端口 + TLS 跳转自环检查（此前仅端口/策略校验，
		// 备份中自环规则校验放行并导入成功，生成自环 Location）；行内有
		// custom_routes_enabled/path_rules 信息时一并传入，保持与保存路径同口径。
		// 禁用规则不参与渲染（caddy.go WHERE enabled=1），其
		// 80+TLS+跳转组合无运行时影响；若仍按启用态校验会整包拒绝，导出→导入
		// 往返断裂（与 v1 路径自环规则软跳过口径一致），故禁用行将
		// EnableTLS/TLSHTTPRedirect 置 false，其余字段校验保留。
		enabled := backupRuleEnabled(rule)
		// 注入 DynamicDNS + 启用上游计数——此前两者恒零值，保存侧
		// validateRuleFeatures 的「动态上游单启用」门在导入链
		// 恒不触发：启用行延迟到 Caddy 阶段以整包 400 形态失败（fail-closed 但
		// 与同文件逐规则点名口径不一致），禁用行入库后成「永不启用」死行。
		// 与保存/Duplicate 链同门（DuplicateRule 为此专门 hydrate 上游计数，
		// rule_features.go 注释）。
		ruleID := backupString(rule["caddy_id"])
		// caddy_id 必须满足证书路径字母表（非空、≤64、
		// 仅小写字母/数字/_/-）——含点等形态会在证书物化阶段失败回滚，且与
		// 日志文件名净化键碰撞；导入期 fail-fast 点名。
		if !services.ValidCertRuleID(ruleID) {
			return fmt.Errorf("规则 #%d：caddy_id %q 含证书路径不支持的字符（仅允许小写字母、数字、_ 与 -，长度 1-64）", index+1, ruleID)
		}
		if conflict := services.RuleIDNamespaceConflict(ruleID, backupRuleIDs); conflict != "" {
			return fmt.Errorf("规则 #%d：caddy_id %q 与规则 %q 的子路由 @id 命名空间冲突（子路由 @id 形如 <规则ID>_path_<序号>/_geoip/_redirect），请修改其中一个 ID", index+1, ruleID, conflict)
		}
		// 阶段拦截页四列（仅生效 HTTP 规则；TCP 行残留属已裁定豁免）。
		if enabled && (protocol == "http" || protocol == "") {
			for _, stage := range []struct{ label, idKey, statusKey string }{
				{"阶段 1（IP 访问控制/地域拦截）", "block_page_stage1_id", "block_page_stage1_status"},
				{"阶段 3（WAF）", "block_page_stage3_id", "block_page_stage3_status"},
			} {
				pageID, _ := backupInteger(rule[stage.idKey])
				status, _ := backupInteger(rule[stage.statusKey])
				if err := validateStageBlockPageRefWith(int(pageID), int(status), stage.label, stagePageExists); err != nil {
					return fmt.Errorf("规则 #%d：%w", index+1, err)
				}
			}
		}
		enabledHosts := enabledHostsByRule[ruleID]
		// 补 EnableDnsServer/DnsServer——此前恒零值，
		// validateRuleFeatures 的 门（TCP 携带 DNS 服务发现配置即拒）
		// 在导入链恒不触发，TCP+dns_server 脏行原样落库成死配置（保存侧
		// 已拒、协议切换零值化、存量迁移已清空）。HTTP 规则合法 dns 字段
		// 不受影响（该门仅 TCP 分支消费）。
		input := ruleFeatureInput{
			Protocol:                   protocol,
			Strategy:                   backupString(rule["strategy"]),
			NTLMCompatible:             backupInt(rule["ntlm_compatible"]),
			DynamicDNS:                 backupBooleanEnabled(rule["dynamic_dns"]),
			EnableDnsServer:            backupBooleanEnabled(rule["enable_dns_server"]),
			DnsServer:                  backupString(rule["dns_server"]),
			EnabledUpstreamCount:       len(enabledHosts),
			EnabledUpstreamHosts:       enabledHosts,
			DnsFamily:                  backupString(rule["dns_family"]),
			ListenPort:                 listenPort,
			EnableTLS:                  backupBooleanEnabled(rule["enable_tls"]) && enabled,
			TLSHTTPRedirect:            backupBooleanEnabled(rule["tls_http_redirect"]) && enabled,
			CustomRoutesEnabled:        backupBooleanEnabled(rule["custom_routes_enabled"]),
			ProxyDialTimeout:           backupInt(rule["proxy_dial_timeout"]),
			ProxyResponseHeaderTimeout: backupInt(rule["proxy_response_header_timeout"]),
			ProxyReadTimeout:           backupInt(rule["proxy_read_timeout"]),
			ProxyWriteTimeout:          backupInt(rule["proxy_write_timeout"]),
			ProxyStreamTimeout:         backupInt(rule["proxy_stream_timeout"]),
			ProxyFlushInterval:         backupInt(rule["proxy_flush_interval"]),
			ProxyStreamCloseDelay:      backupInt(rule["proxy_stream_close_delay"]),
			EnableCompress:             backupBooleanEnabled(rule["enable_compress"]),
			CompressTypes:              backupString(rule["compress_types"]),
		}
		if pathRules, found := pathRulesByRule[ruleID]; found {
			// 保存路径先 normalizePathRules（TrimSpace）再校验
			// （createRuleFeatures/updateRuleFeatures），备份路径此前直传导致手造备份
			// 含前导空格路径时 validateRuleFeatures 的 HasPrefix("/") 误拒绝。
			input.PathRules = normalizePathRules(pathRules)
		}
		// 规则级请求体上限与保存侧同值域；超过 Coraza 1GiB 上限拒绝导入，
		// 其余历史非法形态仍按既有兼容规则归一。
		if rawBody, exists := rule["request_body_max_size_mb"]; exists {
			if n, integerShape := backupInteger(rawBody); integerShape && n > maxRequestBodySizeMB {
				return fmt.Errorf("request_body_max_size_mb 必须在 0-%d MB 之间", maxRequestBodySizeMB)
			}
			rule["request_body_max_size_mb"] = normalizeBackupRequestBodyMB(rawBody, 0, 0)
		}
		// 库值唯一真相（批 1+2）：健康检查族/tcp_try_interval 为类型①值型列，
		// 旧备份可携带 0（渲染兜底时代合法落库）——导入门写回归治理默认，
		// restoreTable 直写后库恒有效（渲染层已零兜底）；缺失键由
		// backupTableNullDefaults 的 NULL→默认通道承担，两通道落同一默认值。
		for key, def := range map[string]int64{
			"health_check_interval":            int64(db.DefaultHealthCheckInterval),
			"health_check_timeout":             int64(db.DefaultHealthCheckTimeout),
			"health_check_unhealthy_threshold": int64(db.DefaultHealthCheckUnhealthyThreshold),
			"health_check_healthy_threshold":   int64(db.DefaultHealthCheckHealthyThreshold),
			"tcp_try_interval":                 int64(db.DefaultTCPTryInterval),
		} {
			if n, ok := backupInteger(rule[key]); !ok || n <= 0 {
				rule[key] = def
			}
		}
		// 输入必须在上述归一之后补全：健康/重试字段若沿用构造时的零值，
		// validateRuleFeatures 的保存侧边界会在导入链恒不可达。
		input.HealthCheckInterval = backupInt(rule["health_check_interval"])
		input.HealthCheckTimeout = backupInt(rule["health_check_timeout"])
		input.TCPHealthCheckPort = backupInt(rule["tcp_health_check_port"])
		input.TCPTryDuration = backupInt(rule["tcp_try_duration"])
		input.TCPTryInterval = backupInt(rule["tcp_try_interval"])
		input.UpstreamForceHTTP1 = backupInt(rule["upstream_force_http1"])
		input.UpstreamKeepaliveTimeout = backupInt(rule["upstream_keepalive_timeout"])
		if err := validateRuleHostHeader(backupString(rule["host_header"])); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
		// 健康检查路径与保存侧同口径：仅在主动健康检查启用时有渲染消费，
		// 未启用属死字段——存量死组合（enable=0 + path 无前导 /）不得让整包
		// 导入被无关校验拒绝。不改写备份数据（导入是存量行还原）。
		if backupBooleanEnabled(rule["enable_active_health_check"]) {
			if err := validateRuleHealthCheckPath(backupString(rule["health_check_path"])); err != nil {
				return fmt.Errorf("规则 #%d：%w", index+1, err)
			}
		}
		if err := validateDnsServerShape(backupString(rule["dns_server"])); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
		// dynamic_dns+dns_family 走与保存侧同口径的
		// 枚举校验——此前 input 不带 DnsFamily，垃圾值原样落库后渲染端 versions
		// 双 false 解析退化为双栈（fail-open 方向）。合法值含 "both"：UI 双选
		// IPv4+IPv6 时前端写 'both'（Rules.vue:2415）、渲染端 case "both" 双栈
		// （caddy.go）——初版漏列 both 会把启用双栈的规则导出物整包误拒，
		// 导出→导入往返断裂。
		dynamicDNS := backupBooleanEnabled(rule["dynamic_dns"])
		if dynamicDNS {
			dnsFamily := backupString(rule["dns_family"])
			if dnsFamily != "" && dnsFamily != "ipv4" && dnsFamily != "ipv6" && dnsFamily != "both" {
				return fmt.Errorf("规则 #%d：dns_family 必须为 ipv4、ipv6 或 both（当前 %q）", index+1, dnsFamily)
			}
		}
		if err := validateRuleFeatures(input); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
	}
	return nil
}

// validateV2BackupTLSShape 校验最终处于启用态的 HTTP+TLS 规则的证书形态：
// tls_source 白名单、manual 证书材料、acme_dns 域名合法性与 ACME 引用。
// 与 cert_jobs 不变量同序——必须在 disableV2RuleConflicts 之后执行，
// 将被冲突自动置禁用的规则不投入运行，不参与运行态形态校验（此前垃圾
// tls_source 的冲突行会把可自愈备份整包 400，与 cert_jobs 豁免哲学不一致）。
// 导入/预览双路径同序调用（ImportConfigBackup / ValidateConfigImport）。
// 启用 TLS 的行先做 tls_source 白名单——保存侧（rules.go）
// 与启用侧（rule_features.go validateStoredRuleConfig）均对非 manual/acme_dns
// 400，导入此前是唯一能放行该形态的门：”/垃圾值行两个分支都不命中、整包
// 放行，渲染侧 availableCerts 仅认 manual/acme_dns → 无证书、无
// tls_connection_policies → TLS 端口明文服务（与启用的 acme_dns 行同类缺口）。
// 启用的手动 TLS 规则必须携带证书与私钥（镜像保存/启用侧
// rule_features.go validateStoredRuleConfig 口径），拒绝时点名规则。
// 导入此前是唯一能绕过该校验的门：无证书规则不在 availableCerts 内 → 无
// TLS policy → TLS 端口明文服务，且 autohttps.disable_certificates 阻止
// Caddy 自动签发自愈。
// 原「硬入口」validateV2BackupTLSShape（软入口的
// 零参数包装）生产零调用（生产一律 validateV2BackupTLSShapeSoft），作为第二
// 调用链误导维护者——已移入 _test.go（既有用例同包消费）。
//
// validateV2BackupTLSShapeSoft 支持软降级:softLiveACMERefs=true
// 时,「备份不含 cert 表、按 live 解析」失败的 ACME 引用不整包 400,计入返回
// 的悬挂数(调用方降级警告,与预检对称;导入/预览双路径同序)。
// 返回 (悬挂数, 硬错误)。
func validateV2BackupTLSShapeSoft(tables map[string][]map[string]any, softLiveACMERefs bool) (int, error) {
	acmeDangling := 0
	// ACME 引用解析索引（惰性构建，每个表最多
	// 一次读取；此前每条 ACME 规则全表扫 certificate_configs/ca_providers
	// 或逐 id 打库）。
	acmeRefs := newACMEImportRefIndex(tables)
	for index, rule := range tables["lb_rules"] {
		protocol, _ := rule["protocol"].(string)
		// （传播通道钳制）：TCP 规则不终结入站 TLS，携带 enable_tls=1 +
		// 空 manual 证书的行（源自旧版 v1 导入的导出物）会让该规则任何编辑恒 400
		// 且 UI 无自救路径——静默钳制为关闭 TLS 并清空证书材料（与 dns_family
		// 等行级钳制同哲学，不因存量形态拒绝整包导入）。
		if protocol == "tcp" && backupBooleanEnabled(rule["enable_tls"]) {
			rule["enable_tls"] = 0
			rule["tls_cert"], rule["tls_key"] = "", ""
		}
		if !backupRuleEnabled(rule) || protocol != "http" || !backupBooleanEnabled(rule["enable_tls"]) {
			continue
		}
		tlsSource := backupString(rule["tls_source"])
		if tlsSource != "manual" && tlsSource != "acme_dns" {
			return 0, fmt.Errorf("规则 #%d（%s）：启用 TLS 时必须选择证书来源（manual 或 acme_dns）", index+1, backupString(rule["name"]))
		}
		if tlsSource == "manual" &&
			(strings.TrimSpace(backupString(rule["tls_cert"])) == "" || strings.TrimSpace(backupString(rule["tls_key"])) == "") {
			return 0, fmt.Errorf("规则 #%d（%s）：手动证书模式下必须提供 TLS 证书和私钥", index+1, backupString(rule["name"]))
		}
		// 启用的 acme_dns 行按 validateRuleACMEReferences 同口径校验——
		// acme_config_id=0/悬挂/已禁用与 ca_provider_id 悬挂/已禁用均整包 400。
		// 导入把规则已启用地带入运行态，EnableRule 门拦不住这条路径；
		// 坏行导入后 TLS 端口明文服务且签发必败，与手动证书缺材料的拒绝理由同型。
		if tlsSource == "acme_dns" {
			// 导入侧补 ACME 域名合法性门（与保存侧 rules.go / 启用侧
			// createOrRequeueCertJob 同口径，单域名或根域+www）——此前导入链无任何
			// ValidateACMEDomainsForIssuance 等价校验，手造备份可带入 "a.com,b.org" 形态，
			// 运行期 certJobRuleApplicable 严格规范化失败 → 续签永久断链且
			// TLS 端口明文服务。
			if err := services.ValidateACMEDomainsForIssuance(backupString(rule["domain"])); err != nil {
				return 0, fmt.Errorf("规则 #%d（%s）：%w", index+1, backupString(rule["name"]), err)
			}
			if err := acmeRefs.validate(rule); err != nil {
				// 「备份不含 cert 表、按 live 解析」失败在软降级方向
				// (导规则不导系统数据、备份从未携带 cert 表)计入悬挂数,不整包 400。
				var liveRefErr *acmeLiveRefUnresolvedError
				if softLiveACMERefs && errors.As(err, &liveRefErr) {
					acmeDangling++
					continue
				}
				return 0, fmt.Errorf("规则 #%d（%s）：%w", index+1, backupString(rule["name"]), err)
			}
		}
	}
	return acmeDangling, nil
}

// certJobShape 是启用 ACME 规则不变量判定所需的证书任务行形状。
type certJobShape struct {
	domain string
	status string
	pem    bool
}

// certJobShapesByRule 把证书任务行按 rule_id 归组（跳过 disabled 行）。
// writeBackCanonical=true 时把规范域名写回行载荷——持久化与运行期查找共用
// 排序规范形式；非法形态留给启用不变量按既有错误口径拒绝，禁用/历史行保持
// 原容错语义。
func certJobShapesByRule(jobs []map[string]any, writeBackCanonical bool) map[string][]certJobShape {
	jobsByRule := make(map[string][]certJobShape)
	for _, job := range jobs {
		domain := backupString(job["domain"])
		if canonical, err := services.CanonicalACMEDomains(domain); err == nil {
			if writeBackCanonical {
				job["domain"] = canonical
			}
			domain = canonical
		}
		if backupString(job["status"]) == "disabled" {
			continue
		}
		if ruleID, ok := job["rule_id"].(string); ok && ruleID != "" {
			status := backupString(job["status"])
			// issued/downloaded 必须带可用证书材料；空 PEM 的 issued 会让
			// 启用规则在 TLS 端口无证书运行，且 EnableRule/续期都按到期日
			// 跳过补签。
			hasMaterial := backupString(job["cert_pem"]) != "" && backupString(job["key_pem"]) != ""
			jobsByRule[ruleID] = append(jobsByRule[ruleID], certJobShape{domain: domain, status: status, pem: hasMaterial})
		}
	}
	return jobsByRule
}

// loadLiveCertJobShapes 读取本地 cert_jobs 行（形状与备份行一致）。
// 备份未携带该表时「缺席=保留本地」（deleteOrder 对缺席表直接跳过），
// 因此导入后的任务行就是本地行——启用 ACME 规则的不变量必须针对它校验，
// 按空集硬拒会让「仅规则」的部分备份被误判为缺少任务行。
// q 是读取面：初检传 *sql.DB，导入锁内复核传 *sql.Tx——同一不变量必须按
// 「导入后视图」求值，锁外读到的行在初检→加锁窗口内可能已被并发删除。
func loadLiveCertJobShapes(ctx context.Context, q certJobRowQueryer) ([]map[string]any, error) {
	rows, err := q.QueryContext(ctx, `SELECT rule_id, domain, COALESCE(status,''), COALESCE(cert_pem,''), COALESCE(key_pem,'') FROM cert_jobs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var ruleID, domain, status, certPEM, keyPEM string
		if err := rows.Scan(&ruleID, &domain, &status, &certPEM, &keyPEM); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"rule_id": ruleID, "domain": domain, "status": status,
			"cert_pem": certPEM, "key_pem": keyPEM,
		})
	}
	return out, rows.Err()
}

// certJobRowQueryer 是证书任务统计的查询面：导入锁内传 *sql.Tx，预览传
// *sql.DB——同一判据两条路径共用，避免预览与导入对同一备份给出不同告警。
// QueryRowContext 是 CA 提供商存在性/启用态读取面：必须走同一 querier（此
// 前走 db.DB 直读另一条连接，导入路径读到的不是事务视图）。
type certJobRowQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// certJobProviderDanglingCounts 统计「导入后会参与续签」的证书任务中 CA 提供商
// 在导入后不可解析的行数，并按消费侧语义分两档：
//   - disabled：提供商行存在但 enabled=0 → loadCAProvider 硬失败，任务落
//     failed 终态（显式选择不会静默改派）；
//   - missing：提供商行不存在 → loadCAProvider 回落首个启用提供商并成功续签
//     （自愈，不应断言「续签将失败」）。
//
// 计数面收敛为「非终态 ∧ 规则为启用 ACME」——此前对 cert_jobs 全表（含
// failed/disabled 残留行与非 ACME 规则的孤儿行）计数，告警系统性偏高。
// 规则源按备份是否携带 lb_rules 二选一：随包时用备份行（导入后视图），
// 否则 JOIN live——此前恒读调用时的库视图，导入路径在 deleteOrder 之前执行，
// 「导入前规则态」与「导入后任务行」组合会漏计/多计。
func certJobProviderDanglingCounts(ctx context.Context, q certJobRowQueryer, tables map[string][]map[string]any, sectionTables map[string]bool) (disabled, missing int, err error) {
	if _, certJobsCarried := tables["cert_jobs"]; certJobsCarried {
		return 0, 0, nil
	}
	if !sectionTables["ca_providers"] && !sectionTables["certificate_configs"] {
		return 0, 0, nil
	}
	// 「备份是否携带 lb_rules」按键存在判定（与 validateBackupRuleReferences /
	// acmeRefResolvablePostImport / 链内缺席回填同口径）：键在但为空数组=导入后
	// 无规则（applicableRules 空集→计数 0），不得回退去读 live 规则——live 行
	// 在导入全量替换后会被删除，告警与实际结果相反。
	_, rulesCarried := tables["lb_rules"]
	query := `
		SELECT j.rule_id, COALESCE(j.ca_provider_id,0) FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE COALESCE(j.ca_provider_id,0) <> 0
		  AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns'
		  AND j.status NOT IN ('failed','disabled')`
	if rulesCarried {
		query = `
		SELECT rule_id, COALESCE(ca_provider_id,0) FROM cert_jobs
		WHERE COALESCE(ca_provider_id,0) <> 0 AND status NOT IN ('failed','disabled')`
	}
	rows, qerr := q.QueryContext(ctx, query)
	if qerr != nil {
		return 0, 0, qerr
	}
	defer rows.Close()
	// 备份随包时的「导入后启用 ACME 规则集」（JOIN 形态已由 SQL 过滤）。
	var applicableRules map[string]bool
	if rulesCarried {
		applicableRules = make(map[string]bool, len(tables["lb_rules"]))
		for _, rule := range tables["lb_rules"] {
			protocol, _ := rule["protocol"].(string)
			if backupRuleEnabled(rule) && protocol == "http" &&
				backupBooleanEnabled(rule["enable_tls"]) && backupString(rule["tls_source"]) == "acme_dns" {
				applicableRules[backupString(rule["caddy_id"])] = true
			}
		}
	}
	state := make(map[int]struct{ exists, enabled bool })
	for rows.Next() {
		var ruleID string
		var providerID int
		if scanErr := rows.Scan(&ruleID, &providerID); scanErr != nil {
			return 0, 0, scanErr
		}
		if applicableRules != nil && !applicableRules[ruleID] {
			continue
		}
		st, seen := state[providerID]
		if !seen {
			if _, carried := tables["ca_providers"]; carried {
				row, found := backupRowByID(tables, "ca_providers", providerID)
				st = struct{ exists, enabled bool }{exists: found, enabled: found && backupRowEnabled(row)}
			} else {
				var enabled int
				liveErr := q.QueryRowContext(ctx, "SELECT COALESCE(enabled,0) FROM ca_providers WHERE id=?", providerID).Scan(&enabled)
				if liveErr != nil && !errors.Is(liveErr, sql.ErrNoRows) {
					return 0, 0, liveErr
				}
				st = struct{ exists, enabled bool }{exists: liveErr == nil, enabled: liveErr == nil && enabled == 1}
			}
			state[providerID] = st
		}
		switch {
		case !st.exists:
			missing++
		case !st.enabled:
			disabled++
		}
	}
	return disabled, missing, rows.Err()
}

// certJobProviderDanglingWarnings 两档悬挂告警的文案单源（预览 warnings 与
// 导入审计共用）——此前预览/导入各写一份近似文案，措辞与口径随时可能分叉。
func certJobProviderDanglingWarnings(disabled, missing int) []string {
	warnings := make([]string, 0, 2)
	if disabled > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 个证书任务的 CA 提供商已禁用——续签将失败（任务转 failed 终态），请补齐 CA 提供商或在证书页手工重试", disabled))
	}
	if missing > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 个证书任务引用的 CA 提供商已不存在——续签时将回落首个启用提供商（自愈），如需保持原提供商请补齐", missing))
	}
	return warnings
}

// validateV2BackupCertJobs 校验最终处于启用态的 acme_dns 规则携带域名匹配的
// 证书任务行。备份携带 cert_jobs 时导入为全量替换（deleteOrder 清光后仅插入
// 备份行），缺失即导入后续签永久断链且无信号（周期路径只遍历已存在的任务行，
// 不补建）；备份未携带该表时「缺席=保留本地」，校验对象是本地行（见
// loadLiveCertJobShapes）。必须在 disableV2RuleConflicts 之后执行——将被冲突
// 自动置禁用的规则不投入运行，不参与运行态不变量。不变量还须校验 job.domain
// 与规则域名一致（canonical/reversed 双形式，与 certjobs.go 续签扫描
// lower+replace 口径同型）——错域残留行只凭存在性放行后，续签扫描按
// rule_id+domain 匹配永不命中，断链同果。域比较两侧均须可规范化——
// canonicalACMEDomainForJobLookup 的原串回退是查询侧良性 miss 语义（视为无任务），
// 用于校验侧会把 "a.com,b.org" 等不可规范化形态假放行；与运行期
// certJobRuleApplicable 的严格 CanonicalACMEDomains 全等语义对齐，不可规范化即
// 响亮拒绝。两侧规范化后大小写/空白/顺序变体天然归一（排序规范形式）。
//
// 初检（*sql.DB 视图）与导入锁内复核（*sql.Tx 视图）共用本实现——「备份未
// 携带 cert_jobs」分支读的是 live 行，锁外初检与加锁之间并发删除任务行会让
// 初检结论失效，锁内必须按事务视图重跑（见 revalidateImportLiveDependencies）。
func validateV2BackupCertJobs(tables map[string][]map[string]any) ([]string, error) {
	return validateV2BackupCertJobsWithQuerier(context.Background(), tables, db.DB)
}

// validateV2BackupCertJobsWithQuerier 允许调用方指定 live 读取面。
func validateV2BackupCertJobsWithQuerier(ctx context.Context, tables map[string][]map[string]any, q certJobRowQueryer) ([]string, error) {
	var warnings []string
	// cert_jobs.ca_provider_id 参与导入期可解析性校验（与 lb_rules 的
	// ACME 引用同一索引语义：备份表优先、缺表回退 live）：悬挂/已禁用的
	// 提供商会让非终态任务首次入队即落 failed 终态（loadCAProvider 对
	// 「存在但禁用」显性报错）——归一为 0（跟随默认，loadCAProvider 的
	// 既有默认语义承担）并显式警告，不整包拒绝。
	var providerRefs *acmeImportRefIndex
	danglingProviderJobs := 0
	for _, job := range tables["cert_jobs"] {
		caProviderID, ok := backupInteger(job["ca_provider_id"])
		if !ok || caProviderID == 0 {
			continue
		}
		if providerRefs == nil {
			providerRefs = newACMEImportRefIndex(tables)
		}
		providerOK, err := providerRefs.resolveEnabled("ca_providers", caProviderID)
		if err != nil {
			return nil, fmt.Errorf("校验证书任务 CA 提供商失败: %w", err)
		}
		if !providerOK {
			job["ca_provider_id"] = 0
			danglingProviderJobs++
		}
	}
	if danglingProviderJobs > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 条证书任务引用的 CA 提供商不存在或已禁用，已归一为跟随默认提供商（原引用会导致任务首次入队即失败）", danglingProviderJobs))
	}
	jobRows, carried := tables["cert_jobs"]
	if !carried {
		// 「缺席=保留本地」：deleteOrder/insertOrder 对缺席表直接 continue，
		// live 任务行在导入后仍然有效，校验对象必须是它们而不是空集。
		liveRows, err := loadLiveCertJobShapes(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("读取本地证书任务用于启用 ACME 规则校验: %w", err)
		}
		jobRows = liveRows
	}
	jobsByRule := certJobShapesByRule(jobRows, carried)
	for index, rule := range tables["lb_rules"] {
		protocol, _ := rule["protocol"].(string)
		if !backupRuleEnabled(rule) || protocol != "http" ||
			!backupBooleanEnabled(rule["enable_tls"]) || backupString(rule["tls_source"]) != "acme_dns" {
			continue
		}
		jobDomains := jobsByRule[backupString(rule["caddy_id"])]
		if len(jobDomains) == 0 {
			if !carried {
				return nil, fmt.Errorf("规则 #%d（%s）：启用的 ACME 规则缺少证书签发任务（备份未携带 cert_jobs 表，导入将保留本地任务行，而本地也没有该规则的非 disabled 任务），导入后将无法自动续签", index+1, backupString(rule["name"]))
			}
			return nil, fmt.Errorf("规则 #%d（%s）：启用的 ACME 规则缺少证书签发任务（导入后的 cert_jobs 无非 disabled 行），导入后将无法自动续签", index+1, backupString(rule["name"]))
		}
		canonical, err := services.CanonicalACMEDomains(backupString(rule["domain"]))
		if err != nil {
			return nil, fmt.Errorf("规则 #%d（%s）：ACME 域名不合法（仅支持单域名或根域+www 二级域名），导入后将无法自动续签", index+1, backupString(rule["name"]))
		}
		matched := false
		emptyMaterial := false
		for _, job := range jobDomains {
			jobCanonical, err := services.CanonicalACMEDomains(job.domain)
			if err != nil {
				return nil, fmt.Errorf("规则 #%d（%s）：证书任务域名 %q 不合法（仅支持单域名或根域+www 二级域名），导入后将无法自动续签", index+1, backupString(rule["name"]), job.domain)
			}
			if jobCanonical != canonical {
				continue
			}
			if (job.status == "issued" || job.status == "downloaded") && !job.pem {
				emptyMaterial = true
				continue
			}
			matched = true
			break
		}
		if !matched {
			if emptyMaterial {
				return nil, fmt.Errorf("规则 #%d（%s）：证书任务标记为已签发但证书材料为空，导入后 TLS 端口将无证书可用", index+1, backupString(rule["name"]))
			}
			return nil, fmt.Errorf("规则 #%d（%s）：证书任务域名与规则域名不一致，导入后将无法自动续签", index+1, backupString(rule["name"]))
		}
		allowed := map[string]struct{}{canonical: {}}
		for _, d := range strings.Split(canonical, ",") {
			allowed[strings.TrimSpace(d)] = struct{}{}
		}
		for _, job := range jobDomains {
			jobCanonical, _ := services.CanonicalACMEDomains(job.domain)
			if _, ok := allowed[jobCanonical]; !ok {
				return nil, fmt.Errorf("规则 #%d（%s）：证书任务包含规则当前域名之外的旧域行 %q，导入后任务视图与对账无法收敛", index+1, backupString(rule["name"]), job.domain)
			}
		}
	}
	return warnings, nil
}

// backupSystemIPListNames 内置（system=1）名单名全集：威胁库三源内置名单 ∪
// 自动封禁预置名单 ∪ 四个爬虫官方名单。导入的
// system 行名称白名单与配额口径共用本注册表（此前任意 system=1 行都被当作
// 「内置名单」计数并登记，管理员随后无法编辑/删除——UI 宣称由任务维护，
// 实际上只能再导入或改库）。
func backupSystemIPListNames() map[string]bool {
	names := make(map[string]bool)
	for _, seed := range db.ThreatSystemLists() {
		names[seed.Name] = true
	}
	names[services.AutobanPresetListName] = true
	for _, name := range services.CrawlerSystemListNames() {
		names[name] = true
	}
	return names
}

// validateImportedSystemIPLists 仅接受种子名称集合的 system=1 行，其余 400
// 点名（威胁/爬虫源行本身已走名称白名单，名单行此前是唯一开口）。
func validateImportedSystemIPLists(rows []map[string]any) error {
	allowed := backupSystemIPListNames()
	for index, row := range rows {
		if !backupBooleanEnabled(row["system"]) {
			continue
		}
		name := backupString(row["name"])
		if !allowed[name] {
			return fmt.Errorf("安全 IP 列表 #%d：内置名单名称 %q 不受支持（内置名单由威胁情报库、爬虫地址库与自动封禁任务维护）", index+1, name)
		}
	}
	return nil
}

// validateBackupIPListQuota 以导入后最终状态校验名单配额：200 是用户可管理
// 名单额度（与 ipListMaxGlobalCount 一致），服务端系统名单在提交后自动补齐
// （威胁三源/自动封禁经 db.SeedSystemIPLists；爬虫四源经
// services.RestoreCrawlerIPListSnapshot 逐引擎补种），不应占用用户额度；最终
// 总行数再以「200 + 固定系统种子数」封顶，防止备份注入任意数量的 system 行
// 绕过资源门。
func validateBackupIPListQuota(rows []map[string]any) error {
	systemNames := backupSystemIPListNames()
	presentSystem := make(map[string]bool, len(systemNames))
	userCount := 0
	for _, row := range rows {
		if backupBooleanEnabled(row["system"]) {
			presentSystem[backupString(row["name"])] = true
		} else {
			userCount++
		}
	}
	if userCount > ipListMaxGlobalCount {
		return fmt.Errorf("IP 地址列表（用户创建）数量已达上限（%d 个）", ipListMaxGlobalCount)
	}
	missingSystem := 0
	for name := range systemNames {
		if !presentSystem[name] {
			missingSystem++
		}
	}
	finalTotal := len(rows) + missingSystem
	finalCeiling := ipListMaxGlobalCount + len(systemNames)
	if finalTotal > finalCeiling {
		return fmt.Errorf("导入后 IP 地址列表总数（含系统名单补播）%d 超过上限（%d 个）", finalTotal, finalCeiling)
	}
	return nil
}

// validateV2BackupSecurityPolicies 按保存侧同口径（validateAndNormalizeCRSField，
// security.go）校验备份 security_policies 的 crs_rule_groups/crs_excluded_rules，
// 拒绝时点名策略；合法行同步写回归一值（空串→"[]"），保持列形状一致。
// 原始值存在且非字符串（数字/布尔/数组，null/缺省除外）直接拒绝——
// 保存侧 JSON 绑定对同值 400，导入侧不得经 backupString 静默归一放行。
// 旧版备份可能携带 "941" 式组号或含空白的条目——导入原样落库后
// REQUEST-9<code>-*.conf glob 零匹配，blocking 模式静默无任何 CRS 规则生效。
// （v2.3.0）：security_ip_lists 随备份全量替换——先校验列表行 entries
// 形状（JSON 数组文本）并收集 id 集，再校验策略 ip_acl_list_refs/
// ip_whitelist_refs（整数数组 JSON 文本，逐 id 对备份内列表解析——导入为
// 全量替换，备份行才是导入后的真实数据，与 validateBackupRuleReferences
// 的备份内解析哲学一致；悬挂引用会让引用展开静默跳过，UI 宣称的引用
// 控制静默失效）。
// crsTreeReplaced=true 表示本次导入同时替换 CRS 规则树（历史
// 审计）：此时组号/规则 ID 的存在性基准应是导入后的规则树，而 live 索引代表
// 导入前那一代——按 live 校验会误拒可自愈的旧备份、或反向放行落地后空 Include。
// 该场景降级为形状校验 + 调用方警告。
func validateV2BackupSecurityPolicies(tables map[string][]map[string]any, crsTreeReplaced bool) error {
	if db.DB == nil {
		return validateV2BackupSecurityPoliciesWithQuerier(context.Background(), tables, crsTreeReplaced, nil)
	}
	return validateV2BackupSecurityPoliciesWithQuerier(context.Background(), tables, crsTreeReplaced, db.DB)
}

// validateV2BackupSecurityPoliciesWithQuerier 允许初检（*sql.DB）与导入锁内
// 复核（*sql.Tx）共享同一引用解析实现。备份未携带 IP 名单表时，该表在导入后
// 保持本地现状，因此 refs/allow 生效集必须回退到 querier 的 live 视图。
func validateV2BackupSecurityPoliciesWithQuerier(ctx context.Context, tables map[string][]map[string]any, crsTreeReplaced bool, querier tableQuerier) error {
	ipListIDs := make(map[int]struct{}, len(tables["security_ip_lists"]))
	ipListValues := make(map[int][]string, len(tables["security_ip_lists"]))
	builtinIPLists := map[int64]string{}
	if _, carried := tables["security_ip_lists"]; !carried && len(tables["security_policies"]) > 0 && querier != nil {
		rows, err := querier.QueryContext(ctx, `SELECT id,COALESCE(name,''),COALESCE(system,0),COALESCE(entries,'[]') FROM security_ip_lists`)
		if err != nil {
			// live 回退读失败属基础设施故障（锁/IO）：映射 500，不回 400。
			return importInfraReadFailure(fmt.Errorf("读取安全策略引用的 IP 列表失败: %w", err))
		}
		for rows.Next() {
			var id int
			var name, entriesText string
			var system int
			if err := rows.Scan(&id, &name, &system, &entriesText); err != nil {
				rows.Close()
				return importInfraReadFailure(fmt.Errorf("读取安全策略引用的 IP 列表失败: %w", err))
			}
			ipListIDs[id] = struct{}{}
			if system == 1 {
				builtinIPLists[int64(id)] = name
			}
			var entries []struct {
				Value string `json:"value"`
			}
			if json.Unmarshal([]byte(entriesText), &entries) == nil {
				for _, entry := range entries {
					if entry.Value != "" && validIPOrCIDR(entry.Value) {
						ipListValues[id] = append(ipListValues[id], entry.Value)
					}
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return importInfraReadFailure(fmt.Errorf("读取安全策略引用的 IP 列表失败: %w", err))
		}
		rows.Close()
	}
	if err := validateBackupIPListQuota(tables["security_ip_lists"]); err != nil {
		return err
	}
	if err := validateImportedSystemIPLists(tables["security_ip_lists"]); err != nil {
		return err
	}
	for index, row := range tables["security_ip_lists"] {
		if err := validateIPListMetadataShape(backupString(row["name"]), backupString(row["description"]), backupString(row["category"])); err != nil {
			return fmt.Errorf("安全 IP 列表 #%d：%w", index+1, err)
		}
		var listID int
		if id, ok := backupInteger(row["id"]); ok {
			ipListIDs[id] = struct{}{}
			listID = id
			if id > 0 && backupBooleanEnabled(row["system"]) {
				builtinIPLists[int64(id)] = backupString(row["name"])
			}
		}
		if rawEntries, exists := row["entries"]; exists && rawEntries != nil {
			entries, ok := rawEntries.(string)
			if !ok {
				return fmt.Errorf("安全 IP 列表 #%d：entries 需为 JSON 数组文本，实际类型 %T", index+1, rawEntries)
			}
			// 空串视同 '[]'（restoreTable 的 NULL 归一同值兜底），仅非空
			// 文本要求可解析为 JSON 数组。
			if strings.TrimSpace(entries) != "" {
				var parsed []any
				if err := json.Unmarshal([]byte(entries), &parsed); err != nil {
					return fmt.Errorf("安全 IP 列表 #%d：entries 需为 JSON 数组文本", index+1)
				}
				// 导入路径按 validIPOrCIDR 口径校验
				// 条目值——zone 形态(fe80::1%eth0)等无效条目落库后 coraza
				// @ipMatch 静默丢弃(零留痕),必须拒绝。
				for ei, entry := range parsed {
					entryMap, ok := entry.(map[string]any)
					if !ok {
						// 非对象成员(裸字符串等)
						// 不得 continue 放行——zone 形态可藏其中,同保存侧口径拒绝。
						return fmt.Errorf("安全 IP 列表 #%d 条目 #%d：需为 JSON 对象（含 value 字段），实际类型 %T", index+1, ei+1, entry)
					}
					if rawRemark, exists := entryMap["remark"]; exists && rawRemark != nil {
						remark, ok := rawRemark.(string)
						if !ok {
							return fmt.Errorf("安全 IP 列表 #%d 条目 #%d：备注需为字符串", index+1, ei+1)
						}
						if len([]rune(remark)) > ipListMaxRemarkLength {
							return fmt.Errorf("安全 IP 列表 #%d 条目 #%d：备注长度不能超过 %d 个字符", index+1, ei+1, ipListMaxRemarkLength)
						}
						// 备注控制字符门与保存侧单源（hasIPListRemarkControlChar）：
						// 导出件按「值 空格 备注」逐行组文本，备注里的换行会造出
						// 伪条目（再当名单导入即误加 IP），制表/回车同样破坏行结构；
						// 且该行随后任何保存/改名都会被保存侧同一门 400 挡死。
						if hasIPListRemarkControlChar(remark) {
							return fmt.Errorf("安全 IP 列表 #%d 条目 #%d：备注不能包含换行、制表符或其他控制字符", index+1, ei+1)
						}
					}
					// 缺/空/非 string value 同样拒绝——
					// 非 string value(数字等)落库后渲染侧 Unmarshal 整表静默丢弃
					// (securityiplists.go:120/177),fail-open。
					value, ok := entryMap["value"].(string)
					if !ok || value == "" {
						return fmt.Errorf("安全 IP 列表 #%d 条目 #%d：缺 value 字段或为空/非字符串", index+1, ei+1)
					}
					if !validIPOrCIDR(value) {
						return fmt.Errorf("安全 IP 列表 #%d 条目 #%d：无效 IP/CIDR 值 %q（zone 形态如 fe80::1%%eth0 不被 WAF 引擎支持）", index+1, ei+1, value)
					}
					if listID > 0 {
						ipListValues[listID] = append(ipListValues[listID], value)
					}
				}
				// 条目上限按**生效**条目计（到期条目在保存/渲染/追加侧都不占
				// 名额）：备份可携带旧版本遗留的到期残留，按原始长度计会把合法
				// 备份拒之门外——与 validateIPListShape / 手动追加同口径。
				typedEntries := make([]models.IPListEntry, 0, len(parsed))
				for _, entry := range parsed {
					entryMap, ok := entry.(map[string]any)
					if !ok {
						continue
					}
					expiresAt, _ := entryMap["expires_at"].(string)
					typedEntries = append(typedEntries, models.IPListEntry{ExpiresAt: expiresAt})
				}
				if len(services.AutobanActiveEntries(typedEntries)) > ipListMaxEntries {
					return fmt.Errorf("安全 IP 列表 #%d：生效条目数量不能超过 %d 条（已到期条目不计入）", index+1, ipListMaxEntries)
				}
			}
		}
	}
	// 策略 custom_rules 的 ID 数组必须引用存在的自定义
	// 规则——悬空 ID 在发射阶段被静默跳过（WAF 静默削弱），保存侧已 400。
	// 存在性基准与 ip_lists refs 同哲学：备份携带表则按备份行集合，缺席则
	// 按 live 集合（旧 JSON 备份只带策略行的形态）。
	customRuleIDs := make(map[int]struct{}, len(tables["security_custom_rules"]))
	if rows, carried := tables["security_custom_rules"]; carried {
		for _, row := range rows {
			if id, ok := backupInteger(row["id"]); ok {
				customRuleIDs[int(id)] = struct{}{}
			}
		}
	} else if querier != nil {
		rows, qerr := querier.QueryContext(ctx, `SELECT id FROM security_custom_rules`)
		if qerr != nil {
			return fmt.Errorf("校验安全策略引用的自定义规则失败: %v", qerr)
		}
		for rows.Next() {
			var id int
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("校验安全策略引用的自定义规则失败: %v", err)
			}
			customRuleIDs[id] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("校验安全策略引用的自定义规则失败: %v", err)
		}
		rows.Close()
	}
	for index, policy := range tables["security_policies"] {
		name := backupString(policy["name"])
		if utf8.RuneCountInString(name) > securityNameMaxRunes {
			return fmt.Errorf("安全策略 #%d：策略名称不能超过 %d 字符", index+1, securityNameMaxRunes)
		}
		if utf8.RuneCountInString(backupString(policy["description"])) > securityDescriptionMaxRunes {
			return fmt.Errorf("安全策略 #%d（%s）：策略描述不能超过 %d 字符", index+1, name, securityDescriptionMaxRunes)
		}
		// 只校验「字符串形态且可解析为整数数组」的引用（既有形状宽容裁定：
		// 内嵌对象/顶层字符串数组保持原样存储）。
		if rawCR, exists := policy["custom_rules"]; exists && rawCR != nil {
			if crText, ok := rawCR.(string); ok && strings.TrimSpace(crText) != "" {
				var crIDs []int
				if err := json.Unmarshal([]byte(crText), &crIDs); err == nil {
					for _, crID := range crIDs {
						if _, found := customRuleIDs[crID]; !found {
							return fmt.Errorf("安全策略 #%d（%s）：引用了不存在的自定义规则 %d", index+1, name, crID)
						}
					}
				}
			}
		}
		for _, field := range []string{"crs_rule_groups", "crs_excluded_rules"} {
			raw, exists := policy[field]
			if exists && raw != nil {
				if _, ok := raw.(string); !ok {
					return fmt.Errorf("安全策略 #%d（%s）：%s 需为字符串（JSON 数组文本），实际类型 %T", index+1, name, field, raw)
				}
			}
			value := backupString(raw)
			if err := validateAndNormalizeCRSField(field, &value, !crsTreeReplaced); err != nil {
				return fmt.Errorf("安全策略 #%d（%s）：%w", index+1, name, err)
			}
			policy[field] = value
		}
		// 三个枚举字段按 Create 侧口径（security.go CreateSecurityPolicy）
		// 归一/校验。前的旧备份合法携带空串（旧 Create 不归一、列默认 ''），
		// restoreTable 原样落库后发射端仅 allow/deny/绕过 等具名分支产出规则，
		// "" 零产出——启用态 ACL 零强制而 UI 宣称控制已启用（mode/geoip_mode 同型
		// 漂移）。空串/null/缺省归一为默认值；非空值复用保存侧枚举校验拒绝；
		// 非字符串值与同口径拒绝（保存侧 JSON 绑定对同值 400）。
		for _, field := range []string{"mode", "ip_acl_mode", "geoip_mode"} {
			raw, exists := policy[field]
			if exists && raw != nil {
				if _, ok := raw.(string); !ok {
					return fmt.Errorf("安全策略 #%d（%s）：%s 需为字符串，实际类型 %T", index+1, name, field, raw)
				}
			}
		}
		// 429 已剔出保存侧白名单——
		// 导入侧归一为 403,与同格(导入不宽于保存侧),修复前时代
		// 的合法备份不因新白名单硬拒。
		// 库值唯一真相（批 3）：值列导入门归一——旧备份可携带治理前形态
		//（anomaly_threshold=0/NULL/非整数、burst 负值、block_status_code 枚举
		// 外如 429/418），在导入门写回归一值后 restoreTable 直写，库恒有效
		//（渲染层已零兜底/fail-visible）；缺失键由 backupTableNullDefaults 的
		// NULL→默认通道承担（anomaly→5、block→0 省略型）。429 归一为既有
		// 口径的枚举外全集特例。rate_limit_rps 不在此归一：enabled=1 时 rps<1
		// 交由下方既有检查 400 拒绝（写侧同口径，导入不宽于保存侧）。
		if raw, exists := policy["anomaly_threshold"]; exists {
			if n, ok := backupInteger(raw); !ok || n <= 0 {
				policy["anomaly_threshold"] = int64(db.DefaultAnomalyThreshold)
			}
		}
		if raw, exists := policy["rate_limit_burst"]; exists {
			if n, ok := backupInteger(raw); !ok || n < 0 {
				policy["rate_limit_burst"] = int64(0)
			}
		}
		if raw, exists := policy["block_status_code"]; exists {
			if n, ok := backupInteger(raw); !ok || !services.ValidBlockStatusCode(int(n)) {
				policy["block_status_code"] = int64(db.DefaultBlockStatusCode)
			}
		}
		mode := backupString(policy["mode"])
		if mode == "" {
			mode = "off"
		}
		ipACLMode := backupString(policy["ip_acl_mode"])
		if ipACLMode == "" {
			ipACLMode = "deny"
		}
		geoIPMode := backupString(policy["geoip_mode"])
		if geoIPMode == "" {
			geoIPMode = "deny"
		}
		crawlerExempt := backupBooleanEnabled(policy["geoip_crawler_exempt"])
		if err := validatePolicyCrawlerExemption(crawlerExempt, backupString(policy["geoip_crawler_engines"]), geoIPMode); err != nil {
			return fmt.Errorf("安全策略 #%d（%s）：%w", index+1, name, err)
		}
		policy["geoip_crawler_exempt"] = crawlerExemptBool(crawlerExempt, geoIPMode != "" && geoIPMode != "off")
		if err := validateSecurityPolicyEnums(mode, ipACLMode, geoIPMode, 0, 0); err != nil {
			return fmt.Errorf("安全策略 #%d（%s）：%w", index+1, name, err)
		}
		// 策略内联 IP 三字段按保存侧
		// validateIPCIDRList 口径校验——备份导入落库后 coraza @ipMatch
		// 对无效条目静默丢弃,必须拒绝。
		for _, field := range []string{"ip_acl_list", "ip_whitelist", "ip_blacklist"} {
			raw := policy[field]
			// 非字符串类型门——
			// backupString 对非 string 静默归一为 "" 放行,数字/数组形态可绕过。
			if raw != nil {
				if _, ok := raw.(string); !ok {
					return fmt.Errorf("安全策略 #%d（%s）：%s 需为字符串（JSON 数组文本），实际类型 %T", index+1, name, field, raw)
				}
			}
			if str := backupString(raw); str != "" {
				if err := validateIPCIDRList(field, str); err != nil {
					return fmt.Errorf("安全策略 #%d（%s）：%w", index+1, name, err)
				}
			}
		}
		policy["mode"] = mode
		policy["ip_acl_mode"] = ipACLMode
		policy["geoip_mode"] = geoIPMode
		// policy_type 值域门——显式值必须是五枚举之一
		//（models.PolicyType* 单一事实源），未知类型落库会漂移策略页分组与阶段外
		// 字段归一判定。空串/null/缺省放行（restoreTable 导入侧对空行按内容重
		// 推断，InferSnapshotPolicyType 单一事实源）；非字符串形态与三枚举门同
		// 口径拒绝（同型，backupString 不得静默归一）。
		if rawType, exists := policy["policy_type"]; exists && rawType != nil {
			typeStr, ok := rawType.(string)
			if !ok {
				return fmt.Errorf("安全策略 #%d（%s）：policy_type 需为字符串，实际类型 %T", index+1, name, rawType)
			}
			switch typeStr {
			case "", models.PolicyTypeStage0, models.PolicyTypeStage1, models.PolicyTypeStage2, models.PolicyTypeStage3, models.PolicyTypeMixed:
			default:
				return fmt.Errorf("安全策略 #%d（%s）：policy_type 需为 stage0/stage1/stage2/stage3/mixed 之一，实际 %q", index+1, name, typeStr)
			}
		}
		// 导入侧限流形状与保存侧 validateRateLimitShape
		// 同口径——enabled=true 而 rps<=0 时发射分支直接跳过限流 handler，而
		// 汇总/绑定宣称已启用；旧备份（保存侧校验前导出）可携带该形状经导入
		// 复活。与三枚举同哲学：只做拒绝（数值语义无安全默认值可归一）。
		if backupBooleanEnabled(policy["rate_limit_enabled"]) {
			rps, rpsOK := backupInteger(policy["rate_limit_rps"])
			burst, burstOK := backupInteger(policy["rate_limit_burst"])
			if (rpsOK && rps < 1) || (burstOK && burst < 0) || !rpsOK {
				return fmt.Errorf("安全策略 #%d（%s）：启用限流时 rate_limit_rps 必须 ≥1、rate_limit_burst 不能为负", index+1, name)
			}
			// 上界与保存侧同口径——渲染侧 rps*60/rps+burst 的 int64 溢出防线。
			if rps > 1_000_000_000 || burst > 1_000_000_000 {
				return fmt.Errorf("安全策略 #%d（%s）：rate_limit_rps/burst 过大（上限 1000000000）", index+1, name)
			}
		}
		// geoip_countries 形状按保存侧 ValidateGeoIPCountries 同口径
		// （空串/缺省放行——与三枚举的「无值归一」一致；有值则必须是合法 JSON
		// 数组文本且省份可判）。引用块（block_page_id）在备份缺 security_block_pages
		// 表时校验会误拒全量替换导入（表本身可选），保留为运行时 JOIN 语义
		// （悬挂绑定在 JOIN 中不可见、不产出规则——与记录的口径一致）。
		if rawGeo, exists := policy["geoip_countries"]; exists && rawGeo != nil {
			s, ok := rawGeo.(string)
			if !ok {
				return fmt.Errorf("安全策略 #%d（%s）：geoip_countries 需为字符串（JSON 数组文本），实际类型 %T", index+1, name, rawGeo)
			}
			// off 态名单是保留数据（保存侧同口径），仅做形状校验。
			backupGeoIPMode, _ := policy["geoip_mode"].(string)
			if strings.TrimSpace(s) != "" {
				if err := services.ValidateGeoIPCountries(s, backupGeoIPMode); err != nil {
					return fmt.Errorf("安全策略 #%d（%s）：%w", index+1, name, err)
				}
			}
		}
		// refs 两列按保存侧同口径校验——字符串列承载整数数组的 JSON
		// 文本（空串/null/缺省视同 '[]' 放行，写入侧由 restoreTable 归一），
		// 非字符串类型与同口径拒绝。
		// crs_excluded_rules.listRefs 存在性校验——与两 refs 列同口径
		//（"备份内解析哲学"），悬空引用在正常主端不可达（保存 400/删除 409 双门），
		// 但手工编辑/带外改库导出的备份可携带；落库后发射侧静默缩小匹配集。
		var aclRefIDs, wlRefIDs, excludedRefIDs []int64
		if excludedRaw, exists := policy["crs_excluded_rules"]; exists && excludedRaw != nil {
			if excludedStr, ok := excludedRaw.(string); ok && strings.TrimSpace(excludedStr) != "" {
				for _, entry := range services.ParseCRSExcludedRules(excludedStr) {
					for _, refID := range entry.ListRefs {
						excludedRefIDs = append(excludedRefIDs, refID)
						if _, found := ipListIDs[int(refID)]; !found {
							return fmt.Errorf("安全策略 #%d（%s）：crs_excluded_rules 引用了不存在的 IP 列表 %d", index+1, name, refID)
						}
					}
				}
			}
		}
		for _, field := range []string{"ip_acl_list_refs", "ip_whitelist_refs"} {
			raw, exists := policy[field]
			if !exists || raw == nil {
				continue
			}
			refsText, ok := raw.(string)
			if !ok {
				return fmt.Errorf("安全策略 #%d（%s）：%s 需为整数数组的 JSON 文本，实际类型 %T", index+1, name, field, raw)
			}
			if strings.TrimSpace(refsText) == "" {
				continue
			}
			var refs []int
			if err := json.Unmarshal([]byte(refsText), &refs); err != nil {
				return fmt.Errorf("安全策略 #%d（%s）：%s 需为整数数组的 JSON 文本", index+1, name, field)
			}
			ids64 := make([]int64, len(refs))
			for i, id := range refs {
				ids64[i] = int64(id)
				if _, exists := ipListIDs[id]; !exists {
					return fmt.Errorf("安全策略 #%d（%s）：引用了不存在的 IP 列表 %d", index+1, name, id)
				}
			}
			if field == "ip_acl_list_refs" {
				aclRefIDs = ids64
			} else {
				wlRefIDs = ids64
			}
		}
		if message := validateBuiltinIPListRefs(builtinIPLists, aclRefIDs, wlRefIDs, excludedRefIDs, ipACLMode); message != "" {
			return fmt.Errorf("安全策略 #%d（%s）：%s", index+1, name, message)
		}
		// 启用 allow 的导入后生效集必须非空——旧校验只看 refs 个数，
		// 空内联/引用空名单会落库成「allow 但实际放行全部」。这里按备份行实际
		// 条目计算 inline ∪ refs；时间为空/全部到期仍由渲染层恒拒兜底。
		if backupBooleanEnabled(policy["ip_acl_enabled"]) && ipACLMode == "allow" {
			nonEmpty := false
			var inline []string
			if raw := backupString(policy["ip_acl_list"]); strings.TrimSpace(raw) != "" {
				if err := json.Unmarshal([]byte(raw), &inline); err == nil {
					for _, v := range inline {
						if strings.TrimSpace(v) != "" {
							nonEmpty = true
							break
						}
					}
				}
			}
			if !nonEmpty {
				var refs []int
				if raw := backupString(policy["ip_acl_list_refs"]); strings.TrimSpace(raw) != "" {
					_ = json.Unmarshal([]byte(raw), &refs)
				}
				for _, id := range refs {
					if len(ipListValues[id]) > 0 {
						nonEmpty = true
						break
					}
				}
			}
			if !nonEmpty {
				return fmt.Errorf("安全策略 #%d（%s）：启用白名单（allow）但生效 IP 列表为空（内联与引用均无可用于导入的条目）", index+1, name)
			}
		}
	}
	for index, page := range tables["security_block_pages"] {
		name := backupString(page["name"])
		if utf8.RuneCountInString(name) > securityNameMaxRunes {
			return fmt.Errorf("拦截页面 #%d：拦截页面名称不能超过 %d 字符", index+1, securityNameMaxRunes)
		}
		if utf8.RuneCountInString(backupString(page["description"])) > securityDescriptionMaxRunes {
			return fmt.Errorf("拦截页面 #%d（%s）：拦截页面描述不能超过 %d 字符", index+1, name, securityDescriptionMaxRunes)
		}
		if backupBooleanEnabled(page["is_builtin"]) {
			id, idOK := backupInteger(page["id"])
			validIdentity := false
			for _, identity := range builtinBlockPageIdentities {
				if idOK && int(id) == identity.id && name == identity.name {
					validIdentity = true
					break
				}
			}
			if !validIdentity {
				return fmt.Errorf("拦截页面 #%d（%s）：is_builtin 仅允许系统内置页面 9001/9002 及其库存名称", index+1, name)
			}
		}
	}
	return nil
}

// acmeImportRefIndex 导入后视图的 ACME 引用解析索引（历史
// 审计）：按 validateRuleACMEReferences（rule_features.go）同口径按需建立
// certificate_configs / ca_providers 的 id→启用 视图（每个表最多构建一次），
// 逐规则解析 O(1)。引用优先在备份自带表中解析——导入为全量替换（deleteOrder
// 清光 live 的这两张表），备份行才是导入后的真实数据；备份缺该表时回退 live
// 表一次读取（直测/非常规调用场景，及 自此「该 cert 表不参与本次分类
// 导入」的常规场景——sections 过滤前置后，过滤掉的表在 backup.Tables 中缺席，
// live 回退自动等于「过滤后导入表∪live 保留表」正确口径）。配置/提供商行缺
// enabled 键时按表默认值 TRUE 处理（backupRowEnabled 单源口径）。
//
// 惰性构建是语义的一部分：旧逐规则实现只在规则真正引用某表时才触碰该表
// （纯校验夹具无 DB 句柄时，未引用的表不得触发查询）。
type acmeImportRefIndex struct {
	tables   map[string][]map[string]any
	enabled  map[string]map[int]bool
	fromLive map[string]bool
}

func newACMEImportRefIndex(tables map[string][]map[string]any) *acmeImportRefIndex {
	return &acmeImportRefIndex{
		tables:   tables,
		enabled:  map[string]map[int]bool{},
		fromLive: map[string]bool{},
	}
}

// enabledIDs 返回该表在导入后的 id→启用视图（首次访问时构建并缓存）。
func (acmeIndex *acmeImportRefIndex) enabledIDs(table string) (map[int]bool, error) {
	if ids, built := acmeIndex.enabled[table]; built {
		return ids, nil
	}
	ids := map[int]bool{}
	if rows, carried := acmeIndex.tables[table]; carried {
		for _, row := range rows {
			if id, ok := backupInteger(row["id"]); ok {
				ids[id] = backupRowEnabled(row)
			}
		}
	} else {
		acmeIndex.fromLive[table] = true
		label := "校验 DNS 提供商配置失败"
		if table == "ca_providers" {
			label = "校验 CA 提供商失败"
		}
		rows, err := db.DB.Query("SELECT id, COALESCE(enabled,1) FROM " + table)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", label, err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id int
			var enabled bool
			if err := rows.Scan(&id, &enabled); err != nil {
				return nil, fmt.Errorf("%s: %v", label, err)
			}
			ids[id] = enabled
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("%s: %v", label, err)
		}
	}
	acmeIndex.enabled[table] = ids
	return ids, nil
}

func (acmeIndex *acmeImportRefIndex) resolveEnabled(table string, id int) (bool, error) {
	ids, err := acmeIndex.enabledIDs(table)
	if err != nil {
		return false, err
	}
	enabled, found := ids[id]
	return found && enabled, nil
}

// validate 与 validateBackupACMEReferenceIDs 原逐规则实现同序、同文案。
// live 回退解析失败的错误包装为 acmeLiveRefUnresolvedError——分类
// 导入「导规则不导系统数据」且备份从未携带 cert 表时，调用方按对称
// 语义把它降级为悬挂警告；其余错误（备份行解析失败、acme_config_id=0、DB
// 查询失败）维持整包 400。
func (acmeIndex *acmeImportRefIndex) validate(rule map[string]any) error {
	acmeConfigID, ok := backupInteger(rule["acme_config_id"])
	if !ok || acmeConfigID == 0 {
		return errors.New("使用 ACME 签发时必须选择 DNS 提供商配置")
	}
	configOK, err := acmeIndex.resolveEnabled("certificate_configs", acmeConfigID)
	if err != nil {
		return err
	}
	if !configOK {
		err := errors.New("选择的 DNS 提供商配置不存在或已禁用")
		if acmeIndex.fromLive["certificate_configs"] {
			return &acmeLiveRefUnresolvedError{inner: err}
		}
		return err
	}
	caProviderID, ok := backupInteger(rule["ca_provider_id"])
	if !ok || caProviderID == 0 {
		return nil
	}
	providerOK, err := acmeIndex.resolveEnabled("ca_providers", caProviderID)
	if err != nil {
		return err
	}
	if !providerOK {
		err := errors.New("指定的 CA 提供商不存在或已禁用")
		if acmeIndex.fromLive["ca_providers"] {
			return &acmeLiveRefUnresolvedError{inner: err}
		}
		return err
	}
	return nil
}

// acmeLiveRefUnresolvedError 标记「备份不含该 cert 表、按 live 解析」失败的
// ACME 引用错误。导入/预览在「导规则不导 cert 配置且备份从未
// 携带 cert 表」方向经 errors.As 识别并降级为悬挂警告（与对称，
// 不阻断）；其余方向维持整包 400。错误文案与硬拒绝口径一致。
type acmeLiveRefUnresolvedError struct{ inner error }

func (e *acmeLiveRefUnresolvedError) Error() string { return e.inner.Error() }
func (e *acmeLiveRefUnresolvedError) Unwrap() error { return e.inner }

// validateV2BackupAdminTLS 按 UpdateAdminTLS 同口径校验备份全局配置区的
// admin_tls_*：缺省键合并当前库内值（与 UpdateAdminTLS 的合并语义一致），
// 启用态 mode 白名单 + upload 模式证书配对/有效期。导入此前无等价
// 校验直接落库，坏配置（enabled+upload+空证书或过期证书）使下次启动
// ResolveCertificate 失败即进程退出（main.go），形成崩溃循环——导入必须
// 整包 400（零写入语义，导入/预览双路径同序调用）。
func validateV2BackupAdminTLS(config map[string]any) error {
	if config == nil {
		return nil
	}
	// 仅当备份实际携带 admin_tls_* 键时才合并校验——该键组不受
	// 导入影响时（备份未携带），live 值（如运行期自然过期的 upload 证书）不得
	// 阻断无关导入。
	carriesAdminTLSKeys := false
	for _, key := range []string{"admin_tls_enabled", "admin_tls_mode", "admin_tls_cert", "admin_tls_key"} {
		if _, exists := config[key]; exists {
			carriesAdminTLSKeys = true
			break
		}
	}
	if !carriesAdminTLSKeys {
		return nil
	}
	// 合并校验用严格 loader——读失败中止导入/预览（不得用降级默认
	// 值校验，否则携带部分 admin_tls_* 键的备份可能以错误基线通过校验）。
	merged, err := services.LoadAdminTLSConfigE()
	if err != nil {
		// 读的是**当前库**现状，不是备份内容：归入基础设施读失败族，由导入
		// 入口映射为 500 + 固定文案（否则 400「备份校验失败」把管理员引向
		// 反复更换备份文件，并回显底层驱动文本）。
		return importInfraReadFailure(fmt.Errorf("读取当前管理面板 HTTPS 配置失败，无法校验备份：%w", err))
	}
	if value, exists := config["admin_tls_enabled"]; exists {
		merged.Enabled = backupBooleanEnabled(value)
	}
	if value, exists := config["admin_tls_mode"]; exists {
		merged.Mode = backupString(value)
	}
	if value, exists := config["admin_tls_cert"]; exists {
		merged.Cert = backupString(value)
	}
	if value, exists := config["admin_tls_key"]; exists {
		merged.Key = backupString(value)
	}
	if err := validateAdminTLSConfigValues(merged); err != nil {
		return fmt.Errorf("备份的全局配置包含不可用的管理面板 HTTPS 配置：%w", err)
	}
	return nil
}

// validateV2BackupAutobanConfig 自动封禁六列导入门（导入/
// 预览双路径同序调用，镜像 validateV2BackupAdminTLS 位次）：布尔两键的类型门
// 已由 backupBooleanConfigKeys 枚举（validateV2BackupBooleanTypes）承担；此处
// 承担数值钳制与枚举校验——写侧（services.ValidateAutobanConfig）同口径，导入
// 不宽于保存侧。越界数值钳到写侧同边界（镜像 backupConfigClampRules
// 钳制族）、非整数形态归一缺省；duration/scope 空串/null 归一缺省（镜像
// security_policies mode 族「无值归一」）、非空非法与非字符串形态响亮拒绝。
// 返回钳制/归一留痕（导入侧并入审计明细；预览侧忽略）。归一写回 backup.Config
// 在 checksum 校验之后执行，不影响完整性判定。
// 三通道归一语义分歧（保存拒/导入钳/回填复位默认）的
// 显式声明锚在 services.ValidateAutobanConfig 注释——本函数即「导入钳」通道。
func validateV2BackupAutobanConfig(config map[string]any) ([]string, error) {
	if config == nil {
		return nil, nil
	}
	var notes []string
	if raw, exists := config["autoban_threshold"]; exists && raw != nil {
		if n, ok := backupInteger(raw); ok {
			if n < 1 || n > 10000 {
				clamped := n
				if n < 1 {
					clamped = 1
				}
				if n > 10000 {
					clamped = 10000
				}
				config["autoban_threshold"] = clamped
				notes = append(notes, fmt.Sprintf("autoban_threshold 越界（%d），已钳位为 %d", n, clamped))
			}
		} else {
			config["autoban_threshold"] = 100
			notes = append(notes, "autoban_threshold 非整数形态，已归一为 100")
		}
	}
	if raw, exists := config["autoban_window_minutes"]; exists && raw != nil {
		if n, ok := backupInteger(raw); ok {
			if n < 1 || n > 60 {
				clamped := n
				if n < 1 {
					clamped = 1
				}
				if n > 60 {
					clamped = 60
				}
				config["autoban_window_minutes"] = clamped
				notes = append(notes, fmt.Sprintf("autoban_window_minutes 越界（%d），已钳位为 %d", n, clamped))
			}
		} else {
			config["autoban_window_minutes"] = 5
			notes = append(notes, "autoban_window_minutes 非整数形态，已归一为 5")
		}
	}
	for _, field := range []struct {
		key     string
		def     string
		invalid func(string) bool
		choices string
	}{
		{"autoban_duration", "1h", func(s string) bool { return !services.ValidAutobanDuration(s) }, "10m/30m/1h/6h/12h/24h/permanent"},
		{"autoban_scope", "all", func(s string) bool { return !services.ValidAutobanScope(s) }, "blocked/logged/all"},
	} {
		raw, exists := config[field.key]
		if !exists || raw == nil {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			// 同型：保存侧 JSON 绑定对非字符串同值 400，导入不得经
			// backupString 静默归一放行。
			return nil, fmt.Errorf("备份校验失败：全局配置 %s 需为字符串，实际类型 %T", field.key, raw)
		}
		if strings.TrimSpace(value) == "" {
			config[field.key] = field.def
			notes = append(notes, fmt.Sprintf("%s 空值，已归一为 %s", field.key, field.def))
			continue
		}
		if field.invalid(value) {
			return nil, fmt.Errorf("备份校验失败：全局配置 %s 取值无效（%s），须为 %s 之一", field.key, value, field.choices)
		}
	}
	return notes, nil
}

// validateV2BackupTrustedProxyConfig 受信代理三 TEXT 列导入门（历史
// 审计；导入/预览双路径同序调用）：trusted_proxy_ranges/range_refs/headers 为
// TEXT 列承载 JSON 数组文本，此前导入零门——手造备份可落任意畸形文本，渲染层
// 对畸形按未启用丢弃，真实 IP 还原静默失效而面板仍宣称已启用。
// 复用保存侧校验单一口径：形态门+归一+引用存在性+内联∪引用展开总量上限；
// 载荷未携带的键按库内存量值参与合成判定（与保存侧 PATCH 语义一致）。
// tables 为备份携带表：按「备份是否携带
// security_ip_lists 表」分流——携带时 refs 存在性/条目/上限仅按备份行集合
// 解析（全量替换先例：备份行才是导入后的真实数据，指向库内但不在备份内
// 的 id 导入后必然悬空，400 拒绝）；未携带时按库内解析（「缺席=保留本地」，
// 迟到表 era 备份不误拒）。归一写回 backup.Config 在 checksum 校验之后执行。
func validateV2BackupTrustedProxyConfig(config map[string]any, tables map[string][]map[string]any) error {
	if config == nil {
		return nil
	}
	source := trustedProxyBackupListSource(tables)
	req := models.UpdateConfigRequest{}
	carried := false
	for _, field := range []struct {
		key string
		dst **string
	}{
		{"trusted_proxy_ranges", &req.TrustedProxyRanges},
		{"trusted_proxy_range_refs", &req.TrustedProxyRangeRefs},
		{"trusted_proxy_headers", &req.TrustedProxyHeaders},
	} {
		raw, exists := config[field.key]
		if !exists || raw == nil {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			return fmt.Errorf("备份校验失败：全局配置 %s 需为字符串（JSON 数组文本），实际类型 %T", field.key, raw)
		}
		*field.dst = &value
		carried = true
	}
	if !carried {
		return nil
	}
	if err := validateTrustedProxyFieldsWithSource(&req, source); err != nil {
		// %w 保留错误类型：受信代理校验内含 DB 读取，其失败必须在导入端点
		// 映射为 500（而非「备份校验失败」400 + 底层 SQL 文本）。
		return fmt.Errorf("备份校验失败：全局配置受信代理设置：%w", err)
	}
	if req.TrustedProxyRanges != nil {
		config["trusted_proxy_ranges"] = *req.TrustedProxyRanges
	}
	if req.TrustedProxyRangeRefs != nil {
		config["trusted_proxy_range_refs"] = *req.TrustedProxyRangeRefs
	}
	if req.TrustedProxyHeaders != nil {
		config["trusted_proxy_headers"] = *req.TrustedProxyHeaders
	}
	return nil
}

// validateV2BackupRuntimeSettings 运行期设置门：导入侧此前对
// timezone/server_map_lat/server_map_lon/threat_screen_mode/代理超时/
// caddy_log_level/default_ca_provider_id 零校验——非法值落库后 /config 渲染
// 或保存侧反校验 500/400。与保存侧（handlers/caddy.go UpdateConfig）同口径：
// 非法时区/枚举/坐标/负超时 400；default_ca_provider_id 按「导入后视图」
// （备份携带 ca_providers 表时只看备份行，否则看库内现存行）校验存在性。
func validateV2BackupRuntimeSettings(config map[string]any, tables map[string][]map[string]any) error {
	if config == nil {
		return nil
	}
	if raw, exists := config["acme_email"]; exists && raw != nil {
		text, ok := raw.(string)
		if !ok {
			return fmt.Errorf("备份的 acme_email 必须为字符串")
		}
		email, err := normalizeACMEEmail(text)
		if err != nil {
			return fmt.Errorf("备份的 acme_email 无效: %w", err)
		}
		config["acme_email"] = email
	}
	if raw, exists := config["sync_interval"]; exists && raw != nil {
		value, ok := backupInteger(raw)
		if !ok || value < 10 || value > 86400 {
			return fmt.Errorf("备份的 sync_interval 必须是 10 到 86400 之间的整数")
		}
	}
	if raw, exists := config["timezone"]; exists && raw != nil {
		tz := backupString(raw)
		// 与保存侧共用 services.ValidateLocationName：空串/纯空白串不是合法时区
		// （time.LoadLocation("") 会静默返回 UTC，导入后时间显示全体漂移）。
		if err := services.ValidateLocationName(tz); err != nil {
			return fmt.Errorf("备份包含无效的时区 %q: %w", tz, err)
		}
	}
	for _, item := range []struct {
		key  string
		lo   float64
		hi   float64
		name string
	}{
		{"server_map_lat", -90, 90, "本站纬度"},
		{"server_map_lon", -180, 180, "本站经度"},
	} {
		raw, exists := config[item.key]
		if !exists || raw == nil {
			continue
		}
		value, ok := backupFloat(raw)
		if !ok {
			return fmt.Errorf("备份的%s必须为数值", item.name)
		}
		if value < item.lo || value > item.hi {
			return fmt.Errorf("备份的%s必须在 %g 到 %g 之间", item.name, item.lo, item.hi)
		}
	}
	if raw, exists := config["threat_screen_mode"]; exists && raw != nil {
		if mode := backupString(raw); !models.IsValidThreatScreenMode(mode) {
			return fmt.Errorf("备份的威胁大屏模式仅支持 map 或 globe，实际 %q", mode)
		}
	}
	for _, key := range []string{"log_level", "caddy_log_level"} {
		raw, exists := config[key]
		if !exists || raw == nil {
			continue
		}
		switch backupString(raw) {
		case "debug", "info", "warn", "error":
		default:
			if key == "caddy_log_level" {
				return fmt.Errorf("备份包含无效的 Caddy 日志级别")
			}
			return fmt.Errorf("备份包含无效的应用日志级别")
		}
	}
	for _, key := range []string{"proxy_dial_timeout", "proxy_response_header_timeout", "proxy_read_timeout", "proxy_write_timeout", "proxy_stream_timeout"} {
		if raw, exists := config[key]; exists && raw != nil {
			value, ok := backupInteger(raw)
			if !ok || value < 0 {
				return fmt.Errorf("备份的代理超时时间 %s 不能为负数或非整数", key)
			}
		}
	}
	if raw, exists := config["proxy_flush_interval"]; exists && raw != nil {
		if value, ok := backupInteger(raw); !ok || value < -1 {
			return fmt.Errorf("备份的代理刷新间隔不能小于 -1")
		}
	}
	if raw, exists := config["proxy_stream_close_delay"]; exists && raw != nil {
		if value, ok := backupInteger(raw); !ok || value < 0 {
			return fmt.Errorf("备份的代理流关闭延迟不能为负数")
		}
	}
	// http 三超时的符号与下界由 backupConfigClampRules（ResetOnLow）统一处置：
	// 0/负值/非法形态一律归治理默认并留审计，与「导入钳制」单口径一致。
	// 此处再设一道负值 400 会让同一输入得到相反结论（400 vs 静默归一），
	// 且该 400 先于钳制执行，钳制的负值分支永远不可达。
	if raw, exists := config["threat_traffic_sample_n"]; exists && raw != nil {
		value, ok := backupInteger(raw)
		if !ok {
			return fmt.Errorf("备份的大屏流量采样必须是整数（-1 自适应 / 0 关闭）")
		}
		// 仅 -1/0。旧备份的 1（全量）与固定 2..64 按启动迁移同口径归一到 -1
		//（自适应），导入不因旧契约整包被拒。
		switch value {
		case -1, 0:
		default:
			config["threat_traffic_sample_n"] = db.DefaultThreatTrafficSampleN
		}
	}
	// 0=自动的旧语义废除——导入侧 0 归一为显式默认
	// （自此 def 取 db.Default* 单源），其余越界/非整数响亮 400；
	// 写侧只接受 1..max。
	for _, item := range []struct {
		key   string
		max   int
		def   int64
		label string
	}{
		{key: "security_events_retention_days", max: db.MaxSecurityEventsRetentionDays, def: db.DefaultSecurityEventsRetentionDays, label: "安全事件保留天数"},
		{key: "security_events_row_cap", max: db.MaxSecurityEventsRowCap, def: db.DefaultSecurityEventsRowCap, label: "安全事件行数上限"},
	} {
		if raw, exists := config[item.key]; exists && raw != nil {
			value, ok := backupInteger(raw)
			if !ok {
				return fmt.Errorf("备份的%s必须是整数", item.label)
			}
			if value == 0 {
				config[item.key] = item.def
				continue
			}
			if value < 1 || value > item.max {
				return fmt.Errorf("备份的%s必须是 1 到 %d 之间的整数", item.label, item.max)
			}
		}
	}
	if raw, exists := config["default_ca_provider_id"]; exists && raw != nil {
		id, ok := backupInteger(raw)
		if !ok {
			return fmt.Errorf("备份的默认 CA 提供商 ID 必须为整数")
		}
		if id < 0 {
			return fmt.Errorf("备份的默认 CA 提供商 ID 不能为负数")
		}
		if id > 0 && !backupCAProviderExistsPostImport(tables, id) {
			return fmt.Errorf("备份的默认 CA 提供商（ID %d）在导入后不存在或已禁用", id)
		}
	}
	// access_log_format 导入侧此前零校验——手造
	// 备份可落库「删除 request>remote_ip/uri/headers」的格式，日志统计与 UA
	// 统计静默失效（保存侧 caddy.go UpdateConfig 有 validateAccessLogFormat
	// 门）。与保存侧同门同序：规模门 → 语义门 → 归一强制携带 API Key 头脱敏行
	// → 落库值再过一次规模门（归一可能多出脱敏行；渲染层另有恒等不变量兜底，
	// 导入落库值即所见）。
	if raw, exists := config["access_log_format"]; exists && raw != nil {
		format, ok := raw.(string)
		if !ok {
			return fmt.Errorf("备份的 access_log_format 必须为字符串")
		}
		if err := validateAccessLogFormatSize(format); err != nil {
			return fmt.Errorf("备份的 access_log_format 无效: %w", err)
		}
		if err := validateAccessLogFormat(format); err != nil {
			return fmt.Errorf("备份的 access_log_format 无效: %w", err)
		}
		normalized := normalizeAccessLogRedaction(format)
		if err := validateAccessLogFormatSize(normalized); err != nil {
			return fmt.Errorf("备份的 access_log_format 无效: %w（导入时会自动补一行脱敏规则，落库值按此计数）", err)
		}
		config["access_log_format"] = normalized
	}
	// 上游 keepalive 为「0=继承」省略型列（写侧 caddy.go UpdateConfig /
	// rules.go 创建更新明确拒绝负值——负值落库后基础设置保存恒 400、规则行
	// 编辑被同门卡死）。负值/非整数归 0 的钳制与留痕由全局配置数值归一
	// （backupConfigClampRules 的 upstream_keepalive_timeout 行）单点负责，
	// 预览 warning 与导入成功审计同源；本门不再二次静默改写。
	// 全局配置区其余写侧门也必须前移到导入——
	// github_proxy_url 写侧白名单（services.ValidateGitHubProxyURL），
	// oidc_config 写侧「损坏即拒绝改写」（auth_oidc.go loadOIDCConfig）。
	// 此前二者零校验：导入后 /config 回显白名单外 URL 或损坏 OIDC 使设置
	// 端点持续 500（仅能靠另一份备份/直接改库修复）。
	if raw, exists := config["github_proxy_url"]; exists && raw != nil {
		if err := services.ValidateGitHubProxyURL(backupString(raw)); err != nil {
			return fmt.Errorf("备份的 GitHub 加速代理地址无效: %w", err)
		}
	}
	if raw, exists := config["oidc_config"]; exists && raw != nil {
		text := backupString(raw)
		if strings.TrimSpace(text) != "" {
			var oidcCfg OIDCConfig
			if err := json.Unmarshal([]byte(text), &oidcCfg); err != nil {
				return fmt.Errorf("备份的 OIDC 配置不是有效 JSON: %w", err)
			}
			if oidcCfg.Enabled {
				// 与面板保存门/公开状态/登录入口共用同一条完整性判据
				// （OIDCConfig.usable：必填 client_secret + issuer URL 合规）。
				// 只查 issuer/client_id 会放行「已启用但不可用」的配置——公开
				// 状态虽隐藏按钮，直连 /auth/oidc/login 仍进入 discovery/令牌
				// 交换并必败（表面启用、实际不可用），只能再改一次配置恢复。
				if err := oidcCfg.usable(); err != nil {
					return fmt.Errorf("备份的 OIDC 配置已启用但不可用: %w", err)
				}
			}
		}
	}
	return nil
}

// validateAutoBackupScheduleCombination frequency/day 合并视图校验单源
// （validateV2BackupAutoBackupConfig 与锁内复核共用）。
func validateAutoBackupScheduleCombination(freq string, day int) error {
	switch freq {
	case "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("备份的 auto_backup_frequency 必须是 daily/weekly/monthly，实际 %q", freq)
	}
	high := autoBackupDayHigh(freq)
	if day < 1 || day > high {
		return fmt.Errorf("备份的 auto_backup_day 必须在 1-%d 之间（导入后排程 %s/day=%d）", high, freq, day)
	}
	return nil
}

// revalidateImportLiveDependencies 在取得 caddyOpMu 与事务之后、任何写入之前，
// 重跑依赖 live 数据的合并型校验（规则引用、受信代理名单、自动备份排程、
// 默认 CA 提供商、证书任务不变量）。初检到加锁之间有秒级窗口（等
// configImportBeginMu、暂停调度、30s 在途排空、等 WAF 锁），窗口内并发删除
// 规则引用对象/名单/证书任务、或保存自动备份排程、删除 CA 提供商，都会让
// 初检结论失效。全部读取走导入事务，与后续写入同一快照。
func revalidateImportLiveDependencies(ctx context.Context, tx *sql.Tx, backup *configBackup, sectionTables map[string]bool) error {
	if backup == nil {
		return nil
	}
	// 0) 规则引用：备份携带 upstreams/path_rules 而规则表保持 live 时，初检按
	// 锁外 live 规则视图放行（validateBackupRuleReferences 的「缺席则 live」
	// 分支）。初检→加锁窗口内删除被引用规则会让写入落成悬挂行；锁内按事务
	// 视图重验，命中即 400 点名表/行/规则 ID（与初检同口径）。判据必须是
	// 「备份是否携带 lb_rules」（缺席=live 保留），分类选择集合恒含 lb_rules。
	_, rulesCarried := backup.Tables["lb_rules"]
	_, policiesCarried := backup.Tables["security_policies"]
	bindingRows := backup.Tables["security_policy_bindings"]
	if !rulesCarried && (len(backup.Tables["upstreams"]) > 0 || len(backup.Tables["path_rules"]) > 0 || len(bindingRows) > 0) {
		liveRuleIDs := make(map[string]struct{})
		rows, err := tx.QueryContext(ctx, `SELECT caddy_id FROM lb_rules`)
		if err != nil {
			return fmt.Errorf("锁内读取规则引用视图失败: %v", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("锁内读取规则引用视图失败: %v", err)
			}
			liveRuleIDs[id] = struct{}{}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return fmt.Errorf("锁内读取规则引用视图失败: %v", err)
		}
		for _, table := range []string{"upstreams", "path_rules"} {
			for i, row := range backup.Tables[table] {
				ruleID, _ := row["rule_id"].(string)
				if _, exists := liveRuleIDs[ruleID]; !exists {
					return fmt.Errorf("%s 第 %d 行引用了不存在的规则 %q（导入期间规则已被删除）", table, i+1, ruleID)
				}
			}
		}
		// 绑定表的规则轴：初检按「规则表缺席则 live 视图」放行，窗口内规则被
		// 删除会让绑定原样落库（该表无外键，无 FK 兜底），规则消失后绑定成为
		// 悬挂行；按事务视图重验，口径与初检一致。
		for i, row := range bindingRows {
			ruleID, _ := row["rule_caddy_id"].(string)
			if _, exists := liveRuleIDs[ruleID]; !exists {
				return fmt.Errorf("security_policy_bindings 第 %d 行引用了不存在的规则 %q（导入期间规则已被删除）", i+1, ruleID)
			}
		}
	}
	// 绑定表的策略轴：初检在策略表缺席时按 live 策略视图放行；窗口内删除被
	// 引用策略会让绑定落库而 loadSecurityPolicyContext 查不到策略——该规则
	// WAF/限流/GeoIP 全部静默失效（UI 仍显示已绑定）。锁内按事务视图重验。
	if len(bindingRows) > 0 && !policiesCarried {
		livePolicyIDs := make(map[int64]struct{})
		rows, err := tx.QueryContext(ctx, `SELECT id FROM security_policies`)
		if err != nil {
			return fmt.Errorf("锁内读取安全策略引用视图失败: %v", err)
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("锁内读取安全策略引用视图失败: %v", err)
			}
			livePolicyIDs[id] = struct{}{}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return fmt.Errorf("锁内读取安全策略引用视图失败: %v", err)
		}
		for i, row := range bindingRows {
			policyID, ok := backupInteger(row["policy_id"])
			if !ok {
				return fmt.Errorf("security_policy_bindings 第 %d 行 policy_id 必须为整数", i+1)
			}
			if _, exists := livePolicyIDs[int64(policyID)]; !exists {
				return fmt.Errorf("security_policy_bindings 第 %d 行引用了不存在的安全策略 %d（导入期间策略已被删除）", i+1, policyID)
			}
		}
	}
	// 1) 受信代理引用名单：refs 与名单表按「导入后视图」配对复核（含
	// 「名单表被替换且 refs 保持 live」组合——live refs 按备份名单 id 集重验）。
	if err := revalidateImportTrustedProxyRefs(ctx, tx, backup); err != nil {
		return err
	}
	// 1b) 策略↔IP 名单配对的反方向：名单表被替换、策略表保持 live。初检的
	// 策略轴只遍历「备份携带」的两表行（策略不在包内=零覆盖），live 策略的
	// ip_acl_list_refs/ip_whitelist_refs/crs_excluded_rules.listRefs 按「id 存在
	// 即有效」放行——名单表替换后同 id 内容换人，策略生效 IP 集合静默改变
	// （黑名单失效/白名单放行），零告警零审计。与受信代理轴同形：悬空即 400
	// 点名策略与名单 id。
	if _, listsCarried := backup.Tables["security_ip_lists"]; listsCarried && !policiesCarried {
		if err := revalidateImportLivePolicyIPListRefs(ctx, tx, backup); err != nil {
			return err
		}
	}
	// 1c) 自定义规则轴的反方向同理：规则表被替换而策略表保持 live 时，
	// 初检只遍历备份策略，无法看到 live 策略对已消失规则 id 的引用。
	if _, customRulesCarried := backup.Tables["security_custom_rules"]; customRulesCarried && !policiesCarried {
		if err := revalidateImportLivePolicyCustomRuleRefs(ctx, tx, backup); err != nil {
			return err
		}
	}
	// 2) 自动备份排程：frequency/day 缺席列保留 live，必须按事务内 live 行
	// 重算合并视图（窗口内保存的 weekly/day=9 会静默停摆）。仅全局配置区
	// 存在时才有这条合并视图（分类备份可不带 Config）；下方默认 CA 与证书
	// 任务不变量不读 Config，不得被该判据短路。
	if backup.Config != nil {
		_, freqProvided := backup.Config["auto_backup_frequency"]
		_, dayProvided := backup.Config["auto_backup_day"]
		if !freqProvided || !dayProvided {
			freq := db.DefaultAutoBackupFrequency
			day := db.DefaultAutoBackupDay
			if raw, exists := backup.Config["auto_backup_frequency"]; exists && raw != nil {
				freq = backupString(raw)
			}
			if raw, exists := backup.Config["auto_backup_day"]; exists && raw != nil {
				if n, ok := backupInteger(raw); ok {
					day = int(n)
				}
			}
			var liveFreq string
			var liveDay int
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE(auto_backup_frequency,?), COALESCE(auto_backup_day,?) FROM global_config WHERE id=1`,
				db.DefaultAutoBackupFrequency, db.DefaultAutoBackupDay).Scan(&liveFreq, &liveDay); err != nil {
				return fmt.Errorf("锁内读取自动备份排程失败: %v", err)
			}
			if !freqProvided {
				freq = liveFreq
			}
			if !dayProvided {
				day = liveDay
			}
			if err := validateAutoBackupScheduleCombination(freq, day); err != nil {
				return err
			}
		}
	}
	// 3) 默认 CA 提供商：备份未携带 ca_providers 时按 live 行校验存在且启用。
	if _, providersCarried := backup.Tables["ca_providers"]; !providersCarried {
		if raw, exists := backup.Config["default_ca_provider_id"]; exists && raw != nil {
			if id, ok := backupInteger(raw); ok && id > 0 {
				var count int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ca_providers WHERE id=? AND COALESCE(enabled,1)=1`, id).Scan(&count); err != nil {
					return fmt.Errorf("锁内复核默认 CA 提供商失败: %v", err)
				}
				if count == 0 {
					return fmt.Errorf("导入期间默认 CA 提供商（ID %d）已被删除或禁用", id)
				}
			}
		}
	}
	// 4) 证书任务不变量：备份未携带 cert_jobs 时任务行保持 live，初检按锁外
	// 本地行放行；窗口内并发删除某条启用 ACME 规则的任务行会让「规则启用但
	// 无续签行」的断链状态静默落库（续签扫描只遍历已存在的任务行，不补建，
	// 证书到期后 TLS 端口无证书可用）。锁内按事务视图重跑同一不变量。
	if _, certJobsCarried := backup.Tables["cert_jobs"]; !certJobsCarried && len(backup.Tables["lb_rules"]) > 0 {
		if _, err := validateV2BackupCertJobsWithQuerier(ctx, backup.Tables, tx); err != nil {
			return err
		}
	}
	return nil
}

// revalidateImportTrustedProxyRefs 锁内复核受信代理引用名单——refs 与名单表
// 按「导入后视图」配对
//   - 备份携带 refs、名单表缺席：refs 将替换为备份值、名单保持 live → refs 按
//     事务内 live 名单复核（窗口内删除名单会让初检结论失效）；
//   - 名单表携带、备份未携带 refs（未选系统数据 Config==nil，或 Config 未含
//     该键）：refs 保持 live、名单=备份行集合 → live refs 必须按备份名单 id
//     集复核，悬空即拒绝（此前该组合无门禁，导入后受信网段渲染静默缺条目）；
//   - 两侧均携带：初检 validateV2BackupTrustedProxyConfig 已按备份行确定性
//     解析（无 live 依赖），锁内不重复；
//   - 两侧均缺席：导入不改变该配对，无需复核。
func revalidateImportTrustedProxyRefs(ctx context.Context, tx *sql.Tx, backup *configBackup) error {
	refsCarried := false
	var refsRaw any
	if backup.Config != nil {
		if raw, exists := backup.Config["trusted_proxy_range_refs"]; exists && raw != nil {
			refsCarried, refsRaw = true, raw
		}
	}
	// 「名单表携带」的判据必须是备份实际携带的表（backup.Tables），不是
	// sections 分类选中集合——迟到表 era（预 v2.2.1 全量备份/手造精确表集）
	// 里 sections 缺省=全选，但表并未随包携带；按分类判定会把 live refs 与
	// 空备份 id 集比对，误拒本应放行的导入（初检正是按表携带放行的）。
	_, listsCarried := backup.Tables["security_ip_lists"]
	switch {
	case !listsCarried && refsCarried:
		refsText, ok := refsRaw.(string)
		if !ok || strings.TrimSpace(refsText) == "" {
			return nil
		}
		unique, err := parseTrustedProxyRefIDs(refsText)
		if err != nil {
			return err
		}
		found := make(map[int64]bool, len(unique))
		for _, ch := range chunkIDs(unique, 500) {
			rows, err := tx.QueryContext(ctx, `SELECT id FROM security_ip_lists WHERE id IN (`+ch.placeholders+`)`, ch.args...)
			if err != nil {
				return fmt.Errorf("锁内复核受信代理引用失败: %v", err)
			}
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return fmt.Errorf("锁内复核受信代理引用失败: %v", err)
				}
				found[id] = true
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return fmt.Errorf("锁内复核受信代理引用失败: %v", err)
			}
		}
		for _, id := range unique {
			if !found[id] {
				return fmt.Errorf("导入期间受信代理引用的地址列表已被删除：#%d", id)
			}
		}
	case listsCarried && !refsCarried:
		var refsText string
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&refsText); err != nil {
			return fmt.Errorf("锁内读取受信代理引用列表失败: %v", err)
		}
		if strings.TrimSpace(refsText) == "" {
			return nil
		}
		unique, err := parseTrustedProxyRefIDs(refsText)
		if err != nil {
			// 存量畸形（仅见于带外改库）按无引用处理——渲染层对畸形同样
			// fail-closed 丢弃，不因存量畸形整包拒绝导入（trustedProxyInlineCount 同口径）。
			return nil
		}
		carriedIDs := make(map[int64]bool, len(backup.Tables["security_ip_lists"]))
		builtinIDs := make(map[int64]bool, len(backup.Tables["security_ip_lists"]))
		for _, row := range backup.Tables["security_ip_lists"] {
			if id, ok := backupInteger(row["id"]); ok {
				carriedIDs[int64(id)] = true
				// 内置名单复检：初检 validateImportedSystemIPLists 只校验 system
				// 行名称白名单（允许 id 与 live refs 撞号）——refs 指向备份行中
				// 的 system=1 名单必须按写侧契约拒绝（受信代理不能引用内置地址
				// 列表；渲染对 system=1 走 .iplist 装载通道，语义相反）。
				if backupBooleanEnabled(row["system"]) {
					builtinIDs[int64(id)] = true
				}
			}
		}
		for _, id := range unique {
			if !carriedIDs[id] {
				return fmt.Errorf("导入后受信代理引用的地址列表将不存在：#%d", id)
			}
			if builtinIDs[id] {
				return fmt.Errorf("受信代理不能引用内置地址列表：#%d", id)
			}
		}
	}
	return nil
}

// revalidateImportLivePolicyIPListRefs 锁内复核「名单表被替换、策略表保持 live」
// 组合下 live 策略的三个引用面（与删除守卫同集合）：
//   - security_policies.ip_acl_list_refs
//   - security_policies.ip_whitelist_refs
//   - security_policies.crs_excluded_rules 条目内 listRefs（读侧双格式归一）
//
// 判据：引用 id 必须存在于「导入后名单集合」（=备份携带的名单行 id 集）。初检
// （validateV2BackupSecurityPoliciesWithQuerier）只遍历备份携带的两表行，策略表
// 缺席时整条轴跳过；名单表替换又是全量 delete+insert（restoreTable 保留原 id），
// 于是同 id 的内容可以整份换人——策略的生效/放行 IP 集合随备份内容变化而
// 没有任何告警。悬空即 400 点名策略与名单 id（与受信代理轴同一取向：宁可
// 要求同时携带策略表，也不放行「已绑定但语义换人」的静默状态）。
func revalidateImportLivePolicyIPListRefs(ctx context.Context, tx *sql.Tx, backup *configBackup) error {
	if backup == nil {
		return nil
	}
	carriedListIDs := make(map[int64]struct{}, len(backup.Tables["security_ip_lists"]))
	for _, row := range backup.Tables["security_ip_lists"] {
		if id, ok := backupInteger(row["id"]); ok {
			carriedListIDs[int64(id)] = struct{}{}
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(name,''), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(crs_excluded_rules,'[]') FROM security_policies`)
	if err != nil {
		return fmt.Errorf("锁内读取安全策略的名单引用失败: %v", err)
	}
	defer rows.Close()
	var firstPolicyID int64
	var firstName string
	var firstListID int64
	found := false
	for rows.Next() {
		var policyID int64
		var policyName, aclRefs, whitelistRefs, crsExcluded string
		if err := rows.Scan(&policyID, &policyName, &aclRefs, &whitelistRefs, &crsExcluded); err != nil {
			return fmt.Errorf("锁内读取安全策略的名单引用失败: %v", err)
		}
		check := func(listID int64) {
			if found {
				return
			}
			if _, ok := carriedListIDs[listID]; !ok {
				firstPolicyID, firstName, firstListID, found = policyID, policyName, listID, true
			}
		}
		for _, raw := range []string{aclRefs, whitelistRefs} {
			for _, listID := range parseIPListRefsIDs(raw) {
				check(listID)
			}
		}
		for _, listID := range crsExcludedListRefs(crsExcluded) {
			check(listID)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("锁内读取安全策略的名单引用失败: %v", err)
	}
	if found {
		return fmt.Errorf("导入后安全策略 %q(#%d) 引用的地址列表 #%d 将不存在（策略表未随包携带，而名单表被替换为不含该 id 的集合）——请同时携带安全策略表或保留该名单", firstName, firstPolicyID, firstListID)
	}
	return nil
}

// revalidateImportLivePolicyCustomRuleRefs 复核「自定义规则表被替换、策略表
// 保持 live」的反向组合。初检只遍历备份携带的策略行；此处按事务内 live
// 策略逐 id 对照备份规则集合，悬空即拒绝，避免 WAF 引用静默失效。
func revalidateImportLivePolicyCustomRuleRefs(ctx context.Context, tx *sql.Tx, backup *configBackup) error {
	if backup == nil {
		return nil
	}
	carriedRuleIDs := make(map[int]struct{}, len(backup.Tables["security_custom_rules"]))
	for _, row := range backup.Tables["security_custom_rules"] {
		if id, ok := backupInteger(row["id"]); ok {
			carriedRuleIDs[int(id)] = struct{}{}
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(name,''), COALESCE(custom_rules,'[]') FROM security_policies`)
	if err != nil {
		return fmt.Errorf("锁内读取安全策略的自定义规则引用失败: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var policyID int64
		var policyName, refs string
		if err := rows.Scan(&policyID, &policyName, &refs); err != nil {
			return fmt.Errorf("锁内读取安全策略的自定义规则引用失败: %v", err)
		}
		var ruleIDs []int
		if err := json.Unmarshal([]byte(refs), &ruleIDs); err != nil {
			// 与初检的既有形状宽容口径一致：非整数数组文本不在这里新增门。
			continue
		}
		for _, ruleID := range ruleIDs {
			if _, ok := carriedRuleIDs[ruleID]; !ok {
				return fmt.Errorf("导入后安全策略 %q(#%d) 引用的自定义规则 #%d 将不存在（策略表未随包携带，而自定义规则表被替换为不含该 id 的集合）——请同时携带安全策略表或保留该规则", policyName, policyID, ruleID)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("锁内读取安全策略的自定义规则引用失败: %v", err)
	}
	return nil
}

// parseTrustedProxyRefIDs 解析 trusted_proxy_range_refs 的 JSON id 数组并去重
// （锁内复核两分支共用的单源解析）。
func parseTrustedProxyRefIDs(refsText string) ([]int64, error) {
	var ids []int64
	if err := json.Unmarshal([]byte(refsText), &ids); err != nil {
		return nil, fmt.Errorf("受信代理引用列表必须是整数 id 的 JSON 数组: %v", err)
	}
	seen := map[int64]bool{}
	unique := make([]int64, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	return unique, nil
}

// revalidateImportStageBlockPages 锁内复核「规则→阶段拦截页」引用
// 备份携带 lb_rules 且未携带 security_block_pages 时，初检（validateV2BackupRules）
// 按锁外 live 页集合放行；初检→加锁窗口内 DeleteSecurityBlockPage 可删掉被
// 备份规则引用的页（live 删除守卫只看 live 规则，看不到备份行引用），导入后
// 规则阶段页悬空、拦截响应静默回落「跟随策略」。此处按事务内 live 页集合重验，
// 语义与初检 validateStageBlockPageRefWith 同口径（含 page=0 但 status≠0 的
// 配对门——该形状初检已整包拒绝，锁内重验保持同门不分裂）。
func revalidateImportStageBlockPages(ctx context.Context, tx *sql.Tx, tables map[string][]map[string]any) error {
	_, rulesCarried := tables["lb_rules"]
	_, pagesCarried := tables["security_block_pages"]
	if !rulesCarried || pagesCarried {
		return nil
	}
	pageExists := func(id int) (bool, error) {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_block_pages WHERE id=?`, id).Scan(&count); err != nil {
			return false, err
		}
		return count > 0, nil
	}
	for index, rule := range tables["lb_rules"] {
		protocol, _ := rule["protocol"].(string)
		// 与初检同范围：仅启用态 HTTP 规则参与阶段页校验（禁用行/TCP 残留同初检口径）。
		if !backupRuleEnabled(rule) || (protocol != "http" && protocol != "") {
			continue
		}
		for _, stage := range []struct{ label, idKey, statusKey string }{
			{"阶段 1（IP 访问控制/地域拦截）", "block_page_stage1_id", "block_page_stage1_status"},
			{"阶段 3（WAF）", "block_page_stage3_id", "block_page_stage3_status"},
		} {
			pageID, _ := backupInteger(rule[stage.idKey])
			status, _ := backupInteger(rule[stage.statusKey])
			if err := validateStageBlockPageRefWith(int(pageID), int(status), stage.label, pageExists); err != nil {
				return fmt.Errorf("规则 #%d：%w", index+1, err)
			}
		}
	}
	return nil
}

// backupCAProviderExistsPostImport 按「导入后视图」校验 CA 提供商存在性：
// 备份携带 ca_providers 表时，导入后该表=备份行集合，只能
// 在备份行内解析；表缺席（分类导出未选系统数据）=本地行保留，按库内解析。
func backupCAProviderExistsPostImport(tables map[string][]map[string]any, id int) bool {
	if _, carried := tables["ca_providers"]; carried {
		row, found := backupRowByID(tables, "ca_providers", id)
		return found && backupRowEnabled(row)
	}
	if db.DB == nil {
		return false
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM ca_providers WHERE id=? AND COALESCE(enabled,1)=1`, id).Scan(&count); err != nil {
		return false
	}
	return count > 0
}

// backupFloat 读取备份中的数值（JSON 反序列化 float64 / 内部 int 形态）。
func backupFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// validateV2BackupAutoBackupConfig 自动备份设置组导入门：frequency
// 枚举、HH:MM、day 区间（weekly 1-7 / 其余 1-28）、keep 钳到写侧 [1,30]、
// sections 必须是已知分类子集（legacy 键归一后校验，归一值写回）。非法值
// 此前原样落库，消费侧（services.nextAutoBackupSlot）返回零槽 → 自动备份
// 静默停摆且设置页保存被写侧校验锁死。
func validateV2BackupAutoBackupConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	freq := db.DefaultAutoBackupFrequency
	freqProvided := false
	if raw, exists := config["auto_backup_frequency"]; exists && raw != nil {
		value, ok := raw.(string)
		if !ok {
			return fmt.Errorf("备份的 auto_backup_frequency 必须为字符串")
		}
		freq = value
		freqProvided = true
	}
	day := db.DefaultAutoBackupDay
	dayProvided := false
	if raw, exists := config["auto_backup_day"]; exists && raw != nil {
		value, ok := backupInteger(raw)
		if !ok {
			return fmt.Errorf("备份的 auto_backup_day 必须为整数")
		}
		day = value
		dayProvided = true
	}
	// 全局配置是 PATCH 写法语义：缺席列保留 live。frequency/day 必须
	// 先合并再校验，避免「live weekly + 备份只带 day=9」等组合静默停摆。
	if db.DB != nil && (!freqProvided || !dayProvided) {
		var liveFreq string
		var liveDay int
		if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_frequency,?), COALESCE(auto_backup_day,?) FROM global_config WHERE id=1`,
			db.DefaultAutoBackupFrequency, db.DefaultAutoBackupDay).Scan(&liveFreq, &liveDay); err != nil {
			return fmt.Errorf("读取现有自动备份排程以校验导入后视图: %w", err)
		}
		if !freqProvided {
			freq = liveFreq
		}
		if !dayProvided {
			day = liveDay
		}
	}
	if err := validateAutoBackupScheduleCombination(freq, day); err != nil {
		return err
	}
	if raw, exists := config["auto_backup_time"]; exists && raw != nil {
		value, ok := raw.(string)
		if !ok || !services.ValidScheduleHHMM(value) {
			return fmt.Errorf("备份的 auto_backup_time 必须为 HH:MM（00:00-23:59）")
		}
	}
	if raw, exists := config["auto_backup_keep"]; exists && raw != nil {
		keep, ok := backupInteger(raw)
		if !ok {
			return fmt.Errorf("备份的 auto_backup_keep 必须为整数")
		}
		clamped := keep
		if clamped < autoBackupKeepMin {
			clamped = autoBackupKeepMin
		}
		if clamped > autoBackupKeepMax {
			clamped = autoBackupKeepMax
		}
		config["auto_backup_keep"] = clamped
	}
	if raw, exists := config["auto_backup_sections"]; exists && raw != nil {
		sections, err := parseBackupAutoBackupSections(raw)
		if err != nil {
			return err
		}
		sections = normalizeBackupSectionKeys(sections)
		// 空集必须拒绝，与保存侧同口径——否则落库
		// "[]" 后消费侧 loadAutoBackupSectionsSetting 每轮 fail-closed，自动
		// 备份持续失败（导入不得宽于保存侧）。
		if len(sections) == 0 {
			return fmt.Errorf("备份范围不能为空")
		}
		if _, _, ok := configBackupSectionTables(sections); !ok {
			return fmt.Errorf("备份的 auto_backup_sections 含未知的配置分类")
		}
		normalized, err := json.Marshal(sections)
		if err != nil {
			return fmt.Errorf("备份的 auto_backup_sections 序列化失败: %w", err)
		}
		config["auto_backup_sections"] = string(normalized)
	}
	return nil
}

// parseBackupAutoBackupSections 解析 auto_backup_sections 存储形态（TEXT
// JSON 数组；容忍备份被手工加工成 JSON 数组的形态）。
func parseBackupAutoBackupSections(raw any) ([]string, error) {
	switch value := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil, nil
		}
		var sections []string
		if err := json.Unmarshal([]byte(trimmed), &sections); err != nil {
			return nil, fmt.Errorf("备份的 auto_backup_sections 需为 JSON 字符串数组")
		}
		return sections, nil
	case []any:
		sections := make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("备份的 auto_backup_sections 需为 JSON 字符串数组")
			}
			sections = append(sections, text)
		}
		return sections, nil
	}
	return nil, fmt.Errorf("备份的 auto_backup_sections 需为 JSON 字符串数组")
}

// trustedProxyBackupListSource 从备份 security_ip_lists 行构建名单解析源
// 表未携带=零值源（carried=false，未命中 id
// 按库内解析——导入后名单表保持现状，库内解析即导入后实态）；表携带=
// carried=true，refs 存在性仅按备份行集合解析（全量替换先例：备份行才是
// 导入后的真实数据，库内命中不代表导入后存在——悬空在校验期 400 拒绝）。
func trustedProxyBackupListSource(tables map[string][]map[string]any) trustedProxyBackupSource {
	rows, exists := tables["security_ip_lists"]
	if !exists {
		return trustedProxyBackupSource{}
	}
	source := make(map[int64]trustedProxyListSource, len(rows))
	for _, row := range rows {
		id, ok := backupInteger(row["id"])
		if !ok {
			continue
		}
		entries, _ := row["entries"].(string)
		name, _ := row["name"].(string)
		source[int64(id)] = trustedProxyListSource{name: name, entries: entries, builtin: backupBooleanEnabled(row["system"])}
	}
	return trustedProxyBackupSource{lists: source, carried: true}
}

func backupBooleanEnabled(value any) bool {
	switch value := value.(type) {
	case bool:
		return value
	case float64:
		return value == 1
	case int:
		return value == 1
	case int64:
		return value == 1
	case string:
		// 管理员预门先于布尔类型门执行；若备份把 is_enabled 写成字符串，
		// 此处需按存储期 SQLite 亲和性语义判断管理员是否存在，随后行级门
		// 会整包拒绝该字符串形态（不会进入恢复写入）。
		normalized := strings.ToLower(strings.TrimSpace(value))
		return normalized == "1" || normalized == "true"
	default:
		return false
	}
}

// backupRuleEnabled 读取备份行 enabled 字段：校验侧保守口径——缺省视为启用以覆盖
// 自环/遮蔽检查（不放松校验）；存储口径 NULL 视同禁用。
func backupRuleEnabled(row map[string]any) bool {
	if raw, exists := row["enabled"]; exists {
		return backupBooleanEnabled(raw)
	}
	return true
}

func backupString(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

// backupRowByID 在备份表行中按 id 查找（表缺席时自然返回未命中——调用方
// 自行决定 live 回退）。CA/ACME 引用解析的三处
// 同构循环收敛到此单一实现，避免「备份行 enabled 口径」在多处漂移。
func backupRowByID(tables map[string][]map[string]any, table string, id int) (map[string]any, bool) {
	for _, row := range tables[table] {
		if rowID, ok := backupInteger(row["id"]); ok && rowID == id {
			return row, true
		}
	}
	return nil, false
}

// backupRowEnabled 读取备份行的 enabled 列：键缺失/NULL=启用（schema DEFAULT
// TRUE 语义），显式禁用值才为 false。CA/ACME 引用校验的单一口径。
func backupRowEnabled(row map[string]any) bool {
	raw, exists := row["enabled"]
	return !exists || raw == nil || backupBooleanEnabled(raw)
}

// acmeRefResolvablePostImport:导入后某 ACME 引用(id)是否仍可解析——备份携带
// 该表时以备份行为准(整表替换),否则 live 表原样保留。enabled 口径与
// backupCAProviderExistsPostImport / acmeImportRefIndex 的 COALESCE(enabled,1)
// 一致：可空列 NULL 视同启用（正常写路径 NULL→1 归一，NULL 只可能来自带外
// 改库/极旧遗留；口径分裂会让悬挂告警与实际可用性相反）。
func acmeRefResolvablePostImport(tables map[string][]map[string]any, table string, id int) bool {
	if _, carried := tables[table]; carried {
		row, found := backupRowByID(tables, table, id)
		return found && backupRowEnabled(row)
	}
	var exists bool
	if err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM "+table+" WHERE id = ? AND COALESCE(enabled,1) = 1)", id).Scan(&exists); err != nil {
		return false
	}
	return exists
}

// ip2regionTagFromBackup:从备份表区读 IP2Region 版本 tag（随文件
// 传入 ApplyWafFileBundle,保持 .version 伴生文件与记录一致)。
func ip2regionTagFromBackup(tables map[string][]map[string]any) string {
	rows := tables["security_ip2region_version"]
	if len(rows) == 0 {
		return ""
	}
	tag, _ := rows[0]["version"].(string)
	return tag
}

// backupContainsUsername 报告备份 users 表是否包含指定账户。自锁门使用
// 导入全量替换 users/api_keys 且递增 password_version 吊销现有 JWT，备份缺少
// 操作者自身账户时导入后需用备份内账户重新登录——2026-09-18 裁定降级为
// warning+照常导入(见下方 operatorReplaced)。
func backupContainsUsername(users []map[string]any, username string) bool {
	for _, row := range users {
		if backupString(row["username"]) == username {
			return true
		}
	}
	return false
}

// backupPathRulesByRule 一次性把备份 path_rules 行按 rule_id 分桶并解析为模型
// 此前每条规则对 path_rules 全表扫描一次。
// upstreams_json 形态错误必须上抛：吞错后 Upstreams=nil 被
// validateRuleFeatures 按「回退主上游」放行，落库后 loadPathRulesBatch 对
// 同一 JSON 硬失败——ListRules/GetRule/UpdateRule/EnableRule 全 500。
// 错误文案保留全局行号，定位与逐规则扫描时代一致。
func backupPathRulesByRule(rows []map[string]any) (map[string][]models.PathRule, error) {
	byRule := make(map[string][]models.PathRule, len(rows))
	for i, row := range rows {
		ruleID, _ := row["rule_id"].(string)
		if ruleID == "" {
			continue // 行级引用门已先行 400，防御性跳过
		}
		pathRule := models.PathRule{
			SortOrder:    backupInt(row["sort_order"]),
			MatchType:    backupString(row["match_type"]),
			Path:         backupString(row["path"]),
			UpstreamPath: backupString(row["upstream_path"]),
			// 静态响应/301 跳转（2026-10-10）：缺键=零值=转发形态（旧备份天然兼容）
			ResponseMode:        backupString(row["response_mode"]),
			ResponseStatus:      backupInt(row["response_status"]),
			ResponseBody:        backupString(row["response_body"]),
			ResponseContentType: backupString(row["response_content_type"]),
			RedirectTo:          backupString(row["redirect_to"]),
		}
		if raw, ok := row["upstreams_json"].(string); ok && raw != "" {
			if err := json.Unmarshal([]byte(raw), &pathRule.Upstreams); err != nil {
				return nil, fmt.Errorf("规则 %s 的路径规则行 #%d upstreams_json 无法解析: %w", ruleID, i+1, err)
			}
		}
		byRule[ruleID] = append(byRule[ruleID], pathRule)
	}
	return byRule, nil
}

// validateCredentialsJSONObject allows empty strings but requires non-empty values to be JSON objects.
func validateCredentialsJSONObject(raw string) error {
	if raw == "" {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return err
	}
	if obj == nil {
		return errors.New("凭证必须是 JSON 对象，不能为 null")
	}
	return nil
}

// normalizeBackupRequestBodyMB 将备份中的整数/数值字符串/畸形形态统一
// 归一为整型 MB 值；min=1 用于全局设置，min=0 用于规则级覆盖。
func normalizeBackupRequestBodyMB(value any, min, fallback int) int {
	n, ok := backupInteger(value)
	if !ok || n < min {
		return fallback
	}
	if n > maxRequestBodySizeMB {
		return maxRequestBodySizeMB
	}
	return n
}

func backupInt(value any) int {
	if v, ok := backupInteger(value); ok {
		return v
	}
	return 0
}

func backupInteger(value any) (int, bool) {
	switch value := value.(type) {
	case float64:
		if value == math.Trunc(value) && value >= math.MinInt && value <= math.MaxInt {
			return int(value), true
		}
	case int:
		return value, true
	case int64:
		if value >= math.MinInt && value <= math.MaxInt {
			return int(value), true
		}
	case string:
		// 字符串形态数值（如 "99999999999"）——此前返回!ok 使
		// 钳制点静默跳过，SQLite INTEGER 亲和性照样落库大整数，绕过钳制的
		// 唯一残留向量。解析后钳制点即可正常钳位；解析失败维持 !ok（由
		// 各调用方按非法形态处理）。
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return n, true
		}
	}
	return 0, false
}

// skipEmptyDomainHTTPRules 移除域名为空的 HTTP 规则及其关联行（上游/路径规则/证书任务/
// 安全策略绑定），返回跳过警告；TCP 规则无需域名，不受影响。
// 关联表须含 security_policy_bindings 且其规则列名为 rule_caddy_id（其余为
// rule_id）——漏掉该表会让跳过在 validateBackupRuleReferences 之前把规则移出
// lb_rules，其绑定命中「引用了不存在的规则」整包 400，与软跳过语义冲突。
func skipEmptyDomainHTTPRules(tables map[string][]map[string]any) []string {
	rows, exists := tables["lb_rules"]
	if !exists {
		return nil
	}
	skippedIDs := map[string]bool{}
	warnings := []string{}
	kept := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		protocol, _ := row["protocol"].(string)
		domain, _ := row["domain"].(string)
		// 空 protocol（非法但 v1 备份可能存在）也按 HTTP 处理，避免绕过空域名跳过逻辑。
		if (protocol != "http" && protocol != "") || strings.TrimSpace(domain) != "" {
			kept = append(kept, row)
			continue
		}
		caddyID, _ := row["caddy_id"].(string)
		name, _ := row["name"].(string)
		if name == "" {
			name = caddyID
		}
		skippedIDs[caddyID] = true
		warnings = append(warnings, fmt.Sprintf("规则 %s 的域名为空，已跳过导入", name))
	}
	if len(skippedIDs) == 0 {
		return nil
	}
	tables["lb_rules"] = kept
	// 表 → 引用规则的列名；security_policy_bindings 的规则列为 rule_caddy_id
	ruleRefTables := []struct {
		table  string
		column string
	}{
		{"upstreams", "rule_id"},
		{"path_rules", "rule_id"},
		{"cert_jobs", "rule_id"},
		{"security_policy_bindings", "rule_caddy_id"},
	}
	droppedBindings := 0
	for _, ref := range ruleRefTables {
		related, exists := tables[ref.table]
		if !exists {
			continue
		}
		filtered := make([]map[string]any, 0, len(related))
		for _, row := range related {
			ruleID, _ := row[ref.column].(string)
			if skippedIDs[ruleID] {
				if ref.table == "security_policy_bindings" {
					droppedBindings++
				}
				continue
			}
			filtered = append(filtered, row)
		}
		tables[ref.table] = filtered
	}
	if droppedBindings > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 条安全策略绑定随空域名规则一并跳过", droppedBindings))
	}
	return warnings
}

// skipEmptyBlockPages 移除 content 为空/纯空白（含缺省与 NULL）的
// security_block_pages 行，返回跳过警告（与
// skipEmptyDomainHTTPRules 同款软跳过口径）：手造备份 content:"" 原样
// 落库后，引用该页的 WAF/GeoIP/限流拦截渲染空响应体，静默退化为 Caddy
// 原生 403。被跳过页面的悬挂 block_page_id 引用沿用口径
// （运行时 JOIN 语义，悬挂不产出规则）；全表跳空时默认页由导入事务内
// 重播种 + SeedDefaultBlockPage 渲染兜底。
func skipEmptyBlockPages(tables map[string][]map[string]any) []string {
	rows, exists := tables["security_block_pages"]
	if !exists {
		return nil
	}
	warnings := []string{}
	kept := make([]map[string]any, 0, len(rows))
	skipped := map[int]struct{}{}
	for _, row := range rows {
		content, _ := row["content"].(string)
		if strings.TrimSpace(content) != "" {
			kept = append(kept, row)
			continue
		}
		name, _ := row["name"].(string)
		if name == "" {
			name = fmt.Sprintf("#%v", row["id"])
		}
		if id := backupInt(row["id"]); id > 0 {
			skipped[id] = struct{}{}
		}
		warnings = append(warnings, fmt.Sprintf("拦截页面 %s 的内容为空，已跳过导入", name))
	}
	if len(warnings) == 0 {
		return nil
	}
	tables["security_block_pages"] = kept
	// 被跳过页面的引用必须同步清空：后续 validateBackupRuleReferences/
	// validateV2BackupRules 以「页不存在」整包 400，软跳过契约失效
	// 清空 id/status 与运行时 JOIN 无页等效（默认页兜底）。
	if len(skipped) > 0 {
		for _, rule := range tables["lb_rules"] {
			for _, pair := range [][2]string{{"block_page_stage1_id", "block_page_stage1_status"}, {"block_page_stage3_id", "block_page_stage3_status"}} {
				if _, hit := skipped[backupInt(rule[pair[0]])]; hit {
					rule[pair[0]] = 0
					rule[pair[1]] = 0
				}
			}
		}
		for _, policy := range tables["security_policies"] {
			if _, hit := skipped[backupInt(policy["block_page_id"])]; hit {
				policy["block_page_id"] = 0
			}
		}
	}
	return warnings
}

// normalizeBlockPageContentTypes 把导入备份中 security_block_pages.content_type
// 的白名单外值归一为默认 text/html; charset=utf-8（用户裁定，
// 与 mode 枚举门同口径的导入侧值域收敛）——CRUD 写侧有
// models.ValidBlockPageContentType 把守，备份导入是带外通道：手造备份可将
// 含 CRLF 的任意字符串落库为 content_type 渲染进响应头。渲染侧
// blockPageContentType 另有白名单回退双保险。
func normalizeBlockPageContentTypes(tables map[string][]map[string]any) {
	rows, exists := tables["security_block_pages"]
	if !exists {
		return
	}
	for _, row := range rows {
		// 非字符串值静默归一默认（有意从宽，与 skipEmptyBlockPages 软跳过同
		// 哲学：导入鲁棒性优先，值域收敛不落 400——与 mode 枚举门「非字符串
		// 拒绝」口径不同属有意差异，裁定保留）。
		contentType, _ := row["content_type"].(string)
		if !models.ValidBlockPageContentType(contentType) {
			row["content_type"] = models.DefaultBlockPageContentType
		}
	}
}

// canonicalizeBackupRuleDomains 在冲突矩阵之前把 HTTP 规则域名归一为规范形式
// （与 validateV2BackupRules 同口径：idna 小写/punycode/去重）。冲突键依赖
// 规范化域名，后续矩阵与逐行校验不能对大小写/IDN 变体误判为不同域
// 不可归一的域名保持原值，交由随后逐行校验 400。
func canonicalizeBackupRuleDomains(rows []map[string]any) {
	for _, rule := range rows {
		protocol, _ := rule["protocol"].(string)
		if protocol != "http" && protocol != "" {
			continue
		}
		if canonical, err := db.CanonicalDomains(backupString(rule["domain"])); err == nil {
			rule["domain"] = canonical
		}
	}
}

func disableV2RuleConflicts(rows []map[string]any) []disabledRuleConflict {
	candidates := make([]ruleConflictCandidate, len(rows))
	for index, row := range rows {
		candidates[index] = newRuleConflictCandidate(
			backupString(row["name"]), backupString(row["caddy_id"]), backupString(row["protocol"]), backupString(row["domain"]),
			backupInt(row["listen_port"]),
			// 与校验侧 backupRuleEnabled 同口径——
			// 手造备份缺 enabled 列时按表结构 COALESCE(enabled,1) 视为启用；此前用
			// backupBooleanEnabled 缺键按禁用，门控下校验按启用、矩阵按禁用跳过，
			// 两条同端口同域名规则双双启用导入、运行时相互遮蔽。
			backupRuleEnabled(row), backupBooleanEnabled(row["enable_tls"]), backupBooleanEnabled(row["tls_http_redirect"]),
		)
	}
	conflicts := validateRuleConflictMatrix(candidates)
	for _, conflict := range conflicts {
		rows[conflict.index]["enabled"] = 0
	}
	return conflicts
}

// backupConfigClampRule 导入侧整型配置钳制规格（同族钳制段收敛为单表，新增
// 配置键只需登记一行）。mode 语义：
//   - clampToBound（默认）：越界钳到最近边界（日志大小/保留月数/证书参数族）
//   - resetDefault：越界一律回退默认值（jwt 过期分钟：越界与非法同待遇）
//   - ResetOnLow：低于下界一律回退 Def（http 三超时：0/NULL 是旧省略语义残留，
//     不是用户选择，钳到 1 会产生一个虚假的极小值）
//
// Hi=0 表示无上界（http 三超时；写侧同样无上界，导入不得新造上界）。
// 非整数形态一律回退 Def（与 schema 缺省/显示侧 COALESCE 对齐）。
type backupConfigClampRule struct {
	Key         string
	Lo, Hi      int
	Def         int
	ResetOnHigh bool
	ResetOnLow  bool
}

var backupConfigClampRules = []backupConfigClampRule{
	{Key: "jwt_expire_minutes", Lo: 1, Hi: 1440, Def: 20, ResetOnHigh: true, ResetOnLow: true},
	{Key: "audit_retention_months", Lo: 1, Hi: 12, Def: 3, ResetOnLow: true},
	{Key: "caddy_log_size_mb", Lo: 100, Hi: 10240, Def: 100},
	{Key: "audit_log_size_mb", Lo: 1, Hi: 512, Def: 10},
	{Key: "task_log_size_mb", Lo: 1, Hi: 1024, Def: 10},
	{Key: "runtime_log_size_mb", Lo: 1, Hi: 1024, Def: 100},
	// 续签/有效期数值（与写侧 caddy.go 校验同边界）：cert_renewal_days 超大值
	// 会让续签扫描窗口覆盖一切证书（续签成功后仍在窗口内 → 永久续签风暴耗尽
	// CA 配额）；负值漂移 Keep/Resume 决策。0=默认 30（不参与下界钳制）。
	{Key: "cert_renewal_days", Lo: 0, Hi: services.CertRenewalDaysMax, Def: 30},
	{Key: "cert_renewal_attempts", Lo: 1, Hi: 10, Def: 5},
	{Key: "cert_expiry_days", Lo: 1, Hi: 365, Def: 30},
	// 库值唯一真相（批 1+2）：http 三超时为类型①值型列（NOT NULL DEFAULT
	// 60/60/120+启动回填）——旧备份的 0/NULL（省略语义时代残留）在导入门归
	// 治理默认；写侧无上界，故 Hi=0。本表是这三键的唯一导入门：负值/0/非法
	// 形态统一归默认并留审计（ResetOnLow 覆盖负值与 0），不再另设 400 门。
	{Key: "http_read_timeout", Lo: 1, Hi: 0, Def: db.DefaultHTTPReadTimeout, ResetOnLow: true},
	{Key: "http_write_timeout", Lo: 1, Hi: 0, Def: db.DefaultHTTPWriteTimeout, ResetOnLow: true},
	{Key: "http_idle_timeout", Lo: 1, Hi: 0, Def: db.DefaultHTTPIdleTimeout, ResetOnLow: true},
	// upstream_keepalive_timeout 同为「0=继承」省略型列（写侧拒绝负值、无上界）：
	// 负值按越界钳到 0、非整数按非法形态归 0，两条说明与其余键同源进
	// ConfigClampNotes（预览 warning 与导入成功审计双通道）。此前该键在运行期
	// 设置门内静默归零——预览「可导入无提示」而落库值已变。
	{Key: "upstream_keepalive_timeout", Lo: 0, Hi: 0, Def: 0},
}

// clampBackupConfigInts 按 backupConfigClampRules 就地钳制全局配置区，返回
// 审计留痕（越界/非法形态各一条，文案与历史逐键文本同口径）。
func clampBackupConfigInts(config map[string]any) []string {
	if config == nil {
		return nil
	}
	var notes []string
	for _, rule := range backupConfigClampRules {
		value, exists := config[rule.Key]
		if !exists || value == nil {
			continue
		}
		n, ok := backupInteger(value)
		if !ok {
			config[rule.Key] = rule.Def
			notes = append(notes, fmt.Sprintf("%s 非法形态，已重置为 %d", rule.Key, rule.Def))
			continue
		}
		if rule.ResetOnLow && n < rule.Lo {
			config[rule.Key] = rule.Def
			notes = append(notes, fmt.Sprintf("%s 非法（须为正整数），已归默认 %d", rule.Key, rule.Def))
			continue
		}
		if rule.Hi == 0 {
			// 无上界：只校验下界（越下界按钳到边界处理）。
			if n >= rule.Lo {
				continue
			}
		} else if n >= rule.Lo && n <= rule.Hi {
			continue
		}
		if rule.ResetOnHigh && n > rule.Hi {
			config[rule.Key] = rule.Def
			notes = append(notes, fmt.Sprintf("%s 越界，已重置为 %d", rule.Key, rule.Def))
			continue
		}
		clamped := n
		if clamped < rule.Lo {
			clamped = rule.Lo
		}
		if clamped > rule.Hi {
			clamped = rule.Hi
		}
		config[rule.Key] = clamped
		notes = append(notes, fmt.Sprintf("%s 越界（%d），已钳位为 %d", rule.Key, n, clamped))
	}
	return notes
}

// clearDeletedNodeStateBeforeRestore
// 节点拓扑整体替换（DELETE FROM nodes + 重插备份行）之前，按 ip:port 身份
// 找出「本地有而备份无」的将被删除节点，清除其 TOFU 指纹钉（文件+内存缓存，
// 与 ForgetClusterNodePin 端点同口径：ForgetNodePin 解析地址删文件 +
// ForgetNodePinCache 清内存）与分区上报缓存（ClearNodeSectionReports）。
// 备份仍携带的节点 pin/上报一律保留。
//
// 必须在 DELETE 之前执行：ForgetNodePin 需按现存行解析访问地址。若导入随后
// 回滚，已清 pin 在下次服务控制按 TOFU 重新钉扎（幂等无害）；分区上报缓存
// 随下次上报（≤60s）重建。清理失败仅留痕不否决导入（与 DeleteNode 的 pin
// 清理同口径）；返回完成清理的节点数供成功审计留痕。
func (h *Handlers) clearDeletedNodeStateBeforeRestore(ctx context.Context, tx *sql.Tx, backupRows []map[string]any) int {
	surviving := nodeSurvivingIdentities(backupRows)
	rows, err := tx.QueryContext(ctx, `SELECT id, ip_address, COALESCE(port,8000) FROM nodes`)
	if err != nil {
		services.Logf("warn", "配置导入：读取本地节点身份失败（已删除节点 pin/分区上报清理跳过）: %v", err)
		return 0
	}
	type localNode struct {
		id  int
		key string
	}
	locals := []localNode{}
	for rows.Next() {
		var node localNode
		var ip string
		var port int
		if err := rows.Scan(&node.id, &ip, &port); err != nil {
			_ = rows.Close()
			services.Logf("warn", "配置导入：扫描本地节点身份失败（已删除节点清理跳过）: %v", err)
			return 0
		}
		node.key = ip + ":" + strconv.Itoa(port)
		locals = append(locals, node)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		services.Logf("warn", "配置导入：读取本地节点身份失败（已删除节点清理跳过）: %v", err)
		return 0
	}
	_ = rows.Close()
	cleared := 0
	for _, node := range locals {
		if surviving[node.key] {
			continue
		}
		host, pinErr := h.clusterService.ForgetNodePin(ctx, node.id)
		switch {
		case pinErr == nil:
			if h.syncService != nil {
				h.syncService.ForgetNodePinCache(host)
			}
		case errors.Is(pinErr, services.ErrNoClusterPin) || errors.Is(pinErr, services.ErrNodeNotFound):
			// 无钉可删（http 地址/从未服务控制）——幂等语义，照常清理上报缓存。
		default:
			services.Logf("warn", "配置导入：清除已删除节点 %d 的证书指纹钉失败: %v", node.id, pinErr)
		}
		services.ClearNodeSectionReports(db.DB, node.id)
		cleared++
	}
	return cleared
}

// nodeSurvivingIdentities 把备份 nodes 行映射为「导入后仍存活」的 ip:port
// 身份键集合。port 缺键/NULL 必须取与落库同源的
// 默认值（backupTableNullDefaults["nodes"]["port"]，schema DEFAULT 8000）——
// 此前缺 port 行在存活集中缺席，而 restoreTable 仍按默认 8000 落库，导致
// 「备份带 ip:8000 节点且本地同身份节点实际存活」时其 TOFU 指纹钉与分区上报
// 缓存被误清（无安全后果，但产生无谓 churn）。扫描侧的本地键同为
// COALESCE(port,8000)，三处口径一致。
func nodeSurvivingIdentities(backupRows []map[string]any) map[string]bool {
	surviving := make(map[string]bool, len(backupRows))
	for _, row := range backupRows {
		// 行级门已先行 400，此处全为合法形态；防御性跳过缺身份行。
		ip := backupString(row["ip_address"])
		if ip == "" {
			continue
		}
		port, ok := backupInteger(row["port"])
		if !ok {
			port = backupInt(backupTableNullDefaults["nodes"]["port"])
		}
		surviving[ip+":"+strconv.Itoa(port)] = true
	}
	return surviving
}

// reconcileImportNodeTokens 在 nodes 全表替换前按 (ip_address,port) 与本地现存
// 节点比对：身份匹配且本地持有令牌时保留本地 cluster_token_hash / is_approved /
// cluster_token_delivered（备份只提供坐标/名称/同步间隔等拓扑属性）。否则跨环境
// 导入或「回滚旧备份」会把备份里的旧令牌哈希覆盖到仍存活的节点行上，真实从节点
// 令牌立即 401，从端按终止类停止重试，全集群需人工重新审批。
// 返回「备份令牌被忽略」的节点数（用于 warnings + 审计）。本地无该身份（真正
// 灾备到新机）时沿用备份令牌，保持灾备主路径不变。
func reconcileImportNodeTokens(ctx context.Context, tx *sql.Tx, rows []map[string]any) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	type liveNodeToken struct {
		hash      string
		approved  int
		delivered int
	}
	live := make(map[string]liveNodeToken)
	liveRows, err := tx.QueryContext(ctx, `SELECT COALESCE(ip_address,''), COALESCE(port,8000),
		COALESCE(cluster_token_hash,''), COALESCE(is_approved,0), COALESCE(cluster_token_delivered,0) FROM nodes`)
	if err != nil {
		return 0, fmt.Errorf("读取本地节点令牌: %w", err)
	}
	for liveRows.Next() {
		var ip, hash string
		var port, approved, delivered int
		if err := liveRows.Scan(&ip, &port, &hash, &approved, &delivered); err != nil {
			liveRows.Close()
			return 0, err
		}
		if ip == "" {
			continue
		}
		live[ip+":"+strconv.Itoa(port)] = liveNodeToken{hash: hash, approved: approved, delivered: delivered}
	}
	if err := liveRows.Err(); err != nil {
		liveRows.Close()
		return 0, err
	}
	liveRows.Close()

	ignored := 0
	for _, row := range rows {
		ip := backupString(row["ip_address"])
		if ip == "" {
			continue
		}
		// port 缺键/NULL 取与落库同源默认（backupTableNullDefaults），与
		// nodeSurvivingIdentities 口径一致。
		port, ok := backupInteger(row["port"])
		if !ok {
			port = backupInt(backupTableNullDefaults["nodes"]["port"])
		}
		local, exists := live[ip+":"+strconv.Itoa(port)]
		if !exists || local.hash == "" {
			continue
		}
		if backupHash := backupString(row["cluster_token_hash"]); backupHash != "" && backupHash != local.hash {
			ignored++
		}
		row["cluster_token_hash"] = local.hash
		row["is_approved"] = local.approved
		row["cluster_token_delivered"] = local.delivered
	}
	return ignored, nil
}

// importAttributionTables 全部引用 users.id 的归属列（lb_rules 两列 + 安全四表；
// api_keys.created_by 随 users 分节同批替换、cluster_register_tokens 不在备份面，
// 均不入列）。
var importAttributionTables = map[string][]string{
	"lb_rules":              {"created_by", "updated_by"},
	"security_policies":     {"updated_by"},
	"security_ip_lists":     {"created_by", "updated_by"},
	"security_block_pages":  {"created_by", "updated_by"},
	"security_custom_rules": {"updated_by"},
}

// snapshotImportUserNames 在 users 全表替换前快照本地 id→username，供导入后
// 判断归属列是否「换了人」。读失败仅留痕（告警降级，不影响导入）。
func snapshotImportUserNames(ctx context.Context, tx *sql.Tx) map[int]string {
	names := make(map[int]string)
	rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(username,'') FROM users`)
	if err != nil {
		services.Logf("warn", "配置导入：快照本地用户名失败（归属告警跳过）: %v", err)
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			services.Logf("warn", "配置导入：扫描本地用户名失败（归属告警跳过）: %v", err)
			return nil
		}
		names[id] = name
	}
	if err := rows.Err(); err != nil {
		services.Logf("warn", "配置导入：遍历本地用户名失败（归属告警跳过）: %v", err)
		return nil
	}
	return names
}

// snapshotImportPasswordVersions 在 users 全表替换前保存各 id 的 live 版本。
// 还原旧备份后的吊销版本必须取 max(live, backup)+1，而不是只对备份值 +1；
// 否则备份时点之后签发的 JWT 会在还原后继续通过 pwd_ver 校验。
func snapshotImportPasswordVersions(ctx context.Context, tx *sql.Tx) (map[int]int64, error) {
	versions := make(map[int]int64)
	rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(password_version,0) FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var version int64
		if err := rows.Scan(&id, &version); err != nil {
			return nil, err
		}
		versions[id] = version
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return versions, nil
}

// collectImportAttributionMismatches 统计「users 已替换、但该归属表未随包替换」
// 时归属 id 指向的人发生变化的行数：同 id 在导入用户集中换成了另一位用户，或
// 该 id 已不在导入用户集中。只统计导入引入的变化——本地与导入两侧都缺失的
// 「—」不算。用户名变化也可能只是重命名（合法），因此只告警/审计，不改写。
func collectImportAttributionMismatches(ctx context.Context, tx *sql.Tx, tables map[string][]map[string]any, localUserNames map[int]string) int {
	importedUserNames := make(map[int]string)
	for _, row := range tables["users"] {
		id, ok := backupInteger(row["id"])
		if !ok {
			continue
		}
		importedUserNames[id] = backupString(row["username"])
	}
	total := 0
	for table, columns := range importAttributionTables {
		if _, replaced := tables[table]; replaced {
			// 表随包替换：归属值来自同一份备份，与本包用户集自洽。
			continue
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(columns, ", ")+" FROM "+table)
		if err != nil {
			services.Logf("warn", "配置导入：读取 %s 归属列失败（归属告警跳过）: %v", table, err)
			return total
		}
		values := make([]sql.NullInt64, len(columns))
		targets := make([]any, len(columns))
		for index := range values {
			targets[index] = &values[index]
		}
		for rows.Next() {
			if err := rows.Scan(targets...); err != nil {
				services.Logf("warn", "配置导入：扫描 %s 归属列失败（归属告警跳过）: %v", table, err)
				break
			}
			mismatched := false
			for _, value := range values {
				if !value.Valid || value.Int64 == 0 {
					continue
				}
				id := int(value.Int64)
				if localUserNames[id] != importedUserNames[id] {
					mismatched = true
					break
				}
			}
			if mismatched {
				total++
			}
		}
		rows.Close()
	}
	return total
}

// suppressImportClusterVersionBumps 在导入事务内暂时把 is_master 置为 0，
// 使既有行级触发器跳过逐行 cluster_version 写放大；提交前由返回的 restore
// 恢复角色。读取/恢复都采用 COALESCE(is_master,1) 单源口径（NULL 视为主节点，
// 与 RoleOf/写闸/触发器一致）。coordinator 的显式 BumpClusterVersion 因而成为
// 唯一一次版本递增。该角色变化只在未提交事务可见，任何 abort 都随 ROLLBACK 消失。
func suppressImportClusterVersionBumps(ctx context.Context, tx *sql.Tx) (restore func() error, err error) {
	var role int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(is_master,1) FROM global_config WHERE id=1`).Scan(&role); err != nil {
		return nil, fmt.Errorf("读取导入前节点角色: %w", err)
	}
	if role == 0 {
		return func() error { return nil }, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		return nil, fmt.Errorf("抑制导入逐行集群版本写入: %w", err)
	}
	restored := false
	return func() error {
		if restored {
			return nil
		}
		result, err := tx.ExecContext(ctx, `UPDATE global_config SET is_master=1 WHERE id=1`)
		if err != nil {
			return fmt.Errorf("恢复导入前节点角色: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return fmt.Errorf("恢复导入前节点角色命中 %d 行（err=%v）", affected, err)
		}
		restored = true
		return nil
	}, nil
}

// installImportVersionSentinels 在导入事务内为「未导入且导入前无行」的版本表
// 写入临时哨兵行（auto_update=0），阻止提交后的首槽 rearm 补真实种子行。
func installImportVersionSentinels(ctx context.Context, tx *sql.Tx, tables map[string][]map[string]any, libraryImported bool, existedBefore map[string]bool) error {
	if !libraryImported {
		return nil
	}
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		if _, imported := tables[table]; imported || existedBefore[table] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO `+table+` (id, version, auto_update) VALUES (1, ?, 0)`, importVersionSeedSentinel); err != nil {
			return fmt.Errorf("写入 %s 导入占位行: %w", table, err)
		}
	}
	return nil
}

// removeImportVersionSentinel 仅删除本次导入写入且仍保持哨兵形态的行——任何
// 并发更新（版本/开关/状态/排程变化）都会使 CAS 条件失配，行保留给真实写者。
func removeImportVersionSentinel(ctx context.Context, table string) (bool, error) {
	result, err := db.DB.ExecContext(ctx, `DELETE FROM `+table+` WHERE id=1 AND version=? AND COALESCE(auto_update,1)=0
		AND COALESCE(next_update,'')='' AND COALESCE(update_status,'') IN ('','idle')`, importVersionSeedSentinel)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

// cleanupImportVersionSentinels 撤销本次导入写入的临时版本种子行
// （security_crs_version/security_ip2region_version）。
// 提交已落地，清理必须与请求生命周期解耦：前端超时/关页/网关断连会让请求
// ctx 取消，残留哨兵行 auto_update=0 且不被 rearm 补槽（自动更新静默停摆）。
// 与 collectPostCommitCleanup 同口径：WithoutCancel + 独立预算。
func cleanupImportVersionSentinels(ctx context.Context, tables []string) {
	for _, table := range tables {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), importCleanupBudget)
		removed, err := removeImportVersionSentinel(cleanupCtx, table)
		cancel()
		if err != nil {
			services.Logf("warn", "配置导入：撤销 %s 版本种子行失败: %v", table, err)
		} else if !removed {
			services.Logf("info", "配置导入：%s 占位行已被并发更新，保留该行", table)
		}
	}
}

// errUnknownBackupSection:buildLbbakExport 的 4xx 语义哨兵——薄壳端点据此
// 保持原 400 文案,其余错误一律 500「导出失败: …」。分类合并后
// 「仅全局配置」形态不可达(global_config 是 users 别名,恒有表),
// errGlobalOnlyBackup 哨兵随一并撤销。
var errUnknownBackupSection = errors.New("未知的配置分类")

// buildLbbakExport 生产 lbbak 备份净荷(纯逻辑:无 HTTP、无审计)。sel 为空
// 表示全部分类;返回净荷字节、实际导出分类(空选择归一为全部分类)、各表
// 行数摘要(与导入审计同文案)与是否包含规则库文件本体。HTTP 导出端点与
// 自动/手动备份执行器(autobackup.go)共用。
func (h *Handlers) buildLbbakExport(ctx context.Context, sel []string) (payload []byte, exportedSections []string, countsSummary string, includesWafFiles bool, err error) {
	sel = normalizeBackupSectionKeys(sel)
	sectionTables, includeGlobal, ok := configBackupSectionTables(sel)
	if !ok {
		return nil, nil, "", false, errUnknownBackupSection
	}
	// 实际导出分类（空选择=全部分类）写入包体 Sections——还原/导入/
	// 预览按该值过滤，不再依赖 ?sections= query 或恒「全选」。
	exportedSections = append([]string(nil), sel...)
	if len(exportedSections) == 0 {
		for _, sec := range configBackupSections {
			exportedSections = append(exportedSections, sec.Key)
		}
	}
	backup := configBackup{
		Sections: exportedSections,
		Meta:     configBackupMeta{App: "lazy-balancer-v2", Version: 3, AppVersion: h.cfg.Version, ExportedAt: time.Now().UTC().Format(time.RFC3339)},
		Tables:   map[string][]map[string]any{},
	}
	// DB 快照与 WAF 文件 bundle 必须来自同一稳定代。锁序
	// wafFileMu→DB 与 CRS/威胁库更新器一致（写者在同一锁内写文件与版本行）。
	wafFilePhase := sectionTables["security_crs_version"]
	wafLocked := wafFilePhase
	if wafLocked {
		services.WafFileLock().Lock()
		defer func() {
			if wafLocked {
				services.WafFileLock().Unlock()
			}
		}()
	}
	tx, err := db.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, nil, "", false, err
	}
	configRows, err := dumpTable(ctx, tx, "global_config")
	if err != nil {
		return nil, nil, "", false, errors.Join(err, tx.Rollback())
	}
	if len(configRows) > 0 && includeGlobal {
		backup.Config = configRows[0]
		for key := range configBackupProtectedConfigKeys {
			delete(backup.Config, key)
		}
	}
	for _, table := range configBackupTables {
		if !sectionTables[table] {
			continue
		}
		rows, err := dumpTable(ctx, tx, table)
		if err != nil {
			return nil, nil, "", false, errors.Join(err, tx.Rollback())
		}
		if table == "nodes" {
			sanitizeNodeRowsForExport(rows)
		}
		backup.Tables[table] = rows
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, "", false, err
	}
	if configBackupExportAfterDBSnapshot != nil {
		configBackupExportAfterDBSnapshot()
	}
	var bundle *services.WafFileBundle
	var threatSnapshot map[string][]byte
	if wafFilePhase {
		var complete bool
		bundle, complete = services.BuildWafFileBundleInLockChecked()
		if !complete {
			// 缺件包（瞬时读失败）不得静默导出——恢复时
			// 会静默缺少 CRS/xdb/威胁名单，且 manifest 只覆盖已写入条目。
			return nil, nil, "", false, fmt.Errorf("规则库文件读取不完整（CRS/IP2Region/威胁名单存在瞬时读失败），已中止导出，请重试")
		}
		threatSnapshot, err = snapshotLbbakThreatIplists(bundle)
		if err != nil {
			return nil, nil, "", false, err
		}
	}
	// 锁内只物化稳定代（DB 行 + WAF 文件字节 + 威胁名单原文）；JSON/校验和/
	// manifest 哈希/tar/gzip 全部在锁外对内存快照执行，缩短阻塞三库更新的窗口。
	if wafLocked {
		services.WafFileLock().Unlock()
		wafLocked = false
	}
	checksumPayload, err := configBackupChecksumPayload(backup)
	if err != nil {
		return nil, nil, "", false, err
	}
	sum := sha256.Sum256(checksumPayload)
	backup.Meta.Checksum = hex.EncodeToString(sum[:])
	// v2.3.0(用户裁定 2026-09-18):导出恒为 lbbak tar.gz 包——勾选「规则库
	// 数据库」时附 CRS/IP2Region 文件本体,未勾选时仅 config.json;纯 JSON 仅作
	// 旧备份导入兼容,不再产出。
	backupJSON, err := json.Marshal(backup)
	if err != nil {
		return nil, nil, "", false, err
	}
	payload, err = buildLbbakPayloadWithThreatIplists(backupJSON, bundle, threatSnapshot)
	if err != nil {
		return nil, nil, "", false, err
	}
	return payload, exportedSections, importCountsDetail(backup.Tables), bundle != nil, nil
}

func (h *Handlers) ExportConfigBackup(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	// 导入窗口门：security 分类导出会取 WafFileLock，而导入从 prelock 到 close
	// 全程持有该锁——不接门就会在导入期间阻塞至导入结束（排空 30s 上限 + 提交
	// 渲染/load），客户端易超时截断下载。与同族写者一致 409 fast-fail。
	if rejectWriteDuringImport(c, "导出配置备份") {
		return
	}
	qs := c.Query("sections")
	sel := parseSectionsParam(qs)
	if qs == "" {
		sel = nil
	}
	payload, _, countsSummary, includesWafFiles, err := h.buildLbbakExport(c.Request.Context(), sel)
	if err != nil {
		status := http.StatusInternalServerError
		message := "导出失败: " + err.Error()
		if errors.Is(err, errUnknownBackupSection) {
			status = http.StatusBadRequest
			message = err.Error()
		}
		c.JSON(status, models.APIResponse{Code: status, Message: message})
		return
	}
	detail := "导出为完整备份（含凭证与证书材料），请妥善保管"
	if includesWafFiles {
		detail = "导出为完整备份（lbbak，含规则库文件、凭证与证书材料），请妥善保管"
	}
	recordAudit(c, "导出", "配置备份", services.FormatAuditDetail(countsSummary, detail, services.AuditResultPart("success")))
	writeLbbakResponse(c, payload)
}

func (h *Handlers) ImportConfigBackup(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	if !limitConfigImportBody(c) {
		return
	}
	raw, rerr := io.ReadAll(c.Request.Body)
	if rerr != nil {
		// 读体失败必须携带底层原因——此前以 dataOK=false
		// 交回 core 对原（已半消费）body 走 ShouldBindJSON，transport 读失败退化为
		// 通用「备份文件格式不正确」，排障方向被误导（validate/v1 两路径早已
		// 显式返回「备份文件读取失败: …」/「内容为空」）。
		// 尺寸超限（413）属探测面，不落审计；其余读失败与空体是「被拒绝的导入
		// 尝试」，与核心的事务前校验失败同口径留痕。
		if isRequestBodyTooLarge(rerr) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: configImportLimitMessage()})
			return
		}
		failImportValidation(c, "导入", "备份文件读取失败: "+rerr.Error())
		return
	}
	if len(raw) == 0 {
		failImportValidation(c, "导入", "备份文件内容为空")
		return
	}
	h.importConfigBackupCore(c, raw, "", "导入")
}

const warningPureJSONThreatSourcesPreserved = "纯 JSON 备份不携带威胁名单文件，已保留本地威胁源配置与名单"

// prepareV2BackupSkips 是预览/导入共用的行准备序列。纯 JSON 无法携带威胁
// 名单文件，其源表必须在任何行级门之前剔除（本地表与文件均保留）；空域名
// 规则及空内容拦截页同样先软跳过，避免将被丢弃行的坏布尔/时间戳升级为整包
// 400。checksum 与 sections 过滤已由调用方在此之前完成。
func prepareV2BackupSkips(backup *configBackup, payload *lbbakPayload, sectionTables map[string]bool) ([]string, error) {
	warnings := []string{}
	if rows, carried := backup.Tables["nodes"]; carried {
		sanitizeNodeRowsForRestore(rows)
	}
	if payload == nil && sectionTables["security_crs_version"] {
		if rows, carried := backup.Tables["security_threat_sources"]; carried {
			// 该表虽不导入，仍需拒绝伪造源 URL/名称，防止纯 JSON 通道绕过
			// 威胁源白名单；合法表随后删除并保留本地配置与文件。
			if err := validateImportedThreatSources(rows); err != nil {
				return nil, err
			}
			delete(backup.Tables, "security_threat_sources")
			warnings = append(warnings, warningPureJSONThreatSourcesPreserved)
		}
	}
	warnings = append(warnings, skipEmptyDomainHTTPRules(backup.Tables)...)
	warnings = append(warnings, skipEmptyBlockPages(backup.Tables)...)
	return warnings, nil
}

// importedActiveUpdateStatusMessage 是随备份导入的「更新中」活动态的归一文案：
// 活动态只属于执行该任务的进程，导入节点既不执行也不可能推进到终态——保留
// 活动词会让规则库页/更新弹框长期显示「更新中」（最长到一个排程槽），而任务
// 监控同任务显示空闲。与快照搬运归一文案同族但归属不同（备份而非主端快照）。
const importedActiveUpdateStatusMessage = "随备份导入的进行中状态，导入节点不执行该任务"

// normalizeImportedVersionUpdateStatuses 导入门归一四张版本/源表的
// update_status 列，两类分流：
//   - 活动态（类判据 services.IsActiveUpdateStatus：版本表四活动词 + 源表
//     running）→ failed + 归属文案。活动态是「类」而非逐词白名单：白名单
//     必然滞后于写侧新增活动词（running 曾被漏掉），而活动态跨进程序列化后
//     没有任何归一通道（装配期归一只在主节点启动执行、导入提交后钩子不做）。
//   - 词表外值（含空串/非字符串形态）→ idle（值域单源
//     services.NormalizeVersionUpdateStatus）。
//
// 行键缺席不动（restoreTable 按 schema DEFAULT 落库）。返回汇总警告（有改动
// 时），供响应/审计展示。
func normalizeImportedVersionUpdateStatuses(tables map[string][]map[string]any) []string {
	carried := 0
	normalized := 0
	for _, table := range []string{"security_crs_version", "security_ip2region_version", "security_threat_sources", "security_crawler_sources"} {
		for _, row := range tables[table] {
			raw, exists := row["update_status"]
			if !exists {
				continue
			}
			value, isString := raw.(string)
			if isString && services.IsActiveUpdateStatus(value) {
				row["update_status"] = string(services.CRSStatusFailed)
				if _, hasMessage := row["message"]; hasMessage {
					row["message"] = importedActiveUpdateStatusMessage
				}
				carried++
				continue
			}
			if isString && value == services.NormalizeVersionUpdateStatus(value) {
				continue
			}
			row["update_status"] = services.NormalizeVersionUpdateStatus(value)
			normalized++
		}
	}
	var warnings []string
	if carried > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 条版本/源记录携带「更新中」活动态，导入节点不执行该任务，已归一为 failed", carried))
	}
	if normalized > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 条版本/源记录的 update_status 不在词表内，已归一为 idle", normalized))
	}
	return warnings
}

// backfillCertJobExpiryFromPEM 为「有效材料但 expires_at 缺失」的证书任务
// 行派生并回填到期时间。列值优先（不覆盖已有值）；不可解析材料跳过。
// 目的：/certificates/jobs 已按 PEM 派生展示，而聚合消费面（节点健康
// certs_expiring_30d、/certificates）仍以列为门——不回填会让同一条证书在
// 两处给出不同到期结论。
func backfillCertJobExpiryFromPEM(ctx context.Context, tx *sql.Tx) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(cert_pem,'') FROM cert_jobs
		WHERE COALESCE(expires_at,'')='' AND `+services.CertJobMaterialPredicateSQL(""))
	if err != nil {
		return 0, err
	}
	type expiryUpdate struct {
		id     int64
		expiry string
	}
	var updates []expiryUpdate
	for rows.Next() {
		var id int64
		var certPEM string
		if err := rows.Scan(&id, &certPEM); err != nil {
			rows.Close()
			return 0, err
		}
		if notAfter, ok := services.CertNotAfterFromPEM(certPEM); ok {
			updates = append(updates, expiryUpdate{id: id, expiry: notAfter.UTC().Format("2006-01-02 15:04:05")})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, update := range updates {
		if _, err := tx.ExecContext(ctx, `UPDATE cert_jobs SET expires_at=? WHERE id=? AND COALESCE(expires_at,'')=''`, update.expiry, update.id); err != nil {
			return 0, err
		}
	}
	return len(updates), nil
}

// failImportAbort 是导入事务内失败收尾的「回滚 → 失败审计」两件套单源：
// 29 处锁内复核/写入分支此前各自内联同一三行块（abort + recordAudit +
// 响应），文案与动作前缀靠人工对齐已出现细微分叉（respondAfterWafFailure 与
// failImportTx 两套）。detailPrefix 为空时详情即错误文本，否则
// 「<前缀>: <错误>」；返回 abort 后的错误供响应文案复用同一文本。
// 响应通道由调用方选择（c.JSON 直写或 WAF 相位后的 respondAfterWafFailure）。
func failImportAbort(c *gin.Context, session *configImportSession, action, detailPrefix string, cause error) error {
	err := session.abort(cause)
	// 审计 detail 全员可见：Caddy 应用阶段失败含 admin 端点原文，剥离后落盘。
	causeDetail := services.RedactCaddyAdminEndpoint(err.Error())
	detail := causeDetail
	if detailPrefix != "" {
		detail = detailPrefix + ": " + causeDetail
	}
	recordAudit(c, action+"失败", "配置备份", detail)
	return err
}

// failImportTx 在 failImportAbort 之上追加响应拼装：「回滚 → 失败审计 → 响应」
// 的完整单一收尾。同函数内其余失败分支均如此；漏接会让该失败面在 audit_log
// 中完全无痕（会话吊销/管理员门/OIDC/配置结构读取恰是运维最需要复盘的面），
// 且各分支各写一份响应文案容易漂移。responsePrefix 为空时直接以错误文本作响应
// （客户端可修正的 400），否则拼「<前缀>，已回滚: <err>」（500）。
func failImportTx(c *gin.Context, session *configImportSession, action, detail string, cause error, status int, responsePrefix string) error {
	err := failImportAbort(c, session, action, detail, cause)
	message := err.Error()
	if responsePrefix != "" {
		message = responsePrefix + "，已回滚: " + err.Error()
	}
	c.JSON(status, models.APIResponse{Code: status, Message: message})
	return err
}

// rowsAffectedOrUnknown 读取执行结果的受影响行数：错误时留痕并按「未知」返回
// known=false。调用方不得把未知当 0——归一计数会把已发生的语义变更（off→
// custom_only 使自定义规则开始生效）静默成「0 条」，重播种计数会把「已插入」
// 误报成「未生效」，两者都直接误导运维与审计。
func rowsAffectedOrUnknown(result sql.Result, action, what string) (int64, bool) {
	counted, err := result.RowsAffected()
	if err != nil {
		services.Logf("warn", "配置%s：读取%s失败（按未知继续，不改判定）: %v", action, what, err)
		return 0, false
	}
	return counted, true
}

// failImportValidation 是导入「事务前」失败分支的单一收尾：审计 + 400。
// 与 failImportTx 对称——篡改备份（校验和不匹配）、伪造/损坏 lbbak 等被
// 拒绝的导入尝试必须在操作审计页可见（V1 导入与集群注册端点同族已如此），
// 否则取证面只剩 stdout 日志。尺寸类探测走 413 分支，不经此处。
func failImportValidation(c *gin.Context, action, detail string) {
	recordAudit(c, action+"失败", "配置备份", detail)
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: detail})
}

// importConfigBackupCore 携带导入全量逻辑,HTTP 导入端点与自动备份还原端点
// (autobackup.go)共用。128MB 压缩上限由 HTTP 调用方 limitConfigImportBody
// 与自动备份还原读取侧共同把守。内存
// 峰值评估——lbbak 解压(gzip 放大,条目上限在读入内存前拦截)+config.json
// 展开为 map+checksum 重 marshal,峰值约上限的 ~10×（约 1.2-1.5GB 瞬态）；
// 导入为管理员手动低频操作，当前不加并发互斥（记录裁定，不再重复评估）。
// data 为调用方已完整读入的备份字节（读体失败由调用方就地返回，不再把半
// 消费的 body 透传进来）；filename 非空时进入审计来源(还原路径);action 为
// 审计动作与结果文案前缀(「导入」/「还原」)。
func (h *Handlers) importConfigBackupCore(c *gin.Context, data []byte, filename, action string) {
	// v2.3.0 lbbak:tar.gz 备份先解包校验,内部 config.json 走既有 V2 流程
	var lbbakFiles *lbbakPayload
	var lbbakUnregisteredThreat []string
	// v2 JSON 备份带 UTF-8 BOM 时预览端点已剥(见
	// config_import_v1.go),导入核心同口径——否则同一份备份预览通过、
	// 导入 400。BOM(\xef\xbb\xbf)与 gzip 魔数(0x1f 0x8b)不冲突,
	// 剥 BOM 必须在 isLbbakBytes 魔数检测之前。
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if isLbbakBytes(data) {
		payload, perr := parseLbbak(data)
		if perr != nil {
			failImportValidation(c, action, perr.Error())
			return
		}
		lbbakFiles = payload
		// manifest 未登记的 threat/*.iplist 条目——老备份兼容照常
		// 落盘，响应/审计侧告警（内容未经 sha256 校验）。
		lbbakUnregisteredThreat = payload.UnregisteredThreatEntries
		c.Request.Body = io.NopCloser(bytes.NewReader(payload.ConfigJSON))
	} else {
		c.Request.Body = io.NopCloser(bytes.NewReader(data))
	}
	var backup configBackup
	if err := c.ShouldBindJSON(&backup); err != nil {
		// 请求体读取在调用方已完成（data 已全量入内存，MaxBytesReader 在
		// 读体路径消费），此处不再存在 413 形态。
		failImportValidation(c, action, "备份文件格式不正确")
		return
	}
	// 完整性 → 分类选择/过滤 → 软跳过 → 行级门 → 形态/引用/任务/全局配置门
	// 全部由 importValidationSteps 单源编排，与预览端点、测试用例同一条链。
	chain, chainErr := validateImportBackupChain(c.Request.Context(), importValidationDeps{
		DB:                     db.DB,
		ValidateRuleListenPort: h.validateRuleListenPortForSave,
	}, &backup, importValidationOptions{LbbakPayload: lbbakFiles, RequestedSections: c.Query("sections")})
	if chainErr != nil {
		// 校验链内的基础设施读失败（受信代理 / 整数列门 / 安全策略 live 回退）
		// 统一 500 + 固定文案；其余仍按 400「备份校验失败」点名。
		if writeImportChainReadFailure(c, chainErr) {
			return
		}
		failImportValidation(c, action, chainErr.Error())
		return
	}
	sectionTables := chain.SectionTables
	skipWarnings := chain.SkipWarnings
	disabledConflicts := chain.DisabledConflicts
	crsTreeReplaced := chain.CRSTreeReplaced
	acmeDanglingImported := chain.ACMEDanglingImported
	certJobProviderWarnings := chain.CertJobProviderWarnings
	autobanClampNotes := chain.AutobanClampNotes
	wafMetadataSkipped := chain.WAFMetadataSkipped
	wafCRSMetadataSkipped := chain.WAFCRSMetadataSkipped
	wafXdbMetadataSkipped := chain.WAFXdbMetadataSkipped
	if chain.UsedLegacyChecksum {
		// 旧格式校验和仅覆盖数据表、不含全局配置区，完整性保障较弱，
		// 显式记审计警告以便追溯（预览端点只读不落审计，避免 UI 选择文件即刷屏）。
		recordAudit(c, action+"警告", "配置备份", "使用旧格式校验和（仅覆盖数据表，不含全局配置）验证备份完整性，建议升级后重新导出备份")
	}
	if chain.NoIntegrityChecksum {
		// 完全没有校验和的史前 v1 备份比「仅数据表校验和」更弱：后者尚有旧格式
		// 警告，前者此前零披露。导入行为不变（结构门全部执行），只补可观测性。
		recordAudit(c, action+"警告", "配置备份", warningNoIntegrityChecksum)
	}
	// 版本表随文件缺失剔除的审计留痕（预览侧同一事实以响应 warning 呈现）。
	if wafMetadataSkipped {
		recordAudit(c, action+"警告", "配置备份", warningWafMetadataSkipped)
	}
	if wafCRSMetadataSkipped {
		recordAudit(c, action+"警告", "配置备份", warningWafCRSMetadataSkipped)
	}
	if wafXdbMetadataSkipped {
		recordAudit(c, action+"警告", "配置备份", warningWafXdbMetadataSkipped)
	}
	// 全局配置数值归一（整型钳制表 + request_body_max_size_mb 专用归一）
	// 已在链内完成——预览与导入共用同一归一点与同一组文案，此处只消费事实。
	configClampNotes := chain.ConfigClampNotes
	ctx := c.Request.Context()
	importUsername := c.GetString("username")
	// 2026-09-18 用户裁定:「备份不含操作者账户」不再硬阻断——①分类导入可
	// 能未选系统数据(操作者仍在);②即使勾了系统数据导致操作者被替换,也尊
	// 重用户选择。降级为响应 warning+审计警告,导入照常(操作者 JWT 由下方
	// password_version 递增吊销,需用备份内账户重新登录)。
	operatorReplaced := false
	// 备份 users 表缺席时,本地用户根本未被触碰——不告警不吊销。
	if importUsername != "" && sectionTables["users"] && len(backup.Tables["users"]) > 0 && !backupContainsUsername(backup.Tables["users"], importUsername) {
		operatorReplaced = true
		recordAudit(c, action+"警告", "配置备份", "备份不含当前操作账户——系统数据将被替换，"+action+"后请使用备份内的管理员账户登录")
	}
	// 反向:导规则不导 cert 配置且备份从未携带 cert 表时,上方 TLS
	// 形态软校验已计数悬挂引用——降级警告进审计(与同格,不阻断)。
	if acmeDanglingImported > 0 {
		recordAudit(c, action+"警告", "配置备份", fmt.Sprintf(action+"后 %d 条启用 ACME 规则的提供商引用悬挂(引用未随备份导入且现有配置缺失)——下一次签发/续签将失败,请补齐 DNS 提供商配置", acmeDanglingImported))
	}
	// 「系统数据」替换 ACME 配置表时,live 启用规则的引用可能悬挂
	// (与删除 409 守卫同果)——预检并降级警告(不阻断,尊重用户选择)。
	// lb_rules 同批替换时跳过预检。预检必须读加锁后的事务视图
	// 锁外读会在「读→取得 caddyOpMu」窗口与规则更新竞态。
	acmeDanglingRules := 0
	// off→custom_only 归一条数（旧语义兼容）：导入把「WAF 关闭 + 挂启用自定义
	// 规则」的策略静默归一为 custom_only（自定义规则从全关变生效）——行为与
	// 启动迁移一致，但必须在响应 warnings 与审计里可见，否则运维只能翻
	// stdout 才能解释业务误拦。
	customOnlyNormalized := int64(0)
	// 导入前快照自动备份开关——提交后仅在 off→on 转换时重置水位线。
	// known=false 表示该列读取失败（未知）——off→on 判定不可信，
	// 跳过水位重置。
	oldAutoBackupEnabled := 0
	oldAutoBackupEnabledKnown := false
	// 导入前快照自动封禁六列——六列是运行期收敛（清桶/重算达标/禁用收尾/
	// 调度联动）的输入，导入走通用 UPDATE 直接落库（绕过
	// services.SetAutobanConfig），提交后必须按「导入前后是否变化」补收敛
	// known=false 表示读取失败或备份未携带该组列（无变化可比）。
	autobanBefore := services.AutobanConfig{}
	autobanBeforeKnown := false
	wafFilePhase := sectionTables["security_crs_version"] && lbbakFiles != nil &&
		(lbbakFiles.CRSTarGz != nil || lbbakFiles.Xdb != nil || len(lbbakFiles.ThreatIplists) > 0)
	// 威胁源表随备份全量替换时，文件收敛（删除空/缺席源的本地旧
	// 名单）也必须在 WafFileLock 内执行——纯 JSON 备份不带任何文件条目，
	// 但表体仍会替换。
	threatFileReconcile := sectionTables["security_crs_version"]
	if _, carried := backup.Tables["security_threat_sources"]; !carried {
		threatFileReconcile = false
	}
	if threatFileReconcile {
		wafFilePhase = true
	}
	if configImportBeforeLock != nil {
		configImportBeforeLock()
	}
	var prelock func() func()
	if wafFilePhase {
		prelock = func() func() {
			services.WafFileLock().Lock()
			return services.WafFileLock().Unlock
		}
	}
	session, err := h.beginConfigImportWithPrelock(ctx, prelock, action)
	if err != nil {
		respondImportBeginError(c, err)
		return
	}
	defer session.close()
	// 失败文案/审计的动作前缀由 begin 时传入的 action 单源携带（导入/还原）。
	tx := session.tx
	// 会话已建立（引擎已暂停、CA 队列已 hold、caddyOpMu 已取、事务已开）：
	// 此后的写入一律走 session.ctx。请求 ctx 只承担排空/取锁阶段的语义——
	// 若核心体仍绑请求 ctx，客户端断连/反代超时（分钟级导入很常见）会让
	// tx.ExecContext 返回 context.Canceled，已开始的导入被整体中止（回滚 +
	// WAF 快照回退），与协调器「会话建立后不得因断连取消」的契约相反。
	ctx = session.ctx
	if configImportAfterSessionHook != nil {
		configImportAfterSessionHook()
	}
	// 初检可能读取 live certificate_configs/ca_providers；从读到
	// 取得 caddyOpMu 的窗口内 DeleteCertificateConfig 可删除被引用行。此处已在
	// 锁内，重跑引用/TLS 形态校验；若初检已有悬挂（soft 警告语义）则不改变其
	// 既有降级口径。
	_, tlsRulesCarried := backup.Tables["lb_rules"]
	_, tlsConfigsCarried := backup.Tables["certificate_configs"]
	_, tlsProvidersCarried := backup.Tables["ca_providers"]
	if tlsRulesCarried && !tlsConfigsCarried && !tlsProvidersCarried && acmeDanglingImported == 0 {
		if _, err := validateV2BackupTLSShapeSoft(backup.Tables, false); err != nil {
			err = failImportAbort(c, session, action, "导入锁内 ACME/TLS 复核失败", err)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "导入期间规则引用的 DNS/CA 配置已失效，已拒绝导入: " + err.Error()})
			return
		}
	}
	if (tlsConfigsCarried || tlsProvidersCarried) && !tlsRulesCarried {
		if rows, qerr := tx.QueryContext(ctx, `SELECT COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0) FROM lb_rules WHERE enabled=1 AND tls_source='acme_dns'`); qerr == nil {
			for rows.Next() {
				var acmeID, caID int
				if rows.Scan(&acmeID, &caID) != nil {
					continue
				}
				if acmeID != 0 && !acmeRefResolvablePostImport(backup.Tables, "certificate_configs", acmeID) {
					acmeDanglingRules++
				} else if caID != 0 && !acmeRefResolvablePostImport(backup.Tables, "ca_providers", caID) {
					acmeDanglingRules++
				}
			}
			rows.Close()
		}
	}
	if acmeDanglingRules > 0 {
		recordAudit(c, action+"警告", "配置备份", fmt.Sprintf(action+"后 %d 条启用 ACME 规则的提供商引用悬挂——下一次签发/续签将失败,请补齐 DNS 提供商配置", acmeDanglingRules))
	}
	// 「系统数据」替换 CA 提供商（或证书配置）而证书任务未随包时，live
	// cert_jobs 的显式 provider 引用不重验：备份里同 id 提供商可为 disabled
	// （真实失败面），也可能整行缺失（caqueue 回落首个启用提供商并自愈）。
	// 两种语义必须分开计数与措辞——混为「续签将失败」对缺失子集是过度断言。
	// 只告警不阻断（「缺席=保留本地」语义不变）。
	certJobProviderDisabled, certJobProviderMissing, certJobProviderCountErr := certJobProviderDanglingCounts(ctx, tx, backup.Tables, sectionTables)
	if certJobProviderCountErr != nil {
		// 计数失败不阻断导入（纯可观测性）：留痕并在响应中显式说明未完成统计。
		services.Logf("warn", "配置导入：证书任务 CA 提供商悬挂统计失败: %v", certJobProviderCountErr)
	}
	// 文案单源（与预览 warnings 同一实现），动作前缀只标明本次操作。
	for _, warning := range certJobProviderDanglingWarnings(certJobProviderDisabled, certJobProviderMissing) {
		recordAudit(c, action+"警告", "配置备份", warning)
	}
	// 初检读取 live 的三项合并校验在锁内重跑（任何写之前）。
	if err := revalidateImportLiveDependencies(ctx, tx, &backup, sectionTables); err != nil {
		err = failImportAbort(c, session, action, "导入锁内实时依赖复核失败", err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "导入期间依赖的实时数据已变化，已拒绝导入: " + err.Error()})
		return
	}
	// 「规则→阶段拦截页」引用同样在锁内重验——初检按锁外 live 页集合
	// 放行后，窗口内删除被备份规则引用的页会让导入后阶段页悬空。
	if err := revalidateImportStageBlockPages(ctx, tx, backup.Tables); err != nil {
		err = failImportAbort(c, session, action, "导入锁内阶段拦截页复核失败", err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "导入期间依赖的实时数据已变化，已拒绝导入: " + err.Error()})
		return
	}
	_, ipListsCarried := backup.Tables["security_ip_lists"]
	_, customRulesCarried := backup.Tables["security_custom_rules"]
	if len(backup.Tables["security_policies"]) > 0 && (!ipListsCarried || !customRulesCarried) {
		// 策略引用的名单/自定义规则表缺席时，初检按 live 回退；该 live 视图
		// 也必须在锁内事务重验，堵住初检到加锁之间删除引用对象的窗口。
		if err := validateV2BackupSecurityPoliciesWithQuerier(ctx, backup.Tables, crsTreeReplaced, tx); err != nil {
			err = failImportAbort(c, session, action, "导入锁内安全策略引用复核失败", err)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "导入期间依赖的实时数据已变化，已拒绝导入: " + err.Error()})
			return
		}
	}
	if db.DB != nil {
		// 读失败不得当作 off——旧形态 `_ = ...Scan()`
		// 吞错、变量保持 0，会把「原本已启用」误判为 off→on，导入后可能重置
		// 自动备份水位线（推迟下一次自动备份至多一个周期）。读失败=未知：跳过
		// 水位重置分支（保守不重置）并留 warn；不升级为导入失败（该列与导入
		// 主体无关）。
		enabled, readErr := readImportOldAutoBackupEnabled(ctx, tx)
		if readErr != nil {
			services.Logf("warn", "配置导入：读取导入前自动备份开关失败，已跳过自动备份水位重置: %v", readErr)
		} else {
			oldAutoBackupEnabled, oldAutoBackupEnabledKnown = enabled, true
		}
	}
	// 六列自动封禁配置的「导入前」快照：仅在备份实际携带该组列时读取（未
	// 携带时通用 UPDATE 不写这些列，运行值不可能变化——省一次点查且避免把
	// 无关导入纳入收敛判定）。读失败=未知：跳过运行期收敛并留痕，不升级为
	// 导入失败（该组列与导入主体无关，误判方向是「少清一次桶」而非数据损坏）。
	if backup.Config != nil && configCarriesAutobanColumns(backup.Config) {
		if cfg, readErr := services.ReadAutobanConfigFrom(ctx, tx); readErr != nil {
			services.Logf("warn", "配置导入：读取导入前自动封禁配置失败，已跳过运行期收敛: %v", readErr)
		} else {
			autobanBefore, autobanBeforeKnown = cfg, true
		}
	}
	// 配套：两版本表单行是否存在同样在加锁后的同一事务快照内读取。
	versionRowExistedBefore := map[string]bool{}
	// 仅记 bool 无法在文件落盘失败时回填导入前本地行——同事务快照
	// 完整行（含 auto_update/排程/状态），失败分支整行恢复并阻止 rearm 覆盖。
	versionRowsBefore := map[string][]map[string]any{}
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		rows, err := dumpTable(ctx, tx, table)
		if err != nil {
			err = failImportAbort(c, session, action, "快照版本行失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		}
		versionRowsBefore[table] = rows
		versionRowExistedBefore[table] = len(rows) > 0
	}
	restoreImportNodeRole, err := suppressImportClusterVersionBumps(ctx, tx)
	if err != nil {
		err = failImportAbort(c, session, action, "", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
		return
	}
	// security_ip_lists 先删/先插 security_policies——refs 是策略行上的
	// JSON 引用（无外键，顺序本自由），固定 lists→policies 与集群 apply 侧
	// 一致，保证插入后引用即时指向存在行。
	// 威胁库文件逐源落盘可能在下方失败——先快照导入前的本地源行，
	// 失败源在事务内整行回滚为本地值（保留本地 last_updated，文件亦未覆盖）。
	var localThreatRows map[string]map[string]any
	if lbbakFiles != nil && len(lbbakFiles.ThreatIplists) > 0 {
		localThreatRows = captureThreatSourceRows(ctx)
	}
	// /nodes 整体替换前清理「将被删除节点」的 TOFU 指纹钉与
	// 分区上报缓存（保留备份仍携带节点的 pin）——必须赶在 DELETE FROM nodes
	// 之前（pin 地址需按现存行解析）。
	clearedNodeArtifacts := 0
	if nodeRows, nodesCarried := backup.Tables["nodes"]; nodesCarried && h.clusterService != nil {
		clearedNodeArtifacts = h.clearDeletedNodeStateBeforeRestore(ctx, tx, nodeRows)
	}
	// nodes 全表替换前保留「身份匹配且本地持有令牌」节点的本地令牌/审批态，
	// 避免备份中的旧令牌哈希切断仍存活从节点的认证（跨环境导入/回滚旧备份）。
	ignoredNodeTokens := 0
	if nodeRows, nodesCarried := backup.Tables["nodes"]; nodesCarried {
		ignoredNodeTokens, err = reconcileImportNodeTokens(ctx, tx, nodeRows)
		if err != nil {
			err = failImportAbort(c, session, action, "", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		}
	}
	// users 分节替换会同时改变归属列的「作者」语义：归属列是数字 id、无外键，
	// 未随包替换的规则/安全表仍指向同一 id，但该 id 已换成另一个人（或不再
	// 存在）。导入前快照本地用户名，提交前只统计与告警，不改写归属字段。
	var localUserNames map[int]string
	var livePasswordVersions map[int]int64
	if _, usersCarried := backup.Tables["users"]; usersCarried {
		localUserNames = snapshotImportUserNames(ctx, tx)
		livePasswordVersions, err = snapshotImportPasswordVersions(ctx, tx)
		if err != nil {
			err = failImportAbort(c, session, action, "快照本地会话版本失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "快照本地会话版本失败，已回滚: " + err.Error()})
			return
		}
	}
	deleteOrder := []string{"security_policy_bindings", "security_crs_version", "security_ip2region_version", "security_threat_sources", "security_crawler_sources", "security_custom_rules", "security_block_pages", "security_ip_lists", "security_policies", "api_keys", "path_rules", "upstreams", "cert_jobs", "lb_rules", "users", "ca_providers", "certificate_configs", "nodes"}
	for _, table := range deleteOrder {
		if _, exists := backup.Tables[table]; !exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			err = failImportAbort(c, session, action, "", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清空表 " + table + " 失败，已回滚: " + err.Error()})
			return
		}
	}
	insertOrder := []string{"users", "lb_rules", "ca_providers", "certificate_configs", "api_keys", "upstreams", "path_rules", "cert_jobs", "security_ip_lists", "security_policies", "security_crs_version", "security_ip2region_version", "security_threat_sources", "security_crawler_sources", "security_block_pages", "security_custom_rules", "security_policy_bindings", "nodes"}
	for _, table := range insertOrder {
		rows, exists := backup.Tables[table]
		if !exists {
			continue
		}
		// 写入侧幂等兜底：verifyBackupIntegrity 已归一 NULL，此处覆盖直接
		// restoreTable 调用/历史测试路径，保持列形状一致。
		if table == "lb_rules" || table == "upstreams" || table == "users" {
			normalizeBackupBooleanNulls(map[string][]map[string]any{table: rows})
		}
		// 策略实体单职化：备份行 policy_type 为空（旧版本导出/缺席补默认 ''）
		// 时按内容推断落库（services.InferSnapshotPolicyType → models.
		// InferPolicyType 单一事实源）——导入后类型不滞留 ''。
		if table == "security_policies" {
			for _, row := range rows {
				if t, _ := row["policy_type"].(string); t == "" {
					row["policy_type"] = services.InferSnapshotPolicyType(row)
				}
			}
		}
		if err := restoreTable(ctx, tx, db.DB, table, rows); err != nil {
			err = failImportAbort(c, session, action, "", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		}
	}
	// setup 管理员标记兜底：旧备份不含 is_setup_admin（缺键→列默认 0）或标记
	// 行已不是启用的管理员时，按「最低 id 的启用管理员」重建 break-glass 保护
	// 目标——否则跨实例还原后保护可能落到普通账号（错保护）或不落任何行
	// （漏保护）。与启动迁移同一实现，事务内执行随导入一并回滚。
	if _, usersCarried := backup.Tables["users"]; usersCarried {
		if err := db.EnsureSetupAdminFlag(ctx, tx); err != nil {
			err = failImportAbort(c, session, action, "", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		}
	}
	// users 已替换、归属表未替换时统计「换了人/已不存在」的行数（只告警不改写）。
	attributionMismatches := 0
	if localUserNames != nil {
		attributionMismatches = collectImportAttributionMismatches(ctx, tx, backup.Tables, localUserNames)
	}
	// 规则三面同构（2026-10-11 用户裁定；收敛）：导入的规则行
	// 在事务内做 TCP 死值清零（七字段+TLS 三字段）+ lb_rules/path_rules 时间戳
	// 平面格式归一——与 normalizeRuleForTransport 传输归一/启动迁移同一清单
	// （不归一则导入后主端 DB 重新回到三态并存）。此前是平行手写 SQL 归一块
	// （缺 TLS 三字段与 path_rules 时间戳），现改调与 v1 导入共享的
	// normalizeRuleRowsForTransport（单一事实源）。
	var droppedTCPBindings int64
	_, rulesReplaced := backup.Tables["lb_rules"]
	if rulesReplaced {
		droppedTCPBindings, err = normalizeRuleRowsForTransport(ctx, tx)
		if err != nil {
			err = failImportAbort(c, session, action, "规则传输归一失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		}
	} else if _, bindingsCarried := backup.Tables["security_policy_bindings"]; bindingsCarried {
		// 规则表缺席（如仅导入「安全防护」）时上面的归一不跑，
		// 但 security_policy_bindings 被携带——指向 live TCP 规则的绑定会随
		// 插入存活，必须在插入后清理（幂等）。绑定表也缺席的分类导入不得顺手
		// 改写安全绑定。
		droppedTCPBindings, err = pruneTCPRuleBindings(ctx, tx)
		if err != nil {
			err = failImportAbort(c, session, action, "", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		}
	}

	// 规则整体替换但 upstreams/path_rules 未随包
	// 携带（手工/截断备份）时，live 的 upstream/path 行会指向已被替换掉的规则
	// ——渲染不可见，但集群快照原样 dump（snapshotRules/snapshotAllPathRules），
	// 且极小概率的 caddy_id 复用会误挂。此处按导入后规则视图幂等剪枝（与
	// cert_jobs 孤儿清理同型）。
	if rulesReplaced {
		for _, table := range []string{"upstreams", "path_rules"} {
			// NOT EXISTS 而非 NOT IN：子查询出现 NULL 时 NOT IN 恒为 NULL
			// （整条清理静默失效），NOT EXISTS 无此陷阱。
			pruneSQL := "DELETE FROM " + table + " WHERE NOT EXISTS (SELECT 1 FROM lb_rules WHERE lb_rules.caddy_id = " + table + ".rule_id)"
			if _, err := tx.ExecContext(ctx, pruneSQL); err != nil {
				err = failImportAbort(c, session, action, "清理孤立 "+table+" 失败", err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
				return
			}
		}
	}

	// 规则或策略被整体替换而绑定表缺席时，live 绑定仍保留。
	// 在事务内按导入后视图清理两端任一悬挂的绑定；未触碰这三张表的
	// 分类导入不得顺手改写安全绑定。
	var prunedBindings int64
	_, policiesReplaced := backup.Tables["security_policies"]
	if rulesReplaced || policiesReplaced {
		result, err := tx.ExecContext(ctx, `DELETE FROM security_policy_bindings
			WHERE NOT EXISTS (SELECT 1 FROM lb_rules WHERE lb_rules.caddy_id = security_policy_bindings.rule_caddy_id)
			   OR NOT EXISTS (SELECT 1 FROM security_policies WHERE security_policies.id = security_policy_bindings.policy_id)`)
		if err != nil {
			err = failImportAbort(c, session, action, "清理悬挂安全策略绑定失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		}
		// DELETE 已成功：计数失败只影响审计/响应里的条数展示，不影响导入结果
		// ——按 0 计并留痕（同文件其余 RowsAffected 调用均判错，此处不得独吞）。
		counted, countErr := result.RowsAffected()
		if countErr != nil {
			services.Logf("warn", "配置%s：读取悬挂安全策略绑定清理条数失败（按 0 计，清理动作已成功）: %v", action, countErr)
		} else {
			prunedBindings = counted
		}
	}

	// 四态化启动迁移只覆盖启动路径——pre-v2.2.7 备份
	// 导入 off+启用自定义规则的策略后静默失活(旧语义 off=自定义照常发射,
	// 新语义 off=全关),违背迁移「行为零突变」意图。导入事务内做同款归一
	// (与 migrateSecurityPolicyCustomOnlyMode 的行级语义一致,但不走旗标门:
	// 每次导入都归一,导入的是「旧世界数据」这一事实由备份内容自证)。
	// 新语义下合法保存的 off+启用规则导出→导入会被
	// 归一为 custom_only(规则从全关静默变生效)。行为与启动迁移一致(旧世界
	// 数据归一),但在此留审计提示,运维可从事件日志追溯。
	if policiesReplaced {
		if result, err := tx.ExecContext(ctx, db.SecurityPolicyCustomOnlyModeNormalizationSQL); err != nil {
			err = failImportAbort(c, session, action, "off→custom_only 归一", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		} else if n, known := rowsAffectedOrUnknown(result, action, "off→custom_only 归一计数"); !known {
			// 归一 SQL 已成功、条数未知：语义变更仍已发生，必须留痕（不得
			// 因计数失败而静默——那是「自定义规则从全关变生效」的披露通道）。
			recordAudit(c, action+"警告", "配置备份", action+"后 WAF 模式为 off 且挂启用自定义规则的策略已按旧语义归一为 custom_only（自定义规则开始生效；受影响条数读取失败）")
		} else if n > 0 {
			customOnlyNormalized = n
			services.Logf("info", "配置导入：%d 个 mode=off 且挂启用自定义规则的策略已归一为 custom_only（旧语义兼容）", n)
			// 注释承诺的「留审计提示」在此落地：归一改变运行态语义（自定义
			// 规则从全关变生效），必须在操作审计与响应 warnings 双通道可见。
			recordAudit(c, action+"警告", "配置备份", fmt.Sprintf(action+"后 %d 个 WAF 模式为 off 且挂启用自定义规则的策略已按旧语义归一为 custom_only（自定义规则开始生效）", n))
		}
	}
	// 备份可能携带 ≥2 个 is_default=1 的拦截页。restoreTable
	// 原值插入后这些行全部成为不可编辑/删除的死行，且 branding 重渲染会覆盖
	// 全部默认页内容。提交前降级多余默认页，仅保留 MIN(id) 一行。
	// 备份中保留行（MIN id）常是未定制过的种子行，而用户真实
	// 定制内容在被降级行上。保留行内容为种子库存（空或默认渲染）且存在内容不同的
	// 被降级行时，把内容非空且非库存、id 最大的被降级行 content 提升到保留行；
	// 失败仅记警告（内容层面问题，branding 重渲染会覆盖，不影响拦截功能）。
	// 提升先于降级执行——降级后「被降级行」与从未是默认页的自定义行
	// 无法区分；CTE 在降级前圈定待降级行集合，提升源限定该集合且以 EXISTS 门控
	// （未发生降级即跳过提升），单默认页+自定义页的备份不再静默改写默认页内容。
	reseedBlockPageNeeded := false
	reseedApplyFailed := false
	if _, blockPagesReplaced := backup.Tables["security_block_pages"]; blockPagesReplaced {
		stockBlockPage := renderDefaultBlockPage(loadBrandingConfig(h.cfg.DataDir))
		if _, err := tx.ExecContext(ctx, `WITH demoted AS (SELECT id, content FROM security_block_pages WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)) UPDATE security_block_pages SET content=(SELECT content FROM demoted WHERE content NOT IN ('', ?) ORDER BY id DESC LIMIT 1) WHERE id=(SELECT MIN(id) FROM security_block_pages WHERE is_default=1) AND content IN ('', ?) AND EXISTS (SELECT 1 FROM demoted WHERE content NOT IN ('', ?))`, stockBlockPage, stockBlockPage, stockBlockPage); err != nil {
			recordAudit(c, action+"警告", "配置备份", "默认拦截页面内容提升失败: "+err.Error())
		}
		if _, err := tx.ExecContext(ctx, `UPDATE security_block_pages SET is_default=0 WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)`); err != nil {
			err = failImportAbort(c, session, action, "降级多余的默认拦截页失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "降级多余的默认拦截页失败，已回滚: " + err.Error()})
			return
		}
		// 默认页重播种移入导入事务，与导入同生共死；失败仅记警告不阻断
		// 导入（拦截响应短暂退化，由后续 SeedDefaultBlockPage/branding 触发自愈）。
		var hasDefaultBlockPage int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&hasDefaultBlockPage); err != nil {
			recordAudit(c, action+"警告", "配置备份", "默认拦截页面计数失败: "+err.Error())
		} else if hasDefaultBlockPage == 0 {
			result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO security_block_pages (id, name, description, content, is_default, created_at, updated_at) VALUES (1, '默认拦截页面', '系统默认 403 拦截页面', '', TRUE, datetime('now'), datetime('now'))`)
			if err != nil {
				recordAudit(c, action+"警告", "配置备份", "默认拦截页面重播种失败: "+err.Error())
			} else if affected, known := rowsAffectedOrUnknown(result, action, "默认拦截页面重播种计数"); !known {
				// 未知不等于 0：不得报「未生效」（实际可能已插入）。
			} else if affected == 0 {
				// 备份携带 id=1 的非默认行时 OR IGNORE 因 PK 冲突静默
				// no-op，导入后仍旧零默认页且无任何 error——告警机制不会
				// 触发，此处显式补记警告以便追溯。
				recordAudit(c, action+"警告", "配置备份", "默认拦截页面重播种未生效（id=1 已存在）")
			} else {
				reseedBlockPageNeeded = true
			}
		}
	}
	revokedSessions := false
	// 仅「系统数据」被替换时吊销全员会话(用户/密钥已换,旧 JWT
	// 必须失效);其余分类导入不触碰用户数据,不吊销、不打扰。
	// 备份 users 表缺席=用户数据未替换,同样不吊销。
	if sectionTables["users"] && len(backup.Tables["users"]) > 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE users SET password_version=COALESCE(password_version,0)+1"); err != nil {
			failImportTx(c, session, action, "吊销现有登录会话失败", err, http.StatusInternalServerError, "吊销现有登录会话失败")
			return
		}
		for id, liveVersion := range livePasswordVersions {
			target := liveVersion + 1
			if _, err := tx.ExecContext(ctx, `UPDATE users SET password_version=? WHERE id=? AND COALESCE(password_version,0)<?`, target, id, target); err != nil {
				failImportTx(c, session, action, "吊销现有登录会话失败", err, http.StatusInternalServerError, "吊销现有登录会话失败")
				return
			}
		}
		revokedSessions = true
	}
	var enabledAdmins int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='admin' AND is_enabled=1").Scan(&enabledAdmins); err != nil {
		failImportTx(c, session, action, "确认管理员账号失败", err, http.StatusInternalServerError, "确认管理员账号失败")
		return
	}
	if enabledAdmins == 0 {
		failImportTx(c, session, action, "导入后必须至少保留一个已启用的管理员账号", errors.New("导入后必须至少保留一个已启用的管理员账号"), http.StatusBadRequest, "")
		return
	}
	var importUserID sql.NullInt64
	if importUsername != "" {
		err := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE username=?", importUsername).Scan(&importUserID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			err = failImportAbort(c, session, action, "重映射规则操作者失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重映射规则操作者失败，已回滚: " + err.Error()})
			return
		}
	}
	// 归属重映射仅在操作者存在时执行——操作者行缺失时写 NULL 会抹掉
	// 全部规则归属（操作者非空但缺席备份的场景已降级为 warning 警告（2026-09-18 裁定）；
	// 此分支兜底无操作者上下文的路径）。
	if importUserID.Valid && rulesReplaced {
		if _, err := tx.ExecContext(ctx, "UPDATE lb_rules SET updated_by=?", importUserID); err != nil {
			err = failImportAbort(c, session, action, "更新规则操作者失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新规则操作者失败，已回滚: " + err.Error()})
			return
		}
	}
	_, certJobsReplaced := backup.Tables["cert_jobs"]
	// 产物清理门：仅当本次导入替换了规则/证书任务面时才允许清理消失规则
	// 与失效任务（users-only 等分类导入对 live 数据零触碰）。
	session.replaceRuleArtifacts = rulesReplaced || certJobsReplaced
	if rulesReplaced || certJobsReplaced {
		if _, err := tx.ExecContext(ctx, "DELETE FROM cert_jobs WHERE NOT EXISTS (SELECT 1 FROM lb_rules WHERE lb_rules.caddy_id = cert_jobs.rule_id)"); err != nil {
			err = failImportAbort(c, session, action, "清理孤儿证书任务失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理孤儿证书任务失败，已回滚: " + err.Error()})
			return
		}
		// 规则存在但已非 ACME 自动签发态（manual/未启用/TLS
		// 关闭）的 cert_jobs 行——上方孤儿清理只覆盖 rule_id 不在 lb_rules 的行，
		// 此类「规则仍在」的失效任务会被续签扫描/任务列表当作活任务。谓词与续签
		// 扫描（certjobs.go/caddy.go 的 ACME 规则判据）同口径。
		if _, err := tx.ExecContext(ctx, "DELETE FROM cert_jobs WHERE rule_id IN (SELECT caddy_id FROM lb_rules WHERE NOT (COALESCE(enable_tls,0)=1 AND COALESCE(tls_source,'manual')='acme_dns'))"); err != nil {
			err = failImportAbort(c, session, action, "清理失效证书任务失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理失效证书任务失败，已回滚: " + err.Error()})
			return
		}
		// 到期口径收敛：有效材料但 expires_at 缺失的导入行按 PEM 派生回填
		// （已有列值优先，不改写）。不回填会让 /certificates/jobs 的派生值
		// 与聚合端（节点健康 certs_expiring_30d、证书页）的列值口径分叉。
		if _, err := backfillCertJobExpiryFromPEM(ctx, tx); err != nil {
			err = failImportAbort(c, session, action, "回填证书任务到期时间失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "回填证书任务到期时间失败，已回滚: " + err.Error()})
			return
		}
	}
	// 冲突矩阵置禁用的规则与 DisableRule 端点
	// 同口径暂停证书任务——否则导入提交后队列恢复（RequeueNonTerminalCertJobs）
	// 会给已禁用规则续签。写点=Rules 域收敛的单源
	// disableCertJobsForRuleTx（rules.go，守卫白名单在册），谓词与
	// DisableRule 逐字一致。条件只需 len(disabledConflicts)>0：冲突矩阵只跑
	// 在备份携带 lb_rules 时；cert_jobs 缺席的分类导入保留 live 任务行，
	// 同样适用本暂停。
	if len(disabledConflicts) > 0 {
		for _, conflict := range disabledConflicts {
			if _, err := disableCertJobsForRuleTx(tx, conflict.CaddyID); err != nil {
				err = failImportAbort(c, session, action, "暂停冲突禁用规则的证书任务失败", err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "暂停冲突禁用规则的证书任务失败，已回滚: " + err.Error()})
				return
			}
		}
	}
	oidcConverged := false
	if backup.Config != nil {
		// G（2026-09-20 用户裁定「配置收敛」）：备份含全局配置区但不含
		// oidc_config 键（旧版本/未配置 OIDC 时导出）→ OIDC 配置随备份收敛
		// 清空——PATCH 语义的 UPDATE 只写备份携带键，不收敛会留下「OIDC
		// 启用（live 残留）+ 用户被备份 users 表替换清空」的不一致死态。
		if _, hasOIDC := backup.Config["oidc_config"]; !hasOIDC {
			var liveOIDC string
			if err := tx.QueryRowContext(ctx, "SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1").Scan(&liveOIDC); err != nil {
				failImportTx(c, session, action, "读取 OIDC 配置失败", err, http.StatusInternalServerError, "读取 OIDC 配置失败")
				return
			}
			if liveOIDC != "" {
				backup.Config["oidc_config"] = ""
				oidcConverged = true
			}
		}
	}
	if backup.Config != nil {
		valid, err := tableColumns(ctx, db.DB, "global_config")
		if err != nil {
			failImportTx(c, session, action, "读取配置结构失败", err, http.StatusInternalServerError, "读取配置结构失败")
			return
		}
		sets := []string{}
		values := []any{}
		// 列名排序后再拼 SET：map 迭代序每进程随机 → 同一备份在不同导入/进程
		// 生成不同 SQL 文本，而 database/sql 以 SQL 文本为键缓存 prepared
		// statement 且不淘汰（与 restoreRowStatement 同一策略，防每次导入新增
		// 一条永不命中的 ~60 列语句缓存）。
		configColumns := make([]string, 0, len(backup.Config))
		for column := range backup.Config {
			configColumns = append(configColumns, column)
		}
		sort.Strings(configColumns)
		for _, column := range configColumns {
			value := backup.Config[column]
			if configBackupProtectedConfigKeys[column] || !valid[column] {
				continue
			}
			// 布尔配置键写入前归一（与 restoreTable 同口径）——
			// 规范与 legacy 均已在行级门拒绝字符串，此处只转换合法 bool/0/1。
			if isBackupBooleanConfigKey(column) {
				value = normalizeBackupBooleanValue(value)
			}
			sets = append(sets, `"`+column+`"=?`)
			values = append(values, value)
		}
		if len(sets) > 0 {
			if _, err := tx.ExecContext(ctx, "UPDATE global_config SET "+strings.Join(sets, ",")+" WHERE id=1", values...); err != nil {
				err = failImportAbort(c, session, action, "", err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入全局配置失败，已回滚: " + err.Error()})
				return
			}
		}
	}
	affectedRuleIDs := append([]string(nil), session.existingRuleIDs...)
	ruleCertificates, importCertWarnings := collectImportCertificates(backup.Tables["lb_rules"])
	pendingCertificates := ruleCertificates
	affectedRuleIDs = append(affectedRuleIDs, ruleCertificateRuleIDs(backup.Tables["lb_rules"])...)
	counts := importCountsDetail(backup.Tables)
	// lbbak:文件落盘必须在 session.commit 之前——commit 内的 Caddy 应用
	// (ApplyConfigFromTxCertAwareForce)要读到新 CRS 文件;xdb 落盘后立即
	// 热换内存缓存(完整更新流程,2026-09-18 用户裁定)。
	wafApply := lbbakWafApplyResult{}
	respondAfterWafFailure := func(status int, message string) {
		failureWarnings := append([]string{}, skipWarnings...)
		failureWarnings = append(failureWarnings, wafApply.Warnings...)
		// 文件面提示按 abort 的实际回退结论生成：已回退=明示一致；
		// 回退失败=显性告知可能分裂（不得沿用固定文案谎报）；提交结果不确定=
		// 文件保持导入后状态并给人工核对指引（不得断言一致/分裂）。
		if warning := lbbakWafRollbackWarning(wafApply.FilesLanded, session.wafRestoreAttempted, session.wafRestoreErr, session.commitIndeterminate); warning != "" {
			failureWarnings = append(failureWarnings, warning)
		}
		failureWarnings = append(failureWarnings, session.wafRestoreWarnings...)
		// 会话收尾阶段的一般性披露（提交不确定态下的产物清理去向）：
		// 与 WAF 回退结论并列透出，避免「导入失败」被读成「磁盘也已收敛」。
		failureWarnings = append(failureWarnings, session.failureWarnings...)
		c.JSON(status, models.APIResponse{Code: status, Message: message, Data: gin.H{
			"summary": counts, "disabled_conflicts": disabledConflicts, "warnings": failureWarnings,
		}})
	}
	// 落盘前快照将被修改的 WAF 路径（CRS 整树/xdb+版本标记/全部威胁名单
	// 文件）：落盘先于事务提交，提交或校验失败回滚数据库时文件必须同批回退。
	// 快照失败即中止——此时尚未写入任何字节，fail-closed 无副作用。
	if wafFilePhase {
		threatFilesSnapshotted := lbbakFiles != nil && (len(lbbakFiles.ThreatIplists) > 0 || threatFileReconcile)
		snapshot, snapshotErr := snapshotLbbakWafTargets(lbbakFiles, threatFilesSnapshotted)
		if snapshotErr != nil {
			err = failImportAbort(c, session, action, "快照规则库文件失败（未写入任何文件）", fmt.Errorf("快照规则库文件失败: %w", snapshotErr))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		}
		session.wafSnapshot = snapshot
	}
	if lbbakFiles != nil && sectionTables["security_crs_version"] {
		wafApply = applyLbbakWafFilesInLock(c, action, lbbakFiles, services.SanitizeBundleVersion(ip2regionTagFromBackup(backup.Tables)))
		// 未落盘文件对应版本记录在提交前同批丢弃（此前失败仍 commit
		// 版本行——记录与文件分裂且响应谎报更新成功）。
		for _, item := range []struct {
			failed bool
			table  string
		}{
			{wafApply.FailedCRS, "security_crs_version"},
			{wafApply.FailedXdb, "security_ip2region_version"},
		} {
			if !item.failed {
				continue
			}
			// 记录与文件同批：该表视为未导入（后续首槽武装也不得为它补槽）。
			delete(backup.Tables, item.table)
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+item.table); err != nil {
				err = failImportAbort(c, session, action, "丢弃未落盘版本记录失败", err)
				respondAfterWafFailure(http.StatusInternalServerError, action+"失败，已回滚: "+err.Error())
				return
			}
			// 导入前的本地版本/排程行必须整行回填，不能留下零行让
			// rearm 用默认种子覆盖（磁盘仍是旧文件，记录必须对应当前文件）。
			if localRows := versionRowsBefore[item.table]; len(localRows) > 0 {
				if err := restoreTable(ctx, tx, db.DB, item.table, localRows); err != nil {
					err = failImportAbort(c, session, action, "恢复本地版本记录失败", err)
					respondAfterWafFailure(http.StatusInternalServerError, action+"失败，已回滚: "+err.Error())
					return
				}
			}
		}
		// CRS 规则树实际未落盘时，早前的「按新树降级只做形状
		// 校验」不再成立——必须按仍生效的 live 索引重验策略，避免落库空 Include。
		if crsTreeReplaced && wafApply.FailedCRS {
			crsTreeReplaced = false
			if verifyErr := validateV2BackupSecurityPolicies(backup.Tables, false); verifyErr != nil {
				err = failImportAbort(c, session, action, "CRS 文件未落盘，安全策略按现有规则库校验失败", verifyErr)
				respondAfterWafFailure(http.StatusBadRequest, "CRS 规则库文件未落盘，备份安全策略与现有规则库不兼容，已回滚: "+verifyErr.Error())
				return
			}
		}
		// 逐源失败——整行回滚为本地快照（表已全量替换；成功源仍按
		// 备份行导入，失败源保留本地文件与记录）。
		for _, source := range wafApply.FailedThreatSources {
			if _, err := tx.ExecContext(ctx, `DELETE FROM security_threat_sources WHERE name=?`, source); err != nil {
				err = failImportAbort(c, session, action, "回滚失败威胁源失败", err)
				respondAfterWafFailure(http.StatusInternalServerError, action+"失败，已回滚: "+err.Error())
				return
			}
			if local, ok := localThreatRows[source]; ok {
				if err := restoreTable(ctx, tx, db.DB, "security_threat_sources", []map[string]any{local}); err != nil {
					err = failImportAbort(c, session, action, "恢复本地威胁源失败", err)
					respondAfterWafFailure(http.StatusInternalServerError, action+"失败，已回滚: "+err.Error())
					return
				}
			}
		}
	}
	// 源表全量替换后，按导入后源集合收敛威胁库文件——空/缺席源
	// 与已删源的本地旧 .iplist/.fast 必须删除（否则 DB 与执行面分叉）。
	if threatFileReconcile {
		warnings, changed := reconcileImportedThreatFiles(backup.Tables, lbbakFiles, wafApply.FailedThreatSources)
		if changed {
			wafApply.FilesLanded = true
		}
		for _, warning := range warnings {
			wafApply.Warnings = append(wafApply.Warnings, warning)
			recordAudit(c, action+"警告", "配置备份", warning)
		}
	}
	// 摘要必须在 WAF 版本表按落盘结果丢弃之后重算，否则响应仍宣称已导入
	counts = importCountsDetail(backup.Tables)
	// 门控：仅当本次导入实际携带（且成功落盘）规则库四表之一时才
	// 需要重装首槽——否则（如 JSON 导入跳过版本表、规则类导入）武装会为
	// 空表补种子行，改变「未导入=本地零行」的既有语义。
	securityLibraryTablesImported := false
	for _, table := range []string{"security_crs_version", "security_ip2region_version", "security_threat_sources", "security_crawler_sources"} {
		if _, ok := backup.Tables[table]; ok {
			securityLibraryTablesImported = true
			break
		}
	}
	_, crsVersionImported := backup.Tables["security_crs_version"]
	_, ip2RegionVersionImported := backup.Tables["security_ip2region_version"]
	rearmSecurityLibrarySlots := securityLibraryTablesImported || backup.Config != nil
	if err := installImportVersionSentinels(ctx, tx, backup.Tables, rearmSecurityLibrarySlots, versionRowExistedBefore); err != nil {
		err = failImportAbort(c, session, action, "", err)
		respondAfterWafFailure(http.StatusInternalServerError, action+"失败，已回滚: "+err.Error())
		return
	}
	if err := restoreImportNodeRole(); err != nil {
		err = failImportAbort(c, session, action, "", err)
		respondAfterWafFailure(http.StatusInternalServerError, action+"失败，已回滚: "+err.Error())
		return
	}
	var queueRecoveryErr error
	if err := session.commit(affectedRuleIDs, pendingCertificates); err != nil {
		if importFailurePhase(err) == importPhaseQueue {
			// 数据库已提交。queue 恢复失败属于部分失败，必须继续
			// 全部提交后收敛（缓存失效/哨兵清理/驱动同步），最后再返回 500。
			queueRecoveryErr = err
			recordAudit(c, "部分失败", "配置备份", importFailureAuditDetail(err))
		} else {
			status := http.StatusInternalServerError
			// 消息正文与审计 detail 同源（阶段描述+真实错误）：err.Error() 自带
			// 「导入/还原失败」动作前缀，再拼「配置X失败:」会双前缀。
			message := "配置" + action + "失败: " + importFailureAuditDetail(err)
			if importFailureCaddyRejected(err) {
				status = http.StatusBadRequest
				message = "备份生成的配置未通过 Caddy 验证，未执行" + action + ": " + importFailureAuditDetail(err)
			}
			auditAction := action + "失败"
			auditDetail := importFailureAuditDetail(err)
			recordAudit(c, auditAction, "配置备份", auditDetail)
			respondAfterWafFailure(status, message)
			return
		}
	}
	if wafApply.SecurityDataApplied {
		// 文件落盘发生在事务内，但成功审计必须等数据库提交确定成功；
		// 否则 Caddy/Commit 失败回滚文件后会留下与实际终态相反的成功记录。
		recordAudit(c, action, "安全数据", services.FormatAuditDetail("规则库数据库(随备份还原/导入)", services.AuditResultPart("success")))
	}
	// branding_json 只是文件镜像。提交成功后把备份值物化到
	// branding.json，再刷新镜像与默认页面；否则下一次镜像会把 DB 回写成旧文件。
	brandingWarning := ""
	if backup.Config != nil {
		if raw, carried := backup.Config["branding_json"]; carried {
			if _, err := services.MaterializeBranding(h.cfg.DataDir, backupString(raw)); err != nil {
				brandingWarning = "品牌配置文件还原失败: " + err.Error()
				recordAudit(c, action+"警告", "配置备份", brandingWarning)
				// 文件仍是唯一事实源：立即把 DB 镜像回本地文件，避免留下分叉。
				if _, mirrorErr := services.RefreshBrandingMirror(h.cfg.DataDir); mirrorErr != nil {
					recordAudit(c, action+"警告", "配置备份", "品牌镜像回读失败: "+mirrorErr.Error())
				}
			} else {
				reseedBlockPageNeeded = true
				if _, err := services.RefreshBrandingMirror(h.cfg.DataDir); err != nil {
					brandingWarning = "品牌镜像刷新失败: " + err.Error()
					recordAudit(c, action+"警告", "配置备份", brandingWarning)
				}
			}
		}
	}
	// 备份导入是第三条解封面——本函数对
	// security_ip_lists 全量替换（DELETE 全表+插备份行，deleteOrder/insertOrder
	// 语义），commit 成功后内存 autobanWindows 若保留旧计数桶，还原旧备份后
	// 零新流量 ≤1 tick 重封（与「删除即解封」同型撤销，两接线点不覆盖导入
	// 面）。门控=备份实际携带该表（迟到表「缺席=保留本地」形态本地名单未动，
	// 计数桶保留）；此时点在 session.commit 之后且仍持 caddyOpMu（beginConfigImport
	// 取锁），与 handlers 解封清桶（同锁临界区）全序、无回滚副作用。Ruling
	// （2026-10-15 主审裁定）：选 ResetAutobanCounters 整体清桶而非按名单差集
	// ForgetIPs——导入是全量替换语义：导入后名单世界=备份行集合（预置名单可
	// 缺席/换 id/换条目），旧计数桶的全部前提失效；差集需跨事务快照旧条目+解析
	// 备份 entries+按值比对，且覆盖不了「预置名单随备份整体消失」形态，复杂而不
	// 更正确；Reset 代价=未受导入影响的 IP 计数清零重新累计（观察态一个窗口内
	// 自愈）。预览端（ValidateConfigImport）零写入语义、不发生替换，不接清桶。
	if _, listsReplaced := backup.Tables["security_ip_lists"]; listsReplaced {
		// 导入是全表替换——旧备份可能不含 system=1
		// 预置行（或含同名 system=0 用户列表使启动播种按名跳过）。提交成功后
		// 按 db 种子表补播全部内置 system 名单（威胁三源 + 自动封禁），与默认
		// 拦截页 reseed 同位、同「提交成功后收敛」语义；幂等（已存在零写入），
		// 失败仅告警不影响已提交导入。
		if err := db.SeedSystemIPLists(db.DB); err != nil {
			recordAudit(c, action+"警告", "配置备份", "内置系统名单补播失败: "+err.Error())
		}
		services.ResetAutobanCounters()
	}
	// 六列自动封禁配置的第二条写入路径（上方通用
	// `UPDATE global_config`）绕过 services.SetAutobanConfig 的清桶/禁用收尾
	// 不变量。上方的清桶门只覆盖「备份携带 security_ip_lists（名单全量替换）」
	// 形态——只导「系统数据」（含 global_config、不含迟到表）时六列被改写而
	// 计数桶原样保留，≤60s 后的评估轮会按新窗口把陈旧计数整批并入封禁候选
	// （窗口变小/口径收窄 → 批量误封；停用后不收敛 → 重新启用即按数天前的
	// 计数立即封禁）。收敛判定、动作与文案单源
	// services.ReconcileAutobanRuntimeAfterConfigReplace /
	// AutobanConfigReplaceEffectNote（与 PUT 保存同语义，六列未变化时不清桶）。
	// 执行时机：本函数仍持 caddyOpMu，而禁用收尾要自取 CaddyOpLock（非重入
	// 锁）——排入 session.postLockActions，在 close() 释放锁之后、调度恢复之前
	// 执行；响应/审计只披露「将要执行的收敛」，不谎报已落定。
	autobanRuntimeNote := ""
	if autobanBeforeKnown {
		if newAutoban, readErr := services.GetAutobanConfig(); readErr != nil {
			services.Logf("warn", "配置%s：读取导入后自动封禁配置失败，运行期收敛已跳过: %v", action, readErr)
		} else if note := services.AutobanConfigReplaceEffectNote(autobanBefore, newAutoban); note != "" {
			autobanRuntimeNote = note
			before, after := autobanBefore, newAutoban
			session.postLockActions = append(session.postLockActions, func() {
				services.ReconcileAutobanRuntimeAfterConfigReplace(before, after)
			})
		}
	}
	if reseedBlockPageNeeded {
		// 提交成功后才渲染 branding 内容：INSERT 只放空 content 占位，真实内容
		// 由 SeedDefaultBlockPage 依据 branding.json 写入；失败不影响导入结果。
		// 返回值不再丢弃——渲染出错，或未生效且表内仍无默认页时记警告。
		seeded, seedErr := SeedDefaultBlockPage(h.cfg.DataDir)
		if seedErr != nil {
			recordAudit(c, action+"警告", "配置备份", "默认拦截页面内容渲染失败: "+seedErr.Error())
		} else if !seeded {
			var defaultCount int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&defaultCount); err == nil && defaultCount == 0 {
				recordAudit(c, action+"警告", "配置备份", "默认拦截页面重播种后仍无默认页")
			}
		}
		note := h.caddyApplyNoteLocked()
		if note != "" {
			reseedApplyFailed = true
			recordAudit(c, action+"警告", "配置备份", "默认拦截页面重新播种后"+note)
		}
	}

	// 提交后立即应用运行期设置（此前导入只 SyncBusinessTaskDrivers
	// + 清缓存，log_level 变更要等重启；管理面板 HTTPS 变更需重启才能生效）。
	services.ApplyLogLevel()
	// 导入替换四个规则库排程族的行（版本表整行 / 威胁与爬虫源行），而
	// next_update 是按**导出机**时区算出的 UTC 槽：只导入 security 分类时本机
	// 时区不变，「下次更新」展示与实际触发会按源机偏移错位一周期。保存时区路径
	// 已接同一重排（caddy.go UpdateConfig），导入在此补齐。调用安全性：该函数
	// 幂等——只改未来槽、过期槽保留补跑、空槽不动（首槽武装归
	// RearmSecurityLibrarySlots），故无条件调用（不能只在 timezone 随备份变化
	// 时调用——分区导入正是时区不变而槽属他机的形态）。
	services.RearmScheduleSlotsAfterTimezoneChange()
	// 导入可改 task_log_size_mb——服务端 5 分钟 TTL 缓存必须立即失效。
	invalidateImportTaskLogCache()
	// 重启判定必须用严格读取变体（与集群同步后判定同口径）：宽容版读失败
	// 回退 {Enabled:false, selfsigned}，与运行态上传证书指纹不等时会在导入成功
	// 但库读抖动的情况下误报「需重启」并落一条假审计。读失败仅 warn 并跳过
	// 本轮判定（不误报、不改状态）。
	adminTLSRestartWarning := ""
	if adminTLS, tlsErr := services.LoadAdminTLSConfigE(); tlsErr != nil {
		services.Logf("warn", "导入后读取管理面板 HTTPS 配置失败，跳过重启判定: %v", tlsErr)
	} else if services.RuntimeAdminTLSChanged(adminTLS) {
		adminTLSRestartWarning = "管理面板 HTTPS 配置已" + action + "，需重启后生效（当前进程继续使用启动时的证书）"
		recordAudit(c, action+"警告", "配置备份", adminTLSRestartWarning)
	}
	// off→on 且水位线为空/陈旧（>1 分钟）→ 置 now，避免导入后立即
	// 补跑停用期首轮。直接写列而非 SetAutoBackupEnabled（后者会二次 StartLoop）。
	// 导入前开关读取失败（known=false）时不重置——把「未知」当 off
	// 会在原本已启用时误重置水位线。
	if importAutoBackupResetNeeded(oldAutoBackupEnabledKnown, oldAutoBackupEnabled) {
		var newEnabled int
		var lastRun string
		if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_enabled,?), COALESCE(auto_backup_last_run,'') FROM global_config WHERE id=1`,
			db.DefaultAutoBackupEnabled).Scan(&newEnabled, &lastRun); err == nil && newEnabled == 1 {
			if autoBackupWatermarkEmptyOrStale(lastRun) {
				if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_last_run=? WHERE id=1`, time.Now().Format(time.RFC3339)); err != nil {
					services.Logf("warn", "配置导入：重置 auto_backup_last_run 失败: %v", err)
				}
			}
		}
	}
	auditSource := "v2 备份（覆盖" + action + "）"
	if filename != "" {
		auditSource = "服务器备份 " + filename + "（覆盖" + action + "）"
	}
	auditParts := []string{"来源：" + auditSource, counts}
	auditParts = append(auditParts, configClampNotes...)
	auditParts = append(auditParts, autobanClampNotes...)
	if autobanRuntimeNote != "" {
		// 六列运行期收敛（清桶/禁用收尾/调度联动）是导入的可感知副作用，
		// 必须与响应 warnings 同源留痕（此前只在 PUT 保存路径有审计）。
		auditParts = append(auditParts, autobanRuntimeNote)
	}
	if len(skipWarnings) > 0 {
		// 列表现含空域名规则与空内容拦截页两类跳过，标签泛化。
		auditParts = append(auditParts, "跳过警告："+strings.Join(skipWarnings, "；"))
	}
	if len(importCertWarnings) > 0 {
		// 证书链/域名警告随成功审计留痕(不阻断)。
		auditParts = append(auditParts, "证书警告："+strings.Join(importCertWarnings, "；"))
	}
	if len(certJobProviderWarnings) > 0 {
		// 证书任务 CA 提供商归一（ca_provider_id 就地写回 0）会改变无人值守
		// 签发路径，必须与响应 warnings 双通道留痕（同 custom_only 归一）。
		auditParts = append(auditParts, "证书任务提供商归一："+strings.Join(certJobProviderWarnings, "；"))
	}
	if len(disabledConflicts) > 0 {
		auditParts = append(auditParts, "冲突置为禁用："+formatDisabledRuleConflicts(disabledConflicts))
	}
	if clearedNodeArtifacts > 0 {
		auditParts = append(auditParts, fmt.Sprintf("清理已删除节点 %d 个的证书指纹钉与分区上报缓存", clearedNodeArtifacts))
	}
	if ignoredNodeTokens > 0 {
		auditParts = append(auditParts, fmt.Sprintf("%d 个节点的备份令牌被忽略（已保留本地令牌与审批状态）", ignoredNodeTokens))
	}
	if attributionMismatches > 0 {
		auditParts = append(auditParts, fmt.Sprintf("%d 条记录的归属用户与导入用户集不一致（未改写归属字段）", attributionMismatches))
	}
	if prunedBindings > 0 {
		auditParts = append(auditParts, fmt.Sprintf("清理悬挂安全策略绑定：%d 条", prunedBindings))
	}
	if operatorReplaced {
		auditParts = append(auditParts, "操作者账户已被备份替换,请使用备份内管理员登录")
	}
	if warning := backupProductVersionWarning(backup.Meta, h.cfg.Version); warning != "" {
		auditParts = append(auditParts, "版本兼容警告："+warning)
	}
	if queueRecoveryErr == nil {
		auditParts = append(auditParts, services.AuditResultPart("success"))
		recordAudit(c, action, "配置备份", services.FormatAuditDetail(auditParts...))
	}
	recordAudit(c, "重载", "Caddy服务", action+"配置后自动重载")
	// 2026-09-07：导入成功后清除陈旧 caddy_apply_error
	// ——但 reseed 失败时不清（reseed 的 caddyApplyNoteLocked 可能刚写入
	// 失败标记，无条件清除会把真实失败横幅抹掉）。
	// 未走 reseed 路径时 reseedApplyFailed 恒 false（只在上方 reseed 块内置位），
	// 故双重否定守卫等价于 !reseedApplyFailed。
	if !reseedApplyFailed {
		h.recordCaddyApplyResult(nil)
	}
	responseWarnings := skipWarnings
	if warning := backupProductVersionWarning(backup.Meta, h.cfg.Version); warning != "" {
		responseWarnings = append(append([]string{}, responseWarnings...), warning)
	}
	if brandingWarning != "" {
		responseWarnings = append(append([]string{}, responseWarnings...), brandingWarning)
	}
	if ignoredNodeTokens > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), fmt.Sprintf("%d 个节点的备份令牌与本地不一致，已保留本地令牌与审批状态（备份仅恢复拓扑属性，从节点无需重新审批）", ignoredNodeTokens))
	}
	if attributionMismatches > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), fmt.Sprintf("%d 条记录的归属用户未随备份包含或已被替换，作者显示可能为空或错配（导入未改写归属字段）", attributionMismatches))
	}
	if prunedBindings > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), fmt.Sprintf("已按导入后的规则与策略视图清理 %d 条悬挂安全策略绑定", prunedBindings))
	}
	if autobanRuntimeNote != "" {
		responseWarnings = append(append([]string{}, responseWarnings...), autobanRuntimeNote)
	}
	if customOnlyNormalized > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), fmt.Sprintf("%d 个 WAF 模式为 off 且挂启用自定义规则的策略已按旧语义归一为 custom_only（自定义规则开始生效）", customOnlyNormalized))
	}
	// 两档悬挂告警与预览/审计同源（文案单源），不得再各写一份字面量。
	if dangling := certJobProviderDanglingWarnings(certJobProviderDisabled, certJobProviderMissing); len(dangling) > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), dangling...)
	}
	if certJobProviderCountErr != nil {
		responseWarnings = append(append([]string{}, responseWarnings...), "证书任务 CA 提供商悬挂统计未完成（读取失败，导入本身不受影响）："+certJobProviderCountErr.Error())
	}
	if droppedTCPBindings > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), fmt.Sprintf("已解除 %d 条 TCP 规则的安全策略绑定（TCP 不参与策略渲染）", droppedTCPBindings))
	}
	if wafMetadataSkipped {
		responseWarnings = append(append([]string{}, responseWarnings...), warningWafMetadataSkipped)
	}
	if crsTreeReplaced {
		responseWarnings = append(append([]string{}, responseWarnings...), warningCRSTreeReplaced)
	}
	if wafCRSMetadataSkipped {
		responseWarnings = append(append([]string{}, responseWarnings...), warningWafCRSMetadataSkipped)
	}
	if wafXdbMetadataSkipped {
		responseWarnings = append(append([]string{}, responseWarnings...), warningWafXdbMetadataSkipped)
	}
	// manifest 未登记的威胁库条目——不拒绝（老备份
	// 兼容），但响应与审计必须可见「内容未经完整性校验」。
	if len(lbbakUnregisteredThreat) > 0 {
		unregisteredDetail := fmt.Sprintf("lbbak 含 manifest 未登记的威胁库条目（%s）——内容未经完整性校验，已按原样落盘；建议核实来源后重新导出备份", strings.Join(lbbakUnregisteredThreat, "、"))
		if lbbakFiles == nil || !sectionTables["security_crs_version"] {
			unregisteredDetail = fmt.Sprintf("lbbak 含 manifest 未登记的威胁库条目（%s）——内容未经完整性校验；本次分类未选择安全防护数据，条目未导入、未落盘", strings.Join(lbbakUnregisteredThreat, "、"))
		}
		recordAudit(c, action+"警告", "配置备份", unregisteredDetail)
		responseWarnings = append(append([]string{}, responseWarnings...), unregisteredDetail)
	}
	if len(wafApply.Warnings) > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), wafApply.Warnings...)
	}
	if operatorReplaced {
		responseWarnings = append(append([]string{}, responseWarnings...), "备份不含当前操作账户——系统数据已替换，请使用备份内的管理员账户登录")
	}
	if oidcConverged {
		// 双通道：收敛清空会让启用中的 OIDC 登出（用户按备份替换），
		// 与同函数 custom_only 归一一致——响应 warnings 之外必须落操作审计，
		// 否则事后只能看到「OIDC 忽然关闭」而无从追溯来源。
		detail := "备份未携带 OIDC 配置——现有 OIDC 配置已随备份收敛清空（用户数据按备份替换，避免「OIDC 启用但零用户」不一致状态）"
		responseWarnings = append(append([]string{}, responseWarnings...), detail)
		recordAudit(c, action+"警告", "配置备份", detail)
	}
	if revokedSessions && !operatorReplaced {
		responseWarnings = append(append([]string{}, responseWarnings...), "系统数据已"+action+"：全部登录会话已吊销，请重新登录")
	}
	if acmeDanglingRules > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), fmt.Sprintf(action+"后 %d 条启用规则的 DNS 提供商配置悬挂（引用不在导入数据中）——下一次签发/续签将失败，请及时补齐", acmeDanglingRules))
	}
	// 反向悬挂警告(与上方审计同文案族;与 acmeDanglingRules 互斥,
	// 方向不同:此处为导入规则引用 live 缺失)。
	if acmeDanglingImported > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), fmt.Sprintf(action+"后 %d 条启用规则的 DNS 提供商配置悬挂（引用未随备份导入，且现有配置中不存在或已禁用）——下一次签发/续签将失败，请及时补齐", acmeDanglingImported))
	}
	// 证书任务级 CA 提供商悬挂/禁用引用的归一警告（validateV2BackupCertJobs 产出）。
	if len(certJobProviderWarnings) > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), certJobProviderWarnings...)
	}
	// 证书链/域名警告并入响应(行内容类警告,不阻断)。
	if len(importCertWarnings) > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), importCertWarnings...)
	}
	// 证书签发任务被用户停止时，导入的非终态任务本窗口不会重排（fail-safe，
	// 不越过用户停止意图）——必须披露，否则任务列表显示进行中而实际无 worker。
	// 文案单源在 importQueueRecovery.stalledWarning；操作审计同文留痕。
	if stalledDetail := session.recovery.stalledWarning(); stalledDetail != "" {
		responseWarnings = append(append([]string{}, responseWarnings...), stalledDetail)
		recordAudit(c, action+"警告", "配置备份", stalledDetail)
	}
	if adminTLSRestartWarning != "" {
		responseWarnings = append(append([]string{}, responseWarnings...), adminTLSRestartWarning)
	}
	// 导入提交后按库实态统一对齐六个业务驱动任务；off→on 无需重启。
	// 四族规则库（CRS/IP2Region/威胁库/爬虫库）的「启用且空槽」
	// 行重新武装首槽——导入替换了版本表行，不重装则 NextSlotFn 永不到期，
	// 自动更新静默停摆直到重启。
	if rearmSecurityLibrarySlots {
		services.RearmSecurityLibrarySlots()
		// rearm 对临时哨兵行不补槽（auto_update=0）；提交后仅在哨兵形态未变
		// 时 CAS 删除，维持「未导入=零行」且绝不覆盖并发真实更新。
		var sentinelTables []string
		for _, item := range []struct {
			table    string
			imported bool
		}{
			{"security_crs_version", crsVersionImported},
			{"security_ip2region_version", ip2RegionVersionImported},
		} {
			if item.imported || versionRowExistedBefore[item.table] {
				continue
			}
			sentinelTables = append(sentinelTables, item.table)
		}
		cleanupImportVersionSentinels(ctx, sentinelTables)
	}
	services.SyncBusinessTaskDrivers()
	// 爬虫源或名单被替换后，caddygeoip 的运行交换文件必须立即
	// 与 DB 收敛；导入是全表替换，旧备份可能不含 system=1 爬虫行（v2.3.8 前
	// 导出/用户裁剪），故走「补种缺失引擎 + 重建快照」同一收敛体（与启动
	// Prime 同源），只 rebuild 会让缺失引擎的豁免/伪装检测静默失效到重启为
	// 止。失败仅告警不回滚已提交配置。
	_, crawlerSourcesReplaced := backup.Tables["security_crawler_sources"]
	_, ipListsReplaced := backup.Tables["security_ip_lists"]
	if crawlerSourcesReplaced || ipListsReplaced {
		if err := services.RestoreCrawlerIPListSnapshot(); err != nil {
			warning := "爬虫运行快照重建失败（重启或下次更新后重试）: " + err.Error()
			recordAudit(c, action+"警告", "配置备份", warning)
			responseWarnings = append(append([]string{}, responseWarnings...), warning)
		}
	}
	// api_keys 已随导入整体替换——清空白名单 CIDR
	// 解析缓存（逐 Key 清扫无法枚举存活 Key；重建廉价）。
	purgeAllAPIKeyWhitelistCache()
	if queueRecoveryErr != nil {
		// 事务已提交（DB/Caddy 已是新配置），队列恢复
		// 失败属「部分成功」——500 会让前端按「已回滚」处理而不刷新，管理员
		// 可能重复导入。改为 200 + partial=true，warning 说明失败面。文案单源：
		// 阶段描述只出现一次（见 importPartialSuccessMessage）。
		responseWarnings = append(responseWarnings, importPartialSuccessWarning(queueRecoveryErr))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: importPartialSuccessMessage(action, queueRecoveryErr), Data: gin.H{"summary": counts, "disabled_conflicts": disabledConflicts, "warnings": responseWarnings, "partial": true}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: fmt.Sprintf("配置"+action+"成功：%s", strings.ReplaceAll(counts, "；", "、")), Data: gin.H{"summary": counts, "disabled_conflicts": disabledConflicts, "warnings": responseWarnings}})
}

// importPartialSuccessMessage 是「部分成功」（数据库已提交、证书任务恢复失败）
// 的响应主文案单源：阶段描述由本处给出一次，正文只取 importFailureCause
// （剥离协调器的「导入部分失败（…）：」前缀，与 v1 同一口径）——直接拼
// Error() 会让同一句阶段描述在 message 与 warnings 里各出现两次，读者会以为
// 发生了两起失败。
func importPartialSuccessMessage(action string, queueRecoveryErr error) string {
	return "配置已" + action + "（部分完成）：证书任务恢复失败: " + importFailureCause(queueRecoveryErr)
}

// importPartialSuccessWarning 是部分成功响应 warnings 的单条说明（同源口径）。
func importPartialSuccessWarning(queueRecoveryErr error) string {
	return "数据库已提交，但证书任务恢复失败: " + importFailureCause(queueRecoveryErr)
}

// collectImportCertificates 待物化的手动证书材料与质量警告（/
// 单源）：TCP 行的 TLS 字段已被 normalizeRuleRowsForTransport 在库侧
// 清零（不终结入站 TLS）——不得用内存备份行把私钥物化到 /app/certs。
func collectImportCertificates(rows []map[string]any) ([]importCertificate, []string) {
	certs := make([]importCertificate, 0)
	warnings := make([]string, 0)
	for _, row := range rows {
		caddyID, _ := row["caddy_id"].(string)
		if caddyID == "" {
			continue
		}
		protocol, _ := row["protocol"].(string)
		if protocol == "tcp" {
			continue
		}
		// 物化条件必须与渲染 availableCerts 同口径
		// （enable_tls && tls_source=manual）——事务内归一已把非 manual 行的
		// tls_cert/tls_key 清空，但内存备份行仍会把 acme_dns 行的私钥对物化到
		// /app/certs（DB 已不引用），并产生误导性证书质量警告。
		if tlsSource := backupString(row["tls_source"]); tlsSource != "" && tlsSource != "manual" {
			continue
		}
		// enable_tls 键缺失按 schema 默认 FALSE（db.go lb_rules DDL
		// BOOLEAN DEFAULT FALSE；restoreTable 对缺键行落 0）——此前缺失即视为
		// 启用，会把 DB 侧实际 enable_tls=0（渲染零消费）的行私钥物化到
		// /app/certs 长期驻留。与 validateV2BackupTLSShapeSoft 的判定同口径。
		if !backupBooleanEnabled(row["enable_tls"]) {
			continue
		}
		certPEM, _ := row["tls_cert"].(string)
		keyPEM, _ := row["tls_key"].(string)
		if certPEM == "" || keyPEM == "" {
			continue
		}
		certs = append(certs, importCertificate{ruleID: caddyID, certPEM: certPEM, keyPEM: keyPEM})
		for _, warning := range tlsCertificateWarnings(certPEM, keyPEM, backupString(row["domain"])) {
			warnings = append(warnings, fmt.Sprintf("规则 %s（%s）：%s", backupString(row["name"]), caddyID, warning))
		}
	}
	return certs, warnings
}

// ruleCertificateRuleIDs 备份规则行中出现的 caddy_id（快照/清理目标集合）。
func ruleCertificateRuleIDs(rows []map[string]any) []string {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		if caddyID, ok := row["caddy_id"].(string); ok && caddyID != "" {
			ids = append(ids, caddyID)
		}
	}
	return ids
}

// captureThreatSourceRows 快照导入前的威胁库源行（按 name 索引），供逐源
// 落盘失败时在事务内整行回滚。读失败返回 nil（失败源随之无本地行
// 可恢复，调用方仍会删除备份行——文件未落盘时宁可少一行也不留假记录）。
func captureThreatSourceRows(ctx context.Context) map[string]map[string]any {
	rows, err := dumpTable(ctx, db.DB, "security_threat_sources")
	if err != nil {
		services.Logf("warn", "配置导入：快照本地威胁库源行失败（失败源将无本地行可恢复）: %v", err)
		return nil
	}
	out := make(map[string]map[string]any, len(rows))
	for _, row := range rows {
		if name := backupString(row["name"]); name != "" {
			out[name] = row
		}
	}
	return out
}

// importRowQuerier 导入事务的单行读取面（*sql.Tx 满足；测试可注入真实 tx
// 的失败形态）。。
type importRowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// readImportOldAutoBackupEnabled 读取导入前的 auto_backup_enabled。
// 错误必须向上返回——调用方据此把「off→on」判定降级为未知并跳过水位重置；
// 禁止把错误吞成 0（会把已启用误判为 off）。
func readImportOldAutoBackupEnabled(ctx context.Context, q importRowQuerier) (int, error) {
	var enabled int
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(auto_backup_enabled,?) FROM global_config WHERE id=1`,
		db.DefaultAutoBackupEnabled).Scan(&enabled); err != nil {
		return 0, err
	}
	return enabled, nil
}

// configBackupAutobanColumns 是自动封禁六列：通用
// `UPDATE global_config` 的写入面，也是运行期收敛（清桶/重算达标/禁用收尾/
// 调度联动）判定的输入面。新增/改名时必须与 services.ReadAutobanConfigFrom
// 的列清单同步——否则导入侧比对到「无变化」而运行期实际已换配置。
var configBackupAutobanColumns = []string{
	"autoban_enabled", "autoban_threshold", "autoban_window_minutes",
	"autoban_duration", "autoban_scope", "autoban_dry_run",
}

// configCarriesAutobanColumns 报告备份全局配置区是否携带自动封禁六列之一
// （携带即可能改写运行值，需要在提交后比对并收敛）。
func configCarriesAutobanColumns(config map[string]any) bool {
	for _, column := range configBackupAutobanColumns {
		if _, carried := config[column]; carried {
			return true
		}
	}
	return false
}

// importAutoBackupResetNeeded 判定导入提交后是否重置自动备份水位（口径
// + 未知态）：仅「导入前开关已知且为 off」才重置（off→on 转换）。
func importAutoBackupResetNeeded(oldEnabledKnown bool, oldEnabled int) bool {
	return oldEnabledKnown && oldEnabled == 0
}

// autoBackupWatermarkEmptyOrStale 判定自动备份水位线是否需要重置
// 空/非法形态恒陈旧；正常形态仅在距上次执行超过 1 分钟时视为陈旧（同一秒内
// 刚落的新鲜水位保持不动，避免覆盖并发保存路径刚写入的值）。
func autoBackupWatermarkEmptyOrStale(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return true
	}
	return time.Since(parsed) > time.Minute
}

// importCountsLabels 导入/导出/自动备份汇总的分表计数标签（单一清单，
// 原 importCountsDetail 函数内局部字面量）。结构性钉测
// TestImportCountsDetailCoversAllBackupTables 要求 configBackupTables
// 每张表在此或显式豁免清单（path_rules 随规则计数、security_policy_bindings
// 为派生数据）——新增备份表漏登记会被当场拦截。
var importCountsLabels = []struct {
	table string
	label string
}{
	{"lb_rules", "规则 %d 条"},
	{"upstreams", "上游 %d 个"},
	{"users", "用户 %d 个"},
	{"api_keys", "密钥 %d 个"},
	{"ca_providers", "CA %d 个"},
	{"certificate_configs", "DNS %d 个"},
	{"cert_jobs", "任务 %d 个"},
	// 追加(用户生产观察):安全域用户内容表补入汇总(绑定表为派生数据不加)。
	{"security_policies", "安全策略 %d 条"},
	{"security_custom_rules", "自定义规则 %d 条"},
	{"security_block_pages", "拦截页 %d 个"},
	{"security_ip_lists", "IP 地址列表 %d 个"},
	{"security_crs_version", "CRS 版本 %d 条"},
	{"security_ip2region_version", "IP2Region 版本 %d 条"},
	{"security_threat_sources", "威胁情报库源 %d 条"},
	{"security_crawler_sources", "爬虫地址库源 %d 条"},
	// 节点拓扑分类（nodes）补入汇总——此前仅选「节点拓扑」时
	// countsSummary 为空串（导入响应尾冒号、自动备份 message 无节点计数）。
	{"nodes", "节点 %d 个"},
}

func importCountsDetail(tables map[string][]map[string]any) string {
	parts := []string{}
	for _, item := range importCountsLabels {
		if rows, ok := tables[item.table]; ok {
			parts = append(parts, fmt.Sprintf(item.label, len(rows)))
		}
	}
	return strings.Join(parts, "；")
}
