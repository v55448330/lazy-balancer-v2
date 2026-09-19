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
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var configBackupTables = []string{"lb_rules", "upstreams", "path_rules", "users", "api_keys", "ca_providers", "certificate_configs", "cert_jobs", "security_policies", "security_policy_bindings", "security_custom_rules", "security_block_pages", "security_ip_lists", "security_crs_version", "security_ip2region_version"}

// SEM44-1(第 44 轮审计 P1):迟到表容缺清单——Version=2 导出清单首发(ff632cd,
// v2.0.10,8 表)与安全族并入(4e46f85,v2.1.1,12 表)之后才加入导出清单的表:
//
//	security_crs_version / security_ip2region_version — v2.1.10(76f616a)起
//	security_ip_lists — v2.2.1(6bf0bf5)起
//
// v2.1.2-v2.1.9(12 表)与 v2.1.10-v2.2.13(14 表)全量备份是合法 Version=2
// 文件,必需表门不得因缺迟到表硬拒;缺席表由导入链「缺席=保留本地」语义承接
// (validateV2Backup 内补空表仅供校验均匀性,importConfigBackupCore 将未实际
// 导出的表还原为缺席,restore 跳过未携带表)。v2.1.1 及更早的文件在完整性
// 校验和门已被拒(R44 C1),与本清单无关。
var configBackupLateTables = map[string]struct{}{
	"security_crs_version":       {},
	"security_ip2region_version": {},
	"security_ip_lists":          {},
}

// 三分类合并(2026-09-19 用户裁定):备份分类=集群同步节,收敛为 3 类——
// 全局配置并入「系统数据」(单行键值表单独成类必产无法导入的死备份,BE-C1-6),
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
	{Key: "security", Label: "安全防护", Tables: []string{"security_policies", "security_policy_bindings", "security_custom_rules", "security_block_pages", "security_ip_lists", "security_crs_version", "security_ip2region_version"}},
}

// normalizeBackupSectionKeys 归一 legacy 分类键:三分类合并前的
// global_config(并入系统数据)与 waf_files(并入安全防护)在导出 query、
// 旧备份体内 sections、auto_backup_sections 存量存储值三处长期存在
// (旧备份必须永久可导入,不设淘汰期)——读侧一律先归一到当前三分类再消费,
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

// parseSectionsParam(A40-2-F5):解析 ?sections= query——逐段 TrimSpace、跳空段,
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

var configBackupV1Tables = []string{"lb_rules", "upstreams", "users", "api_keys", "ca_providers", "certificate_configs", "cert_jobs"}

var configBackupCertJobStatuses = map[string]struct{}{
	"queued": {}, "pending": {}, "processing": {}, "creating_account": {}, "creating_order": {}, "order_created": {},
	"cleanup_dns": {}, "cleanup_warning": {}, "presenting_dns": {}, "waiting_propagation": {}, "dns_propagated": {},
	"accepting_challenge": {}, "validating": {}, "validated": {}, "finalizing": {}, "finalized": {}, "downloading": {},
	"downloaded": {}, "issued": {}, "failed": {}, "waiting_ca": {}, "disabled": {}, "waiting_order_ready": {}, "order_ready": {},
	"waiting_order_valid": {}, "order_valid": {},
}

var configBackupProtectedConfigKeys = map[string]bool{
	"id": true, "is_master": true, "master_url": true, "cluster_token": true,
	"registration_id": true, "registration_secret": true, "applied_version": true,
	"sync_fingerprint": true, "last_sync": true, "last_sync_error": true, "cluster_version": true,
	// R57 C-6：本地节点运行态标记，非配置——导入旧备份会复活陈旧的
	// 「应用失败」横幅（导入提交路径不经过 recordCaddyApplyResult 清空）。
	"caddy_apply_error": true, "registration_confirm_failures": true,
	// CL14-新1(第 14 轮审计):恒同步列排除出备份——现行导出恒 1(UpdateSettings
	// 拒绝禁用+启动迁移回填),排除无信息损失;防 v2.2.7 前存量备份携带 0 值
	// 直写,致节点页「系统数据同步=关闭」假状态至重启(同步行为四个在线强制点
	// 不受影响,纯展示层)。
	"sync_users": true,
}

// A40-2-F6:规则库跳过警告统一文案(审计侧与响应侧共用,全角括号口径)。
const (
	warningWafMetadataSkipped    = "备份不含规则库数据文件——规则库版本记录已跳过（仅 lbbak 完整备份可导入该类）"
	warningWafCRSMetadataSkipped = "备份不含 CRS 数据文件——CRS 版本记录已跳过（仅含该文件的 lbbak 备份可导入）"
	warningWafXdbMetadataSkipped = "备份不含 IP2Region 数据文件——IP2Region 版本记录已跳过（仅含该文件的 lbbak 备份可导入）"
)

var requeueNonTerminalCertJobs = services.RequeueNonTerminalCertJobs

// R56 新发现#1：备份 schema 布尔列全量枚举（校验门与恢复归一双侧共用）。
// 类型绕过的影响面是整个枚举而非单个字段——校验侧 backupBooleanEnabled 此前
// 无 string 分支，"1"/"true" 文本在校验期被读为 false，而 SQLite 列亲和性在
// 恢复期把同一文本转存为 INTEGER 1，同一值在校验期与存储期含义相反（不变量：
// 含义必须两期一致），R55 全部校验门（admin_tls 崩溃循环门、TLSShape 白名单、
// 冲突矩阵）均可被字符串形态击穿。
// 枚举含 INTEGER 声明的 0/1 语义列（api_keys.mcp_enabled/read_only、
// security_policies.waf_check_response）；lb_rules.server_tokens_hidden 是
// 有意的 0/1/2 三态列（rules.go 保存侧允许 2），不在其列。
var backupBooleanTableColumns = map[string][]string{
	"lb_rules":                   {"dynamic_dns", "enable_dns_server", "enable_active_health_check", "tcp_proxy_protocol", "custom_routes_enabled", "enable_tls", "tls_http_redirect", "enable_compress", "enabled", "log_enabled"},
	"upstreams":                  {"dynamic_dns", "enabled"},
	"users":                      {"is_enabled", "mfa_enabled"},
	"api_keys":                   {"is_enabled", "mcp_enabled", "read_only"},
	"ca_providers":               {"enabled"},
	"certificate_configs":        {"enabled"},
	"security_policies":          {"ip_acl_enabled", "ip_whitelist_enabled", "rate_limit_enabled", "enabled", "waf_check_response", "log_request_body"}, // SYSRENDER27-P5-4: ip_whitelist_enabled 补入(R56 枚举漏列)
	"security_custom_rules":      {"enabled"},
	"security_block_pages":       {"is_default"},
	"security_crs_version":       {"auto_update"},
	"security_ip2region_version": {"auto_update"},
}

// audit I-A：备份表 NULL→默认值归一映射（restoreTable 写入侧，覆盖
// configBackupTables 全部 15 表）。默认值与集群快照 dump 侧逐列对齐
// （cluster_snapshot.go 各 snapshot* 的 COALESCE 表达式）——「全量替换」
// 两条通道（备份导入/集群快照）对同一 NULL 行必须产出同一落库值。
// 仅收录「集群 dump 侧已 COALESCE 硬化」或「NULL 命中 raw-scan 消费点」的
// 可空列；生命周期合法可空列（cert_jobs key_pem/message/ca_available_after/
// deployment_available_after/updated_at、users.last_login/password_changed_at、
// api_keys.expires_at/last_used、path_rules.upstreams_json、lb_rules.updated_at、
// certificate_configs.updated_at）保持可空，不入映射。时间列读侧消费类型
// 逐列核实（audit 修正：旧注释「lb_rules 及 ca_providers/certificate_configs
// 的 created_at/updated_at 读侧均为 NullTime/NullString」对集群 dump 通道不
// 成立）——lb_rules/ca_providers/certificate_configs 的 created_at 及
// ca_providers.updated_at 在 cluster_snapshot.go snapshotRules/snapshotACME
// 为裸列直扫 models 的 time.Time 字段（LbRule.CreatedAt、CAProvider 双列、
// CertificateConfig.CreatedAt），NULL→快照构建失败→整集群同步中断，归一
// epoch 文本入映射；lb_rules.updated_at 与 certificate_configs.updated_at
// 扫描目标为 JSONNullTime（内嵌 sql.NullTime，NULL→Valid=false 安全），
// 保持可空。NOT NULL 无默认列（name/username/rule_id 等，及
// security_policy_bindings 两列）不入映射：NULL 由列约束响亮失败（500
// 回滚），不属于静默毒化。例外 lb_rules.id：列为可空普通 INTEGER（db.go
// schema 非 NOT NULL），生产 INSERT 不写 id（新规则恒为 NULL），NULL 静默
// 落库且无害——dump 侧 COALESCE(id,0) 兜底；排序消费点（rules.go ListRules
// 与 services/caddy.go 渲染查询）已显式 ORDER BY rowid（LB41-2，恒 NULL 列
// 排序本退化，rowid 化行为等价），无裸读 id 的消费点，同样不入映射。
// 各表归一列与消费点：
//
//	users                created_at 为 epoch 文本——auth.go Login 的 time.Time
//	                     raw 扫描对 NULL/'' 均报错（'' 驱动回退字符串不可扫），
//	                     NULL→500→永久锁死；其余列对齐 dump :705（is_enabled 1、
//	                     mfa_recovery_codes '[]' 等）
//	api_keys             created_at epoch（apikeys.go scanAPIKeys time.Time raw
//	                     扫描）；布尔列 NULL 同路径 500；其余对齐 dump :730
//	lb_rules             对齐 dump :610（strategy/tls_source/dns_family 等文本、
//	                     tcp_try_interval 250/enable_compress 1 等）；读侧
//	                     lbRuleColumns 已 COALESCE，此处保证两通道落库一致；
//	                     created_at epoch——snapshotRules 裸列直扫 time.Time
//	upstreams            对齐 dump :665（weight 1/protocol 'http'/enabled 0）
//	ca_providers         对齐 dump :537；max_concurrent/min_interval_ms/enabled
//	                     NULL→caproviders.go:74 raw 扫描 500→ACME 签发链断裂；
//	                     created_at/updated_at epoch——snapshotACME 裸列直扫
//	                     time.Time，NULL→快照构建失败→集群同步中断
//	certificate_configs  对齐 dump :553（dns_provider 'dnspod'）；created_at
//	                     epoch——snapshotACME 裸列直扫 time.Time（updated_at 为
//	                     JSONNullTime 扫描，NULL 安全，不入映射）
//	cert_jobs            备份通道专属（集群 dump 仅覆盖 TLS 材料子集）：
//	                     ca_provider_id/renewal_attempts/deployment_attempts NULL→
//	                     certificates.go:91 补偿扫描硬失败/:632 续签扫描静默
//	                     跳行；created_at epoch（certjobs.go:112 raw 扫描）
//	path_rules           备份通道专属：created_at epoch——cluster_snapshot.go:682
//	                     快照 dump 的 time.Time raw 扫描对 NULL 失败→整集群
//	                     同步中断
//	security_crs_version / security_ip2region_version  对齐 dump :466/:483；
//	                     auto_update NULL→自动更新静默失效；consecutive_failures
//	                     NULL→crsupdate.go/crsscheduler.go readConsecutiveFailures
//	                     raw int 扫描（读取失败优雅回退 0，退避退化为固定 1h），
//	                     收录以维持映射判据一致，NULL→0
//	security_policies / security_custom_rules / security_block_pages /
//	security_ip_lists（v2.3.0，entries '[]' 对齐 dump 侧 COALESCE）
//	                     原安全表条目原样并入（C5 KNOWN-GAP-1，dump
//	                     :420/:428/:449 对齐）
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
		"proxy_dial_timeout": int64(0), "proxy_response_header_timeout": int64(0), "proxy_read_timeout": int64(0),
		"proxy_write_timeout": int64(0), "proxy_stream_timeout": int64(0), "proxy_flush_interval": int64(0),
		"proxy_stream_close_delay": int64(0), "host_header": "",
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
	},
	"users": {
		"display_name": "", "is_enabled": int64(1), "password_version": int64(0),
		"created_at":  "1970-01-01 00:00:00",
		"mfa_enabled": int64(0), "mfa_secret": "", "mfa_recovery_codes": "[]",
		"mfa_last_timestep": int64(0),
	},
	"api_keys": {
		"is_enabled": int64(1), "mcp_enabled": int64(0), "read_only": int64(0),
		"mcp_ip_whitelist": "", "created_at": "1970-01-01 00:00:00",
	},
	"ca_providers": {
		"credentials": "", "max_concurrent": int64(1), "min_interval_ms": int64(2000), "enabled": int64(1),
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
		"created_at": "1970-01-01 00:00:00",
	},
	"security_policies": {
		"description": "", "mode": "off", "anomaly_threshold": int64(5),
		"ip_acl_mode": "", "ip_acl_list": "[]", "ip_acl_enabled": int64(0),
		"ip_whitelist": "[]", "ip_whitelist_enabled": int64(1), "ip_blacklist": "[]",
		"rate_limit_enabled": int64(0), "rate_limit_rps": int64(0), "rate_limit_burst": int64(0),
		"crs_rule_groups": "[]", "crs_excluded_rules": "[]", "custom_rules": "[]",
		"block_page_id": int64(0), "block_status_code": int64(0), "enabled": int64(0),
		"updated_by": int64(0), "created_at": "", "updated_at": "",
		"geoip_countries": "[]", "geoip_mode": "off", "waf_check_response": int64(0),
		"log_request_body": int64(0),
		"ip_acl_list_refs": "[]", "ip_whitelist_refs": "[]",
	},
	"security_custom_rules": {
		"description": "", "conditions": "[]", "action": "block", "score": int64(5),
		"enabled": int64(1), "updated_by": int64(0), "created_at": "", "updated_at": "",
	},
	"security_block_pages": {
		"description": "", "content": "", "is_default": int64(0),
		"created_by": int64(0), "created_at": "", "updated_by": int64(0), "updated_at": "",
	},
	// v2.3.0 security_ip_lists：默认值与集群 dump 侧 COALESCE 口径逐列对齐
	// （cluster_snapshot.go snapshotSecurityIPLists——entries '[]'、审计 0/''）。
	"security_ip_lists": {
		"description": "", "category": "", "entries": "[]",
		"created_by": int64(0), "created_at": "", "updated_by": int64(0), "updated_at": "",
	},
	"security_crs_version": {
		"updated_at": "", "auto_update": int64(1), "update_status": "idle", "message": "",
		"last_checked": "", "next_update": "", "trigger": "", "started_at": "", "finished_at": "",
		"consecutive_failures": int64(0),
	},
	"security_ip2region_version": {
		"updated_at": "", "auto_update": int64(1), "update_status": "idle", "message": "",
		"last_checked": "", "next_update": "", "trigger": "", "started_at": "", "finished_at": "",
		"consecutive_failures": int64(0),
	},
}

// 全局配置区布尔键（global_config）。protected 键（is_master/sync_users 等）
// 恢复时不写入；sync_users 虽入 protected（导出剔除）但仍在本布尔键列表中
// 参与类型校验（v2 导入对非布尔形态整包 400 点名拒绝——防御纵深,与归一无关）；
// sync_switches_migrated 为内部迁移标记随导出携带、恢复时写入，同属布尔语义。
var backupBooleanConfigKeys = []string{
	"server_tokens_hidden", "access_log_json", "admin_tls_enabled",
	"sync_global_config", "sync_users", "sync_rules", "sync_waf_files", "sync_security",
	"sync_switches_migrated", "waf_mode4_migrated", // SYSRENDER27-P5-4: waf_mode4_migrated 补入(R56 枚举漏列)
	"mfa_write_guard", "mfa_lockout_enabled",
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

// validateV2BackupBooleanTypes 布尔列类型门（R56 新发现#1）：备份中布尔列的
// JSON 值只能是布尔或 0/1 数值，其余形态（字符串 "1"/"true"、数值 2、数组等）
// 整包拒绝并点名 表/行/字段——与 R48-3 CRS 字段非字符串拒绝同口径。字符串
// 形态在校验期被读为 false、恢复期被 SQLite 亲和性转存为 INTEGER 1，同一值
// 两期含义相反，会击穿全部依赖布尔读取的校验门（admin_tls/TLSShape/冲突矩阵）。
// 注意：legacy（仅 tables）校验和路径在 validateV2Backup 内早退，不经过本门，
// 由 restoreTable 的写入归一兜底（"1"/"true"→1、"0"/"false"→0）。
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

// normalizeBackupBooleanValue 把布尔列值归一为规范 INTEGER 0/1（恢复写入侧兜底）。
// 布尔与 0/1 数值原样规范化；幸存字符串（legacy 校验和路径跳过类型门）按
// "1"/"true"→1、"0"/"false"→0 归一；其余形态（数值 2、无法识别文本）原样透传
// ——规范路径已被 validateV2BackupBooleanTypes 先行拒绝，此处不重复拒绝。
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
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true":
			return int64(1)
		case "0", "false":
			return int64(0)
		}
	}
	return value
}

type importQueueRecovery struct {
	manager *services.CAQueueManager
	done    bool
}

func (recovery *importQueueRecovery) finish() error {
	if recovery.manager == nil || recovery.done {
		return nil
	}
	recovery.done = true
	recovery.manager.Resume()
	return requeueNonTerminalCertJobs()
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

type configBackupMeta struct {
	App        string `json:"app"`
	Version    int    `json:"version"`
	ExportedAt string `json:"exported_at"`
	Checksum   string `json:"checksum,omitempty"`
}

type tableQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func dumpTable(ctx context.Context, database tableQuerier, table string) ([]map[string]any, error) {
	return queryRowsAsMaps(ctx, database, rowQuery{label: "表 " + table, query: "SELECT * FROM " + table})
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
		columns := make([]string, 0, len(row))
		placeholders := make([]string, 0, len(row))
		values := make([]any, 0, len(row))
		for column, value := range row {
			if !valid[column] {
				continue
			}
			// R56 新发现#1：布尔列写入前归一为规范 INTEGER 0/1——legacy 校验和
			// 路径跳过类型门，字符串形态可幸存至此；归一保证存储期值与校验期
			// 读取含义一致（belt-and-braces，规范路径已被类型门先行拒绝）。
			if isBackupBooleanColumn(table, column) {
				value = normalizeBackupBooleanValue(value)
			}
			// audit I-A：全备份表可空列的 NULL 毒化归一（写入侧兜底）——布尔归一
			// 对 nil 透传，故在布尔归一之后把仍为 nil 的列替换为 dump 侧对齐默认值
			// （backupTableNullDefaults）：NULL 布尔列落到 schema/dump 默认（如
			// enabled→0）而非布尔强转；created_at 等被 raw time.Time 扫描消费的
			// 时间列归一为可解析 epoch，NULL/'' 均会使登录/列表扫描 500。
			if value == nil {
				if columnDefault, ok := backupTableNullDefaults[table][column]; ok {
					value = columnDefault
				}
			}
			// CL13-新3(第 13 轮审计):旧从节点库(pre-fix)导出的备份可携带字面量
			// "null" 白名单——middleware 把非空串当白名单配置(Unmarshal null 成功
			// 但 0 CIDR)→ 主端全来源 403 直至重启迁移;导入侧归一为 ''。
			if table == "api_keys" && column == "mcp_ip_whitelist" {
				if sv, ok := value.(string); ok && sv == "null" {
					value = ""
				}
			}
			columns = append(columns, `"`+column+`"`)
			placeholders = append(placeholders, "?")
			values = append(values, value)
		}
		if len(columns) == 0 {
			continue
		}
		query := "INSERT INTO " + table + " (" + joinStrings(columns, ",") + ") VALUES (" + joinStrings(placeholders, ",") + ")"
		if _, err := tx.ExecContext(ctx, query, values...); err != nil {
			return fmt.Errorf("写入表 %s: %w", table, err)
		}
	}
	return nil
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += sep
		}
		out += part
	}
	return out
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
	rows, err := db.DB.QueryContext(ctx, "SELECT caddy_id FROM lb_rules")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ruleIDs := make([]string, 0)
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, err
		}
		ruleIDs = append(ruleIDs, ruleID)
	}
	return ruleIDs, rows.Err()
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

func (h *Handlers) restoreImportRuntime(snapshot importRuntimeSnapshot) error {
	certErr := services.RestoreCertFiles(snapshot.certFiles)
	caddyErr := h.caddyService.ApplyConfig(snapshot.caddyConfig)
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

// normalizeBackupBooleanNulls 把 pre-R24/pre-R36 库导出的 NULL 布尔行归一为当前表结构
// 要求的非空值（lb_rules/upstreams.enabled NULL→0、users.is_enabled NULL→1），与
// R36/R24 迁移口径一致（用户缺省启用，规则/上游缺省禁用）。
// 必须在 checksum 校验之后执行（checksum 覆盖原始内容，先归一会让自带校验和的备份
// 全部误报篡改），并在管理员校验之前执行（backupBooleanEnabled(nil)=false 会把
// 全 null 管理员备份先行 400 拦截，归一不可达——R39-C-1）。
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
// （该表无外键，无 FK 兜底，见 R49 C-#2）。
func validateBackupRuleReferences(tables map[string][]map[string]any) error {
	ruleIDs := make(map[string]struct{}, len(tables["lb_rules"]))
	for _, row := range tables["lb_rules"] {
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
	// R62 C3-F2：upstreams.protocol 按所属规则协议过白名单——与保存侧
	// （validateRulePayloadBeforeSave 内联白名单，handlers.go）同口径。此前 v2 导入链不触碰 upstreams 行，
	// 手造备份可带入 http 规则 + 上游 protocol="tls"（保存侧明确拒绝的形态）：
	// 配置对 Caddy 合法（无 per-upstream 协议字段），导入/启用链零报错，但渲染侧
	// 仅 "https" 触发 TLS transport → 明文 HTTP 打 TLS 端口，该规则全部请求静默 502。
	// 空 protocol 视为 http（与 skipEmptyDomainHTTPRules 的 Round 35 I-10 口径一致）。
	ruleProtocols := make(map[string]string, len(tables["lb_rules"]))
	for _, row := range tables["lb_rules"] {
		if id, ok := row["caddy_id"].(string); ok {
			ruleProtocols[id], _ = row["protocol"].(string)
		}
	}
	for i, row := range tables["upstreams"] {
		protocol, _ := row["protocol"].(string)
		if protocol == "" {
			continue
		}
		ruleID, _ := row["rule_id"].(string)
		// 与保存侧（validateRulePayloadBeforeSave 内联白名单）完全同口径：仅 "http" 走 http/https 白名单，
		// 其余（含空 protocol）按 TCP 侧 tcp/tls 白名单。
		if ruleProtocols[ruleID] == "http" {
			if protocol != "http" && protocol != "https" {
				return fmt.Errorf("备份校验失败：upstreams 第 %d 行（规则 %q）协议 %q 无效（HTTP 规则仅支持 http/https）", i+1, ruleID, protocol)
			}
		} else if protocol != "tcp" && protocol != "tls" {
			return fmt.Errorf("备份校验失败：upstreams 第 %d 行（规则 %q）协议 %q 无效（TCP 规则仅支持 tcp/tls）", i+1, ruleID, protocol)
		}
	}
	// R49 C-#2：security_policy_bindings 无外键约束，悬挂引用可原样落库——绑定指向
	// 不存在的策略时，loadSecurityPolicyContext 查不到策略即按无策略渲染，该规则
	// WAF/限流/GeoIP 全部静默失效（与 R47 B-5 同类的静默 weakening）。保存侧绑定
	// 要求策略与规则均存在，导入校验须同严。
	policyIDs := make(map[int]struct{}, len(tables["security_policies"]))
	for _, row := range tables["security_policies"] {
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

// validateImportedSecurityCustomRules（R72 二十六次 W1-5）：导入路径复用保存侧
// validateSecurityCustomRule 的行级约束——此前导入对 security_custom_rules 零验证，
// 篡改/损坏备份可带入 score=-5（coraza setvar:+-5 运行时减分，异常评分静默失真）
// 或非法 action/名称。与 R56 布尔门同位：结构性校验阶段拒绝，零写入。
func validateImportedSecurityCustomRules(rows []map[string]any) error {
	for i, row := range rows {
		// C5 KNOWN-GAP-1：action/score 为 NULL 的可空形态按 schema/dump 默认
		// （'block'/5，cluster_snapshot.go:428）看待通过校验；写入侧由 restoreTable
		// 归一为同一默认值。本校验在 checksum 之前执行，不得回写行数据（回写会让
		// 自带校验和的备份误报篡改），故只做读取侧替换。
		rule := models.SecurityCustomRule{
			Name:   fmt.Sprintf("%v", row["name"]),
			Action: "block",
			Score:  5,
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
			// C5：NULL 按 schema/dump 默认 5 看待（见上），写入侧归一为同值。
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

// validateV2Backup 校验 v2 备份结构与完整性。返回 usedLegacyChecksum=true 表示
// 走了旧格式（仅 tables）校验和回退——调用方应记审计警告（R43 F-D）。
func validateV2Backup(backup configBackup) (bool, error) {
	if backup.Meta.App != "lazy-balancer-v2" || backup.Tables == nil {
		return false, errors.New("不是有效的 Lazy Balancer 备份文件")
	}
	if backup.Meta.Version != 1 && backup.Meta.Version != 2 {
		return false, fmt.Errorf("不支持的备份版本: %d", backup.Meta.Version)
	}
	// v2.3.0 分类导出可不带全局配置区(未勾选「全局配置」):Config=nil 合法,
	// 校验和按导出时的实际内容(含 null 形态)计算仍完整覆盖;从完整导出中
	// 恶意剥离 Config 会触发校验和不一致而被拒。
	// R45 F-3: v2 备份必带导出时间戳与校验和（v2.1.1 起导出即两者齐备）。剥掉
	// exported_at 或 checksum 的 v2 文件一律按不兼容拒绝——旧格式校验和回退仅限
	// Version==1 的史前导出，防止 Config 区（dns_credentials/acme_email/管理面板
	// TLS 材料）借字段剥离绕过完整性校验。
	if backup.Meta.Version == 2 && backup.Meta.ExportedAt == "" {
		return false, errors.New("备份由 v2.1.1 或更早版本导出，校验和格式不兼容，请使用 v2.1.2 及以上版本重新导出后再导入")
	}
	if backup.Meta.Version == 2 && backup.Meta.Checksum == "" {
		return false, errors.New("备份缺少完整性校验和，请使用 v2.1.2 及以上版本重新导出后再导入")
	}
	// R72 二十六次 W1-5：自定义规则行级验证（保存侧同款约束）。
	if rows, ok := backup.Tables["security_custom_rules"]; ok {
		if err := validateImportedSecurityCustomRules(rows); err != nil {
			return false, err
		}
	}
	if backup.Meta.Checksum != "" {
		checksumPayload, err := json.Marshal(struct {
			Tables map[string][]map[string]any `json:"tables"`
			Config map[string]any              `json:"config"`
		}{backup.Tables, backup.Config})
		if err != nil {
			return false, fmt.Errorf("计算备份校验和失败: %w", err)
		}
		sum := sha256.Sum256(checksumPayload)
		if hex.EncodeToString(sum[:]) != backup.Meta.Checksum {
			// R43 F-D: 旧格式（仅 tables）校验和回退仅限明确的旧格式标记
			// （Version==1 且无 exported_at 的史前导出，R45 F-3 收紧）；新格式文件
			// （带 exported_at）校验和不匹配直接拒绝——否则仅篡改 Config 区
			// （dns_credentials/acme_email/管理面板 TLS 材料）而保留 tables 的文件
			// 可借回退通过完整性校验。
			tablesJSON, _ := json.Marshal(backup.Tables)
			oldSum := sha256.Sum256(tablesJSON)
			tablesOnlyMatch := hex.EncodeToString(oldSum[:]) == backup.Meta.Checksum
			if backup.Meta.ExportedAt == "" && backup.Meta.Version == 1 {
				if tablesOnlyMatch {
					return true, nil
				}
			} else if tablesOnlyMatch {
				// R44 C1: v2.1.1（及更早）导出即「tables-only 校验和 + exported_at
				// 非空」形态——tables 区完整性成立，是合法旧版文件而非篡改证据；
				// 但 Config 区不受旧校验和保护，仍须拒绝导入，仅改报兼容性提示。
				return false, errors.New("备份由 v2.1.1 或更早版本导出，校验和格式不兼容，请使用 v2.1.2 及以上版本重新导出后再导入")
			}
			return false, errors.New("备份校验和不匹配，文件可能已被篡改或损坏")
		}
	}
	// R39 C-1: 归一须在 checksum 校验之后（避免自带校验和的备份被误判篡改）、
	// 管理员校验之前（backupBooleanEnabled(nil)=false 会先行 400 拦截全 null 管理员备份）。
	normalizeBackupBooleanNulls(backup.Tables)
	requiredTables := configBackupTables
	if backup.Meta.Version == 1 {
		requiredTables = configBackupV1Tables
	}
	// v2.3.0 分类导出只含所选分类的表:必需表清单仅对「全量形态」生效——
	// 三分类合并(2026-09-19)后以三类表族齐备判全量(全量导出恒含
	// users/lb_rules/security;V1 恒全量)。旧判定「含 users 即全量」会把
	// users 分类备份(系统数据+全局配置)误判为全量并以缺表拒绝——正是
	// BE-C1-6 要消灭的死备份形态。分类备份只要求至少一张已知表,完整性
	// 由校验和兜底。
	_, hasUsers := backup.Tables["users"]
	_, hasRules := backup.Tables["lb_rules"]
	_, hasSecurity := backup.Tables["security_policies"]
	if (hasUsers && hasRules && hasSecurity) || backup.Meta.Version == 1 {
		for _, required := range requiredTables {
			if _, exists := backup.Tables[required]; exists {
				continue
			}
			// SEM44-1:迟到表容缺(见 configBackupLateTables)——Version=2 导出
			// 清单中途新增的表,此前时代的合法全量备份不含,缺席不拒绝。
			if _, late := configBackupLateTables[required]; late {
				continue
			}
			return false, errors.New("备份缺少必需的数据表: " + required)
		}
	} else {
		known := 0
		for _, table := range configBackupTables {
			if _, exists := backup.Tables[table]; exists {
				known++
			}
		}
		if known == 0 {
			return false, errors.New("备份不包含任何已知数据表")
		}
	}
	for _, table := range configBackupTables {
		if _, exists := backup.Tables[table]; !exists {
			backup.Tables[table] = []map[string]any{}
		}
	}
	// R56 新发现#1：布尔列类型门须在 normalizeBackupBooleanNulls 之后（NULL 已归一
	// 为 0/1 数值，不会被误判）、逐行校验之前（字符串布尔先行 400，不再进入下游
	// backupBooleanEnabled 读取链）。
	if err := validateV2BackupBooleanTypes(backup); err != nil {
		return false, err
	}
	for _, job := range backup.Tables["cert_jobs"] {
		status, ok := job["status"].(string)
		if !ok {
			return false, errors.New("证书任务状态不能为空")
		}
		if _, allowed := configBackupCertJobStatuses[status]; !allowed {
			return false, fmt.Errorf("无效的证书任务状态: %s", status)
		}
	}
	const invalidCredentialsMsg = "备份包含无效的凭证格式（ca_providers.credentials / certificate_configs.dns_credentials 需为 JSON 对象）"
	for _, provider := range backup.Tables["ca_providers"] {
		if err := validateCredentialsJSONObject(backupString(provider["credentials"])); err != nil {
			return false, errors.New(invalidCredentialsMsg)
		}
		// CERT44-1(第 44 轮审计 P2):provider 白名单与 directory_url 官方常量
		// 覆写,与保存/更新侧(services/caproviders.go UpdateCAProvider
		// :194-201)同口径——provider 必须 ∈{letsencrypt,zerossl},否则恶意
		// CA 类型经备份落库绕过保存侧门;directory_url 无条件覆写为官方常量,
		// 消除备份携带恶意 ACME 目录 URL 落库(签发/续签被导向攻击者服务器)。
		switch backupString(provider["provider"]) {
		case services.ProviderLetsEncrypt:
			provider["directory_url"] = services.LetsEncryptDirectoryURL
		case services.ProviderZeroSSL:
			provider["directory_url"] = services.ZeroSSLDirectoryURL
		default:
			return false, fmt.Errorf("备份包含无效的 CA 提供商类型: %s（必须为 %s 或 %s）", backupString(provider["provider"]), services.ProviderLetsEncrypt, services.ProviderZeroSSL)
		}
	}
	for _, certCfg := range backup.Tables["certificate_configs"] {
		if err := validateCredentialsJSONObject(backupString(certCfg["dns_credentials"])); err != nil {
			return false, errors.New(invalidCredentialsMsg)
		}
	}
	// v2.3.0 分类导出可不带 users 表:不含/空=本地用户不动,管理员门跳过
	// (全量导出恒有≥1 管理员;上方 normalize 已把缺失表补成空切片,故按长度判)
	if len(backup.Tables["users"]) == 0 {
		return false, nil
	}
	for _, user := range backup.Tables["users"] {
		if role, _ := user["role"].(string); role == "admin" && backupBooleanEnabled(user["is_enabled"]) {
			return false, nil
		}
	}
	return false, errors.New("备份必须至少包含一个已启用的管理员账号")
}

// validateV2BackupRules 逐行校验备份 lb_rules 的端口与特性（校验侧保守口径）。
// 必须在 skipEmptyDomainHTTPRules 之后执行（R38 C-3）：空域名行无论端口/特性
// 是否非法都一律软跳过，不被逐行校验先行整包 400。
func validateV2BackupRules(tables map[string][]map[string]any) error {
	rows := tables["lb_rules"]
	pathRows := tables["path_rules"]
	for index, rule := range rows {
		protocol, _ := rule["protocol"].(string)
		listenPort, validPort := backupInteger(rule["listen_port"])
		if !validPort {
			return fmt.Errorf("规则 #%d：监听端口必须为整数", index+1)
		}
		if err := validateRuleListenPort(protocol, listenPort); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
		// R62 B-NEW-1（用户裁决：系统不支持通配符域名）：创建/更新（rules.go CanonicalDomains）、
		// 启用/复制（:2136/:2327 同门）、v1 导入（isValidDomain 拒绝 '*'）均拒绝通配与非法
		// 形态，v2 导入是最后一个能把它带入运行库的门（此前仅 acme_dns 行有
		// ValidateACMEDomains 门，manual/无 TLS 行的域名原样落库）。与保存侧 :609/:613
		// 同口径——http 规则域名必须非空且可规范化（idna 拒绝 '*'、IP 形态、超长段），
		// 否则整包 400：通配域名进入 lb_rules 后安全事件归属映射对该规则整体跳过
		// （db.CanonicalDomains 报错即 continue），Enable/Update 又被同门卡死成
		// 「永不启用」的死行。空 protocol 与 skipEmptyDomainHTTPRules 的 Round 35 I-10
		// 同口径按 HTTP 处理（空域名行已在先前环节软跳过，此处非空域名必须可规范化）。
		// 合法值同时钳回规范形式（小写/punycode/去重），与行级钳制哲学一致。
		if protocol == "http" || protocol == "" {
			canonicalDomain, err := db.CanonicalDomains(backupString(rule["domain"]))
			if err != nil {
				return fmt.Errorf("规则 #%d（%s）：域名格式无效（系统不支持通配符域名）: %w", index+1, backupString(rule["name"]), err)
			}
			rule["domain"] = canonicalDomain
		}
		// Round 29 G-1: 补传 ListenPort/EnableTLS/TLSHTTPRedirect 等字段，启用
		// validateRuleFeatures 的 80 端口 + TLS 跳转自环检查（此前仅端口/策略校验，
		// 备份中自环规则校验放行并导入成功，生成自环 Location）；行内有
		// custom_routes_enabled/path_rules 信息时一并传入，保持与保存路径同口径。
		// Round 30 F-1: 禁用规则不参与渲染（caddy.go WHERE enabled=1），其
		// 80+TLS+跳转组合无运行时影响；若仍按启用态校验会整包拒绝，导出→导入
		// 往返断裂（与 v1 路径自环规则软跳过口径一致），故禁用行将
		// EnableTLS/TLSHTTPRedirect 置 false，其余字段校验保留。
		enabled := backupRuleEnabled(rule)
		// R67 C-N2：注入 DynamicDNS + 启用上游计数——此前两者恒零值，保存侧
		// validateRuleFeatures 的「动态上游单启用」门（Round 37 I-8）在导入链
		// 恒不触发：启用行延迟到 Caddy 阶段以整包 400 形态失败（fail-closed 但
		// 与同文件逐规则点名口径不一致），禁用行入库后成「永不启用」死行。
		// 与保存/Duplicate 链同门（DuplicateRule 为此专门 hydrate 上游计数，
		// rule_features.go R57 C-8 注释）。
		ruleID := backupString(rule["caddy_id"])
		enabledHosts := make([]string, 0, 2)
		for _, row := range tables["upstreams"] {
			if backupString(row["rule_id"]) == ruleID && backupBooleanEnabled(row["enabled"]) {
				enabledHosts = append(enabledHosts, backupString(row["host"]))
			}
		}
		input := ruleFeatureInput{
			Protocol:                   protocol,
			Strategy:                   backupString(rule["strategy"]),
			DynamicDNS:                 backupBooleanEnabled(rule["dynamic_dns"]),
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
		if pathRules, found, err := backupPathRulesForRule(pathRows, backupString(rule["caddy_id"])); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		} else if found {
			// Round 30 F-6: 保存路径先 normalizePathRules（TrimSpace）再校验
			// （createRuleFeatures/updateRuleFeatures），备份路径此前直传导致手造备份
			// 含前导空格路径时 validateRuleFeatures 的 HasPrefix("/") 误拒绝。
			input.PathRules = normalizePathRules(pathRules)
		}
		// R59 C-F1：规则级 request_body_max_size_mb 导入钳制 [0,4096]（写回行
		// 数据，restoreTable 直写不再携带越界值）——R58 C-N2 只钳了全局
		// backup.Config，行级向量经 restoreTable 原样落库，渲染侧 MB→字节
		// int64 乘法回绕会让该规则的 body 限制静默取消。
		if rawBody, exists := rule["request_body_max_size_mb"]; exists {
			if n, ok := backupInteger(rawBody); ok && (n < 0 || n > 4096) {
				clamped := 0
				if n > 4096 {
					clamped = 4096
				}
				rule["request_body_max_size_mb"] = clamped
			}
		}
		// R57 C-5（R58 C-N1 修正）：dynamic_dns+dns_family 走与保存侧同口径的
		// 枚举校验——此前 input 不带 DnsFamily，垃圾值原样落库后渲染端 versions
		// 双 false 解析退化为双栈（fail-open 方向）。合法值含 "both"：UI 双选
		// IPv4+IPv6 时前端写 'both'（Rules.vue:2415）、渲染端 case "both" 双栈
		// （caddy.go）——R57 初版漏列 both 会把启用双栈的规则导出物整包误拒，
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
// R55 C-1：与 cert_jobs 不变量同序——必须在 disableV2RuleConflicts 之后执行，
// 将被冲突自动置禁用的规则不投入运行，不参与运行态形态校验（此前垃圾
// tls_source 的冲突行会把可自愈备份整包 400，与 cert_jobs 豁免哲学不一致）。
// 导入/预览双路径同序调用（ImportConfigBackup / ValidateConfigImport）。
// R54 新发现1：启用 TLS 的行先做 tls_source 白名单——保存侧（rules.go）
// 与启用侧（rule_features.go validateStoredRuleConfig）均对非 manual/acme_dns
// 400，导入此前是唯一能放行该形态的门：”/垃圾值行两个分支都不命中、整包
// 放行，渲染侧 availableCerts 仅认 manual/acme_dns → 无证书、无
// tls_connection_policies → TLS 端口明文服务（与 R53 发现2 同类缺口）。
// R43 F-C / R46 C-B-1: 启用的手动 TLS 规则必须携带证书与私钥（镜像保存/启用侧
// rule_features.go validateStoredRuleConfig 口径），拒绝时点名规则。
// 导入此前是唯一能绕过该校验的门：无证书规则不在 availableCerts 内 → 无
// TLS policy → TLS 端口明文服务，且 autohttps.disable_certificates 阻止
// Caddy 自动签发自愈。
func validateV2BackupTLSShape(tables map[string][]map[string]any) error {
	_, err := validateV2BackupTLSShapeSoft(tables, false)
	return err
}

// validateV2BackupTLSShapeSoft 同 validateV2BackupTLSShape,额外支持
// CERT41-1 软降级:softLiveACMERefs=true 时,「备份不含 cert 表、按 live
// 解析」失败的 ACME 引用不整包 400,计入返回的悬挂数(调用方降级警告,
// 与 R39-14 预检对称;导入/预览双路径同序)。返回 (悬挂数, 硬错误)。
func validateV2BackupTLSShapeSoft(tables map[string][]map[string]any, softLiveACMERefs bool) (int, error) {
	acmeDangling := 0
	for index, rule := range tables["lb_rules"] {
		protocol, _ := rule["protocol"].(string)
		// R62 C2-N1（传播通道钳制）：TCP 规则不终结入站 TLS，携带 enable_tls=1 +
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
		// R53 发现2：启用的 acme_dns 行按 validateRuleACMEReferences 同口径校验——
		// acme_config_id=0/悬挂/已禁用与 ca_provider_id 悬挂/已禁用均整包 400。
		// 导入把规则已启用地带入运行态，R52 F-2 的 EnableRule 门拦不住这条路径；
		// 坏行导入后 TLS 端口明文服务且签发必败，与手动证书缺材料的拒绝理由同型。
		if tlsSource == "acme_dns" {
			// R55 C-2：导入侧补 ACME 域名合法性门（与保存侧 rules.go / 启用侧
			// createOrRequeueCertJob 同口径，单域名或根域+www）——此前导入链无任何
			// ValidateACMEDomains 等价校验，手造备份可带入 "a.com,b.org" 形态，
			// 运行期 certJobRuleApplicable 严格规范化失败 → 续签永久断链且
			// TLS 端口明文服务。
			if err := services.ValidateACMEDomains(backupString(rule["domain"])); err != nil {
				return 0, fmt.Errorf("规则 #%d（%s）：%w", index+1, backupString(rule["name"]), err)
			}
			if err := validateBackupACMEReferenceIDs(tables, rule); err != nil {
				// CERT41-1:「备份不含 cert 表、按 live 解析」失败在软降级方向
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

// validateV2BackupCertJobs 校验最终处于启用态的 acme_dns 规则携带域名匹配的
// 证书任务行。R53-A-2：导入为全量替换（deleteOrder 清光 cert_jobs 后仅插入
// 备份行），缺失即导入后续签永久断链且无信号（周期路径只遍历已存在的任务行，
// 不补建）。R54 新发现2：必须在 disableV2RuleConflicts 之后执行——将被冲突
// 自动置禁用的规则不投入运行，不参与运行态不变量；此前不变量先执行会把可自愈
// 的冲突备份整包 400。R54 新发现3：不变量还须校验 job.domain 与规则域名一致
// （canonical/reversed 双形式，与 certjobs.go 续签扫描 lower+replace 口径同型）——
// 错域残留行只凭存在性放行后，续签扫描按 rule_id+domain 匹配永不命中，断链同果。
// R55 C-2：域比较两侧（规则域名与任务域名）均须可规范化——
// canonicalACMEDomainForJobLookup 的原串回退是查询侧良性 miss 语义（视为无任务），
// 用于校验侧会把 "a.com,b.org" 等不可规范化形态假放行；与运行期
// certJobRuleApplicable 的严格 CanonicalACMEDomains 全等语义对齐，不可规范化即
// 响亮拒绝。两侧规范化后大小写/空白/顺序变体天然归一（排序规范形式）。
func validateV2BackupCertJobs(tables map[string][]map[string]any) error {
	jobsByRule := make(map[string][]string)
	for _, job := range tables["cert_jobs"] {
		if backupString(job["status"]) == "disabled" {
			continue
		}
		if ruleID, ok := job["rule_id"].(string); ok && ruleID != "" {
			jobsByRule[ruleID] = append(jobsByRule[ruleID], backupString(job["domain"]))
		}
	}
	for index, rule := range tables["lb_rules"] {
		protocol, _ := rule["protocol"].(string)
		if !backupRuleEnabled(rule) || protocol != "http" ||
			!backupBooleanEnabled(rule["enable_tls"]) || backupString(rule["tls_source"]) != "acme_dns" {
			continue
		}
		jobDomains := jobsByRule[backupString(rule["caddy_id"])]
		if len(jobDomains) == 0 {
			return fmt.Errorf("规则 #%d（%s）：启用的 ACME 规则缺少证书签发任务（cert_jobs 无非 disabled 行），导入后将无法自动续签", index+1, backupString(rule["name"]))
		}
		canonical, err := services.CanonicalACMEDomains(backupString(rule["domain"]))
		if err != nil {
			return fmt.Errorf("规则 #%d（%s）：ACME 域名不合法（仅支持单域名或根域+www 二级域名），导入后将无法自动续签", index+1, backupString(rule["name"]))
		}
		matched := false
		for _, jobDomain := range jobDomains {
			jobCanonical, err := services.CanonicalACMEDomains(jobDomain)
			if err != nil {
				return fmt.Errorf("规则 #%d（%s）：证书任务域名 %q 不合法（仅支持单域名或根域+www 二级域名），导入后将无法自动续签", index+1, backupString(rule["name"]), jobDomain)
			}
			if jobCanonical == canonical {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("规则 #%d（%s）：证书任务域名与规则域名不一致，导入后将无法自动续签", index+1, backupString(rule["name"]))
		}
	}
	return nil
}

// validateV2BackupSecurityPolicies 按保存侧同口径（validateAndNormalizeCRSField，
// security.go）校验备份 security_policies 的 crs_rule_groups/crs_excluded_rules，
// 拒绝时点名策略；合法行同步写回归一值（空串→"[]"），保持列形状一致。
// R48-3：原始值存在且非字符串（数字/布尔/数组，null/缺省除外）直接拒绝——
// 保存侧 JSON 绑定对同值 400，导入侧不得经 backupString 静默归一放行。
// R47 B-5：旧版备份可能携带 "941" 式组号或含空白的条目——导入原样落库后
// REQUEST-9<code>-*.conf glob 零匹配，blocking 模式静默无任何 CRS 规则生效。
// W2（v2.3.0）：security_ip_lists 随备份全量替换——先校验列表行 entries
// 形状（JSON 数组文本）并收集 id 集，再校验策略 ip_acl_list_refs/
// ip_whitelist_refs（整数数组 JSON 文本，逐 id 对备份内列表解析——导入为
// 全量替换，备份行才是导入后的真实数据，与 validateBackupRuleReferences
// 的备份内解析哲学一致；悬挂引用会让引用展开静默跳过，UI 宣称的引用
// 控制静默失效）。
func validateV2BackupSecurityPolicies(tables map[string][]map[string]any) error {
	ipListIDs := make(map[int]struct{}, len(tables["security_ip_lists"]))
	for index, row := range tables["security_ip_lists"] {
		if id, ok := backupInteger(row["id"]); ok {
			ipListIDs[id] = struct{}{}
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
				// SECLB26-P2-2(第 26 轮审计):导入路径按 validIPOrCIDR 口径校验
				// 条目值——zone 形态(fe80::1%eth0)等无效条目落库后 coraza
				// @ipMatch 静默丢弃(零留痕),必须拒绝。
				for ei, entry := range parsed {
					entryMap, ok := entry.(map[string]any)
					if !ok {
						// SECLB27-P2-1(第 27 轮审计):非对象成员(裸字符串等)
						// 不得 continue 放行——zone 形态可藏其中,同保存侧口径拒绝。
						return fmt.Errorf("安全 IP 列表 #%d 条目 #%d：需为 JSON 对象（含 value 字段），实际类型 %T", index+1, ei+1, entry)
					}
					// SECLB28-P4-3(第 28 轮审计):缺/空/非 string value 同样拒绝——
					// 非 string value(数字等)落库后渲染侧 Unmarshal 整表静默丢弃
					// (securityiplists.go:120/177),fail-open。
					value, ok := entryMap["value"].(string)
					if !ok || value == "" {
						return fmt.Errorf("安全 IP 列表 #%d 条目 #%d：缺 value 字段或为空/非字符串", index+1, ei+1)
					}
					if !validIPOrCIDR(value) {
						return fmt.Errorf("安全 IP 列表 #%d 条目 #%d：无效 IP/CIDR 值 %q（zone 形态如 fe80::1%%eth0 不被 WAF 引擎支持）", index+1, ei+1, value)
					}
				}
			}
		}
	}
	for index, policy := range tables["security_policies"] {
		name := backupString(policy["name"])
		for _, field := range []string{"crs_rule_groups", "crs_excluded_rules"} {
			raw, exists := policy[field]
			if exists && raw != nil {
				if _, ok := raw.(string); !ok {
					return fmt.Errorf("安全策略 #%d（%s）：%s 需为字符串（JSON 数组文本），实际类型 %T", index+1, name, field, raw)
				}
			}
			value := backupString(raw)
			if err := validateAndNormalizeCRSField(field, &value); err != nil {
				return fmt.Errorf("安全策略 #%d（%s）：%w", index+1, name, err)
			}
			policy[field] = value
		}
		// R51 B-F1：三个枚举字段按 Create 侧口径（security.go CreateSecurityPolicy）
		// 归一/校验。R50 前的旧备份合法携带空串（旧 Create 不归一、列默认 ''），
		// restoreTable 原样落库后发射端仅 allow/deny/bypass 等具名分支产出规则，
		// "" 零产出——启用态 ACL 零强制而 UI 宣称控制已启用（mode/geoip_mode 同型
		// 漂移）。空串/null/缺省归一为默认值；非空值复用保存侧枚举校验拒绝；
		// 非字符串值与 R48-3 同口径拒绝（保存侧 JSON 绑定对同值 400）。
		for _, field := range []string{"mode", "ip_acl_mode", "geoip_mode"} {
			raw, exists := policy[field]
			if exists && raw != nil {
				if _, ok := raw.(string); !ok {
					return fmt.Errorf("安全策略 #%d（%s）：%s 需为字符串，实际类型 %T", index+1, name, field, raw)
				}
			}
		}
		// W3-R44-3(第 44 轮 W3 评审):429 已剔出保存侧白名单(SEC44-1)——
		// 导入侧归一为 403,与 CERT44-1 同格(导入不宽于保存侧),修复前时代
		// 的合法备份不因新白名单硬拒。
		if v, ok := backupInteger(policy["block_status_code"]); ok && v == 429 {
			policy["block_status_code"] = int64(403)
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
		if err := validateSecurityPolicyEnums(mode, ipACLMode, geoIPMode, 0, 0); err != nil {
			return fmt.Errorf("安全策略 #%d（%s）：%w", index+1, name, err)
		}
		// SECLB27-P2-1(第 27 轮审计):策略内联 IP 三字段按保存侧
		// validateIPCIDRList 口径校验——备份导入落库后 coraza @ipMatch
		// 对无效条目静默丢弃,必须拒绝。
		for _, field := range []string{"ip_acl_list", "ip_whitelist", "ip_blacklist"} {
			raw := policy[field]
			// SECLB28-P4-2(第 28 轮审计):非字符串类型门(R48-3 同型)——
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
		// R58 C-N4（R57 B-#2 遗留）：导入侧限流形状与保存侧 validateRateLimitShape
		// 同口径——enabled=true 而 rps<=0 时发射分支直接跳过限流 handler，而
		// 汇总/绑定宣称已启用；旧备份（保存侧校验前导出）可携带该形状经导入
		// 复活。与三枚举同哲学：只做拒绝（数值语义无安全默认值可归一）。
		if backupBooleanEnabled(policy["rate_limit_enabled"]) {
			rps, rpsOK := backupInteger(policy["rate_limit_rps"])
			burst, burstOK := backupInteger(policy["rate_limit_burst"])
			if (rpsOK && rps < 1) || (burstOK && burst < 0) || !rpsOK {
				return fmt.Errorf("安全策略 #%d（%s）：启用限流时 rate_limit_rps 必须 ≥1、rate_limit_burst 不能为负", index+1, name)
			}
			// R69 C-N2：上界与保存侧同口径——渲染侧 rps*60/rps+burst 的 int64 溢出防线。
			if rps > 1_000_000_000 || burst > 1_000_000_000 {
				return fmt.Errorf("安全策略 #%d（%s）：rate_limit_rps/burst 过大（上限 1000000000）", index+1, name)
			}
		}
		// R58 B-N3：geoip_countries 形状按保存侧 ValidateGeoIPCountries 同口径
		// （空串/缺省放行——与三枚举的「无值归一」一致；有值则必须是合法 JSON
		// 数组文本且省份可判）。引用块（block_page_id）在备份缺 security_block_pages
		// 表时校验会误拒全量替换导入（表本身可选），保留为运行时 JOIN 语义
		// （悬挂绑定在 JOIN 中不可见、不产出规则——与 R33 F10 记录的口径一致）。
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
		// W2：refs 两列按保存侧同口径校验——字符串列承载整数数组的 JSON
		// 文本（空串/null/缺省视同 '[]' 放行，写入侧由 restoreTable 归一），
		// 非字符串类型与 R48-3 同口径拒绝。
		// 审计 U3-F5：crs_excluded_rules.listRefs 存在性校验——与两 refs 列同口径
		//（"备份内解析哲学"），悬空引用在正常主端不可达（保存 400/删除 409 双门），
		// 但手工编辑/带外改库导出的备份可携带；落库后发射侧静默缩小匹配集。
		if excludedRaw, exists := policy["crs_excluded_rules"]; exists && excludedRaw != nil {
			if excludedStr, ok := excludedRaw.(string); ok && strings.TrimSpace(excludedStr) != "" {
				for _, entry := range services.ParseCRSExcludedRules(excludedStr) {
					for _, refID := range entry.ListRefs {
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
			for _, id := range refs {
				if _, exists := ipListIDs[id]; !exists {
					return fmt.Errorf("安全策略 #%d（%s）：引用了不存在的 IP 列表 %d", index+1, name, id)
				}
			}
		}
	}
	return nil
}

// validateBackupACMEReferenceIDs 按 validateRuleACMEReferences（rule_features.go）
// 同口径校验备份行的 ACME 引用，错误文案保持一致。引用优先在备份自带表中解析——
// 导入为全量替换（deleteOrder 清光 live 的 certificate_configs/ca_providers），
// 备份行才是导入后的真实数据；备份缺该表时回退 live 表（直测/非常规调用场景，
// 及 CERT41-1 起「该 cert 表不参与本次分类导入」的常规场景——sections 过滤前置
// 后，过滤掉的表在 backup.Tables 中缺席，live 回退自动等于「过滤后导入表∪live
// 保留表」正确口径）。配置/提供商行缺 enabled 键时按表默认值 TRUE 处理（与
// backupRuleEnabled 的校验侧口径一致）。
// CERT41-1：live 回退解析失败的错误包装为 acmeLiveRefUnresolvedError——分类
// 导入「导规则不导系统数据」且备份从未携带 cert 表时，调用方按 R39-14 对称
// 语义把它降级为悬挂警告；其余错误（备份行解析失败、acme_config_id=0、DB
// 查询失败）维持整包 400。
func validateBackupACMEReferenceIDs(tables map[string][]map[string]any, rule map[string]any) error {
	acmeConfigID, ok := backupInteger(rule["acme_config_id"])
	if !ok || acmeConfigID == 0 {
		return errors.New("使用 ACME 签发时必须选择 DNS 提供商配置")
	}
	configOK := false
	configFromLive := false
	if configRows, exists := tables["certificate_configs"]; exists {
		for _, configRow := range configRows {
			id, idOK := backupInteger(configRow["id"])
			if idOK && id == acmeConfigID {
				enabledRaw, hasEnabled := configRow["enabled"]
				configOK = !hasEnabled || backupBooleanEnabled(enabledRaw)
			}
		}
	} else {
		configFromLive = true
		if err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM certificate_configs WHERE id = ? AND enabled = 1)", acmeConfigID).Scan(&configOK); err != nil {
			return fmt.Errorf("校验 DNS 提供商配置失败: %v", err)
		}
	}
	if !configOK {
		err := errors.New("选择的 DNS 提供商配置不存在或已禁用")
		if configFromLive {
			return &acmeLiveRefUnresolvedError{inner: err}
		}
		return err
	}
	caProviderID, ok := backupInteger(rule["ca_provider_id"])
	if !ok || caProviderID == 0 {
		return nil
	}
	providerOK := false
	providerFromLive := false
	if providerRows, exists := tables["ca_providers"]; exists {
		for _, providerRow := range providerRows {
			id, idOK := backupInteger(providerRow["id"])
			if idOK && id == caProviderID {
				enabledRaw, hasEnabled := providerRow["enabled"]
				providerOK = !hasEnabled || backupBooleanEnabled(enabledRaw)
			}
		}
	} else {
		providerFromLive = true
		if err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM ca_providers WHERE id = ? AND enabled = 1)", caProviderID).Scan(&providerOK); err != nil {
			return fmt.Errorf("校验 CA 提供商失败: %v", err)
		}
	}
	if !providerOK {
		err := errors.New("指定的 CA 提供商不存在或已禁用")
		if providerFromLive {
			return &acmeLiveRefUnresolvedError{inner: err}
		}
		return err
	}
	return nil
}

// acmeLiveRefUnresolvedError 标记「备份不含该 cert 表、按 live 解析」失败的
// ACME 引用错误（CERT41-1）。导入/预览在「导规则不导 cert 配置且备份从未
// 携带 cert 表」方向经 errors.As 识别并降级为悬挂警告（与 R39-14 对称，
// 不阻断）；其余方向维持整包 400。错误文案与硬拒绝口径一致。
type acmeLiveRefUnresolvedError struct{ inner error }

func (e *acmeLiveRefUnresolvedError) Error() string { return e.inner.Error() }
func (e *acmeLiveRefUnresolvedError) Unwrap() error { return e.inner }

// validateV2BackupAdminTLS 按 UpdateAdminTLS 同口径校验备份全局配置区的
// admin_tls_*：缺省键合并当前库内值（与 UpdateAdminTLS 的合并语义一致），
// 启用态 mode 白名单 + upload 模式证书配对/有效期。R55 C-4：导入此前无等价
// 校验直接落库，坏配置（enabled+upload+空证书或过期证书）使下次启动
// ResolveCertificate 失败即进程退出（main.go），形成崩溃循环——导入必须
// 整包 400（零写入语义，导入/预览双路径同序调用）。
func validateV2BackupAdminTLS(config map[string]any) error {
	if config == nil {
		return nil
	}
	// R56 新发现#2：仅当备份实际携带 admin_tls_* 键时才合并校验——该键组不受
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
	merged := services.LoadAdminTLSConfig()
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
		// R56 新发现#1：legacy（仅 tables）校验和路径跳过布尔类型门，字符串形态
		// 仍可到达读取链——按存储期 SQLite 亲和性同口径解读（"1"/"true" 落库为
		// INTEGER 1），保证校验期与存储期含义一致；其余文本与落库值（非 1）一致
		// 视为 false。
		normalized := strings.ToLower(strings.TrimSpace(value))
		return normalized == "1" || normalized == "true"
	default:
		return false
	}
}

// backupRuleEnabled 读取备份行 enabled 字段：校验侧保守口径——缺省视为启用以覆盖
// 自环/遮蔽检查（不放松校验）；存储口径 NULL 视同禁用（R36 迁移 + IIF）。
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

// backupContainsUsername 报告备份 users 表是否包含指定账户。审计 B3 自锁门使用：
// 导入全量替换 users/api_keys 且递增 password_version 吊销现有 JWT，备份缺少
// 操作者自身账户时导入后需用备份内账户重新登录——2026-09-18 裁定降级为
// warning+照常导入(见下方 operatorReplaced)。
// acmeRefResolvablePostImport:导入后某 ACME 引用(id)是否仍可解析——备份携带
// 该表时以备份行为准(整表替换),否则 live 表原样保留(R39-14 预检口径)。
func acmeRefResolvablePostImport(tables map[string][]map[string]any, table string, id int) bool {
	if rows, carried := tables[table]; carried {
		for _, row := range rows {
			if rid, ok := backupInteger(row["id"]); ok && rid == id {
				enabledRaw, hasEnabled := row["enabled"]
				return !hasEnabled || backupBooleanEnabled(enabledRaw)
			}
		}
		return false
	}
	var exists bool
	if err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM "+table+" WHERE id = ? AND enabled = 1)", id).Scan(&exists); err != nil {
		return false
	}
	return exists
}

// ip2regionTagFromBackup:从备份表区读 IP2Region 版本 tag(R39-12:随文件
// 传入 ApplyWafFileBundle,保持 .version 伴生文件与记录一致)。
func ip2regionTagFromBackup(tables map[string][]map[string]any) string {
	rows := tables["security_ip2region_version"]
	if len(rows) == 0 {
		return ""
	}
	tag, _ := rows[0]["version"].(string)
	return tag
}

func backupContainsUsername(users []map[string]any, username string) bool {
	for _, row := range users {
		if backupString(row["username"]) == username {
			return true
		}
	}
	return false
}

// backupPathRulesForRule 从备份 path_rules 表收集指定规则的自定义路径规则，
// 供 validateV2Backup 按保存路径同口径校验；无该规则行时返回 found=false。
// upstreams_json 形态错误必须上抛（R57 C-1）：吞错后 Upstreams=nil 被
// validateRuleFeatures 按「回退主上游」放行，落库后 loadPathRulesBatch 对
// 同一 JSON 硬失败——ListRules/GetRule/UpdateRule/EnableRule 全 500。
func backupPathRulesForRule(rows []map[string]any, ruleID string) ([]models.PathRule, bool, error) {
	if ruleID == "" {
		return nil, false, nil
	}
	found := false
	pathRules := make([]models.PathRule, 0)
	for i, row := range rows {
		ownerID, _ := row["rule_id"].(string)
		if ownerID != ruleID {
			continue
		}
		found = true
		pathRule := models.PathRule{
			SortOrder: backupInt(row["sort_order"]),
			MatchType: backupString(row["match_type"]),
			Path:      backupString(row["path"]),
		}
		if raw, ok := row["upstreams_json"].(string); ok && raw != "" {
			if err := json.Unmarshal([]byte(raw), &pathRule.Upstreams); err != nil {
				return nil, false, fmt.Errorf("规则 %s 的路径规则行 #%d upstreams_json 无法解析: %w", ruleID, i+1, err)
			}
		}
		pathRules = append(pathRules, pathRule)
	}
	return pathRules, found, nil
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
	return nil
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
		// R60 C-F1：字符串形态数值（如 "99999999999"）——此前返回 !ok 使
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
// R50-N1：关联表须含 security_policy_bindings 且其规则列名为 rule_caddy_id（其余为
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
		// Round 35 I-10: 空 protocol（非法但 v1 备份可能存在）也按 HTTP 处理，避免绕过空域名跳过逻辑。
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
	// 表 → 引用规则的列名；security_policy_bindings 的规则列为 rule_caddy_id（R50-N1）
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
// security_block_pages 行，返回跳过警告（N+13 H2-F3，与
// skipEmptyDomainHTTPRules 同款软跳过口径）：手造备份 content:"" 原样
// 落库后，引用该页的 WAF/GeoIP/限流拦截渲染空响应体，静默退化为 Caddy
// 原生 403。被跳过页面的悬挂 block_page_id 引用沿用 R58 B-N3 口径
// （运行时 JOIN 语义，悬挂不产出规则）；全表跳空时默认页由导入事务内
// 重播种 + SeedDefaultBlockPage 渲染兜底（R41 B3）。
func skipEmptyBlockPages(tables map[string][]map[string]any) []string {
	rows, exists := tables["security_block_pages"]
	if !exists {
		return nil
	}
	warnings := []string{}
	kept := make([]map[string]any, 0, len(rows))
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
		warnings = append(warnings, fmt.Sprintf("拦截页面 %s 的内容为空，已跳过导入", name))
	}
	if len(warnings) == 0 {
		return nil
	}
	tables["security_block_pages"] = kept
	return warnings
}

func disableV2RuleConflicts(rows []map[string]any) []disabledRuleConflict {
	candidates := make([]ruleConflictCandidate, len(rows))
	for index, row := range rows {
		candidates[index] = newRuleConflictCandidate(
			backupString(row["name"]), backupString(row["caddy_id"]), backupString(row["protocol"]), backupString(row["domain"]),
			backupInt(row["listen_port"]),
			// Round 32 F-1: 与校验侧 backupRuleEnabled（config_backup.go:284）同口径——
			// 手造备份缺 enabled 列时按表结构 COALESCE(enabled,1) 视为启用；此前用
			// backupBooleanEnabled 缺键按禁用，C1 门控下校验按启用、矩阵按禁用跳过，
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

func clampBackupJWTExpireMinutes(value any) (any, bool) {
	switch minutes := value.(type) {
	case float64:
		if minutes >= 1 && minutes <= 1440 && minutes == math.Trunc(minutes) {
			return value, false
		}
	case int:
		if minutes >= 1 && minutes <= 1440 {
			return value, false
		}
	case int64:
		if minutes >= 1 && minutes <= 1440 {
			return value, false
		}
	}
	return 20, true
}

// clampBackupAuditRetentionMonths 导入侧 audit_retention_months 钳制
// （R56 新发现#3）：与启动钳位（clampAuditRetentionMonthsOnStartup）同边界
// ——越界钳到 [1,12] 最近边界；非整数形态按缺省 3 归一（与消费端
// COALESCE(...,3) 回退口径一致）。此前导入原样落库越界值，基础设置保存被
// 写侧 1-12 校验锁死（400），直至下次重启钳位才解套；与 jwt_expire_minutes
// 的导入钳制对称。
func clampBackupAuditRetentionMonths(value any) (any, bool) {
	months, ok := backupInteger(value)
	if !ok {
		return 3, true
	}
	if months < 1 {
		return 1, true
	}
	if months > 12 {
		return 12, true
	}
	return value, false
}

// clampBackupCaddyLogSizeMB 导入侧 caddy_log_size_mb 钳制(SYS37-2,第 37 轮
// 审计 P3,R56#3 同族):与写侧(caddy.go UpdateConfig,100-10240)同边界——低于
// 100 钳到 100、高于 10240 钳到 10240(SYS41-7 补上限,与 UI :max 对齐);非整数
// 形态按 schema 缺省 100 归一(db.go:369)。越界原样落库会锁死基础设置保存
// (写侧 400),与 jwt_expire/audit_retention 钳制对称。
func clampBackupCaddyLogSizeMB(value any) (any, bool) {
	mb, ok := backupInteger(value)
	if !ok {
		return 100, true
	}
	if mb < 100 {
		return 100, true
	}
	if mb > 10240 {
		return 10240, true
	}
	return value, false
}

// clampBackupAuditLogSizeMB 导入侧 audit_log_size_mb 钳制(SYS37-2):与写侧
// (caddy.go:380-387,1-512)同边界——越界钳到 [1,512] 最近边界;非整数形态
// 按 schema 缺省 10 归一(db.go:386)。
func clampBackupAuditLogSizeMB(value any) (any, bool) {
	mb, ok := backupInteger(value)
	if !ok {
		return 10, true
	}
	if mb < 1 {
		return 1, true
	}
	if mb > 512 {
		return 512, true
	}
	return value, false
}

// errUnknownBackupSection:buildLbbakExport 的 4xx 语义哨兵——薄壳端点据此
// 保持原 400 文案,其余错误一律 500「导出失败: …」。三分类合并后
// 「仅全局配置」形态不可达(global_config 是 users 别名,恒有表),
// errGlobalOnlyBackup 哨兵随 BE-C1-6 一并撤销。
var errUnknownBackupSection = errors.New("未知的配置分类")

// buildLbbakExport 生产 lbbak 备份净荷(纯逻辑:无 HTTP、无审计)。sel 为空
// 表示全部分类;返回净荷字节、实际导出分类(空选择归一为全部 3 类)、各表
// 行数摘要(与导入审计同文案)与是否包含规则库文件本体。HTTP 导出端点与
// 自动/手动备份执行器(autobackup.go)共用。
func (h *Handlers) buildLbbakExport(ctx context.Context, sel []string) (payload []byte, exportedSections []string, countsSummary string, includesWafFiles bool, err error) {
	sel = normalizeBackupSectionKeys(sel)
	sectionTables, includeGlobal, ok := configBackupSectionTables(sel)
	if !ok {
		return nil, nil, "", false, errUnknownBackupSection
	}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: time.Now().UTC().Format(time.RFC3339)},
		Tables: map[string][]map[string]any{},
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
		backup.Tables[table] = rows
	}
	checksumPayload, err := json.Marshal(struct {
		Tables map[string][]map[string]any `json:"tables"`
		Config map[string]any              `json:"config"`
	}{backup.Tables, backup.Config})
	if err != nil {
		return nil, nil, "", false, errors.Join(err, tx.Rollback())
	}
	sum := sha256.Sum256(checksumPayload)
	backup.Meta.Checksum = hex.EncodeToString(sum[:])
	if err := tx.Commit(); err != nil {
		return nil, nil, "", false, err
	}
	// v2.3.0(用户裁定 2026-09-18):导出恒为 lbbak tar.gz 包——勾选「规则库
	// 数据库」时附 CRS/IP2Region 文件本体,未勾选时仅 config.json;纯 JSON 仅作
	// 旧备份导入兼容,不再产出。
	backupJSON, err := json.Marshal(backup)
	if err != nil {
		return nil, nil, "", false, err
	}
	var bundle *services.WafFileBundle
	if sectionTables["security_crs_version"] {
		bundle = services.BuildWafFileBundle()
	}
	payload, err = buildLbbakPayload(backupJSON, bundle)
	if err != nil {
		return nil, nil, "", false, err
	}
	exportedSections = append([]string(nil), sel...)
	if len(exportedSections) == 0 {
		for _, sec := range configBackupSections {
			exportedSections = append(exportedSections, sec.Key)
		}
	}
	return payload, exportedSections, importCountsDetail(backup.Tables), bundle != nil, nil
}

func (h *Handlers) ExportConfigBackup(c *gin.Context) {
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导出配置"})
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
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导入配置"})
		return
	}
	if !limitConfigImportBody(c) {
		return
	}
	if raw, rerr := io.ReadAll(c.Request.Body); rerr == nil {
		h.importConfigBackupCore(c, raw, true, "", "导入")
		return
	}
	// 读体失败(如 MaxBytesReader 中途掐断):不替换 body,交由 core 内
	// ShouldBindJSON 走原 413/400 判定路径(与抽取前行为一致)。
	h.importConfigBackupCore(c, nil, false, "", "导入")
}

// importConfigBackupCore 携带导入全量逻辑,HTTP 导入端点与自动备份还原端点
// (autobackup.go)共用。48MB 上限由 HTTP 调用方 limitConfigImportBody 把守。
// PERF41-1(第 41 轮审计 P5,记录裁定):内存峰值评估——lbbak 解压(gzip
// 放大,条目上限在读入内存前拦截)+config.json 展开为 map+checksum 重
// marshal,峰值约为上限的 ~10×(≈500-600MB 瞬态);容器内存 limit 建议 ≥1GB。
// 导入为管理员手动低频操作,当前不加并发互斥(记录裁定,不再重复评估)。
// dataOK=false 表示请求体读取失败,body 保持原样(错误透传给 ShouldBindJSON,
// 保持原 413/400 判定);filename 非空时进入审计来源(还原路径);action 为
// 审计动作与结果文案前缀(「导入」/「还原」)。
func (h *Handlers) importConfigBackupCore(c *gin.Context, data []byte, dataOK bool, filename, action string) {
	// v2.3.0 lbbak:tar.gz 备份先解包校验,内部 config.json 走既有 V2 流程
	var lbbakFiles *lbbakPayload
	if dataOK {
		// SYS42-1:v2 JSON 备份带 UTF-8 BOM 时预览端点已剥(见
		// config_import_v1.go),导入核心同口径——否则同一份备份预览通过、
		// 导入 400。BOM(\xef\xbb\xbf)与 gzip 魔数(0x1f 0x8b)不冲突,
		// 剥 BOM 必须在 isLbbakBytes 魔数检测之前。
		data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
		if isLbbakBytes(data) {
			payload, perr := parseLbbak(data)
			if perr != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: perr.Error()})
				return
			}
			lbbakFiles = payload
			c.Request.Body = io.NopCloser(bytes.NewReader(payload.ConfigJSON))
		} else {
			c.Request.Body = io.NopCloser(bytes.NewReader(data))
		}
	}
	exportedTables := map[string]bool{}
	var backup configBackup
	if err := c.ShouldBindJSON(&backup); err != nil {
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "备份文件不能超过 48MB"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件格式不正确"})
		return
	}
	for table := range backup.Tables {
		exportedTables[table] = true
	}
	// R39-1:lbbak 二进制备份无法在请求体内携带 sections——分类选择经
	// ?sections= query 传输(与导出对称);JSON 备份以体内 sections 字段为准。
	if lbbakFiles != nil {
		if sel := parseSectionsParam(c.Query("sections")); len(sel) > 0 {
			backup.Sections = sel
		}
	}
	usedLegacyChecksum, err := validateV2Backup(backup)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// validateV2Backup 会把缺失表回填为空切片(校验均匀性),此处还原「缺席」
	// 语义——分类导出不含的表不得被当作「清空本地表」应用
	for table := range backup.Tables {
		if !exportedTables[table] {
			delete(backup.Tables, table)
		}
	}
	if usedLegacyChecksum {
		// R43 F-D: 旧格式校验和仅覆盖数据表、不含全局配置区，完整性保障较弱，
		// 显式记审计警告以便追溯（预览端点只读不落审计，避免 UI 选择文件即刷屏）。
		recordAudit(c, action+"警告", "配置备份", "使用旧格式校验和（仅覆盖数据表，不含全局配置）验证备份完整性，建议升级后重新导出备份")
	}
	// CERT41-1(第 41 轮审计 P2,用户裁定):sections 过滤前置到全部形态/任务
	// 校验之前——过滤后 backup.Tables 只剩实际导入表:
	// ①未选分类的坏行不再误拒整包(此前 validateV2BackupRules 等对全量表执行);
	// ②validateBackupACMEReferenceIDs「备份有表按备份行、缺表按 live」自动等于
	//   「过滤后导入表∪live 保留表」正确口径——备份带 certificate_configs 但用户
	//   未勾系统数据时,不再按将被丢弃的备份行误放行;
	// ③全局配置区同理:仅 includeGlobal 时参与校验/钳制(未选系统数据时
	//   backup.Config=nil,validateV2BackupAdminTLS/钳制链自然短路)。
	// 校验和仍验整包(上方 validateV2Backup),未选分类的表与全局配置保持现状。
	// (导入/预览双路径同序,见 ValidateConfigImport。)
	// backupCarriedCertTables:备份是否原本携带 cert 表——下方反向悬挂降级
	// 仅对「从未携带」开放;携带却被分类丢弃时维持硬拒绝(误放行关闭)。
	backupCarriedCertTables := false
	if _, ok := backup.Tables["certificate_configs"]; ok {
		backupCarriedCertTables = true
	}
	if _, ok := backup.Tables["ca_providers"]; ok {
		backupCarriedCertTables = true
	}
	sectionTables, includeGlobal, sectionsOK := configBackupSectionTables(backup.Sections)
	if !sectionsOK {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "未知的配置分类"})
		return
	}
	for table := range backup.Tables {
		if !sectionTables[table] {
			delete(backup.Tables, table)
		}
	}
	if !includeGlobal {
		backup.Config = nil
	}
	// 规则库数据库分类要求文件本体(lbbak):分类选择流(显式携带 sections)
	// 中无文件却勾选该分类 → 剔除其表并警告,防记录与文件分叉(2026-09-18
	// 用户裁定)。旧式全量 JSON 导入(无 sections 字段)保持原语义不动。
	// 规则库版本记录与文件必须同批落库:纯 JSON 备份(非 lbbak)不可能携带
	// 数据文件,版本表恒跳过——否则记录与本地文件分叉(2026-09-18 用户裁定:
	// 只有元数据=该类配置不应导入)。lbbak 无 waf 条目同理。
	// CERT41-1:与过滤的相对顺序固定为「先剔除未选表,再按文件缺失跳过版本表」。
	wafMetadataSkipped := false
	wafCRSMetadataSkipped := false
	wafXdbMetadataSkipped := false
	if sectionTables["security_crs_version"] {
		crsMissing := lbbakFiles == nil || lbbakFiles.CRSTarGz == nil
		xdbMissing := lbbakFiles == nil || lbbakFiles.Xdb == nil
		switch {
		case crsMissing && xdbMissing:
			for _, t := range []string{"security_crs_version", "security_ip2region_version"} {
				delete(backup.Tables, t)
			}
			wafMetadataSkipped = true
			recordAudit(c, action+"警告", "配置备份", warningWafMetadataSkipped)
		case crsMissing:
			// BE-C1-10:单侧文件缺失→仅跳过对应版本表(记录与文件同批落地)。
			delete(backup.Tables, "security_crs_version")
			wafCRSMetadataSkipped = true
			recordAudit(c, action+"警告", "配置备份", warningWafCRSMetadataSkipped)
		case xdbMissing:
			delete(backup.Tables, "security_ip2region_version")
			wafXdbMetadataSkipped = true
			recordAudit(c, action+"警告", "配置备份", warningWafXdbMetadataSkipped)
		}
	}
	// R38 C-3: 空域名行软跳过须先于逐行校验（validateV2BackupRules）——否则
	// 空域名+非法端口行会先行整包 400，与「空域名规则一律软跳过」语义不符；
	// 校验和/结构校验已在 validateV2Backup 内完成，不受跳过影响。
	skipWarnings := skipEmptyDomainHTTPRules(backup.Tables)
	// N+13 H2-F3：空内容拦截页同款软跳过（校验和已在 validateV2Backup 内
	// 验证完毕，跳过不影响完整性；预览端 ValidateConfigImport 同序）。
	skipWarnings = append(skipWarnings, skipEmptyBlockPages(backup.Tables)...)
	if err := validateBackupRuleReferences(backup.Tables); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := validateV2BackupRules(backup.Tables); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := validateV2BackupSecurityPolicies(backup.Tables); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	disabledConflicts := disableV2RuleConflicts(backup.Tables["lb_rules"])
	// R55 C-1：TLS 形态校验与任务不变量同在冲突置禁用之后执行——将自动禁用
	// 的规则不投入运行，不参与运行态形态/不变量校验（导入/预览双路径同序，
	// 见 ValidateConfigImport）。
	// CERT41-1 反向悬挂预检:「导规则不导 cert 配置」且备份从未携带 cert 表时,
	// live 配置被保留,启用 ACME 规则引用 live 缺失降级为悬挂警告(与下方
	// R39-14 预检对称,不阻断,进 responseWarnings+审计);备份携带 cert 表却被
	// 分类过滤丢弃时维持硬拒绝(误放行关闭)。
	softLiveACMERefs := sectionTables["lb_rules"] &&
		!sectionTables["certificate_configs"] && !sectionTables["ca_providers"] &&
		!backupCarriedCertTables
	acmeDanglingImported, tlsShapeErr := validateV2BackupTLSShapeSoft(backup.Tables, softLiveACMERefs)
	if tlsShapeErr != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: tlsShapeErr.Error()})
		return
	}
	// R54 新发现2：任务不变量在冲突置禁用之后执行——将自动禁用的规则不投入
	// 运行，不参与运行态不变量（导入/预览双路径同序，见 ValidateConfigImport）。
	if err := validateV2BackupCertJobs(backup.Tables); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// R55 C-4：写全局配置前按 UpdateAdminTLS 同口径校验 admin_tls_*——坏配置
	// 会使下次启动进程退出（崩溃循环），整包 400 保持零写入语义。
	// CERT41-1:仅 includeGlobal 时全局配置区参与校验/钳制(未选系统数据时
	// backup.Config 已置 nil,本校验与下方钳制链自然短路)。
	if err := validateV2BackupAdminTLS(backup.Config); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	jwtExpireClamped := false
	if value, exists := backup.Config["jwt_expire_minutes"]; exists {
		backup.Config["jwt_expire_minutes"], jwtExpireClamped = clampBackupJWTExpireMinutes(value)
	}
	// R56 新发现#3：audit_retention_months 导入钳制（与启动钳位同边界），
	// 避免越界值落库后锁死基础设置保存。
	auditRetentionClamped := false
	if value, exists := backup.Config["audit_retention_months"]; exists {
		backup.Config["audit_retention_months"], auditRetentionClamped = clampBackupAuditRetentionMonths(value)
	}
	// SYS37-2(第 37 轮审计 P3,R56-58 同族):两个日志大小键导入钳制——
	// 越界原样落库会锁死基础设置保存(写侧 400),钳到写侧同边界。
	caddyLogSizeClamped := false
	if value, exists := backup.Config["caddy_log_size_mb"]; exists {
		backup.Config["caddy_log_size_mb"], caddyLogSizeClamped = clampBackupCaddyLogSizeMB(value)
	}
	auditLogSizeClamped := false
	if value, exists := backup.Config["audit_log_size_mb"]; exists {
		backup.Config["audit_log_size_mb"], auditLogSizeClamped = clampBackupAuditLogSizeMB(value)
	}
	// R57 C-2：续签/有效期数值导入钳制（与写侧 caddy.go 校验同边界）——
	// cert_renewal_days 超大值会让续签扫描窗口覆盖一切证书（续签成功后仍在
	// 窗口内 → 永久续签风暴耗尽 CA 配额）；负值漂移 Keep/Resume 决策。
	certNumericClamped := make([]string, 0, 4)
	for _, kc := range []struct {
		key         string
		lo, hi      int
		fallbackDef int
	}{
		// R66 C-F3：非法形态回退值对齐 schema 默认（db.go cert_renewal_days=30/
		// cert_renewal_attempts=5/cert_expiry_days=30）与显示侧 COALESCE——
		// 此前 3/90 与写侧校验边界一致但与默认值漂移，修复后的续签窗口/到期
		// 提醒参数会静默偏离系统默认直至管理员重存。
		{"cert_renewal_days", 0, 90, 30},
		{"cert_renewal_attempts", 1, 10, 5},
		{"cert_expiry_days", 1, 365, 30},
	} {
		if value, exists := backup.Config[kc.key]; exists {
			if n, ok := backupInteger(value); ok {
				if n < kc.lo || n > kc.hi {
					clamped := n
					if n < kc.lo {
						clamped = kc.lo
					}
					if n > kc.hi {
						clamped = kc.hi
					}
					backup.Config[kc.key] = clamped
					certNumericClamped = append(certNumericClamped, fmt.Sprintf("%s 越界（%d），已钳位为 %d", kc.key, n, clamped))
				}
			} else if value != nil {
				backup.Config[kc.key] = kc.fallbackDef
				certNumericClamped = append(certNumericClamped, fmt.Sprintf("%s 非法形态，已重置为 %d", kc.key, kc.fallbackDef))
			}
		}
	}
	// R58 C-N2：request_body_max_size_mb 导入钳制 ≤4096（与 R57 C-7 写侧三处
	// 同边界）——溢出向量此前只堵了保存/更新，备份导入可携带天文数字绕过，
	// 渲染侧 MB→字节 int64 乘法回绕会让 body 限制静默取消。
	if value, exists := backup.Config["request_body_max_size_mb"]; exists {
		if n, ok := backupInteger(value); ok && (n < 0 || n > 4096) {
			clamped := 0
			if n > 4096 {
				clamped = 4096
			}
			backup.Config["request_body_max_size_mb"] = clamped
			certNumericClamped = append(certNumericClamped, fmt.Sprintf("request_body_max_size_mb 越界（%d），已钳位为 %d", n, clamped))
		}
	}
	ctx := c.Request.Context()
	importUsername := c.GetString("username")
	// 2026-09-18 用户裁定:「备份不含操作者账户」不再硬阻断——①分类导入可
	// 能未选系统数据(操作者仍在);②即使勾了系统数据导致操作者被替换,也尊
	// 重用户选择。降级为响应 warning+审计警告,导入照常(操作者 JWT 由下方
	// password_version 递增吊销,需用备份内账户重新登录)。
	operatorReplaced := false
	// A40-2-F3:备份 users 表缺席时,本地用户根本未被触碰——不告警不吊销。
	if importUsername != "" && sectionTables["users"] && len(backup.Tables["users"]) > 0 && !backupContainsUsername(backup.Tables["users"], importUsername) {
		operatorReplaced = true
		recordAudit(c, action+"警告", "配置备份", "备份不含当前操作账户——系统数据将被替换，"+action+"后请使用备份内的管理员账户登录")
	}
	// R39-14:「系统数据」替换 ACME 配置表时,live 启用规则的引用可能悬挂
	// (与 C-04 删除 409 守卫同果)——预检并降级警告(不阻断,尊重用户选择)。
	// A40-2-F1:lb_rules 同批替换时跳过预检——预检读的是「导入前」live 规则,
	// 这些规则马上被备份规则整体替换,恒误报。
	acmeDanglingRules := 0
	if (sectionTables["certificate_configs"] || sectionTables["ca_providers"]) && !sectionTables["lb_rules"] {
		if rows, qerr := db.DB.Query(`SELECT COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0) FROM lb_rules WHERE enabled=1 AND tls_source='acme_dns'`); qerr == nil {
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
	// CERT41-1 反向:导规则不导 cert 配置且备份从未携带 cert 表时,上方 TLS
	// 形态软校验已计数悬挂引用——降级警告进审计(与 R39-14 同格,不阻断)。
	if acmeDanglingImported > 0 {
		recordAudit(c, action+"警告", "配置备份", fmt.Sprintf(action+"后 %d 条启用 ACME 规则的提供商引用悬挂(引用未随备份导入且现有配置缺失)——下一次签发/续签将失败,请补齐 DNS 提供商配置", acmeDanglingImported))
	}
	session, err := h.beginConfigImport(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer session.close()
	tx := session.tx
	// W2：security_ip_lists 先删/先插 security_policies——refs 是策略行上的
	// JSON 引用（无外键，顺序本自由），固定 lists→policies 与集群 apply 侧
	// 一致，保证插入后引用即时指向存在行。
	deleteOrder := []string{"security_policy_bindings", "security_crs_version", "security_ip2region_version", "security_custom_rules", "security_block_pages", "security_ip_lists", "security_policies", "api_keys", "path_rules", "upstreams", "cert_jobs", "lb_rules", "users", "ca_providers", "certificate_configs"}
	for _, table := range deleteOrder {
		if _, exists := backup.Tables[table]; !exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			err = session.abort(err)
			recordAudit(c, action+"失败", "配置备份", err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清空表 " + table + " 失败，已回滚: " + err.Error()})
			return
		}
	}
	insertOrder := []string{"users", "lb_rules", "ca_providers", "certificate_configs", "api_keys", "upstreams", "path_rules", "cert_jobs", "security_ip_lists", "security_policies", "security_crs_version", "security_ip2region_version", "security_block_pages", "security_custom_rules", "security_policy_bindings"}
	for _, table := range insertOrder {
		rows, exists := backup.Tables[table]
		if !exists {
			continue
		}
		// 归一兜底：validateV2Backup 内的 normalizeBackupBooleanNulls 已被
		// legacy（仅 tables）校验和早退路径跳过，此处幂等重复执行覆盖该场景
		//（R37 F37-2 / R38 C-1 / R39 C-1）。
		if table == "lb_rules" || table == "upstreams" || table == "users" {
			normalizeBackupBooleanNulls(map[string][]map[string]any{table: rows})
		}
		if err := restoreTable(ctx, tx, db.DB, table, rows); err != nil {
			err = session.abort(err)
			recordAudit(c, action+"失败", "配置备份", err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
			return
		}
	}

	// K2-P2-03(第 2 轮审计):四态化启动迁移只覆盖启动路径——pre-v2.2.7 备份
	// 导入 off+启用自定义规则的策略后静默失活(旧语义 off=自定义照常发射,
	// 新语义 off=全关),违背迁移「行为零突变」意图。导入事务内做同款归一
	// (与 migrateSecurityPolicyCustomOnlyMode 的行级语义一致,但不走旗标门:
	// 每次导入都归一,导入的是「旧世界数据」这一事实由备份内容自证)。
	// K2-P2-03-E(第 3 轮审计):新语义下合法保存的 off+启用规则导出→导入会被
	// 归一为 custom_only(规则从全关静默变生效)。行为与启动迁移一致(旧世界
	// 数据归一),但在此留审计提示,运维可从事件日志追溯。
	if result, err := tx.ExecContext(ctx, `UPDATE security_policies SET mode='custom_only'
WHERE mode='off' AND json_valid(COALESCE(custom_rules,'[]')) AND json_type(COALESCE(custom_rules,'[]')) IN ('array','object') AND EXISTS (
  SELECT 1 FROM json_each(COALESCE(custom_rules,'[]')) je
  WHERE json_extract(je.value,'$.enabled')=1
     OR (json_type(je.value)='integer' AND EXISTS (
          SELECT 1 FROM security_custom_rules r
          WHERE r.id=je.value AND COALESCE(r.enabled,1)=1)))`); err != nil {
		err = session.abort(err)
		recordAudit(c, action+"失败", "配置备份", "off→custom_only 归一: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: action + "失败，已回滚: " + err.Error()})
		return
	} else if n, _ := result.RowsAffected(); n > 0 {
		services.Logf("info", "配置导入：%d 个 mode=off 且挂启用自定义规则的策略已归一为 custom_only（旧语义兼容）", n)
	}
	// R41 B1: pre-R40 备份可能携带 ≥2 个 is_default=1 的拦截页。restoreTable
	// 原值插入后这些行全部成为不可编辑/删除的死行，且 branding 重渲染会覆盖
	// 全部默认页内容。提交前降级多余默认页，仅保留 MIN(id) 一行。
	// R42 B42-2: pre-R40 备份中保留行（MIN id）常是未定制过的种子行，而用户真实
	// 定制内容在被降级行上。保留行内容为种子库存（空或默认渲染）且存在内容不同的
	// 被降级行时，把内容非空且非库存、id 最大的被降级行 content 提升到保留行；
	// 失败仅记警告（内容层面问题，branding 重渲染会覆盖，不影响拦截功能）。
	// R43 B43-1: 提升先于降级执行——降级后「被降级行」与从未是默认页的自定义行
	// 无法区分；CTE 在降级前圈定待降级行集合，提升源限定该集合且以 EXISTS 门控
	// （未发生降级即跳过提升），单默认页+自定义页的备份不再静默改写默认页内容。
	stockBlockPage := renderDefaultBlockPage(loadBrandingConfig(h.cfg.DataDir))
	if _, err := tx.ExecContext(ctx, `WITH demoted AS (SELECT id, content FROM security_block_pages WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)) UPDATE security_block_pages SET content=(SELECT content FROM demoted WHERE content NOT IN ('', ?) ORDER BY id DESC LIMIT 1) WHERE id=(SELECT MIN(id) FROM security_block_pages WHERE is_default=1) AND content IN ('', ?) AND EXISTS (SELECT 1 FROM demoted WHERE content NOT IN ('', ?))`, stockBlockPage, stockBlockPage, stockBlockPage); err != nil {
		recordAudit(c, action+"警告", "配置备份", "默认拦截页面内容提升失败: "+err.Error())
	}
	if _, err := tx.ExecContext(ctx, `UPDATE security_block_pages SET is_default=0 WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)`); err != nil {
		err = session.abort(err)
		recordAudit(c, action+"失败", "配置备份", "降级多余的默认拦截页失败: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "降级多余的默认拦截页失败，已回滚: " + err.Error()})
		return
	}
	// R41 B3: 默认页重播种移入导入事务，与导入同生共死；失败仅记警告不阻断
	// 导入（拦截响应短暂退化，由后续 SeedDefaultBlockPage/branding 触发自愈）。
	reseedBlockPageNeeded := false
	reseedApplyFailed := false
	var hasDefaultBlockPage int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&hasDefaultBlockPage); err != nil {
		recordAudit(c, action+"警告", "配置备份", "默认拦截页面计数失败: "+err.Error())
	} else if hasDefaultBlockPage == 0 {
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO security_block_pages (id, name, description, content, is_default, created_at, updated_at) VALUES (1, '默认拦截页面', '系统默认 403 拦截页面', '', TRUE, datetime('now'), datetime('now'))`)
		if err != nil {
			recordAudit(c, action+"警告", "配置备份", "默认拦截页面重播种失败: "+err.Error())
		} else if affected, _ := result.RowsAffected(); affected == 0 {
			// R42 B42-1: 备份携带 id=1 的非默认行时 OR IGNORE 因 PK 冲突静默
			// no-op，导入后仍旧零默认页且无任何 error——B3 的告警机制不会
			// 触发，此处显式补记警告以便追溯。
			recordAudit(c, action+"警告", "配置备份", "默认拦截页面重播种未生效（id=1 已存在）")
		} else {
			reseedBlockPageNeeded = true
		}
	}
	revokedSessions := false
	// R39-11:仅「系统数据」被替换时吊销全员会话(用户/密钥已换,旧 JWT
	// 必须失效);其余分类导入不触碰用户数据,不吊销、不打扰。
	// A40-2-F3:备份 users 表缺席=用户数据未替换,同样不吊销。
	if sectionTables["users"] && len(backup.Tables["users"]) > 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE users SET password_version=COALESCE(password_version,0)+1"); err != nil {
			err = session.abort(err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "吊销现有登录会话失败，已回滚: " + err.Error()})
			return
		}
		revokedSessions = true
	}
	var enabledAdmins int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='admin' AND is_enabled=1").Scan(&enabledAdmins); err != nil {
		err = session.abort(err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认管理员账号失败，已回滚: " + err.Error()})
		return
	}
	if enabledAdmins == 0 {
		err = session.abort(errors.New("导入后必须至少保留一个已启用的管理员账号"))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	var importUserID sql.NullInt64
	if importUsername != "" {
		err := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE username=?", importUsername).Scan(&importUserID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			err = session.abort(err)
			recordAudit(c, action+"失败", "配置备份", "重映射规则操作者失败: "+err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重映射规则操作者失败，已回滚: " + err.Error()})
			return
		}
	}
	// 审计 B3：归属重映射仅在操作者存在时执行——操作者行缺失时写 NULL 会抹掉
	// 全部规则归属（操作者非空但缺席备份的场景已降级为 warning 警告（2026-09-18 裁定）；
	// 此分支兜底无操作者上下文的路径）。
	if importUserID.Valid {
		if _, err := tx.ExecContext(ctx, "UPDATE lb_rules SET updated_by=?", importUserID); err != nil {
			err = session.abort(err)
			recordAudit(c, action+"失败", "配置备份", "更新规则操作者失败: "+err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新规则操作者失败，已回滚: " + err.Error()})
			return
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cert_jobs WHERE rule_id NOT IN (SELECT caddy_id FROM lb_rules)"); err != nil {
		err = session.abort(err)
		recordAudit(c, action+"失败", "配置备份", "清理孤儿证书任务失败: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理孤儿证书任务失败，已回滚: " + err.Error()})
		return
	}
	if backup.Config != nil {
		valid, err := tableColumns(ctx, db.DB, "global_config")
		if err != nil {
			err = session.abort(err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取配置结构失败: " + err.Error()})
			return
		}
		sets := []string{}
		values := []any{}
		for column, value := range backup.Config {
			if configBackupProtectedConfigKeys[column] || !valid[column] {
				continue
			}
			// R56 新发现#1：布尔配置键写入前归一（与 restoreTable 同兜底）——
			// legacy 校验和仅覆盖 tables，Config 区字符串布尔可幸存至此。
			if isBackupBooleanConfigKey(column) {
				value = normalizeBackupBooleanValue(value)
			}
			sets = append(sets, `"`+column+`"=?`)
			values = append(values, value)
		}
		if len(sets) > 0 {
			if _, err := tx.ExecContext(ctx, "UPDATE global_config SET "+joinStrings(sets, ",")+" WHERE id=1", values...); err != nil {
				err = session.abort(err)
				recordAudit(c, action+"失败", "配置备份", err.Error())
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入全局配置失败，已回滚: " + err.Error()})
				return
			}
		}
	}
	affectedRuleIDs := append([]string(nil), session.existingRuleIDs...)
	pendingCertificates := make([]importCertificate, 0)
	// CERT41-4:手动证书材料的链完整性/域名覆盖警告(不阻断)——配对合法性
	// 仍由 materializeImportCertificates 硬校验;警告并入 responseWarnings/审计。
	importCertWarnings := make([]string, 0)
	for _, row := range backup.Tables["lb_rules"] {
		if caddyID, ok := row["caddy_id"].(string); ok && caddyID != "" {
			affectedRuleIDs = append(affectedRuleIDs, caddyID)
			certPEM, _ := row["tls_cert"].(string)
			keyPEM, _ := row["tls_key"].(string)
			if certPEM != "" && keyPEM != "" {
				pendingCertificates = append(pendingCertificates, importCertificate{ruleID: caddyID, certPEM: certPEM, keyPEM: keyPEM})
				for _, warning := range tlsCertificateWarnings(certPEM, keyPEM, backupString(row["domain"])) {
					importCertWarnings = append(importCertWarnings, fmt.Sprintf("规则 %s（%s）：%s", backupString(row["name"]), caddyID, warning))
				}
			}
		}
	}
	counts := importCountsDetail(backup.Tables)
	// lbbak:文件落盘必须在 session.commit 之前——commit 内的 Caddy 应用
	// (ApplyConfigFromTxCertAwareForce)要读到新 CRS 文件;xdb 落盘后立即
	// 热换内存缓存(完整更新流程,2026-09-18 用户裁定)。
	wafApplyWarning := ""
	if lbbakFiles != nil && sectionTables["security_crs_version"] {
		wafApplyWarning = applyLbbakWafFiles(c, lbbakFiles, services.SanitizeBundleVersion(ip2regionTagFromBackup(backup.Tables)))
	}
	if err := session.commit(affectedRuleIDs, pendingCertificates); err != nil {
		status := http.StatusInternalServerError
		message := "配置" + action + "失败: " + err.Error()
		if importFailurePhase(err) == importPhaseCaddy {
			status = http.StatusBadRequest
			message = "备份生成的配置未通过 Caddy 验证，未执行" + action + ": " + err.Error()
		}
		if importFailurePhase(err) == importPhaseQueue {
			message = "配置已" + action + "但证书任务恢复失败: " + err.Error()
		}
		auditAction := action + "失败"
		if importFailurePhase(err) == importPhaseQueue {
			auditAction = "部分失败"
		}
		auditDetail := err.Error()
		if importFailurePhase(err) == importPhaseQueue && len(disabledConflicts) > 0 {
			auditDetail = services.FormatAuditDetail(auditDetail, "冲突置为禁用："+formatDisabledRuleConflicts(disabledConflicts))
		}
		recordAudit(c, auditAction, "配置备份", auditDetail)
		failureWarnings := skipWarnings
		if wafApplyWarning != "" {
			// A40-2-F4:规则库文件已落盘 live 树而 DB 已回滚——状态分裂必须
			// 随失败响应可见,不得只在审计侧留痕。
			failureWarnings = append(append([]string{}, failureWarnings...), wafApplyWarning)
		}
		c.JSON(status, models.APIResponse{Code: status, Message: message, Data: gin.H{"summary": counts, "disabled_conflicts": disabledConflicts, "warnings": failureWarnings}})
		return
	}

	if reseedBlockPageNeeded {
		// 提交成功后才渲染 branding 内容：INSERT 只放空 content 占位，真实内容
		// 由 SeedDefaultBlockPage 依据 branding.json 写入；失败不影响导入结果。
		// R42 B42-1: 返回值不再丢弃——渲染出错，或未生效且表内仍无默认页时记警告。
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

	auditSource := "v2 备份（覆盖" + action + "）"
	if filename != "" {
		auditSource = "服务器备份 " + filename + "（覆盖" + action + "）"
	}
	auditParts := []string{"来源：" + auditSource, counts}
	if jwtExpireClamped {
		auditParts = append(auditParts, "jwt_expire_minutes 越界，已重置为 20")
	}
	if auditRetentionClamped {
		auditParts = append(auditParts, fmt.Sprintf("audit_retention_months 越界，已钳位为 %v", backup.Config["audit_retention_months"]))
	}
	if caddyLogSizeClamped {
		auditParts = append(auditParts, fmt.Sprintf("caddy_log_size_mb 越界，已钳位为 %v", backup.Config["caddy_log_size_mb"]))
	}
	if auditLogSizeClamped {
		auditParts = append(auditParts, fmt.Sprintf("audit_log_size_mb 越界，已钳位为 %v", backup.Config["audit_log_size_mb"]))
	}
	auditParts = append(auditParts, certNumericClamped...)
	if len(skipWarnings) > 0 {
		// N+13 H2-F3：列表现含空域名规则与空内容拦截页两类跳过，标签泛化。
		auditParts = append(auditParts, "跳过警告："+strings.Join(skipWarnings, "；"))
	}
	if len(importCertWarnings) > 0 {
		// CERT41-4:证书链/域名警告随成功审计留痕(不阻断)。
		auditParts = append(auditParts, "证书警告："+strings.Join(importCertWarnings, "；"))
	}
	if len(disabledConflicts) > 0 {
		auditParts = append(auditParts, "冲突置为禁用："+formatDisabledRuleConflicts(disabledConflicts))
	}
	if operatorReplaced {
		auditParts = append(auditParts, "操作者账户已被备份替换,请使用备份内管理员登录")
	}
	auditParts = append(auditParts, services.AuditResultPart("success"))
	recordAudit(c, action, "配置备份", services.FormatAuditDetail(auditParts...))
	recordAudit(c, "重载", "Caddy服务", action+"配置后自动重载")
	// 2026-09-07 审计 L4（round5 F2 修正）：导入成功后清除陈旧 caddy_apply_error
	// ——但 reseed 失败时不清（reseed 的 caddyApplyNoteLocked 可能刚写入
	// 失败标记，无条件清除会把真实失败横幅抹掉）。
	if !reseedBlockPageNeeded || reseedApplyFailed == false {
		h.recordCaddyApplyResult(nil)
	}
	responseWarnings := skipWarnings
	if wafMetadataSkipped {
		responseWarnings = append(append([]string{}, responseWarnings...), warningWafMetadataSkipped)
	}
	if wafCRSMetadataSkipped {
		responseWarnings = append(append([]string{}, responseWarnings...), warningWafCRSMetadataSkipped)
	}
	if wafXdbMetadataSkipped {
		responseWarnings = append(append([]string{}, responseWarnings...), warningWafXdbMetadataSkipped)
	}
	if wafApplyWarning != "" {
		responseWarnings = append(append([]string{}, responseWarnings...), wafApplyWarning)
	}
	if operatorReplaced {
		responseWarnings = append(append([]string{}, responseWarnings...), "备份不含当前操作账户——系统数据已替换，请使用备份内的管理员账户登录")
	}
	if revokedSessions && !operatorReplaced {
		responseWarnings = append(append([]string{}, responseWarnings...), "系统数据已"+action+"：全部登录会话已吊销，请重新登录")
	}
	if acmeDanglingRules > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), fmt.Sprintf(action+"后 %d 条启用规则的 DNS 提供商配置悬挂（引用不在导入数据中）——下一次签发/续签将失败，请及时补齐", acmeDanglingRules))
	}
	// CERT41-1 反向悬挂警告(与上方审计同文案族;与 acmeDanglingRules 互斥,
	// 方向不同:此处为导入规则引用 live 缺失)。
	if acmeDanglingImported > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), fmt.Sprintf(action+"后 %d 条启用规则的 DNS 提供商配置悬挂（引用未随备份导入，且现有配置中不存在或已禁用）——下一次签发/续签将失败，请及时补齐", acmeDanglingImported))
	}
	// CERT41-4:证书链/域名警告并入响应(行内容类警告,不阻断)。
	if len(importCertWarnings) > 0 {
		responseWarnings = append(append([]string{}, responseWarnings...), importCertWarnings...)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: fmt.Sprintf("配置"+action+"成功：%s", strings.ReplaceAll(counts, "；", "、")), Data: gin.H{"summary": counts, "disabled_conflicts": disabledConflicts, "warnings": responseWarnings}})
}

func importCountsDetail(tables map[string][]map[string]any) string {
	parts := []string{}
	labels := []struct {
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
		// R41 追加(用户生产观察):安全域用户内容表补入汇总(绑定表为派生数据不加)。
		{"security_policies", "安全策略 %d 条"},
		{"security_custom_rules", "自定义规则 %d 条"},
		{"security_block_pages", "拦截页 %d 个"},
		{"security_ip_lists", "IP 地址列表 %d 个"},
		{"security_crs_version", "CRS 版本 %d 条"},
		{"security_ip2region_version", "IP2Region 版本 %d 条"},
	}
	for _, item := range labels {
		if rows, ok := tables[item.table]; ok {
			parts = append(parts, fmt.Sprintf(item.label, len(rows)))
		}
	}
	return joinStrings(parts, "；")
}
