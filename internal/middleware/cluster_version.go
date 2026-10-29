package middleware

import (
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func clusterVersionMiddleware(database *sql.DB) gin.HandlerFunc {
	// 触发器就绪：生产启动路径已在任务引擎之前完成安装（安装失败即拒绝启动），
	// 此处重装是防御刷新并保持测试/嵌入形态自足。重装仍会全量 DROP/CREATE
	// （105 条 DDL、BEGIN IMMEDIATE 取写锁）——若此刻撞上后台写事务并等满
	// busy_timeout，旧实现把「一次瞬时忙」变成**进程内永久 500**（所有分类写
	// 与主端登录 fail-closed 到重启），与「启动门不得带病运行」的取向相反。
	// 因此重装失败后回退为只读探测：库内触发器齐备（就绪门装的那批）即视为
	// 已就绪并留一次 warn；只有触发器确实缺失/不齐时才 fail-closed。
	installErr := ensureClusterVersionTriggers(database)
	// 装配期 DDL 失败后所有同步写与主端登录恒 500，此前只把错误塞进
	// gin 上下文（无日志落点）——系统日志看不到根因。此处一次性留痕，响应与
	// fail-closed 语义不变。
	if installErr != nil {
		services.Logf("error", "集群版本触发器安装失败（同步写与主端登录将 fail-closed 返回 500）: %v", installErr)
	}
	return func(c *gin.Context) {
		if !isSynchronizedWrite(c.Request.Method, c.FullPath()) {
			c.Next()
			return
		}
		if installErr != nil {
			// fail-closed 只对主节点有意义：触发器 WHEN COALESCE(is_master,1)=1，
			// 从节点上的写本就不会 bump——降级态在从端零保护收益，500 只会把
			// 「该去主节点操作」误导成「主节点有故障」（与本包「角色真因优先于
			// 后续 428/500」的口径一致）。因此所有分类写路径统一先读角色：
			// 从端交给下游守卫（readOnlyGuard 给 403，/cluster/* 由 handler 的
			// 角色门兜底）。角色读失败按写闸同语义 fail-closed 落入 500（不猜测
			// 放行）。此前只有 users 表路径做了这层分流。
			if isMaster, err := services.RoleOf(c.Request.Context(), database); err == nil && !isMaster {
				c.Next()
				return
			}
			_ = c.Error(installErr) // 请求日志尾部列输出（requestLogFormatter 消费 ErrorMessage）
			c.AbortWithStatusJSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "集群版本触发器不可用"})
			return
		}
		c.Next()
	}
}

// ensureClusterVersionTriggers 装配期触发器就绪：先尝试全量重装（保持定义
// 随代码刷新——升级后 WHEN/OF 子句变更必须生效），重装失败再回退只读探测。
//
// 重装失败的可恢复形态是「就绪门刚装好、本次重装撞上后台写事务的写锁」：
// 触发器齐备**且定义与安装器一致**（探测比对 sqlite_master 里的定义文本，
// 不只是名字——同名陈旧定义不得被当作就绪），语义与就绪门装的那批一致，
// 不应把一次瞬时忙升级为进程内永久 500（所有分类写与主端登录 fail-closed
// 到重启）。探测本身读 sqlite_master，不取写锁、不阻塞写者。
func ensureClusterVersionTriggers(database *sql.DB) error {
	installErr := InstallClusterVersionTriggers(database)
	if installErr == nil {
		return nil
	}
	present, probeErr := clusterVersionTriggersPresent(database)
	if probeErr == nil && present {
		services.Logf("warn", "集群版本触发器重装失败但库内触发器已齐备（可能撞写锁），按已就绪继续: %v", installErr)
		return nil
	}
	return installErr
}

// clusterVersionTriggersPresent 只读探测触发器是否齐备**且定义与安装器一致**：
// 名与定义文本都由 clusterVersionTriggerStatements 单源派生。
//
// 只比名字不够：同名但 WHEN/OF 子句陈旧（库由旧版本安装、升级后语义未生效）的
// 触发器会被判为「已就绪」，回退路径据此跳过 fail-closed，同步正确性问题被
// 静默保留。生产启动门会无条件重装（失败即拒绝启动），所以本探测只服务于
// 「重装撞上后台写锁」的回退判据；定义漂移仅在「旧版本装的定义 + 本次重装
// 失败」这一窄窗口可达——属加固口径，不是活跃缺陷。
func clusterVersionTriggersPresent(database *sql.DB) (bool, error) {
	expected := clusterVersionTriggerStatements()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(expected)), ",")
	args := make([]any, 0, len(expected))
	for _, trigger := range expected {
		args = append(args, trigger.name)
	}
	rows, err := database.Query(`SELECT name, COALESCE(sql,'') FROM sqlite_master
		WHERE type='trigger' AND name IN (`+placeholders+`)`, args...)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	installed := make(map[string]string, len(expected))
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			return false, err
		}
		installed[name] = definition
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, trigger := range expected {
		// 缺失的名字在 map 里取到空串，与归一后的非空定义天然不等——缺项与
		// 定义漂移在同一条比较里收敛。
		if normalizeTriggerDefinition(installed[trigger.name]) != normalizeTriggerDefinition(trigger.createSQL) {
			return false, nil
		}
	}
	return true, nil
}

// normalizeTriggerDefinition 归一化触发器定义文本用于等值比较：大小写与空白
// 形态（缩进/换行/连续空格）都不构成 SQL 语义差异，而 sqlite_master.sql 原样
// 保存建库时的语句文本——模板缩进或历史版本安装的格式不得被误判为定义漂移。
// 列名/字面量的真实差异（真正影响 bump 语义的部分）保留在比较结果里。
func normalizeTriggerDefinition(definition string) string {
	return strings.Join(strings.Fields(strings.ToLower(definition)), " ")
}

// globalConfigSyncedColumns 是 global_config UPDATE 触发器的 OF 列清单单源
// 凡随集群快照同步的 global_config 列都必须在此——漏列时
// 「仅写该列」的 UPDATE 不 bump cluster_version，从节点经 304 门永久滞留
// 旧值（autoban 六列、自动备份组均曾因同类遗漏修过）。
// 漂移防护：ClusterBasicSettings（internal/models/cluster.go）的全部字段
// （JSON tag = 列名）必须命中本清单，钉测见 cluster_version_of_drift_test.go。
// auto_backup_last_run 刻意排除：调度器每轮备份推进，入列会让每轮备份引发
// 全集群快照重放。
var globalConfigSyncedColumns = []string{
	"sync_users", "sync_rules", "sync_security",
	"branding_json", "caddy_config", "log_level",
	"access_log_json", "access_log_format",
	"task_log_size_mb", "audit_log_size_mb", "runtime_log_size_mb", "audit_retention_months",
	"jwt_expire_minutes", "timezone", "acme_email",
	"cert_expiry_days", "cert_renewal_days", "cert_renewal_attempts", "default_ca_provider_id",
	"sync_interval",
	"admin_tls_enabled", "admin_tls_mode", "admin_tls_cert", "admin_tls_key",
	"caddy_log_level", "caddy_log_size_mb",
	"request_body_max_size_mb",
	"http_read_timeout", "http_write_timeout", "http_idle_timeout",
	"upstream_keepalive_timeout",
	"proxy_dial_timeout", "proxy_response_header_timeout",
	"proxy_read_timeout", "proxy_write_timeout", "proxy_stream_timeout",
	"proxy_flush_interval", "proxy_stream_close_delay",
	"server_tokens_hidden", "oidc_config",
	"mfa_write_guard", "mfa_lockout_enabled", "github_proxy_url",
	"auto_backup_enabled", "auto_backup_frequency", "auto_backup_time",
	"auto_backup_day", "auto_backup_keep", "auto_backup_sections",
	"trusted_proxy_enabled", "trusted_proxy_ranges", "trusted_proxy_range_refs",
	"trusted_proxy_headers", "trusted_proxy_strict",
	"threat_auto_update", "threat_schedule_days", "threat_schedule_time",
	"crawler_auto_update", "crawler_schedule_days", "crawler_schedule_time",
	"autoban_enabled", "autoban_threshold", "autoban_window_minutes",
	"autoban_duration", "autoban_scope", "autoban_dry_run",
	// v2.3.8：安全事件保留两列与大屏采样口径随 users 节同步并物化到从端
	// （models.ClusterBasicSettings / services/cluster_apply.go）——
	// 补列：此前仅靠「同语句 UPDATE 含其他 OF 列」偶然触发 bump，仅写这三列
	// 的端点会滞留主节点。
	"security_events_retention_days", "security_events_row_cap", "threat_traffic_sample_n",
	// 大屏视觉模式同组：从节点写入口被只读门拒绝，配置只能由主节点经快照
	// 下发——漏列时主端改它不 bump 版本，从端经 304 门永久滞留旧视觉。
	"threat_screen_mode",
}

// clusterSyncedTable 集群快照同步表与其触发列清单（触发器安装与「列清单↔
// schema」漂移对账测试共用单源）。
type clusterSyncedTable struct {
	name            string
	snapshotColumns string
}

// clusterSyncedTables 全部随集群快照同步的表（17 张）。增删表/列必须同时
// 更新本清单与 clusterSyncedColumnExclusions（有意不同步的列携理由）——
// 漏登记列时仅写该列的 UPDATE 不 bump cluster_version，从节点经 304 门永久
// 滞留旧值（钉测见 cluster_synced_columns_test.go 的逐表 schema 对账）。
// lb_rules 的触发器 OF 列按语义分组：55 列单行字符串在 diff 中表现为整行
// 替换，新增/删除一列无法 review；分组后增量落到「一组内一行一处」。
// 组顺序即 OF 串顺序（与 schema 对账测试无关，但 CREATE TRIGGER 的 OF 语义
// 只认列集合）。历史教训：NTLM 两列曾整组漏列，靠人工补钉测才发现。
var (
	lbRuleBaseColumns = []string{
		"caddy_id", "name", "description", "protocol", "domain", "listen_port",
		"strategy", "dynamic_dns", "enable_dns_server", "dns_server", "dns_family",
	}
	lbRuleHealthCheckColumns = []string{
		"health_check_path", "health_check_interval", "health_check_timeout",
		"health_check_unhealthy_threshold", "health_check_healthy_threshold",
		"enable_active_health_check",
	}
	lbRuleTCPColumns = []string{
		"tcp_health_check_port", "tcp_proxy_protocol", "tcp_try_duration", "tcp_try_interval",
	}
	lbRuleRequestAndUpstreamColumns = []string{
		"request_body_max_size_mb", "upstream_keepalive_timeout", "server_tokens_hidden",
		"ntlm_compatible", "upstream_force_http1", "host_header", "health_check_host",
		"custom_routes_enabled",
	}
	lbRuleProxyTimeoutColumns = []string{
		"proxy_dial_timeout", "proxy_response_header_timeout", "proxy_read_timeout",
		"proxy_write_timeout", "proxy_stream_timeout", "proxy_flush_interval",
		"proxy_stream_close_delay",
	}
	lbRuleTLSColumns = []string{
		"enable_tls", "tls_source", "acme_config_id", "ca_provider_id",
		"tls_cert", "tls_key", "tls_http_redirect",
	}
	lbRuleCompressColumns  = []string{"enable_compress", "compress_types"}
	lbRuleLifecycleColumns = []string{
		"enabled", "log_enabled", "created_by", "created_at", "updated_at", "updated_by",
	}
	lbRuleStagePageColumns = []string{
		"block_page_stage1_id", "block_page_stage1_status",
		"block_page_stage3_id", "block_page_stage3_status",
	}
)

// lbRuleSnapshotColumns 由分组拼接生成（OF 串单源）。
var lbRuleSnapshotColumns = joinColumnGroups(
	lbRuleBaseColumns,
	lbRuleHealthCheckColumns,
	lbRuleTCPColumns,
	lbRuleRequestAndUpstreamColumns,
	lbRuleProxyTimeoutColumns,
	lbRuleTLSColumns,
	lbRuleCompressColumns,
	lbRuleLifecycleColumns,
	lbRuleStagePageColumns,
)

func joinColumnGroups(groups ...[]string) string {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	columns := make([]string, 0, total)
	for _, group := range groups {
		columns = append(columns, group...)
	}
	return strings.Join(columns, ",")
}

var clusterSyncedTables = []clusterSyncedTable{
	{name: "lb_rules", snapshotColumns: lbRuleSnapshotColumns},
	{name: "upstreams", snapshotColumns: "id,rule_id,host,port,weight,dynamic_dns,enabled,protocol,max_connections,origin_domain"},
	{name: "path_rules", snapshotColumns: "id,rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to"},
	// users 触发器 OF 列表补 v2.1.8 的 MFA 权威列——此前不在列表内，
	// MFA 状态写（含管理员重置）不 bump cluster_version → 快照缓存持续命中
	// 旧指纹 → 从节点 304 循环，主节点 MFA 变更稳态永不传播（泄露 secret 经
	// 重置后在从节点仍可用）。记账两列（last_timestep/failed_attempts）不补
	// 它们经 哈希清零已不参与漂移判定，入列只会让登录热路径的
	// 计数推进引发无谓重放。pending 不跨节点不补。
	// 修订：locked_until（login_locked_until）从初版「不补」枚举划出
	// 入 OF 列表——主端置锁/解锁 UPDATE 即 bump cluster_version，快照缓存重建、
	// locked_users 当周期下发（否则锁只在下次无关变更时才传播）；「补了
	// 引发无谓重放」的前提已被 值变化守卫消除（登录热路径对
	// login_locked_until 的保值写不 bump，见下方守卫段）。仅失败计数
	// （login_failed_attempts）不入列：普通失败不产生版本抖动；从端本地写由
	// WHEN is_master=1 守卫排除。
	// auth_provider/oidc_subject/oidc_issuer 三列刻意不入
	// OF——当前唯一写路径是 OIDC JIT 开户 INSERT(auth_oidc.go),无 UPDATE
	// 写路径;若未来新增该三列 UPDATE 写路径(换绑/issuer 迁移),必须同步
	// 补 OF,否则稳态变更不 bump 版本、永不传播到从节点。
	// users 节：login_locked_until 参与触发器 bump，但不进 users 载荷/节哈希，
	// 锁状态经顶层 locked_users 下发（见 models.ClusterLockedUser 注释）——
	// 移除该列会让主端锁定永不传播到从节点，且无测试会红。
	{name: "users", snapshotColumns: "id,username,password_hash,role,display_name,is_enabled,password_version,password_changed_at,mfa_enabled,mfa_secret,mfa_recovery_codes,login_locked_until"},
	{name: "api_keys", snapshotColumns: "id,name,key_hash,key_prefix,created_by,expires_at,is_enabled,mcp_enabled,read_only,mcp_ip_whitelist"},
	{name: "ca_providers", snapshotColumns: "id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled,created_at,updated_at"},
	{name: "certificate_configs", snapshotColumns: "id,name,dns_provider,dns_credentials,enabled,created_at,updated_at"},
	{name: "cert_jobs", snapshotColumns: "rule_id,domain,status,cert_pem,key_pem,expires_at,ca_provider_id,renewal_attempts,ca_available_after,last_error_code,created_at,updated_at"},
	{name: "security_policies", snapshotColumns: "id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_whitelist_enabled,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,block_status_code,enabled,updated_by,created_at,updated_at,geoip_countries,geoip_mode,geoip_crawler_exempt,geoip_crawler_engines,waf_check_response,log_request_body,ip_acl_list_refs,ip_whitelist_refs,policy_type,trust_detection"},
	{name: "security_policy_bindings", snapshotColumns: "rule_caddy_id,policy_id"},
	{name: "security_custom_rules", snapshotColumns: "id,name,description,conditions,condition_logic,action,score,enabled,updated_by,created_at,updated_at"},
	{name: "security_block_pages", snapshotColumns: "id,name,description,content,content_type,is_default,is_builtin,created_by,created_at,updated_by,updated_at"},
	{name: "security_ip_lists", snapshotColumns: "id,name,description,category,entries,created_by,created_at,updated_by,updated_at,system"},
	// schedule_days/schedule_time 入列——主端排程
	// 保存（setVersionTableSchedule 同语句写两列+next_update）即 bump 版本，
	// 排程随快照到达从端（升主即生效，自动备份先例）。
	{name: "security_crs_version", snapshotColumns: "id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at,schedule_days,schedule_time"},
	{name: "security_ip2region_version", snapshotColumns: "id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at,schedule_days,schedule_time"},
	// 威胁情报库（v2.3.x）：多行表（每源一行状态机），随集群快照同步；
	// last_checked 为运行态读路径指标，UPDATE 触发列排除（同 CRS/IP2Region）。
	{name: "security_threat_sources", snapshotColumns: "id,name,display_name,url,format,update_enabled,apply_enabled,entry_count,version,update_status,message,last_checked,next_update,trigger,started_at,finished_at,consecutive_failures"},
	// 爬虫地址库独立源表：无 apply_enabled；last_checked/consecutive_failures
	// 与威胁源同口径排除运行态读路径写。
	{name: "security_crawler_sources", snapshotColumns: "id,name,display_name,url,format,update_enabled,entry_count,version,update_status,message,last_checked,next_update,trigger,started_at,finished_at,consecutive_failures"},
}

// columnSet 构造列名集合（只读查找表，避免调用方按字符串比较）。
func columnSet(cols ...string) map[string]bool {
	set := make(map[string]bool, len(cols))
	for _, col := range cols {
		set[col] = true
	}
	return set
}

// clusterVersionRuntimeColumns 是「每轮例行检查都会写」的运行态/展示态簿记
// 列单源，按表登记：这些列参与 bump 判定时，库已是最新版本的常态轮（开始
// 标记 + 无变化终态）也会让 cluster_version 逐轮 +1 → 全集群 304 门失效、
// 从节点反复拉取整包快照并重写两表。判定改为「语义列值真实变化」后，运行态
// 列变化不 bump：从端展示陈旧至下次语义变化（快照 dump 恒携带最新值，自愈），
// 与威胁/爬虫源已达成的口径一致。
// users/cert_jobs 的同类守卫例外形态不同（登录热路径、证书成员条件），仍内联
// 在原处；本清单仅覆盖「例行检查写簿记列」这一族。
var clusterVersionRuntimeColumns = map[string]map[string]bool{
	"security_crs_version": columnSet(
		"update_status", "message", "last_checked", "next_update",
		"trigger", "started_at", "finished_at",
	),
	"security_ip2region_version": columnSet(
		"update_status", "message", "last_checked", "next_update",
		"trigger", "started_at", "finished_at",
	),
	"security_threat_sources": columnSet(
		"last_checked", "update_status", "message", "next_update",
		"trigger", "started_at", "finished_at", "consecutive_failures",
	),
	"security_crawler_sources": columnSet(
		"last_checked", "update_status", "message", "next_update",
		"trigger", "started_at", "finished_at", "consecutive_failures",
	),
}

// updateOfColumns 返回 UPDATE 触发器的 OF 列（快照列逐一过滤掉
// clusterVersionRuntimeColumns 登记的运行态/簿记列）。逐列集合判定而非
// 位置敏感的子串裁剪：旧实现 strings.Replace(",last_checked","",1) 在列排到
// 清单首位时静默失效（子串不存在），OF 列表会重新包含运行态列。
func updateOfColumns(table clusterSyncedTable) []string {
	runtimeCols := clusterVersionRuntimeColumns[table.name]
	columns := strings.Split(table.snapshotColumns, ",")
	kept := make([]string, 0, len(columns))
	for _, column := range columns {
		column = strings.TrimSpace(column)
		if column == "" || runtimeCols[column] {
			continue
		}
		kept = append(kept, column)
	}
	return kept
}

// InstallClusterVersionTriggers 安装/替换全部集群版本触发器（幂等 DDL：
// DROP IF EXISTS + CREATE IF NOT EXISTS）。
//
// 启动期必须在任务引擎之前调用（cmd/server 的启动门）：触发器是同步正确性的
// 结构性前提，而 HTTP 侧的 fail-closed 只覆盖请求链——引擎内的周期任务
// （CRS/IP2Region/威胁/爬虫/cert-renewal/autoban）直接经主库句柄写同步表，
// 触发器缺失时这些写不 bump cluster_version：从节点 304 门恒定命中旧指纹，
// 主端稳态变更永不传播，任务日志却全绿（「fail-closed 假象」）。
// 装配期 clusterVersionMiddleware 也调用本函数（幂等），保持测试与嵌入形态
// 自足；生产启动路径已在前置就绪门完成安装，此处重装只是一次防御刷新。
func InstallClusterVersionTriggers(database *sql.DB) error {
	// nil 句柄（库未装配）必须显式报错而不是 nil deref——本函数已进入生产
	// 启动门，panic 会以栈崩形态出现、掩盖真实原因。
	if database == nil {
		return fmt.Errorf("install cluster version triggers: database not initialized")
	}
	// DDL 整体包进一个事务：每条 DROP/CREATE 各自独立提交时存在「旧触发器
	// 已删、新触发器未建」的窗口（毫秒级，但每次启动都有一次机会；期间后台
	// 写者的同步表写不会 bump cluster_version）。SQLite 的 DDL 可事务化：
	// 提交前读者仍见旧触发器，失败则整体回滚——降级面比逐语句更小。
	tx, err := database.Begin()
	if err != nil {
		return fmt.Errorf("install cluster version triggers: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	// 全部 DDL 由单源构造器生成（与就绪探测共用定义文本）。
	// 遗留触发器 cluster_version_cert_jobs_status_update 的语义已并入
	// cert_jobs UPDATE 触发器，这里只需一次性清理残留。
	if _, err := tx.Exec("DROP TRIGGER IF EXISTS cluster_version_cert_jobs_status_update"); err != nil {
		return fmt.Errorf("replace cluster version trigger for cert_jobs status UPDATE: %w", err)
	}
	for _, trigger := range clusterVersionTriggerStatements() {
		if _, err := tx.Exec(trigger.dropSQL); err != nil {
			return fmt.Errorf("replace cluster version trigger %s: %w", trigger.name, err)
		}
		if _, err := tx.Exec(trigger.createSQL); err != nil {
			return fmt.Errorf("install cluster version trigger %s: %w", trigger.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("install cluster version triggers: commit: %w", err)
	}
	committed = true
	return nil
}

// clusterVersionTrigger 是一条集群版本触发器的 DDL：安装器先 DROP 再 CREATE
// （保证定义随代码刷新），就绪探测用同一份 createSQL 比对库内定义。
type clusterVersionTrigger struct {
	name      string
	dropSQL   string
	createSQL string
}

// clusterVersionTriggerStatements 是全部触发器 DDL 的单源。清单由
// clusterSyncedTables × {INSERT,UPDATE,DELETE} + global_config UPDATE 展开，
// 安装器逐条执行、就绪探测逐条比对定义——定义文本若各自维护，升级后同名的
// 旧定义会被判为就绪（探测只认名字时即如此）。
func clusterVersionTriggerStatements() []clusterVersionTrigger {
	triggers := make([]clusterVersionTrigger, 0, len(clusterSyncedTables)*3+1)
	// 逐表逐语句生成（清单=包级单源，对账测试共用）。
	tables := clusterSyncedTables
	const newCertificateMember = "NEW.status<>'disabled' AND COALESCE(NEW.cert_pem,'')<>'' AND COALESCE(NEW.key_pem,'')<>'' AND datetime(NEW.expires_at)>datetime('now')"
	const oldCertificateMember = "OLD.status<>'disabled' AND COALESCE(OLD.cert_pem,'')<>'' AND COALESCE(OLD.key_pem,'')<>'' AND datetime(OLD.expires_at)>datetime('now')"
	for _, table := range tables {
		for _, operation := range []string{"INSERT", "UPDATE", "DELETE"} {
			triggerName := fmt.Sprintf("cluster_version_%s_%s", table.name, strings.ToLower(operation))
			operationClause := operation
			// NULL 兜底与写闸（readonly.go 的 COALESCE(is_master,1)）对齐——
			// NULL 视为主节点。db.go 一次性回填生效后此处为纵深防御：回填前
			// 历史库 NULL 行两层判定不再分裂（写闸放行写、触发器却不 bump 版本）。
			whenClause := "(SELECT COALESCE(is_master,1) FROM global_config WHERE id=1)=1"
			if operation == "UPDATE" {
				// 运行态/簿记列一律排除在 OF 之外（单源：clusterVersionRuntimeColumns）。
				// SQLite 的 UPDATE OF 只要列出现在 SET 即触发（与值是否变化无关），
				// 这些列每轮例行检查都写，入 OF 会让 304 门失效、从节点反复拉取
				// 整包快照并重写表。同时下方值变化守卫也排除同一集合，两处
				// 不再各写一份（旧实现用位置敏感的子串裁剪，列排到首位即静默失效）。
				ofColumns := strings.Join(updateOfColumns(table), ",")
				operationClause += " OF " + ofColumns
			}
			// users 表值变化守卫——登录热路径同值写
			// (成功登录 NULL→NULL、失败计数 CASE 保值)同样触发 OF 触发器,每次
			// 登录引发全集群快照重放+从节点强制 Caddy 重载。改为「任一同步列
			// 值真实变化」(IS NOT NULL 安全比较全链 OR):登录热路径写
			// login_failed_attempts/last_login(均非同步列)与 login_locked_until
			// 保值时零变化→不 bump;真实置锁/解锁与管理员操作
			// (改密/改角色等真实值变化)照常 bump。
			if table.name == "users" && operation == "UPDATE" {
				cols := strings.Split(table.snapshotColumns, ",")
				valueChange := make([]string, 0, len(cols))
				for _, col := range cols {
					col = strings.TrimSpace(col)
					valueChange = append(valueChange, fmt.Sprintf("OLD.%s IS NOT NEW.%s", col, col))
				}
				whenClause += " AND (" + strings.Join(valueChange, " OR ") + ")"
			}
			// 规则库/威胁库/爬虫库的运行态簿记列（update_status/message/
			// started_at/finished_at/last_checked/next_update/trigger/
			// consecutive_failures）每轮例行检查都会写，SQLite 的 UPDATE OF 只要
			// 列出现在 SET 即触发（无论值是否变化）——「已是最新版本」的常态轮
			// 与持续失败轮都会 bump cluster_version，304 门失效、从节点反复全量
			// 重放。改为「语义列值真实变化」守卫（同 users 口径）：version/
			// updated_at/auto_update/schedule_days/schedule_time/entry_count/url/
			// format/开关等影响从端行为与数据的列变化照常 bump；纯运行态/展示态
			// 列变化不 bump（从端展示陈旧至下次语义变化，快照 dump 恒携带最新值）。
			if runtimeCols := clusterVersionRuntimeColumns[table.name]; runtimeCols != nil && operation == "UPDATE" {
				// 与 OF 排除集合共用 updateOfColumns 的过滤结果（单一来源）。
				cols := updateOfColumns(table)
				valueChange := make([]string, 0, len(cols))
				for _, col := range cols {
					valueChange = append(valueChange, fmt.Sprintf("OLD.%s IS NOT NEW.%s", col, col))
				}
				whenClause += " AND (" + strings.Join(valueChange, " OR ") + ")"
			}
			if table.name == "cert_jobs" {
				switch operation {
				case "INSERT":
					whenClause += " AND " + newCertificateMember
				case "UPDATE":
					whenClause += " AND ((" + oldCertificateMember + ") OR (" + newCertificateMember + "))"
					// 簿记抖动守卫——签发/续期的阶段写
					// (message/attempts/updated_at 等簿记列,每次签发 ~15 次)同样
					// 触发 OF 触发器,导致全集群快照 304 门失效+从端强制重载。
					// 与 users 表 同口径:仅语义列(影响渲染/从端行为)
					// 值真实变化才 bump;簿记列同值/变化均不 bump。
					// status 移出语义列——续期形态老证保留使成员
					// 条件恒真,11 次阶段迁移逐 bump(每次全集群强制重载);材料变化
					// (cert_pem/key_pem/expires_at)已覆盖「新证书可用」的唯一同步
					// 时点,中间态对从端不可见(从端不跑签发),waiting_ca 可见性
					// 延迟可接受(自愈于材料变化/下次语义 bump)。
					// 簿记三列(renewal_attempts/ca_available_after/last_error_code)
					// 序列化进指纹并物化到从端,但守卫排除→从端展示陈旧至下次语义
					// bump——有意权衡(从端无功能消费,自愈),注释如实化。
					semanticCols := []string{"rule_id", "domain", "cert_pem", "key_pem", "expires_at", "ca_provider_id"}
					valueChange := make([]string, 0, len(semanticCols))
					for _, col := range semanticCols {
						valueChange = append(valueChange, fmt.Sprintf("OLD.%s IS NOT NEW.%s", col, col))
					}
					// 补充:disabled 例外——证书下线(OLD 成员→NEW disabled)
					// 必须从端感知(从端停止加载该证书),虽仅 status 变化也 bump。
					// 双向化——恢复方向(disabled→成员态)
					// 同须 bump,否则从端定格「规则启用+证书缺席」。
					valueChange = append(valueChange, "(OLD.status<>'disabled' AND NEW.status='disabled')")
					valueChange = append(valueChange, "(OLD.status='disabled' AND NEW.status<>'disabled')")
					whenClause += " AND (" + strings.Join(valueChange, " OR ") + ")"
				case "DELETE":
					// DELETE 侧成员守卫与 UPDATE 同款——注意其不对称性
					// 如实化）：删除非成员行（disabled/过期/无材料）时 WHEN 恒假不 bump，
					// 从节点该行残留至下次任意语义 bump 自愈（展示面-only，快照证书选择
					// 同样只认成员行，签发不受影响）。
					whenClause += " AND " + oldCertificateMember
				}
			}
			// 定义文本即探测比对口径：SQLite 在 sqlite_master 中保存建库语句时
			// 会去掉 IF NOT EXISTS，因此这里直接生成规范形态（DROP 已在前，
			// IF NOT EXISTS 本就多余）。
			statement := fmt.Sprintf(`CREATE TRIGGER cluster_version_%s_%s
				AFTER %s ON %s
				WHEN %s
				BEGIN
					UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1;
				END`, table.name, strings.ToLower(operation), operationClause, table.name, whenClause)
			triggers = append(triggers, clusterVersionTrigger{
				name:      triggerName,
				dropSQL:   "DROP TRIGGER IF EXISTS " + triggerName,
				createSQL: statement,
			})
		}
	}
	// COALESCE(NEW.is_master,1) 同上——与写闸 NULL 语义一致。
	// auto_backup_* 六设置列入 OF(主端保存即下发);auto_backup_last_run
	// 刻意排除——调度器每次备份推进,入列会让每轮备份引发全集群快照重放。
	// trusted_proxy_* 四列入 OF(防御对齐)——主端保存受信代理设置
	// 须即 bump 版本随快照下发,不在 OF 内则稳态变更永不传播到从节点。
	// 2026-10-12:trusted_proxy_range_refs(引用名单 id)同入——引用的名单
	// 本体在 security 节同步,refs 列变化须触发快照重放(从端渲染展开收敛)。
	// threat_auto_update/threat_schedule_days/
	// threat_schedule_time 三列入 OF(同先例)——主端保存威胁库排程/
	// 总开关即下发,从端升主后按主端排程运行。
	// autoban_enabled/threshold/window_minutes/duration/scope/
	// dry_run 六列入 OF(同先例)——主端 PUT /security/autoban 保存即下发;
	// 不在 OF 内则稳态变更经 304 门滞留主节点,从端恒默认值、升主后按陈旧配置
	// 静默运行(名单传播而配置不传播)。
	triggers = append(triggers, clusterVersionTrigger{
		name:    "cluster_version_global_config_update",
		dropSQL: "DROP TRIGGER IF EXISTS cluster_version_global_config_update",
		createSQL: fmt.Sprintf(`CREATE TRIGGER cluster_version_global_config_update
		AFTER UPDATE OF %s
		ON global_config
		WHEN OLD.cluster_version IS NEW.cluster_version AND COALESCE(NEW.is_master,1)=1
		BEGIN
			UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1;
		END`, strings.Join(globalConfigSyncedColumns, ",")),
	})
	return triggers
}

// usersTableWritePostPaths 是「写 users 表同步列」的 POST 路由清单——
// 生产代码的唯一事实源。分类判定（isUsersTableWritePath）与测试路由注册及
// fail-closed 断言全部从本清单派生，测试不再维护第二份副本（副本漂移时新写
// 路径会漏掉 fail-closed 保护而无人发现）。
var usersTableWritePostPaths = []string{
	"/api/v1/auth/login",
	"/api/v1/auth/mfa/verify",
	"/api/v1/auth/setup",
	"/api/v1/auth/mfa/activate",
	"/api/v1/auth/mfa/disable",
	"/api/v1/auth/mfa/recovery-codes",
}

// usersTableWriteOIDCCallbackPath 是 JIT 开户的 GET 形态路由——方法门之外
// 精确匹配（开户写 users 同步列）。
const usersTableWriteOIDCCallbackPath = "/api/v1/auth/oidc/callback"

// isUsersTableWritePath 判定写 users 表同步列（users 触发器 OF 列）的路由单源：
// 密码登录/MFA 验证步（置锁/解锁 login_locked_until）、初始化管理员
// （auth/setup）、OIDC 回调 JIT 开户（GET 形态）、MFA 三段状态变更
// （mfa_enabled/mfa_secret/mfa_recovery_codes）。
//
// 生产消费方仅 isSynchronizedWrite 一处（同步写分类：触发器可用时写后必须
// bump，不可用时 fail-closed）；测试的路由注册与断言同源派生。触发器的降级
// 态（installErr≠nil）不再按路径分流，而是对所有同步写统一先读
// services.RoleOf：从端放行交下游守卫、主端 500（历史：曾只对
// login/mfa-verify 做从端放行，setup/OIDC/改 MFA 在从端被误伤 500）。
//
// 反例（不属于本表写入，刻意不入列）：/auth/mfa/setup 与
// /auth/mfa/verify-step 只写刻意排除的 pending/记账列（永不 bump），按前缀
// 捕获会让降级态误伤 MFA 登录/step-up。
func isUsersTableWritePath(method, path string) bool {
	if method == http.MethodGet && path == usersTableWriteOIDCCallbackPath {
		return true
	}
	if method != http.MethodPost {
		return false
	}
	return slices.Contains(usersTableWritePostPaths, path)
}

func isSynchronizedWrite(method, path string) bool {
	// users 表同步列写入（登录锁传播 / 初始化管理员 / OIDC JIT 开户 / MFA
	// 状态变更）——触发器不可用时同样 fail-closed（否则真实写库不 bump
	// cluster_version，从节点用户集与锁状态漂移）。OIDC 回调是 GET 形态，
	// 精确匹配置于方法门之外。票据登录不写 users 同步列，不在此列（保全从节点
	// 登录可用性）。
	if isUsersTableWritePath(method, path) {
		return true
	}
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return false
	}
	// Writes to synced global_config columns.
	// auto-backup 六设置列与 oidc_config 均在 global_config 触发器 OF
	// 列表(见上),主端保存必须 bump 供从端收敛。
	if method == http.MethodPut && (path == "/api/v1/config" || path == "/api/v1/caddy/config" || path == "/api/v1/cluster/settings" || path == "/api/v1/admin-tls" || path == "/api/v1/settings/auto-backup" || path == "/api/v1/settings/oidc") {
		return true
	}
	if method == http.MethodDelete && path == "/api/v1/settings/oidc" {
		return true
	}
	// Config backup import rewrites rules/upstreams; the validate endpoint only previews.
	if method == http.MethodPost && (path == "/api/v1/config/import" || path == "/api/v1/config/import/v1") {
		return true
	}
	// 手动任务触发可启动 CRS/IP2Region/威胁/爬虫/证书/自动封禁等
	// 同步表写者。整路由 任务 ID 清单唯一归 taskengine，
	// 中间件不维护第二份「哪些任务写同步表」分类。
	if method == http.MethodPost && path == "/api/v1/system/tasks/:id/trigger" {
		return true
	}
	// 自动备份还原经 importConfigBackupCore 重写
	// lb_rules/upstreams 等全部同步表,与 /config/import 同口径 fail-closed;
	// run(手动备份)与 delete 仅写 auto_backups 本地簿记表,不在此列。
	if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/auto-backup/") && strings.HasSuffix(path, "/restore") {
		return true
	}
	// Certificate issuance and job retry/delete write cert_jobs; parse and current-jobs queries are read-only.
	if path == "/api/v1/certificates/issue" ||
		(strings.HasPrefix(path, "/api/v1/certificates/jobs/") && (method == http.MethodDelete || (method == http.MethodPost && strings.HasSuffix(path, "/retry")))) {
		return true
	}
	// CA provider updates write ca_providers.：POST
	// /ca-providers/:id/test 亦然——ZeroSSL 缺 EAB 时 AutoProvisionZeroSSLEAB
	// 会 UPDATE ca_providers.credentials（触发器 OF 列内含 credentials）。
	// 原注释「test 仅探测凭据」的前提不成立：触发器安装失败的降级态须同样
	// fail-closed，不得静默写同步表却不 bump cluster_version。
	if method == http.MethodPut && strings.HasPrefix(path, "/api/v1/ca-providers") {
		return true
	}
	if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/ca-providers/") && strings.HasSuffix(path, "/test") {
		return true
	}
	if path == "/api/v1/rules/cert-info" {
		return false
	}
	// Certificate config test endpoints only probe DNS credentials without writing.
	if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/certificate-configs/") && strings.HasSuffix(path, "/test") {
		return false
	}
	// 大屏流量采集租约 POST/DELETE 是 Caddy admin 的纯
	// 代理（内存租约，不写任何同步表）——security 前缀捕获让触发器安装失败
	// 的降级态把「打开/关闭大屏」这条热路径误伤成 500，与 MFA 三路由同型。
	if strings.HasPrefix(path, "/api/v1/security/overview/threat-screen/") {
		return false
	}
	for _, prefix := range []string{"/api/v1/rules", "/api/v1/users", "/api/v1/api-keys", "/api/v1/certificate-configs", "/api/v1/security"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
