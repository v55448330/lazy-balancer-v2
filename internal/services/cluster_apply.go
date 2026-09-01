package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/models"
)

var restartRequiredHandler = struct {
	sync.RWMutex
	fn func()
}{fn: defaultRestartRequiredHandler}

func defaultRestartRequiredHandler() {
	go func() {
		time.Sleep(time.Second)
		os.Exit(0)
	}()
}

// SetRestartRequiredHandler installs the graceful restart signal used by the
// process lifecycle. Passing nil restores the standalone fallback behavior.
func SetRestartRequiredHandler(handler func()) {
	restartRequiredHandler.Lock()
	defer restartRequiredHandler.Unlock()
	if handler == nil {
		restartRequiredHandler.fn = defaultRestartRequiredHandler
		return
	}
	restartRequiredHandler.fn = handler
}

func requestRestart() {
	restartRequiredHandler.RLock()
	handler := restartRequiredHandler.fn
	restartRequiredHandler.RUnlock()
	handler()
}

func (s *SyncService) applySnapshot(ctx context.Context, snapshot models.ClusterSnapshot) error {
	if err := validateSnapshotACMEState(snapshot); err != nil {
		return err
	}
	// 开关以主节点快照下发的 MasterSyncSwitches 为准（B3）；旧主节点快照
	// 不携带开关时回退本地默认全开，保持 schema 兼容。
	switches := SyncSwitches{GlobalConfig: true, Users: true, Rules: true, WafFiles: true, Security: true}
	if snapshot.MasterSyncSwitches != nil {
		switches = SyncSwitches{
			GlobalConfig: snapshot.MasterSyncSwitches.GlobalConfig,
			Users:        snapshot.MasterSyncSwitches.Users,
			Rules:        snapshot.MasterSyncSwitches.Rules,
			WafFiles:     snapshot.MasterSyncSwitches.WafFiles,
			Security:     snapshot.MasterSyncSwitches.Security,
		}
	}
	previous, err := s.cluster.clusterSnapshotBypassingCache(ctx)
	if err != nil {
		return fmt.Errorf("备份本地快照: %w", err)
	}
	// 本地重建哈希用于漂移检测：记录哈希与主节点一致但本地数据不符时，
	// 哈希跳过让位于强制重放，避免数据丢失被永久掩盖。
	skip := computeSectionSkips(s.db, snapshot, switches, previous.SectionHashes)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始快照事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// 将主节点开关镜像到本地列：从节点 UI/Status 读取本地列展示真实同步范围。
	// 移入事务内，apply 失败回滚时开关镜像一并回滚，避免半套开关落盘。
	// 触发器带 is_master=1 守卫，此写不会 bump cluster_version。
	if snapshot.MasterSyncSwitches != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE global_config SET
			sync_global_config=?, sync_users=?, sync_rules=?, sync_waf_files=?, sync_security=?
			WHERE id=1 AND COALESCE(is_master,0)=0`,
			snapshot.MasterSyncSwitches.GlobalConfig, snapshot.MasterSyncSwitches.Users,
			snapshot.MasterSyncSwitches.Rules, snapshot.MasterSyncSwitches.WafFiles,
			snapshot.MasterSyncSwitches.Security); err != nil {
			return fmt.Errorf("镜像同步开关: %w", err)
		}
	}
	if err := replaceSnapshotTx(ctx, tx, snapshot, skip); err != nil {
		return err
	}
	// R64 A-N5：证书文件轴（删旧+写新）与 cert_jobs 替换同门于 rules 开关——
	// 开关关闭时从节点本地 acme_dns 规则保留，其证书行/文件不得按主节点快照删改。
	if !skip.disabled["rules"] {
		if err := removeMissingSnapshotCerts(previous.Certs, snapshot.Certs); err != nil {
			return errors.Join(fmt.Errorf("删除本地旧证书: %w", err), s.restoreSnapshotArtifacts(previous, snapshot))
		}
		if err := materializeSnapshotCerts(snapshot.Certs); err != nil {
			return errors.Join(fmt.Errorf("写入同步证书: %w", err), s.restoreSnapshotArtifacts(previous, snapshot))
		}
	}
	if err := s.materializeSnapshotDNSOwnership(snapshot.ACME); err != nil {
		return errors.Join(fmt.Errorf("写入同步 DNS 所有权状态: %w", err), s.restoreSnapshotArtifacts(previous, snapshot))
	}
	if _, err := tx.ExecContext(ctx, `UPDATE global_config SET applied_version=?, cluster_version=?, sync_fingerprint=?, last_sync=datetime('now'), last_sync_error='' WHERE id=1`, snapshot.Version, snapshot.Version, snapshot.Fingerprint); err != nil {
		return errors.Join(
			fmt.Errorf("记录同步状态: %w", err),
			s.restoreSnapshotArtifacts(previous, snapshot),
		)
	}
	if err := tx.Commit(); err != nil {
		return errors.Join(
			fmt.Errorf("提交快照事务: %w", err),
			s.restoreSnapshotArtifacts(previous, snapshot),
		)
	}
	logSectionSyncOutcome(skip, snapshot.Version)
	if len(skip.drifted) > 0 {
		Logf("warn", "检测到本地数据与同步记录不一致（%s），已强制重新应用", strings.Join(skip.drifted, "、"))
		RecordAuditLog("system", "同步自愈", "集群同步", FormatAuditDetail(fmt.Sprintf("本地数据与记录不一致：%s", strings.Join(skip.drifted, "、")), fmt.Sprintf("已强制重新应用版本：%d", snapshot.Version)), "")
	}
	// 漂移强制重放后本地数据已镜像主节点——drifted 节必须存本地重建口径哈希作为
	// 稳定参照，否则跨构建口径分歧时（如 I-2 COALESCE 加固前后）漂移判定永远不一致、
	// 每周期全量重拉+Caddy 重载（E3 N-01）。
	recordAppliedSectionHashes(s.db, snapshot, skip, switches, previous.SectionHashes)
	logSyncSwitchGuards(snapshot, skip, switches)

	// 门控必须与漂移判定同口径开路：wafFilesDrifted 比较含版本标签的节
	// 哈希，wafFilesRefDiffers 只比较内容 sha。内容一致而标签分叉时（如
	// .version 陈旧），仅 sha 比较会把本分支短路，R57 A-#4 的
	// rewriteVersionIfMissingOrStale 永不执行——304 分支兜底重拉 → 应用
	// 跳过 → 每周期全量重拉死循环（主节点「同步下发」审计随之刷屏）。
	if switches.WafFiles && (wafFilesRefDiffers(snapshot.WafFiles) || s.wafFilesDrifted()) {
		bundle, ferr := s.fetchWafFiles(ctx, snapshot.WafFiles)
		if ferr != nil {
			Logf("error", "同步安全数据失败（数据库版本行已同步）: %v", ferr)
			RecordAuditLog("system", "同步失败", "安全数据", fmt.Sprintf("拉取安全数据失败: %v", ferr), "")
		} else if crsChanged, xdbChanged, aerr := ApplyWafFileBundle(bundle); aerr != nil {
			Logf("error", "落盘同步安全数据失败: %v", aerr)
			RecordAuditLog("system", "同步失败", "安全数据", fmt.Sprintf("落盘安全数据失败: %v", aerr), "")
		} else if crsChanged || xdbChanged {
			RecordAuditLog("system", "同步", "安全数据", wafBundleSyncDetail(bundle, crsChanged, xdbChanged), "")
		}
	}
	// Caddy 重载必须在事务提交之后：buildWafHandler 等安全配置读取走 db.DB，
	// 提交前的事务内生成看不到本次写入的 security_* 表。重载失败仅记录，
	// 不回滚已提交的快照。R72 二十六次 W1-1：本路径必须强制——证书文件
	// （materializeSnapshotCerts）与 WAF 数据（ApplyWafFileBundle）在生成前已
	// 落盘，生成期内容比对相等 → 快照为空 → 自动强制不触发；而「仅数据文件
	// 变化、JSON 字节相同」正是 errSameConfig 短路让从节点插件内存停留旧库的
	// 场景。applySnapshot 仅在新快照版本时运行，强制无冗余开销。
	if err := s.caddy.ApplyConfigForce(GenerateCaddyConfig()); err != nil {
		Logf("error", "集群同步后重载 Caddy 失败（快照已提交）: %v", err)
		RecordAuditLog("system", "重载失败", "Caddy服务", fmt.Sprintf("同步应用后自动重载失败: %v", err), "")
		// 写入标记：运行配置与数据库不一致。304 分支识别该标记并全量重拉补偿重试，
		// 避免陈旧运行配置存活到下次真实变更或重启。标记必须跨调用方 ctx 取消存活，
		// 套用 persistSyncError 的 WithoutCancel+2s 超时模式（R33 F-3）。
		marker := fmt.Sprintf(syncReloadFailureMarkerPrefix+": %v", err)
		markerCtx, markerCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer markerCancel()
		result, werr := s.db.ExecContext(markerCtx, "UPDATE global_config SET last_sync_error=? WHERE id=1", encodeSyncError(marker, models.SyncErrorCodeApplyFailed))
		if werr != nil {
			Logf("error", "集群同步重载失败标记写入失败: %v", werr)
		} else if rows, raerr := result.RowsAffected(); raerr != nil || rows != 1 {
			Logf("error", "集群同步重载失败标记写入异常（影响 %d 行，错误 %v）：自愈通道失效，请检查数据库", rows, raerr)
		}
	} else {
		RecordAuditLog("system", "重载", "Caddy服务", "同步应用后自动重载", "")
	}
	clusterSnapshotCaches.Delete(s.db)
	caddySync := "未开启"
	if snapshot.CaddyConfig != nil {
		caddySync = "已同步"
	}
	if RuntimeAdminTLSChanged(LoadAdminTLSConfig()) {
		RecordAuditLog("system", "重启", "系统", "同步到新的 HTTPS 访问配置，自动重启生效", "")
		log.Printf("Admin TLS config changed via sync, restarting to apply")
		requestRestart()
	}
	RecordAuditLog("system", "同步", "集群同步", FormatAuditDetail(fmt.Sprintf("应用版本：%d", snapshot.Version), fmt.Sprintf("规则 %d 条", len(snapshot.Rules)), fmt.Sprintf("用户 %d 个", len(snapshot.Users)), fmt.Sprintf("密钥 %d 个", len(snapshot.APIKeys)), fmt.Sprintf("证书 %d 张", len(snapshot.Certs)), "基本设置：已同步", fmt.Sprintf("Caddy 全局配置：%s", caddySync)), "")
	return nil
}

// wafBundleSyncDetail 按组件实际变化组合同步结果文案：更新的组件带版本号，
// 未变化的标注已是最新——操作日志读者能直接看出本次同步更新了什么。
func wafBundleSyncDetail(bundle *WafFileBundle, crsChanged, xdbChanged bool) string {
	crsPart := "CRS 规则已是最新"
	if crsChanged {
		crsPart = "CRS 规则已更新"
		if bundle.CRSVersion != "" {
			crsPart = "CRS 规则已更新至 " + bundle.CRSVersion
		}
	}
	xdbPart := "IP2Region数据库已是最新"
	if xdbChanged {
		xdbPart = "IP2Region数据库已更新"
		if bundle.IP2RegionTag != "" {
			xdbPart = "IP2Region数据库已更新至 " + bundle.IP2RegionTag
		}
	}
	return crsPart + "；" + xdbPart
}

func (s *SyncService) restoreSnapshotArtifacts(previous, current models.ClusterSnapshot) error {
	return errors.Join(restoreSnapshotCerts(previous.Certs, current.Certs), s.materializeSnapshotDNSOwnership(previous.ACME))
}

func (s *SyncService) materializeSnapshotDNSOwnership(acme *models.ClusterACMEState) error {
	if acme == nil {
		return nil
	}
	if err := validateDNSOwnership(acme.DNSOwnership); err != nil {
		return err
	}
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.DataDir
	}
	if dataDir == "" {
		var err error
		dataDir, err = clusterDatabaseDir(s.db)
		if err != nil {
			return err
		}
	}
	path := filepath.Join(dataDir, "acme_dns_ownership.json")
	temporary, err := os.CreateTemp(dataDir, ".acme-dns-ownership-*")
	if err != nil {
		return fmt.Errorf("创建 DNS 所有权临时文件: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		return errors.Join(fmt.Errorf("设置 DNS 所有权文件权限: %w", err), temporary.Close())
	}
	if _, err := temporary.Write(acme.DNSOwnership); err != nil {
		return errors.Join(fmt.Errorf("写入 DNS 所有权临时文件: %w", err), temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(fmt.Errorf("同步 DNS 所有权临时文件: %w", err), temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("关闭 DNS 所有权临时文件: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("替换 DNS 所有权状态: %w", err)
	}
	if err := syncParentDir(path); err != nil {
		return fmt.Errorf("同步 DNS 所有权目录: %w", err)
	}
	return nil
}

func restoreSnapshotCerts(previous, current []models.ClusterCertificate) error {
	return errors.Join(removeMissingSnapshotCerts(current, previous), materializeSnapshotCerts(previous))
}

func removeMissingSnapshotCerts(previous, current []models.ClusterCertificate) error {
	currentIDs := make(map[string]bool, len(current))
	for _, cert := range current {
		currentIDs[cert.RuleID] = true
	}
	var errs []error
	for _, cert := range previous {
		if !currentIDs[cert.RuleID] {
			if err := RemoveCertFiles(cert.RuleID); err != nil {
				errs = append(errs, fmt.Errorf("删除证书 %s: %w", cert.RuleID, err))
			}
		}
	}
	return errors.Join(errs...)
}

func replaceSnapshotTx(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot, skip *sectionSkips) error {
	if skip == nil || skip.disabled == nil {
		skip = &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	}
	if !skip.skip("rules") {
		if err := clearSyncTables(ctx, tx, "path_rules", "upstreams", "lb_rules"); err != nil {
			return err
		}
	}
	// cert_jobs 存主节点下发的证书（从节点自身不签发），与 ca_providers/certificate_configs
	// 同为全量替换，不纳入 rules 节哈希跳过：rules 节命中哈希跳过后证书 INSERT 仍会重放，
	// 残留旧行会撞 (rule_id,domain) 唯一索引，导致同步永久失败。
	// R64 A-N5：仅哈希跳过（unchanged）保持上述全量回放；rules 开关关闭（disabled）时
	// 证书轴必须联动跳过——证书行/文件是规则轴的派生数据：开关关闭时从节点保留本地
	// 规则（含 enabled=1 的 acme_dns 规则），若仍清空 cert_jobs 并按主节点快照删本地
	// 证书文件，从节点该规则的 TLS 会静默永久丢失（渲染侧无证书即不入 TLS 连接策略，
	// Caddy 正常加载零报错，从节点不签发也无自愈路径）。注意 skip() 是
	// disabled||unchanged 的合并视图，此处须精确判 disabled。
	if !skip.disabled["rules"] {
		if err := clearSyncTables(ctx, tx, "cert_jobs"); err != nil {
			return err
		}
	}
	if !skip.skip("users") {
		if err := clearSyncTables(ctx, tx, "api_keys", "users"); err != nil {
			return err
		}
	}
	var statements []string
	if snapshot.ACME != nil {
		statements = append(statements, "DELETE FROM certificate_configs", "DELETE FROM ca_providers")
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("清理快照数据: %w", err)
		}
	}
	if snapshot.ACME != nil {
		for _, provider := range snapshot.ACME.CAProviders {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`, provider.ID, provider.Name, provider.Provider, provider.DirectoryURL, nullableString(provider.Credentials), provider.MaxConcurrent, provider.MinIntervalMS, provider.Enabled, provider.CreatedAt, provider.UpdatedAt); err != nil {
				return fmt.Errorf("写入快照 CA 提供商 %d: %w", provider.ID, err)
			}
		}
		for _, config := range snapshot.ACME.CertificateConfigs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`, config.ID, config.Name, config.DNSProvider, nullableString(config.DNSCredentials), config.Enabled, config.CreatedAt, nullableTime(config.UpdatedAt.NullTime)); err != nil {
				return fmt.Errorf("写入快照证书配置 %d: %w", config.ID, err)
			}
		}
	}
	if !skip.skip("rules") {
		if err := insertSnapshotRules(ctx, tx, snapshot.Rules); err != nil {
			return err
		}
	}
	if !skip.skip("users") {
		if err := insertSnapshotUsersAndKeys(ctx, tx, snapshot); err != nil {
			return err
		}
	}
	// R64 A-N5：证书回插与清空同门（见上方 cert_jobs 清空处注释）。
	if !skip.disabled["rules"] {
		for _, cert := range snapshot.Certs {
			message := "从主节点同步"
			if cert.SourceStatus != "" {
				message += "，源任务状态：" + cert.SourceStatus
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO cert_jobs (rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,renewal_attempts,ca_available_after,last_error_code) SELECT ?,COALESCE(NULLIF(?,''),domain),'issued',?,?,?,?,?,?,?,? FROM lb_rules WHERE caddy_id=? AND tls_source='acme_dns'`, cert.RuleID, cert.Domain, message, nullableString(cert.ExpiresAt), cert.CertPEM, cert.KeyPEM, cert.CAProviderID, cert.RenewalAttempts, nullableTime(cert.CAAvailableAfter.NullTime), nullableString(cert.LastErrorCode), cert.RuleID); err != nil {
				return fmt.Errorf("写入快照证书 %s: %w", cert.RuleID, err)
			}
		}
	}
	if !skip.skip("global_config") {
		if err := updateSnapshotSettings(ctx, tx, snapshot); err != nil {
			return err
		}
	} else {
		// 同步间隔属集群编排自身（快照侧始终下发），即使全局配置同步
		// 关闭也必须应用，否则从节点轮询周期与 UI 显示双陈旧。
		if _, err := tx.ExecContext(ctx, `UPDATE global_config SET sync_interval=? WHERE id=1 AND COALESCE(is_master,0)=0`, snapshot.BasicSettings.SyncInterval); err != nil {
			return fmt.Errorf("写入同步间隔: %w", err)
		}
	}
	if !skip.skip("security") {
		if err := applySecurityTables(ctx, tx, snapshot); err != nil {
			return err
		}
	}
	return nil
}

func clearSyncTables(ctx context.Context, tx *sql.Tx, tables ...string) error {
	for _, t := range tables {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+t); err != nil {
			return fmt.Errorf("清理同步表 %s 失败: %w", t, err)
		}
	}
	return nil
}

func insertSnapshotUsersAndKeys(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) error {
	for _, user := range snapshot.Users {
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version,password_changed_at,created_at,last_login,mfa_enabled,mfa_secret,mfa_recovery_codes,mfa_last_timestep,mfa_failed_attempts,mfa_locked_until) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			user.ID, user.Username, user.PasswordHash, user.Role, user.DisplayName, user.IsEnabled, user.PasswordVersion, user.PasswordChangedAt, user.CreatedAt, nullableTime(user.LastLogin.NullTime),
			user.MFAEnabled, user.MFASecret, user.MFARecoveryCodes, user.MFALastTimestep, user.MFAFailedAttempts, user.MFALockedUntil); err != nil {
			return fmt.Errorf("写入快照用户 %s: %w", user.Username, err)
		}
	}
	for _, key := range snapshot.APIKeys {
		whitelistJSON, err := json.Marshal(key.MCPIPWhitelist)
		if err != nil {
			return fmt.Errorf("序列化快照密钥 %d 的 MCP IP 白名单: %w", key.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,expires_at,is_enabled,mcp_enabled,read_only,mcp_ip_whitelist,last_used,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, key.ID, key.Name, key.KeyHash, key.KeyPrefix, key.CreatedBy, nullableString(key.ExpiresAt), key.IsEnabled, key.MCPEnabled, key.ReadOnly, string(whitelistJSON), nullableTime(key.LastUsed.NullTime), key.CreatedAt); err != nil {
			return fmt.Errorf("写入快照密钥 %d: %w", key.ID, err)
		}
	}
	return nil
}

// policyWhitelistEnabled 兼容旧快照缺列：缺省视为启用（历史语义=名单非空即生效）。
func policyWhitelistEnabled(p map[string]interface{}) bool {
	if v, ok := p["ip_whitelist_enabled"]; ok {
		if b, ok2 := v.(bool); ok2 {
			return b
		}
	}
	return true
}

func applySecurityTables(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) error {
	// 与规则/用户等表一致的全量替换语义：空载荷意味着主节点已清空，从节点必须
	// 同步删除，不能因载荷为空而提前返回。
	statements := []string{
		"DELETE FROM security_policy_bindings",
		"DELETE FROM security_ip_lists",
		"DELETE FROM security_policies",
		"DELETE FROM security_custom_rules",
		"DELETE FROM security_block_pages",
		"DELETE FROM security_crs_version",
		"DELETE FROM security_ip2region_version",
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("清理安全同步表: %w", err)
		}
	}
	// security_ip_lists 先于 security_policies 落库：策略 refs 以 JSON 引用
	// 列表 id，列表先行可保证引用目标即时存在（全量替换事务内顺序无正确性
	// 影响，固定顺序仅为确定性）。
	var ipLists []map[string]interface{}
	if len(snapshot.SecurityIPLists) > 0 {
		if err := json.Unmarshal(snapshot.SecurityIPLists, &ipLists); err != nil {
			return fmt.Errorf("解析 security_ip_lists: %w", err)
		}
	}
	for _, l := range ipLists {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_ip_lists (id,name,description,category,entries,created_by,created_at,updated_by,updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			l["id"], l["name"], l["description"], l["category"], snapshotJSONText(l["entries"]), l["created_by"], l["created_at"], l["updated_by"], l["updated_at"]); err != nil {
			return fmt.Errorf("写入 security_ip_list: %w", err)
		}
	}
	var policies []map[string]interface{}
	if len(snapshot.SecurityPolicies) > 0 {
		if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
			return fmt.Errorf("解析 security_policies: %w", err)
		}
	}
	for _, p := range policies {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_policies (id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_whitelist_enabled,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,block_status_code,enabled,updated_by,created_at,updated_at,geoip_countries,geoip_mode,waf_check_response,ip_acl_list_refs,ip_whitelist_refs) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p["id"], p["name"], p["description"], p["mode"], p["anomaly_threshold"],
			p["ip_acl_mode"], snapshotJSONText(p["ip_acl_list"]), p["ip_acl_enabled"],
			snapshotJSONText(p["ip_whitelist"]), policyWhitelistEnabled(p), snapshotJSONText(p["ip_blacklist"]),
			p["rate_limit_enabled"], p["rate_limit_rps"], p["rate_limit_burst"],
			snapshotJSONText(p["crs_rule_groups"]), snapshotJSONText(p["crs_excluded_rules"]), snapshotJSONText(p["custom_rules"]),
			p["block_page_id"], p["block_status_code"], p["enabled"], p["updated_by"], p["created_at"], p["updated_at"],
			snapshotJSONText(p["geoip_countries"]), p["geoip_mode"], p["waf_check_response"],
			snapshotJSONText(p["ip_acl_list_refs"]), snapshotJSONText(p["ip_whitelist_refs"])); err != nil {
			return fmt.Errorf("写入 security_policy: %w", err)
		}
	}
	var bindings []map[string]interface{}
	if len(snapshot.SecurityBindings) > 0 {
		if err := json.Unmarshal(snapshot.SecurityBindings, &bindings); err != nil {
			return fmt.Errorf("解析 security_bindings: %w", err)
		}
	}
	for _, b := range bindings {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)`, b["rule_caddy_id"], b["policy_id"]); err != nil {
			return fmt.Errorf("写入 security_policy_binding: %w", err)
		}
	}
	if err := applySecurityCustomRules(ctx, tx, snapshot.SecurityCustomRules); err != nil {
		return err
	}
	if err := applySecurityBlockPages(ctx, tx, snapshot.SecurityBlockPages); err != nil {
		return err
	}
	if err := applySecurityCRSVersion(ctx, tx, snapshot.SecurityCRSVersion); err != nil {
		return err
	}
	if err := applySecurityIP2RegionVersion(ctx, tx, snapshot.SecurityIP2RegionVersion); err != nil {
		return err
	}
	return nil
}

// snapshotJSONText 写入快照中的 JSON 文本列。dumpTableAsJSON 已把该列作为
// JSON 字符串携带，直接透传，避免二次编码成带引号的字面量。
func snapshotJSONText(value interface{}) interface{} {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return v
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return string(encoded)
	}
}

func applySecurityCustomRules(ctx context.Context, tx *sql.Tx, rules []models.SecurityCustomRule) error {
	// 只读预检：主节点下发的规则若含尾部反斜杠/空条件/非法 target 或 operator，
	// 发射侧会整条跳过它们（safe no-op），此处仅记录一条告警，不阻断忠实复制
	// （从节点与主节点保持一致）。
	invalid := false
	for _, rule := range rules {
		// R72 二十七次 N8：补 customRuleEmissionIssue（含名字控制字符/双引号、
		// legacy 单 target 形态）——此前只查 conditions，名字含引号的规则被
		// 忠实复制到从节点但仅在发射时跳过，复制阶段无告警（可观测性缺口）。
		if conditionsEmissionIssue(rule.Conditions) != "" || customRuleEmissionIssue(models.CustomRule{
			ID:         rule.ID,
			Name:       rule.Name,
			Enabled:    rule.Enabled,
			Conditions: rule.Conditions,
			Action:     rule.Action,
			Score:      rule.Score,
		}) != "" {
			invalid = true
			break
		}
	}
	if invalid {
		log.Printf("集群同步的自定义规则存在非法项（尾部反斜杠/空条件/非法 target/operator 或名字含控制字符），发射时将跳过 — 主节点应尽快修复")
	}
	for _, rule := range rules {
		conditions := rule.Conditions
		if conditions == nil {
			conditions = []models.CustomRuleCondition{}
		}
		conditionsJSON, err := json.Marshal(conditions)
		if err != nil {
			return fmt.Errorf("序列化快照自定义安全规则 %d 的条件: %w", rule.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_custom_rules (id,name,description,conditions,action,score,enabled,updated_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			rule.ID, rule.Name, rule.Description, string(conditionsJSON), rule.Action, rule.Score, rule.Enabled, rule.UpdatedBy, rule.CreatedAt, rule.UpdatedAt); err != nil {
			return fmt.Errorf("写入快照自定义安全规则 %d: %w", rule.ID, err)
		}
	}
	return nil
}

func applySecurityBlockPages(ctx context.Context, tx *sql.Tx, pages []models.SecurityBlockPage) error {
	for _, page := range pages {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_block_pages (id,name,description,content,is_default,created_by,created_at,updated_by,updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			page.ID, page.Name, page.Description, page.Content, page.IsDefault, page.CreatedBy, page.CreatedAt, page.UpdatedBy, page.UpdatedAt); err != nil {
			return fmt.Errorf("写入快照拦截页面 %d: %w", page.ID, err)
		}
	}
	// R41 B1: 快照（或经 pre-R40 主节点扩散的快照）可能携带 ≥2 个 is_default=1
	// 的拦截页，全部落库后均不可编辑/删除且会被 branding 覆盖。从节点侧防御：
	// 降级多余默认页，仅保留 MIN(id) 一行，与主节点导入路径行为一致。
	if _, err := tx.ExecContext(ctx, `UPDATE security_block_pages SET is_default=0 WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)`); err != nil {
		return fmt.Errorf("降级多余的默认拦截页: %w", err)
	}
	// R42 B42-2: 保留行内容可能为种子库存而用户定制内容在被降级行上。内容提升
	// 只在主节点导入路径做（config_backup.go 可渲染 branding 判定「库存」内容）；
	// 从节点无 branding 渲染可用，且须与主节点内容忠实一致，此处不做提升——
	// 主节点修复后随后续同步自愈。
	return nil
}

func applySecurityCRSVersion(ctx context.Context, tx *sql.Tx, versions []models.ClusterSecurityCRSVersion) error {
	for _, version := range versions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_crs_version (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			version.ID, version.Version, nullableString(version.UpdatedAt), version.AutoUpdate, version.UpdateStatus, version.Message,
			nullableString(version.LastChecked), nullableString(version.NextUpdate), nullableString(version.Trigger), nullableString(version.StartedAt), nullableString(version.FinishedAt)); err != nil {
			return fmt.Errorf("写入快照 CRS 版本 %d: %w", version.ID, err)
		}
	}
	return nil
}

func applySecurityIP2RegionVersion(ctx context.Context, tx *sql.Tx, versions []models.ClusterSecurityIP2RegionVersion) error {
	for _, version := range versions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_ip2region_version (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			version.ID, version.Version, nullableString(version.UpdatedAt), version.AutoUpdate, version.UpdateStatus, version.Message,
			nullableString(version.LastChecked), nullableString(version.NextUpdate), nullableString(version.Trigger), nullableString(version.StartedAt), nullableString(version.FinishedAt)); err != nil {
			return fmt.Errorf("写入快照 ip2region 版本 %d: %w", version.ID, err)
		}
	}
	return nil
}

func validateSnapshotACMEState(snapshot models.ClusterSnapshot) error {
	if snapshot.ACME == nil {
		// R54 S-4：生产仅 v3 快照可达此处（verifiedSnapshotIntegrity 已按
		// SchemaVersion==CurrentSnapshotSchema 拒掉过旧/过新），旧 v2 放行
		// 分支不可达，缺 ACME 区段统一硬拒。
		return errors.New("schema v3 快照缺少必需的 ACME 区段")
	}
	if snapshot.ACME.CAProviders == nil || snapshot.ACME.CertificateConfigs == nil || len(snapshot.ACME.DNSOwnership) == 0 {
		return errors.New("快照 ACME 区段缺少 ca_providers、certificate_configs 或 dns_ownership")
	}
	if err := validateDNSOwnership(snapshot.ACME.DNSOwnership); err != nil {
		return err
	}
	providers := make(map[int]struct{}, len(snapshot.ACME.CAProviders))
	for _, provider := range snapshot.ACME.CAProviders {
		if provider.ID <= 0 || provider.Name == "" || provider.Provider == "" || provider.DirectoryURL == "" {
			// R53-A-1：行级坏数据（仅 v1 导入残留/直改库可达）整包拒绝会让
			// rules/users 等无关节同步一并瘫痪——与 R51 发现3/R52 N3 同型
			// fail-open：逐行 warn+continue，坏行照常镜像落库（空串不违反
			// NOT NULL），该行名下签发由主节点按单任务失败承担，修复后自愈。
			Logf("warn", "快照 CA 提供商 %d 字段不完整（单行损坏，跳过该校验，该行名下签发将按单任务失败），需人工修复", provider.ID)
			continue
		}
		providers[provider.ID] = struct{}{}
	}
	configs := make(map[int]struct{}, len(snapshot.ACME.CertificateConfigs))
	for _, config := range snapshot.ACME.CertificateConfigs {
		if config.ID <= 0 || config.Name == "" || config.DNSProvider == "" {
			Logf("warn", "快照证书配置 %d 字段不完整（单行损坏，跳过该校验，该行名下签发将按单任务失败），需人工修复", config.ID)
			continue
		}
		configs[config.ID] = struct{}{}
	}
	for _, rule := range snapshot.Rules {
		if !rule.EnableTLS || rule.TLSSource != "acme_dns" {
			continue
		}
		// R51 发现3：acme_config_id=0 / 悬挂配置引用在主节点是「单规则损坏」
		// 状态（issuer 按单任务失败，写入侧已被 validateCaddyConfigBeforeSave
		// 拦截，仅导入残留/直改库可达）。整包拒绝会让一条坏规则瘫痪全部从
		// 节点同步——对齐 verifySnapshotConsistency 的 fail-open 哲学，逐条
		// 跳过+warn，主节点修复后随后续同步自愈。
		if rule.ACMEConfigID == 0 {
			Logf("warn", "快照规则 %s 未设置证书配置（单规则损坏，跳过该校验，签发将按单任务失败），需人工修复", rule.CaddyID)
			continue
		}
		if _, exists := configs[rule.ACMEConfigID]; !exists {
			Logf("warn", "快照规则 %s 引用了不存在的证书配置 %d（单规则损坏，跳过该校验，签发将按单任务失败），需人工修复", rule.CaddyID, rule.ACMEConfigID)
			continue
		}
		if rule.CAProviderID != 0 {
			if _, exists := providers[rule.CAProviderID]; exists {
				continue
			}
			// R52 N3/F-1：悬挂 CA 提供商引用与 acme_config_id 轴同型 fail-open
			// （R51 发现3）——整包拒绝会让一条坏规则瘫痪全部从节点同步；签发
			// 仅主节点，按单任务失败/回退，主节点修复后随后续同步自愈。
			Logf("warn", "快照规则 %s 引用了不存在的 CA 提供商 %d（单规则损坏，跳过该校验，签发将按单任务失败），需人工修复", rule.CaddyID, rule.CAProviderID)
			continue
		}
	}
	for _, cert := range snapshot.Certs {
		if cert.CAProviderID == 0 {
			continue
		}
		if _, exists := providers[cert.CAProviderID]; !exists {
			// R52 N3：证书行的悬挂 CA 引用同样 fail-open——证书文件由
			// materializeSnapshotCerts 同步、签发仅主节点，整包拒绝会让
			// 全部从节点永久 degraded（ValidationFailed 每周期重试但永不收敛）。
			Logf("warn", "快照证书 %s 引用了不存在的 CA 提供商 %d（单证书损坏，跳过该校验），需人工修复", cert.RuleID, cert.CAProviderID)
			continue
		}
	}
	return nil
}

func insertSnapshotRules(ctx context.Context, tx *sql.Tx, rules []models.LbRule) error {
	for _, rule := range rules {
		// R59 C-F1：集群快照可能携带旧库/导入产生的越界 body 上限（写侧校验
		// 之前落库的行），从节点应用时归一到 [0,4096]——与写侧/导入侧同边界，
		// 防止渲染侧 int64 乘法回绕静默取消限制。负值→0（不限制）。
		if rule.RequestBodyMaxSizeMB < 0 {
			rule.RequestBodyMaxSizeMB = 0
		} else if rule.RequestBodyMaxSizeMB > 4096 {
			rule.RequestBodyMaxSizeMB = 4096
		}
		// R63 A-N1：跨版本快照防御——预 R62 主节点库中可能残留 tcp+enable_tls=1+
		// 空证书死形态行（v1 导入旧缺陷）。从节点只读无触发路径，但「提升为主」
		// 是 DB 事务、不重跑启动迁移，提升后到下次重启前该行任何编辑恒 400。
		// 应用时归一（与 UpdateRule tcp 分支同语义），消除该窗口。
		if rule.Protocol == "tcp" && rule.EnableTLS {
			rule.EnableTLS = false
			rule.TLSCert, rule.TLSKey = "", ""
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO lb_rules (id,caddy_id,name,description,protocol,domain,listen_port,strategy,dynamic_dns,enable_dns_server,dns_server,dns_family,health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,custom_routes_enabled,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout,proxy_flush_interval,proxy_stream_close_delay,host_header,enable_tls,tls_source,acme_config_id,ca_provider_id,tls_cert,tls_key,tls_http_redirect,enable_compress,compress_types,enabled,log_enabled,created_by,updated_by,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rule.ID, rule.CaddyID, rule.Name, rule.Description, rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy, rule.DynamicDNS, rule.EnableDnsServer, rule.DnsServer, rule.DnsFamily, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout, rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold, rule.EnableActiveHealthCheck, rule.TCPHealthCheckPort, rule.TCPProxyProtocol, rule.TCPTryDuration, rule.TCPTryInterval, rule.RequestBodyMaxSizeMB, rule.UpstreamKeepaliveTimeout, rule.ServerTokensHidden, rule.CustomRoutesEnabled, rule.ProxyDialTimeout, rule.ProxyResponseHeaderTimeout, rule.ProxyReadTimeout, rule.ProxyWriteTimeout, rule.ProxyStreamTimeout, rule.ProxyFlushInterval, rule.ProxyStreamCloseDelay, rule.HostHeader, rule.EnableTLS, rule.TLSSource, rule.ACMEConfigID, rule.CAProviderID, rule.TLSCert, rule.TLSKey, rule.TLSHTTPRedirect, rule.EnableCompress, rule.CompressTypes, rule.Enabled, rule.LogEnabled, rule.CreatedBy, rule.UpdatedBy, rule.CreatedAt, nullableTime(rule.UpdatedAt.NullTime)); err != nil {
			return fmt.Errorf("写入快照规则 %s: %w", rule.CaddyID, err)
		}
		for _, upstream := range rule.Upstreams {
			if _, err := tx.ExecContext(ctx, `INSERT INTO upstreams (id,rule_id,host,port,weight,dynamic_dns,enabled,protocol,max_connections) VALUES (?,?,?,?,?,?,?,?,?)`, upstream.ID, rule.CaddyID, upstream.Host, upstream.Port, upstream.Weight, upstream.DynamicDNS, upstream.Enabled, upstream.Protocol, upstream.MaxConnections); err != nil {
				return fmt.Errorf("写入快照上游 %s: %w", rule.CaddyID, err)
			}
		}
		if err := insertSnapshotPathRules(ctx, tx, rule.CaddyID, rule.PathRules); err != nil {
			return err
		}
	}
	return nil
}

func insertSnapshotPathRules(ctx context.Context, tx *sql.Tx, ruleID string, pathRules []models.PathRule) error {
	for _, pathRule := range pathRules {
		var upstreamsJSON any
		if pathRule.Upstreams != nil {
			encoded, err := json.Marshal(pathRule.Upstreams)
			if err != nil {
				return fmt.Errorf("序列化快照路径 %s 的上游: %w", pathRule.Path, err)
			}
			upstreamsJSON = string(encoded)
		}
		var err error
		if pathRule.ID > 0 {
			_, err = tx.ExecContext(ctx, `INSERT INTO path_rules (id,rule_id,sort_order,match_type,path,upstreams_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)`, pathRule.ID, ruleID, pathRule.SortOrder, pathRule.MatchType, pathRule.Path, upstreamsJSON, pathRule.CreatedAt, nullableTime(pathRule.UpdatedAt))
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstreams_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`, ruleID, pathRule.SortOrder, pathRule.MatchType, pathRule.Path, upstreamsJSON, pathRule.CreatedAt, nullableTime(pathRule.UpdatedAt))
		}
		if err != nil {
			return fmt.Errorf("写入快照路径 %s: %w", pathRule.Path, err)
		}
	}
	return nil
}

func updateSnapshotSettings(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) error {
	settings := snapshot.BasicSettings
	if settings.JWTExpireMinutes <= 0 || settings.JWTExpireMinutes > 1440 {
		settings.JWTExpireMinutes = 20
	}
	query := `UPDATE global_config SET log_level=?,cert_job_log_size_mb=?,audit_log_size_mb=?,runtime_log_size_mb=?,audit_retention_months=?,jwt_expire_minutes=?,timezone=?,acme_email=?,cert_expiry_days=?,cert_renewal_days=?,cert_renewal_attempts=?,default_ca_provider_id=?,dns_provider=?,dns_credentials=?,sync_interval=?,admin_tls_enabled=?,admin_tls_mode=?,admin_tls_cert=?,admin_tls_key=?,mfa_write_guard=?,mfa_lockout_enabled=?,github_proxy_url=?`
	args := []any{settings.LogLevel, settings.CertJobLogSizeMB, settings.AuditLogSizeMB, settings.RuntimeLogSizeMB, settings.AuditRetentionMonths, settings.JWTExpireMinutes, settings.Timezone, settings.ACMEEmail, settings.CertExpiryDays, settings.CertRenewalDays, settings.CertRenewalAttempts, settings.DefaultCAProviderID, settings.DNSProvider, settings.DNSCredentials, settings.SyncInterval, settings.AdminTLSEnabled, settings.AdminTLSMode, settings.AdminTLSCert, settings.AdminTLSKey, settings.MFAWriteGuard, settings.MFALockoutEnabled, settings.GitHubProxyURL}
	if snapshot.CaddyConfig != nil {
		// R60 A-N1：全局 body 上限钳制 [0,4096]（与 insertSnapshotRules 的行级
		// 归一、写侧校验、导入钳制同边界）——这是全局轴最后一个未闭合的持久化
		// 边界；渲染侧 int64(MB)*1024*1024 回绕会让限制静默取消。
		if settings.RequestBodyMaxSizeMB < 0 {
			settings.RequestBodyMaxSizeMB = 0
		} else if settings.RequestBodyMaxSizeMB > 4096 {
			settings.RequestBodyMaxSizeMB = 4096
		}
		query += ",caddy_config=?,access_log_json=?,access_log_format=?,caddy_log_level=?,caddy_log_size_mb=?,request_body_max_size_mb=?,http_read_timeout=?,http_write_timeout=?,http_idle_timeout=?,upstream_keepalive_timeout=?,proxy_dial_timeout=?,proxy_response_header_timeout=?,proxy_read_timeout=?,proxy_write_timeout=?,proxy_stream_timeout=?,proxy_flush_interval=?,proxy_stream_close_delay=?,server_tokens_hidden=?"
		args = append(args, *snapshot.CaddyConfig, settings.AccessLogJSON, settings.AccessLogFormat, settings.CaddyLogLevel, settings.CaddyLogSizeMB,
			settings.RequestBodyMaxSizeMB, settings.HTTPReadTimeout, settings.HTTPWriteTimeout, settings.HTTPIdleTimeout,
			settings.UpstreamKeepaliveTimeout, settings.ProxyDialTimeout, settings.ProxyResponseHeaderTimeout, settings.ProxyReadTimeout, settings.ProxyWriteTimeout, settings.ProxyStreamTimeout, settings.ProxyFlushInterval, settings.ProxyStreamCloseDelay,
			settings.ServerTokensHidden)
	}
	query += " WHERE id=1"
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("写入快照基础设置: %w", err)
	}
	return nil
}

func materializeSnapshotCerts(certs []models.ClusterCertificate) error {
	for _, cert := range certs {
		if err := WriteCertFiles(cert.RuleID, cert.CertPEM, cert.KeyPEM); err != nil {
			return err
		}
	}
	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}
