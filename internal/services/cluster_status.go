package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"lazy-balancer-v2/internal/models"
)

func (s *ClusterService) IsMaster(ctx context.Context) (bool, error) {
	var isMaster bool
	if err := s.db.QueryRowContext(ctx, "SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		return false, fmt.Errorf("读取节点模式: %w", err)
	}
	return isMaster, nil
}

func (s *ClusterService) BecomeSlave(ctx context.Context, masterURL string, registration models.ClusterRegistration) error {
	s.roleMu.Lock()
	defer s.roleMu.Unlock()
	if _, err := s.db.ExecContext(ctx, `UPDATE global_config SET is_master=0, master_url=?, cluster_token='', registration_id=?, registration_secret=?, applied_version=0, sync_fingerprint='', last_sync_error='', registration_confirm_failures=0 WHERE id=1`, masterURL, registration.RegistrationID, registration.RegistrationSecret); err != nil {
		return fmt.Errorf("保存从节点注册状态: %w", err)
	}
	if s.lifecycle != nil {
		s.lifecycle.StopACME()
		s.lifecycle.StartSync()
	}
	// 与 Promote 的 SetMasterRole(true) 对称（R54-N5）：降级时停掉 CRS/IP2Region
	// 自动更新调度器。tick 首行的 is_master 守卫只能拦住未发起的 tick；已越过
	// 守卫的 in-flight 更新会在从节点上继续写版本行、替换规则树并 reload，
	// 瞬时打破从节点只读不变量。
	if crsManager := GetCRSUpdateManager(); crsManager != nil {
		crsManager.SetMasterRole(false)
	}
	if ip2regionMgr := GetIP2RegionUpdateManager(); ip2regionMgr != nil {
		ip2regionMgr.SetMasterRole(false)
	}
	ResetConfigDrift()
	return nil
}

func (s *ClusterService) UpdateSettings(ctx context.Context, req models.ClusterSettingsRequest) error {
	isMaster, err := s.IsMaster(ctx)
	if err != nil {
		return err
	}
	if req.SyncInterval != nil && !isMaster {
		return errors.New("从节点不能修改同步间隔，由主节点统一下发")
	}
	// sync_interval 无下限校验会让从节点 run 循环 waitDelay(0) 进入零间隔
	// Pull 风暴（主节点被持续高压请求打满）；上限 86400 防误填（R42 发现1）。
	if req.SyncInterval != nil && (*req.SyncInterval < 10 || *req.SyncInterval > 86400) {
		return ErrInvalidSyncInterval
	}
	if s.beforeUpdateSettings != nil {
		s.beforeUpdateSettings()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始集群设置事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if req.SyncInterval != nil {
		result, err := tx.ExecContext(ctx, "UPDATE global_config SET sync_interval=? WHERE id=1 AND is_master=1", *req.SyncInterval)
		if err != nil {
			return fmt.Errorf("更新同步间隔: %w", err)
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("读取同步间隔更新结果: %w", err)
		}
		if updated != 1 {
			return errors.New("从节点不能修改同步间隔，由主节点统一下发")
		}
	}
	switchUpdates := []struct {
		name string
		val  *bool
	}{
		{"sync_global_config", req.SyncGlobalConfig},
		{"sync_users", req.SyncUsers},
		{"sync_rules", req.SyncRules},
		{"sync_waf_files", req.SyncWafFiles},
		{"sync_security", req.SyncSecurity},
	}
	for _, sw := range switchUpdates {
		if sw.val == nil {
			continue
		}
		result, err := tx.ExecContext(ctx, "UPDATE global_config SET "+sw.name+"=? WHERE id=1 AND is_master=1", *sw.val)
		if err != nil {
			return fmt.Errorf("更新 %s: %w", sw.name, err)
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("读取 %s 更新结果: %w", sw.name, err)
		}
		if updated != 1 {
			return errors.New("从节点不能修改同步开关，请在主节点操作")
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交集群设置: %w", err)
	}
	return nil
}

func (s *ClusterService) Status(ctx context.Context) (models.ClusterStatus, error) {
	var status models.ClusterStatus
	var isMaster bool
	var clusterToken string
	var lastSync sql.NullTime
	var storedSyncError string
	err := s.db.QueryRowContext(ctx, `SELECT is_master, COALESCE(cluster_version,0), COALESCE(master_url,''), COALESCE(sync_interval,60), COALESCE(sync_global_config,1), COALESCE(sync_users,1), COALESCE(sync_rules,1), COALESCE(sync_waf_files,1), COALESCE(sync_security,1), COALESCE(cluster_token,''), COALESCE(applied_version,0), last_sync, COALESCE(last_sync_error,'') FROM global_config WHERE id=1`).Scan(
		&isMaster, &status.ClusterVersion, &status.MasterURL, &status.SyncInterval, &status.SyncGlobalConfig, &status.SyncUsers, &status.SyncRules, &status.SyncWafFiles, &status.SyncSecurity, &clusterToken, &status.AppliedVersion, &lastSync, &storedSyncError)
	if err != nil {
		return models.ClusterStatus{}, fmt.Errorf("读取集群状态: %w", err)
	}
	status.LastSyncError, status.SyncErrorCode = decodeSyncError(storedSyncError)
	status.NodeMode = "slave"
	status.ClusterActive = clusterToken != ""
	if isMaster {
		status.NodeMode = "master"
		status.ClusterActive = true
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN is_approved=0 THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN is_approved=1 THEN 1 ELSE 0 END),0) FROM nodes`).Scan(&status.PendingCount, &status.ApprovedCount); err != nil {
			return models.ClusterStatus{}, fmt.Errorf("统计集群节点: %w", err)
		}
	}
	if lastSync.Valid {
		status.LastSyncAt = lastSync.Time.UTC().Format(time.RFC3339)
	}
	return status, nil
}

func (s *ClusterService) Nodes(ctx context.Context, now time.Time) ([]models.ClusterNodeView, error) {
	var currentVersion, syncInterval int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(cluster_version,0), COALESCE(sync_interval,60) FROM global_config WHERE id=1").Scan(&currentVersion, &syncInterval); err != nil {
		return nil, fmt.Errorf("读取集群版本: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,''),is_approved,COALESCE(reported_version,0),COALESCE(health_json,''),last_seen,created_at FROM nodes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取节点列表: %w", err)
	}
	defer rows.Close()
	nodes := make([]models.ClusterNodeView, 0)
	for rows.Next() {
		var node models.ClusterNodeView
		var lastSeen, createdAt sql.NullTime
		var healthJSON string
		if err := rows.Scan(&node.ID, &node.Name, &node.IPAddress, &node.Port, &node.Protocol, &node.AccessURL, &node.IsApproved, &node.ReportedVersion, &healthJSON, &lastSeen, &createdAt); err != nil {
			return nil, fmt.Errorf("扫描节点列表: %w", err)
		}
		node.CurrentVersion = currentVersion
		node.Status = ComputeNodeStatus(node.IsApproved, lastSeen.Time, syncInterval, now)
		// 单节点 health_json 损坏只降级该节点（Health=nil），不拖垮整个节点列表
		health, decodeErr := DecodeClusterHealth(healthJSON)
		if decodeErr != nil {
			Logf("warn", "解析节点 %d 健康状态失败: %v", node.ID, decodeErr)
		} else {
			node.Health = health
		}
		if lastSeen.Valid {
			node.LastSeen = lastSeen.Time.UTC().Format(time.RFC3339)
		}
		if createdAt.Valid {
			node.CreatedAt = createdAt.Time.UTC().Format(time.RFC3339)
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	attachSectionSync(ctx, s, nodes)
	return nodes, nil
}

// attachSectionSync 为已上报分区哈希的节点聚合 per-section 同步状态：主节点
// 自身节哈希与同步开关过滤每次请求只计算一次；任一依赖读取失败时整体降级
// （所有节点 SectionSync 保持 nil，等同旧版本从节点占位），绝不把错误上抛
// 拖垮节点列表，也绝不展示可能失真的「全部滞后」。
func attachSectionSync(ctx context.Context, s *ClusterService, nodes []models.ClusterNodeView) {
	reports := s.snapshotSectionReports()
	hasReport := false
	for i := range nodes {
		if nodes[i].IsApproved && reports[nodes[i].ID] != nil {
			hasReport = true
			break
		}
	}
	if !hasReport {
		return
	}
	switches, err := readSyncSwitches(s.db)
	if err != nil {
		Logf("warn", "读取同步开关失败（分区同步状态降级省略）: %v", err)
		return
	}
	masterSnapshot, _, _, err := s.cachedSnapshot(ctx)
	if err != nil {
		Logf("warn", "计算主节点分区哈希失败（分区同步状态降级省略）: %v", err)
		return
	}
	masterHashes := masterSnapshot.SectionHashes
	for i := range nodes {
		if !nodes[i].IsApproved {
			continue
		}
		if reported := reports[nodes[i].ID]; reported != nil {
			nodes[i].SectionSync = buildSectionSyncStatuses(reported, masterHashes, switches)
		}
	}
}

// buildSectionSyncStatuses 按主节点开关过滤节，逐节比对从节点上报哈希与主节点
// 自身哈希；从节点缺该节记录（从未同步/开关曾关闭）按滞后处理。
func buildSectionSyncStatuses(reported, masterHashes map[string]string, switches SyncSwitches) []models.ClusterSectionSyncStatus {
	statuses := make([]models.ClusterSectionSyncStatus, 0, len(syncSections))
	for _, sec := range syncSections {
		if !switches.sectionEnabled(sec.Key) {
			continue
		}
		hash := reported[sec.Key]
		masterHash := masterHashes[sec.Key]
		statuses = append(statuses, models.ClusterSectionSyncStatus{
			Section:    sec.Key,
			Label:      sec.NewLabel,
			Hash:       hash,
			MasterHash: masterHash,
			Synced:     hash != "" && hash == masterHash,
		})
	}
	if len(statuses) == 0 {
		return nil
	}
	return statuses
}

// storeSectionReport 记录节点最近一次上报的分区哈希（防御性拷贝，调用方后续
// 改动上报载荷不影响已存状态）；空哈希视为旧版本从节点上报，清除既有记录。
func (s *ClusterService) storeSectionReport(nodeID int, hashes map[string]string) {
	s.sectionMu.Lock()
	defer s.sectionMu.Unlock()
	if s.sectionReports == nil {
		s.sectionReports = make(map[int]map[string]string)
	}
	if len(hashes) == 0 {
		delete(s.sectionReports, nodeID)
		return
	}
	stored := make(map[string]string, len(hashes))
	for key, hash := range hashes {
		stored[key] = hash
	}
	s.sectionReports[nodeID] = stored
}

func (s *ClusterService) snapshotSectionReports() map[int]map[string]string {
	s.sectionMu.Lock()
	defer s.sectionMu.Unlock()
	reports := make(map[int]map[string]string, len(s.sectionReports))
	for nodeID, hashes := range s.sectionReports {
		copied := make(map[string]string, len(hashes))
		for key, hash := range hashes {
			copied[key] = hash
		}
		reports[nodeID] = copied
	}
	return reports
}

func (s *ClusterService) clearSectionReport(nodeID int) {
	s.sectionMu.Lock()
	defer s.sectionMu.Unlock()
	delete(s.sectionReports, nodeID)
}

func (s *ClusterService) ReportNode(ctx context.Context, nodeID int, report models.ClusterReport, now time.Time) error {
	health := report.Health
	health.LastSyncAt = report.LastSyncAt
	health.LastSyncError = report.LastSyncError
	health.SyncErrorCode = report.SyncErrorCode
	encoded, err := json.Marshal(health)
	if err != nil {
		return fmt.Errorf("编码节点健康状态: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE nodes SET status='online',last_seen=?,reported_version=?,health_json=?,last_sync_at=?,last_sync_error=? WHERE id=? AND is_approved=1`, now.UTC(), report.AppliedVersion, string(encoded), nullableString(report.LastSyncAt), report.LastSyncError, nodeID)
	if err != nil {
		return fmt.Errorf("更新节点上报: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrNodeNotFound
	}
	s.storeSectionReport(nodeID, report.SectionHashes)
	return nil
}

func (s *ClusterService) DeleteNode(ctx context.Context, nodeID int) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM nodes WHERE id=?", nodeID)
	if err != nil {
		return fmt.Errorf("删除节点: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrNodeNotFound
	}
	s.clearSectionReport(nodeID)
	return nil
}
