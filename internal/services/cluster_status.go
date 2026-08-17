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
	return nodes, rows.Err()
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
	return nil
}
