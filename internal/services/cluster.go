package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"lazy-balancer-v2/internal/models"
)

var (
	ErrInvalidRegisterToken = errors.New("注册令牌无效或已过期")
	ErrNodeNotFound         = errors.New("节点不存在")
	ErrInvalidClusterAuth   = errors.New("集群凭证无效")
	ErrAlreadyMaster        = errors.New("当前节点已是主节点")
)

type ClusterLifecycle interface {
	StartACME()
	StopACME()
	StartSync()
	StopSync()
}

type ClusterService struct {
	db                   *sql.DB
	lifecycle            ClusterLifecycle
	roleMu               sync.Mutex
	beforeUpdateSettings func()
}

func NewClusterService(database *sql.DB, lifecycle ClusterLifecycle) *ClusterService {
	return &ClusterService{db: database, lifecycle: lifecycle}
}

func randomHex(byteCount int) (string, error) {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("生成随机凭证: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func permanentClusterToken(registrationSecret string) string {
	hash := sha256.Sum256([]byte("lazy-balancer-cluster:" + registrationSecret))
	return "lb_cluster_" + hex.EncodeToString(hash[:])
}

func (s *ClusterService) GenerateRegisterToken(ctx context.Context, createdBy int, now time.Time) (string, time.Time, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := now.UTC().Add(30 * time.Minute)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO cluster_register_tokens (token_hash, expires_at, created_by, created_at) VALUES (?, ?, ?, ?)`,
		tokenHash(token), expiresAt, createdBy, now.UTC()); err != nil {
		return "", time.Time{}, fmt.Errorf("保存注册令牌: %w", err)
	}
	return token, expiresAt, nil
}

func (s *ClusterService) RegisterNode(ctx context.Context, req models.ClusterRegisterRequest, now time.Time) (models.ClusterRegistration, error) {
	if req.Port == 0 {
		req.Port = 8000
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("开始注册事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `UPDATE cluster_register_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?`,
		now.UTC(), tokenHash(req.Token), now.UTC())
	if err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("使用注册令牌: %w", err)
	}
	used, err := result.RowsAffected()
	if err != nil || used != 1 {
		return models.ClusterRegistration{}, ErrInvalidRegisterToken
	}

	secret, err := randomHex(32)
	if err != nil {
		return models.ClusterRegistration{}, err
	}
	var nodeID int
	err = tx.QueryRowContext(ctx, "SELECT id FROM nodes WHERE ip_address=? AND port=?", req.IPAddress, req.Port).Scan(&nodeID)
	switch {
	case err == nil:
		_, err = tx.ExecContext(ctx, `UPDATE nodes SET name=?, status='pending', is_approved=0, registration_secret=?, registration_secret_expires_at=NULL, cluster_token_hash=NULL, cluster_token_delivered=0, reported_version=0, health_json=NULL, last_seen=NULL WHERE id=?`, req.Name, tokenHash(secret), nodeID)
	case errors.Is(err, sql.ErrNoRows):
		insert, insertErr := tx.ExecContext(ctx, `INSERT INTO nodes (name, mode, ip_address, port, status, is_approved, registration_secret) VALUES (?, 'slave', ?, ?, 'pending', 0, ?)`, req.Name, req.IPAddress, req.Port, tokenHash(secret))
		if insertErr != nil {
			return models.ClusterRegistration{}, fmt.Errorf("创建待审批节点: %w", insertErr)
		}
		id, idErr := insert.LastInsertId()
		if idErr != nil {
			return models.ClusterRegistration{}, fmt.Errorf("读取节点编号: %w", idErr)
		}
		nodeID = int(id)
		err = nil
	default:
		return models.ClusterRegistration{}, fmt.Errorf("查询已有节点: %w", err)
	}
	if err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("更新待审批节点: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("提交节点注册: %w", err)
	}
	return models.ClusterRegistration{RegistrationID: nodeID, RegistrationSecret: secret}, nil
}

func (s *ClusterService) ApproveNode(ctx context.Context, nodeID int) error {
	result, err := s.db.ExecContext(ctx, `UPDATE nodes SET is_approved=1, status='online', registration_secret_expires_at=datetime('now','+24 hours'), cluster_token_hash=NULL, cluster_token_delivered=0 WHERE id=? AND status='pending' AND COALESCE(registration_secret,'')<>''`, nodeID)
	if err != nil {
		return fmt.Errorf("批准节点: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取审批结果: %w", err)
	}
	if updated != 1 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *ClusterService) RegistrationStatus(ctx context.Context, nodeID int, secret string) (models.ClusterRegistrationStatus, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return models.ClusterRegistrationStatus{}, fmt.Errorf("开始状态事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var status, storedSecretHash string
	var approved bool
	var secretExpiresAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT status, is_approved, COALESCE(registration_secret,''), registration_secret_expires_at FROM nodes WHERE id=?`, nodeID).Scan(&status, &approved, &storedSecretHash, &secretExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ClusterRegistrationStatus{Status: "rejected"}, nil
		}
		return models.ClusterRegistrationStatus{}, fmt.Errorf("读取注册状态: %w", err)
	}
	if storedSecretHash == "" || storedSecretHash != tokenHash(secret) || (secretExpiresAt.Valid && !secretExpiresAt.Time.After(time.Now().UTC())) {
		return models.ClusterRegistrationStatus{}, ErrInvalidClusterAuth
	}
	response := models.ClusterRegistrationStatus{Status: "pending"}
	if approved {
		response.Status = "approved"
		clusterToken := permanentClusterToken(secret)
		if _, err := tx.ExecContext(ctx, "UPDATE nodes SET cluster_token_hash=?, cluster_token_delivered=1 WHERE id=?", tokenHash(clusterToken), nodeID); err != nil {
			return models.ClusterRegistrationStatus{}, fmt.Errorf("保存集群令牌: %w", err)
		}
		response.ClusterToken = clusterToken
	} else if status != "pending" {
		response.Status = "rejected"
	}
	if err := tx.Commit(); err != nil {
		return models.ClusterRegistrationStatus{}, fmt.Errorf("提交状态查询: %w", err)
	}
	return response, nil
}

type clusterVersionExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func BumpClusterVersion(ctx context.Context, executor clusterVersionExecutor) error {
	if _, err := executor.ExecContext(ctx, "UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1"); err != nil {
		return fmt.Errorf("递增集群版本: %w", err)
	}
	return nil
}

func (s *ClusterService) Promote(ctx context.Context) error {
	s.roleMu.Lock()
	defer s.roleMu.Unlock()
	isMaster, err := s.IsMaster(ctx)
	if err != nil {
		return err
	}
	if isMaster {
		return ErrAlreadyMaster
	}
	if s.lifecycle != nil {
		s.lifecycle.StopSync()
	}
	promoted := false
	defer func() {
		if !promoted && s.lifecycle != nil {
			s.lifecycle.StartSync()
		}
	}()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始提升事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE global_config SET is_master=1, master_url='', cluster_token='', registration_id=0, registration_secret='' WHERE id=1`); err != nil {
		return fmt.Errorf("重置主节点状态: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交提升事务: %w", err)
	}
	promoted = true
	if s.lifecycle != nil {
		s.lifecycle.StartACME()
	}
	return nil
}

func ComputeNodeStatus(approved bool, lastSeen time.Time, syncInterval int, now time.Time) string {
	if !approved {
		return "pending"
	}
	if lastSeen.IsZero() || now.Sub(lastSeen) > 2*time.Duration(syncInterval)*time.Second {
		return "offline"
	}
	return "online"
}

func DecodeClusterHealth(value string) (*models.ClusterHealth, error) {
	if value == "" {
		return nil, nil
	}
	var health models.ClusterHealth
	if err := json.Unmarshal([]byte(value), &health); err != nil {
		return nil, fmt.Errorf("解析节点健康状态: %w", err)
	}
	return &health, nil
}
