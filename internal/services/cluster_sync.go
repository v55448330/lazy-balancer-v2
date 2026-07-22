package services

import (
	"crypto/tls"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

type SyncResult struct {
	AppliedVersion int  `json:"applied_version"`
	Changed        bool `json:"changed"`
}

type SyncService struct {
	db      *sql.DB
	cfg     *config.Config
	caddy   *CaddyService
	cluster *ClusterService
	client  *http.Client
	mu      sync.Mutex
	cancel  context.CancelFunc
}

func NewSyncService(database *sql.DB, cfg *config.Config, caddy *CaddyService) *SyncService {
	return &SyncService{
		db: database, cfg: cfg, caddy: caddy,
		cluster: NewClusterService(database, nil),
		// Self-signed admin certificates on the master must not break sync.
		client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}},
	}
}

func (s *SyncService) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go func() {
		s.run(ctx)
		// Clear cancel on exit (transient error, demotion, or role loss) so a
		// later Start() can revive the loop instead of no-opping forever.
		s.mu.Lock()
		s.cancel = nil
		s.mu.Unlock()
	}()
}

func (s *SyncService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}

func (s *SyncService) RegisterWithMaster(ctx context.Context, masterURL string, req models.ClusterRegisterRequest) (models.ClusterRegistration, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("编码注册请求: %w", err)
	}
	callCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, strings.TrimRight(masterURL, "/")+"/api/v1/cluster/register", bytes.NewReader(payload))
	if err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("创建注册请求: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return models.ClusterRegistration{}, errors.New("连接主节点超时，请检查主节点地址与网络")
		}
		return models.ClusterRegistration{}, fmt.Errorf("连接主节点失败: %w", err)
	}
	defer resp.Body.Close()
	var envelope struct {
		Message string                     `json:"message"`
		Data    models.ClusterRegistration `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("解析主节点注册响应: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return models.ClusterRegistration{}, errors.New(envelope.Message)
	}
	return envelope.Data, nil
}

func (s *SyncService) Pull(ctx context.Context) (SyncResult, error) {
	var masterURL, token, fingerprint string
	var isMaster bool
	var appliedVersion int
	if err := s.db.QueryRowContext(ctx, `SELECT is_master, COALESCE(master_url,''), COALESCE(cluster_token,''), COALESCE(applied_version,0), COALESCE(sync_fingerprint,'') FROM global_config WHERE id=1`).Scan(&isMaster, &masterURL, &token, &appliedVersion, &fingerprint); err != nil {
		return SyncResult{}, fmt.Errorf("读取同步状态: %w", err)
	}
	if isMaster {
		return SyncResult{}, errors.New("主节点不能从其他节点同步")
	}
	if masterURL == "" || token == "" {
		return SyncResult{}, errors.New("从节点尚未完成集群审批")
	}
	endpoint := strings.TrimRight(masterURL, "/") + "/api/v1/cluster/sync/snapshot?since_version=" + strconv.Itoa(appliedVersion) + "&fingerprint=" + url.QueryEscape(fingerprint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return SyncResult{}, fmt.Errorf("创建快照请求: %w", err)
	}
	req.Header.Set("X-Cluster-Token", token)
	resp, err := s.client.Do(req)
	if err != nil {
		return SyncResult{}, fmt.Errorf("拉取主节点快照: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return SyncResult{AppliedVersion: appliedVersion}, nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return SyncResult{}, fmt.Errorf("主节点快照请求失败(%d): %s", resp.StatusCode, string(body))
	}
	var envelope struct {
		Data models.ClusterSnapshot `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return SyncResult{}, fmt.Errorf("解析集群快照: %w", err)
	}
	if err := s.applySnapshot(ctx, envelope.Data); err != nil {
		_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET last_sync_error=? WHERE id=1", err.Error())
		RecordAuditLog("system", "同步失败", "集群同步", FormatAuditDetail(fmt.Sprintf("版本：%d", envelope.Data.Version), err.Error()), "")
		return SyncResult{}, err
	}
	return SyncResult{AppliedVersion: envelope.Data.Version, Changed: true}, nil
}

// recordSyncError surfaces pull/report failures in last_sync_error so the
// node page shows the real problem instead of a silently stuck state;
// a fully successful cycle clears it.
func (s *SyncService) recordSyncError(ctx context.Context, pullErr, reportErr error) {
	msg := ""
	if pullErr != nil {
		msg = "同步拉取失败: " + pullErr.Error()
	} else if reportErr != nil {
		msg = "状态上报失败: " + reportErr.Error()
	}
	_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET last_sync_error=? WHERE id=1", msg)
}

func (s *SyncService) run(ctx context.Context) {
	for {
		var isMaster bool
		var token string
		var interval int
		if err := s.db.QueryRowContext(ctx, "SELECT is_master, COALESCE(cluster_token,''), COALESCE(sync_interval,60) FROM global_config WHERE id=1").Scan(&isMaster, &token, &interval); err != nil || isMaster {
			return
		}
		if token == "" {
			s.pollRegistration(ctx)
		} else {
			result, pullErr := s.Pull(ctx)
			if pullErr == nil && !result.Changed {
				RecordAuditLog("system", "同步", "集群同步", "配置无变化", "")
			}
			reportErr := s.Report(ctx)
			s.recordSyncError(ctx, pullErr, reportErr)
		}
		delay := time.Duration(interval) * time.Second
		if token == "" {
			delay = 10 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *SyncService) pollRegistration(ctx context.Context) {
	var masterURL, secret string
	var registrationID int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(master_url,''), COALESCE(registration_id,0), COALESCE(registration_secret,'') FROM global_config WHERE id=1").Scan(&masterURL, &registrationID, &secret); err != nil || masterURL == "" || registrationID == 0 || secret == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/cluster/register/%d/status", strings.TrimRight(masterURL, "/"), registrationID), nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Registration-Secret", secret)
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
			message := "注册已被主节点拒绝或移除，请重新注册或提升为主节点"
			_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET last_sync_error=? WHERE id=1", message)
			RecordAuditLog("system", "注册失败", "集群节点", message, "")
		}
		return
	}
	var envelope struct {
		Data models.ClusterRegistrationStatus `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&envelope) == nil && envelope.Data.Status == "approved" && envelope.Data.ClusterToken != "" {
		_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET cluster_token=?, registration_secret='' WHERE id=1", envelope.Data.ClusterToken)
	}
}
