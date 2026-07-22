package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// do transparently migrates the scheme when the master toggles enforced
// admin TLS: plain HTTP hitting an HTTPS server (400) upgrades to HTTPS, and
// HTTPS hitting a plain HTTP server (client error) downgrades to HTTP. A
// successful migration is persisted to master_url so later cycles skip the
// probe entirely.
func (s *SyncService) do(req *http.Request) (*http.Response, error) {
	resp, err := s.client.Do(req)
	if err == nil && req.URL.Scheme == "http" && resp.StatusCode == http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "HTTP request to an HTTPS server") {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return resp, nil
		}
		resp, err = s.client.Do(s.cloneRequest(req, "https"))
		if err == nil {
			s.migrateMasterURLScheme("https")
		}
		return resp, err
	}
	if err != nil && req.URL.Scheme == "https" && strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		resp, err = s.client.Do(s.cloneRequest(req, "http"))
		if err == nil {
			s.migrateMasterURLScheme("http")
		}
		return resp, err
	}
	return resp, err
}

// cloneRequest rebuilds a request with a different scheme, replaying the body
// via GetBody so POST retries (registration) keep their payload.
func (s *SyncService) cloneRequest(req *http.Request, scheme string) *http.Request {
	u := *req.URL
	u.Scheme = scheme
	clone, err := http.NewRequestWithContext(req.Context(), req.Method, u.String(), nil)
	if err != nil {
		return req
	}
	clone.Header = req.Header.Clone()
	if req.GetBody != nil {
		clone.Body, _ = req.GetBody()
	}
	clone.ContentLength = req.ContentLength
	return clone
}

// migrateMasterURLScheme persists the scheme that just worked so subsequent
// sync cycles use it directly.
func (s *SyncService) migrateMasterURLScheme(scheme string) {
	var masterURL string
	if err := s.db.QueryRow("SELECT COALESCE(master_url,'') FROM global_config WHERE id=1").Scan(&masterURL); err != nil || masterURL == "" {
		return
	}
	u, err := url.Parse(masterURL)
	if err != nil || u.Scheme == scheme {
		return
	}
	u.Scheme = scheme
	if _, err := s.db.Exec("UPDATE global_config SET master_url=? WHERE id=1", u.String()); err == nil {
		log.Printf("集群主节点地址协议已自动切换为 %s", scheme)
		RecordAuditLog("system", "更新", "集群同步", fmt.Sprintf("主节点地址协议自动切换为 %s", scheme), "")
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
	resp, err := s.do(httpReq)
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
	resp, err := s.do(req)
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
	if err := verifySnapshotIntegrity(envelope.Data, token); err != nil {
		_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET last_sync_error=? WHERE id=1", err.Error())
		RecordAuditLog("system", "同步失败", "集群同步", FormatAuditDetail(fmt.Sprintf("版本：%d", envelope.Data.Version), err.Error()), "")
		return SyncResult{}, err
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

// verifySnapshotIntegrity re-computes the snapshot fingerprint the same way
// the master does and checks referential consistency, so a corrupted or
// truncated payload is rejected before anything is applied.
func verifySnapshotIntegrity(snapshot models.ClusterSnapshot, clusterToken string) error {
	// Masters older than the fingerprint feature send an empty value; skip the
	// check for them instead of breaking sync across a rolling upgrade.
	if snapshot.Fingerprint != "" {
		if err := verifySnapshotFingerprint(snapshot); err != nil {
			return err
		}
	}
	// Newer masters sign snapshots with the node's cluster token; an on-path
	// attacker cannot forge that without knowing it. Older masters omit the
	// signature and stay accepted until they upgrade.
	if snapshot.Signature != "" {
		if err := verifySnapshotSignature(snapshot, clusterToken); err != nil {
			return err
		}
	}
	return verifySnapshotConsistency(snapshot)
}

func verifySnapshotFingerprint(snapshot models.ClusterSnapshot) error {
	canonical := snapshot
	canonical.Fingerprint = ""
	canonical.Version = 0
	content, err := json.Marshal(canonical)
	if err != nil {
		return fmt.Errorf("快照序列化失败: %w", err)
	}
	hash := sha256.Sum256(content)
	if hex.EncodeToString(hash[:]) != snapshot.Fingerprint {
		return fmt.Errorf("快照指纹校验失败：数据可能被截断或篡改")
	}
	return nil
}

// verifySnapshotSignature recomputes the master's HMAC-SHA256 over the
// canonical snapshot using this node's cluster token as the key.
func verifySnapshotSignature(snapshot models.ClusterSnapshot, clusterToken string) error {
	if clusterToken == "" {
		return fmt.Errorf("快照签名校验失败：本节点缺少集群令牌")
	}
	canonical := snapshot
	canonical.Fingerprint = ""
	canonical.Signature = ""
	canonical.Version = 0
	content, err := json.Marshal(canonical)
	if err != nil {
		return fmt.Errorf("快照序列化失败: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(clusterToken))
	mac.Write(content)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(snapshot.Signature)) {
		return fmt.Errorf("快照签名校验失败：来源无法验证，可能存在中间人攻击")
	}
	return nil
}

func verifySnapshotConsistency(snapshot models.ClusterSnapshot) error {
	for _, rule := range snapshot.Rules {
		if rule.Enabled && len(rule.Upstreams) == 0 {
			return fmt.Errorf("快照一致性校验失败：规则 %s 没有上游", rule.CaddyID)
		}
	}
	return nil
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
	resp, err := s.do(req)
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
