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
	"os"
	"path/filepath"
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
	db                  *sql.DB
	cfg                 *config.Config
	caddy               *CaddyService
	cluster             *ClusterService
	client              *http.Client
	lifecycleMu         sync.Mutex
	pullAdmissionMu     sync.Mutex
	pullApplyMu         sync.Mutex
	pullMu              sync.Mutex
	mu                  sync.Mutex
	cancel              context.CancelFunc
	done                chan struct{}
	generation          uint64
	pullsStopped        bool
	pullWG              sync.WaitGroup
	runFn               func(context.Context)
	loadRunState        func(context.Context) (bool, string, int, error)
	waitRunDelay        func(context.Context, time.Duration) bool
	beforeBeginPull     func()
	afterStopAdmission  func()
	beforeApplySnapshot func()
}

func NewSyncService(database *sql.DB, cfg *config.Config, caddy *CaddyService) *SyncService {
	return &SyncService{
		db: database, cfg: cfg, caddy: caddy,
		cluster: NewClusterService(database, nil),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *SyncService) do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, errors.New("集群主节点地址必须使用 HTTPS")
	}
	pinPath, err := s.clusterPinPath(req.URL.Host)
	if err != nil {
		return nil, err
	}
	observedFingerprint := ""
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("主节点未提供 TLS 证书")
			}
			fingerprint := sha256.Sum256(state.PeerCertificates[0].Raw)
			encoded := hex.EncodeToString(fingerprint[:])
			stored, err := os.ReadFile(pinPath)
			if errors.Is(err, os.ErrNotExist) {
				observedFingerprint = encoded
				return nil
			}
			if err != nil {
				return fmt.Errorf("读取主节点 TLS 证书指纹: %w", err)
			}
			if strings.TrimSpace(string(stored)) != encoded {
				return errors.New("主节点 TLS 证书指纹不匹配")
			}
			return nil
		},
	}}
	client := &http.Client{Timeout: s.client.Timeout, Transport: transport}

	// TOFU accepts the first observed certificate. The unauthenticated probe
	// persists it before a fresh handshake is allowed to carry credentials.
	probe, err := http.NewRequestWithContext(req.Context(), http.MethodGet, "https://"+req.URL.Host+"/api/v1/branding", nil)
	if err != nil {
		return nil, fmt.Errorf("创建主节点 TLS 预检请求: %w", err)
	}
	probeResp, err := client.Do(probe)
	if err != nil {
		return nil, fmt.Errorf("主节点 TLS 预检失败: %w", err)
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(probeResp.Body, 1<<20)); err != nil {
		return nil, errors.Join(fmt.Errorf("读取主节点 TLS 预检响应: %w", err), probeResp.Body.Close())
	}
	if err := probeResp.Body.Close(); err != nil {
		return nil, fmt.Errorf("关闭主节点 TLS 预检响应: %w", err)
	}
	if observedFingerprint != "" {
		if err := verifyOrStoreClusterPin(pinPath, observedFingerprint); err != nil {
			return nil, err
		}
	}
	transport.CloseIdleConnections()
	return client.Do(req)
}

func (s *SyncService) clusterPinPath(host string) (string, error) {
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.DataDir
	}
	if dataDir == "" && s.db != nil {
		var sequence int
		var name, databasePath string
		if err := s.db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &databasePath); err == nil && databasePath != "" {
			dataDir = filepath.Dir(databasePath)
		}
	}
	if dataDir == "" {
		return "", errors.New("无法确定集群证书指纹存储目录")
	}
	hostHash := sha256.Sum256([]byte(strings.ToLower(host)))
	return filepath.Join(dataDir, "cluster_ca_pins", hex.EncodeToString(hostHash[:])), nil
}

func verifyOrStoreClusterPin(path, fingerprint string) error {
	stored, err := os.ReadFile(path)
	if err == nil {
		if strings.TrimSpace(string(stored)) != fingerprint {
			return errors.New("主节点 TLS 证书指纹不匹配")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("读取主节点 TLS 证书指纹: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("创建集群证书指纹目录: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return verifyOrStoreClusterPin(path, fingerprint)
	}
	if err != nil {
		return fmt.Errorf("保存主节点 TLS 证书指纹: %w", err)
	}
	if _, err := file.WriteString(fingerprint + "\n"); err != nil {
		return errors.Join(fmt.Errorf("保存主节点 TLS 证书指纹: %w", err), file.Close())
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("保存主节点 TLS 证书指纹: %w", err)
	}
	return nil
}

func (s *SyncService) Start() {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.pullAdmissionMu.Lock()
	s.pullsStopped = false
	s.pullAdmissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.generation++
	generation := s.generation
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	go func() {
		if s.runFn != nil {
			s.runFn(ctx)
		} else {
			s.run(ctx)
		}
		s.finishRun(generation)
		close(done)
	}()
}

func (s *SyncService) finishRun(generation uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation == generation {
		s.cancel = nil
		s.done = nil
	}
}

func (s *SyncService) Stop() {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.pullAdmissionMu.Lock()
	s.pullsStopped = true
	s.pullAdmissionMu.Unlock()
	if s.afterStopAdmission != nil {
		s.afterStopAdmission()
	}
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	s.pullWG.Wait()
}

func (s *SyncService) RegisterWithMaster(ctx context.Context, masterURL string, req models.ClusterRegisterRequest) (models.ClusterRegistration, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("编码注册请求: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
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
	if err := s.beginPull(); err != nil {
		return SyncResult{}, err
	}
	defer s.pullWG.Done()

	s.pullMu.Lock()
	defer s.pullMu.Unlock()

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
	var currentMasterURL, currentToken string
	if err := s.db.QueryRowContext(ctx, `SELECT is_master, COALESCE(master_url,''), COALESCE(cluster_token,''), COALESCE(applied_version,0) FROM global_config WHERE id=1`).Scan(&isMaster, &currentMasterURL, &currentToken, &appliedVersion); err != nil {
		return SyncResult{}, fmt.Errorf("重读同步状态: %w", err)
	}
	if isMaster || currentMasterURL != masterURL || currentToken != token {
		return SyncResult{}, errors.New("同步角色或主节点凭据已变更，拒绝应用快照")
	}
	if err := verifySnapshotIntegrity(envelope.Data, token, appliedVersion); err != nil {
		_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET last_sync_error=? WHERE id=1", err.Error())
		RecordAuditLog("system", "同步失败", "集群同步", FormatAuditDetail(fmt.Sprintf("版本：%d", envelope.Data.Version), err.Error()), "")
		return SyncResult{}, err
	}
	if s.beforeApplySnapshot != nil {
		s.beforeApplySnapshot()
	}
	s.pullApplyMu.Lock()
	s.pullAdmissionMu.Lock()
	pullsStopped := s.pullsStopped
	s.pullAdmissionMu.Unlock()
	if pullsStopped {
		s.pullApplyMu.Unlock()
		return SyncResult{}, errors.New("集群同步已停止，拒绝应用快照")
	}
	if err := s.applySnapshot(ctx, envelope.Data); err != nil {
		s.pullApplyMu.Unlock()
		_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET last_sync_error=? WHERE id=1", err.Error())
		RecordAuditLog("system", "同步失败", "集群同步", FormatAuditDetail(fmt.Sprintf("版本：%d", envelope.Data.Version), err.Error()), "")
		return SyncResult{}, err
	}
	s.pullApplyMu.Unlock()
	return SyncResult{AppliedVersion: envelope.Data.Version, Changed: true}, nil
}

func (s *SyncService) beginPull() error {
	if s.beforeBeginPull != nil {
		s.beforeBeginPull()
	}
	s.pullAdmissionMu.Lock()
	defer s.pullAdmissionMu.Unlock()
	if s.pullsStopped {
		return errors.New("集群同步已停止")
	}
	s.pullWG.Add(1)
	return nil
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
func verifySnapshotIntegrity(snapshot models.ClusterSnapshot, clusterToken string, appliedVersion int) error {
	// The signature is mandatory: it is the only authenticity proof over the
	// (verification-skipped) transport, and an unsigned payload could be forged
	// by any on-path actor. Masters that predate signing must be upgraded.
	if snapshot.Signature == "" {
		return fmt.Errorf("快照缺少签名：主节点版本过旧，请先升级主节点")
	}
	if err := verifySnapshotSignature(snapshot, clusterToken); err != nil {
		return err
	}
	if snapshot.MinReaderVersion > CurrentSnapshotSchema {
		return fmt.Errorf("快照需要更新的读取端（要求 schema v%d，当前支持 v%d），请先升级本节点", snapshot.MinReaderVersion, CurrentSnapshotSchema)
	}
	// Signed snapshots must also move forward; replaying a captured older one
	// must not resurrect deleted credentials or roll back configuration.
	if appliedVersion > 0 && snapshot.Version <= appliedVersion {
		return fmt.Errorf("快照版本未递增：收到 %d，已应用 %d，疑似重放攻击", snapshot.Version, appliedVersion)
	}
	if snapshot.Fingerprint != "" {
		if err := verifySnapshotFingerprint(snapshot); err != nil {
			return err
		}
	}
	return verifySnapshotConsistency(snapshot)
}

func verifySnapshotFingerprint(snapshot models.ClusterSnapshot) error {
	canonical := snapshot
	canonical.Fingerprint = ""
	canonical.Signature = ""
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
	loadState := s.loadRunState
	if loadState == nil {
		loadState = func(ctx context.Context) (bool, string, int, error) {
			var isMaster bool
			var token string
			var interval int
			err := s.db.QueryRowContext(ctx, "SELECT is_master, COALESCE(cluster_token,''), COALESCE(sync_interval,60) FROM global_config WHERE id=1").Scan(&isMaster, &token, &interval)
			return isMaster, token, interval, err
		}
	}
	waitDelay := s.waitRunDelay
	if waitDelay == nil {
		waitDelay = func(ctx context.Context, delay time.Duration) bool {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return false
			case <-timer.C:
				return true
			}
		}
	}
	retryDelay := time.Second
	for {
		isMaster, token, interval, err := loadState(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			message := "读取同步状态失败: " + err.Error()
			log.Printf("cluster sync state read failed; retrying: %v", err)
			if _, updateErr := s.db.ExecContext(ctx, "UPDATE global_config SET last_sync_error=? WHERE id=1", message); updateErr != nil {
				log.Printf("cluster sync state error persistence failed: %v", updateErr)
			}
			if !waitDelay(ctx, retryDelay) {
				return
			}
			if retryDelay < 30*time.Second {
				retryDelay *= 2
				if retryDelay > 30*time.Second {
					retryDelay = 30 * time.Second
				}
			}
			continue
		}
		if isMaster {
			return
		}
		retryDelay = time.Second
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
		if !waitDelay(ctx, delay) {
			return
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
