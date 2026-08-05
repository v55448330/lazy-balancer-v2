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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

type SyncResult struct {
	AppliedVersion int  `json:"applied_version"`
	Changed        bool `json:"changed"`
}

type SnapshotSchemaTooNewError struct {
	Actual    int
	Supported int
}

type SnapshotSchemaTooOldError struct {
	Actual    int
	Supported int
}

func (err *SnapshotSchemaTooOldError) Error() string {
	return fmt.Sprintf("快照 schema v%d 过旧：主节点需升级到支持 schema v%d 的版本", err.Actual, err.Supported)
}

type syncFailure struct {
	code models.SyncErrorCode
	err  error
}

func (failure *syncFailure) Error() string { return failure.err.Error() }
func (failure *syncFailure) Unwrap() error { return failure.err }

type syncLifecycleState uint32

const (
	syncStateStopped syncLifecycleState = iota
	syncStateRunning
	syncStateDegraded
	syncStateHalted
)

var errClusterPinMismatch = errors.New("主节点 TLS 证书指纹不匹配")

func (err *SnapshotSchemaTooNewError) Error() string {
	return fmt.Sprintf("主节点快照版本 v%d 超出本节点支持范围 v%d，请升级从节点", err.Actual, err.Supported)
}

type SyncService struct {
	db                     *sql.DB
	cfg                    *config.Config
	caddy                  *CaddyService
	cluster                *ClusterService
	client                 *http.Client
	transport              *http.Transport
	transportOnce          sync.Once
	pinMu                  sync.Mutex
	verifiedPins           map[string]string
	lifecycleMu            sync.Mutex
	pullAdmissionMu        sync.Mutex
	pullApplyMu            sync.Mutex
	pullMu                 sync.Mutex
	mu                     sync.Mutex
	cancel                 context.CancelFunc
	done                   chan struct{}
	generation             uint64
	state                  atomic.Uint32
	pullsStopped           bool
	pullWG                 sync.WaitGroup
	runFn                  func(context.Context)
	loadRunState           func(context.Context) (bool, string, int, error)
	waitRunDelay           func(context.Context, time.Duration) bool
	beforeBeginPull        func()
	afterStopAdmission     func()
	beforeApplySnapshot    func()
	beforeRecordSyncStatus func()
}

func NewSyncService(database *sql.DB, cfg *config.Config, caddy *CaddyService) *SyncService {
	service := &SyncService{
		db: database, cfg: cfg, caddy: caddy,
		cluster: NewClusterService(database, nil),
	}
	service.initClusterClient()
	return service
}

func (s *SyncService) do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, errors.New("集群主节点地址必须使用 HTTPS")
	}
	s.initClusterClient()
	pinPath, err := s.clusterPinPath(req.URL.Host)
	if err != nil {
		return nil, err
	}
	s.pinMu.Lock()
	verifiedFingerprint, verified := s.verifiedPins[pinPath]
	s.pinMu.Unlock()
	if verified {
		if err := verifyOrStoreClusterPin(pinPath, verifiedFingerprint); err != nil {
			return nil, err
		}
	}
	return s.client.Do(req)
}

func (s *SyncService) initClusterClient() {
	s.transportOnce.Do(func() {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
		transport := &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       tlsConfig,
		}
		transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			configForAddress := tlsConfig.Clone()
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("解析主节点 TLS 地址: %w", err)
			}
			configForAddress.ServerName = host
			configForAddress.VerifyConnection = func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return errors.New("主节点未提供 TLS 证书")
				}
				pinPath, err := s.clusterPinPath(address)
				if err != nil {
					return err
				}
				fingerprint := sha256.Sum256(state.PeerCertificates[0].Raw)
				encoded := hex.EncodeToString(fingerprint[:])
				if err := verifyOrStoreClusterPin(pinPath, encoded); err != nil {
					return err
				}
				s.pinMu.Lock()
				s.verifiedPins[pinPath] = encoded
				s.pinMu.Unlock()
				return nil
			}
			return (&tls.Dialer{Config: configForAddress}).DialContext(ctx, network, address)
		}
		s.transport = transport
		s.verifiedPins = make(map[string]string)
		if s.client == nil {
			s.client = &http.Client{Timeout: 30 * time.Second}
		}
		s.client.Transport = transport
		s.client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	})
}

func (s *SyncService) clusterPinPath(host string) (string, error) {
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.DataDir
	}
	return clusterPinPath(dataDir, s.db, host)
}

func clusterPinPathForDatabase(database *sql.DB, host string) (string, error) {
	return clusterPinPath("", database, host)
}

func clusterPinPath(dataDir string, database *sql.DB, host string) (string, error) {
	if dataDir == "" && database != nil {
		var sequence int
		var name, databasePath string
		if err := database.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &databasePath); err == nil && databasePath != "" {
			dataDir = filepath.Dir(databasePath)
		}
	}
	if dataDir == "" {
		return "", errors.New("无法确定集群证书指纹存储目录")
	}
	parsed := &url.URL{Host: host}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", errors.New("主节点地址缺少主机名")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	hostHash := sha256.Sum256([]byte(net.JoinHostPort(hostname, port)))
	return filepath.Join(dataDir, "cluster_ca_pins", hex.EncodeToString(hostHash[:])), nil
}

func verifyOrStoreClusterPin(path, fingerprint string) error {
	directory := filepath.Dir(path)
	if err := verifyClusterPinDirectory(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() {
			return errors.New("主节点 TLS 证书指纹必须是普通文件")
		}
		if info.Mode().Perm()&^os.FileMode(0600) != 0 {
			return fmt.Errorf("主节点 TLS 证书指纹文件权限过宽: %04o", info.Mode().Perm())
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("检查主节点 TLS 证书指纹: %w", statErr)
	}
	stored, err := os.ReadFile(path)
	if err == nil {
		if strings.TrimSpace(string(stored)) != fingerprint {
			return errClusterPinMismatch
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("读取主节点 TLS 证书指纹: %w", err)
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("创建集群证书指纹目录: %w", err)
	}
	if err := verifyClusterPinDirectory(directory); err != nil {
		return err
	}
	return storeClusterPin(path, fingerprint, func(file *os.File) error {
		if _, err := file.WriteString(fingerprint + "\n"); err != nil {
			return fmt.Errorf("write fingerprint: %w", err)
		}
		return nil
	})
}

func storeClusterPin(path, fingerprint string, write func(*os.File) error) (err error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".cluster-pin-*")
	if err != nil {
		return fmt.Errorf("创建主节点 TLS 证书指纹临时文件: %w", err)
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		removeErr := os.Remove(temporaryPath)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
		if err != nil && published {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, removeErr)
			}
		}
	}()
	if err := write(temporary); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(fmt.Errorf("同步主节点 TLS 证书指纹: %w", err), temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("关闭主节点 TLS 证书指纹临时文件: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return verifyOrStoreClusterPin(path, fingerprint)
		}
		return fmt.Errorf("发布主节点 TLS 证书指纹: %w", err)
	}
	published = true
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("打开集群证书指纹目录: %w", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		return errors.Join(fmt.Errorf("同步集群证书指纹目录: %w", err), directoryHandle.Close())
	}
	if err := directoryHandle.Close(); err != nil {
		return fmt.Errorf("关闭集群证书指纹目录: %w", err)
	}
	return nil
}

func verifyClusterPinDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("集群证书指纹目录必须是普通目录")
	}
	if info.Mode().Perm()&^os.FileMode(0700) != 0 {
		return fmt.Errorf("集群证书指纹目录权限过宽: %04o", info.Mode().Perm())
	}
	return nil
}

func (s *SyncService) Start() {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.startLocked(false)
}

func (s *SyncService) Resume() {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if syncLifecycleState(s.state.Load()) != syncStateHalted {
		return
	}
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()
	if done != nil {
		<-done
	}
	s.startLocked(true)
}

func (s *SyncService) startLocked(resume bool) {
	if syncLifecycleState(s.state.Load()) == syncStateHalted && !resume {
		return
	}
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.pullAdmissionMu.Lock()
	s.pullsStopped = false
	s.pullAdmissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	s.generation++
	generation := s.generation
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	s.state.Store(uint32(syncStateRunning))
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
		if syncLifecycleState(s.state.Load()) != syncStateHalted {
			s.state.Store(uint32(syncStateStopped))
		}
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
	if syncLifecycleState(s.state.Load()) != syncStateHalted {
		s.state.Store(uint32(syncStateStopped))
	}
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

func (s *SyncService) Pull(ctx context.Context) (result SyncResult, err error) {
	if err := s.beginPull(); err != nil {
		err = newSyncFailure(models.SyncErrorCodeValidationFailed, err)
		if s.db != nil {
			s.recordSyncError(ctx, err, nil)
		}
		return SyncResult{}, err
	}
	defer s.pullWG.Done()

	s.pullMu.Lock()
	defer s.pullMu.Unlock()
	defer func() {
		if s.db != nil {
			if s.beforeRecordSyncStatus != nil {
				s.beforeRecordSyncStatus()
			}
			s.recordSyncError(ctx, err, nil)
		}
	}()

	var masterURL, token, fingerprint string
	var isMaster bool
	var appliedVersion int
	if err := s.db.QueryRowContext(ctx, `SELECT is_master, COALESCE(master_url,''), COALESCE(cluster_token,''), COALESCE(applied_version,0), COALESCE(sync_fingerprint,'') FROM global_config WHERE id=1`).Scan(&isMaster, &masterURL, &token, &appliedVersion, &fingerprint); err != nil {
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeTransportError, fmt.Errorf("读取同步状态: %w", err))
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
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeValidationFailed, fmt.Errorf("创建快照请求: %w", err))
	}
	req.Header.Set("X-Cluster-Token", token)
	resp, err := s.do(req)
	if err != nil {
		code := models.SyncErrorCodeTransportError
		if errors.Is(err, errClusterPinMismatch) {
			code = models.SyncErrorCodePinMismatch
		}
		return SyncResult{}, newSyncFailure(code, fmt.Errorf("拉取主节点快照: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return SyncResult{AppliedVersion: appliedVersion}, nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeTransportError, fmt.Errorf("主节点快照请求失败(%d): %s", resp.StatusCode, string(body)))
	}
	var envelope struct {
		Data models.ClusterSnapshot `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeValidationFailed, fmt.Errorf("解析集群快照: %w", err))
	}
	var currentMasterURL, currentToken string
	if err := s.db.QueryRowContext(ctx, `SELECT is_master, COALESCE(master_url,''), COALESCE(cluster_token,''), COALESCE(applied_version,0) FROM global_config WHERE id=1`).Scan(&isMaster, &currentMasterURL, &currentToken, &appliedVersion); err != nil {
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeTransportError, fmt.Errorf("重读同步状态: %w", err))
	}
	if isMaster || currentMasterURL != masterURL || currentToken != token {
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeValidationFailed, errors.New("同步角色或主节点凭据已变更，拒绝应用快照"))
	}
	verifiedSnapshot, err := verifiedSnapshotIntegrity(envelope.Data, token, appliedVersion)
	if err != nil {
		RecordAuditLog("system", "同步失败", "集群同步", FormatAuditDetail(fmt.Sprintf("版本：%d", envelope.Data.Version), err.Error()), "")
		return SyncResult{}, err
	}
	envelope.Data = verifiedSnapshot
	if s.beforeApplySnapshot != nil {
		s.beforeApplySnapshot()
	}
	s.pullApplyMu.Lock()
	s.pullAdmissionMu.Lock()
	pullsStopped := s.pullsStopped
	s.pullAdmissionMu.Unlock()
	if pullsStopped {
		s.pullApplyMu.Unlock()
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeValidationFailed, errors.New("集群同步已停止，拒绝应用快照"))
	}
	if err := s.applySnapshot(ctx, envelope.Data); err != nil {
		s.pullApplyMu.Unlock()
		RecordAuditLog("system", "同步失败", "集群同步", FormatAuditDetail(fmt.Sprintf("版本：%d", envelope.Data.Version), err.Error()), "")
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeApplyFailed, err)
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
func newSyncFailure(code models.SyncErrorCode, err error) error {
	return &syncFailure{code: code, err: err}
}

func syncErrorCode(err error) models.SyncErrorCode {
	if err == nil {
		return ""
	}
	var schemaTooNew *SnapshotSchemaTooNewError
	if errors.As(err, &schemaTooNew) {
		return models.SyncErrorCodeSchemaTooNew
	}
	var schemaTooOld *SnapshotSchemaTooOldError
	if errors.As(err, &schemaTooOld) {
		return models.SyncErrorCodeSchemaTooOld
	}
	var failure *syncFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	return models.SyncErrorCodeValidationFailed
}

type persistedSyncError struct {
	Code    models.SyncErrorCode `json:"code"`
	Message string               `json:"message"`
}

func encodeSyncError(message string, code models.SyncErrorCode) string {
	if message == "" {
		return ""
	}
	encoded, err := json.Marshal(persistedSyncError{Code: code, Message: message})
	if err != nil {
		return message
	}
	return string(encoded)
}

func decodeSyncError(stored string) (string, models.SyncErrorCode) {
	if stored == "" {
		return "", ""
	}
	var persisted persistedSyncError
	if json.Unmarshal([]byte(stored), &persisted) == nil && persisted.Message != "" {
		return persisted.Message, persisted.Code
	}
	return stored, ""
}

func (s *SyncService) persistSyncError(ctx context.Context, message string, code models.SyncErrorCode) {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(persistCtx, "UPDATE global_config SET last_sync_error=? WHERE id=1", encodeSyncError(message, code)); err != nil {
		Logf("error", "cluster sync error persistence failed: %v", err)
	}
}

func (s *SyncService) recordSyncError(ctx context.Context, pullErr, reportErr error) {
	msg := ""
	code := models.SyncErrorCode("")
	if pullErr != nil {
		msg = "同步拉取失败: " + pullErr.Error()
		code = syncErrorCode(pullErr)
	} else if reportErr != nil {
		msg = "状态上报失败: " + reportErr.Error()
		code = models.SyncErrorCodeTransportError
	}
	s.persistSyncError(ctx, msg, code)
}

// verifySnapshotIntegrity re-computes the snapshot fingerprint the same way
// the master does and checks referential consistency, so a corrupted or
// truncated payload is rejected before anything is applied.
func verifySnapshotIntegrity(snapshot models.ClusterSnapshot, clusterToken string, appliedVersion int) error {
	_, err := verifiedSnapshotIntegrity(snapshot, clusterToken, appliedVersion)
	return err
}

func verifiedSnapshotIntegrity(snapshot models.ClusterSnapshot, clusterToken string, appliedVersion int) (models.ClusterSnapshot, error) {
	// The signature is mandatory: it is the only authenticity proof over the
	// (verification-skipped) transport, and an unsigned payload could be forged
	// by any on-path actor. Masters that predate signing must be upgraded.
	if snapshot.Signature == "" {
		return models.ClusterSnapshot{}, newSyncFailure(models.SyncErrorCodeSignatureInvalid, errors.New("快照缺少签名：主节点版本过旧，请先升级主节点"))
	}
	if err := verifySnapshotSignature(snapshot, clusterToken); err != nil {
		return models.ClusterSnapshot{}, err
	}
	// 只有验签通过后才允许进入 schema_too_new 终止路径：伪造数据永不触发
	// halted，只能降级。验签通过后若读取端版本不足，无法安全解析
	// canonical_payload，必须终止同步并等待本节点升级。
	if snapshot.MinReaderVersion > CurrentSnapshotSchema {
		return models.ClusterSnapshot{}, &SnapshotSchemaTooNewError{Actual: snapshot.MinReaderVersion, Supported: CurrentSnapshotSchema}
	}
	if len(snapshot.CanonicalPayload) > 0 && snapshot.Fingerprint == "" {
		return models.ClusterSnapshot{}, newSyncFailure(models.SyncErrorCodeValidationFailed, errors.New("快照规范内容缺少指纹"))
	}
	if snapshot.Fingerprint != "" {
		if err := verifySnapshotFingerprint(snapshot); err != nil {
			return models.ClusterSnapshot{}, err
		}
	}
	if snapshot.SchemaVersion >= 3 && len(snapshot.CanonicalPayload) == 0 {
		return models.ClusterSnapshot{}, newSyncFailure(models.SyncErrorCodeValidationFailed, errors.New("schema v3 快照缺少 canonical_payload"))
	}
	if len(snapshot.CanonicalPayload) > 0 {
		var canonical models.ClusterSnapshot
		if err := json.Unmarshal(snapshot.CanonicalPayload, &canonical); err != nil {
			return models.ClusterSnapshot{}, newSyncFailure(models.SyncErrorCodeValidationFailed, fmt.Errorf("解析规范快照内容: %w", err))
		}
		if len(canonical.CanonicalPayload) > 0 || canonical.Version != snapshot.Version || canonical.SchemaVersion != snapshot.SchemaVersion || canonical.MinReaderVersion != snapshot.MinReaderVersion {
			return models.ClusterSnapshot{}, newSyncFailure(models.SyncErrorCodeValidationFailed, errors.New("快照规范内容与元数据不一致"))
		}
		canonical.Fingerprint = snapshot.Fingerprint
		canonical.Signature = snapshot.Signature
		canonical.CanonicalPayload = append(json.RawMessage(nil), snapshot.CanonicalPayload...)
		snapshot = canonical
	}
	if snapshot.SchemaVersion > CurrentSnapshotSchema {
		return models.ClusterSnapshot{}, &SnapshotSchemaTooNewError{Actual: snapshot.SchemaVersion, Supported: CurrentSnapshotSchema}
	}
	if snapshot.SchemaVersion < CurrentSnapshotSchema {
		return models.ClusterSnapshot{}, &SnapshotSchemaTooOldError{Actual: snapshot.SchemaVersion, Supported: CurrentSnapshotSchema}
	}
	// 验签通过即代表快照来自真实主节点，HMAC 签名是唯一真实性闸门：从节点
	// 始终跟随主节点。主节点从旧备份恢复时其 cluster_version 会低于从节点
	// 已应用版本，此时照常应用快照，仅对严格回退打印告警。
	if appliedVersion > 0 && snapshot.Version < appliedVersion {
		log.Printf("⚠️ 警告：检测到主节点配置版本回退（恢复场景）：收到快照版本 %d，本节点已应用版本 %d，从节点继续跟随主节点", snapshot.Version, appliedVersion)
	}
	if err := verifySnapshotConsistency(snapshot); err != nil {
		return models.ClusterSnapshot{}, newSyncFailure(models.SyncErrorCodeValidationFailed, err)
	}
	if err := validateSnapshotACMEState(snapshot); err != nil {
		return models.ClusterSnapshot{}, newSyncFailure(models.SyncErrorCodeValidationFailed, err)
	}
	return snapshot, nil
}

func verifySnapshotFingerprint(snapshot models.ClusterSnapshot) error {
	// Round 35 S-11: schema v3 已强制要求 CanonicalPayload，移除 v1/v2 扁平回退路径。
	if len(snapshot.CanonicalPayload) == 0 {
		return newSyncFailure(models.SyncErrorCodeValidationFailed, fmt.Errorf("快照缺少 canonical_payload（schema v3 强制要求）"))
	}
	hash := sha256.Sum256(snapshot.CanonicalPayload)
	if hex.EncodeToString(hash[:]) != snapshot.Fingerprint {
		return newSyncFailure(models.SyncErrorCodeValidationFailed, fmt.Errorf("快照指纹校验失败：数据可能被截断或篡改"))
	}
	return nil
}

// verifySnapshotSignature recomputes the master's HMAC-SHA256 over the
// canonical snapshot using this node's cluster token as the key.
func verifySnapshotSignature(snapshot models.ClusterSnapshot, clusterToken string) error {
	if clusterToken == "" {
		return newSyncFailure(models.SyncErrorCodeSignatureInvalid, fmt.Errorf("快照签名校验失败：本节点缺少集群令牌"))
	}
	// Round 35 S-11: schema v3 已强制要求 CanonicalPayload，移除 v1/v2 扁平回退路径。
	if len(snapshot.CanonicalPayload) == 0 {
		return newSyncFailure(models.SyncErrorCodeSignatureInvalid, fmt.Errorf("快照缺少 canonical_payload（schema v3 强制要求）"))
	}
	content := []byte(snapshot.CanonicalPayload)
	mac := hmac.New(sha256.New, []byte(clusterToken))
	mac.Write(content)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(snapshot.Signature)) {
		return newSyncFailure(models.SyncErrorCodeSignatureInvalid, fmt.Errorf("快照签名校验失败：来源无法验证，可能存在中间人攻击"))
	}
	return nil
}

// verifySnapshotConsistency 记录快照中的数据漂移。启用但零上游的规则通常是
// 历史数据或导入残留，需要人工清理；生成端已对该类规则跳过并告警，此处不再
// 拒绝快照，避免主节点可运行而从节点永久降级。
func verifySnapshotConsistency(snapshot models.ClusterSnapshot) error {
	for _, rule := range snapshot.Rules {
		if rule.Enabled && len(rule.Upstreams) == 0 {
			log.Printf("⚠️ 警告：快照中启用规则 %s 没有上游（数据漂移，需人工清理），生成配置时将跳过该规则", rule.CaddyID)
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
			s.state.Store(uint32(syncStateDegraded))
			Logf("error", "cluster sync state read failed; retrying: %v", err)
			s.persistSyncError(ctx, message, models.SyncErrorCodeTransportError)
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
		if token == "" {
			s.pollRegistration(ctx)
		} else {
			result, pullErr := s.Pull(ctx)
			if pullErr == nil && !result.Changed {
				RecordAuditLog("system", "同步", "集群同步", "配置无变化", "")
			}
			var schemaTooNew *SnapshotSchemaTooNewError
			var schemaTooOld *SnapshotSchemaTooOldError
			terminal := errors.As(pullErr, &schemaTooNew) || errors.As(pullErr, &schemaTooOld)
			if terminal {
				s.state.Store(uint32(syncStateHalted))
			}
			reportErr := s.Report(ctx)
			s.recordSyncError(ctx, pullErr, reportErr)
			if terminal {
				return
			}
			if pullErr != nil || reportErr != nil {
				s.state.Store(uint32(syncStateDegraded))
			} else {
				s.state.Store(uint32(syncStateRunning))
				retryDelay = time.Second
			}
		}
		delay := time.Duration(interval) * time.Second
		if token == "" {
			delay = 10 * time.Second
		} else if syncLifecycleState(s.state.Load()) == syncStateDegraded {
			delay = retryDelay
		}
		if !waitDelay(ctx, delay) {
			return
		}
		if syncLifecycleState(s.state.Load()) == syncStateDegraded && retryDelay < 30*time.Second {
			retryDelay *= 2
			if retryDelay > 30*time.Second {
				retryDelay = 30 * time.Second
			}
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
			s.persistSyncError(ctx, message, models.SyncErrorCodeValidationFailed)
			RecordAuditLog("system", "注册失败", "集群节点", message, "")
		}
		return
	}
	var envelope struct {
		Data models.ClusterRegistrationStatus `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&envelope) == nil && envelope.Data.Status == "approved" && envelope.Data.ClusterToken != "" {
		confirm, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(masterURL, "/")+"/api/v1/cluster/registration/confirm", nil)
		if err != nil {
			return
		}
		confirm.Header.Set("X-Cluster-Token", envelope.Data.ClusterToken)
		confirmed, err := s.do(confirm)
		if err != nil {
			return
		}
		defer confirmed.Body.Close()
		// Round 35 S-12: 移除 404/405 fallback 兼容（v2.0.8+ 主节点均支持 confirm 端点）。
		// 任何 4xx/5xx 都视为注册失败，从节点不应继续存储 token。
		if confirmed.StatusCode >= http.StatusBadRequest {
			return
		}
		_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET cluster_token=?, registration_secret='' WHERE id=1", envelope.Data.ClusterToken)
	}
}
