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

// errSyncPullStopped 是 beginPull 在停机竞态（Stop 期间）下的哨兵错误：该路径
// 不得落库覆盖 apply_ok_reload_failed 标记（见 recordSyncError），错误本身仍
// 返回给调用方（含手动 Pull 的 API 响应）。
var errSyncPullStopped = errors.New("集群同步已停止")

// errSyncTokenRevoked 表示主节点以 401/403 拒绝了本节点的快照拉取：
// 集群令牌已被撤销（节点被主节点删除或注册被拒），继续按周期重试只会
// 无限失败，属于需要人工介入（重新注册或提升为主节点）的终止类错误。
var errSyncTokenRevoked = errors.New("集群令牌已被主节点撤销，请重新注册或提升为主节点")

// errSyncMasterNoPull 表示主节点被调用 Pull：主节点没有同步对象，该错误
// 只返回调用方（手动同步 API），不得经 recordSyncError 落库污染
// last_sync_error（节点页面会持续显示且无自动清除路径，R41 S-1）。
var errSyncMasterNoPull = errors.New("主节点不能从其他节点同步")

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
	reportAuditMu          sync.Mutex
	lastReportFailureMsg   string
	runFn                  func(context.Context)
	loadRunState           func(context.Context) (bool, string, int, error)
	waitRunDelay           func(context.Context, time.Duration) bool
	beforeBeginPull        func()
	afterStopAdmission     func()
	beforeApplySnapshot    func()
	beforeRecordSyncStatus func()
	// wafRepullFailures 记录 WAF 文件兜底重拉的连续未收敛轮数（内存态，
	// atomic.Int32：常规读写发生在 Pull 的 pullMu 临界区内；startLocked/Stop
	// 的清零复位不持 pullMu，与 Halted 态手动 Pull 的临界区无共同互斥锁，
	// 故全部访问经原子操作避免数据竞争（R41 F-1））。连续未收敛达到
	// wafRepullMaxFailures 轮后：把「安全数据持续同步失败」上表面到
	// last_sync_error（节点页面可见），并把兜底重拉降频为每 wafRepullEvery
	// 轮一次；收敛后清零恢复正常。
	wafRepullFailures atomic.Int32
	// reloadRepullFailures（R72 二十七次 N4）：重载失败 marker 触发的补偿
	// 全量重拉的连续失败计数——与 wafRepullFailures 同款节流（5 轮后降频为
	// 每 10 轮），防止 Caddy /load 持续故障时每同步周期全量重拉+全表重写+
	// 强制重载+2 条审计记录的次生负载（间隔下限实为 10s，非 60s）。
	reloadRepullFailures atomic.Int32
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
	if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
		return nil, errors.New("集群主节点地址必须使用 HTTP 或 HTTPS")
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
		dataDir := ""
		if s.cfg != nil {
			dataDir = s.cfg.DataDir
		}
		s.transport = newClusterTOFUTransport(dataDir, s.db, func(pinPath, fingerprint string) {
			s.pinMu.Lock()
			s.verifiedPins[pinPath] = fingerprint
			s.pinMu.Unlock()
		})
		s.verifiedPins = make(map[string]string)
		if s.client == nil {
			s.client = &http.Client{Timeout: 30 * time.Second}
		}
		s.client.Transport = s.transport
		s.client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	})
}

// newClusterTOFUTransport 构建带 TOFU（首次信任）TLS 证书指纹校验的 transport，
// 供同步 Pull 使用，避免自签名主节点握手失败。
func newClusterTOFUTransport(dataDir string, database *sql.DB, onVerified func(pinPath, fingerprint string)) *http.Transport {
	return newClusterVerifyTransport(func(state tls.ConnectionState, address string) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("主节点未提供 TLS 证书")
		}
		pinPath, err := clusterPinPath(dataDir, database, address)
		if err != nil {
			return err
		}
		fingerprint := sha256.Sum256(state.PeerCertificates[0].Raw)
		encoded := hex.EncodeToString(fingerprint[:])
		if err := verifyOrStoreClusterPin(pinPath, encoded); err != nil {
			return err
		}
		if onVerified != nil {
			onVerified(pinPath, encoded)
		}
		return nil
	})
}

// newClusterDetachTransport 为提升后的脱离通知构建"仅比对不落盘"的 TLS 校验
// transport：提升时旧主节点 pin 文件已被删除，若复用 TOFU transport 会在握手时
// 把指纹重新写回、再次信任已脱离的旧主节点；此处仅与已知指纹比对，失败即拒绝。
func newClusterDetachTransport(expectedPin string) *http.Transport {
	return newClusterVerifyTransport(func(state tls.ConnectionState, _ string) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("主节点未提供 TLS 证书")
		}
		fingerprint := sha256.Sum256(state.PeerCertificates[0].Raw)
		if hex.EncodeToString(fingerprint[:]) != expectedPin {
			return errClusterPinMismatch
		}
		return nil
	})
}

func newClusterVerifyTransport(verify func(state tls.ConnectionState, address string) error) *http.Transport {
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
			return verify(state, address)
		}
		return (&tls.Dialer{Config: configForAddress}).DialContext(ctx, network, address)
	}
	return transport
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
	// 角色切换/重启复用同一实例：清零 WAF 兜底重拉连续未收敛计数，
	// 避免陈旧计数让新会话首次漂移重拉被降频延迟（R40 N-1）。
	s.wafRepullFailures.Store(0)
	s.reloadRepullFailures.Store(0)
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
	// 防御性清零：与 startLocked 配对，确保 Stop 后实例处于干净状态（R40 N-1）。
	s.wafRepullFailures.Store(0)
	s.reloadRepullFailures.Store(0)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRegistrationResponseBytes)).Decode(&envelope); err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("解析主节点注册响应: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return models.ClusterRegistration{}, errors.New(envelope.Message)
	}
	return envelope.Data, nil
}

// maxSnapshotResponseBytes caps the Pull snapshot response body: 合法快照内嵌
// 证书 PEM 与 WAF 引用，256MB 留足余量，同时约束恶意/异常膨胀主节点的内存
// 占用（同链路 waf-files 端点为 64MB，仅承载规则包）。超限即解析失败。
var maxSnapshotResponseBytes int64 = 256 << 20

// maxRegistrationResponseBytes 注册/注册状态轮询响应体上限（R52 N2）：与快照
// 拉取同威胁模型（主节点是该链路唯一对端），这两类响应实际仅数百字节。
var maxRegistrationResponseBytes int64 = 1 << 20

// decodeSnapshotEnvelope 解码 Pull 快照响应，响应体经 maxSnapshotResponseBytes
// 限流。多读 1 字节显式探测超限（R52 N1）：LimitReader 静默截断会让超限与
// 网络截断共用「unexpected EOF」，运维无法区分主节点异常膨胀与链路故障。
func decodeSnapshotEnvelope(body io.Reader) (models.ClusterSnapshot, error) {
	raw, err := io.ReadAll(io.LimitReader(body, maxSnapshotResponseBytes+1))
	if err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("读取快照响应体: %w", err)
	}
	if int64(len(raw)) > maxSnapshotResponseBytes {
		return models.ClusterSnapshot{}, fmt.Errorf("快照响应体超过 %d 字节上限", maxSnapshotResponseBytes)
	}
	var envelope struct {
		Data models.ClusterSnapshot `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return models.ClusterSnapshot{}, err
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
	// wafRepullAttempted 标记本周期是否执行了 WAF 文件兜底全量重拉：重拉轮
	// 的 applySnapshot 会清空 last_sync_error（记录同步状态），安全数据若
	// 仍未收敛需在周期末重新上表面持续失败消息。
	wafRepullAttempted := false
	defer func() {
		if s.db != nil {
			if s.beforeRecordSyncStatus != nil {
				s.beforeRecordSyncStatus()
			}
			// 本周期 apply 成功但 Caddy 重载失败时 applySnapshot 已写入
			// apply_ok_reload_failed 标记；成功路径直接清空会让 304 分支的
			// 标记检测同周期失效。真实拉取错误仍覆盖写入。
			if err == nil && s.syncReloadFailureMarkerPresent(ctx) {
				return
			}
			// WAF 兜底重拉轮：applySnapshot 已清空 last_sync_error，但安全
			// 数据仍未收敛（计数 ≥ 阈值）——重新上表面「安全数据持续同步
			// 失败」消息，保证节点页面可见；降频期轮次由 recordSyncError
			// 的空消息守卫保持不清空。
			if err == nil && wafRepullAttempted && s.wafRepullPersistentlyFailed() {
				s.persistWafRepullFailure(ctx)
				return
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
		return SyncResult{}, errSyncMasterNoPull
	}
	if masterURL == "" || token == "" {
		return SyncResult{}, errors.New("从节点尚未完成集群审批")
	}
	// 首轮按增量版本拉取；收到 304 且本地数据与同步记录不一致时，以
	// since_version=0 重拉一次全量快照，让应用路径强制重放漂移的节。
	sinceVersion, sinceFingerprint := appliedVersion, fingerprint
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		endpoint := strings.TrimRight(masterURL, "/") + "/api/v1/cluster/sync/snapshot?since_version=" + strconv.Itoa(sinceVersion) + "&fingerprint=" + url.QueryEscape(sinceFingerprint)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return SyncResult{}, newSyncFailure(models.SyncErrorCodeValidationFailed, fmt.Errorf("创建快照请求: %w", err))
		}
		req.Header.Set("X-Cluster-Token", token)
		resp, err = s.do(req)
		if err != nil {
			code := models.SyncErrorCodeTransportError
			if errors.Is(err, errClusterPinMismatch) {
				code = models.SyncErrorCodePinMismatch
			}
			return SyncResult{}, newSyncFailure(code, fmt.Errorf("拉取主节点快照: %w", err))
		}
		if resp.StatusCode == http.StatusNotModified && attempt == 0 {
			// 上一轮应用已提交但 Caddy 重载失败：运行配置与库数据不一致，
			// 需要全量重拉以补偿重试（不能靠 304 跳过期瞒）。
			var lastSyncErr string
			if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&lastSyncErr); err == nil {
				if msg, _ := decodeSyncError(lastSyncErr); strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
					// R72 二十七次 N4：补偿重拉节流（与 WAF 兜底重拉同款）——
					// 持续失败 5 轮后降频为每 10 轮一次，避免 Caddy 持续故障时
					// 每周期全量重拉打主从负载；last_sync_error 中的 marker 保持
					// 可见（节点页面），恢复后首轮重拉成功即自愈。
					failures := s.reloadRepullFailures.Add(1)
					if failures == wafRepullMaxFailures {
						Logf("error", "同步应用后 Caddy 重载持续失败（已连续 %d 轮），补偿全量重拉降频为每 %d 轮一次", wafRepullMaxFailures, wafRepullEvery)
					}
					if failures > wafRepullMaxFailures && failures%wafRepullEvery != 0 {
						// 降频期：本轮跳过补偿重拉，走 304 返回（marker 保持可见）。
					} else {
						Logf("warn", "检测到上次同步应用后 Caddy 重载失败（%s），全量重拉补偿重试", lastSyncErr)
						RecordAuditLog("system", "同步自愈", "集群同步", FormatAuditDetail("上次应用后重载失败", "配置无变化但运行配置漂移，已改为全量拉取"), "")
						resp.Body.Close()
						sinceVersion, sinceFingerprint = 0, ""
						continue
					}
				}
			}
			if drifted := s.driftedSections(ctx); drifted != "" {
				Logf("warn", "本地数据与同步记录不一致（%s），以全量快照重新同步", drifted)
				RecordAuditLog("system", "同步自愈", "集群同步", FormatAuditDetail(fmt.Sprintf("本地数据与记录不一致：%s", drifted), "配置无变化但本地数据缺失，已改为全量拉取"), "")
				resp.Body.Close()
				sinceVersion, sinceFingerprint = 0, ""
				continue
			}
			// WAF 文件兜底（N-01）：apply 期 fetchWafFiles/ApplyWafFileBundle
			// 失败仅记日志不向上传播（cluster_apply.go），记录哈希已提交而本地
			// 文件未收敛；三节 drift 检测不含 waf_files（文件态节），必须在此
			// 显式比对，否则从节点安全数据随主节点配置静默永久分叉。兜底重拉
			// 带连续失败计数（F-1）：持续失败时上表面到 last_sync_error 并把
			// 重拉降频，避免每 60s 无限循环打主从负载。
			if s.wafFilesDrifted() {
				failures := s.wafRepullFailures.Add(1)
				if failures == wafRepullMaxFailures {
					Logf("error", "安全数据持续同步失败（已连续 %d 轮未收敛），兜底全量重拉降频为每 %d 轮一次", wafRepullMaxFailures, wafRepullEvery)
				}
				if s.wafRepullDue() {
					wafRepullAttempted = true
					Logf("warn", "本地 CRS/IP2Region 文件与同步记录不一致（上次同步安全数据失败），以全量快照重新拉取")
					RecordAuditLog("system", "同步自愈", "集群同步", FormatAuditDetail("本地安全数据文件与记录不一致", "配置无变化但安全数据文件未收敛，已改为全量拉取"), "")
					resp.Body.Close()
					sinceVersion, sinceFingerprint = 0, ""
					continue
				}
				// 持续失败降频期：本轮跳过兜底重拉（last_sync_error 已保持
				// 「安全数据持续同步失败」可见，每 wafRepullEvery 轮再尝试）。
			}
		}
		break
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return SyncResult{AppliedVersion: appliedVersion}, nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		// body 截断至 200B 并回退到合法 UTF-8 边界：错误消息经 last_sync_error
		// 落库（512B 有界设计）并随 Report 上报主节点，超长 body 会击穿有界
		// 并随 60s 周期持续膨胀主节点库（R33 F-2）。复用 pollRegistration 的
		// 既有截断模式（本文件 :1111-1113）。
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		body = truncateValidUTF8Tail(body)
		// 401/403 表示主节点已拒绝本节点凭据（节点被删除或注册被拒），
		// 重试不可能自愈：返回终止类错误，由 run 循环 halt 等待人工介入。
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return SyncResult{}, newSyncFailure(models.SyncErrorCodeValidationFailed,
				fmt.Errorf("主节点拒绝本节点访问(%d): %w", resp.StatusCode, errSyncTokenRevoked))
		}
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeTransportError, fmt.Errorf("主节点快照请求失败(%d): %s", resp.StatusCode, strings.TrimSpace(string(body))))
	}
	var envelope struct {
		Data models.ClusterSnapshot `json:"data"`
	}
	snapshotData, err := decodeSnapshotEnvelope(resp.Body)
	if err != nil {
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeValidationFailed, fmt.Errorf("解析集群快照: %w", err))
	}
	envelope.Data = snapshotData
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
		// last_sync_error 落库由下方 Pull defer 统一覆盖（err != nil 时执行，
		// 主节点节点列表经 Report 通道可见真实失败原因）：此处不再显式写，
		// 避免同一错误单周期重复 UPDATE（R32-2 收敛单写）。
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
		// R72 三十次 F4（第 40 轮审计两路独立确认，提交信息曾声称已修但从未落盘——
		// 第 3 次同类失误）：复用 errSyncPullStopped 哨兵包装——errors.Is(pullErr,
		// errSyncPullStopped) 依赖哨兵识别停机而非普通 validation 失败；此前以
		// ValidationFailed 落库会覆盖 apply_ok_reload_failed 标记（标记必须跨停机
		// 存活才能触发 304 补偿重拉）。
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeValidationFailed, errSyncPullStopped)
	}
	if err := s.applySnapshot(ctx, envelope.Data); err != nil {
		s.pullApplyMu.Unlock()
		RecordAuditLog("system", "同步失败", "集群同步", FormatAuditDetail(fmt.Sprintf("版本：%d", envelope.Data.Version), err.Error()), "")
		return SyncResult{}, newSyncFailure(models.SyncErrorCodeApplyFailed, err)
	}
	s.pullApplyMu.Unlock()
	// 每次成功应用后核对 WAF 文件态：已收敛则清零连续失败计数，恢复正常的
	// 兜底重拉频率与 last_sync_error 语义。
	s.trackWafRepullConvergence()
	s.trackReloadRepullConvergence(ctx)
	return SyncResult{AppliedVersion: envelope.Data.Version, Changed: true}, nil
}

// driftedSections 用本地数据重建节哈希，与已应用记录比对；不一致说明
// 本地数据在同步之外丢失或被改动，返回漂移节名（空串表示无漂移）。
// 仅覆盖 rules/users/security 三个纯全量替换节（见 driftGuardSections）。
// 重建必须绕过快照缓存：从节点本地写入不递增 cluster_version，命中缓存会把
// 稳态漂移永久掩盖。但漂移比对只消费三节哈希，故改用轻量 driftGuardSectionHashes
// （只重建三节 payload，不含 WAF 文件哈希与证书解析），而非全量
// clusterSnapshotBypassingCache。开关关闭的节跳过比对（镜像 computeSectionSkips
// 语义），避免「曾同步→开关关闭→本地改动」时每轮都触发全量重拉、apply 又跳过
// 该节导致的死循环。
func (s *SyncService) driftedSections(ctx context.Context) string {
	if s.cluster == nil || s.db == nil {
		return ""
	}
	local, err := s.cluster.driftGuardSectionHashes(ctx)
	if err != nil {
		Logf("warn", "本地漂移守卫哈希重建失败，跳过漂移检测: %v", err)
		return ""
	}
	applied := readAppliedSectionHashes(s.db)
	switches, err := readSyncSwitches(s.db)
	if err != nil {
		switches = SyncSwitches{GlobalConfig: true, Users: true, Rules: true, WafFiles: true, Security: true}
	}
	var drifted []string
	for _, key := range driftGuardSections {
		if !switches.sectionEnabled(key) {
			continue
		}
		if localHash := local[key]; localHash != "" && applied[key] != "" && localHash != applied[key] {
			drifted = append(drifted, key)
		}
	}
	return strings.Join(drifted, "、")
}

// wafRepullMaxFailures 定义 WAF 文件兜底重拉「连续未收敛」的阈值：达到后
// 上表面「安全数据持续同步失败」到 last_sync_error（节点页面可见），并把
// 兜底重拉降频为每 wafRepullEvery 轮一次，避免持续打主从负载。
const wafRepullMaxFailures = 5

// wafRepullEvery 是持续失败期兜底重拉的降频周期（以同步轮为单位）。
const wafRepullEvery = 10

// wafRepullDue 判定本轮 304 是否执行 WAF 文件兜底全量重拉：连续未收敛
// 达到 wafRepullMaxFailures 后降频为每 wafRepullEvery 轮一次。
func (s *SyncService) wafRepullDue() bool {
	failures := s.wafRepullFailures.Load()
	return failures <= wafRepullMaxFailures || failures%wafRepullEvery == 0
}

// wafRepullPersistentlyFailed 报告 WAF 兜底重拉是否已连续失败达到阈值。
func (s *SyncService) wafRepullPersistentlyFailed() bool {
	return s.wafRepullFailures.Load() >= wafRepullMaxFailures
}

// trackWafRepullConvergence 在快照成功应用后核对 WAF 文件态：已收敛则清零
// 连续失败计数，恢复正常兜底重拉频率与 last_sync_error 语义。仅 Pull 的
// pullMu 临界区内调用。
func (s *SyncService) trackWafRepullConvergence() {
	if !s.wafFilesDrifted() {
		s.wafRepullFailures.Store(0)
	}
}

// trackReloadRepullConvergence（R72 二十七次 N4）：快照成功应用且重载成功
// （marker 被清除）时清零补偿重拉计数。
func (s *SyncService) trackReloadRepullConvergence(ctx context.Context) {
	var lastSyncErr string
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&lastSyncErr); err != nil {
		return
	}
	if msg, _ := decodeSyncError(lastSyncErr); !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		s.reloadRepullFailures.Store(0)
	}
}

// persistWafRepullFailure 把「安全数据持续同步失败（已连续 N 轮未收敛）」上表面到
// last_sync_error（节点页面可见）。计数器兼作退避时钟，N 的语义是「自首次检测到
// 漂移起的同步轮数」而非真实重拉次数（R40 N-2）。经 combineOrReplaceSyncError 复用
// apply_ok_reload_failed 标记保护语义：TransportError 属可恢复类，标记存在
// 时组合保留，不破坏 304 补偿通道。
func (s *SyncService) persistWafRepullFailure(ctx context.Context) {
	message := fmt.Sprintf("安全数据持续同步失败（已连续 %d 轮未收敛）", s.wafRepullFailures.Load())
	s.combineOrReplaceSyncError(ctx, message, models.SyncErrorCodeTransportError)
}

// wafFilesNullRefHash 是 waf_files 节哈希的「空引用」基准：主节点侧无任何
// WAF 文件时快照 ref 为 nil，节哈希即 sha256(json(nil))==sha256("null")。
// 该值无文件态可比对，且全量重拉也无法收敛本地残留文件，必须跳过兜底检测
// 以免永久重拉循环。
var wafFilesNullRefHash = func() string {
	sum := sha256.Sum256([]byte("null"))
	return hex.EncodeToString(sum[:])
}()

// wafFilesSectionHash 以 ComputeSnapshotSectionHashes 的同一口径（sha256 of
// sectionPayloadFor("waf_files") JSON）计算本地 ref 的节哈希。本地文件与
// 已应用 ref 一致时两哈希必然相等，文件分叉时必然不等——比对口径与主节点
// 记录完全对齐。
func wafFilesSectionHash(ref *models.ClusterWafFilesRef) (string, error) {
	data, err := json.Marshal(sectionPayloadFor("waf_files", &models.ClusterSnapshot{WafFiles: ref}))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// wafFilesDrifted 报告本地 CRS/IP2Region 文件态是否与已应用的 waf_files 节
// 哈希分叉。开关关闭的节跳过比对（镜像 driftedSections 语义，防「曾同步→
// 开关关闭→本地改动」死循环）。
// R56 N-3（已接受残留）：sync_waf_files 关闭时，「降级前已启动、降级后仍在
// 后台」的 CRS/IP2Region 在途更新写入的本地文件不会被本函数兜底重拉收敛
// （开关短路），而 security 节版本行（独立开关）会被快照重放回主节点值——
// 从节点「DB 版本行=主节点版本、磁盘文件=本地更新版本」的差异将持续到开关
// 打开或主节点版本变化；期间 UI 版本显示可能与磁盘文件不一致，功能上无害
// （开关关闭语义即本地文件不受同步管辖，且文件本身更新可用）。
func (s *SyncService) wafFilesDrifted() bool {
	if s.db == nil {
		return false
	}
	switches, err := readSyncSwitches(s.db)
	if err != nil || !switches.WafFiles {
		return false
	}
	appliedHash := readAppliedSectionHashes(s.db)["waf_files"]
	if appliedHash == "" || appliedHash == wafFilesNullRefHash {
		return false
	}
	localRef := BuildWafFileRef()
	if localRef == nil {
		// 主节点有文件而本地一个都没有：必然分叉，全量重拉触发重新拉取。
		return true
	}
	localHash, err := wafFilesSectionHash(localRef)
	if err != nil {
		return false
	}
	return localHash != appliedHash
}

func (s *SyncService) beginPull() error {
	if s.beforeBeginPull != nil {
		s.beforeBeginPull()
	}
	s.pullAdmissionMu.Lock()
	defer s.pullAdmissionMu.Unlock()
	if s.pullsStopped {
		return errSyncPullStopped
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

// syncReloadFailureMarkerPrefix 标记「快照已应用但 Caddy 重载失败」：
// applySnapshot 写入，Pull 的 304 分支识别后全量重拉补偿；Pull 成功路径
// 清空 last_sync_error 前必须保留该标记到下周期。
const syncReloadFailureMarkerPrefix = "apply_ok_reload_failed"

// syncFailureCountPrefix/syncFailureCountSuffix 界定组合消息中的「连续失败计数」
// 片段：组合时只保留标记段首个失败原因 + 递增计数，消息长度因此有界，不会随
// 连续失败把整条历史追加为前缀（O(n²) 累计写入，且经 Report 上抛膨胀主节点库）。
const (
	syncFailureCountPrefix = "同步失败（已连续 "
	syncFailureCountSuffix = " 次）"
)

// syncReloadFailureMarkerPresent 报告 last_sync_error 当前是否携带重载失败标记。
// R72 三十次 F4（cluster 审计 F-2 同证）：读侧也用 WithoutCancel——Stop 的
// cancel 在 apply 提交与 defer 检查之间到达时，可取消 ctx 会读失败 → 成功清除
// defer 误判「标记不存在」→ 跳过清除 → 标记存活（正确语义）；但若标记刚被
// persistSyncError（WithoutCancel）写入，可取消读也会失败 → 误删刚写的标记。
// 与写侧（persistSyncError WithoutCancel）对齐。
func (s *SyncService) syncReloadFailureMarkerPresent(ctx context.Context) bool {
	var stored string
	if err := s.db.QueryRowContext(context.WithoutCancel(ctx), "SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		return false
	}
	msg, _ := decodeSyncError(stored)
	return strings.HasPrefix(msg, syncReloadFailureMarkerPrefix)
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
		// 停机竞态（Stop 期间 beginPull 被拒）不落库：进程即将退出，且写入
		// ValidationFailed 会覆盖重载失败标记——标记必须跨重启存活以触发首轮
		// 304 全量重拉补偿；错误本身已返回给调用方（含手动 Pull 的 API 响应）。
		if errors.Is(pullErr, errSyncPullStopped) {
			return
		}
		// 主节点手动调用 Pull 不落库：主节点无同步对象，错误只返回 API
		// 调用方；落库会让节点页面持续显示一个无自愈路径的假错误（R41 S-1）。
		if errors.Is(pullErr, errSyncMasterNoPull) {
			return
		}
		msg = "同步拉取失败: " + pullErr.Error()
		code = syncErrorCode(pullErr)
	} else if reportErr != nil {
		msg = "状态上报失败: " + reportErr.Error()
		code = models.SyncErrorCodeTransportError
	}
	if msg == "" {
		// 成功路径不得清掉 apply_ok_reload_failed 标记：它必须在下一周期
		// 304 分支触发全量重拉补偿（run 循环已在调用点跳过，此处兜底）。
		if s.syncReloadFailureMarkerPresent(ctx) {
			return
		}
		// 安全数据持续同步失败期间（连续 ≥wafRepullMaxFailures 轮未收敛）：
		// 不清空 last_sync_error，保持「安全数据持续同步失败」消息在节点
		// 页面可见（重拉轮由 Pull defer 刷新文案，此处兜底降频期轮次）。
		if s.wafRepullPersistentlyFailed() {
			return
		}
		s.persistSyncError(ctx, "", "")
		return
	}
	s.combineOrReplaceSyncError(ctx, msg, code)
}

// combineOrReplaceSyncError 是 last_sync_error 落库的共享核心：可恢复类错误
// （传输故障/主节点指纹不匹配）组合保留 apply_ok_reload_failed 标记，终止类
// 错误直接覆盖；空消息直接跳过（成功路径的清空由调用方另行处理）。
// recordSyncError、run 循环 loadState 失败路径与 pollRegistration 共用，确保
// 所有可恢复类错误走同一标记保护语义（R32-1/R32-3 收敛直写调用点）。
func (s *SyncService) combineOrReplaceSyncError(ctx context.Context, message string, code models.SyncErrorCode) {
	if message == "" {
		return
	}
	if syncErrorPreservesReloadMarker(code) {
		var stored string
		if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err == nil {
			// 可恢复类错误（传输故障/主节点指纹不匹配）不得覆盖重载失败标记：
			// 标记是全量重拉补偿的唯一触发器，覆盖后下一周期 304 将跳过补偿，
			// 陈旧运行配置保持到下次真实变更。组合只保留首个失败原因 + 计数。
			if storedMsg, _ := decodeSyncError(stored); strings.HasPrefix(storedMsg, syncReloadFailureMarkerPrefix) {
				message = combineSyncErrorWithMarker(storedMsg, message)
			}
		}
	}
	s.persistSyncError(ctx, message, code)
}

// syncErrorPreservesReloadMarker 判定错误是否属于「可恢复类」：传输故障与主节点
// 指纹不匹配都是网络/主节点侧的临时问题，下一周期可能恢复并返回 304；此时重载
// 失败标记必须保留。终止类错误（schema 版本不匹配、签名无效、令牌撤销、校验/
// 应用失败）允许覆盖：它们要么让 run 循环 halt 等待人工介入，要么已失去补偿意义。
func syncErrorPreservesReloadMarker(code models.SyncErrorCode) bool {
	return code == models.SyncErrorCodeTransportError || code == models.SyncErrorCodePinMismatch
}

// combineSyncErrorWithMarker 在重载失败标记上追加新的可恢复类错误：标记段只保留
// 首个失败原因（按 " | " 切分取第一段，丢弃历史累加的传输错误部分），传输错误以
// 「已连续 N 次」计数表示（旧消息已含计数则递增），消息长度因此有界。
func combineSyncErrorWithMarker(storedMsg, newMsg string) string {
	markerSegment := storedMsg
	if idx := strings.Index(storedMsg, " | "); idx >= 0 {
		markerSegment = storedMsg[:idx]
	}
	reason := strings.TrimSpace(strings.TrimPrefix(markerSegment, syncReloadFailureMarkerPrefix))
	reason = strings.TrimSpace(strings.TrimPrefix(reason, ":"))
	count := syncFailureCountIn(storedMsg) + 1
	return syncReloadFailureMarkerPrefix + ": " + reason + " | " + syncFailureCountPrefix + strconv.Itoa(count) + syncFailureCountSuffix + ": " + newMsg
}

// syncFailureCountIn 从旧消息解析「已连续 N 次」计数；消息不含计数片段时返回 0。
func syncFailureCountIn(message string) int {
	start := strings.Index(message, syncFailureCountPrefix)
	if start < 0 {
		return 0
	}
	digits := message[start+len(syncFailureCountPrefix):]
	end := strings.Index(digits, syncFailureCountSuffix)
	if end < 0 {
		return 0
	}
	count, err := strconv.Atoi(strings.TrimSpace(digits[:end]))
	if err != nil || count < 0 {
		return 0
	}
	return count
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
	// R72 二十六次 W1-4：v2 形态旧主节点快照（有签名、无 canonical_payload）此前
	// 落入 verifySnapshotSignature 的空载荷拒绝，误报「签名校验失败」且提示语不
	// 指明升级动作。刻意保持非终止（可重试）而非恢复 Round 30 F6 的 halted 终止：
	// ① 该形态无法在本节点验签（v2 扁平签名路径已于 R35 S-11 移除），终止化会让
	// 任何能注入同步流量的攻击者用伪造 schema<3 载荷把从节点永久停摆；② 非终止
	// 重试在主节点升级到 v3 后自动恢复，运维代价更低。原 R30 F6 分支因验签前置
	// 不可达（S-11 收紧误伤），已移除。
	if snapshot.SchemaVersion < CurrentSnapshotSchema && len(snapshot.CanonicalPayload) == 0 {
		return models.ClusterSnapshot{}, newSyncFailure(models.SyncErrorCodeSignatureInvalid, errors.New("主节点为旧版本（schema v2 快照形态，缺少 canonical_payload）：请先升级主节点，从节点将在主节点升级后自动恢复同步"))
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
			// 瞬时 DB 读错（SQLITE_BUSY 等）属可恢复类：直接覆盖会抹掉
			// apply_ok_reload_failed 标记（304 全量重拉补偿的唯一触发器），
			// 改走共享组合保留逻辑（R32-1）。
			s.combineOrReplaceSyncError(ctx, message, models.SyncErrorCodeTransportError)
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
			// 304「配置无变化」是稳态事件，不留审计（曾按周期刷屏，R24 移除）；
			// 有意义的状态跃迁（漂移自愈、失败）仍在各自路径留痕。
			_, pullErr := s.Pull(ctx)
			var schemaTooNew *SnapshotSchemaTooNewError
			var schemaTooOld *SnapshotSchemaTooOldError
			terminal := errors.As(pullErr, &schemaTooNew) || errors.As(pullErr, &schemaTooOld)
			if terminal || errors.Is(pullErr, errSyncTokenRevoked) {
				s.state.Store(uint32(syncStateHalted))
			}
			if errors.Is(pullErr, errSyncTokenRevoked) {
				// 主节点已撤销本节点令牌：上报必然再次被拒，跳过 Report
				// 直接终止（错误已由 Pull 落库），等待人工重新注册或提升为主节点。
				return
			}
			reportErr := s.Report(ctx)
			// 本周期 apply 成功但 Caddy 重载失败时 Pull 已落库 apply_ok_reload_failed
			// 标记（Pull defer 为此保留它）；周期末的空错误清空会让 304 分支的
			// 标记检测同周期失效，自愈补偿永远不触发。与 Pull defer 同口径跳过。
			// pullErr 非空时 Pull 内部 defer 已按错误分类落库（含快照完整性失败，
			// R32-2 收敛单写），周期末不再重复写；reportErr 仅在 pullErr 为空时
			// 参与落库，此处跳过无信息损失。
			if pullErr == nil {
				if reportErr != nil || !s.syncReloadFailureMarkerPresent(ctx) {
					s.recordSyncError(ctx, nil, reportErr)
				}
			}
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
		// 存量脏数据兜底：R42 前 sync_interval 无下限校验，库里可能残留 0/负数
		// 或校验下限（10s）以下的值（含被主节点经快照原样下发的存量 1-9s），
		// time.NewTimer(<=0) 会立即触发导致零间隔 Pull 风暴，1-9s 同样是 R42
		// 要消除的高频 Pull；clamp 到 60s，下限与 UpdateSettings 校验一致（R43 A-1）。
		if interval < 10 {
			interval = 60
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
	// R69 A-N1：DB 读取失败与「未处于注册态」（字段为空）拆分——前者静默返回
	// 会在持续性本地 DB 故障期间零留痕（状态面与日志均无信号）；行为不变
	//（下周期照常重试），仅补日志。
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(master_url,''), COALESCE(registration_id,0), COALESCE(registration_secret,'') FROM global_config WHERE id=1").Scan(&masterURL, &registrationID, &secret); err != nil {
		log.Printf("注册状态轮询：读取 global_config 失败，本周期跳过: %v", err)
		return
	}
	if masterURL == "" || registrationID == 0 || secret == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/cluster/register/%d/status", strings.TrimRight(masterURL, "/"), registrationID), nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Registration-Secret", secret)
	resp, err := s.do(req)
	if err != nil {
		// 主节点 5xx/网络故障在注册轮询期同样要可见（否则节点页显示正常但一直
		// 注册中）；随 401/404/410 走同一 persistSyncError 通道。
		message := "查询注册状态失败: " + err.Error()
		s.combineOrReplaceSyncError(ctx, message, models.SyncErrorCodeTransportError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
			message := "注册已被主节点拒绝或移除，请重新注册或提升为主节点"
			// R64 A-N6：状态轮询的 401/404/410 复用 confirm 路径的 5 连败终止设计
			// （bumpRegistrationConfirmFailure）——此前该分支每 10s 无限重试：每周期
			// 一条「注册失败」审计日志（~8640 条/天噪音）且永不退出注册循环；
			// 达到上限后落终止文案并清 registration_*（退出循环），运维提示与
			// confirm 路径一致。1-4 次期间 last_sync_error 持续显示可行动文案
			// （combineOrReplaceSyncError 幂等覆盖），审计留痕收敛到终止时一条。
			s.bumpRegistrationConfirmFailure(ctx, "", fmt.Sprintf("注册状态轮询被主节点拒绝（HTTP %d）", resp.StatusCode))
			s.combineOrReplaceSyncError(ctx, message, models.SyncErrorCodeValidationFailed)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		body = truncateValidUTF8Tail(body)
		message := fmt.Sprintf("查询注册状态失败（主节点返回 %d）：%s", resp.StatusCode, strings.TrimSpace(string(body)))
		s.combineOrReplaceSyncError(ctx, message, models.SyncErrorCodeTransportError)
		return
	}
	var envelope struct {
		Data models.ClusterRegistrationStatus `json:"data"`
	}
	// R68 A-N1：decode 失败（主节点 200 但 body 非 envelope——反代错误页/网关维护
	// 页等）此前静默 return，节点零留痕轮询、表面状态不变；仅记日志不改状态机
	// 行为（下周期照常重试，≥400 与 rejected 分支已有各自可观测动作）。
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRegistrationResponseBytes)).Decode(&envelope); err != nil {
		log.Printf("注册状态轮询响应解析失败（HTTP %d，主节点可能被前置代理替换响应）: %v", resp.StatusCode, err)
		return
	}
	if envelope.Data.Status == "rejected" {
		// R67 A-N1：200 "rejected" 出现于「registrationAuth 通过后、RegistrationStatus
		// 事务 SELECT 前节点行被删」的交错窗口（单发瞬态，下一轮即 401 走 R64 A-N6
		// 终止轨道）。显式处理消除该轮的无痕迹轮询并给出准确文案（否则 401 轨道
		// 的文案会误报为「HTTP 401 被拒绝」）。
		s.bumpRegistrationConfirmFailure(ctx, "", "主节点已拒绝该注册（节点记录不存在）")
		s.combineOrReplaceSyncError(ctx, "注册已被主节点拒绝，请重新注册或提升为主节点", models.SyncErrorCodeValidationFailed)
		return
	}
	if envelope.Data.Status == "approved" && envelope.Data.ClusterToken != "" {
		// R67 A-N3：令牌落库先于 confirm——主节点 confirm 成功即消费
		// registration_secret（cluster_snapshot.go ConfirmRegistration 置 NULL），
		// 若本地令牌 UPDATE 在 confirm 之后瞬时失败（SQLITE_BUSY/进程退出），
		// 下周期以已消费的 secret 轮询 → 401 五连败 → 以「被拒绝/移除」的
		// 误导文案清空注册态，需人工重新注册。前置落库后失败面收敛为「多一次
		// confirm 请求」或「confirm 失败走 bump 轨道」，轨道自愈。令牌在主节点
		// 审批时刻即有效（Pull 鉴权只查 cluster_token_hash），confirm 仅是冗余
		// 交付确认（首个签名快照亦会清 secret），前置无安全影响。
		if _, err := s.db.ExecContext(ctx, "UPDATE global_config SET cluster_token=?, registration_secret='' WHERE id=1", envelope.Data.ClusterToken); err != nil {
			log.Printf("保存集群令牌失败（下周期重试状态轮询）: %v", err)
			return
		}
		confirm, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(masterURL, "/")+"/api/v1/cluster/registration/confirm", nil)
		if err != nil {
			return
		}
		confirm.Header.Set("X-Cluster-Token", envelope.Data.ClusterToken)
		confirmed, err := s.do(confirm)
		if err != nil {
			s.bumpRegistrationConfirmFailure(ctx, envelope.Data.ClusterToken, "confirm 端点网络错误: "+err.Error())
			return
		}
		defer confirmed.Body.Close()
		// Round 35 S-12: 移除 404/405 fallback 兼容（v2.0.9+ 主节点均支持 confirm 端点）。
		// Round 36 I-6: 任何 4xx/5xx 不再静默重试。累计失败达到上限后停止注册循环，
		// 持久化错误并提示用户人工处理（在 UI 重新注册或提升为主节点）。
		if confirmed.StatusCode >= http.StatusBadRequest {
			// Round 34 F-R34-2: 与 F-2 模式一致——200B 截断 + UTF-8 边界回退，
			// 确保 confirm 失败原因落入 last_sync_error 后不超过 512B 有界设计。
			body, _ := io.ReadAll(io.LimitReader(confirmed.Body, 200))
			body = truncateValidUTF8Tail(body)
			s.bumpRegistrationConfirmFailure(ctx, envelope.Data.ClusterToken,
				fmt.Sprintf("confirm 端点返回 %d（%s）。主节点可能版本过旧或 confirm 端点异常，请在集群管理页面重新注册或提升为主节点",
					confirmed.StatusCode, strings.TrimSpace(string(body))))
			return
		}
		s.resetRegistrationConfirmFailure(ctx)
	}
}

// ForgetClusterPins 清空内存 TOFU pin 缓存（R67 A-N2）。提升为主节点时
// cleanupClusterPin 已删除 pin 文件，但本 map 不清则残留旧主节点指纹：本节点
// 重新成为从节点且新主节点恰在同一 host:port 换发证书时，do() 会以内存指纹
// 重新落盘 pin 文件（cluster_sync.go verifyOrStoreClusterPin 回写路径）并使
// 每次握手指纹比对恒失败——运维删 pin 文件也被写回，仅进程重启可解。提升后
// 调用使 TOFU 生命周期与 pin 文件侧对齐（新拓扑重新 TOFU）。
func (s *SyncService) ForgetClusterPins() {
	s.pinMu.Lock()
	s.verifiedPins = make(map[string]string)
	s.pinMu.Unlock()
}

// registrationConfirmMaxFailures 定义 confirm 端点连续失败上限。达到后停止注册循环。
const registrationConfirmMaxFailures = 5

// bumpRegistrationConfirmFailure 累计 confirm 失败次数。达到上限后清除 registration_secret，
// 让从节点脱离注册状态，并通过 persistSyncError 提示运维人工介入。
func (s *SyncService) bumpRegistrationConfirmFailure(ctx context.Context, clusterToken, reason string) {
	_, err := s.db.ExecContext(ctx,
		"UPDATE global_config SET registration_confirm_failures = COALESCE(registration_confirm_failures, 0) + 1 WHERE id=1")
	if err != nil {
		log.Printf("bumpRegistrationConfirmFailure: update failed: %v", err)
	}
	var failures int
	if qerr := s.db.QueryRowContext(ctx, "SELECT COALESCE(registration_confirm_failures, 0) FROM global_config WHERE id=1").Scan(&failures); qerr != nil {
		failures = registrationConfirmMaxFailures
	}
	if failures >= registrationConfirmMaxFailures {
		message := fmt.Sprintf("集群注册确认连续失败 %d 次（最后一次：%s）。已停止自动重试，请在“集群管理”页面重新注册，或使用“提升为主节点”脱离集群",
			failures, reason)
		// 经 combineOrReplaceSyncError 落库（R33 F-1）：ValidationFailed 属终止类，
		// helper 直接覆盖，与直写语义等价；闭合「所有写点经 helper」不变式。
		s.combineOrReplaceSyncError(ctx, message, models.SyncErrorCodeValidationFailed)
		RecordAuditLog("system", "注册失败", "集群节点", message, "")
		// 清除 registration_secret 触发从节点退出注册循环；clusterToken 已存入 global_config 但因 confirm 未成功，主节点未真正确认
		if _, derr := s.db.ExecContext(ctx, "UPDATE global_config SET registration_secret='', registration_id=NULL, registration_confirm_failures=0 WHERE id=1"); derr != nil {
			log.Printf("bumpRegistrationConfirmFailure: clear registration state failed: %v", derr)
		}
		if clusterToken != "" {
			_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET cluster_token='' WHERE id=1")
		}
	} else {
		log.Printf("集群注册确认失败 %d/%d：%s", failures, registrationConfirmMaxFailures, reason)
	}
}

// resetRegistrationConfirmFailure 在 confirm 成功后清零失败计数。
func (s *SyncService) resetRegistrationConfirmFailure(ctx context.Context) {
	_, _ = s.db.ExecContext(ctx, "UPDATE global_config SET registration_confirm_failures=0 WHERE id=1")
}
