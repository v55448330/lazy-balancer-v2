package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/models"
)

var (
	ErrInvalidRegisterToken = errors.New("注册令牌无效或已过期")
	ErrNodeNotFound         = errors.New("节点不存在")
	ErrInvalidClusterAuth   = errors.New("集群凭证无效")
	// ErrNodeNotPending(CL40-C1-3):审批/拒绝动作命中非 pending 状态的节点
	// (重复审批/已处理)——handler 侧映射 409。
	ErrNodeNotPending      = errors.New("节点不在待审批状态")
	ErrAlreadyMaster       = errors.New("当前节点已是主节点")
	ErrInvalidSyncInterval = errors.New("同步间隔需在 10-86400 秒之间")
	// ErrSyncUsersLocked 系统数据恒同步不可禁用(SR9-1:handler 映射 400)。
	ErrSyncUsersLocked = errors.New("系统数据为恒同步项（含用户/密钥/ACME），不允许禁用；证书随负载规则开关")
)

type ClusterService struct {
	db *sql.DB
	// dataDir 用于品牌镜像(branding.json)与未来文件态同步的本地路径。
	dataDir              string
	roleMu               sync.Mutex
	pinCleanupMu         sync.Mutex
	pendingPinPath       string
	pendingPinAuditURL   string
	beforeUpdateSettings func()
	snapshotNow          func() time.Time
	// sectionReports 缓存各从节点最近一次上报的分区哈希（ReportNode 写入、
	// DeleteNode 清除、Nodes 聚合读取）。与 nodes 表的 health_json 同为内存态：
	// 进程重启后随从节点下一次上报（≤60s）自动重建。
	sectionMu      sync.Mutex
	sectionReports map[int]map[string]string
}

func NewClusterService(database *sql.DB, dataDir string) *ClusterService {
	return &ClusterService{db: database, dataDir: dataDir, snapshotNow: time.Now, sectionReports: make(map[int]map[string]string)}
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
	// A-M2 令牌卫生：生成新令牌前作废所有未使用令牌（一次性语义——重新生成即让旧令牌
	// 失效），并顺带删除已过期记录（GC），避免令牌表无限增长、旧令牌残留可复用。
	if _, err := s.db.ExecContext(ctx, `DELETE FROM cluster_register_tokens WHERE used_at IS NULL OR expires_at < ?`, now.UTC()); err != nil {
		return "", time.Time{}, fmt.Errorf("清理旧注册令牌: %w", err)
	}
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
	if err := models.ValidateClusterAccessURL(req.AccessURL); err != nil {
		return models.ClusterRegistration{}, err
	}
	if req.Port == 0 {
		req.Port = 8000
	}
	if req.Protocol == "" {
		req.Protocol = "http"
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
	var overwrittenNodeID int
	var overwrittenNodeName string
	err = tx.QueryRowContext(ctx, "SELECT id FROM nodes WHERE ip_address=? AND port=?", req.IPAddress, req.Port).Scan(&nodeID)
	switch {
	case err == nil:
		// L02-03（RG-CLUSTER-NODE-IDENTITY）：命中既有行=upsert（保留重复注册/
		// 重试的兼容路径），但若该行已批准，重置审批与令牌等于静默覆盖一个在运
		// 节点——响应与审计必须点名被覆盖节点。协议不新增 replace 参数：旧从节点
		// 重试注册不携带该标志，强制 409 会让滚动升级期重试永久失败。
		var existingName string
		var existingApproved bool
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(name,''), COALESCE(is_approved,0) FROM nodes WHERE id=?", nodeID).Scan(&existingName, &existingApproved); err != nil {
			return models.ClusterRegistration{}, fmt.Errorf("读取既有节点: %w", err)
		}
		if existingApproved {
			overwrittenNodeID = nodeID
			overwrittenNodeName = existingName
		}
		// CL23-1(第 23 轮审计):access_url 是管理员配置态——重新注册不携带
		// (cluster_mode.go:49-51 恒空)时保留存量,不静默清空。
		_, err = tx.ExecContext(ctx, `UPDATE nodes SET name=?, protocol=?, access_url=COALESCE(NULLIF(?,''),access_url), status='pending', is_approved=0, registration_secret=?, registration_secret_expires_at=NULL, cluster_token_hash=NULL, cluster_token_delivered=0, reported_version=0, health_json=NULL, last_seen=NULL WHERE id=?`, req.Name, req.Protocol, req.AccessURL, tokenHash(secret), nodeID)
	case errors.Is(err, sql.ErrNoRows):
		insert, insertErr := tx.ExecContext(ctx, `INSERT INTO nodes (name, mode, ip_address, port, protocol, access_url, status, is_approved, registration_secret) VALUES (?, 'slave', ?, ?, ?, ?, 'pending', 0, ?)`, req.Name, req.IPAddress, req.Port, req.Protocol, req.AccessURL, tokenHash(secret))
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
	return models.ClusterRegistration{RegistrationID: nodeID, RegistrationSecret: secret, OverwrittenNodeID: overwrittenNodeID, OverwrittenNodeName: overwrittenNodeName}, nil
}

func (s *ClusterService) UpdateNodeAccessURL(ctx context.Context, nodeID int, accessURL string) error {
	if err := models.ValidateClusterAccessURL(accessURL); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, "UPDATE nodes SET access_url=? WHERE id=?", accessURL, nodeID)
	if err != nil {
		return fmt.Errorf("更新节点访问地址: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取节点访问地址更新结果: %w", err)
	}
	if updated != 1 {
		return ErrNodeNotFound
	}
	return nil
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
		// CL40-C1-3:0 行命中分判——节点存在但非 pending(重复审批/已拒绝)
		// 返回 409 语义错误;不存在维持 404。
		var status string
		var secret sql.NullString
		if err := s.db.QueryRowContext(ctx, "SELECT status, registration_secret FROM nodes WHERE id=?", nodeID).Scan(&status, &secret); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNodeNotFound
			}
			return fmt.Errorf("回查节点状态: %w", err)
		}
		return fmt.Errorf("%w: 当前状态 %s", ErrNodeNotPending, status)
	}
	return nil
}

// RegistrationStatus 的 now 参数注入同域惯例(CL10-N17:原为唯一用真实时钟
// 的集群方法,24h 到期边界无法确定性测试)。
func (s *ClusterService) RegistrationStatus(ctx context.Context, nodeID int, secret string, now time.Time) (models.ClusterRegistrationStatus, error) {
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
	// CL41-5(第 41 轮):哈希比对改常量时间——与 HMAC 链路的 hmac.Equal 同口径。
	if storedSecretHash == "" || subtle.ConstantTimeCompare([]byte(storedSecretHash), []byte(tokenHash(secret))) != 1 || (secretExpiresAt.Valid && !secretExpiresAt.Time.After(now)) {
		return models.ClusterRegistrationStatus{}, ErrInvalidClusterAuth
	}
	response := models.ClusterRegistrationStatus{Status: "pending"}
	if approved {
		response.Status = "approved"
		clusterToken := permanentClusterToken(secret)
		// 注意：registration_secret 在此保留，直到从节点首次 Snapshot 请求时由
		// cluster_snapshot.go 的 Snapshot() 清除。这是有意设计：从节点可能在收到
		// token 前遭遇网络问题，需要重复调用 RegistrationStatus 重新获取同一 token。
		// 详见 TestClusterService_ApproveNode_redelivers_cluster_token_until_confirmed。
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
	var masterURL string
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(master_url,'') FROM global_config WHERE id=1").Scan(&masterURL); err != nil {
		return fmt.Errorf("读取旧主节点地址: %w", err)
	}
	te := TaskEngine()
	clusterSyncWasOn := false
	if te != nil {
		if meta, ok := te.Lookup("cluster-sync"); ok {
			clusterSyncWasOn = meta.LoopOn
		}
		if clusterSyncWasOn {
			te.StopLoop("cluster-sync")
		}
	}
	promoted := false
	defer func() {
		if !promoted && te != nil && clusterSyncWasOn {
			te.StartLoop("cluster-sync")
		}
	}()
	// L02-01（RG-CLUSTER-PROMOTE-DRAIN）：engine.StopLoop 只取消 daemon ctx，
	// daemon 的 Stop 在另一 goroutine 异步执行——不显式排干则在途拉取（含已
	// 通过 admission 的 apply）可能在升主提交后继续把从节点数据写回库。
	// 排干失败（ctx 到期）即中止提升，不做半程角色翻转。
	if drainer := syncDrainerFor(s.db); drainer != nil {
		if err := drainer.DrainPulls(ctx); err != nil {
			return fmt.Errorf("等待在途同步拉取结束: %w", err)
		}
	}
	var registrationID int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(registration_id,0) FROM global_config WHERE id=1").Scan(&registrationID); err != nil {
		return fmt.Errorf("读取注册编号: %w", err)
	}
	var oldToken string
	// CL44-1（第 44 轮审计）：旧令牌仅用于提升成功后的脱离通知（best-effort），
	// 读取失败不阻断提升，但须留痕——与上下文显式错误处理对齐，不再静默吞错。
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(cluster_token,'') FROM global_config WHERE id=1").Scan(&oldToken); err != nil {
		Logf("info", "Promote: 读取旧集群令牌失败，提升后的旧主节点脱离通知将跳过: %v", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始提升事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// 与 BecomeSlave 的反向清理对称：提升时同步清空从节点的同步残留
	//（applied_version/sync_fingerprint/last_sync_error/注册确认失败计数），
	// 避免新主节点带着旧集群的同步指纹与错误状态运行。
	// CL42-4（第 42 轮审计裁定·设计声明）：nodes 表（含各从节点
	// cluster_token_hash）跨角色切换刻意保留——Promote/BecomeSlave 均只重置
	// global_config，从不清空 nodes。拓扑连续性语义：脱离通知
	// （notifyMasterDetach）只是 best-effort，旧主节点令牌撤销依赖其成功；
	// 本节点降级后再提升时，旧 nodes 行即刻恢复权威，旧从节点持有的令牌
	// 仍然有效，经手工 Resume/重新注册即可复活上报与同步——这是有意设计
	// （主库清零后可凭从库副本恢复集群拓扑），不是令牌泄漏缺口。
	if _, err := tx.ExecContext(ctx, `UPDATE global_config SET is_master=1, master_url='', cluster_token='', registration_id=0, registration_secret='', applied_version=0, sync_fingerprint='', last_sync_error='', registration_confirm_failures=0 WHERE id=1`); err != nil {
		return fmt.Errorf("重置主节点状态: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交提升事务: %w", err)
	}
	promoted = true
	ResetConfigDrift()

	if registrationID > 0 {
		RecordAuditLog("system", "提升完成", "集群节点", FormatAuditDetail(fmt.Sprintf("注册编号：%d", registrationID), "本节点已脱离集群并提升为主节点", AuditResultPart("success")), "")
	}
	// 自动备份：v2.0 引擎 Scheduled 驱动（RunsOn=MasterOnly 角色门）——
	// promote 后由引擎 SetRole 使能，无需单独拉起。
	// 角色翻转由引擎 SetRole 唯一驱动：cert-issuance/cluster-sync 经 daemon
	// 生命周期挂钩启停，不再存在管理器直调或旧调度器旁路。
	if te != nil {
		te.SetRole(true)
		if clusterSyncWasOn {
			te.StartLoop("cluster-sync")
		}
	}
	// 升主后按库实态统一恢复六个业务驱动任务，而非只恢复 autoban。
	SyncBusinessTaskDrivers()
	if masterURL != "" {
		parsedMasterURL, err := url.Parse(masterURL)
		if err != nil {
			Logf("info", "parse old cluster master URL after promotion: %v", err)
			RecordAuditLog("system", "清理失败", "证书指纹", FormatAuditDetail("旧主节点地址无效", err.Error()), "")
			// 地址损坏时无法定位旧主节点 pin 文件——磁盘残留为已知边界
			// （第 56 轮 F56B2-4 如实化）：残留仅在该 host:port 将来重新注册
			// 为从节点时引发一次 PinMismatch，forget-pins 可恢复。
			return nil
		}
		pinPath, err := clusterPinPathForDatabase(s.db, parsedMasterURL.Host)
		if err != nil {
			Logf("info", "locate old cluster master pin after promotion: %v", err)
			RecordAuditLog("system", "清理失败", "证书指纹", FormatAuditDetail("旧主节点："+parsedMasterURL.Scheme+"://"+parsedMasterURL.Host, err.Error()), "")
			// 同上：pin 路径定位失败，磁盘清理不可达，残留边界已知。
			return nil
		}
		// 先读取已知指纹，再清理并通知：脱离通知的 transport 按连接读取 pin 文件
		//（TOFU 会在文件缺失时重新写回），必须在清理前取出指纹并让通知"仅比对
		// 不落盘"，否则通知握手晚于清理会把旧主节点指纹重新写回、再次信任已脱离
		// 的节点。
		pinFingerprint := ""
		if content, readErr := os.ReadFile(pinPath); readErr == nil {
			pinFingerprint = strings.TrimSpace(string(content))
		}
		if oldToken != "" {
			// 通知旧主节点该从节点已脱离（best-effort：失败不阻断提升，主节点
			// 会在上报超时后将其标记下线；成功则主节点节点列表立即更新并留痕）。
			go notifyMasterDetach(context.WithoutCancel(ctx), masterURL, oldToken, pinFingerprint)
		}
		s.cleanupClusterPin(pinPath, parsedMasterURL.Scheme+"://"+parsedMasterURL.Host)
	}
	return nil
}

func (s *ClusterService) cleanupClusterPin(pinPath, auditURL string) {
	s.pinCleanupMu.Lock()
	defer s.pinCleanupMu.Unlock()
	if err := os.Remove(pinPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// CL21-3(第 21 轮审计):pin 文件本就不存在(HTTP 注册从节点提升
			// 恒现——从未写过 pin)记「清理成功」审计是假阳性,跳过;
			// pending 状态仍清空(无遗留需重试)。
			s.pendingPinPath = ""
			s.pendingPinAuditURL = ""
			return
		}
		s.pendingPinPath = pinPath
		s.pendingPinAuditURL = auditURL
		Logf("info", "cluster pin cleanup deferred: %v", err)
		RecordAuditLog("system", "清理失败", "证书指纹", FormatAuditDetail("旧主节点："+auditURL, err.Error()), "")
		return
	}
	s.pendingPinPath = ""
	s.pendingPinAuditURL = ""
	RecordAuditLog("system", "清理", "证书指纹", FormatAuditDetail("旧主节点："+auditURL, AuditResultPart("success")), "")
}

func (s *ClusterService) retryPendingPinCleanup() {
	s.pinCleanupMu.Lock()
	pinPath := s.pendingPinPath
	auditURL := s.pendingPinAuditURL
	s.pinCleanupMu.Unlock()
	if pinPath != "" {
		s.cleanupClusterPin(pinPath, auditURL)
	}
}

// nodeOfflineMultiplier 判定节点离线时 last_seen 的允许超时倍率（× sync_interval 秒）。
// MetricsService.updateOverview 的在线节点统计口径必须与此一致，共用本常量，
// 避免阈值在两处各自硬编码导致口径漂移。
const nodeOfflineMultiplier = 2

// nodeOfflineThreshold 节点离线阈值的统一口径（F-L2-68-02，第 68 轮审计）：
// max(nodeOfflineMultiplier×sync_interval, masterSyncOfflineThreshold 下限)。
// 存量脏值（R42 前残留的 0/负数或 1-9s）按 60s 计，与从节点 run loop
// （cluster_sync.go）的 clamp 值一致：从节点实际以 60s 周期上报，若按原始脏值
// （或 10s）计算阈值，会把两次上报之间的正常从节点误判为离线（R44-1）。
// ComputeNodeStatus（节点列表/登录票据）、updateOverview（总览在线数）与
// masterSyncServingRound（巡检）共用本函数——此前巡检侧 max(2×global,120s) 而
// UI 侧仅 2×clamp(sync_interval)，sync_interval∈[10,59] 时两口径分叉
// （interval=30：巡检 120s 判在线、UI 60s 判离线）。
func nodeOfflineThreshold(syncInterval int) time.Duration {
	if syncInterval < 10 {
		syncInterval = 60
	}
	threshold := time.Duration(nodeOfflineMultiplier*syncInterval) * time.Second
	if threshold < masterSyncOfflineThreshold {
		threshold = masterSyncOfflineThreshold
	}
	return threshold
}

func ComputeNodeStatus(approved bool, lastSeen time.Time, syncInterval int, now time.Time) string {
	if !approved {
		return "pending"
	}
	// 阈值口径集中在 nodeOfflineThreshold（F-L2-68-02）：脏值 clamp 与 120s 下限
	// 与巡检/总览同函数，UI 不再各自维护一套。
	if lastSeen.IsZero() || now.Sub(lastSeen) > nodeOfflineThreshold(syncInterval) {
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

// notifyMasterDetach best-effort 通知旧主节点本从节点已提升脱离。提升后本节点仍持有
// 旧集群令牌，且旧主节点仍保留本节点行与该令牌哈希，旧令牌在主节点上仍能验签通过，
// 因此携带 detached=true 的上报会令主节点删除本节点行（令牌随之撤销），节点列表即时收敛；
// 客户端仅用已知指纹比对（不落盘），避免清理后的 pin 文件被 TOFU 重新写回；超时 3 秒
// 失败仅记录不阻断提升。
func notifyMasterDetach(ctx context.Context, masterURL, token, expectedPin string) {
	report := models.ClusterReport{ServiceStatus: "ok", Detached: true}
	payload, err := json.Marshal(report)
	if err != nil {
		return
	}
	endpoint := strings.TrimRight(masterURL, "/") + "/api/v1/cluster/nodes/report"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cluster-Token", token)
	client := &http.Client{Timeout: 3 * time.Second, Transport: newClusterDetachTransport(expectedPin)}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// CL42-2（第 42 轮审计）：旧主节点启用管理 HTTPS 后明文端口 301——按集群
	// 同步同一契约对同主机 https Location 重放一次，否则脱离通知永远到不了。
	resp, err := DoWithSameHostTLSUpgradeRedirect(client, req)
	if err != nil {
		Logf("error", "cluster detach notify failed: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		Logf("info", "cluster detach notify rejected: %d", resp.StatusCode)
	}
}
