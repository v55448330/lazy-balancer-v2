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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

var (
	ErrInvalidRegisterToken = errors.New("注册令牌无效或已过期")
	ErrNodeNotFound         = errors.New("节点不存在")
	ErrInvalidClusterAuth   = errors.New("集群凭证无效")
	// ErrNodeNotPending:审批/拒绝动作命中非 pending 状态的节点
	// (重复审批/已处理)——handler 侧映射 409。
	ErrNodeNotPending = errors.New("节点不在待审批状态")
	ErrAlreadyMaster  = errors.New("当前节点已是主节点")
	// ErrNotMasterNode：请求已通过 handler 角色门，但在节点簿记
	// 写语句执行前角色已降级（TOCTOU）。handler 应映射 403，与 requireMaster
	// 同文案。
	ErrNotMasterNode       = errors.New("该操作仅允许在主节点执行")
	ErrInvalidSyncInterval = errors.New("同步间隔需在 10-86400 秒之间")
	// ErrSyncUsersLocked 系统数据恒同步不可禁用。
	ErrSyncUsersLocked = errors.New("系统数据为恒同步项（含用户/密钥/ACME），不允许禁用；证书随负载规则开关")
)

// ClusterTokenInvalidErrorCode 是集群令牌拒绝（401）的机器可读错误码。
// 从节点 Pull 只能凭它把「本服务撤销令牌」与「主节点前置代理/身份网关
// 返回 401」区分开：前者终止等待人工介入，后者可重试自愈。
const ClusterTokenInvalidErrorCode = "cluster_token_invalid"

type ClusterService struct {
	db *sql.DB
	// dataDir 用于品牌镜像(branding.json)与未来文件态同步的本地路径。
	dataDir      string
	roleMu       sync.Mutex
	pinCleanupMu sync.Mutex
	// pendingPins 是「pin 清理失败、待重试」的表（pin 路径 → 旧主节点审计地址）。
	// 单槽实现会在第二次清理失败时覆盖先前的待重试项：那枚 pin 文件从此既无
	// 重试也不再留痕，只能人工删盘。同一路径重复失败保留原审计地址（同一 pin
	// 对应同一旧主节点）。
	pendingPins map[string]string
	// pinCleanupFailureKeys 是逐路径的失败审计去重键（pin 路径 → 路径+错误
	// 文本）：失败后 retryPendingPinCleanup 每个快照/巡检周期都会重试，同一
	// 失败（权限/只读目录）稳定复现时只应留一条审计，恢复成功时清空。
	pinCleanupFailureKeys map[string]string
	beforeUpdateSettings  func()
	snapshotNow           func() time.Time
	// sectionReports 缓存各从节点最近一次上报的分区哈希（ReportNode 写入、
	// DeleteNode 清除、Nodes 聚合读取）。与 nodes 表的 health_json 同为内存态：
	// 进程重启后随从节点下一次上报（≤60s）自动重建。
	sectionMu      sync.Mutex
	sectionReports map[int]map[string]string
}

func NewClusterService(database *sql.DB, dataDir string) *ClusterService {
	service := &ClusterService{db: database, dataDir: dataDir, snapshotNow: time.Now, sectionReports: make(map[int]map[string]string)}
	registerClusterService(service)
	return service
}

// clusterHandleRegistry 是按数据库句柄登记同类集群实例的通用表：
// 用 *sql.DB 作键隔离测试实例（每个夹具独立库）；同一库可登记多个实例
// （逐个处理而不依赖构造顺序）；显式注销优先，残留的死句柄条目由
// probeClusterDBHandle 在查表路径兜底剔除（库已 Close/连接已丢），探活超时
// 或瞬时错误只保留条目——误删会让排干面/pin 清理链静默断裂。
// 集群服务表与同步排干器表结构性相同，共用本实现，避免两份回收逻辑各自
// 演化（新增回收钩子时只改一处）。
type clusterHandleRegistry[T comparable] struct {
	mu   sync.Mutex
	byDB map[*sql.DB][]T
}

func (r *clusterHandleRegistry[T]) register(database *sql.DB, item T) {
	if database == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.byDB[database] {
		if existing == item {
			return
		}
	}
	if r.byDB == nil {
		r.byDB = map[*sql.DB][]T{}
	}
	r.byDB[database] = append(r.byDB[database], item)
}

func (r *clusterHandleRegistry[T]) unregister(database *sql.DB, item T) {
	if database == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	registered := r.byDB[database]
	if len(registered) == 0 {
		return
	}
	remaining := registered[:0]
	for _, candidate := range registered {
		if candidate != item {
			remaining = append(remaining, candidate)
		}
	}
	if len(remaining) == 0 {
		delete(r.byDB, database)
		return
	}
	r.byDB[database] = remaining
}

// list 返回该库登记的全部实例。Ping 在锁外执行：死/卡句柄的探活最长 1s，
// 持锁等待会阻塞全部查表与角色翻转排干。锁内只拷贝列表，锁外探活，回锁再删。
func (r *clusterHandleRegistry[T]) list(database *sql.DB) []T {
	if database == nil {
		return nil
	}
	r.mu.Lock()
	registered := r.byDB[database]
	items := make([]T, 0, len(registered))
	items = append(items, registered...)
	if len(items) == 0 {
		delete(r.byDB, database)
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	if probeClusterDBHandle(database) == clusterHandleClosed {
		r.mu.Lock()
		delete(r.byDB, database)
		r.mu.Unlock()
		resetClusterHandleStrikes(database)
		return nil
	}
	return items
}

// clusterServices 按数据库句柄登记集群服务实例，供主节点巡检周期
// （masterSyncServingRound，无 ClusterService 接收者的自由函数）触达提升后
// pin 清理重试。pending pin 状态是实例本地的，因此按库保留全部实例、逐个
// 重试，不依赖构造顺序决定谁是「当前」实例。
var clusterServiceRegistry = clusterHandleRegistry[*ClusterService]{}

func registerClusterService(service *ClusterService) {
	if service == nil {
		return
	}
	clusterServiceRegistry.register(service.db, service)
}

// unregisterClusterService 移除单个实例：全局表以 *sql.DB 为键
// 且此前永不移除条目——测试/运行期重建 DB 时全局表强引用已 Close 的句柄，
// 内存与其关联的 service 无法回收。测试 teardown 与显式释放路径调用本函数。
func unregisterClusterService(service *ClusterService) {
	if service == nil || service.db == nil {
		return
	}
	clusterServiceRegistry.unregister(service.db, service)
	// 句柄已由调用方显式注销：探活计数一并丢弃（避免全局表残留已 Close 句柄键）。
	resetClusterHandleStrikes(service.db)
	// 同族句柄回收：三节哈希缓存以库句柄为键，注销即释放（防全局缓存强引用
	// 已关闭句柄；未走注销的死条目由重建路径的 probeClusterDBHandle 兜底剔除）。
	forgetClusterSectionHashCache(service.db)
	// 快照缓存（clusterSnapshotCaches）同样以库句柄为键且持有完整快照
	//（canonical bytes/证书/规则）：注销不释放会把已 Close 的句柄与其快照
	// 驻留到进程退出——与节哈希缓存同口径，注销即删。
	clusterSnapshotCaches.Delete(service.db)
}

// clusterHandleProbeTimeout 限制单次句柄探活 Ping 的等待。生产 1s；变量供
// 测试注入短超时（超时形态的用例不必真等 1s）。
var clusterHandleProbeTimeout = time.Second

// clusterHandleUnverifiedStrikes 是「不可判定」探活连续达到判定死亡的次数。
// 单次超时只保留登记项，连续该次数仍不可判定才按死句柄剔除。取 5：探活只在
// 主节点巡检（默认 60s）与 Promote/BecomeSlave 触发，5 次≈数分钟的持续不可用；
// 真正的句柄死亡（库已 Close）由确定性分支立即剔除，不经计数。
const clusterHandleUnverifiedStrikes = 5

// clusterHandleState 句柄探活三态。
type clusterHandleState int

const (
	// clusterHandleAlive：Ping 成功。
	clusterHandleAlive clusterHandleState = iota
	// clusterHandleClosed：确定不可用（库已 Close/连接已丢）。
	clusterHandleClosed
	// clusterHandleUnverified：1s 内未取得连接（长写事务/磁盘停顿/GC 停顿）
	// 或驱动瞬时错误——不可等价于「句柄永久死亡」，保留登记项。
	clusterHandleUnverified
)

// clusterHandleStrikes 记录同一句柄连续不可判定的探活次数（键=库句柄，
// 与两张注册表同维度：句柄死活在两个消费面之间是同一事实）。
var (
	clusterHandleStrikesMu sync.Mutex
	clusterHandleStrikes   = map[*sql.DB]int{}
)

func resetClusterHandleStrikes(database *sql.DB) {
	clusterHandleStrikesMu.Lock()
	delete(clusterHandleStrikes, database)
	clusterHandleStrikesMu.Unlock()
}

// clusterHandleStrikeCount 在锁内读取某句柄的连续探活失败次数——测试断言必须
// 经此入口：直接索引 clusterHandleStrikes 与探活写者（probeClusterDBHandle 在
// 锁内自增）构成并发读写，-race 下是 data race。
func clusterHandleStrikeCount(database *sql.DB) int {
	clusterHandleStrikesMu.Lock()
	defer clusterHandleStrikesMu.Unlock()
	return clusterHandleStrikes[database]
}

// probeClusterDBHandle 报告句柄可用性三态（兜底回收：库已 Close 而未见显式
// unregister 时，查询路径顺手剔除死条目，防止全局表在测试/重建场景无限累积）。
// 查询路径仅在主节点巡检与 Promote/BecomeSlave 触发，Ping 成本可忽略。
//
// 保守判死：只有确定性关闭（sql.ErrConnDone / "database is closed"）与连续
// clusterHandleUnverifiedStrikes 次不可判定才返回 clusterHandleClosed。原实现
// 把 1s Ping 超时等价死亡，长写事务/GC 停顿时会误删登记项——Promote/BecomeSlave
// 的排干面随之清空（在途 Pull 不排干）且 pin 清理重试链断裂。
func probeClusterDBHandle(database *sql.DB) clusterHandleState {
	ctx, cancel := context.WithTimeout(context.Background(), clusterHandleProbeTimeout)
	defer cancel()
	err := database.PingContext(ctx)
	if err == nil {
		resetClusterHandleStrikes(database)
		return clusterHandleAlive
	}
	if errors.Is(err, sql.ErrConnDone) || strings.Contains(err.Error(), "database is closed") {
		return clusterHandleClosed
	}
	clusterHandleStrikesMu.Lock()
	clusterHandleStrikes[database]++
	strikes := clusterHandleStrikes[database]
	clusterHandleStrikesMu.Unlock()
	if strikes >= clusterHandleUnverifiedStrikes {
		return clusterHandleClosed
	}
	Logf("warn", "集群：数据库句柄探活未成功（第 %d/%d 次，保留登记项待下轮重试）: %v",
		strikes, clusterHandleUnverifiedStrikes, err)
	return clusterHandleUnverified
}

func clusterServicesFor(database *sql.DB) []*ClusterService {
	// 只在确定性关闭时剔除；探活超时/瞬时错误保留登记项（见
	// probeClusterDBHandle），否则 Promote/BecomeSlave 的排干面与 pin 清理重试链
	// 会在一次停顿后静默断裂（语义单源于 clusterHandleRegistry.list）。
	return clusterServiceRegistry.list(database)
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

// masterRoleConditionSQL 是节点簿记写语句的 SQL 级角色条件。
// 原因：handler 的 requireMaster 与本次写之间没有共享锁，BecomeSlave 可在窗口内
// 提交 is_master=0——带该条件的写语句在降级后恒 0 行，消除「降级后仍审批/
// 上报/改访问地址」的 TOCTOU 类别。
//
// 谓词本体在 db 包（db.MasterRoleConditionSQL / db.SlaveRoleConditionSQL）：
// db 的后台 flusher 与 middleware 的触发器 WHEN 也用同一条口径，三处不得各
// 写一份（同 TCPRuleDeadFieldsResetSQL 的跨包单源模式）。此处保留包内别名只为
// 让本包的写语句读起来仍是「services 自己的角色条件」。
const masterRoleConditionSQL = db.MasterRoleConditionSQL

// slaveRoleConditionSQL 是 masterRoleConditionSQL 的逆谓词：从端专有状态
// （同步错误、补偿标记）只能在从节点语境落库。升主会清空这些列，若在途的
// 从端写（persistSyncError 走 WithoutCancel 以跨 Stop 取消存活）不带该条件，
// 升主提交后会被旧从端写回，而全仓没有第二处清空点（只剩降级/导入）。
const slaveRoleConditionSQL = db.SlaveRoleConditionSQL

// masterScopeMissError 在带 SQL 角色条件的读写命中 0 行后复核角色：
// 已降级统一返回 403 哨兵；主节点下的 0 行由调用方提供 NotFound/内部错误语义。
func (s *ClusterService) masterScopeMissError(ctx context.Context, fallback error) error {
	isMaster, err := RoleOf(ctx, s.db)
	if err != nil {
		return fmt.Errorf("复核节点角色: %w", err)
	}
	if !isMaster {
		return ErrNotMasterNode
	}
	return fallback
}

// nodeWriteMissError 区分节点写未生效时的「已降级」与「节点不存在」。
func (s *ClusterService) nodeWriteMissError(ctx context.Context) error {
	return s.masterScopeMissError(ctx, ErrNodeNotFound)
}

func permanentClusterToken(registrationSecret string) string {
	hash := sha256.Sum256([]byte("lazy-balancer-cluster:" + registrationSecret))
	return "lb_cluster_" + hex.EncodeToString(hash[:])
}

func (s *ClusterService) GenerateRegisterToken(ctx context.Context, createdBy int, now time.Time) (string, time.Time, error) {
	// 令牌卫生：生成新令牌前作废所有未使用令牌（一次性语义——重新生成即让旧令牌
	// 失效），并顺带删除已过期记录（GC），避免令牌表无限增长、旧令牌残留可复用。
	// 作废与生成必须在同一事务：分两语句时 INSERT 失败会留下「旧令牌已删、新令牌
	// 未落库」的空窗；并发两次生成也会交错各自作废，留下两枚有效令牌。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("开始注册令牌事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM cluster_register_tokens WHERE (used_at IS NULL OR expires_at < ?) AND `+masterRoleConditionSQL, now.UTC()); err != nil {
		return "", time.Time{}, fmt.Errorf("清理旧注册令牌: %w", err)
	}
	token, err := randomHex(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := now.UTC().Add(30 * time.Minute)
	result, err := tx.ExecContext(ctx, `INSERT INTO cluster_register_tokens (token_hash, expires_at, created_by, created_at) SELECT ?, ?, ?, ? WHERE `+masterRoleConditionSQL,
		tokenHash(token), expiresAt, createdBy, now.UTC())
	if err != nil {
		return "", time.Time{}, fmt.Errorf("保存注册令牌: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("读取注册令牌保存结果: %w", err)
	}
	if inserted != 1 {
		// 事务内复核角色（同事务视图，回滚不会翻转已提交的降级）：降级窗口
		// 统一 ErrNotMasterNode(403)；主节点下的 0 行是内部错误。
		masterNow, roleErr := db.IsMasterNode(ctx, tx)
		_ = tx.Rollback()
		if roleErr != nil {
			return "", time.Time{}, fmt.Errorf("复核节点角色: %w", roleErr)
		}
		if !masterNow {
			return "", time.Time{}, ErrNotMasterNode
		}
		return "", time.Time{}, fmt.Errorf("保存注册令牌: 影响 %d 行", inserted)
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, fmt.Errorf("提交注册令牌事务: %w", err)
	}
	return token, expiresAt, nil
}

// RegisterNode 处理从节点注册。sourceIP 是服务端观测到的注册来源地址
// （HTTP 入口=连接对端地址），自述 access_url 只在主机与其一致时落库——
// 请求体 ip_address 是自述值，不得充当该判定的信任锚。
func (s *ClusterService) RegisterNode(ctx context.Context, req models.ClusterRegisterRequest, sourceIP string, now time.Time) (models.ClusterRegistration, error) {
	if err := models.ValidateClusterAccessURL(req.AccessURL); err != nil {
		return models.ClusterRegistration{}, err
	}
	// 自述地址缺失（从节点出口 IP 探测失败时按空串上报）→ 以服务端观测到的
	// 注册来源地址落库。回退 127.0.0.1 会让「两台都探测失败的从节点」命中
	// UNIQUE(ip_address,port) 互相覆盖（后注册者重置前者的审批与集群令牌，
	// 前者 Pull 立即 401 并停止重试）。来源地址不可用时拒绝注册（可行动错误），
	// 不写回环地址。
	if strings.TrimSpace(req.IPAddress) == "" {
		source := strings.TrimSpace(sourceIP)
		if net.ParseIP(source) == nil {
			return models.ClusterRegistration{}, models.ErrMissingClusterNodeIP
		}
		req.IPAddress = source
	} else if net.ParseIP(req.IPAddress) == nil {
		// 非空自述地址必须自身就是 IP 字面量（与空值分支的来源地址校验、
		// HTTP 侧 binding ip 同判）：host:port/方括号/垃圾串不得落进
		// nodes.ip_address——该列是服务控制/登录票据投递地址的推导输入。
		return models.ClusterRegistration{}, models.ErrInvalidClusterNodeIP
	}
	// 落库侧名字归一是最后一道闸（binding max=100 只覆盖 HTTP
	// 入口；服务层直调/旧客户端仍可传入超长或带控制字符的名字）。
	req.Name = models.NormalizeClusterNodeName(req.Name)
	if req.Name == "" {
		return models.ClusterRegistration{}, models.ErrInvalidClusterNodeName
	}
	// 自述 access_url 只在主机即**注册来源地址**时落库。该值随后被用作
	// 服务控制/登录票据（Bearer 能力凭证）的投递地址——未校验时持有注册令牌
	// 的一方可把票据引向任意第三方主机。不一致时按「未携带」处理：既有行的
	// 管理员配置值由 COALESCE(NULLIF(?,''),access_url) 保留，新行留空回退
	// protocol://ip:port。
	accessURL := req.AccessURL
	accessURLIgnored := false
	if accessURL != "" && !models.ClusterAccessURLHostMatchesIP(accessURL, sourceIP) {
		accessURL = ""
		accessURLIgnored = true
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

	// 事务内角色复核（SQL 级）。降级已提交则拒绝注册/覆盖，避免
	// 旧主节点在降级窗口继续写入节点簿记。读同一事务视图（db.IsMasterNode
	// 接受 *sql.Tx），跨事务句柄会看到降级前/后的另一个快照。
	masterNow, err := db.IsMasterNode(ctx, tx)
	if err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("复核节点角色: %w", err)
	}
	if !masterNow {
		return models.ClusterRegistration{}, ErrNotMasterNode
	}

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
		// 命中既有行=upsert（保留重复注册/
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
		// access_url 是管理员配置态——重新注册不携带
		// (cluster_mode.go:49-51 恒空)时保留存量,不静默清空。
		_, err = tx.ExecContext(ctx, `UPDATE nodes SET name=?, protocol=?, access_url=COALESCE(NULLIF(?,''),access_url), status='pending', is_approved=0, registration_secret=?, registration_secret_expires_at=NULL, cluster_token_hash=NULL, cluster_token_delivered=0, reported_version=0, health_json=NULL, last_seen=NULL WHERE id=?`, req.Name, req.Protocol, accessURL, tokenHash(secret), nodeID)
	case errors.Is(err, sql.ErrNoRows):
		insert, insertErr := tx.ExecContext(ctx, `INSERT INTO nodes (name, mode, ip_address, port, protocol, access_url, status, is_approved, registration_secret) VALUES (?, 'slave', ?, ?, ?, ?, 'pending', 0, ?)`, req.Name, req.IPAddress, req.Port, req.Protocol, accessURL, tokenHash(secret))
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
	// nodes 不在 cluster_version 触发器清单（middleware/cluster_version.go
	// 依赖显式 bump）——注册/覆盖改变节点拓扑后必须同事务 bump，否则快照缓存键
	// 不变，新节点的 node_sites 缺项，继承坐标静默不生效直至下一次无关 bump。
	if err := BumpClusterVersion(ctx, tx); err != nil {
		return models.ClusterRegistration{}, err
	}
	if err := tx.Commit(); err != nil {
		return models.ClusterRegistration{}, fmt.Errorf("提交节点注册: %w", err)
	}
	// 同 IP:port 行被覆盖后旧分区哈希不再属于本次注册。
	s.clearSectionReport(nodeID)
	return models.ClusterRegistration{RegistrationID: nodeID, RegistrationSecret: secret, OverwrittenNodeID: overwrittenNodeID, OverwrittenNodeName: overwrittenNodeName, AccessURLIgnored: accessURLIgnored}, nil
}

func (s *ClusterService) UpdateNodeSiteCoordinates(ctx context.Context, nodeID int, lat, lon float64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启节点站点坐标事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// 无变更保存=no-op——现值相同则不写库不 bump（「打开弹框原样
	// 保存」不得放大为全集群快照重放；继承节点 0,0 原样保存保持继承不固化）。
	var currentLat, currentLon float64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(server_map_lat,0), COALESCE(server_map_lon,0) FROM nodes WHERE id=? AND `+masterRoleConditionSQL, nodeID).Scan(&currentLat, &currentLon); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return s.nodeWriteMissError(ctx)
		}
		return fmt.Errorf("读取节点站点坐标: %w", err)
	}
	if currentLat == lat && currentLon == lon {
		return nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE nodes SET server_map_lat=?, server_map_lon=? WHERE id=? AND `+masterRoleConditionSQL, lat, lon, nodeID)
	if err != nil {
		return fmt.Errorf("更新节点站点坐标: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取节点站点坐标更新结果: %w", err)
	}
	if updated != 1 {
		return s.nodeWriteMissError(ctx)
	}
	// 坐标是 node-local 下发数据，必须 bump 版本触发从节点拉取；与节点行同事务。
	if err := BumpClusterVersion(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交节点站点坐标: %w", err)
	}
	return nil
}

func (s *ClusterService) UpdateNodeAccessURL(ctx context.Context, nodeID int, accessURL string) error {
	if err := models.ValidateClusterAccessURL(accessURL); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, "UPDATE nodes SET access_url=? WHERE id=? AND "+masterRoleConditionSQL, accessURL, nodeID)
	if err != nil {
		return fmt.Errorf("更新节点访问地址: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取节点访问地址更新结果: %w", err)
	}
	if updated != 1 {
		return s.nodeWriteMissError(ctx)
	}
	return nil
}

func (s *ClusterService) ApproveNode(ctx context.Context, nodeID int, now time.Time) error {
	// 注册密钥 24h 到期窗口用注入 now（同域 RegistrationStatus/票据族惯例）：
	// 真实时钟会让到期边界无法确定性测试。
	result, err := s.db.ExecContext(ctx, `UPDATE nodes SET is_approved=1, status='online', registration_secret_expires_at=?, cluster_token_hash=NULL, cluster_token_delivered=0 WHERE id=? AND status='pending' AND COALESCE(registration_secret,'')<>'' AND `+masterRoleConditionSQL,
		now.UTC().Add(24*time.Hour), nodeID)
	if err != nil {
		return fmt.Errorf("批准节点: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取审批结果: %w", err)
	}
	if updated != 1 {
		// 先区分「已降级」（403 语义）与节点状态/存在性问题——角色复核
		// 单源 masterScopeMissError（fallback=nil：主节点继续下方分判）。
		if roleErr := s.masterScopeMissError(ctx, nil); roleErr != nil {
			return roleErr
		}
		// 0 行命中分判——节点存在但非 pending(重复审批/已拒绝)
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

// RegistrationStatus 的 now 参数注入同域惯例（原为唯一用真实时钟
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
	// 哈希比对改常量时间——与 HMAC 链路的 hmac.Equal 同口径。
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
		result, err := tx.ExecContext(ctx, "UPDATE nodes SET cluster_token_hash=?, cluster_token_delivered=1 WHERE id=? AND "+masterRoleConditionSQL, tokenHash(clusterToken), nodeID)
		if err != nil {
			return models.ClusterRegistrationStatus{}, fmt.Errorf("保存集群令牌: %w", err)
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return models.ClusterRegistrationStatus{}, fmt.Errorf("读取集群令牌保存结果: %w", err)
		}
		if updated != 1 {
			// 先回滚再复核角色：nodeWriteMissError 使用独立连接，不能在持锁事务内调用。
			_ = tx.Rollback()
			return models.ClusterRegistrationStatus{}, s.nodeWriteMissError(ctx)
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

// NodeName 读取节点名（审计展示用），走本服务的库句柄——调用方不得另用
// 全局库句柄回查（句柄不一致时会把审计对象错标到另一库的同 ID 节点）。
// 节点不存在时返回空串与错误，由调用方回退「节点 #<id>」格式。
func (s *ClusterService) NodeName(ctx context.Context, nodeID int) (string, error) {
	var name string
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(name,'') FROM nodes WHERE id=?", nodeID).Scan(&name); err != nil {
		return "", fmt.Errorf("读取节点名: %w", err)
	}
	return name, nil
}

func BumpClusterVersion(ctx context.Context, executor clusterVersionExecutor) error {
	result, err := executor.ExecContext(ctx, "UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1")
	if err != nil {
		return fmt.Errorf("递增集群版本: %w", err)
	}
	// global_config 行缺失/异常时 Exec 返回 0 行且 nil error，集群
	// 版本不递增，从节点可能继续 304 不拉新内容——按 fail-visible 报错。
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取集群版本递增结果: %w", err)
	}
	if updated != 1 {
		return fmt.Errorf("递增集群版本命中 %d 行（global_config 行缺失或已损坏）", updated)
	}
	return nil
}

// clearAppliedSections 清理旧拓扑的已应用节记账（幂等）。executor 是拓扑事务
// （翻转路径：与角色更新同成同败）或库句柄（对账路径：库角色已是目标值，
// 补做）。残留的节哈希会让下一轮同步把旧集群的跳过依据当成当前状态。
func clearAppliedSections(ctx context.Context, executor clusterVersionExecutor) error {
	if _, err := executor.ExecContext(ctx, `DELETE FROM cluster_applied_sections`); err != nil {
		return fmt.Errorf("清理已应用节记账: %w", err)
	}
	return nil
}

// resetAppliedWAFFileState 复位 WAF 文件态记账（幂等）。翻转路径在拓扑
// UPDATE 的同一语句内完成（保持集群版本单次 bump），本函数供对账路径复用。
func resetAppliedWAFFileState(ctx context.Context, executor clusterVersionExecutor) error {
	if _, err := executor.ExecContext(ctx, `UPDATE global_config SET applied_waf_ref_hash='', applied_waf_ref_version=0 WHERE id=1`); err != nil {
		return fmt.Errorf("复位 WAF 文件态记账: %w", err)
	}
	return nil
}

// clearAppliedTopologyState 是「旧拓扑记账 + WAF 文件态」的组合清理，
// 供角色对账路径使用（翻转路径见上：WAF 复位在拓扑 UPDATE 语句内）。
func clearAppliedTopologyState(ctx context.Context, executor clusterVersionExecutor) error {
	if err := clearAppliedSections(ctx, executor); err != nil {
		return err
	}
	return resetAppliedWAFFileState(ctx, executor)
}

// applyRoleSideEffects 是角色翻转「数据/状态半边」的进程内单源（Promote/
// BecomeSlave/reconcileTaskEngineRole 三处共用）。
// 对账器只翻引擎半边会把旧角色时代的缓存/分区上报/漂移态带入新角色，后续
// 再升主时旧快照会被当作权威下发（Promote 注释登记过同一风险）。
// 调用方须持 roleMu，且必须在 SetRole 之前调用——ResetConfigDrift 先于
// 角色翻转，在途看门狗轮才不会按新角色误报一次「配置漂移」（与 BecomeSlave
// 既有顺序一致）。DB 半边由调用方在事务内先行完成（clearAppliedTopologyState），
// 保持「记账清理与角色落库同成同败」。
func (s *ClusterService) applyRoleSideEffects() {
	if s != nil {
		// 缓存键只有 version/ownership/开关，不含角色——降级期间在途的
		// master-only Run 可写过库且 is_master=0 不 bump 版本。
		clusterSnapshotCaches.Delete(s.db)
		// 旧角色时代的分区上报缓存不再有权威来源。
		s.clearAllSectionReports()
	}
	ResetConfigDrift()
}

// rebuildCrawlerSnapshotAfterPromote 升主后以本地 DB 重建爬虫运行快照——
// 从节点期间的快照可能陈旧/缺失（此前仅主节点写该文件），升主后本节点
// 将成为插件文件的生产者。失败仅留痕（下轮更新/重启收敛）。
// Promote 与角色对账（DB=主/引擎=从）共用。
func rebuildCrawlerSnapshotAfterPromote() {
	if err := RebuildCrawlerIPListSnapshot(); err != nil {
		Logf("warn", "升主后爬虫运行快照重建失败（插件按旧快照运行至下次更新）: %v", err)
	}
}

// restoreClusterSyncSchedulingAfterDemote 切从后的拉取调度对齐（须在
// SetRole(false) 之后调用：先 SetRole 让 daemon 换代为拉取分支）。BecomeSlave
// 与角色对账（DB=从/引擎=主）共用。
//
// 用户显式停止的 cluster-sync（loopOn=false）保持停止——角色翻转不得复活
// 用户停止态（task-engine 标准 v2.2 §5）：切从只翻转角色语义，不覆盖用户
// 对调度开关的裁定。此时以 Logf warn + 操作审计显式提示「切从后不会同步，
// 请手动开启」，不得静默脱管；偏好表也不再回写 enabled=1（旧实现无条件
// StartLoop + 持久化偏好，既复活了停止态，重启后还会按残留偏好继续停同步）。
// 开启态：确保调度开启 + 持久化偏好（偏好表若残留主节点期间的 0，下次重启
// 会再次停同步）。resumeHaltedSyncLifecycle 只在开启态调用——daemon 停止时
// 复活同步服务会让同步在无调度的情况下运行，违背用户停止裁定。
func restoreClusterSyncSchedulingAfterDemote() {
	te := TaskEngine()
	if te == nil {
		return
	}
	if meta, ok := te.Lookup("cluster-sync"); ok && !meta.LoopOn {
		Logf("warn", "cluster-sync 调度处于用户停止态：切从后不会同步，请手动开启")
		RecordAuditLog("system", "同步停止", "集群模式",
			FormatAuditDetail("已停止：切从后不会同步，请手动开启", AuditResultPart("warning")), "")
		return
	}
	// 角色恢复：非唤醒——仅恢复角色翻转前已开启的调度（loopEnabled 保留语义），
	// 业务事件不得借道此处 StartLoop 唤醒（标准 v2.2 §0.6-4 例外仅此一类）。
	te.StartLoop("cluster-sync")
	// StartLoop 只按角色换代 daemon；Halted 的 SyncService 对 Start 是 no-op
	// （startLocked(resume=false) 直接返回），从节点数据会永久不收敛。复活
	// 必须走 Resume——与 BecomeSlave 显式 Resume 的口径对齐（此前只有那条路
	// 有最后一跳，角色对账降级这里是缺口）。
	resumeHaltedSyncLifecycle()
	if err := RecordTaskLoopPref("cluster-sync", true); err != nil {
		Logf("warn", "切成从节点后持久化 cluster-sync 调度偏好失败（当前进程已恢复）: %v", err)
	}
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
	// 角色翻转显式失效快照缓存（幂等零成本）。缓存键只有
	// version/ownership/开关，降级期间在途的 master-only Run 可写过库且
	// is_master=0 不 bump 版本——若从降级到再升主之间没有发生 apply，旧缓存
	// 内容会被当作权威重新对外提供。放在角色检查之后，成功/失败路径都覆盖。
	clusterSnapshotCaches.Delete(s.db)
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
			// 角色恢复：非唤醒——提升失败回滚只恢复翻转前已开启态。
			te.StartLoop("cluster-sync")
		}
	}()
	// engine.StopLoop 只取消 daemon ctx，
	// daemon 的 Stop 在另一 goroutine 异步执行——不显式排干则在途拉取（含已
	// 通过 admission 的 apply）可能在升主提交后继续把从节点数据写回库。
	// 排干失败（ctx 到期）即中止提升，不做半程角色翻转。
	// 同库可能登记多个同步服务实例（测试/重建），逐个排干——
	// 只排干最后注册的一个会让其余实例的在途 apply 越过升主提交点。
	if drainers := syncDrainersFor(s.db); len(drainers) > 0 {
		// 排干失败的返回路径同样必须重开准入（defer 必须先于
		// DrainPulls 注册）。DrainPulls 自身已置 pullsStopped=true，原实现只在
		// 成功后注册 defer：失败路径若 cluster-sync 已停（用户关闭）或
		// TaskEngine()==nil，准入永久关闭——从节点「立即同步」被 beginPull 拒绝
		// 且哨兵不落库，静默脱同步直到再次 Promote/BecomeSlave/重启。
		for _, drainer := range drainers {
			defer drainer.reopenPullAdmission()
			if err := drainer.DrainPulls(ctx); err != nil {
				return fmt.Errorf("等待在途同步拉取结束: %w", err)
			}
		}
		// 排干成功后的任意返回路径都必须重开准入。成功升主后再降级
		// 也有 BecomeSlave 的显式重开，此处兜底保持不变量。
	}
	var registrationID int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(registration_id,0) FROM global_config WHERE id=1").Scan(&registrationID); err != nil {
		return fmt.Errorf("读取注册编号: %w", err)
	}
	// 升主可见告警（不自动动作）：last_sync_error 在下方重置事务中被清空——
	// 若旧集群同步残留未完成补偿标记（重载失败/品牌落盘失败/安全数据未
	// 收敛），必须在清标记前捕获现值，提交后告警留痕（与看门狗「只报告」
	// 口径一致，不自动触发任何补偿动作）。
	var storedSyncError string
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&storedSyncError); err != nil {
		return fmt.Errorf("读取同步错误标记: %w", err)
	}
	pendingCompensations := promotePendingCompensations(storedSyncError)
	var oldToken string
	// 旧令牌仅用于提升成功后的脱离通知，
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
	// nodes 表（含各从节点
	// cluster_token_hash）跨角色切换刻意保留——Promote/BecomeSlave 均只重置
	// global_config，从不清空 nodes。拓扑连续性语义：脱离通知
	// （notifyMasterDetach）只是 best-effort，旧主节点令牌撤销依赖其成功；
	// 本节点降级后再提升时，旧 nodes 行即刻恢复权威，旧从节点持有的令牌
	// 仍然有效，经手工 Resume/重新注册即可复活上报与同步——这是有意设计
	// （主库清零后可凭从库副本恢复集群拓扑），不是令牌泄漏缺口。
	// last_sync 与 applied_version 同语义：旧集群的同步时间对新主节点无意义；
	// 此前漏置 NULL 让 Status() 继续格式化旧集群时间（与 BecomeSlave 的对称缺失）。
	result, err := tx.ExecContext(ctx, `UPDATE global_config SET is_master=1, master_url='', cluster_token='', registration_id=0, registration_secret='', applied_version=0, sync_fingerprint='', last_sync_error='', registration_confirm_failures=0, last_sync=NULL, applied_waf_ref_hash='', applied_waf_ref_version=0 WHERE id=1`)
	if err != nil {
		return fmt.Errorf("重置主节点状态: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取主节点状态重置结果: %w", err)
	}
	if updated != 1 {
		return fmt.Errorf("重置主节点状态: 影响 %d 行", updated)
	}
	// 已应用节哈希只属于旧拓扑；与角色更新同事务清空，后续再次切从时首轮
	// 按新主节点重建，不沿用旧集群的跳过依据（WAF 文件态已在上一语句复位——
	// 同一语句保持集群版本单次 bump）。
	if err := clearAppliedSections(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交提升事务: %w", err)
	}
	promoted = true
	// 角色生效面的进程内失效半边（与 BecomeSlave/对账器共用同一入口）。
	s.applyRoleSideEffects()
	rebuildCrawlerSnapshotAfterPromote()

	if registrationID > 0 {
		RecordAuditLog("system", "提升完成", "集群节点", FormatAuditDetail(fmt.Sprintf("注册编号：%d", registrationID), "本节点已脱离集群并提升为主节点", AuditResultPart("success")), "")
	}
	if len(pendingCompensations) > 0 {
		// 只报告不自动动作：补偿属于旧集群拓扑，新主节点不能替旧主重放；
		// 告警指引一次系统配置载入收敛运行态。
		detail := fmt.Sprintf("升主完成：检测到上次同步存在未完成补偿（%s），建议执行一次系统配置载入", strings.Join(pendingCompensations, "、"))
		Logf("warn", "Promote: %s", detail)
		RecordAuditLog("system", "提升完成", "集群节点", FormatAuditDetail(detail, AuditResultPart("warning")), "")
	}
	// 自动备份：v2.0 引擎 Scheduled 驱动（RunsOn=MasterOnly 角色门）——
	// promote 后由引擎 SetRole 使能，无需单独拉起。
	// 角色翻转由引擎 SetRole 唯一驱动：cert-issuance/cluster-sync 经 daemon
	// 生命周期挂钩启停，不再存在管理器直调或旧调度器旁路。
	if te != nil {
		te.SetRole(true)
		if clusterSyncWasOn {
			// 角色恢复：非唤醒——升主只恢复翻转前已开启态（偏好保留语义）。
			te.StartLoop("cluster-sync")
		} else {
			// cluster-sync 两角色语义不同：从端=拉取，主端=服务面巡检（从节点
			// 离线/版本滞后判定，cluster_masterserving.go）。升主不擅自武装被
			// 用户停掉的调度（偏好保留，既有钉测锁定），但巡检缺位必须可见——
			// 否则从节点离线/版本滞后不再告警且无任何信号。
			detail := "cluster-sync 调度保持停止（用户偏好保留）：主节点服务面巡检（从节点离线/版本滞后判定）未启用，需要时请在任务监控启动「集群同步」"
			Logf("warn", "Promote: %s", detail)
			RecordAuditLog("system", "提升完成", "集群节点", FormatAuditDetail(detail, AuditResultPart("warning")), "")
		}
	}
	// 升主后的任务面收尾（六业务驱动任务对齐 + 规则库首槽重装）与角色对账
	// 升主分支共用单源——两条升主路径分头维护会漏项。
	applyPromoteTaskSideEffects()
	s.detachFromMaster(ctx, masterURL, oldToken)
	return nil
}

// promotePendingCompensations 解析升主前 last_sync_error 现值中尚未完成的
// 补偿标记（重载失败/品牌落盘失败/提交结果不确定/安全数据未收敛），返回人类可读清单；
// 非补偿性质的普通同步错误（传输失败等）不纳入。
func promotePendingCompensations(stored string) []string {
	msg, _ := decodeSyncError(stored)
	if msg == "" {
		return nil
	}
	var pending []string
	switch syncPostCommitMarkerPrefix(msg) {
	case syncReloadFailureMarkerPrefix:
		pending = append(pending, "重载失败补偿")
	case syncBrandingFailureMarkerPrefix:
		pending = append(pending, "品牌落盘补偿")
	case syncCommitUncertainMarkerPrefix:
		pending = append(pending, "提交不确定补偿")
	}
	if strings.Contains(msg, wafRepullFailureMessagePrefix) {
		pending = append(pending, "安全数据未收敛")
	}
	return pending
}

// detachFromMaster 复用升主/换主的旧主脱离收尾：按已知 pin 仅比对通知
// detached，再清理旧主 pin。调用方负责在本地拓扑提交成功后调用。
func (s *ClusterService) detachFromMaster(ctx context.Context, masterURL, oldToken string) {
	if masterURL == "" {
		return
	}
	parsedMasterURL, err := url.Parse(masterURL)
	if err != nil {
		Logf("info", "parse old cluster master URL after promotion: %v", err)
		RecordAuditLog("system", "清理失败", "证书指纹", FormatAuditDetail("旧主节点地址无效", err.Error()), "")
		// 地址损坏时无法定位旧主节点 pin 文件——磁盘残留为已知边界
		// 残留仅在该 host:port 将来重新注册
		// 为从节点时引发一次 PinMismatch，forget-pins 可恢复。
		return
	}
	// pin 目录解析单源=本服务的 dataDir（写入/校验侧 SyncService 同口径
	// 经 cfg.DataDir）；dataDir 为空（测试构造）时 clusterPinPath 内部
	// 回退数据库文件目录推导。
	pinPath, err := clusterPinPath(s.dataDir, s.db, parsedMasterURL.Host)
	if err != nil {
		Logf("info", "locate old cluster master pin after promotion: %v", err)
		RecordAuditLog("system", "清理失败", "证书指纹", FormatAuditDetail("旧主节点："+parsedMasterURL.Scheme+"://"+parsedMasterURL.Host, err.Error()), "")
		// 同上：pin 路径定位失败，磁盘清理不可达，残留边界已知。
		return
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
		// 通知旧主节点该从节点已脱离（失败不阻断提升，主节点
		// 会在上报超时后将其标记下线；成功则主节点节点列表立即更新并留痕）。
		go notifyMasterDetach(context.WithoutCancel(ctx), masterURL, oldToken, pinFingerprint)
	}
	s.cleanupClusterPin(pinPath, parsedMasterURL.Scheme+"://"+parsedMasterURL.Host)
}

func (s *ClusterService) cleanupClusterPin(pinPath, auditURL string) {
	s.pinCleanupMu.Lock()
	defer s.pinCleanupMu.Unlock()
	if err := os.Remove(pinPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// pin 文件本就不存在(HTTP 注册从节点提升
			// 恒现——从未写过 pin)记「清理成功」审计是假阳性,跳过;
			// pending 状态仍清空(无遗留需重试)。
			s.clearPendingPinLocked(pinPath)
			return
		}
		// 同一 pin 路径的审计地址保持首次登记值（该 pin 只对应一个旧主节点）；
		// 不同路径各占一条，互不覆盖——单槽实现会让先前的待重试项永久失联。
		if _, exists := s.pendingPins[pinPath]; !exists {
			if s.pendingPins == nil {
				s.pendingPins = make(map[string]string, 2)
			}
			s.pendingPins[pinPath] = auditURL
		}
		Logf("info", "cluster pin cleanup deferred: %v", err)
		// 重试由 Snapshot（每次 Pull）与主节点巡检（60s）驱动，同一失败会
		// 按分钟稳定复现：审计只在失败形态（路径+错误）变化时写一条，恢复
		// 成功时才重记「清理」；否则取证面被重复行淹没且掩盖真正的残留告警。
		failureKey := pinPath + "\x00" + err.Error()
		if s.pinCleanupFailureKeys == nil {
			s.pinCleanupFailureKeys = make(map[string]string, 2)
		}
		if s.pinCleanupFailureKeys[pinPath] != failureKey {
			s.pinCleanupFailureKeys[pinPath] = failureKey
			RecordAuditLog("system", "清理失败", "证书指纹", FormatAuditDetail("旧主节点："+auditURL, err.Error()), "")
		}
		return
	}
	s.clearPendingPinLocked(pinPath)
	RecordAuditLog("system", "清理", "证书指纹", FormatAuditDetail("旧主节点："+auditURL, AuditResultPart("success")), "")
}

// clearPendingPinLocked 清除该路径的待重试与失败去重状态（调用方持锁）。
func (s *ClusterService) clearPendingPinLocked(pinPath string) {
	delete(s.pendingPins, pinPath)
	delete(s.pinCleanupFailureKeys, pinPath)
}

func (s *ClusterService) retryPendingPinCleanup() {
	s.pinCleanupMu.Lock()
	pending := make(map[string]string, len(s.pendingPins))
	for pinPath, auditURL := range s.pendingPins {
		pending[pinPath] = auditURL
	}
	s.pinCleanupMu.Unlock()
	for pinPath, auditURL := range pending {
		s.cleanupClusterPin(pinPath, auditURL)
	}
}

const (
	minSyncIntervalSeconds     = 10
	defaultSyncIntervalSeconds = 60
	maxSyncIntervalSeconds     = 86400
)

// normalizeSyncInterval 将存量/快照脏值归一到运行时和展示共同接受的区间。
// 低于下限沿用历史 60s 口径（1-9s 会形成高频 Pull 风暴），高于上限钳到 24h
// （避免同步长停与在线阈值被无限放大）。
func normalizeSyncInterval(interval int) int {
	if interval < minSyncIntervalSeconds {
		return defaultSyncIntervalSeconds
	}
	if interval > maxSyncIntervalSeconds {
		return maxSyncIntervalSeconds
	}
	return interval
}

// normalizeJWTExpireMinutes 把 jwt_expire_minutes 收敛到写侧允许区间
// 1..1440（越界回退治理默认）。装载侧与 apply 侧共用同一 helper——两侧口径
// 分叉会让 users 节哈希主从不相等（脏值触发的整节重放与漂移补偿全量重拉）。
func normalizeJWTExpireMinutes(minutes int) int {
	if minutes <= 0 || minutes > 1440 {
		return db.DefaultJWTExpireMinutes
	}
	return minutes
}

// normalizeCertExpiryDays 把 cert_expiry_days 收敛到写侧允许区间 1..365
// （越界回退治理默认）。与 normalizeJWTExpireMinutes 同族、同单源理由。
func normalizeCertExpiryDays(days int) int {
	if days <= 0 || days > 365 {
		return db.DefaultCertExpiryDays
	}
	return days
}

// nodeOfflineMultiplier 判定节点离线时 last_seen 的允许超时倍率（× sync_interval 秒）。
// MetricsService.updateOverview 的在线节点统计口径必须与此一致，共用本常量，
// 避免阈值在两处各自硬编码导致口径漂移。
const nodeOfflineMultiplier = 2

// nodeOfflineThreshold 节点离线阈值的统一口径
// max(nodeOfflineMultiplier×sync_interval, masterSyncOfflineThreshold 下限)。
// 存量脏值（前残留的 0/负数或 1-9s）按 60s 计，与从节点 run loop
// （cluster_sync.go）的 clamp 值一致：从节点实际以 60s 周期上报，若按原始脏值
// （或 10s）计算阈值，会把两次上报之间的正常从节点误判为离线。
// ComputeNodeStatus（节点列表/登录票据）、updateOverview（总览在线数）与
// masterSyncServingRound（巡检）共用本函数——此前巡检侧 max(2×global,120s) 而
// UI 侧仅 2×clamp(sync_interval)，sync_interval∈[10,59] 时两口径分叉
// （interval=30：巡检 120s 判在线、UI 60s 判离线）。
func nodeOfflineThreshold(syncInterval int) time.Duration {
	syncInterval = normalizeSyncInterval(syncInterval)
	threshold := time.Duration(nodeOfflineMultiplier*syncInterval) * time.Second
	if threshold < masterSyncOfflineThreshold {
		threshold = masterSyncOfflineThreshold
	}
	return threshold
}

// nodeOfflineThresholdSeconds 按 nodeOfflineThreshold 唯一口径折算离线阈值秒数，
// 供必须在 SQL 内比较 last_seen 的调用方（MetricsService.updateOverview）使用。
// 此前总览的在线节点统计在 SQL 内另写一套
// MIN(86400, MAX(?×clamp(sync_interval),120)) —— 阈值被硬顶在 24h，与 Go 侧
// 阈值（2×86400=48h）分叉；sync_interval∈(43200,86400] 时节点列表与总览互相
// 矛盾，且常量调整后两处必然再次漂移。
func nodeOfflineThresholdSeconds(database *sql.DB) int {
	interval := defaultSyncIntervalSeconds
	if database != nil {
		var raw sql.NullInt64
		if err := database.QueryRow("SELECT sync_interval FROM global_config WHERE id = 1").Scan(&raw); err != nil {
			// 状态转换口径（首报 warn + 恢复 info）与同函数另三条 DB 派生指标
			// 一致：30s 一轮的采集直接把 warn 打出去会以同一条消息刷屏，而
			// 恢复时零信号——阈值长期按默认值计算这件事会永久隐身。
			if !errors.Is(err, sql.ErrNoRows) {
				if lvl := logStateTransition("overview-count-sync-interval", true); lvl != "" {
					Logf(lvl, "updateOverview: 读取 sync_interval 失败，离线阈值按默认 %ds 计: %v", defaultSyncIntervalSeconds, err)
				}
			}
		} else {
			if lvl := logStateTransition("overview-count-sync-interval", false); lvl != "" {
				Logf(lvl, "updateOverview: 读取 sync_interval 已恢复，离线阈值按库值计算")
			}
			if raw.Valid {
				interval = int(raw.Int64)
			}
		}
	}
	return int(nodeOfflineThreshold(interval).Seconds())
}

func ComputeNodeStatus(approved bool, lastSeen time.Time, syncInterval int, now time.Time) string {
	if !approved {
		return "pending"
	}
	// 阈值口径集中在 nodeOfflineThreshold：脏值 clamp 与 120s 下限
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
	// 脱离通知是一次性的：transport 绑定本次已知指纹（不能复用共享 client，
	// 否则「仅比对不落盘」语义失效），用完必须关闭空闲连接——否则连接与其
	// 读写 goroutine 会滞留到 IdleConnTimeout(90s)，反复升降主时累积多份残留
	// transport（与 handlers 侧 per-request client 的收尾同口径）。
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// 旧主节点启用管理 HTTPS 后明文端口 301——按集群
	// 同步同一契约对同主机 https Location 重放一次，否则脱离通知永远到不了。
	resp, err := DoWithSameHostTLSUpgradeRedirect(client, req)
	if err != nil {
		Logf("error", "cluster detach notify failed: %v", err)
		return
	}
	resp.Body.Close()
	if isHTTPRedirect(resp.StatusCode) {
		Logf("info", "cluster detach notify rejected: %d（重定向未跟随，旧主节点记录可能残留）", resp.StatusCode)
		return
	}
	if resp.StatusCode >= http.StatusBadRequest {
		Logf("info", "cluster detach notify rejected: %d", resp.StatusCode)
	}
}
