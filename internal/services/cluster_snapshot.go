package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
	"lazy-balancer-v2/internal/models"
)

// API Key 安全属性不能由旧读取端静默降级为宽权限默认值。
//
// 版本义务：CurrentSnapshotSchema 只描述信封/字段形态，是读者门的唯一依据
// （MinReaderVersion=本值，旧从节点据此拒绝新信封）。新增/删除任何参与同步的
// 列或字段时必须同步评估是否 bump：不 bump 时，滚动升级窗口内旧从节点按自己的
// INSERT 列清单落库，新列静默取 schema 默认值且无门可拒（单版本内的列清单
// 完整性由 cluster_snapshot/apply 的列清单钉测覆盖，跨版本只能靠 bump）。
const CurrentSnapshotSchema = 3

type clusterSnapshotCache struct {
	// buildMu 串行化「构建」（只读事务 + 全树 WAF ref + X.509 解析 + 发布）；
	// mu 只保护字段读写（微秒级）。此前单锁覆盖整段构建：导入/CRS 交换长持
	// wafFileMu 时，首个 Pull 会阻塞在构建里，其余从端 Pull 全部排在 mu 后
	// （集群面瞬间停顿）。拆开后等锁期间到达的请求会在拿到 buildMu 后做
	// 「双检」命中刚发布的缓存，不再各自重建。
	buildMu     sync.Mutex
	mu          sync.Mutex
	initialized bool
	version     int
	snapshot    models.ClusterSnapshot
	canonical   json.RawMessage
	fingerprint string
	ownership   [sha256.Size]byte
	switches    string
	expiresAt   time.Time
}

var clusterSnapshotCaches sync.Map

// snapshotRowIsolation 是单行损坏数据的限频告警状态
// 同一「表:行 ID」在 snapshotRowIsolationWindow 内只告警一次，避免每次快照
// 重建/每轮同步把同一坏行刷成日志与审计洪泛。
var (
	snapshotRowIsolationMu     sync.Mutex
	snapshotRowIsolationSeen   = map[string]time.Time{}
	snapshotRowIsolationWindow = 10 * time.Minute
	// snapshotRowIsolationHook 测试观察点（生产恒 nil）。
	snapshotRowIsolationHook func(table string, rowID any, err error)
)

// resetSnapshotRowIsolationThrottle 清空限频表（仅测试使用）。
func resetSnapshotRowIsolationThrottle() {
	snapshotRowIsolationMu.Lock()
	snapshotRowIsolationSeen = map[string]time.Time{}
	snapshotRowIsolationMu.Unlock()
}

// warnCorruptedSnapshotRow 显式隔离（跳过）单行损坏数据并留下结构化告警：
// 快照是主→从的整包下发通道，一行 JSON 畸形不得让全部规则/策略/节点数据
// 500。告警必须点名表与行 ID。
//
// 语义如实化：隔离**不是**「从节点保留本地既有行」——快照节是全量
// 替换语义（users 节先 clearSyncTables(api_keys, users)、security 节先
// DELETE security_custom_rules 再插入 payload），且节哈希按剔除坏行后的
// payload 计算，从节点不会因哈希不一致跳过。因此主节点某行损坏时，从节点
// 下一次 apply 后该行**消失**（api_keys 表现为认证消失、custom_rules 表现为
// 拦截规则消失），主节点修复该行后下一次同步自然自愈。该 fail-open 隔离是
// 有意取舍（防单行坏数据瘫痪全量同步），调用方 skip 后必须继续。
func warnCorruptedSnapshotRow(table string, rowID any, err error) {
	key := fmt.Sprintf("%s:%v", table, rowID)
	now := time.Now()
	snapshotRowIsolationMu.Lock()
	allowed := throttleWarnAllowed(snapshotRowIsolationSeen, key, now, snapshotRowIsolationWindow, snapshotRowIsolationWindow)
	hook := snapshotRowIsolationHook
	snapshotRowIsolationMu.Unlock()
	if !allowed {
		return
	}
	if hook != nil {
		hook(table, rowID, err)
	}
	Logf("error", "集群快照隔离损坏行：表 %s 行 %v 解析失败（该行不下发，健康行照常同步；请修复主节点数据）: %v", table, rowID, err)
	RecordAuditLog("system", "同步失败", "集群快照",
		FormatAuditDetail(fmt.Sprintf("表 %s 行 %v", table, rowID), "行数据解析失败，未随快照下发（从节点全量替换后该行消失，主节点修复后自愈）", err.Error()), "")
}

type snapshotStore interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Snapshot builds the full cluster snapshot. tokenKey signs the payload with
// the requesting node's cluster token  so slaves can verify;
// tokenKey 为空跳过签名——仅测试接缝(生产 GetClusterSnapshot 恒经
// clusterTokenAuth 携带非空令牌）。
func (s *ClusterService) Snapshot(ctx context.Context, sinceVersion int, clientFingerprint string, tokenKey string) (models.ClusterSnapshot, bool, error) {
	s.retryPendingPinCleanup()
	// 品牌镜像刷新(2026-09-11):每次同步轮询先对账 branding.json→
	// global_config.branding_json——文件变化即 bump 版本,304 门自然失效,
	// 变更流向从节点;内容不变零扰动。快照缓存随版本失效自然重建。
	// 显式传本服务 s.db（不再依赖全局 db.DB），内容未变时
	// 函数内先读短路，纯 304 轮不再向主库写。
	// 本调用先于 cachedSnapshot 的角色门（is_master）——角色安全由
	// RefreshBrandingMirrorDB 自身的 `WHERE … is_master=1` 谓词承担（降级窗口内
	// 恒 0 行），不得在函数内去除该谓词，也不得把本调用改成无条件写。
	if s.dataDir != "" {
		if changed, err := RefreshBrandingMirrorDB(s.db, s.dataDir); err != nil {
			Logf("warn", "刷新品牌配置镜像失败: %v", err)
		} else if changed {
			clusterSnapshotCaches.Delete(s.db)
		}
	}
	snapshot, canonical, fingerprint, err := s.cachedSnapshot(ctx)
	if err != nil {
		return models.ClusterSnapshot{}, false, err
	}
	snapshot.Fingerprint = fingerprint
	if sinceVersion >= snapshot.Version && clientFingerprint != "" && clientFingerprint == snapshot.Fingerprint {
		// 304 响应体为空，canonical 拷贝、HMAC 签名与「确认旧协议集群
		// 令牌交付」的 nodes UPDATE 都只属于真正下发的快照（与 cluster_sync.go
		// 注册轮询侧的 confirm 交付语义同源），在 304 门之前执行纯属浪费。
		return snapshot, false, nil
	}
	// 只读事务视图在第一条 SELECT 时冻结：cachedSnapshot 起点的角色复核之后
	// 提交的降级对该事务不可见，仍会按主节点视图组装并下发一份完整快照
	// （用户 hash/证书私钥/云凭据）。构建返回后、写响应前做一次事务外点查
	// 复核；读失败按 fail-closed 处理（无法确认角色即不下发）。成本=一次主键
	// 点查，仅真正下发的快照承担。
	if isMaster, err := RoleOf(ctx, s.db); err != nil {
		return models.ClusterSnapshot{}, false, fmt.Errorf("复核节点角色: %w", err)
	} else if !isMaster {
		return models.ClusterSnapshot{}, false, ErrNotMasterNode
	}
	snapshot.CanonicalPayload = append(json.RawMessage(nil), canonical...)
	if tokenKey != "" {
		// 签名绑定 canonical(含版本),
		// 但接收端对验签通过而版本低于已应用版本的快照(主节点旧备份恢复
		// 跟随回退,已裁定设计)仅告警后照常应用——防重放在接收侧不存在,
		// 真实性依赖 TOFU pin TLS+令牌,勿据此注释推断防重放保证。
		mac := hmac.New(sha256.New, []byte(tokenKey))
		_, _ = mac.Write(canonical)
		snapshot.Signature = hex.EncodeToString(mac.Sum(nil))
		if _, err := s.db.ExecContext(ctx, "UPDATE nodes SET registration_secret=NULL, registration_secret_expires_at=NULL WHERE cluster_token_hash=? AND registration_secret IS NOT NULL AND "+masterRoleConditionSQL, tokenHash(tokenKey)); err != nil {
			return models.ClusterSnapshot{}, false, fmt.Errorf("确认旧协议集群令牌交付: %w", err)
		}
	}
	return snapshot, true, nil
}

// ConfirmRegistration 确认集群令牌交付，返回被确认节点名（审计归因用：确认
// 成功即注册密钥失效，须能证明是哪个节点消费了它）。
func (s *ClusterService) ConfirmRegistration(ctx context.Context, token string) (string, error) {
	// 清列与上方旧协议交付确认（84）对齐——过期时间戳
	// 一并置 NULL，不与已清空的 secret 残留分叉。
	// SQL 级角色条件——降级窗口内的确认不得再写节点簿记。
	// RETURNING name 免除额外查询，且与「确认了哪一行」天然同源。
	var nodeName string
	err := s.db.QueryRowContext(ctx, "UPDATE nodes SET registration_secret=NULL, registration_secret_expires_at=NULL WHERE cluster_token_hash=? AND "+masterRoleConditionSQL+" RETURNING name", tokenHash(token)).Scan(&nodeName)
	if errors.Is(err, sql.ErrNoRows) {
		// 角色复核单源 masterScopeMissError：已降级 → ErrNotMasterNode(403)，
		// 主节点下的 0 行 → 令牌不匹配（ErrInvalidClusterAuth）。
		return "", s.masterScopeMissError(ctx, ErrInvalidClusterAuth)
	}
	if err != nil {
		return "", fmt.Errorf("确认集群令牌交付: %w", err)
	}
	return nodeName, nil
}

func (s *ClusterService) cachedSnapshot(ctx context.Context) (models.ClusterSnapshot, json.RawMessage, string, error) {
	value, _ := clusterSnapshotCaches.LoadOrStore(s.db, &clusterSnapshotCache{})
	cache := value.(*clusterSnapshotCache)
	// 构建锁（非发布锁）：同一 DB 只允许一个构建在飞，其余请求在获得锁后
	// 走下方双检直接命中缓存——它们是「等一次构建」而不是「各建一份」。
	cache.buildMu.Lock()
	defer cache.buildMu.Unlock()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return models.ClusterSnapshot{}, nil, "", fmt.Errorf("开启集群快照事务: %w", err)
	}
	defer tx.Rollback()

	// 版本读取与角色复核并入同一行读取（零额外查询，304 轮也执行）：
	// handler 的 requireMaster 与本读之间无共享锁，BecomeSlave 可在窗口内
	// 提交 is_master=0——读路径不带角色条件时降级瞬间仍会下发一次完整
	// 快照（含用户 hash/证书私钥/凭据）。is_master=0 即返回降级哨兵，
	// handler 映射 403（从端 Pull 已有「目标降级，可重试」分类）。
	var isMaster int
	var version int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(is_master,1), COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&isMaster, &version); err != nil {
		return models.ClusterSnapshot{}, nil, "", fmt.Errorf("读取集群版本: %w", err)
	}
	if isMaster == 0 {
		return models.ClusterSnapshot{}, nil, "", ErrNotMasterNode
	}
	ownershipHash, err := snapshotOwnershipHash(ctx, tx)
	if err != nil {
		return models.ClusterSnapshot{}, nil, "", err
	}
	now := s.snapshotNow()
	// 开关读取失败必须报错——空缓存键 + nil 开关会把主节点 sync_users=0
	// 等关闭保护在该份快照内绕过（从节点 computeSectionSkips 回退全开默认值），
	// 且无自愈路径。无法确认权威开关状态时不得发布快照。
	// 开关读取与快照内容共用同一事务视图（此前走 s.db，事务外读取
	// 可能拿到不同时点数据；单连接池下更会对自身连接永久等待）。
	switches, err := readSyncSwitches(ctx, tx)
	if err != nil {
		return models.ClusterSnapshot{}, nil, "", fmt.Errorf("读取同步开关: %w", err)
	}
	switchesKey := fmt.Sprintf("%t%t%t", switches.Users, switches.Rules, switches.Security)
	// 双检：读字段用 mu（构建已在 buildMu 内串行化，此处只防并发读的撕裂）。
	cache.mu.Lock()
	hit := cache.initialized && cache.version == version && cache.ownership == ownershipHash && cache.switches == switchesKey && (cache.expiresAt.IsZero() || now.Before(cache.expiresAt))
	cachedSnapshot, cachedCanonical, cachedFingerprint := cache.snapshot, cache.canonical, cache.fingerprint
	cache.mu.Unlock()
	if hit {
		return cachedSnapshot, cachedCanonical, cachedFingerprint, nil
	}
	snapshot, err := s.buildFullSnapshot(ctx, tx)
	if err != nil {
		return models.ClusterSnapshot{}, nil, "", err
	}
	canonicalSnapshot := snapshot
	canonicalSnapshot.Fingerprint = ""
	canonicalSnapshot.Signature = ""
	canonicalSnapshot.CanonicalPayload = nil
	// 指纹与 users 节哈希同一口径：清零 last_login / last_used（节点本地记账），
	// 避免主节点登录或密钥使用即改变指纹、触发从节点全量重拉窗口。
	canonicalSnapshot.Users = sanitizeUsersForHash(snapshot.Users)
	canonicalSnapshot.APIKeys = sanitizeAPIKeysForHash(snapshot.APIKeys)
	canonical, err := json.Marshal(canonicalSnapshot)
	if err != nil {
		return models.ClusterSnapshot{}, nil, "", fmt.Errorf("序列化集群快照: %w", err)
	}
	hash := sha256.Sum256(canonical)
	fingerprint := hex.EncodeToString(hash[:])
	if err := tx.Commit(); err != nil {
		return models.ClusterSnapshot{}, nil, "", fmt.Errorf("提交集群快照事务: %w", err)
	}
	cache.mu.Lock()
	cache.initialized = true
	cache.version = snapshot.Version
	cache.snapshot = snapshot
	cache.canonical = canonical
	cache.fingerprint = fingerprint
	cache.ownership = ownershipHash
	cache.switches = switchesKey
	cache.expiresAt = nearestSnapshotCertificateExpiry(snapshot.Certs, now)
	cache.mu.Unlock()
	return snapshot, canonical, fingerprint, nil
}

// buildFullSnapshot 完成快照构建与后处理（WAF 引用、主节点开关镜像、节哈希、
// schema 版本、ACME 状态自校验），不触碰缓存。缓存命中路径与绕过路径共用此
// 实现，保证两者产出一致的 SectionHashes 等字段。
func (s *ClusterService) buildFullSnapshot(ctx context.Context, store snapshotStore) (models.ClusterSnapshot, error) {
	snapshot, err := s.buildSnapshot(ctx, store)
	if err != nil {
		return models.ClusterSnapshot{}, err
	}
	snapshot.WafFiles = BuildWafFileRef()
	// 与缓存键侧同口径——读不到权威开关时不得发布 nil 开关快照。
	// 走调用方 store（cachedSnapshot 的 tx），与快照内容同事务视图。
	switches, err := readSyncSwitches(ctx, store)
	if err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("读取主节点同步开关: %w", err)
	}
	snapshot.MasterSyncSwitches = &models.ClusterSyncSwitchesPayload{
		Users: switches.Users, Rules: switches.Rules, Security: switches.Security,
	}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	snapshot.SchemaVersion = CurrentSnapshotSchema
	snapshot.MinReaderVersion = CurrentSnapshotSchema
	// 主节点与从节点共用同一 ACME 状态校验：结构性不一致（缺区段/字段不全）
	// 会被从节点拒绝，此处提前校验并记录错误以提升主节点可见性，但仍照常
	// 发布。单规则/单证书损坏（acme_config_id=0、悬挂配置、悬挂 CA 提供商
	// 引用）两侧均为 warn 跳过，不阻断同步。
	if err := validateSnapshotACMEState(snapshot); err != nil {
		Logf("error", "cluster snapshot self-validation failed (still publishing): %v", err)
	}
	return snapshot, nil
}

// clusterSnapshotForApply 绕过共享快照缓存，为 apply 的 previous 备份读取
// 当前库状态。缓存键为 cluster_version/所有权/开关，从节点本地写入（如
// users.last_login）不会递增 cluster_version，稳态下缓存永不失效，命中缓存
// 会把真实漂移掩盖掉——因此本路径必须直读库，不能复用 cachedSnapshot。
// 装载面刻意收敛到 apply 的实际消费面（见函数内注释），不再全量构建。
func (s *ClusterService) clusterSnapshotForApply(ctx context.Context) (models.ClusterSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("开启 apply 基线事务: %w", err)
	}
	defer tx.Rollback()
	var previous models.ClusterSnapshot
	// apply 的 previous 只消费三节哈希、证书轴与
	// ACME ownership（computeSectionSkips/recordAppliedSectionHashes 的
	// localHashes、snapshotCertsDiffer/removeMissingSnapshotCerts、
	// restoreSnapshotArtifacts）。此前复用全量快照装载，每次 apply（含补偿
	// 重拉循环）白做一次 CRS 树 tar.gz+sha256（BuildWafFileRef）与 xdb
	// 哈希——WafFiles 字段全程零消费。此处按消费面装载：节 payload 输入 +
	// 证书候选（X.509 解析是证书轴必需）+ ACME ownership；不调用
	// BuildWafFileRef。
	if err := s.loadSectionHashInputs(ctx, tx, &previous); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if previous.Certs, err = s.snapshotCertificates(ctx, tx); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if previous.ACME, err = s.snapshotACME(ctx, tx); err != nil {
		return models.ClusterSnapshot{}, err
	}
	// 节哈希与全量快照同源（sectionPayloadFor 单源），供 computeSectionSkips
	// 的本地重建口径比对；waf_files 不在 syncSections，无需 BuildWafFileRef。
	previous.SectionHashes = ComputeSnapshotSectionHashes(&previous)
	if err := tx.Commit(); err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("提交 apply 基线事务: %w", err)
	}
	return previous, nil
}

// loadSectionHashInputs 装载 users/rules/security 三节哈希所需的全部输入
// （全局配置区 + 三节表域），与 buildSnapshot 共用同一装载函数族（哈希奇偶
// 不变式）。漂移守卫与 apply 基线共用本函数，避免两套「哪些列进哈希」的
// 平行清单——家族收敛点。
func (s *ClusterService) loadSectionHashInputs(ctx context.Context, store snapshotStore, snapshot *models.ClusterSnapshot) error {
	// 三分类合并:users 节 payload 含 basic_settings/caddy_config——必须装载
	// 全局配置区,且与 BuildSnapshot 复用同一装载函数(哈希奇偶不变式)。
	if err := s.loadSnapshotGlobalSettings(ctx, store, snapshot); err != nil {
		return err
	}
	var err error
	// (security 节 payload 为纯表域——文件态由 wafFilesDrifted 专用通道比对,
	// 与漂移守卫的轻量约束一致:不调用 BuildWafFileRef 的全树哈希。)
	if snapshot.Rules, err = s.snapshotRules(ctx, store); err != nil {
		return err
	}
	if snapshot.Users, err = s.snapshotUsers(ctx, store); err != nil {
		return err
	}
	if snapshot.APIKeys, err = s.snapshotAPIKeys(ctx, store); err != nil {
		return err
	}
	if snapshot.SecurityPolicies, err = s.snapshotSecurityPolicies(ctx, store); err != nil {
		return err
	}
	if snapshot.SecurityBindings, err = s.snapshotSecurityBindings(ctx, store); err != nil {
		return err
	}
	if snapshot.SecurityCustomRules, err = s.snapshotSecurityCustomRules(ctx, store); err != nil {
		return err
	}
	if snapshot.SecurityBlockPages, err = s.snapshotSecurityBlockPages(ctx, store); err != nil {
		return err
	}
	if snapshot.SecurityIPLists, err = s.snapshotSecurityIPLists(ctx, store); err != nil {
		return err
	}
	if snapshot.SecurityThreatSources, err = s.snapshotSecurityThreatSources(ctx, store); err != nil {
		return err
	}
	if snapshot.SecurityCrawlerSources, err = s.snapshotSecurityCrawlerSources(ctx, store); err != nil {
		return err
	}
	// CRS/IP2Region 版本行装载已删——版本行移出全部
	// 守卫节 payload(766f4c81 差分门控裁定)后此处为死装载,每 304 白扫
	// 2 表且引入无谓失败面。
	return nil
}

// driftGuardSectionHashes 仅重建漂移守卫三节（rules/users/security）的节哈希，
// 走只读事务、复用与全量快照完全一致的逐节 payload 构造（sectionPayloadFor）。
// 它刻意不调用 BuildWafFileRef（全量 CRS 树 tar.gz+sha256）与 snapshotCertificates
// （X.509 解析）：漂移比对只消费这三节的 SectionHashes，二者都不参与。
// 本函数在每次 304（默认 60s）都会执行，必须保持轻量。
//
// 哈希奇偶不变式（正确性不变量）：对三个守卫键，本函数返回值必须等于
// ComputeSnapshotSectionHashes(buildFullSnapshot())[key]——漂移比对拿轻量重建哈希
// 去对比全量快照路径写入的已应用记录，二者口径必须一致（由 sectionPayloadFor
// 共用同一 payload 构造保证）。
func (s *ClusterService) driftGuardSectionHashes(ctx context.Context) (map[string]string, error) {
	_, hashes, err := s.driftGuardSectionHashesWithVersion(ctx)
	return hashes, err
}

// driftGuardSectionHashesWithVersion 同 driftGuardSectionHashes，并返回哈希
// 内容所属的 cluster_version（loadSnapshotGlobalSettings 在同一只读事务内
// 读取）——版本与内容单次读取，供节哈希缓存以真实版本作键。
func (s *ClusterService) driftGuardSectionHashesWithVersion(ctx context.Context) (int, map[string]string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return 0, nil, fmt.Errorf("开启漂移守卫事务: %w", err)
	}
	defer tx.Rollback()

	var snapshot models.ClusterSnapshot
	// 装载失败语义与既有守卫节一致(报错上抛)。
	if err := s.loadSectionHashInputs(ctx, tx, &snapshot); err != nil {
		return 0, nil, err
	}
	if err := tx.Commit(); err != nil {
		return 0, nil, fmt.Errorf("提交漂移守卫事务: %w", err)
	}

	hashes := make(map[string]string, len(driftGuardSections))
	for _, key := range driftGuardSections {
		data, err := json.Marshal(sectionPayloadFor(key, &snapshot))
		if err != nil {
			return 0, nil, fmt.Errorf("序列化漂移守卫节 %s: %w", key, err)
		}
		sum := sha256.Sum256(data)
		hashes[key] = hex.EncodeToString(sum[:])
	}
	return snapshot.Version, hashes, nil
}

// emptyDNSOwnershipCanonical 是 DNS 所有权文件缺失/损坏时快照侧回退的空规范字节
// （与 ownership store 隔离后的空态一致）。
var emptyDNSOwnershipCanonical = []byte(`{"version":1,"records":[]}`)

// readSnapshotDNSOwnership 读取快照侧 DNS 所有权文件，供缓存键哈希（snapshotOwnershipHash）
// 与 ACME 区段（snapshotACME）共用。文件缺失按空规范字节继续（原语义）。文件损坏
// （JSON 解码失败或结构校验失败）同样回退空态，对齐 ownership.Store.load 的隔离语义
// （internal/dnsprovider/ownership/store.go：坏文件重命名 .corrupt-<unixts> 后按空态
// 继续——所有权文件是尽力而为的缓存，空分发可经幂等 not-found 删除与 75min stale
// 窗口自愈）。快照侧不执行重命名（避免与 store 的 fileMu 读改写竞态），仅告警一行；
// store 下一次 Add/Matching/Remove 触碰坏文件时会完成实际隔离，随后本函数自然走
// ErrNotExist 分支。其余读取错误（真实 I/O 故障）保持报错，不被空态掩盖。
func readSnapshotDNSOwnership(ctx context.Context, store snapshotStore) ([]byte, error) {
	dataDir, err := clusterSnapshotDataDir(ctx, store)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "acme_dns_ownership.json")
	content, readErr := os.ReadFile(path)
	if errors.Is(readErr, os.ErrNotExist) {
		return bytes.Clone(emptyDNSOwnershipCanonical), nil
	}
	if readErr != nil {
		return nil, fmt.Errorf("读取 DNS 所有权状态: %w", readErr)
	}
	if err := validateDNSOwnership(content); err != nil {
		// 本读取点随每次全量快照构建（主节点 ticker + 每个从节点
		// Pull）执行，坏文件在 store 侧实际隔离前持续存在——告警必须走
		// 60s 限流（数字归一键），否则每周期刷一条。
		throttledAuditFailureLogf("DNS 所有权文件 %s 损坏（%v），集群快照按空状态回退继续——对齐 ownership store 隔离语义，store 下次触碰该文件时完成隔离", path, err)
		return bytes.Clone(emptyDNSOwnershipCanonical), nil
	}
	return content, nil
}

func snapshotOwnershipHash(ctx context.Context, store snapshotStore) ([sha256.Size]byte, error) {
	content, err := readSnapshotDNSOwnership(ctx, store)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(content), nil
}

// snapshotCertMissingExpiryWindow 是 ACME 证书缺失 expires_at 时的最小缓存重建窗口：
// 缺失过期时间的证书无法参与有效期判定，若直接返回 now 会使缓存永远命中失败、每次
// 从节点 Pull 都重建全量快照；给定 30s 窗口把自愈重试节奏限制在该周期内。
const snapshotCertMissingExpiryWindow = 30 * time.Second

func nearestSnapshotCertificateExpiry(certificates []models.ClusterCertificate, now time.Time) time.Time {
	var nearest time.Time
	missingExpiry := false
	for _, certificate := range certificates {
		if certificate.ExpiresAt == "" {
			// 手工证书（Domain 为空）不做有效期过滤，不参与失效判定；ACME 证书
			// 缺失 expires_at 时给出最小重建窗口，避免每次 Pull 全量重建风暴，
			// 同时保留自愈尝试的节奏。
			if certificate.Domain != "" {
				missingExpiry = true
			}
			continue
		}
		expiresAt, err := parseSnapshotExpiry(certificate.ExpiresAt)
		// 解析失败视同缺失——唯一 ACME 证书 expires_at 非空
		// 不可解析时 nearest 保持零 → 缓存快照永不按时间过期 → ACME 续期不传播
		// 到副本。给最小重建窗口（ACME 域才计，避免非 ACME 误触发）。
		if err != nil {
			if certificate.Domain != "" {
				missingExpiry = true
			}
			continue
		}
		if nearest.IsZero() || expiresAt.Before(nearest) {
			nearest = expiresAt
		}
	}
	// 存在缺失过期时间的 ACME 证书时，重建窗口不能覆盖更早的真实到期时间：
	// 取「最近到期」与「缺失窗口」中更早者，避免较近的真实到期被 30s 窗口吞掉。
	if missingExpiry {
		rebuild := now.Add(snapshotCertMissingExpiryWindow)
		if nearest.IsZero() || rebuild.Before(nearest) {
			return rebuild
		}
	}
	// expires_at 列落在过去的证书（status<>'disabled' 且 pem 非空、叶
	// 证书仍有效，但列值是续期回写失败/带外导入的过期残留）会把缓存失效点钉
	// 在过去：now.Before(expiresAt) 恒 false → 每次快照都全量重建（X.509 解析
	// +marshal+sha256 全程持缓存锁）。触发器救不了——cert_jobs 触发器成员条件
	// 是 datetime(expires_at)>datetime('now')，过期的列值永不满足任一分支。
	// 钳制到缺失窗口：重建节奏收敛到 30s 一档；真正的续期传播由 UPDATE 触发
	// 器的 (old)OR(new) 分支覆盖——新证书写入未来 expires_at 必然递增
	// cluster_version，版本缓存键先行失效。零值（纯手工证书清单，无任何
	// 有效期凭证）不参与钳制：手工证书不按时间过期，变更由 lb_rules 触发器
	// 的版本键覆盖，保持缓存不过期语义。
	if !nearest.IsZero() && nearest.Before(now) {
		return now.Add(snapshotCertMissingExpiryWindow)
	}
	return nearest
}

// normalizeSnapshotDatetime 把源行时间列归一为平面 UTC 串（crsTimeLayout，
// 与 cert_jobs 写侧/读取侧同口径）。双布局解析（平面串 + RFC3339）后统一转
// UTC；无法解析（空/畸形）返回空串，由 apply 侧回落 DB 默认，避免把畸形源值
// 原样搬进从端。
func normalizeSnapshotDatetime(raw string) string {
	if raw == "" {
		return ""
	}
	parsed := parseUTCSlot(raw)
	if parsed.IsZero() {
		return ""
	}
	return parsed.UTC().Format(crsTimeLayout)
}

func parseSnapshotExpiry(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	if parsed := parseUTCSlot(value); !parsed.IsZero() {
		return parsed, nil
	}
	return time.Time{}, fmt.Errorf("无法解析证书过期时间 %q", value)
}

// normalizeSnapshotCaddyNumericSettings 归一快照携带的 Caddy 全局数值设置
// （request_body_max_size_mb / 三类 HTTP 超时 / caddy_log_size_mb）。
// 主端装载侧（loadSnapshotGlobalSettings）与从端 apply 侧
// （updateSnapshotSettings）必须共用本函数：仅在场但非法的值被归一，nil 保持
// nil（旧主端缺席语义）；单边归一会让 users 节哈希主从恒不等，每次版本递增
// 多一轮「配置无变化但本地数据不一致」的全量重拉与重载。
func normalizeSnapshotCaddyNumericSettings(settings *models.ClusterBasicSettings) {
	if settings.RequestBodyMaxSizeMB != nil {
		normalized := *settings.RequestBodyMaxSizeMB
		if normalized <= 0 {
			normalized = db.DefaultRequestBodyMaxSizeMB
		} else if normalized > 4096 {
			normalized = 4096
		}
		settings.RequestBodyMaxSizeMB = &normalized
	}
	normalizePositive := func(field **int, fallback int) {
		if *field == nil || **field > 0 {
			return
		}
		*field = new(fallback)
	}
	normalizePositive(&settings.HTTPReadTimeout, db.DefaultHTTPReadTimeout)
	normalizePositive(&settings.HTTPWriteTimeout, db.DefaultHTTPWriteTimeout)
	normalizePositive(&settings.HTTPIdleTimeout, db.DefaultHTTPIdleTimeout)
	normalizePositive(&settings.CaddyLogSizeMB, db.DefaultCaddyLogSizeMB)
}

// normalizeSnapshotSecurityEventsRetentionDays 归一安全事件保留天数：
// 写侧只接受 1..MaxSecurityEventsRetentionDays（handlers/caddy.go），
// 0/越界只可能带外产生——读侧按默认值消费，快照与 apply 必须同口径。
func normalizeSnapshotSecurityEventsRetentionDays(days int) int {
	if days <= 0 || days > db.MaxSecurityEventsRetentionDays {
		return securityEventsRetentionDefaultDays
	}
	return days
}

// normalizeSnapshotSecurityEventsRowCap 归一安全事件行数上限，判据同上。
func normalizeSnapshotSecurityEventsRowCap(rowCap int) int {
	if rowCap <= 0 || rowCap > db.MaxSecurityEventsRowCap {
		return securityEventsRetentionDefaultMax
	}
	return rowCap
}

// normalizeSnapshotThreatTrafficSampleN 归一威胁大屏采样口径：合法域只有
// -1（自适应）与 0（关闭），其余归默认（写侧白名单同源）。
func normalizeSnapshotThreatTrafficSampleN(sample int) int {
	if sample != db.DefaultThreatTrafficSampleN && sample != 0 {
		return db.DefaultThreatTrafficSampleN
	}
	return sample
}

// normalizeSnapshotSecurityRetentionSettings 归一安全事件保留/采样三列。
// 主端装载侧（loadSnapshotGlobalSettings）与从端 apply 侧
// （updateSnapshotSettings）必须共用本函数：从端 apply 会把 0/越界值归一后
// 落库并重算 users 节哈希，主端若按脏值算哈希，两边恒不等——每同步周期强制
// 重放 users 节并重载 Caddy（一次性启动回填 marker 置位后永不收敛）。
// nil 保持 nil（旧主端缺席语义）。
func normalizeSnapshotSecurityRetentionSettings(settings *models.ClusterBasicSettings) {
	if settings.SecurityEventsRetentionDays != nil {
		normalized := normalizeSnapshotSecurityEventsRetentionDays(*settings.SecurityEventsRetentionDays)
		settings.SecurityEventsRetentionDays = &normalized
	}
	if settings.SecurityEventsRowCap != nil {
		normalized := normalizeSnapshotSecurityEventsRowCap(*settings.SecurityEventsRowCap)
		settings.SecurityEventsRowCap = &normalized
	}
	if settings.ThreatTrafficSampleN != nil {
		normalized := normalizeSnapshotThreatTrafficSampleN(*settings.ThreatTrafficSampleN)
		settings.ThreatTrafficSampleN = &normalized
	}
}

// loadSnapshotGlobalSettings 装载快照的全局配置区(BasicSettings+
// CaddyConfig,含 branding 镜像与 Caddy 全局列)——buildSnapshot(全量快照)
// 与 driftGuardSectionHashes(漂移守卫三节重建)共用同一装载函数:三分类
// 合并后 users 节 payload 含 basic_settings/caddy_config,两侧列清单分叉
// 即哈希口径分叉(奇偶不变式被破坏),不得另写第二套列清单。
// 三分类合并(2026-09-19):全局配置并入系统数据节(恒同步)——装载不再受
// sync_global_config 开关裁剪(列已删除,快照恒携带)。
func (s *ClusterService) loadSnapshotGlobalSettings(ctx context.Context, store snapshotStore, snapshot *models.ClusterSnapshot) error {
	// 证书到期/续签天数/重试次数三列兜底统一绑定 db.Default*（消费点族单源，
	// 读侧禁字面量回流；其余既有批 1+2 口径见各 COALESCE 注释）。
	// global_config.dns_credentials 已退役（列由启动迁移删除，凭证唯一来源是
	// certificate_configs.dns_credentials 并随 ACME 节同步）——不在本清单内。
	var caddyConfig string
	var brandingJSON string
	err := store.QueryRowContext(ctx, `SELECT COALESCE(cluster_version,0), COALESCE(caddy_config,'{}'), COALESCE(branding_json,''),
		COALESCE(log_level,'info'),
		COALESCE(task_log_size_mb,10), COALESCE(audit_log_size_mb,10), COALESCE(runtime_log_size_mb,100), COALESCE(audit_retention_months,3), COALESCE(jwt_expire_minutes,20), COALESCE(timezone,?),
		COALESCE(acme_email,''), COALESCE(cert_expiry_days,?), COALESCE(cert_renewal_days,?), COALESCE(cert_renewal_attempts,?),
		COALESCE(default_ca_provider_id,0), COALESCE(dns_provider,''), COALESCE(sync_interval,60),
		COALESCE(admin_tls_enabled,0), COALESCE(admin_tls_mode,'selfsigned'), COALESCE(admin_tls_cert,''), COALESCE(admin_tls_key,''),
		COALESCE(mfa_write_guard,0), COALESCE(mfa_lockout_enabled,0), COALESCE(github_proxy_url,'https://v4.gh-proxy.org/'),
		COALESCE(oidc_config,'')
		FROM global_config WHERE id=1`, db.DefaultTimezone, db.DefaultCertExpiryDays, db.DefaultCertRenewalDays, db.DefaultCertRenewalAttempts).Scan(&snapshot.Version, &caddyConfig, &brandingJSON,
		&snapshot.BasicSettings.LogLevel,
		&snapshot.BasicSettings.TaskLogSizeMB, &snapshot.BasicSettings.AuditLogSizeMB, &snapshot.BasicSettings.RuntimeLogSizeMB, &snapshot.BasicSettings.AuditRetentionMonths, &snapshot.BasicSettings.JWTExpireMinutes, &snapshot.BasicSettings.Timezone,
		&snapshot.BasicSettings.ACMEEmail, &snapshot.BasicSettings.CertExpiryDays, &snapshot.BasicSettings.CertRenewalDays, &snapshot.BasicSettings.CertRenewalAttempts,
		&snapshot.BasicSettings.DefaultCAProviderID, &snapshot.BasicSettings.DNSProvider, &snapshot.BasicSettings.SyncInterval,
		&snapshot.BasicSettings.AdminTLSEnabled, &snapshot.BasicSettings.AdminTLSMode, &snapshot.BasicSettings.AdminTLSCert, &snapshot.BasicSettings.AdminTLSKey,
		&snapshot.BasicSettings.MFAWriteGuard, &snapshot.BasicSettings.MFALockoutEnabled, &snapshot.BasicSettings.GitHubProxyURL, &snapshot.BasicSettings.OIDCConfig)
	if err != nil {
		return fmt.Errorf("读取集群基础设置: %w", err)
	}
	// 主端装载侧同口径归一——从端 apply 时会对 sync_interval
	// 归一后落库并重建节哈希，主端若按脏值（<10 / >86400）算哈希，两边恒不等，
	// 每次版本递增都会重放 users 节并触发一次漂移补偿全量重拉。
	if snapshot.BasicSettings.SyncInterval != nil {
		normalized := normalizeSyncInterval(*snapshot.BasicSettings.SyncInterval)
		snapshot.BasicSettings.SyncInterval = &normalized
	}
	// 同族剩余两列：apply 侧会归一后落库并重建节哈希，主端装载侧必须同口径，
	// 否则带外写入的上限越界值（运行期直改库）让 users 节哈希主从恒不等。
	if snapshot.BasicSettings.JWTExpireMinutes != nil {
		normalized := normalizeJWTExpireMinutes(*snapshot.BasicSettings.JWTExpireMinutes)
		snapshot.BasicSettings.JWTExpireMinutes = &normalized
	}
	if snapshot.BasicSettings.CertExpiryDays != nil {
		normalized := normalizeCertExpiryDays(*snapshot.BasicSettings.CertExpiryDays)
		snapshot.BasicSettings.CertExpiryDays = &normalized
	}
	snapshot.BasicSettings.BrandingJSON = new(brandingJSON)
	snapshot.CaddyConfig = &caddyConfig
	if err := store.QueryRowContext(ctx, `SELECT COALESCE(caddy_log_level,'info'), COALESCE(caddy_log_size_mb,100),
		COALESCE(access_log_json,1), COALESCE(access_log_format,''),
		COALESCE(request_body_max_size_mb,0), COALESCE(http_read_timeout,60), COALESCE(http_write_timeout,60), COALESCE(http_idle_timeout,120),
		COALESCE(upstream_keepalive_timeout,0),
		COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
		COALESCE(server_tokens_hidden,0),
		COALESCE(trusted_proxy_enabled,0), COALESCE(trusted_proxy_ranges,'[]'), COALESCE(trusted_proxy_range_refs,'[]'), COALESCE(trusted_proxy_headers,'[]'), COALESCE(trusted_proxy_strict,1)
		FROM global_config WHERE id=1`).Scan(
		&snapshot.BasicSettings.CaddyLogLevel, &snapshot.BasicSettings.CaddyLogSizeMB,
		&snapshot.BasicSettings.AccessLogJSON, &snapshot.BasicSettings.AccessLogFormat,
		&snapshot.BasicSettings.RequestBodyMaxSizeMB, &snapshot.BasicSettings.HTTPReadTimeout, &snapshot.BasicSettings.HTTPWriteTimeout, &snapshot.BasicSettings.HTTPIdleTimeout,
		&snapshot.BasicSettings.UpstreamKeepaliveTimeout,
		&snapshot.BasicSettings.ProxyDialTimeout, &snapshot.BasicSettings.ProxyResponseHeaderTimeout, &snapshot.BasicSettings.ProxyReadTimeout, &snapshot.BasicSettings.ProxyWriteTimeout, &snapshot.BasicSettings.ProxyStreamTimeout, &snapshot.BasicSettings.ProxyFlushInterval, &snapshot.BasicSettings.ProxyStreamCloseDelay,
		&snapshot.BasicSettings.ServerTokensHidden,
		&snapshot.BasicSettings.TrustedProxyEnabled, &snapshot.BasicSettings.TrustedProxyRanges, &snapshot.BasicSettings.TrustedProxyRangeRefs, &snapshot.BasicSettings.TrustedProxyHeaders, &snapshot.BasicSettings.TrustedProxyStrict); err != nil {
		return fmt.Errorf("读取 Caddy 全局设置: %w", err)
	}
	// 主端装载侧与从端 apply 侧共用同一归一：任一侧单边归一都会让 users 节
	// 哈希主从恒不等（每次版本递增多一轮漂移补偿全量重拉 + 一条自愈审计）。
	normalizeSnapshotCaddyNumericSettings(&snapshot.BasicSettings)
	// 自动备份六设置列随 users 节同步。指针形态装载,
	// COALESCE 兜底使主端快照恒携带(非 nil);last_run 为节点本地运行态,
	// 刻意不在此装载(调度器每轮推进,参与哈希会让 users 节每轮抖动)。
	var abEnabled bool
	var abFrequency, abTime, abSections string
	var abDay, abKeep int
	if err := store.QueryRowContext(ctx, `SELECT COALESCE(auto_backup_enabled,0), COALESCE(auto_backup_frequency,'daily'),
		COALESCE(auto_backup_time,'03:00'), COALESCE(auto_backup_day,1), COALESCE(auto_backup_keep,7),
		COALESCE(auto_backup_sections,?)
		FROM global_config WHERE id=1`, db.DefaultAutoBackupSections).Scan(&abEnabled, &abFrequency, &abTime, &abDay, &abKeep, &abSections); err != nil {
		return fmt.Errorf("读取自动备份设置: %w", err)
	}
	snapshot.BasicSettings.AutoBackupEnabled = &abEnabled
	snapshot.BasicSettings.AutoBackupFrequency = &abFrequency
	snapshot.BasicSettings.AutoBackupTime = &abTime
	snapshot.BasicSettings.AutoBackupDay = &abDay
	snapshot.BasicSettings.AutoBackupKeep = &abKeep
	snapshot.BasicSettings.AutoBackupSections = &abSections
	// 威胁库任务级排程三列随 users 节同步（镜像
	// 自动备份组：指针装载+COALESCE 兜底恒携带，升主即生效）。
	var threatAuto bool
	var threatDays, threatTime string
	if err := store.QueryRowContext(ctx, `SELECT COALESCE(threat_auto_update,1),
		COALESCE(threat_schedule_days,'1,2,3,4,5,6,7'), COALESCE(threat_schedule_time,'04:00')
		FROM global_config WHERE id=1`).Scan(&threatAuto, &threatDays, &threatTime); err != nil {
		return fmt.Errorf("读取威胁库排程设置: %w", err)
	}
	snapshot.BasicSettings.ThreatAutoUpdate = &threatAuto
	snapshot.BasicSettings.ThreatScheduleDays = &threatDays
	snapshot.BasicSettings.ThreatScheduleTime = &threatTime
	// 爬虫地址库独立总闸与排程三列（不共享 threat_* 通道）。
	var crawlerAuto bool
	var crawlerDays, crawlerTime string
	if err := store.QueryRowContext(ctx, `SELECT COALESCE(crawler_auto_update,1),
		COALESCE(crawler_schedule_days,'1,2,3,4,5,6,7'), COALESCE(crawler_schedule_time,'04:00')
		FROM global_config WHERE id=1`).Scan(&crawlerAuto, &crawlerDays, &crawlerTime); err != nil {
		return fmt.Errorf("读取爬虫地址库排程设置: %w", err)
	}
	snapshot.BasicSettings.CrawlerAutoUpdate = &crawlerAuto
	snapshot.BasicSettings.CrawlerScheduleDays = &crawlerDays
	snapshot.BasicSettings.CrawlerScheduleTime = &crawlerTime
	// v2.3.8：安全事件保留与大屏采样随 users 节同步（从节点/升主后口径一致）。
	var seDays, seCap, trafficSample int
	var screenMode string
	if err := store.QueryRowContext(ctx, `SELECT COALESCE(security_events_retention_days,?),
		COALESCE(security_events_row_cap,?), COALESCE(threat_traffic_sample_n,?),
		COALESCE(threat_screen_mode,?)
		FROM global_config WHERE id=1`,
		db.DefaultSecurityEventsRetentionDays, db.DefaultSecurityEventsRowCap, db.DefaultThreatTrafficSampleN, db.DefaultThreatScreenMode).Scan(&seDays, &seCap, &trafficSample, &screenMode); err != nil {
		return fmt.Errorf("读取安全事件保留/流量采样设置: %w", err)
	}
	snapshot.BasicSettings.SecurityEventsRetentionDays = &seDays
	snapshot.BasicSettings.SecurityEventsRowCap = &seCap
	snapshot.BasicSettings.ThreatTrafficSampleN = &trafficSample
	// 三列与 apply 侧同口径归一（库值唯一真相：0/越界值读侧本按默认消费，
	// 哈希输入必须同源）。写侧只接受合法域，脏值仅带外直写可达——若按脏值
	// 参与 users 节哈希，从端 apply 落默认后主从哈希恒不等，每同步周期强制
	// 重放 users 节并重载 Caddy，且一次性启动回填 marker 使重启也不收敛。
	normalizeSnapshotSecurityRetentionSettings(&snapshot.BasicSettings)
	// 主端装载侧同口径归一（与 sync_interval 同理由）：从端 apply 会把非法
	// 枚举归为默认后落库并重算节哈希；主端若按脏值算哈希，两边恒不等，
	// 每次版本递增都重放 users 节。
	if !models.IsValidThreatScreenMode(screenMode) {
		screenMode = db.DefaultThreatScreenMode
	}
	snapshot.BasicSettings.ThreatScreenMode = &screenMode

	// 自动封禁六项配置随 users 节同步（镜像
	// 指针装载+COALESCE 兜底恒携带，升主即按主端配置生效）。局部名 abn* 与上方
	// 自动备份组 ab* 区分（同一函数作用域）。
	var abnEnabled, abnDryRun bool
	var abnThreshold, abnWindow int
	var abnDuration, abnScope string
	if err := store.QueryRowContext(ctx, `SELECT COALESCE(autoban_enabled,0), COALESCE(autoban_threshold,100),
		COALESCE(autoban_window_minutes,5), COALESCE(autoban_duration,'1h'), COALESCE(autoban_scope,'all'), COALESCE(autoban_dry_run,1)
		FROM global_config WHERE id=1`).Scan(&abnEnabled, &abnThreshold, &abnWindow, &abnDuration, &abnScope, &abnDryRun); err != nil {
		return fmt.Errorf("读取自动封禁设置: %w", err)
	}
	snapshot.BasicSettings.AutobanEnabled = &abnEnabled
	snapshot.BasicSettings.AutobanThreshold = &abnThreshold
	snapshot.BasicSettings.AutobanWindowMinutes = &abnWindow
	snapshot.BasicSettings.AutobanDuration = &abnDuration
	snapshot.BasicSettings.AutobanScope = &abnScope
	snapshot.BasicSettings.AutobanDryRun = &abnDryRun
	return nil
}

func (s *ClusterService) buildSnapshot(ctx context.Context, store snapshotStore) (models.ClusterSnapshot, error) {
	var snapshot models.ClusterSnapshot
	var err error
	if err = s.loadSnapshotGlobalSettings(ctx, store, &snapshot); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.Rules, err = s.snapshotRules(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.Users, err = s.snapshotUsers(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.APIKeys, err = s.snapshotAPIKeys(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.LockedUsers, err = s.snapshotLockedUsers(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.NodeSites, err = s.snapshotNodeSites(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.Certs, err = s.snapshotCertificates(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.ACME, err = s.snapshotACME(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityPolicies, err = s.snapshotSecurityPolicies(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityBindings, err = s.snapshotSecurityBindings(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityCustomRules, err = s.snapshotSecurityCustomRules(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityBlockPages, err = s.snapshotSecurityBlockPages(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityIPLists, err = s.snapshotSecurityIPLists(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityCRSVersion, err = s.snapshotSecurityCRSVersion(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityIP2RegionVersion, err = s.snapshotSecurityIP2RegionVersion(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityThreatSources, err = s.snapshotSecurityThreatSources(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityCrawlerSources, err = s.snapshotSecurityCrawlerSources(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	return snapshot, nil
}

func (s *ClusterService) snapshotNodeSites(ctx context.Context, store snapshotStore) (map[int]models.ClusterNodeSite, error) {
	var masterLat, masterLon float64
	if err := store.QueryRowContext(ctx, `SELECT COALESCE(server_map_lat,0), COALESCE(server_map_lon,0) FROM global_config WHERE id=1`).Scan(&masterLat, &masterLon); err != nil {
		return nil, fmt.Errorf("读取主节点默认站点坐标: %w", err)
	}
	rows, err := store.QueryContext(ctx, `SELECT id, COALESCE(server_map_lat,0), COALESCE(server_map_lon,0) FROM nodes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取节点站点坐标: %w", err)
	}
	defer rows.Close()
	sites := make(map[int]models.ClusterNodeSite)
	for rows.Next() {
		var id int
		var site models.ClusterNodeSite
		if err := rows.Scan(&id, &site.ServerMapLat, &site.ServerMapLon); err != nil {
			return nil, fmt.Errorf("扫描节点站点坐标: %w", err)
		}
		// 未单独配置的从节点继承主节点坐标；主节点也未配置时保持 0,0。
		if site.ServerMapLat == 0 && site.ServerMapLon == 0 {
			site.ServerMapLat = masterLat
			site.ServerMapLon = masterLon
		}
		sites[id] = site
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

func (s *ClusterService) snapshotSecurityPolicies(ctx context.Context, store snapshotStore) (json.RawMessage, error) {
	// 全部可空列 COALESCE（别名保持裸列名——dumpTableAsJSON 以列名为键，从节点
	// apply 按裸名取值）：主节点一行 NULL 不得经快照透传在从节点重新落 NULL；
	// 默认值与读路径归一化（scanSecurityPolicyByID/loadSecurityPolicyContext）
	// 逐项对齐，保证主节点生效行为与从节点落库行为一致（geoip_mode 归一化为
	// 'off' 而非 schema 默认 'deny' 即为此——主节点读路径把 NULL 当 'off'；
	// enabled 归一化为 0 而非 schema 默认 1 同理——读路径 WHERE enabled=1 把
	// NULL 当禁用，落 1 会让从节点执行主节点未启用的策略）。
	return s.dumpTableAsJSON(ctx, store, "security_policies", "id,name,COALESCE(description,'') AS description,COALESCE(mode,'off') AS mode,COALESCE(anomaly_threshold,5) AS anomaly_threshold,COALESCE(ip_acl_mode,'') AS ip_acl_mode,COALESCE(ip_acl_list,'[]') AS ip_acl_list,COALESCE(ip_acl_enabled,0) AS ip_acl_enabled,COALESCE(ip_whitelist,'[]') AS ip_whitelist, COALESCE(ip_whitelist_enabled,1) AS ip_whitelist_enabled,COALESCE(ip_blacklist,'[]') AS ip_blacklist,COALESCE(rate_limit_enabled,0) AS rate_limit_enabled,COALESCE(rate_limit_rps,0) AS rate_limit_rps,COALESCE(rate_limit_burst,0) AS rate_limit_burst,COALESCE(crs_rule_groups,'[]') AS crs_rule_groups,COALESCE(crs_excluded_rules,'[]') AS crs_excluded_rules,COALESCE(custom_rules,'[]') AS custom_rules,COALESCE(block_page_id,0) AS block_page_id,COALESCE(block_status_code,0) AS block_status_code,COALESCE(enabled,0) AS enabled,COALESCE(updated_by,0) AS updated_by,COALESCE(created_at,'') AS created_at,COALESCE(updated_at,'') AS updated_at,COALESCE(geoip_countries,'[]') AS geoip_countries,COALESCE(geoip_mode,'off') AS geoip_mode,COALESCE(geoip_crawler_exempt,0) AS geoip_crawler_exempt,COALESCE(geoip_crawler_engines,'[]') AS geoip_crawler_engines,COALESCE(waf_check_response,0) AS waf_check_response,COALESCE(log_request_body,0) AS log_request_body,COALESCE(ip_acl_list_refs,'[]') AS ip_acl_list_refs,COALESCE(ip_whitelist_refs,'[]') AS ip_whitelist_refs,COALESCE(policy_type,'') AS policy_type,COALESCE(trust_detection,0) AS trust_detection", "id")
}

// snapshotSecurityIPLists（v2.3.0）dump 可复用 IP 地址列表：策略 refs 引用
// 的目标表，NULL 归一口径与 security_policies 一致（entries '[]'、审计列
// 0/”），保证主从落库行为一致。
func (s *ClusterService) snapshotSecurityIPLists(ctx context.Context, store snapshotStore) (json.RawMessage, error) {
	// entries 空值归一 COALESCE('') →
	// '[]' 是**纠正方向**，不是等价改写——快照出口载荷字节由此改变（从端
	// restoreTable/快照版本哈希拿到的是 '[]' 而非 ''），「行为等价」仅在下游
	// 读路径再做一次 COALESCE 归一的前提下才成立（handlers 读路径
	// COALESCE(entries,'[]')/备份 restoreTableNullDefaults/自动封禁 merge 同
	// 归一），并非无差异 no-op。本点修正的是快照出口单点与全链 '[]' 单源
	// 口径的分叉。
	return s.dumpTableAsJSON(ctx, store, "security_ip_lists", "id,name,COALESCE(description,'') AS description,COALESCE(category,'') AS category,COALESCE(entries,'[]') AS entries,COALESCE(created_by,0) AS created_by,COALESCE(created_at,'') AS created_at,COALESCE(updated_by,0) AS updated_by,COALESCE(updated_at,'') AS updated_at,COALESCE(system,0) AS system", "id")
}

// snapshotSecurityThreatSources（v2.3.x）dump 威胁情报库源表：NULL 归一口径
// 与备份 restoreTable 写入侧（backupTableNullDefaults）逐列对齐——两条
// 「全量替换」通道对同一 NULL 行产出同一落库值。
func (s *ClusterService) snapshotSecurityThreatSources(ctx context.Context, store snapshotStore) (json.RawMessage, error) {
	return s.dumpTableAsJSON(ctx, store, "security_threat_sources",
		"id,name,COALESCE(display_name,'') AS display_name,COALESCE(url,'') AS url,COALESCE(format,'plain') AS format,COALESCE(update_enabled,1) AS update_enabled,COALESCE(apply_enabled,1) AS apply_enabled,COALESCE(entry_count,0) AS entry_count,COALESCE(version,'') AS version,COALESCE(update_status,'idle') AS update_status,COALESCE(message,'') AS message,COALESCE(last_checked,'') AS last_checked,COALESCE(next_update,'') AS next_update,COALESCE(trigger,'') AS trigger,COALESCE(started_at,'') AS started_at,COALESCE(finished_at,'') AS finished_at,COALESCE(consecutive_failures,0) AS consecutive_failures,COALESCE(created_at,'') AS created_at,COALESCE(updated_at,'') AS updated_at", "id")
}

// snapshotSecurityCrawlerSources dump 爬虫地址库独立源表（无 apply_enabled/
// content_hash 列，其余状态机字段与威胁源同形）。
func (s *ClusterService) snapshotSecurityCrawlerSources(ctx context.Context, store snapshotStore) (json.RawMessage, error) {
	return s.dumpTableAsJSON(ctx, store, "security_crawler_sources",
		"id,name,COALESCE(display_name,'') AS display_name,COALESCE(url,'') AS url,COALESCE(format,'plain') AS format,COALESCE(update_enabled,1) AS update_enabled,COALESCE(entry_count,0) AS entry_count,COALESCE(version,'') AS version,COALESCE(update_status,'idle') AS update_status,COALESCE(message,'') AS message,COALESCE(last_checked,'') AS last_checked,COALESCE(next_update,'') AS next_update,COALESCE(trigger,'') AS trigger,COALESCE(started_at,'') AS started_at,COALESCE(finished_at,'') AS finished_at,COALESCE(consecutive_failures,0) AS consecutive_failures,COALESCE(created_at,'') AS created_at,COALESCE(updated_at,'') AS updated_at", "id")
}

func (s *ClusterService) snapshotSecurityBindings(ctx context.Context, store snapshotStore) (json.RawMessage, error) {
	return s.dumpTableAsJSON(ctx, store, "security_policy_bindings", "rule_caddy_id,policy_id", "rule_caddy_id, policy_id")
}

func (s *ClusterService) snapshotSecurityCustomRules(ctx context.Context, store snapshotStore) ([]models.SecurityCustomRule, error) {
	rows, err := store.QueryContext(ctx, `SELECT id,name,COALESCE(description,''),COALESCE(conditions,'[]'),COALESCE(NULLIF(condition_logic,''),'and'),COALESCE(action,'block'),COALESCE(score,5),COALESCE(enabled,1),COALESCE(updated_by,0),COALESCE(created_at,''),COALESCE(updated_at,'') FROM security_custom_rules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照自定义安全规则: %w", err)
	}
	defer rows.Close()
	rules := make([]models.SecurityCustomRule, 0)
	for rows.Next() {
		var rule models.SecurityCustomRule
		var conditionsJSON string
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Description, &conditionsJSON, &rule.ConditionLogic, &rule.Action, &rule.Score, &rule.Enabled, &rule.UpdatedBy, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照自定义安全规则: %w", err)
		}
		if err := json.Unmarshal([]byte(conditionsJSON), &rule.Conditions); err != nil {
			// 单行损坏不得整包 500——隔离该行（不下发），健康行照常发布。
			warnCorruptedSnapshotRow("security_custom_rules", rule.ID, err)
			continue
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (s *ClusterService) snapshotSecurityBlockPages(ctx context.Context, store snapshotStore) ([]models.SecurityBlockPage, error) {
	rows, err := store.QueryContext(ctx, `SELECT id,name,COALESCE(description,''),COALESCE(content,''),COALESCE(content_type,''),COALESCE(is_default,0),COALESCE(is_builtin,0),COALESCE(created_by,0),COALESCE(created_at,''),COALESCE(updated_by,0),COALESCE(updated_at,'') FROM security_block_pages ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照拦截页面: %w", err)
	}
	defer rows.Close()
	pages := make([]models.SecurityBlockPage, 0)
	for rows.Next() {
		var page models.SecurityBlockPage
		if err := rows.Scan(&page.ID, &page.Name, &page.Description, &page.Content, &page.ContentType, &page.IsDefault, &page.IsBuiltin, &page.CreatedBy, &page.CreatedAt, &page.UpdatedBy, &page.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照拦截页面: %w", err)
		}
		pages = append(pages, page)
	}
	return pages, rows.Err()
}

// clusterRuleLibVersionColumns 是 CRS/IP2Region 版本行的列清单单源
// 快照导出、差分本地读取、从端写侧三处此前
// 各抄一份（列增减需同时改 6 处， 已出现「快照列与差分行不同步」
// 教训）。两张表列清单/扫描顺序完全一致，共享本常量与下方中性行扫描。
const clusterRuleLibVersionColumns = `id,version,COALESCE(updated_at,''),COALESCE(auto_update,1),COALESCE(update_status,'idle'),COALESCE(message,''),COALESCE(last_checked,''),COALESCE(next_update,''),COALESCE(trigger,''),COALESCE(started_at,''),COALESCE(finished_at,''),COALESCE(schedule_days,'1,2,3,4,5,6,7'),COALESCE(schedule_time,'04:00')`

// clusterRuleLibVersionRow 是 CRS/IP2Region 版本行的中性投影：两模型字段与
// JSON 标签逐字段相同，故可无损转换为任一模型（差分比对按模型序列化，
// 保证与快照侧 JSON 字节口径一致）。
type clusterRuleLibVersionRow struct {
	ID           int
	Version      string
	UpdatedAt    string
	AutoUpdate   bool
	UpdateStatus string
	Message      string
	LastChecked  string
	NextUpdate   string
	Trigger      string
	StartedAt    string
	FinishedAt   string
	ScheduleDays string
	ScheduleTime string
}

func scanClusterRuleLibVersionRow(rows *sql.Rows) (clusterRuleLibVersionRow, error) {
	var row clusterRuleLibVersionRow
	err := rows.Scan(&row.ID, &row.Version, &row.UpdatedAt, &row.AutoUpdate, &row.UpdateStatus, &row.Message,
		&row.LastChecked, &row.NextUpdate, &row.Trigger, &row.StartedAt, &row.FinishedAt, &row.ScheduleDays, &row.ScheduleTime)
	return row, err
}

func (row clusterRuleLibVersionRow) crsVersion() models.ClusterSecurityCRSVersion {
	return models.ClusterSecurityCRSVersion{
		ID: row.ID, Version: row.Version, UpdatedAt: row.UpdatedAt, AutoUpdate: row.AutoUpdate,
		UpdateStatus: row.UpdateStatus, Message: row.Message, LastChecked: row.LastChecked,
		NextUpdate: row.NextUpdate, Trigger: row.Trigger, StartedAt: row.StartedAt,
		FinishedAt: row.FinishedAt, ScheduleDays: row.ScheduleDays, ScheduleTime: row.ScheduleTime,
	}
}

func (row clusterRuleLibVersionRow) ip2RegionVersion() models.ClusterSecurityIP2RegionVersion {
	return models.ClusterSecurityIP2RegionVersion{
		ID: row.ID, Version: row.Version, UpdatedAt: row.UpdatedAt, AutoUpdate: row.AutoUpdate,
		UpdateStatus: row.UpdateStatus, Message: row.Message, LastChecked: row.LastChecked,
		NextUpdate: row.NextUpdate, Trigger: row.Trigger, StartedAt: row.StartedAt,
		FinishedAt: row.FinishedAt, ScheduleDays: row.ScheduleDays, ScheduleTime: row.ScheduleTime,
	}
}

// readClusterRuleLibVersionRows 按共享列清单读取一张版本表（快照导出与
// 差分本地读取共用；ORDER BY id 保证两侧顺序一致）。
func readClusterRuleLibVersionRows(ctx context.Context, store snapshotStore, table string) ([]clusterRuleLibVersionRow, error) {
	rows, err := store.QueryContext(ctx, "SELECT "+clusterRuleLibVersionColumns+" FROM "+table+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]clusterRuleLibVersionRow, 0)
	for rows.Next() {
		row, err := scanClusterRuleLibVersionRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *ClusterService) snapshotSecurityCRSVersion(ctx context.Context, store snapshotStore) ([]models.ClusterSecurityCRSVersion, error) {
	// schedule_days/schedule_time 随版本行同步（升主即生效）。
	rows, err := readClusterRuleLibVersionRows(ctx, store, "security_crs_version")
	if err != nil {
		return nil, fmt.Errorf("读取快照 CRS 版本: %w", err)
	}
	versions := make([]models.ClusterSecurityCRSVersion, 0, len(rows))
	for _, row := range rows {
		versions = append(versions, row.crsVersion())
	}
	return versions, nil
}

func (s *ClusterService) snapshotSecurityIP2RegionVersion(ctx context.Context, store snapshotStore) ([]models.ClusterSecurityIP2RegionVersion, error) {
	// schedule_days/schedule_time 随版本行同步（升主即生效）。
	rows, err := readClusterRuleLibVersionRows(ctx, store, "security_ip2region_version")
	if err != nil {
		return nil, fmt.Errorf("读取快照 ip2region 版本: %w", err)
	}
	versions := make([]models.ClusterSecurityIP2RegionVersion, 0, len(rows))
	for _, row := range rows {
		versions = append(versions, row.ip2RegionVersion())
	}
	return versions, nil
}

// snapshotTime 把快照时间统一到秒：从端落库使用 crsTimeLayout（秒），
// 若主端哈希输入保留亚秒，主从节哈希永久不等并触发多余全量重拉
func snapshotTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC().Truncate(time.Second)
}

func (s *ClusterService) dumpTableAsJSON(ctx context.Context, store snapshotStore, table, columns, orderBy string) (json.RawMessage, error) {
	rows, err := store.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM %s ORDER BY %s", columns, table, orderBy))
	if err != nil {
		return nil, fmt.Errorf("读取 %s: %w", table, err)
	}
	defer rows.Close()
	colNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		values := make([]interface{}, len(colNames))
		ptrs := make([]interface{}, len(colNames))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]interface{})
		for i, col := range colNames {
			if t, ok := values[i].(time.Time); ok {
				row[col] = snapshotTime(t)
			} else {
				row[col] = values[i]
			}
		}
		result = append(result, row)
	}
	// Close() 只回报关闭错误，迭代错误必须经 rows.Err() 观测——静默截断的节
	// 会被签名+发布，从节点 DELETE+INSERT 放大为集群级静默删行。
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历 %s: %w", table, err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *ClusterService) snapshotACME(ctx context.Context, store snapshotStore) (*models.ClusterACMEState, error) {
	state := &models.ClusterACMEState{CAProviders: make([]models.CAProvider, 0), CertificateConfigs: make([]models.CertificateConfig, 0)}
	// ca_providers.enabled 的 NULL 语义与本地读侧同源（services/caproviders.go 的
	// COALESCE(enabled,0)，fail-closed）：所有取用门都是 `WHERE enabled=1`，NULL 本就
	// 不命中；导出成「启用」会让从节点把主节点读成禁用的同一行落成启用，主从切换后
	// 该提供商「自己启用」，与主节点此前的失败归因相反。
	rows, err := store.QueryContext(ctx, `SELECT id,name,provider,directory_url,COALESCE(credentials,''),COALESCE(max_concurrent,`+strconv.Itoa(db.DefaultCAProviderMaxConcurrent)+`),COALESCE(min_interval_ms,`+strconv.Itoa(db.DefaultCAProviderMinIntervalMS)+`),COALESCE(enabled,0),created_at,updated_at FROM ca_providers ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照 CA 提供商: %w", err)
	}
	for rows.Next() {
		var provider models.CAProvider
		if err := rows.Scan(&provider.ID, &provider.Name, &provider.Provider, &provider.DirectoryURL, &provider.Credentials, &provider.MaxConcurrent, &provider.MinIntervalMS, &provider.Enabled, &provider.CreatedAt, &provider.UpdatedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("扫描快照 CA 提供商: %w", err)
		}
		provider.CreatedAt = snapshotTime(provider.CreatedAt)
		provider.UpdatedAt = snapshotTime(provider.UpdatedAt)
		state.CAProviders = append(state.CAProviders, provider)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("遍历快照 CA 提供商: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("关闭 CA 提供商结果: %w", err)
	}

	// certificate_configs.enabled 与 ca_providers 刻意不同：本表的 NULL 语义是
	// 「启用」（与 handlers/certificates.go 的读取列表、certissuer.go 的绑定门
	// COALESCE(enabled,1) 同源），导出必须保持同一口径，否则主从读值分叉。
	rows, err = store.QueryContext(ctx, `SELECT id,name,COALESCE(dns_provider,'dnspod'),COALESCE(dns_credentials,''),COALESCE(enabled,1),created_at,updated_at FROM certificate_configs ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照证书配置: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var config models.CertificateConfig
		if err := rows.Scan(&config.ID, &config.Name, &config.DNSProvider, &config.DNSCredentials, &config.Enabled, &config.CreatedAt, &config.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照证书配置: %w", err)
		}
		config.CreatedAt = snapshotTime(config.CreatedAt)
		if config.UpdatedAt.Valid {
			config.UpdatedAt.Time = snapshotTime(config.UpdatedAt.Time)
		}
		state.CertificateConfigs = append(state.CertificateConfigs, config)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历快照证书配置: %w", err)
	}
	ownership, err := readSnapshotDNSOwnership(ctx, store)
	if err != nil {
		return nil, err
	}
	state.DNSOwnership = ownership
	return state, nil
}

// clusterSnapshotDataDir 经 PRAGMA database_list 定位数据目录；*sql.DB 天然满足
// snapshotStore 接口（QueryContext/QueryRowContext 签名一致），非事务调用方
// 直接传 *sql.DB 即可（Phase10 与原 clusterDatabaseDir 合一）。
func clusterSnapshotDataDir(ctx context.Context, store snapshotStore) (string, error) {
	var sequence int
	var name, databasePath string
	if err := store.QueryRowContext(ctx, "PRAGMA database_list").Scan(&sequence, &name, &databasePath); err != nil {
		return "", fmt.Errorf("读取集群数据库路径: %w", err)
	}
	if databasePath == "" {
		return "", errors.New("无法确定集群数据目录")
	}
	return filepath.Dir(databasePath), nil
}

func (s *ClusterService) snapshotRules(ctx context.Context, store snapshotStore) ([]models.LbRule, error) {
	// health_check_timeout 的 NULL 回退取 2，与渲染/写侧（rule_features/
	// caddy.go、UpdateRule 存量读取）同口径——快照仍导 5 会造成主节点实际行为（2）
	// 与下发值（5）分叉，且从节点回放会把 5 物化为非 NULL 值，永久固化错误口径。
	// rules 节哈希主从两侧同走本函数（主端导出 / 从端 driftGuardSectionHashes
	// 重建），同版本代码天然一致；滚动升级窗口内存量 NULL 行会引入一次性哈希
	// 抖动（旧从端按 5 重建 vs 新主端按 2 导出）→ 触发一轮全量重拉，回放把值
	// 物化为非 NULL 后自然收敛，无需额外迁移。
	rows, err := store.QueryContext(ctx, lbRuleSnapshotSelectSQL())
	if err != nil {
		return nil, fmt.Errorf("读取快照规则: %w", err)
	}
	defer rows.Close()

	upstreamsByRule, err := s.snapshotAllUpstreams(ctx, store)
	if err != nil {
		return nil, err
	}
	pathRulesByRule, err := s.snapshotAllPathRules(ctx, store)
	if err != nil {
		return nil, err
	}

	rules := make([]models.LbRule, 0)
	for rows.Next() {
		var rule models.LbRule
		// 扫描序=规范序（lbRuleColumnSpecs，与写侧 INSERT 列清单同源）。
		if err := rows.Scan(&rule.ID, &rule.CaddyID, &rule.Name, &rule.Description, &rule.Protocol, &rule.Domain, &rule.ListenPort,
			&rule.Strategy, &rule.DynamicDNS, &rule.EnableDnsServer, &rule.DnsServer, &rule.DnsFamily,
			&rule.HealthCheckPath, &rule.HealthCheckInterval, &rule.HealthCheckTimeout, &rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
			&rule.EnableActiveHealthCheck, &rule.TCPHealthCheckPort, &rule.TCPProxyProtocol, &rule.TCPTryDuration, &rule.TCPTryInterval,
			&rule.RequestBodyMaxSizeMB, &rule.UpstreamKeepaliveTimeout, &rule.ServerTokensHidden, &rule.NTLMCompatible, &rule.UpstreamForceHTTP1,
			&rule.CustomRoutesEnabled,
			&rule.ProxyDialTimeout, &rule.ProxyResponseHeaderTimeout, &rule.ProxyReadTimeout, &rule.ProxyWriteTimeout, &rule.ProxyStreamTimeout, &rule.ProxyFlushInterval, &rule.ProxyStreamCloseDelay,
			&rule.HostHeader, &rule.HealthCheckHost,
			&rule.EnableTLS, &rule.TLSSource, &rule.ACMEConfigID, &rule.CAProviderID, &rule.TLSCert, &rule.TLSKey,
			&rule.TLSHTTPRedirect, &rule.EnableCompress, &rule.CompressTypes, &rule.Enabled, &rule.LogEnabled,
			&rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt, &rule.UpdatedBy,
			&rule.BlockPageStage1ID, &rule.BlockPageStage1Status, &rule.BlockPageStage3ID, &rule.BlockPageStage3Status); err != nil {
			return nil, fmt.Errorf("扫描快照规则: %w", err)
		}
		// 与 path_rules/users/api_keys/ACME 逐行
		// 对称，规则时间戳截到秒（写侧 crsTimeLayout=秒/UTC）。仅启动迁移处理
		// 存量行，运行期导入/备份恢复/带外写入的亚秒或 +08:00 形态会让主端
		// 导出 JSON 与从端落库重建形态分叉 → rules 节哈希永久不等，每次主端
		// 版本递增多一轮全量重拉+强制重载。主从两侧同走本函数，归一无行为变化。
		rule.CreatedAt = snapshotTime(rule.CreatedAt)
		if rule.UpdatedAt.Valid {
			rule.UpdatedAt.Time = snapshotTime(rule.UpdatedAt.Time)
		}
		// 传输归一（单一事实源，2026-10-11）：body 钳制 + TCP 死形态 + TCP
		// 七字段——导出侧与从端 insertSnapshotRules 共用 normalizeRuleForTransport。
		// 历史事故：两处平行手写归一块改一侧漏另一侧，主从 canonical 不同形，
		// 「分区滞后」在 304 稳态下永不自愈。
		normalizeRuleForTransport(&rule)
		rule.Upstreams = upstreamsByRule[rule.CaddyID]
		if rule.Upstreams == nil {
			rule.Upstreams = make([]models.Upstream, 0)
		}
		rule.PathRules = pathRulesByRule[rule.CaddyID]
		if rule.PathRules == nil {
			rule.PathRules = make([]models.PathRule, 0)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历快照规则: %w", err)
	}
	return rules, nil
}

func (s *ClusterService) snapshotAllUpstreams(ctx context.Context, store snapshotStore) (map[string][]models.Upstream, error) {
	rows, err := store.QueryContext(ctx, `SELECT u.id, u.rule_id, u.host, u.port, COALESCE(u.weight,1), COALESCE(u.dynamic_dns,0), IIF(u.enabled IN ('1',1),1,0), COALESCE(u.protocol,'http'), COALESCE(u.max_connections,0), COALESCE(u.origin_domain,''), COALESCE(r.protocol,'') FROM upstreams u LEFT JOIN lb_rules r ON r.caddy_id = u.rule_id ORDER BY u.rule_id, u.id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照上游: %w", err)
	}
	defer rows.Close()
	byRule := make(map[string][]models.Upstream)
	for rows.Next() {
		var upstream models.Upstream
		var ruleProtocol string
		if err := rows.Scan(&upstream.ID, &upstream.RuleID, &upstream.Host, &upstream.Port, &upstream.Weight, &upstream.DynamicDNS, &upstream.Enabled, &upstream.Protocol, &upstream.MaxConnections, &upstream.OriginDomain, &ruleProtocol); err != nil {
			return nil, fmt.Errorf("扫描快照上游: %w", err)
		}
		// 上游传输归一（单一事实源）：dynamic_dns 废弃列与写侧恒 0 同口径、
		// TCP 规则的回源域名按「仅 HTTP 消费」清零，与从端落库/重建同形
		// （rules 节哈希主从相等的前提）。
		normalizeUpstreamForTransport(&upstream, ruleProtocol)
		byRule[upstream.RuleID] = append(byRule[upstream.RuleID], upstream)
	}
	return byRule, rows.Err()
}

func (s *ClusterService) snapshotAllPathRules(ctx context.Context, store snapshotStore) (map[string][]models.PathRule, error) {
	rows, err := store.QueryContext(ctx, `SELECT id, rule_id, sort_order, match_type, path, upstream_path, upstreams_json, response_mode, response_status, response_body, response_content_type, redirect_to, created_at, updated_at FROM path_rules ORDER BY rule_id, sort_order, id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照路径规则: %w", err)
	}
	defer rows.Close()
	byRule := make(map[string][]models.PathRule)
	for rows.Next() {
		var pathRule models.PathRule
		var upstreamsJSON sql.NullString
		if err := rows.Scan(&pathRule.ID, &pathRule.RuleID, &pathRule.SortOrder, &pathRule.MatchType, &pathRule.Path, &pathRule.UpstreamPath, &upstreamsJSON,
			&pathRule.ResponseMode, &pathRule.ResponseStatus, &pathRule.ResponseBody, &pathRule.ResponseContentType, &pathRule.RedirectTo, &pathRule.CreatedAt, &pathRule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照路径规则: %w", err)
		}
		pathRule.CreatedAt = snapshotTime(pathRule.CreatedAt)
		if pathRule.UpdatedAt.Valid {
			pathRule.UpdatedAt.Time = snapshotTime(pathRule.UpdatedAt.Time)
		}
		if upstreamsJSON.Valid {
			if err := json.Unmarshal([]byte(upstreamsJSON.String), &pathRule.Upstreams); err != nil {
				// 同族收敛——上游列畸形只隔离该路由行（下发空上游会让
				// 路由静默 502），并点名 path_rules 行 ID。
				warnCorruptedSnapshotRow("path_rules", pathRule.ID, err)
				continue
			}
		}
		byRule[pathRule.RuleID] = append(byRule[pathRule.RuleID], pathRule)
	}
	return byRule, rows.Err()
}

func (s *ClusterService) snapshotUsers(ctx context.Context, store snapshotStore) ([]models.ClusterUser, error) {
	rows, err := store.QueryContext(ctx, `SELECT id, username, password_hash, role, COALESCE(display_name,''), COALESCE(is_enabled,1),
		COALESCE(password_version,0), strftime('%Y-%m-%dT%H:%M:%fZ', password_changed_at), created_at, last_login,
		COALESCE(mfa_enabled,0), COALESCE(mfa_secret,''), COALESCE(mfa_recovery_codes,'[]'),
		COALESCE(mfa_last_timestep,0), COALESCE(auth_provider,''), COALESCE(oidc_subject,''), COALESCE(oidc_issuer,''),
		COALESCE(is_setup_admin,0) FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("读取快照用户: %w", err)
	}
	defer rows.Close()
	users := make([]models.ClusterUser, 0)
	for rows.Next() {
		var user models.ClusterUser
		var passwordChangedAt sql.NullString
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.DisplayName, &user.IsEnabled, &user.PasswordVersion, &passwordChangedAt, &user.CreatedAt, &user.LastLogin,
			&user.MFAEnabled, &user.MFASecret, &user.MFARecoveryCodes, &user.MFALastTimestep,
			&user.AuthProvider, &user.OIDCSubject, &user.OIDCIssuer, &user.IsSetupAdmin); err != nil {
			return nil, fmt.Errorf("扫描快照用户: %w", err)
		}
		if passwordChangedAt.Valid {
			user.PasswordChangedAt = &passwordChangedAt.String
		}
		user.CreatedAt = snapshotTime(user.CreatedAt)
		users = append(users, user)
	}
	return users, rows.Err()
}

// snapshotLockedUsers 读取主节点活跃登录锁：只带未来时间的锁
// ——存储格式即 auth recordLoginFailure 写入的 UTC "2006-01-02 15:04:05"，
// 与 datetime('now')（同为 UTC 同形字符串）字典序比较等价于时间比较，
// 口径与 handlers.loginLockedNow 一致。已过期锁自动不进快照，无需清理路径。
// 该载荷不参与任何节哈希（sectionPayloadFor 不引用）——users 触发器 OF 列表
// 补 login_locked_until（cluster_version.go）后，置锁/解锁 UPDATE 会 bump
// cluster_version 使快照缓存重建、当周期即下发；普通失败计数 UPDATE（仅
// login_failed_attempts）不在 OF 列表，不产生版本抖动。
func (s *ClusterService) snapshotLockedUsers(ctx context.Context, store snapshotStore) ([]models.ClusterLockedUser, error) {
	rows, err := store.QueryContext(ctx, `SELECT username, login_locked_until FROM users WHERE login_locked_until IS NOT NULL AND login_locked_until > datetime('now') ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("读取快照活跃登录锁: %w", err)
	}
	defer rows.Close()
	locked := make([]models.ClusterLockedUser, 0)
	for rows.Next() {
		var entry models.ClusterLockedUser
		if err := rows.Scan(&entry.Username, &entry.LockedUntil); err != nil {
			return nil, fmt.Errorf("扫描快照活跃登录锁: %w", err)
		}
		locked = append(locked, entry)
	}
	return locked, rows.Err()
}

func (s *ClusterService) snapshotAPIKeys(ctx context.Context, store snapshotStore) ([]models.ClusterAPIKey, error) {
	rows, err := store.QueryContext(ctx, `SELECT id, name, key_hash, key_prefix, created_by, COALESCE(expires_at,''), COALESCE(is_enabled,1), COALESCE(mcp_enabled,0), COALESCE(read_only,0), COALESCE(mcp_ip_whitelist,''), last_used, created_at FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照密钥: %w", err)
	}
	defer rows.Close()
	keys := make([]models.ClusterAPIKey, 0)
	for rows.Next() {
		var key models.ClusterAPIKey
		var whitelistJSON string
		if err := rows.Scan(&key.ID, &key.Name, &key.KeyHash, &key.KeyPrefix, &key.CreatedBy, &key.ExpiresAt, &key.IsEnabled, &key.MCPEnabled, &key.ReadOnly, &whitelistJSON, &key.LastUsed, &key.CreatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照密钥: %w", err)
		}
		key.CreatedAt = snapshotTime(key.CreatedAt)
		if whitelistJSON != "" {
			if err := json.Unmarshal([]byte(whitelistJSON), &key.MCPIPWhitelist); err != nil {
				// 同族：白名单畸形不能降级为空名单（会放宽 MCP 访问面），
				// 隔离该 Key 行并点名 api_keys 行 ID。
				warnCorruptedSnapshotRow("api_keys", key.ID, err)
				continue
			}
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *ClusterService) snapshotCertificates(ctx context.Context, store snapshotStore) ([]models.ClusterCertificate, error) {
	// 手工证书轴镜像全部 enable_tls=1 的 manual 行，不按 r.enabled 过滤——
	// 与下方 ACME 轴（仅启用规则）刻意不对称：lb_rules 快照载荷本身（
	// insertSnapshotRules）就携带全部规则的 tls_cert/tls_key，禁用规则的手工
	// 证书落到从端只是多一份与表内一致的材料，且主从渲染对禁用规则不建 TLS
	// 连接策略，不构成额外暴露。若未来把证书文件轴定义为「纯运行材料」，需
	// 改为按 enabled 过滤（数据面语义变更，需裁定）。
	rows, err := store.QueryContext(ctx, `SELECT caddy_id, tls_cert, tls_key FROM lb_rules WHERE enable_tls=1 AND tls_source='manual' AND COALESCE(tls_cert,'')<>'' AND COALESCE(tls_key,'')<>'' ORDER BY caddy_id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照证书: %w", err)
	}
	certs := make([]models.ClusterCertificate, 0)
	for rows.Next() {
		var cert models.ClusterCertificate
		if err := rows.Scan(&cert.RuleID, &cert.CertPEM, &cert.KeyPEM); err != nil {
			rows.Close()
			return nil, fmt.Errorf("扫描快照证书: %w", err)
		}
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("遍历手工证书: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("关闭手工证书结果: %w", err)
	}

	// 证书轴仅镜像**启用**规则
	// （r.enabled=1）的 ACME 证书。主从「规则-证书」页面对禁用规则不一致是
	// 有意取舍而非缺陷：从端 cert_jobs 全量替换 + removeMissingSnapshotCerts
	// 会移除禁用规则的历史证书行与文件（disabled 规则不参与流量，无可用性
	// 影响）；该从节点升主后，禁用规则的历史证书需重新签发才能恢复。
	// 改为「启用或仍持有有效证书」属数据面语义变更，需用户裁定——本轮仅
	// 声明契约并以 TestSnapshotCertificates_mirrorsOnlyEnabledRules 钉死。
	rows, err = store.QueryContext(ctx, `SELECT r.caddy_id,r.domain,j.domain,j.cert_pem,j.key_pem,COALESCE(j.expires_at,''),COALESCE(j.ca_provider_id,0),j.status,
		COALESCE(j.renewal_attempts,0),j.ca_available_after,COALESCE(j.last_error_code,''),COALESCE(julianday(COALESCE(j.updated_at,j.created_at)),0),j.id,
		COALESCE(j.created_at,''),COALESCE(j.updated_at,'')
		FROM lb_rules r JOIN cert_jobs j ON j.rule_id=r.caddy_id
		WHERE r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns'
		AND `+CertJobMaterialPredicateSQL("j")+`
		ORDER BY r.caddy_id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照 ACME 证书: %w", err)
	}
	defer rows.Close()
	type snapshotCertificateCandidate struct {
		selection CertificateCandidate
		snapshot  models.ClusterCertificate
	}
	candidatesByRule := make(map[string][]snapshotCertificateCandidate)
	ruleDomains := make(map[string]string)
	now := s.snapshotNow()
	for rows.Next() {
		var cert models.ClusterCertificate
		var ruleDomain string
		var sourceCreatedAt, sourceUpdatedAt string
		var candidate CertificateCandidate
		if err := rows.Scan(&cert.RuleID, &ruleDomain, &cert.Domain, &cert.CertPEM, &cert.KeyPEM, &cert.ExpiresAt, &cert.CAProviderID, &cert.SourceStatus, &cert.RenewalAttempts, &cert.CAAvailableAfter, &cert.LastErrorCode, &candidate.UpdatedAt, &candidate.ID, &sourceCreatedAt, &sourceUpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照 ACME 证书: %w", err)
		}
		// 时间轴按平面 UTC 归一（源行原值；无法解析时留空，apply 回落 DB 默认）。
		cert.CreatedAt = normalizeSnapshotDatetime(sourceCreatedAt)
		cert.UpdatedAt = normalizeSnapshotDatetime(sourceUpdatedAt)
		canonicalRuleDomain, err := CanonicalACMEDomains(ruleDomain)
		if err != nil {
			// fail-open 裁定家族：单条规则的域名串损坏（导入残留/
			// 直改库）只跳过该规则候选并限频告警——整包报错会让主节点对所有
			// 从节点 Pull 持续 500 且无自愈路径。
			warnSnapshotCertificateCandidate(cert.RuleID, int(candidate.ID), fmt.Errorf("规则域名规范化失败: %w", err), now)
			continue
		}
		candidate.Domain = cert.Domain
		candidate.Status = cert.SourceStatus
		candidate.CertPEM = cert.CertPEM
		candidate.KeyPEM = cert.KeyPEM
		cert.Domain = canonicalRuleDomain
		ruleDomains[cert.RuleID] = canonicalRuleDomain
		candidatesByRule[cert.RuleID] = append(candidatesByRule[cert.RuleID], snapshotCertificateCandidate{selection: candidate, snapshot: cert})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历快照 ACME 证书: %w", err)
	}
	ruleIDs := make([]string, 0, len(candidatesByRule))
	for ruleID := range candidatesByRule {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	for _, ruleID := range ruleIDs {
		// 组选阶段统一解析候选证书（行扫描阶段不再逐候选做 X509KeyPair
		// 全量解析，消除每候选双解析）。解析/有效期/域名覆盖失败的候选按 rule/job
		// 限频告警后跳过；解析结果存入 Leaf 供 selectCertificate 复用。
		canonicalDomains, err := CanonicalACMEDomains(ruleDomains[ruleID])
		if err != nil {
			continue
		}
		domains := strings.Split(canonicalDomains, ",")
		selectionCandidates := make([]CertificateCandidate, 0, len(candidatesByRule[ruleID]))
		for _, candidate := range candidatesByRule[ruleID] {
			pair, err := tls.X509KeyPair([]byte(candidate.selection.CertPEM), []byte(candidate.selection.KeyPEM))
			if err != nil || len(pair.Certificate) == 0 {
				warnSnapshotCertificateCandidate(candidate.snapshot.RuleID, int(candidate.selection.ID), errors.New("证书、私钥、有效期或域名覆盖无效"), now)
				continue
			}
			leaf := pair.Leaf
			if leaf == nil {
				if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
					warnSnapshotCertificateCandidate(candidate.snapshot.RuleID, int(candidate.selection.ID), errors.New("证书、私钥、有效期或域名覆盖无效"), now)
					continue
				}
			}
			coversDomains := true
			for _, domain := range domains {
				if leaf.VerifyHostname(domain) != nil {
					coversDomains = false
					break
				}
			}
			if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || !coversDomains {
				warnSnapshotCertificateCandidate(candidate.snapshot.RuleID, int(candidate.selection.ID), errors.New("证书、私钥、有效期或域名覆盖无效"), now)
				continue
			}
			candidate.selection.Leaf = leaf
			selectionCandidates = append(selectionCandidates, candidate.selection)
		}
		selection, selected := selectCertificate(selectionCandidates, ruleDomains[ruleID], now)
		if !selected {
			continue
		}
		for _, candidate := range candidatesByRule[ruleID] {
			if candidate.selection.ID == selection.Candidate.ID {
				certs = append(certs, candidate.snapshot)
				break
			}
		}
	}
	return certs, nil
}

var snapshotCertificateWarnings = struct {
	sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

// snapshotCertificateWarningsGCTtl 控制警告 map 中条目的最长保留时间。
// 超过此时间未被再次更新的条目会在下次 warnSnapshotCertificateCandidate 调用时被清理。
const snapshotCertificateWarningsGCTtl = time.Hour

// snapshotCertificateWarnWindow 是同一证书候选告警的放行窗口。
const snapshotCertificateWarnWindow = 5 * time.Minute

func warnSnapshotCertificateCandidate(ruleID string, jobID int, cause error, now time.Time) {
	key := fmt.Sprintf("%s/%d", ruleID, jobID)
	snapshotCertificateWarnings.Lock()
	allowed := throttleWarnAllowed(snapshotCertificateWarnings.last, key, now, snapshotCertificateWarnWindow, snapshotCertificateWarningsGCTtl)
	snapshotCertificateWarnings.Unlock()
	if !allowed {
		return
	}
	Logf("warn", "cluster snapshot skipped malformed certificate candidate: rule_id=%s job_id=%d error=%v", ruleID, jobID, cause)
}

func validateDNSOwnership(data []byte) error {
	var state struct {
		Version int                `json:"version"`
		Records []ownership.Record `json:"records"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("DNS 所有权状态不是有效 JSON: %w", err)
	}
	if state.Version != 1 || state.Records == nil {
		return errors.New("DNS 所有权状态格式无效")
	}
	for _, record := range state.Records {
		// 空 value 是所有权存储支持的遗留形态（升级前写入的残留，见
		// ownership.Store.MatchingValue），不能让快照整体失败；其余结构性
		// 缺字段仍然拒绝。
		if record.Provider == "" || record.Zone == "" || record.FQDN == "" || record.RecordID == "" {
			return errors.New("DNS 所有权记录缺少 provider、zone、fqdn 或 record_id")
		}
	}
	return nil
}
