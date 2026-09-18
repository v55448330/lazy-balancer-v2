package services

import (
	"context"
	"crypto/sha256"

	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lazy-balancer-v2/internal/db"

	"lazy-balancer-v2/internal/models"
)

// 集群同步节定义：开关列名 ↔ 快照节。哪个变动同步哪个——从节点逐节比对
// SectionHashes 与 cluster_applied_sections，一致的节跳过重放并留痕。
// 三分类合并(2026-09-19 用户裁定):节收敛为 3 类,与备份分类同构——全局
// 配置并入「系统数据」(users 恒同步不可禁用,basic_settings/caddy_config
// 随 users 节 payload 携带),规则库文件差量通道并入「安全防护」(单开关
// 统策略行与文件,见 wafFilesDrifted/replaceSnapshotTx)。
type syncSection struct {
	Key      string
	NewLabel string
}

var syncSections = []syncSection{
	// 系统数据排第一(2026-09-11 裁定):恒同步不可禁用,含用户/密钥/ACME
	// 与全局配置(证书任务行与文件随 rules 开关,R64 A-N5)。
	{Key: "users", NewLabel: "系统数据"},
	{Key: "rules", NewLabel: "负载规则"},
	{Key: "security", NewLabel: "安全防护"},
}

// ComputeSnapshotSectionHashes derives a stable SHA-256 per section from the
// snapshot payload itself, so master and slave agree without extra DB reads.
func ComputeSnapshotSectionHashes(s *models.ClusterSnapshot) map[string]string {
	if s == nil {
		return nil
	}
	hashes := make(map[string]string, len(syncSections)+1)
	for _, sec := range syncSections {
		data, err := json.Marshal(sectionPayloadFor(sec.Key, s))
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		hashes[sec.Key] = hex.EncodeToString(sum[:])
	}
	return hashes
}

// sectionPayloadFor returns the JSON-marshaled payload a section hash is derived
// from. Extracted so the full-snapshot hashing (ComputeSnapshotSectionHashes) and
// the lightweight drift guard (driftGuardSectionHashes) share ONE canonical payload
// definition — the hash parity invariant between the two depends on it.
func sectionPayloadFor(key string, s *models.ClusterSnapshot) interface{} {
	switch key {
	case "users":
		// 三分类合并:users 节 payload 并入全局配置(basic_settings+
		// caddy_config,字段顺序固定,主从同构建共享本定义)。CaddyConfig
		// 为 nil 时 caddy_config 序列化为空串(手造快照/测试形态)。
		caddy := ""
		if s.CaddyConfig != nil {
			caddy = *s.CaddyConfig
		}
		return struct {
			Users         []models.ClusterUser        `json:"users"`
			APIKeys       []models.ClusterAPIKey      `json:"api_keys"`
			BasicSettings models.ClusterBasicSettings `json:"basic_settings"`
			CaddyConfig   string                      `json:"caddy_config"`
		}{sanitizeUsersForHash(s.Users), sanitizeAPIKeysForHash(s.APIKeys), s.BasicSettings, caddy}
	case "rules":
		return s.Rules
	case "security":
		// IPLists（v2.3.0）参与 security 节哈希：列表行变化必须触发节重放；
		// 字段顺序是哈希输入的一部分，主从同构建共享本定义，勿单独调整。
		// 三分类合并勘误(2026-09-19):WafFiles ref 不进本节哈希——ref 入哈希后,
		// 文件拉取持续失败的从节点 security 节哈希在「主端 ref 域/本地 ref 域」
		// 间永久乒乓(每两轮一次无退避全量重拉),击穿 R40 兜底重拉降频;文件态
		// 漂移由 wafFilesDrifted 专用通道(含退避与标签自愈)独占,版本行与文件
		// 差量通道随安全防护开关(cluster_apply.go/cluster_sync.go)。
		return struct {
			Policies    json.RawMessage             `json:"policies"`
			Bindings    json.RawMessage             `json:"bindings"`
			CustomRules []models.SecurityCustomRule `json:"custom_rules"`
			BlockPages  []models.SecurityBlockPage  `json:"block_pages"`
			IPLists     json.RawMessage             `json:"ip_lists"`
		}{s.SecurityPolicies, s.SecurityBindings, s.SecurityCustomRules, s.SecurityBlockPages, s.SecurityIPLists}
	case "global_config":
		// legacy case:三分类合并前 global_config 节的 payload 形态。保留仅供
		// 参照,syncSections 不再含该节(ComputeSnapshotSectionHashes 产 3 键)。
		if s.CaddyConfig != nil {
			return struct {
				Basic models.ClusterBasicSettings `json:"basic_settings"`
				Caddy string                      `json:"caddy_config"`
			}{s.BasicSettings, *s.CaddyConfig}
		}
		return s.BasicSettings
	case "waf_files":
		// 文件态哈希保持纯 ref 语义(2026-09-11 修正:版本行不进节哈希——
		// 进哈希会让主从行状态强耦合,漂移判定不可收敛)。CRS/IP2Region 版本行
		// 改经内容差分门控应用(cluster_apply.go versionRowsDiffer),随
		// 安全防护开关;版本行变化的版本 bump 由 security_crs_version
		// 触发器驱动(已排除 last_checked 读路径写)。本 case 三分类合并后
		// 仅供 wafFilesSectionHash/wafFilesNullRefHash(文件漂移比对,哈希域
		// =纯 ref 含版本标签)与 cluster_applied_sections 的 waf_files 记账行。
		return s.WafFiles
	}
	return nil
}

// sanitizeUsersForHash 返回用于 users 节哈希计算的用户副本：清零节点本地记账
// 字段。last_login（登录时间）与 mfa_last_timestep（从节点本地登录推进）是
// 「从节点登录端点会写、主节点值无权威意义」的本地态：不清零则从节点每次
// MFA 登录都触发漂移全量重拉，且从节点锁定在一个同步周期（≤60s）内被主节点
// 值抹除（R72 F-3）。mfa_failed_attempts/mfa_locked_until 死列已于 2026-09-10
// 物理删除(db.go migrateDropDeadMFALockColumns),快照不再搬运该二值。
// login_failed_attempts / login_locked_until 是从节点本地登录锁定记账（登录
// 端点写入，不进快照与节哈希）：users 节重放时由 replaceSnapshotTx 读出并在
// 回插后回写保留（SC-4），重放不会解锁从节点被锁账户。
// 注意：mfa_enabled/mfa_secret/mfa_recovery_codes 是主节点权威字段，不清零
// （其漂移检测配合 R72 F-4 的触发器补列，保证管理员重置等安全操作正常传播）。
func sanitizeUsersForHash(users []models.ClusterUser) []models.ClusterUser {
	if len(users) == 0 {
		return users
	}
	out := make([]models.ClusterUser, len(users))
	for i, u := range users {
		out[i] = u
		out[i].LastLogin = models.JSONNullTime{}
		out[i].MFALastTimestep = 0
	}
	return out
}

// sanitizeAPIKeysForHash 同理清零 api_keys 的 last_used（节点本地使用时间记账）。
func sanitizeAPIKeysForHash(keys []models.ClusterAPIKey) []models.ClusterAPIKey {
	if len(keys) == 0 {
		return keys
	}
	out := make([]models.ClusterAPIKey, len(keys))
	for i, k := range keys {
		out[i] = k
		out[i].LastUsed = models.JSONNullTime{}
	}
	return out
}

// SyncSwitches 是节点本地同步开关集(读取见 readSyncSwitches,CL10-N4:此前注释引用不存在的 LoadSyncSwitches 且口径写错)。
// 三分类合并后仅剩 users(恒 true)/rules/security 三开关。
type SyncSwitches struct {
	Users    bool
	Rules    bool
	Security bool
}

// sectionEnabled maps a section key to its switch state.
func (sw SyncSwitches) sectionEnabled(key string) bool {
	switch key {
	case "users":
		return sw.Users
	case "rules":
		return sw.Rules
	case "security":
		return sw.Security
	}
	return true
}

// readSyncSwitches reads the node-local sync switches (defaults all-on for
// missing columns/rows, e.g. pre-migration databases).
func readSyncSwitches(dbh interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}) (SyncSwitches, error) {
	sw := SyncSwitches{Users: true, Rules: true, Security: true}
	if dbh == nil {
		return sw, nil
	}
	// CL9-N12(第 9 轮审计):sync_users 子查询已删——恒同步裁定下 sw.Users
	// 恒 true(读取/赋值成死代码);无 FROM 的子查询标量 SELECT 恒返回 1 行,
	// ErrNoRows 分支不可达,一并收敛。三分类合并(2026-09-19)后
	// sync_global_config/sync_waf_files 列已物理删除,读取只剩 rules/security。
	var r, sec sql.NullBool
	err := dbh.QueryRowContext(context.Background(), `SELECT
		(SELECT sync_rules FROM global_config WHERE id=1),
		(SELECT sync_security FROM global_config WHERE id=1)`).Scan(&r, &sec)
	if err != nil {
		return sw, err
	}
	if r.Valid {
		sw.Rules = r.Bool
	}
	if sec.Valid {
		sw.Security = sec.Bool
	}
	// 系统数据恒同步(2026-09-11 裁定):sync_users 不可禁用——任何存量 0 值
	// 一律按 1 读取;禁用请求由 UpdateSettings 拒绝,启动迁移回填。
	sw.Users = true
	return sw, nil
}

func formatSectionAction(action, key string) string {
	for _, sec := range syncSections {
		if sec.Key == key {
			return fmt.Sprintf("%s：%s", action, sec.NewLabel)
		}
	}
	return action + "：" + key
}

// sectionSkips decides, per section, whether apply should skip it — either
// because the node's sync switch is off or the section hash is unchanged.
type sectionSkips struct {
	disabled  map[string]bool
	unchanged map[string]bool
	// drifted 记录「记录哈希与主节点一致、但本地数据重建哈希与记录不符」的
	// 节：本地数据在同步之外丢失/被改动，哈希跳过必须让位于强制重放。
	drifted []string
}

func (sk *sectionSkips) skip(key string) bool {
	return sk != nil && (sk.disabled[key] || sk.unchanged[key])
}

func (sk *sectionSkips) wasDrifted(key string) bool {
	for _, d := range sk.drifted {
		if d == key {
			return true
		}
	}
	return false
}

func readAppliedSectionHashes(dbh *sql.DB) map[string]string {
	if dbh == nil {
		return nil
	}
	rows, err := dbh.Query(`SELECT section, hash FROM cluster_applied_sections`)
	if err != nil {
		// 吞错会让漂移检测静默回退全量重放（良性但不可见）——warn 一行暴露
		// 基础设施故障信号，行为不变。
		Logf("warn", "读取已应用节哈希失败（漂移检测将回退全量重放口径）: %v", err)
		return nil
	}
	defer rows.Close()
	applied := map[string]string{}
	for rows.Next() {
		var sec, hash string
		if rows.Scan(&sec, &hash) == nil {
			applied[sec] = hash
		}
	}
	return applied
}

// driftGuardSections 限定漂移检测范围：这些节是纯全量替换表，本地重建哈希
// 在稳态下与主节点哈希一致，比对才有意义。三分类合并后 users 节含全局
// 配置(basic+caddy)——节点本地记账列不在 BasicSettings 结构内,重建口径
// 与主端一致(同一装载函数);waf_files 为文件态记账节(哈希域=纯 ref),
// 由 wafFilesDrifted 专用通道比对,不纳入表级守卫。
var driftGuardSections = []string{"rules", "users", "security"}

func computeSectionSkips(dbh *sql.DB, snapshot models.ClusterSnapshot, switches SyncSwitches, localHashes map[string]string) *sectionSkips {
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	if dbh == nil {
		return sk
	}
	applied := readAppliedSectionHashes(dbh)
	for _, sec := range syncSections {
		if sec.Key == "users" {
			// 系统数据恒同步(2026-09-11 裁定):纵使快照携带旧主节点的
			// MasterSyncSwitches.Users=false 也强制应用(防旧快照绕过)。
			switches.Users = true
		}
		if !switches.sectionEnabled(sec.Key) {
			sk.disabled[sec.Key] = true
			continue
		}
		if h, ok := snapshot.SectionHashes[sec.Key]; ok && applied[sec.Key] == h {
			if localHash, local := localHashes[sec.Key]; local && localHash != "" && localHash != applied[sec.Key] && driftGuardContains(sec.Key) {
				sk.drifted = append(sk.drifted, sec.Key)
				continue
			}
			sk.unchanged[sec.Key] = true
		}
	}
	return sk
}

func driftGuardContains(key string) bool {
	for _, k := range driftGuardSections {
		if k == key {
			return true
		}
	}
	return false
}

func logSectionSyncOutcome(sk *sectionSkips, version int) {
	for _, sec := range syncSections {
		switch {
		case sk.disabled[sec.Key]:
			RecordAuditLog("system", "同步跳过", "集群同步", FormatAuditDetail(formatSectionAction("开关关闭", sec.Key), fmt.Sprintf("版本：%d", version)), "")
		case sk.unchanged[sec.Key]:
			RecordAuditLog("system", "同步跳过", "集群同步", FormatAuditDetail(formatSectionAction("哈希一致", sec.Key), fmt.Sprintf("版本：%d", version)), "")
		default:
			RecordAuditLog("system", "同步应用", "集群同步", FormatAuditDetail(formatSectionAction("内容已更新", sec.Key), fmt.Sprintf("版本：%d", version)), "")
		}
	}
}

func recordAppliedSectionHashes(dbh *sql.DB, snapshot models.ClusterSnapshot, sk *sectionSkips, switches SyncSwitches, localHashes map[string]string) {
	if dbh == nil {
		return
	}
	for _, sec := range syncSections {
		if !switches.sectionEnabled(sec.Key) {
			continue
		}
		h, ok := snapshot.SectionHashes[sec.Key]
		if !ok {
			continue
		}
		if sk.unchanged[sec.Key] {
			if _, err := dbh.Exec(`UPDATE cluster_applied_sections SET applied_version=?, applied_at=datetime('now') WHERE section=?`, snapshot.Version, sec.Key); err == nil {
				continue
			}
		}
		// 漂移节已被强制重放、本地数据镜像主节点：落本地重建口径哈希作为
		// 稳定参照（见 applySnapshot 调用点注释）；本地哈希缺失回退快照侧。
		if sk.wasDrifted(sec.Key) {
			if lh, lok := localHashes[sec.Key]; lok && lh != "" {
				h = lh
			}
		}
		if _, err := dbh.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version, applied_at) VALUES (?,?,?,datetime('now'))
			ON CONFLICT(section) DO UPDATE SET hash=excluded.hash, applied_version=excluded.applied_version, applied_at=excluded.applied_at`, sec.Key, h, snapshot.Version); err != nil {
			Logf("warn", "记录已应用节哈希失败（section=%s）: %v", sec.Key, err)
		}
	}

	// 三分类合并·方案A(2026-09-19 裁定):文件态记账落 global_config 专用列
	// (applied_waf_ref_hash=纯 ref 哈希含版本标签,applied_waf_ref_version=
	// 告警去重版本)——cluster_applied_sections 严格 3 行与 syncSections
	// 同构;wafFilesDrifted 的 304 兜底重拉与 R57 A-#4 标签自愈依赖该记录。
	// 随安全防护开关写入/冻结(节哈希、上报与 hover 均不包含文件态)。
	if switches.Security {
		refHash := wafFilesNullRefHash
		if snapshot.WafFiles != nil {
			if hh, rerr := wafFilesSectionHash(snapshot.WafFiles); rerr == nil {
				refHash = hh
			}
		}
		if _, err := dbh.Exec(`UPDATE global_config SET applied_waf_ref_hash=?, applied_waf_ref_version=? WHERE id=1`, refHash, snapshot.Version); err != nil {
			Logf("warn", "记录文件态记账失败（applied_waf_ref_*）: %v", err)
		}
	}
}

// logSyncSwitchGuards surfaces cross-section drift: security-switch-off nodes
// whose master references newer CRS/IP2Region files (file state follows the
// security switch after the 3-category merge).
func logSyncSwitchGuards(snapshot models.ClusterSnapshot, sk *sectionSkips, switches SyncSwitches) {
	// R57 A-#3：告警对象是「开关关闭导致 WAF 文件滞后」的从节点——开关开启时
	// applySnapshot 随即拉取文件，无滞后可告。三分类合并后判定挂 security
	// 开关(waf_files 不再是同步节,sk.disabled 只含 3 节键);dedup 记账走
	// global_config.applied_waf_ref_version(方案A 列;security 关闭时
	// recordAppliedSectionHashes 不写该列,版本冻结在开关关闭前,每版本
	// bump 至多刷一条告警审计)。
	if !sk.disabled["security"] || snapshot.WafFiles == nil || !wafFilesRefDiffers(snapshot.WafFiles) {
		return
	}
	var lastWarnVersion int
	if db.DB != nil {
		// 读失败属稀有基础设施故障——不限频 warn 一行，否则去重依据静默归零、
		// 每个 apply 周期都刷审计告警且无信号解释。
		if err := db.DB.QueryRow("SELECT COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1").Scan(&lastWarnVersion); err != nil {
			Logf("warn", "读取文件态记账版本失败（同步开关告警去重不可用）: %v", err)
		}
	}
	if lastWarnVersion >= snapshot.Version {
		return
	}
	RecordAuditLog("system", "同步警告", "集群同步", "检测到主节点 CRS/IP2Region 文件已更新（同步开关关闭），本地文件保持不变", "")
	// CL10-N7:告警后只推进去重版本(哈希不动——security 关闭时哈希列不被
	// 消费),保证每版本 bump 至多一条告警。
	if db.DB != nil {
		_, _ = db.DB.Exec(`UPDATE global_config SET applied_waf_ref_version=? WHERE id=1`, snapshot.Version)
	}
}
