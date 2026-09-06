package services

import (
	"context"
	"crypto/sha256"

	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lazy-balancer-v2/internal/db"

	"lazy-balancer-v2/internal/models"
)

// 集群同步节定义：开关列名 ↔ 快照节。哪个变动同步哪个——从节点逐节比对
// SectionHashes 与 cluster_applied_sections，一致的节跳过重放并留痕。
type syncSection struct {
	Key      string
	NewLabel string
}

var syncSections = []syncSection{
	{Key: "global_config", NewLabel: "全局配置"},
	{Key: "users", NewLabel: "系统数据"},
	{Key: "rules", NewLabel: "负载规则"},
	{Key: "waf_files", NewLabel: "规则库数据库"},
	{Key: "security", NewLabel: "安全策略及自定义规则"},
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
	case "global_config":
		if s.CaddyConfig != nil {
			return struct {
				Basic models.ClusterBasicSettings `json:"basic_settings"`
				Caddy string                      `json:"caddy_config"`
			}{s.BasicSettings, *s.CaddyConfig}
		}
		return s.BasicSettings
	case "users":
		return struct {
			Users   []models.ClusterUser   `json:"users"`
			APIKeys []models.ClusterAPIKey `json:"api_keys"`
		}{sanitizeUsersForHash(s.Users), sanitizeAPIKeysForHash(s.APIKeys)}
	case "rules":
		return s.Rules
	case "waf_files":
		return s.WafFiles
	case "security":
		// IPLists（v2.3.0）参与 security 节哈希：列表行变化必须触发节重放；
		// 字段顺序是哈希输入的一部分，主从同构建共享本定义，勿单独调整。
		return struct {
			Policies    json.RawMessage                          `json:"policies"`
			Bindings    json.RawMessage                          `json:"bindings"`
			CustomRules []models.SecurityCustomRule              `json:"custom_rules"`
			BlockPages  []models.SecurityBlockPage               `json:"block_pages"`
			IPLists     json.RawMessage                          `json:"ip_lists"`
			CRSVersion  []models.ClusterSecurityCRSVersion       `json:"crs_version"`
			IP2Region   []models.ClusterSecurityIP2RegionVersion `json:"ip2region_version"`
		}{s.SecurityPolicies, s.SecurityBindings, s.SecurityCustomRules, s.SecurityBlockPages, s.SecurityIPLists, s.SecurityCRSVersion, s.SecurityIP2RegionVersion}
	}
	return nil
}

// sanitizeUsersForHash 返回用于 users 节哈希计算的用户副本：清零节点本地记账
// 字段。last_login（登录时间）与 mfa_last_timestep（从节点本地登录推进）是
// 「从节点登录端点会写、主节点值无权威意义」的本地态：不清零则从节点每次
// MFA 登录都触发漂移全量重拉，且从节点锁定在一个同步周期（≤60s）内被主节点
// 值抹除（R72 F-3）。mfa_failed_attempts / mfa_locked_until 是 M7 残留死列
// （随快照搬运、无读写语义，见系统域 S-4），此处一并清零只为口径稳定。只清零
// 副本、不改动 s.Users 原值，快照线上格式保持不变。
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
		out[i].MFAFailedAttempts = 0
		out[i].MFALockedUntil = ""
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

// LoadSyncSwitches reads the master-side sync switches; defaults all-on.
type SyncSwitches struct {
	GlobalConfig bool
	Users        bool
	Rules        bool
	WafFiles     bool
	Security     bool
}

// sectionEnabled maps a section key to its switch state.
func (sw SyncSwitches) sectionEnabled(key string) bool {
	switch key {
	case "global_config":
		return sw.GlobalConfig
	case "users":
		return sw.Users
	case "rules":
		return sw.Rules
	case "waf_files":
		return sw.WafFiles
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
	sw := SyncSwitches{GlobalConfig: true, Users: true, Rules: true, WafFiles: true, Security: true}
	if dbh == nil {
		return sw, nil
	}
	var g, u, r, w, sec sql.NullBool
	err := dbh.QueryRowContext(context.Background(), `SELECT
		(SELECT sync_global_config FROM global_config WHERE id=1),
		(SELECT sync_users FROM global_config WHERE id=1),
		(SELECT sync_rules FROM global_config WHERE id=1),
		(SELECT sync_waf_files FROM global_config WHERE id=1),
		(SELECT sync_security FROM global_config WHERE id=1)`).Scan(&g, &u, &r, &w, &sec)
	if err != nil {
		if err == sql.ErrNoRows {
			return sw, nil
		}
		return sw, err
	}
	if g.Valid {
		sw.GlobalConfig = g.Bool
	}
	if u.Valid {
		sw.Users = u.Bool
	}
	if r.Valid {
		sw.Rules = r.Bool
	}
	if w.Valid {
		sw.WafFiles = w.Bool
	}
	if sec.Valid {
		sw.Security = sec.Bool
	}
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
// 在稳态下与主节点哈希一致，比对才有意义（global_config 含节点本地记账
// 字段、waf_files 含文件态，本地重建哈希天然可能与主节点不同，不纳入）。
var driftGuardSections = []string{"rules", "users", "security"}

func computeSectionSkips(dbh *sql.DB, snapshot models.ClusterSnapshot, switches SyncSwitches, localHashes map[string]string) *sectionSkips {
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	if dbh == nil {
		return sk
	}
	applied := readAppliedSectionHashes(dbh)
	for _, sec := range syncSections {
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
}

// logSyncSwitchGuards surfaces cross-section drift: security policies that
// reference CRS files the node didn't sync, and waf-files updates skipped by
// an off switch.
func logSyncSwitchGuards(snapshot models.ClusterSnapshot, sk *sectionSkips, switches SyncSwitches) {
	// R57 A-#3：告警对象是「开关关闭导致 WAF 文件滞后」的从节点——开关开启时
	// applySnapshot 随即拉取文件，无滞后可告。原条件 !switches.WafFiles 恰好
	// 把唯一应告警的形态挡在门外；且 recordAppliedSectionHashes 对 disabled 节
	// 跳过 applied_version 写入，本版本去重仍正确。
	if !sk.disabled["waf_files"] || snapshot.WafFiles == nil || !wafFilesRefDiffers(snapshot.WafFiles) {
		return
	}
	var lastWarnVersion int
	if db.DB != nil {
		// ErrNoRows 是合法空态（首次告警前无记录，按版本 0 处理）；其余读取
		// 失败属稀有基础设施故障——不限频 warn 一行，否则去重依据静默归零、
		// 每个 apply 周期都刷审计告警且无信号解释。
		if err := db.DB.QueryRow("SELECT applied_version FROM cluster_applied_sections WHERE section='waf_files'").Scan(&lastWarnVersion); err != nil && !errors.Is(err, sql.ErrNoRows) {
			Logf("warn", "读取 waf_files 已应用版本失败（同步开关告警去重不可用）: %v", err)
		}
	}
	if lastWarnVersion >= snapshot.Version {
		return
	}
	RecordAuditLog("system", "同步警告", "集群同步", "检测到主节点 CRS/IP2Region 文件已更新（同步开关关闭），本地文件保持不变", "")
}
