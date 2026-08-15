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
type syncSection struct {
	Key      string
	NewLabel string
}

var syncSections = []syncSection{
	{Key: "global_config", NewLabel: "全局配置"},
	{Key: "users", NewLabel: "系统数据"},
	{Key: "rules", NewLabel: "负载均衡规则"},
	{Key: "waf_files", NewLabel: "CRS/IP2Region 数据库"},
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
		var payload interface{}
		switch sec.Key {
		case "global_config":
			payload = s.BasicSettings
			if s.CaddyConfig != nil {
				payload = struct {
					Basic models.ClusterBasicSettings `json:"basic_settings"`
					Caddy string                      `json:"caddy_config"`
				}{s.BasicSettings, *s.CaddyConfig}
			}
		case "users":
			payload = struct {
				Users   []models.ClusterUser   `json:"users"`
				APIKeys []models.ClusterAPIKey `json:"api_keys"`
			}{s.Users, s.APIKeys}
		case "rules":
			payload = s.Rules
		case "waf_files":
			payload = s.WafFiles
		case "security":
			payload = struct {
				Policies    json.RawMessage             `json:"policies"`
				Bindings    json.RawMessage             `json:"bindings"`
				CustomRules []models.SecurityCustomRule `json:"custom_rules"`
				BlockPages  []models.SecurityBlockPage  `json:"block_pages"`
			}{s.SecurityPolicies, s.SecurityBindings, s.SecurityCustomRules, s.SecurityBlockPages}
		}
		data, err := json.Marshal(payload)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		hashes[sec.Key] = hex.EncodeToString(sum[:])
	}
	return hashes
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
}

func (sk *sectionSkips) skip(key string) bool {
	return sk != nil && (sk.disabled[key] || sk.unchanged[key])
}

func computeSectionSkips(dbh *sql.DB, snapshot models.ClusterSnapshot, switches SyncSwitches) *sectionSkips {
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	if dbh == nil {
		return sk
	}
	rows, err := dbh.Query(`SELECT section, hash FROM cluster_applied_sections`)
	if err != nil {
		return sk
	}
	defer rows.Close()
	applied := map[string]string{}
	for rows.Next() {
		var sec, hash string
		if rows.Scan(&sec, &hash) == nil {
			applied[sec] = hash
		}
	}
	for _, sec := range syncSections {
		if !switches.sectionEnabled(sec.Key) {
			sk.disabled[sec.Key] = true
			continue
		}
		if h, ok := snapshot.SectionHashes[sec.Key]; ok && applied[sec.Key] == h {
			sk.unchanged[sec.Key] = true
		}
	}
	return sk
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

func recordAppliedSectionHashes(dbh *sql.DB, snapshot models.ClusterSnapshot, sk *sectionSkips, switches SyncSwitches) {
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
		dbh.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version, applied_at) VALUES (?,?,?,datetime('now'))
			ON CONFLICT(section) DO UPDATE SET hash=excluded.hash, applied_version=excluded.applied_version, applied_at=excluded.applied_at`, sec.Key, h, snapshot.Version)
	}
}

// logSyncSwitchGuards surfaces cross-section drift: security policies that
// reference CRS files the node didn't sync, and waf-files updates skipped by
// an off switch.
func logSyncSwitchGuards(snapshot models.ClusterSnapshot, sk *sectionSkips, switches SyncSwitches) {
	if !switches.WafFiles || snapshot.WafFiles == nil || !wafFilesRefDiffers(snapshot.WafFiles) {
		return
	}
	var lastWarnVersion int
	if db.DB != nil {
		db.DB.QueryRow("SELECT applied_version FROM cluster_applied_sections WHERE section='waf_files'").Scan(&lastWarnVersion)
	}
	if lastWarnVersion >= snapshot.Version {
		return
	}
	RecordAuditLog("system", "同步警告", "集群同步", "检测到主节点 CRS/IP2Region 文件已更新（同步开关关闭），本地文件保持不变", "")
}
