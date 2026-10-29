package services

import (
	"context"
	"crypto/sha256"

	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

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
	// 与全局配置(证书任务行与文件随 rules 开关）。
	{Key: "users", NewLabel: "系统数据"},
	{Key: "rules", NewLabel: "负载均衡规则"},
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
			// 静默 continue 会让该节哈希键缺失：跳过判定恒不命中、记账恒缺 →
			// 每周期隐式强制重放且零信号。当前载荷均为可序列化类型（实际不可达），
			// 一旦新增不可序列化字段/非法 RawMessage 必须立刻可见。
			Logf("error", "集群节哈希序列化失败（section=%s，该节将每周期强制重放）: %v", sec.Key, err)
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
		// 间永久乒乓(每两轮一次无退避全量重拉),击穿兜底重拉降频;文件态
		// 漂移由 wafFilesDrifted 专用通道(含退避与标签自愈)独占,版本行与文件
		// 差量通道随安全防护开关(cluster_apply.go/cluster_sync.go)。
		bindings := s.SecurityBindings
		if s.MasterSyncSwitches != nil && !s.MasterSyncSwitches.Rules {
			// rules 关闭时 apply 有意保留本地绑定；绑定差异不属于本节点实际
			// 落库形态，主端与本地重建必须同时排除，避免记账在两个口径间振荡。
			bindings = nil
		}
		return struct {
			Policies       json.RawMessage             `json:"policies"`
			Bindings       json.RawMessage             `json:"bindings"`
			CustomRules    []models.SecurityCustomRule `json:"custom_rules"`
			BlockPages     []models.SecurityBlockPage  `json:"block_pages"`
			IPLists        json.RawMessage             `json:"ip_lists"`
			ThreatSources  json.RawMessage             `json:"threat_sources"`
			CrawlerSources json.RawMessage             `json:"crawler_sources"`
		}{
			// 值归一单源（见 normalizeSnapshotPolicyRow/normalizeSnapshotSourceRow/
			// normalizeSnapshotBlockPagesForHash）：apply 侧的落库归一不改变主端
			// payload 字节，却会改变从端落库结果——哈希若照抄原始载荷，主端哈希
			// 与从端 apply 后重建哈希长期不等（节点列表该节永久显示「滞后」，
			// 且每次相关版本 bump 多一轮全量重放）。三面（下发值/哈希输入/从端
			// 落库值）经同一组归一函数收敛后，稳态哈希一致。
			canonicalizeSecurityPolicyRows(s.SecurityPolicies),
			bindings,
			s.SecurityCustomRules,
			normalizeSnapshotBlockPagesForHash(s.SecurityBlockPages),
			s.SecurityIPLists,
			canonicalizeSnapshotSourceRows(s.SecurityThreatSources),
			canonicalizeSnapshotSourceRows(s.SecurityCrawlerSources),
		}
	case "waf_files":
		// 文件态哈希保持纯 ref 语义(2026-09-11 修正:版本行不进节哈希——
		// 进哈希会让主从行状态强耦合,漂移判定不可收敛)。CRS/IP2Region 版本行
		// 改经内容差分门控应用(cluster_apply.go snapshotSecurityVersionRowsDiffer),随
		// 安全防护开关;版本行变化的版本 bump 由 security_crs_version
		// 触发器驱动(已排除 last_checked 读路径写)。本 case 三分类合并后
		// 仅供 wafFilesSectionHash/wafFilesNullRefHash(文件漂移比对,哈希域
		// =纯 ref 含版本标签)与 cluster_applied_sections 的 waf_files 记账行。
		return s.WafFiles
	}
	return nil
}

// canonicalizeSecurityPolicyRows 把策略行载荷规范化为「从端落库后重建」形态：
// 逐行经 normalizeSnapshotPolicyRow 归一（与 apply 写侧单源），再按
// encoding/json 的确定键序重新序列化。两侧输入可以是「主端原始行（含待归一
// 值）」或「从端已归一行」，归一幂等 + 键序确定 ⇒ 同一行的哈希字节一致。
// 解包失败原样返回（与既有 fail-visible：apply 会在解析时报错，不允许哈希
// 侧静默改写载荷）。
func canonicalizeSecurityPolicyRows(raw json.RawMessage) json.RawMessage {
	return canonicalizeSecurityRowMap(raw, normalizeSnapshotPolicyRow)
}

// canonicalizeSnapshotSourceRows 同 canonicalizeSecurityPolicyRows，用于威胁
// 情报库/爬虫地址库源行（活动态任务三列归一）。
func canonicalizeSnapshotSourceRows(raw json.RawMessage) json.RawMessage {
	return canonicalizeSecurityRowMap(raw, normalizeSnapshotSourceRow)
}

// canonicalizeSecurityRowMap 是行 map 规范化的公共实现：解包 → 逐行 normalize
// → 重新序列化（map 键按字典序，字节确定）。空/缺失载荷保持原形态（nil 仍按
// null 参与哈希，与改造前一致）。
func canonicalizeSecurityRowMap(raw json.RawMessage, normalize func(map[string]interface{})) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return raw
	}
	for _, row := range rows {
		if row == nil {
			continue
		}
		normalize(row)
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		return raw
	}
	return encoded
}

// normalizeSnapshotBlockPagesForHash 复刻 applySecurityBlockPages 的默认页降级
// （仅保留 MIN(id) 一个 is_default=1），在副本上执行——主端库里可能并存多个
// 默认页，从端落库后只剩一个，哈希必须与落库形态一致。
func normalizeSnapshotBlockPagesForHash(pages []models.SecurityBlockPage) []models.SecurityBlockPage {
	if len(pages) == 0 {
		return pages
	}
	keep := 0
	for _, page := range pages {
		if page.IsDefault && (keep == 0 || page.ID < keep) {
			keep = page.ID
		}
	}
	if keep == 0 {
		return pages
	}
	out := make([]models.SecurityBlockPage, len(pages))
	demoted := false
	for i, page := range pages {
		out[i] = page
		if page.IsDefault && page.ID != keep {
			out[i].IsDefault = false
			demoted = true
		}
	}
	if !demoted {
		return pages
	}
	return out
}

// sanitizeUsersForHash 返回用于 users 节哈希计算的用户副本：清零 last_login（登录时间）
// 与 mfa_last_timestep（从节点本地登录推进）。清零有两个作用：哈希稳定（避免从端
// 本地登录触发漂移重拉），以及 v3 信封化后 canonical 即唯一下发载荷时避免把节点
// 本地的登录时间镜像到对端。apply 侧重放会先以快照值落库，再由
// restoreLocalLoginLockouts 回写本地 last_login/login_* 记账——从端
// “最后登录”保持本节点事实。
// login_failed_attempts / login_locked_until 是从节点本地登录锁定记账（登录
// 端点写入，不进快照与节哈希）：users 节重放时由 replaceSnapshotTx 读出并在
// 回插后回写保留，重放不会解锁从节点被锁账户。
// 注意：mfa_enabled/mfa_secret/mfa_recovery_codes 是主节点权威字段，不清零
// （其漂移检测配合 触发器补列，保证管理员重置等安全操作正常传播）。
func sanitizeUsersForHash(users []models.ClusterUser) []models.ClusterUser {
	if len(users) == 0 {
		return users
	}
	out := make([]models.ClusterUser, len(users))
	for i, u := range users {
		out[i] = u
		out[i].LastLogin = models.JSONNullTime{}
		out[i].MFALastTimestep = 0
		// is_setup_admin **不随快照同步**：本函数产出的 users 节既是节哈希输入，
		// 也是 v3 信封化后唯一实际下发的 canonical 载荷——此处清零意味着从端
		// 收到的恒为「无标记」形态。标记由接收端本地归一：apply 落库后立即
		// 按「最低 id 的启用管理员」重建（insertSnapshotUsersAndKeys →
		// db.EnsureSetupAdminFlag）。主端标记若带外落在非最低 id 的管理员上，
		// 不会在对端复现，这是刻意的本地归一语义，不是载荷丢失。
		// 清零的第二个理由与 last_login 同源：标记进哈希会让「主端未携带标记」
		// 的形态在从端每轮重建出与载荷不同的哈希，触发永久重放/重载
		// （waf ref 同型乒乓）。
		out[i].IsSetupAdmin = false
	}
	return out
}

// sanitizeAPIKeysForHash 同理清零 api_keys 的 last_used（使用时间）：清零仅为哈希稳定（避免从端
// 本地调用触发漂移重拉）。last_used 属节点本地记账——v3 下从端唯一应用的是
// 已清零该字段的 canonical 载荷，apply 后由 restoreLocalAPIKeyLastUsed 回写
// 「本地与快照中较晚者」，主端值不会到达从端（从端 Keys 页显示的是本节点
// 使用时间，仅在主端使用过的 Key 恒为空）。
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

// SyncSwitches 是节点本地同步开关集（读取见 readSyncSwitches）。
// 三分类合并后仅剩 users(恒 true)/rules/security 三开关。
type SyncSwitches struct {
	Users    bool
	Rules    bool
	Security bool
}

// sectionEnabled maps a section key to its switch state. 未知键（含拼写错误）
// 一律拒绝：默认 true 会让「新增节但忘记加开关映射」的节被静默同步/放行，
// 与「开关是门、默认不放行」的语义相反；syncSections 是键的唯一真相源。
func (sw SyncSwitches) sectionEnabled(key string) bool {
	switch key {
	case "users":
		return sw.Users
	case "rules":
		return sw.Rules
	case "security":
		return sw.Security
	}
	return false
}

// readSyncSwitches reads the node-local sync switches (defaults all-on for
// missing columns/rows, e.g. pre-migration databases). ctx 由调用方直传
// （不再内部 context.Background()，保持本包 ctx 透传约定
// ——快照构建可随调用方取消）。
func readSyncSwitches(ctx context.Context, dbh interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}) (SyncSwitches, error) {
	sw := SyncSwitches{Users: true, Rules: true, Security: true}
	if dbh == nil {
		return sw, nil
	}
	// sync_users 子查询已删——恒同步裁定下 sw.Users
	// 恒 true(读取/赋值成死代码);无 FROM 的子查询标量 SELECT 恒返回 1 行,
	// ErrNoRows 分支不可达,一并收敛。三分类合并(2026-09-19)后
	// sync_global_config/sync_waf_files 列已物理删除,读取只剩 rules/security。
	var r, sec sql.NullBool
	err := dbh.QueryRowContext(ctx, `SELECT
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

func readAppliedSectionHashes(ctx context.Context, dbh *sql.DB) map[string]string {
	if dbh == nil {
		return nil
	}
	rows, err := dbh.QueryContext(ctx, `SELECT section, hash FROM cluster_applied_sections`)
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
		// 逐行 Scan 失败与行遍历错误同口径（fail-visible + 返回 nil）：静默跳过
		// 会返回「部分 map」——computeSectionSkips 侧缺记录方向安全（按需重放），
		// 但 driftedSections 会用残缺 applied 记录比对，把未漂移节误判为漂移
		// （多一轮全量重拉），且故障本身零信号。两列均为 TEXT，正常形态不会失败，
		// 只有驱动/连接异常可达。
		if err := rows.Scan(&sec, &hash); err != nil {
			Logf("warn", "读取已应用节哈希失败（漂移检测将回退全量重放口径）: %v", err)
			return nil
		}
		applied[sec] = hash
	}
	if err := rows.Err(); err != nil {
		Logf("warn", "遍历已应用节哈希失败（漂移检测将回退全量重放口径）: %v", err)
		return nil
	}
	return applied
}

// driftGuardSections 限定漂移检测范围：这些节是纯全量替换表，本地重建哈希
// 在稳态下与主节点哈希一致，比对才有意义。三分类合并后 users 节含全局
// 配置(basic+caddy)——节点本地记账列不在 BasicSettings 结构内,重建口径
// 与主端一致(同一装载函数);waf_files 为文件态记账节(哈希域=纯 ref),
// 由 wafFilesDrifted 专用通道比对,不纳入表级守卫。
// 键表由 syncSections 派生（单源）：新增/改名一节只改 syncSections，漂移
// 守卫范围自动跟随，避免历史上「快照列与差分行不同步」的漏节事故。
var driftGuardSections = syncSectionKeys()

// syncSectionKeys 返回全部同步节键（顺序与 syncSections 一致）。
func syncSectionKeys() []string {
	keys := make([]string, 0, len(syncSections))
	for _, sec := range syncSections {
		keys = append(keys, sec.Key)
	}
	return keys
}

func computeSectionSkips(ctx context.Context, dbh *sql.DB, snapshot models.ClusterSnapshot, switches SyncSwitches, localHashes map[string]string) *sectionSkips {
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	if dbh == nil {
		return sk
	}
	// 系统数据恒同步（2026-09-11 裁定）：在本函数边界显式归一一次，防未来新增
	// 调用方传入 Users=false 静默跳过 users 节（唯一生产调用方 applySnapshot 也
	// 已强制 true；readSyncSwitches 恒返回 true——三处是同一不变量的门，不是
	// 各自独立的判定）。此前该归一行写在逐节循环内，形似「首次遇到 users 才强制」，
	// 易被误读为此处是唯一强制点。
	switches.Users = true
	applied := readAppliedSectionHashes(ctx, dbh)
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

// sectionOutcome 节级三态：应用 / 哈希一致跳过 / 开关关闭跳过。
// drifted 节（记录哈希一致但本地数据与记录不符）归入应用——强制重放。
type sectionOutcome int

const (
	sectionOutcomeApplied sectionOutcome = iota
	sectionOutcomeUnchanged
	sectionOutcomeDisabled
)

// sectionOutcomes 是节级三态判定的唯一实现：逐节审计行
// （logSectionSyncOutcome）与同步汇总行（sectionOutcomeNames）都只在此结果上
// 做文案映射，新增第四态/调整判定优先级时只改本函数（两份判定曾各自维护，
// 漏改一处即审计行与汇总行互相矛盾）。
func sectionOutcomes(sk *sectionSkips) map[string]sectionOutcome {
	outcomes := make(map[string]sectionOutcome, len(syncSections))
	for _, sec := range syncSections {
		switch {
		case sk != nil && sk.disabled[sec.Key]:
			outcomes[sec.Key] = sectionOutcomeDisabled
		case sk != nil && sk.unchanged[sec.Key]:
			outcomes[sec.Key] = sectionOutcomeUnchanged
		default:
			outcomes[sec.Key] = sectionOutcomeApplied
		}
	}
	return outcomes
}

func logSectionSyncOutcome(sk *sectionSkips, version int) {
	outcomes := sectionOutcomes(sk)
	for _, sec := range syncSections {
		switch outcomes[sec.Key] {
		case sectionOutcomeDisabled:
			RecordAuditLog("system", "同步跳过", "集群同步", FormatAuditDetail(formatSectionAction("开关关闭", sec.Key), fmt.Sprintf("版本：%d", version)), "")
		case sectionOutcomeUnchanged:
			RecordAuditLog("system", "同步跳过", "集群同步", FormatAuditDetail(formatSectionAction("哈希一致", sec.Key), fmt.Sprintf("版本：%d", version)), "")
		default:
			RecordAuditLog("system", "同步应用", "集群同步", FormatAuditDetail(formatSectionAction("内容已更新", sec.Key), fmt.Sprintf("版本：%d", version)), "")
		}
	}
}

// sectionOutcomeNames 节级三态命名（2026-10-03 用户裁定：同步汇总审计
// 反映实际应用面——内容清单与「哈希一致跳过」自相矛盾）。
func sectionOutcomeNames(sk *sectionSkips) (applied, hashSkipped, disSkipped []string) {
	outcomes := sectionOutcomes(sk)
	for _, sec := range syncSections {
		switch outcomes[sec.Key] {
		case sectionOutcomeDisabled:
			disSkipped = append(disSkipped, sec.NewLabel)
		case sectionOutcomeUnchanged:
			hashSkipped = append(hashSkipped, sec.NewLabel)
		default:
			applied = append(applied, sec.NewLabel)
		}
	}
	return applied, hashSkipped, disSkipped
}

// recordAppliedSectionHashes 落已应用节哈希与文件态记账。写入失败聚合为
// error 返回（仍逐条 warn 留痕）：调用方不回滚已提交的快照应用，但必须
// 感知失败——记账陈旧时漂移/跳过判定失真，apply 的 WAF 门据此回退
// 「不依赖 DB 记账」的内容哈希兜底。
func recordAppliedSectionHashes(ctx context.Context, dbh *sql.DB, snapshot models.ClusterSnapshot, sk *sectionSkips, switches SyncSwitches, localHashes map[string]string) error {
	if dbh == nil {
		return nil
	}
	var errs []error
	for _, sec := range syncSections {
		if !switches.sectionEnabled(sec.Key) {
			continue
		}
		h, ok := snapshot.SectionHashes[sec.Key]
		if !ok {
			continue
		}
		if sk.unchanged[sec.Key] {
			// UPDATE 命中 0 行（行被并发清理/Role flip 清表）
			// 时 err==nil 仍 continue，会静默不记账 → 下一次 304 多一轮漂移重放。
			// 只有真正更新到行才跳过落哈希。
			result, err := dbh.ExecContext(ctx, `UPDATE cluster_applied_sections SET applied_version=?, applied_at=datetime('now') WHERE section=?`, snapshot.Version, sec.Key)
			if err == nil {
				if n, rowsErr := result.RowsAffected(); rowsErr == nil && n > 0 {
					continue
				}
			}
		}
		// 漂移节已被强制重放、本地数据镜像主节点：落本地重建口径哈希作为
		// 稳定参照（见 applySnapshot 调用点注释）；本地哈希缺失回退快照侧。
		// 代价如实化：同构建常态下每次漂移会多 1 轮全量重拉才收敛
		//（本轮强制重放+落本地口径，下轮起哈希一致走跳过）——这是有意取舍，
		// 问题 的跨构建漂移防护优先于省一轮重拉。
		if sk.wasDrifted(sec.Key) {
			if lh, lok := localHashes[sec.Key]; lok && lh != "" {
				h = lh
			}
		}
		if _, err := dbh.ExecContext(ctx, `INSERT INTO cluster_applied_sections (section, hash, applied_version, applied_at) VALUES (?,?,?,datetime('now'))
			ON CONFLICT(section) DO UPDATE SET hash=excluded.hash, applied_version=excluded.applied_version, applied_at=excluded.applied_at`, sec.Key, h, snapshot.Version); err != nil {
			Logf("warn", "记录已应用节哈希失败（section=%s）: %v", sec.Key, err)
			errs = append(errs, fmt.Errorf("节 %s: %w", sec.Key, err))
		}
	}

	// 三分类合并·方案A(2026-09-19 裁定):文件态记账落 global_config 专用列
	// (applied_waf_ref_hash=纯 ref 哈希含版本标签,applied_waf_ref_version=
	// 告警去重版本)——cluster_applied_sections 严格 3 行与 syncSections
	// 同构;wafFilesDrifted 的 304 兜底重拉与标签自愈依赖该记录。
	// 随安全防护开关写入/冻结(节哈希、上报与 hover 均不包含文件态)。
	if switches.Security {
		refHash := wafFilesNullRefHash
		if snapshot.WafFiles != nil {
			if hh, rerr := wafFilesSectionHash(snapshot.WafFiles); rerr == nil {
				refHash = hh
			}
		}
		if _, err := dbh.ExecContext(ctx, `UPDATE global_config SET applied_waf_ref_hash=?, applied_waf_ref_version=? WHERE id=1`, refHash, snapshot.Version); err != nil {
			Logf("warn", "记录文件态记账失败（applied_waf_ref_*）: %v", err)
			errs = append(errs, fmt.Errorf("applied_waf_ref_*: %w", err))
		}
	}
	return errors.Join(errs...)
}

// logSyncSwitchGuards surfaces cross-section drift: security-switch-off nodes
// whose master references newer CRS/IP2Region files (file state follows the
// security switch after the 3-category merge).
func logSyncSwitchGuards(ctx context.Context, dbh *sql.DB, snapshot models.ClusterSnapshot, sk *sectionSkips, switches SyncSwitches) {
	// 告警对象是「开关关闭导致 WAF 文件滞后」的从节点——开关开启时
	// applySnapshot 随即拉取文件，无滞后可告。三分类合并后判定挂 security
	// 开关(waf_files 不再是同步节,sk.disabled 只含 3 节键);dedup 记账走
	// global_config.applied_waf_ref_version(方案A 列;security 关闭时
	// recordAppliedSectionHashes 不写该列,版本冻结在开关关闭前,每版本
	// bump 至多刷一条告警审计)。
	// 判定顺序「便宜门在前」：开关关闭 → 快照带引用 → 版本去重（一次点查）
	// → 最后才 wafFilesRefVersionLabelsDiffer（只读两个小版本文件 + 逐源
	// .fast 哈希；不用 wafFilesRefDiffers 的整树哈希，见该函数注释）。同版本
	// 重放（重载失败补偿重拉）本应被去重直接跳过，若先算哈希会白付一次全树
	// 哈希并阻塞三库更新器与 lbbak 导入文件相位。
	// 语义不变：三个条件仍同时成立才告警（AND）；判据覆盖 CRS/IP2Region/
	// 威胁库三段——同步开关关闭时任一被引用面更新都要留信号。
	if !sk.disabled["security"] || snapshot.WafFiles == nil {
		return
	}
	var lastWarnVersion int
	if dbh != nil {
		// 读失败属稀有基础设施故障——不限频 warn 一行，否则去重依据静默归零、
		// 每个 apply 周期都刷审计告警且无信号解释。
		if err := dbh.QueryRow("SELECT COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1").Scan(&lastWarnVersion); err != nil {
			Logf("warn", "读取文件态记账版本失败（同步开关告警去重不可用）: %v", err)
		}
	}
	if lastWarnVersion >= snapshot.Version {
		return
	}
	// 轻量比对（版本标签 + 威胁 .fast 哈希）替代整树哈希：本告警只回答
	// 「主节点安全数据是否已更新」，开关开启时的内容级漂移检测仍由
	// wafFilesDrifted 的哈希口径承担。
	if !wafFilesRefVersionLabelsDiffer(snapshot.WafFiles) {
		return
	}
	RecordAuditLog("system", "同步警告", "集群同步", "检测到主节点 CRS/IP2Region/威胁库文件已更新（同步开关关闭），本地文件保持不变", "")
	// 告警后只推进去重版本(哈希不动——security 关闭时哈希列不被
	// 消费),保证每版本 bump 至多一条告警。推进失败必须留痕：该列是去重唯一
	// 依据，静默失败会让同一告警按 apply 轮重复刷审计且无信号解释（正是上方
	// 读失败分支注释要防的形态）；用 ExecContext 与同文件其余写点同口径。
	if dbh != nil {
		if _, err := dbh.ExecContext(ctx, `UPDATE global_config SET applied_waf_ref_version=? WHERE id=1`, snapshot.Version); err != nil {
			Logf("warn", "推进文件态告警去重版本失败（下轮可能重复告警）: %v", err)
		}
	}
}
