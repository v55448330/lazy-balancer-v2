package db

import (
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
)

// ThreatSourceSeed 是内置威胁源下载端的唯一事实源；数据库种子、备份导入
// 与 lbbak 文件名白名单共用，防止合法 name 携带伪造 URL/format。
type ThreatSourceSeed struct {
	Name        string
	DisplayName string
	URL         string
	Format      string
}

var threatSourceSeeds = []ThreatSourceSeed{
	{Name: "ustc", DisplayName: "中科大恶意 IP（USTC）", URL: "https://blackip.ustc.edu.cn/list.php?txt", Format: "plain"},
	{Name: "firehol_l1", DisplayName: "FireHOL Level 1", URL: "https://iplists.firehol.org/files/firehol_level1.netset", Format: "plain"},
	{Name: "et_compromised", DisplayName: "Emerging Threats Compromised", URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", Format: "plain"},
}

// CanonicalThreatSource 按内置 name 返回官方下载端定义。
func CanonicalThreatSource(name string) (ThreatSourceSeed, bool) {
	for _, seed := range threatSourceSeeds {
		if seed.Name == name {
			return seed, true
		}
	}
	return ThreatSourceSeed{}, false
}

// ThreatSystemList 威胁情报库内置只读名单条目（v2.3.2 名单化重构）。
// Source=威胁源名（security_threat_sources.name，更新任务定位键），
// Name=security_ip_lists.name（用户可见，稳定不变——策略 refs 按 id 引用，
// 行永不删除，id 跨更新稳定）。
type ThreatSystemList struct {
	Source      string
	Name        string
	Description string
}

// threatSystemLists 是内置威胁名单种子的唯一可变载体（私有）。
// 此前导出 `ThreatSystemLists` 是可变包级切片，任一
// 消费方 append/改元素会污染播种、备份配额校验、详情计数与快照链路；同文件
// certJobStatuses 的先例是「私有 + 返回副本」。现统一走 ThreatSystemLists()
// 取副本；跨包测试需要「未来源」形态时用 SetThreatSystemListsForTest 注入
// （生产不调用）。
var threatSystemLists = []ThreatSystemList{
	{"ustc", "中科大恶意 IP 名单（USTC）", "中国科学技术大学恶意 IP 库（blackip.ustc.edu.cn）——威胁情报库更新任务维护，只读"},
	{"firehol_l1", "FireHOL Level 1 综合黑名单", "FireHOL Level 1 聚合黑名单（iplists.firehol.org）——威胁情报库更新任务维护，只读"},
	{"et_compromised", "Emerging Threats 失陷主机名单", "Emerging Threats Compromised IPs（失陷主机）——威胁情报库更新任务维护，只读"},
}

// ThreatSystemLists 返回三源内置名单种子的副本（防调用方篡改全局）。
func ThreatSystemLists() []ThreatSystemList {
	return slices.Clone(threatSystemLists)
}

// SetThreatSystemListsForTest 仅供跨包测试注入扩展注册表（模拟未来新增内置源，
// 生产不调用）；返回还原函数。注入内容同样被复制，调用方后续修改入参不影响全局。
func SetThreatSystemListsForTest(lists []ThreatSystemList) func() {
	previous := threatSystemLists
	threatSystemLists = slices.Clone(lists)
	return func() { threatSystemLists = previous }
}

// threatSystemListLegacyNames 新名 → 旧名（迁移定位键；仅 v2.3.2 名单化初期的
// 「威胁情报库-*」旧名一档）。
var threatSystemListLegacyNames = map[string]string{
	"中科大恶意 IP 名单（USTC）":       "威胁情报库-中科大黑 IP",
	"FireHOL Level 1 综合黑名单":   "威胁情报库-FireHOL level1",
	"Emerging Threats 失陷主机名单": "威胁情报库-ET Compromised",
}

// threatListTakeoverSkipMarkerColumn 是「已告警的规范名占用冲突」指纹列
// （global_config，newColumns 登记）。值为「;」分隔的冲突指纹集合，
// 空串=无冲突或冲突已解除。
const threatListTakeoverSkipMarkerColumn = "threat_list_takeover_skip_fp"

// readThreatListTakeoverSkipMarker 读已告警指纹集合。读失败（单行缺失/库忙等）
// 返回错误交由调用方点名留痕后按空集继续——错误与「确无已告警指纹」是两种
// 状态，静默折叠成空集会让「同一僵持态只留一条审计」失效且无排查线索。
func readThreatListTakeoverSkipMarker() (map[string]struct{}, error) {
	stored := ""
	if err := DB.QueryRow(`SELECT COALESCE(` + threatListTakeoverSkipMarkerColumn + `,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, fingerprint := range strings.Split(stored, ";") {
		if fingerprint != "" {
			seen[fingerprint] = struct{}{}
		}
	}
	return seen, nil
}

// writeThreatListTakeoverSkipMarker 覆盖写指纹集合（空集写空串即清除）；
// 失败只告警不阻断启动（下次启动重报）。UPDATE 命中 0 行=global_config 单行
// 缺失或不可写，同样只告警——否则指纹从未落库而调用方毫无信号，重复审计
// 退化为无头案。
func writeThreatListTakeoverSkipMarker(fingerprints map[string]struct{}) {
	sorted := make([]string, 0, len(fingerprints))
	for fingerprint := range fingerprints {
		sorted = append(sorted, fingerprint)
	}
	sort.Strings(sorted)
	res, err := DB.Exec(`UPDATE global_config SET `+threatListTakeoverSkipMarkerColumn+`=? WHERE id=1`, strings.Join(sorted, ";"))
	if err != nil {
		log.Printf("启动迁移：威胁名单占名冲突告警指纹写入失败（下次启动将重报）: %v", err)
		return
	}
	if n, rerr := res.RowsAffected(); rerr == nil && n == 0 {
		log.Printf("WARN: 启动迁移：global_config 单行缺失或不可写，威胁名单占名冲突告警指纹无法持久化（下次启动将重报）")
	}
}

// threatListTakeoverSkipFingerprint 标识一处「规范名被另一 system=1 行占用」
// 僵持态：规范名 + 旧名 + 双方行 id。任何一方变化（人工归并后新建冲突）都
// 视为新冲突并重报。
func threatListTakeoverSkipFingerprint(canonical, legacy string) string {
	var canonicalID, legacyID int64
	_ = DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND system=1 ORDER BY id LIMIT 1`, canonical).Scan(&canonicalID)
	_ = DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND system=1 ORDER BY id LIMIT 1`, legacy).Scan(&legacyID)
	return fmt.Sprintf("%s|%s|%d|%d", canonical, legacy, canonicalID, legacyID)
}

// migrateThreatSystemListNames 存量 system=1 内置名单按旧名改名为新名（保 id——
// 策略 refs 按 id 引用）。幂等；种子 INSERT 按新名查重，旧名行不改名会双重存在。
// 识别同名冲突；历史起新名被占用（如用户手工建的
// 同名 system=0 名单）时，把冲突用户行改名为「规范名（用户 <id>）」（保 id/
// 数据），再让 system 行接管规范名。避免同名双行导致选择器歧义，且旧 system
// 名单不会因跳过改名而永久失更。
func migrateThreatSystemListNames() error {
	renamedUserLists := 0
	// 已知僵持态集合（本次启动观察到的）与已告警集合（上次落库的）：
	// 集合相等即不再写审计，只在变化时留痕并覆盖 marker。读取失败按未告警
	// 继续（fail-open 语义不变），但必须点名留痕——静默折叠成空集时，
	// 「同一僵持态只留一条审计」失效且无从排查。
	reportedSkips, err := readThreatListTakeoverSkipMarker()
	if err != nil {
		log.Printf("WARN: 启动迁移：威胁名单占名冲突告警指纹读取失败（按未告警继续，同一冲突可能重报一条审计）: %v", err)
		reportedSkips = map[string]struct{}{}
	}
	observedSkips := make(map[string]struct{})
	for _, sl := range ThreatSystemLists() {
		legacy, ok := threatSystemListLegacyNames[sl.Name]
		if !ok {
			continue
		}
		var legacyRows int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1 AND name=?`, legacy).Scan(&legacyRows); err != nil {
			return fmt.Errorf("failed to check legacy threat system list %s: %w", legacy, err)
		}
		if legacyRows == 0 {
			continue // 幂等零命中
		}
		var conflicts int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, sl.Name).Scan(&conflicts); err != nil {
			return fmt.Errorf("failed to check threat system list name conflict %s: %w", sl.Name, err)
		}
		if conflicts > 0 {
			// 规范名已被另一 system=1 行占用（如上一次迁移中断的残留形态）：
			// 改名用户行的通道解决不了该冲突——强行接管会撞
			// u_security_ip_lists_system_name 唯一索引中止启动。保留双方、
			// 跳过接管并告警留痕，由人工归并（种子按规范名查重，旧名行
			// 残留不会双重存在，仅失更）。
			var systemHeld int
			if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND system=1`, sl.Name).Scan(&systemHeld); err != nil {
				return fmt.Errorf("failed to check system-held threat list name %s: %w", sl.Name, err)
			}
			if systemHeld > 0 {
				log.Printf("WARN: 内置威胁名单规范名 %q 已被另一 system=1 行占用，旧名 %q 行跳过接管（双方保留，请人工归并）", sl.Name, legacy)
				// 同一僵持态只留一条审计：该状态按设计「双方保留 + 人工归并」，
				// 每重启重放会让审计噪声随重启次数线性增长；指纹变化（人工归并
				// 后出现新冲突）自动重报。
				fingerprint := threatListTakeoverSkipFingerprint(sl.Name, legacy)
				observedSkips[fingerprint] = struct{}{}
				if _, alreadyReported := reportedSkips[fingerprint]; !alreadyReported {
					recordSystemAudit("启动迁移", "IP 名单", fmt.Sprintf("启动迁移：内置威胁名单规范名 %q 已被另一 system=1 行占用，旧名 %q 行跳过接管（双方保留，名单可能失更，请人工归并）", sl.Name, legacy))
				}
				continue
			}
			// 新名被用户名单占用时不能跳过：旧 system 名单会永久失更。
			// 把占用的用户行改名为带 id 的唯一名称（保 id/数据），再让
			// system 行接管规范名。
			rows, rerr := DB.Query(`SELECT id FROM security_ip_lists WHERE name=? AND system=0`, sl.Name)
			if rerr != nil {
				return fmt.Errorf("query conflicting threat system list rows: %w", rerr)
			}
			var ids []int64
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return fmt.Errorf("scan conflicting threat system list row: %w", err)
				}
				ids = append(ids, id)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return fmt.Errorf("iterate conflicting threat system list rows: %w", err)
			}
			rows.Close()
			for _, id := range ids {
				renamed := fmt.Sprintf("%s（用户 %d）", sl.Name, id)
				if _, err := DB.Exec(`UPDATE security_ip_lists SET name=?, updated_at=datetime('now') WHERE id=?`, renamed, id); err != nil {
					return fmt.Errorf("rename conflicting user list %d: %w", id, err)
				}
			}
			log.Printf("WARN: 内置威胁名单新名 %q 被用户名单占用，已改名用户行（ids=%v）后接管规范名", sl.Name, ids)
			if len(ids) > 0 {
				// 用户名单被改名属于用户可见数据改写，
				// 聚合留痕（此前仅进程 stdout）。
				renamedUserLists += len(ids)
				detail := fmt.Sprintf("启动迁移：内置威胁名单新名 %q 被占用，已改名用户名单 %d 条（ids=%v，保 id/数据）", sl.Name, len(ids), ids)
				recordSystemAudit("启动迁移", "IP 名单", detail)
			}
		}
		if _, err := DB.Exec(`UPDATE security_ip_lists SET name=?, description=?, updated_at=datetime('now') WHERE system=1 AND name=?`, sl.Name, sl.Description, legacy); err != nil {
			return fmt.Errorf("failed to rename threat system list %s: %w", legacy, err)
		}
	}
	if renamedUserLists > 0 {
		log.Printf("启动迁移：威胁名单规范化共改名用户名单 %d 条", renamedUserLists)
	}
	if !sameThreatListTakeoverFingerprints(reportedSkips, observedSkips) {
		writeThreatListTakeoverSkipMarker(observedSkips)
	}
	return nil
}

// sameThreatListTakeoverFingerprints 比较两次观察到的僵持态集合（长度为 0 的
// 空集相等——收敛库与「冲突已解除」都不触发 marker 写）。
func sameThreatListTakeoverFingerprints(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for fingerprint := range a {
		if _, ok := b[fingerprint]; !ok {
			return false
		}
	}
	return true
}

// ThreatListNameBySource 源名 → 名单名（未登记返回空串）。
func ThreatListNameBySource(source string) string {
	for _, sl := range ThreatSystemLists() {
		if sl.Source == source {
			return sl.Name
		}
	}
	return ""
}
