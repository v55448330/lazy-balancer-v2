package db

import (
	"fmt"
	"log"
)

// ThreatSystemList 威胁情报库内置只读名单条目（v2.3.2 名单化重构）。
// Source=威胁源名（security_threat_sources.name，更新任务定位键），
// Name=security_ip_lists.name（用户可见，稳定不变——策略 refs 按 id 引用，
// 行永不删除，id 跨更新稳定）。
type ThreatSystemList struct {
	Source      string
	Name        string
	Description string
}

// ThreatSystemLists 三源内置名单种子（与 security_threat_sources 种子同源）。
// 专业化命名（2026-09-24 用户裁定）：去「威胁情报库-」前缀——选择器分组已
// 承载归属语义；存量库旧名经 migrateThreatSystemListNames 迁移（保 id）。
var ThreatSystemLists = []ThreatSystemList{
	{"ustc", "中科大恶意 IP 名单（USTC）", "中国科学技术大学恶意 IP 库（blackip.ustc.edu.cn）——威胁情报库更新任务维护，只读"},
	{"firehol_l1", "FireHOL Level 1 综合黑名单", "FireHOL Level 1 聚合黑名单（iplists.firehol.org）——威胁情报库更新任务维护，只读"},
	{"et_compromised", "Emerging Threats 失陷主机名单", "Emerging Threats Compromised IPs（失陷主机）——威胁情报库更新任务维护，只读"},
}

// threatSystemListLegacyNames 新名 → 旧名（迁移定位键；仅 v2.3.2 名单化初期的
// 「威胁情报库-*」旧名一档）。
var threatSystemListLegacyNames = map[string]string{
	"中科大恶意 IP 名单（USTC）":       "威胁情报库-中科大黑 IP",
	"FireHOL Level 1 综合黑名单":   "威胁情报库-FireHOL level1",
	"Emerging Threats 失陷主机名单": "威胁情报库-ET Compromised",
}

// migrateThreatSystemListNames 存量 system=1 内置名单按旧名改名为新名（保 id——
// 策略 refs 按 id 引用）。幂等；种子 INSERT 按新名查重，旧名行不改名会双重存在。
// CORE-U3（第 69 轮）：同名冲突守卫——security_ip_lists.name 无 UNIQUE 约束，
// 新名已被占用（如用户手工建的同名 system=0 名单）时改名会产出同名双行且种子
// 查重静默跳过——跳过改名并 WARN 留给人工处置（不阻断启动）。
func migrateThreatSystemListNames() error {
	for _, sl := range ThreatSystemLists {
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
			log.Printf("WARN: 内置威胁名单改名跳过——新名 %q 已被库中既有名单占用（旧名 %q 行保留，请人工改名后重启收敛）", sl.Name, legacy)
			continue
		}
		if _, err := DB.Exec(`UPDATE security_ip_lists SET name=?, description=?, updated_at=datetime('now') WHERE system=1 AND name=?`, sl.Name, sl.Description, legacy); err != nil {
			return fmt.Errorf("failed to rename threat system list %s: %w", legacy, err)
		}
	}
	return nil
}

// ThreatListNameBySource 源名 → 名单名（未登记返回空串）。
func ThreatListNameBySource(source string) string {
	for _, sl := range ThreatSystemLists {
		if sl.Source == source {
			return sl.Name
		}
	}
	return ""
}
