package db

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
var ThreatSystemLists = []ThreatSystemList{
	{"ustc", "威胁情报库-中科大黑 IP", "中科大黑 IP 列表（blackip.ustc.edu.cn）——威胁情报库更新任务维护，只读"},
	{"firehol_l1", "威胁情报库-FireHOL level1", "FireHOL level1 黑名单（iplists.firehol.org）——威胁情报库更新任务维护，只读"},
	{"et_compromised", "威胁情报库-ET Compromised", "Emerging Threats Compromised IPs——威胁情报库更新任务维护，只读"},
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
