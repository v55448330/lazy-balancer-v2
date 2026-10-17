package services

import "fmt"

// auditResultTextMap 是审计结果码 → 中文渲染的唯一事实源（SVC-F1 第 73 轮：
// 由 switch 改为 map，供 audit_result_text_test.go 以 AST/字面量互检钉住
// 「AuditResultPart 字面量实参集合 ⊆ 映射键集」——新增结果码漏映射即测试红）。
// 未收录码在 AuditResultText 中原样返回（保留英文兜底），但落库前应补映射。
var auditResultTextMap = map[string]string{
	"success":              "成功",
	"failed":               "失败",
	"failure":              "失败",
	"partial":              "部分成功",
	"max_attempts":         "达到最大重试次数",
	"missing_material":     "证书数据缺失",
	"queued":               "已重新排队",
	"requested":            "已触发",
	"skipped":              "已跳过",
	"invalid_request":      "请求格式错误",
	"invalid_credentials":  "用户名或密码错误",
	"credentials_invalid":  "凭证无效",
	"internal_error":       "系统内部错误",
	"enabled":              "已启用",
	"disabled":             "已禁用",
	"approved":             "已通过",
	"rejected":             "已拒绝",
	"created":              "已创建",
	"reregistered":         "已重新注册",
	"not_found":            "对象不存在",
	"missing_domain":       "缺少测试域名",
	"unknown_provider":     "未知提供商",
	"provider_error":       "提供商错误",
	"missing_acme_email":   "缺少 ACME 邮箱",
	"invalid_config":       "配置无效",
	"register_failed":      "注册失败",
	"storage_corrupted":    "存储数据损坏",
	"applied_or_no_change": "同步完成或无变更",
	"sync_failed":          "同步失败",
	"io_error":             "文件写入失败",
	"query_failed":         "查询失败",
}

func AuditResultText(result string) string {
	if text, ok := auditResultTextMap[result]; ok {
		return text
	}
	return result
}

func FormatAuditDetail(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return joinChineseParts(filtered)
}

func joinChineseParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, part := range parts[1:] {
		result += "；" + part
	}
	return result
}

// AuditUserPart 用户标识段(2026-09-11 裁定):用户相关审计详情显示完整标识
// 「用户 12（zhang）」;用户名空回退「用户 12」(不可解析场景)。
func AuditUserPart(id int, username string) string {
	if username == "" {
		return fmt.Sprintf("用户 %d", id)
	}
	return fmt.Sprintf("用户 %d（%s）", id, username)
}

func AuditJobPart(jobID int) string {
	return fmt.Sprintf("任务 %d", jobID)
}

func AuditRulePart(ruleID string) string {
	return fmt.Sprintf("规则 %s", ruleID)
}

func AuditResultPart(result string) string {
	return fmt.Sprintf("结果：%s", AuditResultText(result))
}

func AuditSourcePart(source string) string {
	switch source {
	case "certificate_issued":
		return "来源：证书签发"
	case "startup_materialization":
		return "来源：启动恢复"
	case "ca_cooldown":
		return "来源：CA 冷却结束"
	case "startup_recovery":
		return "来源：启动恢复"
	case "renewal":
		return "来源：自动续签"
	case "manual":
		return "来源：手动操作"
	case "rule_create":
		return "来源：创建规则"
	case "rule_update":
		return "来源：更新规则"
	case "rule_delete":
		return "来源：删除规则"
	case "rule_enable":
		return "来源：启用规则"
	case "rule_disable":
		return "来源：禁用规则"
	case "ip2region_update":
		return "来源：IP 库更新"
	case "crs_update":
		return "来源：CRS 规则库更新"
	case "threat_update":
		return "来源：威胁情报库更新"
	case "autoban":
		return "来源：自动封禁名单"
	default:
		return fmt.Sprintf("来源：%s", source)
	}
}

// recordSystemReloadAudit 数据类更新（IP 库/CRS）触发的真实 Caddy 重载统一
// 留痕（system 归因，裁定 2026-09-07；对齐 certissuer/集群同步口径）。
func recordSystemReloadAudit(source string, err error) {
	if err != nil {
		RecordAuditLog("system", "重载失败", "Caddy服务", FormatAuditDetail(AuditSourcePart(source), err.Error()), "")
		return
	}
	RecordAuditLog("system", "重载", "Caddy服务", FormatAuditDetail(AuditSourcePart(source), AuditResultPart("success")), "")
}
