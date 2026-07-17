package services

import "fmt"

func AuditResultText(result string) string {
	switch result {
	case "success":
		return "成功"
	case "failed":
		return "失败"
	case "max_attempts":
		return "达到最大重试次数"
	case "missing_material":
		return "证书数据缺失"
	case "queued":
		return "已重新排队"
	case "requested":
		return "已触发"
	case "invalid_request":
		return "请求格式错误"
	case "invalid_credentials":
		return "用户名或密码错误"
	case "credentials_invalid":
		return "凭证无效"
	case "internal_error":
		return "系统内部错误"
	case "enabled":
		return "已启用"
	case "disabled":
		return "已禁用"
	case "approved":
		return "已通过"
	case "rejected":
		return "已拒绝"
	case "created":
		return "已创建"
	case "reregistered":
		return "已重新注册"
	case "not_found":
		return "对象不存在"
	case "missing_domain":
		return "缺少测试域名"
	case "unknown_provider":
		return "未知提供商"
	case "applied_or_no_change":
		return "同步完成或无变更"
	case "sync_failed":
		return "同步失败"
	case "io_error":
		return "文件写入失败"
	case "query_failed":
		return "查询失败"
	default:
		return result
	}
}

func FormatAuditDetail(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return fmt.Sprintf("%s", joinChineseParts(filtered))
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
	default:
		return fmt.Sprintf("来源：%s", source)
	}
}
