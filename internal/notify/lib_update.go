package notify

// 安全库更新终态事件（四库统一）：CRS / IP2Region / 威胁情报库 / 爬虫地址库。
// 发布点=各 manager 的终态收尾（每轮仅一条，不随阶段刷新重复发）：
//   - 成功（含「已是最新」）→ sec.lib_update_succeeded（info，默认关）；
//   - 失败 → sec.lib_update_failed（warn，默认开）。
// 用户取消/节点降级中止不是故障（无成功事实也无失败事实），不发终态事件。
//
// 字段序契约（目录模板参数序）：1=库名 2=触发（自动/手动）3=版本或错误摘要。

import "strings"

// libUpdateResultEvent 构造终态事件（纯函数；级别留空由目录回填，保证
// 级别单源在 catalog）。
func libUpdateResultEvent(success bool, lib, trigger, detail string) Event {
	typ := EvtLibUpdateFailed
	if success {
		typ = EvtLibUpdateSucceeded
	} else if strings.TrimSpace(detail) == "" {
		detail = "未知错误"
	}
	return Event{
		Type: typ,
		Fields: map[string]string{
			"1": lib,
			"2": libUpdateTriggerLabel(trigger),
			"3": detail,
		},
	}
}

// libUpdateTriggerLabel 触发来源可读文案（自动/手动；未知取值原样透传）。
func libUpdateTriggerLabel(trigger string) string {
	switch trigger {
	case "auto":
		return "自动"
	case "manual":
		return "手动"
	default:
		return trigger
	}
}

// PublishLibUpdateSucceeded 发布安全库更新成功（version 为空时回落「已完成」）。
func PublishLibUpdateSucceeded(lib, trigger, version string) {
	if strings.TrimSpace(version) == "" {
		version = "已完成"
	}
	Publish(libUpdateResultEvent(true, lib, trigger, version))
}

// PublishLibUpdateFailed 发布安全库更新失败（detail=错误摘要）。
func PublishLibUpdateFailed(lib, trigger, detail string) {
	Publish(libUpdateResultEvent(false, lib, trigger, detail))
}
