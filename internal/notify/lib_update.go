package notify

// 规则库更新终态事件（四库统一）：CRS / IP2Region / 威胁情报库 / 爬虫地址库。
// 手动与自动共用同一事件（sec.lib_updated，标题「规则库更新」）——不再拆
// 成功/失败两个事件；级别随结果：成功 info、失败 warn（目录默认订阅关闭，
// 失败同时有 task.failed 兜底）。字段序=目录模板参数序：
// 1=库名 2=触发（自动/手动）3=结果（成功/失败）4=版本或错误摘要。

import "strings"

// libUpdateResultEvent 构造终态事件（纯函数，便于单测断言级别/字段/正文）。
func libUpdateResultEvent(success bool, lib, trigger, detail string) Event {
	if strings.TrimSpace(detail) == "" {
		if success {
			detail = "已完成"
		} else {
			detail = "未知错误"
		}
	}
	level := LevelInfo
	result := "成功"
	if !success {
		level = LevelWarn
		result = "失败"
	}
	return Event{
		Type:  EvtLibUpdated,
		Level: level,
		Fields: map[string]string{
			"1": lib,
			"2": libUpdateTriggerLabel(trigger),
			"3": result,
			"4": detail,
		},
	}
}

// PublishLibUpdateResult 发布规则库更新终态（每轮一次，取消/降级不发）。
func PublishLibUpdateResult(lib, trigger string, success bool, detail string) {
	Publish(libUpdateResultEvent(success, lib, trigger, detail))
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
