package notify

// Caddy 应用失败标记（global_config.caddy_apply_error）与通知的联动：
// 通知由标记状态变化驱动——
//   - 新失败（标记 空 → 置值）：发 critical 应用失败事件；标记已存在时由
//     调用方判定 prev 非空并跳过（不重复发）。
//   - 恢复（标记 非空 → 清空）：发 info 恢复事件。
// 调用方是横幅/标记的唯一写点与清除点（handlers persistCaddyApplyBanner/
// recordCaddyApplyResult、services applyRenderDegradationState 与后台重载
// 清除分支），prev 判据以调用方读到的写前状态或条件 UPDATE 的 RowsAffected
// 为准——本包不读库，保持 notify 对存储无依赖。

import "os"

// PublishCaddyApplyFailed 新失败通知（调用方仅在标记 空→置值 转变处调用）。
func PublishCaddyApplyFailed(detail string) {
	Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": LocalNodeName(), "2": detail}})
}

// PublishCaddyRecovered 标记清除恢复通知（调用方仅在标记 非空→清空 转变处
// 调用，含条件 UPDATE 命中行的语义）。
func PublishCaddyRecovered() {
	Publish(Event{Type: EvtCaddyRecovered, Fields: map[string]string{"1": LocalNodeName()}})
}

// LocalNodeName 本机节点标识（通知正文用；主机名缺失回退「本机」）。
func LocalNodeName() string {
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}
	return "本机"
}
