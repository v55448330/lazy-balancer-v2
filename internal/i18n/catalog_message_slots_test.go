package i18n

// 尾冒号错误详情词条的 %s 槽回归：早期迁移曾把 8 条「操作失败: 」形态词条的 %s 槽
// 弄丢（母本只剩悬空冒号，Tf 传入的错误详情被静默丢弃）。
// 本钉测按语义断言中文母本必须以占位槽承接详情（键是语义键，不随母本措辞变化；
// 传参数与模板动词数的对账见各调用面的槽数守卫）。英文译文归前端词条，其槽数
// 对等由 web/tests/apiMessagesParity.spec.ts 与前端渲染守卫钉住。

import (
	"testing"
)

func TestCatalog_failureDetailEntriesCarrySlot(t *testing.T) {
	cases := []struct {
		key      string
		zhPrefix string
	}{
		{"caddy.rawConfigSaveFailed", "保存 Caddy 配置失败: "},
		{"system.taskTriggerFailed", "任务触发失败: "},
		{"cert.caProviderConfigInvalid", "CA 提供商配置无效: "},
		{"caddy.rawConfigRejected", "Caddy 拒绝配置: "},
		{"system.taskTriggerRejected", "任务当前不可触发: "},
		{"caddy.configBackupFailed", "备份当前 Caddy 配置失败: "},
		{"backup.autoBackupTriggerFailed", "触发备份失败: "},
		{"system.adminTlsSaveFailed", "保存 HTTPS 配置失败: "},
	}
	for _, c := range cases {
		zh := T(c.key)
		if zh == c.key {
			t.Errorf("%s 未登记（尾冒号词条补槽后必须换新键）", c.key)
			continue
		}
		if zh != c.zhPrefix+"%s" {
			t.Errorf("%s zh=%q, want %q（详情槽不得丢失）", c.key, zh, c.zhPrefix+"%s")
		}
	}
}

// 集群节点动作动词词条化：动作词（审批/拒绝/删除/更新地址）必须登记为独立词条，
// 消费侧插值到「%s节点成功」的 %s 槽，而不是把动作词硬编码在调用点。
func TestCatalog_clusterNodeActionVerbsRegistered(t *testing.T) {
	cases := []struct{ key, zh string }{
		{"cluster.nodeActionApprove", "审批"},
		{"cluster.nodeActionReject", "拒绝"},
		{"cluster.nodeActionDelete", "删除"},
		{"cluster.nodeActionUpdateAccessUrl", "更新地址"},
	}
	for _, c := range cases {
		if got := T(c.key); got != c.zh {
			t.Errorf("%s zh=%q, want %q", c.key, got, c.zh)
		}
	}
}
