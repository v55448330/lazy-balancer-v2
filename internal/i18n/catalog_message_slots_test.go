package i18n

// 尾冒号错误详情词条的 %s 槽回归：早期迁移曾把 8 条「操作失败: 」形态词条的 %s 槽
// 弄丢（zh/en 双语只剩悬空冒号，Tf 传入的错误详情被静默丢弃）。
// 本钉测按语义断言：zh/en 模板都必须以占位槽承接详情（键是语义键，不随母本措辞
// 变化；传参数与模板动词数的对账见各调用面的槽数守卫）。

import (
	"strings"
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
		zh, en := T(ZH, c.key), T(EN, c.key)
		if zh == c.key || en == c.key {
			t.Errorf("%s 未登记（尾冒号词条补槽后必须换新键）", c.key)
			continue
		}
		if zh != c.zhPrefix+"%s" {
			t.Errorf("%s zh=%q, want %q（详情槽不得丢失）", c.key, zh, c.zhPrefix+"%s")
		}
		if !strings.HasSuffix(en, "%s") || strings.HasSuffix(en, ": ") {
			t.Errorf("%s en=%q, want 以 %%s 承接详情（不得悬空冒号）", c.key, en)
		}
	}
}

// 集群节点动作动词词条化：动作词（审批/拒绝/删除/更新地址）此前以中文动词
// 直插 "%s节点成功" 的 %s 槽——英文用户看到「审批 node succeeded」。动词
// 必须登记为独立词条（zh 母本 + en 译文），消费侧按请求语言取词后再插值。
func TestCatalog_clusterNodeActionVerbsRegistered(t *testing.T) {
	cases := []struct{ key, zh, en string }{
		{"cluster.nodeActionApprove", "审批", "Approve"},
		{"cluster.nodeActionReject", "拒绝", "Reject"},
		{"cluster.nodeActionDelete", "删除", "Delete"},
		{"cluster.nodeActionUpdateAccessUrl", "更新地址", "Update access URL of"},
	}
	for _, c := range cases {
		if got := T(ZH, c.key); got != c.zh {
			t.Errorf("%s zh=%q, want %q", c.key, got, c.zh)
		}
		if got := T(EN, c.key); got != c.en {
			t.Errorf("%s en=%q, want %q", c.key, got, c.en)
		}
	}
}

// zh 母本 %sT 畸形（codemod 把生产方 fmt 的 %T 误转成 %s 时漏删 T）：
// 生产方 cluster_apply.go 渲染「列 x 的值（map[string]interface {}）无法
// 序列化为 JSON: …」，母本含 %sT 时字面量对不上，英文翻译永不命中。
func TestTrErr_columnSerializeFailureTranslates(t *testing.T) {
	msg := "列 geoip_countries 的值（map[string]interface {}）无法序列化为 JSON: unsupported type"
	want := "value of column geoip_countries (map[string]interface {}) cannot be serialized to JSON: unsupported type"
	if got := TrErr(msg, EN); got != want {
		t.Errorf("TrErr EN=%q, want %q", got, want)
	}
	if got := TrErr(msg, ZH); got != msg {
		t.Errorf("zh 应原样回落: %q", got)
	}
}
