package notify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 2026-11-21 查漏补缺批：每类新增事件必须有真实发布点（handler/services
// 内 notify.Publish 消费）——只进目录不发布的常量是死键，订阅矩阵永远收不到。
func TestNewEventTypesHavePublishSites(t *testing.T) {
	// 键=常量名（源码搜索词），值=事件 ID（目录断言用）
	newEvents := map[string]string{
		"EvtCaddyLifecycle":         EvtCaddyLifecycle,
		"EvtOIDCChanged":            EvtOIDCChanged,
		"EvtAutoBackupChanged":      EvtAutoBackupChanged,
		"EvtNotificationCfgChanged": EvtNotificationCfgChanged,
		"EvtClusterSettingsChanged": EvtClusterSettingsChanged,
		"EvtCertConfigChanged":      EvtCertConfigChanged,
		"EvtPolicyChanged":          EvtPolicyChanged,
		"EvtIPListChanged":          EvtIPListChanged,
		"EvtCustomRuleChanged":      EvtCustomRuleChanged,
		"EvtBlockPageChanged":       EvtBlockPageChanged,
		"EvtAutobanCfgChanged":      EvtAutobanCfgChanged,
		"EvtMCPDisconnected":        EvtMCPDisconnected,
		"EvtLibUpdated":             EvtLibUpdated,
		"EvtLibSettingsChanged":     EvtLibSettingsChanged,
		"EvtClusterServiceControl":  EvtClusterServiceControl,
		"EvtClusterLoginTicket":     EvtClusterLoginTicket,
		"EvtClusterNodeSettings":    EvtClusterNodeSettings,
		"EvtClusterManualSync":      EvtClusterManualSync,
		"EvtAPIKeyToggled":          EvtAPIKeyToggled,
		"EvtRestartRequested":       EvtRestartRequested,
		"EvtTaskManualAction":       EvtTaskManualAction,
		"EvtNotifyChannelChanged":   EvtNotifyChannelChanged,
		"EvtNotifyRuleChanged":      EvtNotifyRuleChanged,
	}
	// handlers+services 源码全文（排除测试）
	root := ".."
	var corpus strings.Builder
	for _, dir := range []string{filepath.Join(root, "handlers"), filepath.Join(root, "services")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			corpus.Write(b)
		}
	}
	src := corpus.String()
	// 统一发布 helper：常量只在 notify 包内使用（handler/services 调用 helper），
	// 发布点守卫按 helper 名核对，避免把「封装」误判为「无发布点」。
	publishTokens := map[string]string{
		"EvtLibUpdated":        "PublishLibUpdateResult", // 四库手动/自动统一终态事件
		"EvtCertConfigChanged": "publishCertConfigChanged",
	}
	for evt, id := range newEvents {
		token := evt
		if t, ok := publishTokens[evt]; ok {
			token = t
		}
		if !strings.Contains(src, token) {
			t.Errorf("事件 %s（%s）无发布点——handler/services 内无 %s 消费路径", id, evt, token)
		}
	}
	// 目录完整性：新常量必须进 catalog（订阅矩阵可见）
	byID := map[string]bool{}
	for _, e := range catalog {
		byID[e.ID] = true
	}
	for _, id := range newEvents {
		if !byID[id] {
			t.Errorf("事件 %s 未进事件目录——订阅矩阵不可见", id)
		}
	}
}
