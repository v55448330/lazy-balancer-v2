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
		"EvtAdminTLSChanged":        EvtAdminTLSChanged,
		"EvtOIDCChanged":            EvtOIDCChanged,
		"EvtAutoBackupChanged":      EvtAutoBackupChanged,
		"EvtNotificationCfgChanged": EvtNotificationCfgChanged,
		"EvtClusterSettingsChanged": EvtClusterSettingsChanged,
		"EvtCAProviderChanged":      EvtCAProviderChanged,
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
	for evt, id := range newEvents {
		if !strings.Contains(src, evt) {
			t.Errorf("事件 %s（%s）无发布点——handler/services 内无 notify.Publish 消费该常量", id, evt)
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
