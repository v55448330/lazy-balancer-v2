package notify

import "testing"

func TestEveryCatalogEventHasDescription(t *testing.T) {
	for _, e := range catalog {
		if catalogDescriptions[e.ID] == "" {
			t.Errorf("事件 %s 缺少说明（订阅浮层无法 hover 解释触发条件）", e.ID)
		}
	}
	for _, e := range CatalogExport() {
		if e.Description == "" {
			t.Errorf("CatalogExport %s description 为空", e.ID)
		}
	}
}
