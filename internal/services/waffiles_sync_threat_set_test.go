package services

import (
	"testing"

	"lazy-balancer-v2/internal/models"
)

// bundle/ref 的威胁面核验必须是「集合精确相等 + 名称唯一」：只校验 ref 声明的
// 源存在且哈希相符时，损坏/恶意主节点可以额外塞入未声明条目（Apply 会逐条落盘），
// 或用同名第二条覆盖预期名单——从节点落进未由快照引用授权的威胁清单。
func TestWafFilesRefMatchesBundle_threatSetMustMatchExactly(t *testing.T) {
	ref := &models.ClusterWafFilesRef{ThreatSha256s: map[string]string{"spam404": "hash-1", "firehol1": "hash-2"}}
	entry := func(name, sha string) models.ThreatFileEntry {
		return models.ThreatFileEntry{Name: name, Sha256: sha}
	}

	for _, tc := range []struct {
		name   string
		bundle *WafFileBundle
		want   bool
	}{
		{
			name:   "集合精确相等（顺序无关）",
			bundle: &WafFileBundle{ThreatFiles: []models.ThreatFileEntry{entry("firehol1", "hash-2"), entry("spam404", "hash-1")}},
			want:   true,
		},
		{
			name:   "bundle 多出未声明条目",
			bundle: &WafFileBundle{ThreatFiles: []models.ThreatFileEntry{entry("spam404", "hash-1"), entry("firehol1", "hash-2"), entry("et_compromised", "hash-3")}},
			want:   false,
		},
		{
			name:   "bundle 同名重复条目",
			bundle: &WafFileBundle{ThreatFiles: []models.ThreatFileEntry{entry("spam404", "hash-1"), entry("firehol1", "hash-2"), entry("spam404", "hash-1")}},
			want:   false,
		},
		{
			name:   "ref 声明源缺失",
			bundle: &WafFileBundle{ThreatFiles: []models.ThreatFileEntry{entry("spam404", "hash-1")}},
			want:   false,
		},
		{
			name:   "哈希不符",
			bundle: &WafFileBundle{ThreatFiles: []models.ThreatFileEntry{entry("spam404", "hash-x"), entry("firehol1", "hash-2")}},
			want:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wafFilesRefMatchesBundle(ref, tc.bundle); got != tc.want {
				t.Fatalf("wafFilesRefMatchesBundle=%v, want %v（威胁条目必须集合相等且名称唯一）", got, tc.want)
			}
		})
	}
}

// 回归形状：双方都没有威胁条目（威胁同步关闭/无 .fast 文件的部署）时必须匹配。
// 反向形态（ref 未声明而 bundle 携带条目）属「额外条目」，与显式声明后多塞一条
// 同源同罪，一律拒绝——主节点 BuildWafFileBundle 只按 ref 声明的源打包，正常
// 协议不会产生该形态。
func TestWafFilesRefMatchesBundle_emptyThreatSurfacesMatch(t *testing.T) {
	ref := &models.ClusterWafFilesRef{}
	if !wafFilesRefMatchesBundle(ref, &WafFileBundle{}) {
		t.Fatalf("双方均无威胁条目时必须匹配")
	}
	undeclared := &WafFileBundle{ThreatFiles: []models.ThreatFileEntry{{Name: "spam404", Sha256: "h"}}}
	if wafFilesRefMatchesBundle(ref, undeclared) {
		t.Fatalf("ref 未声明威胁面而 bundle 携带条目（额外条目）必须拒绝")
	}
}
