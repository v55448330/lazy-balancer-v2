package services

// 集群同步拉取的版本串不在 HMAC/哈希覆盖内（流氓主节点可注入超长/控制
// 字符），CRS/v4 标签在 fetchWafFiles 落盘前经 sanitizeBundleVersion 消毒，
// v6 标签必须同口径——否则注入内容直写 .version 伴生文件与审计详情。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestFetchWafFiles_sanitizesV6VersionTag(t *testing.T) {
	_, database := newClusterTestService(t)
	injected := "v6.0.0\n" + strings.Repeat("x", 80) // 控制字符 + 超长
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": WafFileBundle{
			CRSVersion:     "v4.29.0",
			IP2RegionTag:   "v3.17.0",
			IP2RegionV6Tag: injected,
		}})
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET master_url=?, cluster_token='token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := &SyncService{db: database, client: &http.Client{}}

	bundle, err := service.fetchWafFiles(context.Background(), &models.ClusterWafFilesRef{})
	if err != nil {
		t.Fatalf("fetchWafFiles: %v", err)
	}
	if bundle.IP2RegionV6Tag != "" {
		t.Fatalf("畸形 v6 版本串必须消毒置空（与 CRS/v4 同口径），got %q", bundle.IP2RegionV6Tag)
	}
	// 合法版本串零变化（三族同钉，防消毒误伤正常同步）。
	if bundle.CRSVersion != "v4.29.0" || bundle.IP2RegionTag != "v3.17.0" {
		t.Fatalf("合法版本串必须原样保留: %+v", bundle)
	}
}

// Given 本地 v6 库伴生 .version 与 ref 声明的 IP2RegionV6Tag。
// When 「同步开关关闭」轻量比对（wafFilesRefVersionLabelsDiffer）。
// Then v6 标签必须参与判定：一致→不判分叉；不一致→分叉；标签文件缺失但
// ref 声明非空→分叉（读失败按分叉，不静默放行）。
// 此前轻量比对只钉了 threat 段，v6 分支删掉也全绿（标签面漏判会让从端
// 停在旧 v6 库上不重拉）。
func TestWafFilesRefVersionLabelsDiffer_v6TagBranch(t *testing.T) {
	dir := t.TempDir()
	oldV6 := ip2regionV6LivePath
	ip2regionV6LivePath = filepath.Join(dir, "ip2region_v6.xdb")
	t.Cleanup(func() { ip2regionV6LivePath = oldV6 })

	label := ip2regionV6LivePath + ".version"
	if err := os.WriteFile(label, []byte("v6.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := &models.ClusterWafFilesRef{IP2RegionV6Tag: "v6.1.0"}
	if wafFilesRefVersionLabelsDiffer(ref) {
		t.Fatal("v6 标签一致时不得判分叉")
	}

	if err := os.WriteFile(label, []byte("v6.2.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !wafFilesRefVersionLabelsDiffer(ref) {
		t.Fatal("v6 标签不一致必须判分叉")
	}

	if err := os.Remove(label); err != nil {
		t.Fatal(err)
	}
	if !wafFilesRefVersionLabelsDiffer(ref) {
		t.Fatal("ref 声明非空而本地 v6 标签缺失（读失败）必须判分叉")
	}
}
