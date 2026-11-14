package services

// 集群同步拉取的版本串不在 HMAC/哈希覆盖内（流氓主节点可注入超长/控制
// 字符），CRS/v4 标签在 fetchWafFiles 落盘前经 sanitizeBundleVersion 消毒，
// v6 标签必须同口径——否则注入内容直写 .version 伴生文件与审计详情。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
