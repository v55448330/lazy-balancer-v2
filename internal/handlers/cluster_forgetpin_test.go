package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 2026-09-06 二轮 C-3：主节点侧按节点 pin 重置端点——主节点 + 存在节点 → 200
// 且仅删除该节点 pin 文件；从节点调用 → 403（requireMaster 门）；节点不存在 →
// 404。与从节点侧 forget-pins 端点（TestGetClusterWafFiles_demotedMasterForbidden
// 同搭建模式）对称。
func TestForgetClusterNodePin_removesTargetPinAndGuards(t *testing.T) {
	// Given：主节点 + 节点 31（access_url 定位钉）+ 对应 pin 文件
	// （cluster_ca_pins/<sha256("host:port")>，与 services 侧 TOFU 钉扎同一命名）
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,access_url,is_approved) VALUES (31,'slave-pin','172.18.0.2',8000,'http','https://slave-pin.example:8443',1)`); err != nil {
		t.Fatal(err)
	}
	hostHash := sha256.Sum256([]byte("slave-pin.example:8443"))
	pinPath := filepath.Join(dataDir, "cluster_ca_pins", hex.EncodeToString(hostHash[:]))
	if err := os.MkdirAll(filepath.Dir(pinPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte("sha256-fingerprint\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{
		clusterService: services.NewClusterService(db.DB, nil),
		syncService:    services.NewSyncService(db.DB, &config.Config{DataDir: dataDir}, nil),
	}
	router := gin.New()
	router.POST("/cluster/nodes/:id/forget-pin", h.ForgetClusterNodePin)
	call := func(id string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/cluster/nodes/"+id+"/forget-pin", nil).WithContext(context.Background())
		router.ServeHTTP(response, request)
		return response
	}

	// When：主节点清除节点 31 的钉
	response := call("31")

	// Then：200，pin 文件已删除
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q, want 200", response.Code, response.Body.String())
	}
	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Fatalf("pin file still exists: %v", err)
	}

	// When：节点不存在
	response = call("999")
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing node status=%d body=%q, want 404", response.Code, response.Body.String())
	}

	// When：从节点调用（requireMaster 门）
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	response = call("31")
	if response.Code != http.StatusForbidden {
		t.Fatalf("slave status=%d body=%q, want 403", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "仅允许在主节点执行") {
		t.Fatalf("slave rejection body=%q, want requireMaster message", response.Body.String())
	}
}
