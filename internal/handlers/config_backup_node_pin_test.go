package handlers

// 备份导入删除节点时，TOFU 指纹钉清理必须与导入事务同生共死：目标在事务内
// 识别（地址解析需现存行），实际删除排入 session.postLockActions、提交成功后
// 才落地。abort/回滚（Caddy CLI 拒绝）不再先清后回——旧实现在事务内直接删
// pin 文件，失败导入的「幸存节点」在下次服务控制按 TOFU 重新钉扎，安全边界
// 随一次失败导入退化为首连即信。

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// writeImportNodePin 复算服务层 pin 命名（cluster_ca_pins/<sha256(host:port)>）
// 落盘，并用 ForgetNodePinHost 探针自证命名未漂移（探针删除后重建）：命名
// 漂移时此处先红，主断言不会静默通过。
func writeImportNodePin(t *testing.T, clusterService *services.ClusterService, dataDir, host string) {
	t.Helper()
	parsed := &url.URL{Host: host}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	sum := sha256.Sum256([]byte(net.JoinHostPort(strings.ToLower(parsed.Hostname()), port)))
	dir := filepath.Join(dataDir, "cluster_ca_pins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(path, []byte("sha256-fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := clusterService.ForgetNodePinHost(host); err != nil {
		t.Fatalf("pin 命名自证失败（服务层命名可能已漂移）: %v", err)
	}
	if err := os.WriteFile(path, []byte("sha256-fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// newImportNodePinHarness 装配「本地节点 21（https://10.0.0.21:8000，持 pin）
// + 备份只携带另一节点」的导入场景：节点 21 属「将被删除」目标。
func newImportNodePinHarness(t *testing.T) (*Handlers, *gin.Engine, string) {
	t.Helper()
	h := newBackupTestHandlers(t)
	seedAdminShared(t)
	dataDir := t.TempDir()
	h.cfg.DataDir = dataDir
	h.clusterService = services.NewClusterService(db.DB, dataDir)
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,protocol,is_approved) VALUES (21,'pin-node','slave','10.0.0.21',8000,'https',1)`); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	const host = "10.0.0.21:8000"
	writeImportNodePin(t, h.clusterService, dataDir, host)

	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	return h, router, host
}

func importNodePinBackup(t *testing.T, router *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	body := buildBackup(t, backupFixtureOptions{FillAll: true, Sections: []string{"cluster", "rules"}, Tables: map[string][]map[string]any{
		"nodes": {{
			"name": "survivor", "mode": "slave", "ip_address": "10.0.0.22", "port": 8000,
			"protocol": "https", "is_approved": 1, "sync_interval": 60,
		}},
		"lb_rules": {{"caddy_id": "lb_pinimp", "name": "pinimp", "protocol": "http", "domain": "pinimp.example.test", "listen_port": 8099, "enabled": 1}},
	}, EmptyConfigIfNil: true})
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// Caddy CLI 拒绝 → 导入回滚：被删除目标节点的 pin 文件必须原样保留
// （旧实现在事务提交前已删，失败后 ErrNoClusterPin）。
func TestImportBackup_caddyRejectionKeepsDeletedNodePin(t *testing.T) {
	h, router, host := newImportNodePinHarness(t)
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return errors.New("cli: reject pin-import") })

	response := importNodePinBackup(t, router)
	if response.Code == http.StatusOK {
		t.Fatalf("CLI 拒绝必须中止导入, got 200 body=%s", response.Body.String())
	}

	var nodeCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id=21`).Scan(&nodeCount); err != nil {
		t.Fatal(err)
	}
	if nodeCount != 1 {
		t.Fatalf("回滚后本地节点 21 必须仍在, got count=%d", nodeCount)
	}
	if pinErr := h.clusterService.ForgetNodePinHost(host); pinErr != nil {
		t.Fatalf("失败回滚后 pin 必须仍存在（ForgetNodePinHost 应删除成功）, got %v", pinErr)
	}
}

// 提交成功 → pin 清理照常落地（证明 postLockActions 登记不是死代码）：
// 被删除目标节点的 pin 必须已清（ErrNoClusterPin），备份携带的存活节点在库。
func TestImportBackup_successClearsDeletedNodePin(t *testing.T) {
	h, router, host := newImportNodePinHarness(t)

	response := importNodePinBackup(t, router)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	var survivorCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE ip_address='10.0.0.22'`).Scan(&survivorCount); err != nil {
		t.Fatal(err)
	}
	if survivorCount != 1 {
		t.Fatalf("存活节点必须来自备份, got count=%d", survivorCount)
	}
	if pinErr := h.clusterService.ForgetNodePinHost(host); !errors.Is(pinErr, services.ErrNoClusterPin) {
		t.Fatalf("提交成功后已删除节点的 pin 必须已清理（want ErrNoClusterPin）, got %v", pinErr)
	}
}
