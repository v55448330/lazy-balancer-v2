package handlers

// 导入携带变更的 human_secret 时运行配置必须收敛到新值：事务内 Caddy 应用
// 读已提交库（WAL 下未提交 tx 不可见）=旧密钥，缓存失效在提交后——若提交后
// 无重渲染，运行 Caddy 的 lb_human.secret 停留旧值直至下一次无关重载
// （集群形态主从密钥分叉，已签发挑战凭证互不通过）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// humanSecretLoadRecorder 记录 fake admin 每次 /load 载荷中的 lb_human.secret。
type humanSecretLoadRecorder struct {
	mu      sync.Mutex
	secrets []string
	last    map[string]any
}

func (r *humanSecretLoadRecorder) handler() http.HandlerFunc {
	extract := func(cfg map[string]any) []string {
		var out []string
		var walk func(any)
		walk = func(node any) {
			switch v := node.(type) {
			case map[string]any:
				if v["handler"] == "lb_human" {
					if s, ok := v["secret"].(string); ok {
						out = append(out, s)
					}
				}
				for _, ch := range v {
					walk(ch)
				}
			case []any:
				for _, ch := range v {
					walk(ch)
				}
			}
		}
		walk(cfg)
		return out
	}
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost && req.URL.Path == "/load" {
			var payload map[string]any
			if err := json.NewDecoder(req.Body).Decode(&payload); err == nil {
				r.mu.Lock()
				r.last = payload
				r.secrets = append(r.secrets, extract(payload)...)
				r.mu.Unlock()
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		r.mu.Lock()
		cfg := r.last
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if cfg == nil {
			cfg = map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(cfg)
	}
}

func (r *humanSecretLoadRecorder) runningSecrets(t *testing.T, h *Handlers) []string {
	t.Helper()
	running, err := h.caddyService.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	var out []string
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if v["handler"] == "lb_human" {
				if s, ok := v["secret"].(string); ok {
					out = append(out, s)
				}
			}
			for _, ch := range v {
				walk(ch)
			}
		case []any:
			for _, ch := range v {
				walk(ch)
			}
		}
	}
	walk(running)
	return out
}

// Given 库内已播种密钥且进程缓存已装载（导入前运行态）。
// When 导入携带异值 human_secret 的备份（Config 区不含 branding_json——
// reseed 重载不触发的形态）。
// Then 运行中配置（fake admin 最后接受的 /load）的 lb_human.secret=新值。
func TestImportConfigBackup_humanSecretConvergesRunningConfig(t *testing.T) {
	h := newBackupTestHandlers(t)
	stubHumanSecretRenderLibs(t)
	seedHumanSecretImportFixture(t)

	var oldSecret string
	if err := db.DB.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&oldSecret); err != nil || oldSecret == "" {
		t.Fatalf("前置：读取播种密钥失败 %q err=%v", oldSecret, err)
	}
	if got := renderedHumanSecrets(t); len(got) != 1 || got[0] != oldSecret {
		t.Fatalf("前置渲染 secret=%v, want [%s]", got, oldSecret)
	}

	rec := &humanSecretLoadRecorder{}
	fakeCaddy := httptest.NewServer(rec.handler())
	t.Cleanup(fakeCaddy.Close)
	h.caddyService = services.NewCaddyService(fakeCaddy.URL)

	const newSecret = "imported-human-secret-0123456789abcdef"
	backup := buildBackup(t, backupFixtureOptions{
		FillAll: true,
		Omit:    map[string]struct{}{"security_ip_lists": {}, "lb_rules": {}, "upstreams": {}, "security_policies": {}, "security_policy_bindings": {}, "security_block_pages": {}},
		Config:  map[string]any{"human_secret": newSecret},
	})
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var stored string
	_ = db.DB.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&stored)
	if stored != newSecret {
		t.Fatalf("前置不成立：库未落新值 %q", stored)
	}
	runSecrets := rec.runningSecrets(t, h)
	if len(runSecrets) == 0 {
		t.Fatal("运行配置无 lb_human handler——夹具人机链未发射")
	}
	if runSecrets[0] != newSecret {
		t.Fatalf("运行配置 secret=%v, want [%s]（提交后必须收敛重载，不得停留旧密钥）", runSecrets, newSecret)
	}
}

// 回归形状：携带 branding_json 时 reseed 已触发提交后重载——密钥收敛不
// 重复发射（/load 序列中旧值仅事务内一次，新值一次）。
func TestImportConfigBackup_humanSecretWithBrandingNoDoubleApply(t *testing.T) {
	h := newBackupTestHandlers(t)
	stubHumanSecretRenderLibs(t)
	seedHumanSecretImportFixture(t)
	var oldSecret string
	_ = db.DB.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&oldSecret)
	if got := renderedHumanSecrets(t); len(got) != 1 || got[0] != oldSecret {
		t.Fatalf("前置渲染 secret=%v, want [%s]", got, oldSecret)
	}
	rec := &humanSecretLoadRecorder{}
	fakeCaddy := httptest.NewServer(rec.handler())
	t.Cleanup(fakeCaddy.Close)
	h.caddyService = services.NewCaddyService(fakeCaddy.URL)

	const newSecret = "imported-human-secret-fedcba9876543210"
	backup := buildBackup(t, backupFixtureOptions{
		FillAll: true,
		Omit:    map[string]struct{}{"security_ip_lists": {}, "lb_rules": {}, "upstreams": {}, "security_policies": {}, "security_policy_bindings": {}},
		Config:  map[string]any{"human_secret": newSecret, "branding_json": `{"app_name":"restore-brand"}`},
	})
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	runSecrets := rec.runningSecrets(t, h)
	if len(runSecrets) == 0 || runSecrets[0] != newSecret {
		t.Fatalf("运行配置 secret=%v, want [%s]", runSecrets, newSecret)
	}
	rec.mu.Lock()
	seq := append([]string{}, rec.secrets...)
	rec.mu.Unlock()
	newCount := 0
	for _, s := range seq {
		if s == newSecret {
			newCount++
		}
	}
	if newCount != 1 {
		t.Fatalf("/load 序列新值出现 %d 次, want 1（reseed 已重载不得重复发射）: %v", newCount, seq)
	}
}
