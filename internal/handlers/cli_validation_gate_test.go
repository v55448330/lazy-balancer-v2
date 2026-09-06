package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 2026-09-06 裁定 ④'（修正）：任意 Caddy 修改三层校验——前端表单 + 后端字段
// + Caddy CLI（真 validate-only：provision 不运行不绑端口）。CLI 层校验的输入
// 是事务视图渲染出的最终全量配置（校验=将应用），拒绝→回滚 400 不落库；
// 校验器不可用（二进制缺失/超时）→ 记日志放行，事务内 apply 仍是最终门控。
func TestRuleWrite_cliRejectionBlocksCommit(t *testing.T) {
	// Given：CLI 校验桩拒绝一切配置
	handler, _, _ := newAuditRuleHandlers(t, 0)
	handler.caddyService.SetCLIValidatorForTest(func(rendered []byte) error {
		if !strings.Contains(string(rendered), "cli-gate.example.test") {
			return errors.New("渲染产物未包含候选规则")
		}
		return errors.New("coraza: invalid directive in candidate config")
	})
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	// When
	rec := httptest.NewRecorder()
	body := `{"name":"cli-gate","protocol":"http","domain":"cli-gate.example.test","listen_port":8093,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	// Then：400 + 未落库 + 失败审计
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s, want 400（CLI 校验拒绝不得落库）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "coraza: invalid directive") {
		t.Fatalf("body=%s, want CLI rejection detail", rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE domain='cli-gate.example.test'").Scan(&count); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("cli-rejected rule committed rows=%d, want 0", count)
	}
}

func TestRuleWrite_cliUnavailableFailsOpen(t *testing.T) {
	// Given：CLI 校验器不可用（二进制缺失/超时语义）
	handler, _, _ := newAuditRuleHandlers(t, 0)
	handler.caddyService.SetCLIValidatorForTest(func(rendered []byte) error {
		return services.ErrCLIValidatorUnavailable
	})
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	// When
	rec := httptest.NewRecorder()
	body := `{"name":"cli-open","protocol":"http","domain":"cli-open.example.test","listen_port":8094,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	// Then：放行（事务内 apply 仍是门控）
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s, want 201（校验器不可用应放行）", rec.Code, rec.Body.String())
	}
}

func TestSecurityWrite_cliRejectionBlocksCommit(t *testing.T) {
	// Given：安全域写入口（finishTxApply 家族）同样过 CLI 层
	setupSecurityPolicyTestDB(t)
	handler, _, _ := newAuditRuleHandlers(t, 0)
	handler.caddyService.SetCLIValidatorForTest(func(rendered []byte) error {
		return errors.New("cli: block page reference invalid")
	})
	router := gin.New()
	router.POST("/security/custom-rules", handler.CreateSecurityCustomRule)

	// When
	rec := httptest.NewRecorder()
	body := `{"name":"cli 安全层","conditions":[{"target":"uri","operator":"contains","pattern":"/admin"}],"action":"block","score":5,"enabled":true}`
	request := httptest.NewRequest(http.MethodPost, "/security/custom-rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	// Then
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_custom_rules WHERE name='cli 安全层'").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("cli-rejected security rule rows=%d, want 0", count)
	}
}

// 边界补齐（裁定 ④'）：逃生口与导入同样过 CLI 校验层。
func TestPutCaddyConfig_cliRejectionBlocksSave(t *testing.T) {
	// Given：CLI 校验桩拒绝
	handler, _, _ := newAuditRuleHandlers(t, 0)
	handler.caddyService.SetCLIValidatorForTest(func(rendered []byte) error {
		return errors.New("cli: tls app directive invalid")
	})
	router := gin.New()
	router.PUT("/caddy/config", handler.PutCaddyConfig)

	// When
	var before string
	if err := db.DB.QueryRow("SELECT COALESCE(caddy_config,'') FROM global_config WHERE id=1").Scan(&before); err != nil {
		t.Fatalf("read caddy_config before: %v", err)
	}
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/caddy/config", strings.NewReader(`{"content":"{\"apps\":{}}"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	// Then：400 + caddy_config 列未被写入（与请求前一致）
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("put config status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow("SELECT COALESCE(caddy_config,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatalf("read caddy_config: %v", err)
	}
	if stored != before {
		t.Fatalf("cli-rejected config stored=%q, want unchanged %q", stored, before)
	}
}

func TestImportConfigBackup_cliRejectionAbortsImport(t *testing.T) {
	// Given：CLI 校验桩拒绝 + 一份合法备份（含一条 IP 列表）
	h := newBackupTestHandlers(t)
	h.caddyService.SetCLIValidatorForTest(func(rendered []byte) error {
		return errors.New("cli: import render rejected")
	})
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_ip_lists": {{"id": 1, "name": "cli-abort-list", "entries": "[]"}},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// When
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	// Then：导入中止（全有全无）+ 表数据未落库
	if rec.Code < 300 {
		t.Fatalf("import status=%d body=%s, want failure（CLI 拒绝必须中止导入）", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists WHERE name='cli-abort-list'").Scan(&count); err != nil {
		t.Fatalf("count ip lists: %v", err)
	}
	if count != 0 {
		t.Fatalf("cli-aborted import left rows=%d, want 0", count)
	}
}

// 乱填保障闭环（2026-09-06 补充裁定）：CLI 校验器不可用 + admin 传输失败 =
// 配置未经任何 Caddy 级校验且无法应用——此情形下不得退化提交（无法排除
// 坏配置），必须回滚并明确报错；服务与运行配置不受影响。
func TestSecurityWrite_unvalidatedApplyFailsClosed(t *testing.T) {
	// Given：CLI 校验器不可用 + Caddy 管理接口不可达
	setupSecurityPolicyTestDB(t)
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := closed.URL
	closed.Close()
	handler, _, _ := newAuditRuleHandlers(t, 0)
	handler.caddyService = newUnreachableCaddyService(t, url)
	handler.caddyService.SetCLIValidatorForTest(func(rendered []byte) error {
		return services.ErrCLIValidatorUnavailable
	})
	router := gin.New()
	router.POST("/security/custom-rules", handler.CreateSecurityCustomRule)

	// When
	rec := httptest.NewRecorder()
	body := `{"name":"乱填保障","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"block","score":5,"enabled":true}`
	request := httptest.NewRequest(http.MethodPost, "/security/custom-rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	// Then：写入失败（不得 200+落库），DB 零行
	if rec.Code < 400 {
		t.Fatalf("create status=%d body=%s, want ≥400（未经校验的应用失败必须回滚）", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_custom_rules WHERE name='乱填保障'").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("unvalidated write committed rows=%d, want 0", count)
	}
}

func newUnreachableCaddyService(t *testing.T, url string) *services.CaddyService {
	t.Helper()
	return services.NewCaddyService(url)
}
