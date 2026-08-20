package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// R48-1: UpdateRule 改域名时，cert_jobs 域名迁移会就地抹除已签发任务的 PEM。
// 补偿快照（SnapshotCertJobsForRule）必须先于迁移执行——否则迁移后 ACME 入队
// 失败触发 restoreACMEState 时，快照里只剩被抹空 PEM 的行，旧证书 PEM 从 DB
// 永久丢失：规则恢复旧域、任务却是新域+无 PEM，下一次配置再生成该规则无证书
// 可服务，TLS 静默中断且无自动恢复路径。
func TestUpdateRule_restores_issued_cert_pem_when_enqueue_fails_after_domain_migration(t *testing.T) {
	// Given：启用中的 acme_dns 规则（旧域）持有一条已签发任务（PEM 在库），
	// 改域名后 ACME 入队被强制失败。
	harness := newUpdateAuditRuleHandlers(t, "lb_migrate_pem", 0, false)
	seedAuditRule(t, "lb_migrate_pem", "before", "old.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_migrate_pem")
	var providerID int
	if err := db.DB.QueryRow("SELECT default_ca_provider_id FROM global_config WHERE id=1").Scan(&providerID); err != nil {
		t.Fatalf("read default provider: %v", err)
	}
	dnsResult, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('dns','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed dns config: %v", err)
	}
	dnsConfigID, err := dnsResult.LastInsertId()
	if err != nil {
		t.Fatalf("read dns config ID: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=?,ca_provider_id=? WHERE caddy_id='lb_migrate_pem'`, dnsConfigID, providerID); err != nil {
		t.Fatalf("bind acme config to rule: %v", err)
	}
	certPEM, keyPEM, err := generateTestCert("old.example.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("generate issued certificate: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,ca_provider_id)
		VALUES ('lb_migrate_pem','old.example.test','issued',?,?,datetime('now','+90 days'),?)`, certPEM, keyPEM, providerID); err != nil {
		t.Fatalf("seed issued certificate job: %v", err)
	}
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldCreate := createOrRequeueCertJob
	createOrRequeueCertJob = func(string, string, int, *services.CAQueueManager) (int, error) {
		return 0, errors.New("forced enqueue failure")
	}
	t.Cleanup(func() { createOrRequeueCertJob = oldCreate })
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_migrate_pem", strings.NewReader(`{"domain":"new.example.test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：入队失败 → 500，且补偿后规则回旧域、cert_jobs 恢复原行（含 PEM）。
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("update status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var ruleDomain string
	if err := db.DB.QueryRow("SELECT domain FROM lb_rules WHERE caddy_id='lb_migrate_pem'").Scan(&ruleDomain); err != nil {
		t.Fatalf("read restored rule: %v", err)
	}
	if ruleDomain != "old.example.test" {
		t.Fatalf("restored rule domain=%q, want old.example.test", ruleDomain)
	}
	var jobDomain, jobStatus, gotCertPEM, gotKeyPEM string
	if err := db.DB.QueryRow("SELECT domain,status,cert_pem,key_pem FROM cert_jobs WHERE rule_id='lb_migrate_pem'").
		Scan(&jobDomain, &jobStatus, &gotCertPEM, &gotKeyPEM); err != nil {
		t.Fatalf("read restored cert job: %v", err)
	}
	if jobDomain != "old.example.test" || jobStatus != "issued" {
		t.Fatalf("restored job=(%q,%q), want (old.example.test,issued)", jobDomain, jobStatus)
	}
	if gotCertPEM != certPEM || gotKeyPEM != keyPEM {
		t.Fatalf("restored job PEM lost: cert_pem match=%v key_pem match=%v, want original PEM preserved",
			gotCertPEM == certPEM, gotKeyPEM == keyPEM)
	}
}

// R48-3: validateV2BackupSecurityPolicies 此前对非字符串 crs_* 值（数字/布尔/数组）
// 经 backupString 静默归一为 ""→"[]" 放行，而保存侧（security.go Create/Update）
// 对同值 JSON 绑定直接 400——导入校验必须至少与保存侧同严：原始值存在且非字符串
// （非 null/缺省）时拒绝并点名策略+字段；null/缺省仍归一为 "[]"。
func TestImportConfigBackup_rejects_non_string_crs_fields_in_security_policy(t *testing.T) {
	tests := []struct {
		name       string
		groups     any
		exclusions any
		omitFields bool
		wantReject bool
	}{
		{name: "数字类型组号", groups: 123, exclusions: "[]", wantReject: true},
		{name: "数组类型组号", groups: []any{"42"}, exclusions: "[]", wantReject: true},
		{name: "布尔类型组号", groups: true, exclusions: "[]", wantReject: true},
		{name: "数字类型排除项", groups: "[]", exclusions: 942100, wantReject: true},
		{name: "null 归一为 []", groups: nil, exclusions: nil, wantReject: false},
		{name: "缺省字段归一为 []", omitFields: true, wantReject: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given 一个 security_policies 携带非字符串/null/缺省 crs 字段的完整 v2 备份
			h := newBackupTestHandlers(t)
			gin.SetMode(gin.TestMode)
			row := map[string]any{"id": 1, "name": "crs-typed-policy", "mode": "blocking"}
			if !tt.omitFields {
				row["crs_rule_groups"] = tt.groups
				row["crs_excluded_rules"] = tt.exclusions
			}
			backup := completeBackupJSON(t, map[string][]map[string]any{"security_policies": {row}})
			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if tt.wantReject {
				if response.Code != http.StatusBadRequest {
					t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
				}
				if !strings.Contains(response.Body.String(), "crs-typed-policy") {
					t.Fatalf("rejection must name the policy: %s", response.Body.String())
				}
				field := "crs_rule_groups"
				if tt.name == "数字类型排除项" {
					field = "crs_excluded_rules"
				}
				if !strings.Contains(response.Body.String(), field) {
					t.Fatalf("rejection must name the field %s: %s", field, response.Body.String())
				}
				var count int
				if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE name='crs-typed-policy'").Scan(&count); err != nil {
					t.Fatalf("read imported policy: %v", err)
				}
				if count != 0 {
					t.Fatalf("rejected backup must not persist the policy, got %d rows", count)
				}
				return
			}
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var groups, exclusions string
			if err := db.DB.QueryRow("SELECT crs_rule_groups, crs_excluded_rules FROM security_policies WHERE name='crs-typed-policy'").Scan(&groups, &exclusions); err != nil {
				t.Fatalf("read imported policy: %v", err)
			}
			if groups != "[]" || exclusions != "[]" {
				t.Fatalf("imported crs fields=(%q,%q), want ([] , [])", groups, exclusions)
			}
		})
	}
}
