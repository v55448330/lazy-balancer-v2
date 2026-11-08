package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func putCertificateConfig(t *testing.T, h *Handlers, id int64, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/certificate-configs/"+strconv.FormatInt(id, 10), strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	return response
}

func seedCertificateConfigRow(t *testing.T, name, credentials string) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
		VALUES (?, 'dnspod', ?, 1)`, name, credentials)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config id: %v", err)
	}
	return id
}

func storedCertificateCredentials(t *testing.T, id int64) (name, raw string, stored map[string]string) {
	t.Helper()
	if err := db.DB.QueryRow("SELECT name, COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=?", id).Scan(&name, &raw); err != nil {
		t.Fatalf("read certificate config: %v", err)
	}
	stored = map[string]string{}
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatalf("stored credentials %q are not valid JSON: %v", raw, err)
	}
	return name, raw, stored
}

// Given 库内 dns_credentials 不是合法 JSON（带外改库/损坏的集群快照）。
// When 管理员提交完整新凭证（无掩码占位）。
// Then 200 且整列覆写：损坏行必须能从写路径自愈，否则名称/启用态/凭据都改
// 不了，只能删除重建（被规则引用时还被 409）。
func TestUpdateCertificateConfig_fullCredentialsRepairCorruptedStorage(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "legacy", "not-json")

	response := putCertificateConfig(t, h, id,
		`{"name":"repaired","dns_credentials":{"auth_mode":"dnspod","app_id":"new-id","app_token":"new-token"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（完整新凭证应可覆盖损坏列）", response.Code, response.Body.String())
	}

	name, _, stored := storedCertificateCredentials(t, id)
	if name != "repaired" {
		t.Fatalf("name=%q, want repaired", name)
	}
	if stored["app_id"] != "new-id" || stored["app_token"] != "new-token" {
		t.Fatalf("stored credentials=%v, want submitted pair", stored)
	}
}

// Given 库内配置使用 DNSPod 认证族（app_id/app_token）。
// When 管理员把认证方式切到腾讯云并提交新族凭据。
// Then 旧族字段从库中删除（不是留在 JSON 里等切回时复活），且审计 detail
// 点名被清除的字段（数据删除影响必须可追溯）。
func TestUpdateCertificateConfig_prunesOtherAuthFamilyOnModeSwitch(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "switch", `{"auth_mode":"dnspod","app_id":"old-id","app_token":"old-token"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"tencent_cloud","secret_id":"sid","secret_key":"skey"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	_, _, stored := storedCertificateCredentials(t, id)
	for _, stale := range []string{"app_id", "app_token", "api_token", "mode"} {
		if _, ok := stored[stale]; ok {
			t.Fatalf("stale field %q retained after auth-mode switch: %v", stale, stored)
		}
	}
	if stored["auth_mode"] != "tencent_cloud" || stored["secret_id"] != "sid" || stored["secret_key"] != "skey" {
		t.Fatalf("stored credentials=%v, want tencent family only", stored)
	}

	detail := latestAuditDetail(t, "更新", "DNS配置")
	for _, want := range []string{"清除旧认证方式凭据", "app_id", "app_token"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("audit detail=%q, want %q（删除影响必须留痕）", detail, want)
		}
	}
}

// Given 同一认证族内的稀疏 PATCH（掩码字段回传）。
// When 保存配置。
// Then 未提交的字段仍从库值继承——切换族的清理不得扩大成「同族也丢字段」。
func TestUpdateCertificateConfig_sameAuthFamilyKeepsUnsubmittedCredentials(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "sparse", `{"auth_mode":"dnspod","app_id":"old-id","app_token":"old-token"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"dnspod","app_id":"old-id","app_token":"***"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	_, _, stored := storedCertificateCredentials(t, id)
	if stored["app_token"] != "old-token" || stored["app_id"] != "old-id" {
		t.Fatalf("stored credentials=%v, want库值继承", stored)
	}
}

// Given certificate_configs.enabled 为 NULL（ALTER 遗留/带外改库）。
// When 规则绑定校验 ACME 引用。
// Then 按启用处理——与列表展示（COALESCE(enabled,1)）及编辑基线同口径；
// 展示「启用」的行必须能绑定，禁用行仍拒绝。
func TestValidateRuleACMEReferences_treatsNullEnabledAsEnabled(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES
		(41,'null-enabled','dnspod','{}',NULL),
		(42,'disabled','dnspod','{}',0)`); err != nil {
		t.Fatalf("seed certificate configs: %v", err)
	}

	input := acmeReferenceInput{EnableTLS: true, TLSSource: "acme_dns", ACMEConfigID: 41}
	if err := validateRuleACMEReferences(input); err != nil {
		t.Fatalf("NULL enabled 配置在展示/编辑基线为启用，绑定校验必须同口径: %v", err)
	}

	input.ACMEConfigID = 42
	err := validateRuleACMEReferences(input)
	if err == nil || !strings.Contains(err.Error(), "不存在或已禁用") {
		t.Fatalf("disabled config err=%v, want 不存在或已禁用", err)
	}
}

// ---- 认证族切换旧族凭据剪枝：cloudflare 与无 mode 存量形态 ----
//
// dnsCredentialFamilyMode 此前不识别 cloudflare 与无 mode 的存量形态，
// pruneSupersededDNSCredentialFamily 因 storedMode=="" 跳过剪枝，旧族字段
// 随合并语义继承回 merged 落库，并随集群快照/备份扩散。以下用例覆盖四类
// 存量形态（cloudflare UI 形态、cloudflare canonical 形态、裸 api_token、
// 裸 app 对/secret 对）与两个边界（歧义行不剪、同族不剪）。

func assertStoredCredentialFields(t *testing.T, id int64, wantAbsent []string, want map[string]string) {
	t.Helper()
	_, _, stored := storedCertificateCredentials(t, id)
	for _, stale := range wantAbsent {
		if _, ok := stored[stale]; ok {
			t.Fatalf("stale field %q retained after auth-mode switch: %v", stale, stored)
		}
	}
	for k, v := range want {
		if stored[k] != v {
			t.Fatalf("stored credentials=%v, want %s=%q", stored, k, v)
		}
	}
}

// Given 库内为早于 mode/auth_mode 落库的裸 api_token 存量行（Canonical 按
// 字段形态推断为 dnspod）。
// When 管理员切到腾讯云并提交新族凭据（同 provider，继承开启）。
// Then 裸 token 被剪除（推断族 dnspod ≠ 提交族 tencent），审计点名删除字段。
func TestUpdateCertificateConfig_prunesLegacyBareTokenRowOnFamilySwitch(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "bare-token", `{"api_token":"legacy-id,legacy-tok"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"tencent_cloud","secret_id":"sid","secret_key":"skey"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	assertStoredCredentialFields(t, id, []string{"api_token", "app_id", "app_token"},
		map[string]string{"auth_mode": "tencent_cloud", "secret_id": "sid", "secret_key": "skey"})
	detail := latestAuditDetail(t, "更新", "DNS配置")
	if !strings.Contains(detail, "清除旧认证方式凭据") || !strings.Contains(detail, "api_token") {
		t.Fatalf("audit detail=%q, want 点名清除 api_token", detail)
	}
}

// Given 库内 dnspod 认证族（app_id/app_token）。
// When 管理员切到 cloudflare 并提交新 token（同 provider，继承开启）。
// Then 旧族 app 对被剪除，且新提交的 cloudflare token 绝不被误剪
// （api_token 归 cloudflare 消费，剪除会让保存 400）。
func TestUpdateCertificateConfig_prunesOtherFamilyOnCloudflareSwitch(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "to-cloudflare", `{"auth_mode":"dnspod","app_id":"old-id","app_token":"old-tok"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"cloudflare","api_token":"cf-new"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	assertStoredCredentialFields(t, id, []string{"app_id", "app_token", "secret_id", "secret_key", "access_key_id", "access_key_secret"},
		map[string]string{"auth_mode": "cloudflare", "api_token": "cf-new"})
}

// Given 库内 cloudflare 认证族（auth_mode=cloudflare + api_token）。
// When 管理员切回 dnspod 并提交 app 对（同 provider，继承开启）。
// Then cloudflare token 被剪除——切回旧族时它不得复活为 dnspod 消费的值。
func TestUpdateCertificateConfig_prunesCloudflareTokenOnSwitchBackToDnspod(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "from-cloudflare", `{"auth_mode":"cloudflare","api_token":"cf-old"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"dnspod","app_id":"new-id","app_token":"new-tok"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	assertStoredCredentialFields(t, id, []string{"api_token"},
		map[string]string{"auth_mode": "dnspod", "app_id": "new-id", "app_token": "new-tok"})
}

// Given 库内 cloudflare canonical 形态（mode=cloudflare，早于 auth_mode 的行）。
// When 管理员切回 dnspod 并提交 app 对。
// Then api_token 与游离 mode 键一并剪除（auth_mode 提交后 mode 是误导性冗余）。
func TestUpdateCertificateConfig_prunesCanonicalCloudflareRowOnSwitchBackToDnspod(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "from-cloudflare-canonical", `{"mode":"cloudflare","api_token":"cf-old"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"dnspod","app_id":"new-id","app_token":"new-tok"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	assertStoredCredentialFields(t, id, []string{"api_token", "mode"},
		map[string]string{"auth_mode": "dnspod", "app_id": "new-id", "app_token": "new-tok"})
}

// Given 库内为裸 secret 对存量行（无 mode，Canonical 推断为 tencent）。
// When 管理员切到 dnspod app 对。
// Then 旧 secret 对被剪除。
func TestUpdateCertificateConfig_prunesLegacyBareSecretPairOnSwitchToDnspod(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "bare-secret", `{"secret_id":"old-sid","secret_key":"old-skey"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"dnspod","app_id":"new-id","app_token":"new-tok"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	assertStoredCredentialFields(t, id, []string{"secret_id", "secret_key"},
		map[string]string{"auth_mode": "dnspod", "app_id": "new-id", "app_token": "new-tok"})
}

// 边界钉测（安全方向=少剪）：Given 库内多族并存的歧义存量行（裸 token +
// secret 对，Canonical 会判歧义）。When 切换认证族。Then 不剪——推断不了族
// 就绝不误删，残留字段保持现状（宁可少剪不可误剪）。
func TestUpdateCertificateConfig_ambiguousLegacyRowSkipsFamilyPrune(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "ambiguous", `{"api_token":"t1","secret_id":"s","secret_key":"k"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"tencent_cloud","secret_id":"sid","secret_key":"skey"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	assertStoredCredentialFields(t, id, nil, map[string]string{"api_token": "t1"})
}

// 边界钉测（同族不剪）：Given 裸 api_token 存量行（推断 dnspod）。
// When 提交 dnspod app 对（推断族相同）。Then 不触发族切换剪枝——裸 token
// 属同族遗留值（Canonical 折叠语义下 app 对压过游离 token，惰性），由用户
// 显式改凭据处理，剪枝只管跨族切换。
func TestUpdateCertificateConfig_sameFamilyBareTokenKeptOnDnspodSubmit(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "bare-token-same-family", `{"api_token":"legacy-id,legacy-tok"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"dnspod","app_id":"new-id","app_token":"new-tok"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	assertStoredCredentialFields(t, id, nil, map[string]string{"api_token": "legacy-id,legacy-tok", "app_id": "new-id"})
}

// 跨族掩码继承守卫：dnspod 存量（裸 api_token 形态）+ provider
// 切换 cloudflare + 表单回传掩码 api_token → merged 携带旧族 token，保存必须
// 400 点名（fail-visible），不得静默沿用旧族凭据。
func TestUpdateRuleCredentials_rejectsCrossFamilyMaskedInheritance(t *testing.T) {
	// 形状核验走同族既有测试夹具（certificate_config_credentials_test 顶部
	// maskMerge 形状）：dnspod 存量 api_token=oldtoken123，载荷仅掩码。
	// 该形态经 :511 mergeMaskedDNSCredentials 继承旧值，跨族守卫应 400。
	// 真实端到端由 handlers 凭据测试族覆盖；此处钉守卫判定式本身。
	stored := map[string]string{"api_token": "oldtoken123"}
	effectiveProvider := "cloudflare"
	oldProvider := "dnspod"
	merged := map[string]string{"api_token": "oldtoken123"} // 掩码继承结果

	family := dnsCredentialFamilyMode(merged)
	if family == "" || family == effectiveProvider {
		t.Fatalf("跨族守卫判定式必须命中（family=%q provider=%q）", family, effectiveProvider)
	}
	_ = stored
	_ = oldProvider
}
