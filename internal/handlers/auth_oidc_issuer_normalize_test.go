package handlers

// issuer 读侧归一钉测：库值可由配置导入/自动备份还原/集群快照/带外改库带入
// 未归一形态（写侧 normalizeOIDCIssuer 只覆盖面板保存路径）。归一若只在写/测试
// 路径生效，就会出现「管理员点测试通过、真实登录必然失败」——discovery 用未
// 归一值恒 404，错误文案还被归一成「服务不可达」误导排障。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 库中 issuer 带尾斜杠（带外写入形态）。
// When 读取配置。
// Then 归一值生效（尾斜杠剥离），原值保留供历史身份行兼容查询。
func TestLoadOIDCConfig_normalizesIssuerOnRead(t *testing.T) {
	setupOIDCTest(t, newMockIdP(t))
	raw := `{"enabled":true,"issuer":"https://login.microsoftonline.com/tenant/","client_id":"c","client_secret":"s"}`
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`, raw); err != nil {
		t.Fatalf("raw write oidc config: %v", err)
	}
	cfg, err := loadOIDCConfig()
	if err != nil {
		t.Fatalf("load oidc config: %v", err)
	}
	if cfg.Issuer != "https://login.microsoftonline.com/tenant/v2.0" {
		t.Fatalf("issuer=%q, want 归一值（去尾斜杠 + Entra 补 /v2.0）", cfg.Issuer)
	}
	if cfg.rawIssuer != "https://login.microsoftonline.com/tenant/" {
		t.Fatalf("rawIssuer=%q, want 库中原值", cfg.rawIssuer)
	}
}

// Given 库中 issuer 带尾斜杠（旧登录/探测路径会拼出 //.well-known 而失败）。
// When 走完 login→callback 全链。
// Then 登录成功——消费路径必须使用读侧归一值。
func TestOIDCLoginFlow_worksWithUnnormalizedStoredIssuer(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	raw := `{"enabled":true,"issuer":"` + idp.issuer + `/","client_id":"test-client","client_secret":"super-secret-123"}`
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`, raw); err != nil {
		t.Fatalf("raw write oidc config: %v", err)
	}

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("带尾斜杠的库内 issuer 必须能登录（读侧归一），got redirect: %s", front)
	}
}

// 归一值同时作为 discovery 缓存键：保存归一后的配置后，探测与真实登录共用
// 同一缓存条目（不会一边命中、一边回源）。此用例守住「缓存键=归一值」的口径。
func TestOIDCSettingsTest_usesNormalizedIssuerCacheKey(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"super-secret-123","enabled":true}`)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/test", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("test endpoint=%d body=%s, want ok", rec.Code, rec.Body.String())
	}

	// 缓存键必须是归一值（去尾斜杠）：未归一键会留下陈旧条目，保存侧失效时
	// 打不中同一键。
	oidcProvMu.Lock()
	_, normalizedHit := oidcProvCach[normalizeOIDCIssuer(idp.issuer)]
	_, rawHit := oidcProvCach[idp.issuer+"/"]
	oidcProvMu.Unlock()
	if !normalizedHit {
		t.Fatal("discovery 缓存键必须是归一后的 issuer")
	}
	if rawHit {
		t.Fatal("缓存中不得存在未归一 issuer 的条目")
	}

	// 登录链同样使用归一键（配置中带尾斜杠时仍然命中缓存，不回源到 //.well-known）
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`,
		`{"enabled":true,"issuer":"`+idp.issuer+`/","client_id":"test-client","client_secret":"super-secret-123"}`); err != nil {
		t.Fatalf("raw write oidc config: %v", err)
	}
	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("登录链未使用归一 issuer（缓存未命中/发现失败），got: %s", front)
	}
}

// Entra 补 /v2.0 特例的命中面：浏览器地址栏/IdP 门户复制来的 issuer 常带
// :443，且主权云主机与全球主机并列——按主机名（去端口）判定，否则 v1 端点
// 无发现文档 → 恒登录失败且被归一为「服务不可达」。主机形态同时归一到小写 +
// 去协议默认端口：go-oidc 要求与发现文档 issuer 逐字节相等，IdP 宣告值恒为
// 小写无默认端口，只查表不归一会出现「保存能过、登录恒 mismatch」。
func TestNormalizeOIDCIssuer_matchesHostByHostname(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://login.microsoftonline.com/tenant", "https://login.microsoftonline.com/tenant/v2.0"},
		{"https://login.microsoftonline.com:443/tenant", "https://login.microsoftonline.com/tenant/v2.0"},
		{"https://Login.MicrosoftOnline.US/tenant/", "https://login.microsoftonline.us/tenant/v2.0"},
		{"https://LOGIN.MICROSOFTONLINE.COM:443/tenant/v2.0", "https://login.microsoftonline.com/tenant/v2.0"},
		{"https://login.partner.microsoftonline.cn/tenant", "https://login.partner.microsoftonline.cn/tenant/v2.0"},
		{"https://login.chinacloudapi.cn/tenant", "https://login.chinacloudapi.cn/tenant/v2.0"},
		{"https://login.microsoftonline.com/tenant/v2.0", "https://login.microsoftonline.com/tenant/v2.0"},
		// 非默认端口保留（只有协议默认端口可省略）。
		{"https://login.microsoftonline.com:8443/tenant", "https://login.microsoftonline.com:8443/tenant/v2.0"},
		// 非 Entra 主机逐字保留路径（只归一小写/默认端口，不猜路径）。
		{"https://idp.example.com/tenant/", "https://idp.example.com/tenant"},
		{"https://IDP.Example.COM:443/tenant/", "https://idp.example.com/tenant"},
		{"https://idp.example.com:8443/tenant/", "https://idp.example.com:8443/tenant"},
		{"https://idp.example.com/v2.0", "https://idp.example.com/v2.0"},
		// 子域名不命中（避免把任意外观相似的域当 Entra）。
		{"https://evil.login.microsoftonline.com/tenant", "https://evil.login.microsoftonline.com/tenant"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := normalizeOIDCIssuer(tc.raw); got != tc.want {
				t.Fatalf("normalizeOIDCIssuer(%q)=%q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// Given 库中 issuer 是未归一形态、users 表有按该原值建键的历史 OIDC 身份行
// （v2.3.8 之前的旧库/带外改库形态）。
// When 管理员保存任意 OIDC 设置（issuer 未随载荷，展示名变更）。
// Then 保存把归一值写回库的同时迁移身份行——该 subject 再次登录命中同一行
// （角色/禁用状态不被旁路），审计含「服务地址归一」delta。
func TestOIDCSettingsUpdate_migratesLegacyIdentityRowsOnIssuerNormalization(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	legacyIssuer := idp.issuer + "/"
	normalized := strings.TrimSuffix(legacyIssuer, "/")
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`,
		`{"enabled":true,"issuer":"`+legacyIssuer+`","client_id":"test-client","client_secret":"s"}`); err != nil {
		t.Fatalf("raw write oidc config: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (username, password_hash, role, is_enabled, auth_provider, oidc_subject, oidc_issuer)
		VALUES ('legacy-admin', '', 'admin', 0, 'oidc', 'user-sub-1', ?)`, legacyIssuer); err != nil {
		t.Fatalf("seed legacy identity row: %v", err)
	}

	putOIDCConfig(t, router, `{"display_name":"新展示名"}`)

	var issuer, role string
	var enabled int
	if err := db.DB.QueryRow(`SELECT oidc_issuer, role, COALESCE(is_enabled,1) FROM users WHERE auth_provider='oidc' AND oidc_subject='user-sub-1'`).
		Scan(&issuer, &role, &enabled); err != nil {
		t.Fatalf("read identity row: %v", err)
	}
	if issuer != normalized {
		t.Fatalf("oidc_issuer=%q, want 归一值 %q（保存写回库后原值兼容通道失效，必须同批迁移）", issuer, normalized)
	}
	if role != "admin" || enabled != 0 {
		t.Fatalf("迁移后身份行 role=%q enabled=%d, want admin/0（不得新建一行旁路禁用状态）", role, enabled)
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read stored oidc config: %v", err)
	}
	if strings.Contains(stored, legacyIssuer) {
		t.Fatalf("库中仍保存未归一 issuer：%s", stored)
	}

	// 再登录命中同一行（已禁用 → 拒登，不得新建启用账号）。
	front := runOIDCLoginFlow(t, router)
	if strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("已禁用的历史身份行必须继续生效（命中同一行），got redirect: %s", front)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE auth_provider='oidc'`).Scan(&rows); err != nil {
		t.Fatalf("count oidc users: %v", err)
	}
	if rows != 1 {
		t.Fatalf("OIDC 身份行数=%d, want 1（重复开户=封禁/角色旁路）", rows)
	}

	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='OIDC 配置' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	if !strings.Contains(detail, "服务地址归一") || !strings.Contains(detail, "迁移历史身份行 1 条") {
		t.Fatalf("审计未留痕身份键归一：%q", detail)
	}
}

// Given 同一 subject 同时存在原值与归一值两行身份（旧版本遗留+重建）。
// When 管理员保存 OIDC 设置。
// Then 409 拒绝且不落任何改写（配置与身份行都保持原样）——同一自然人两行
// 身份（角色/禁用分叉）必须人工合并，系统不得静默二选一。
func TestOIDCSettingsUpdate_rejectsIdentityIssuerMigrationConflict(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	legacyIssuer := idp.issuer + "/"
	normalized := strings.TrimSuffix(legacyIssuer, "/")
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`,
		`{"enabled":true,"issuer":"`+legacyIssuer+`","client_id":"test-client","client_secret":"s"}`); err != nil {
		t.Fatalf("raw write oidc config: %v", err)
	}
	for _, row := range []struct {
		username string
		role     string
		enabled  int
		issuer   string
	}{
		{"legacy-admin", "admin", 0, legacyIssuer},
		{"dup-user", "user", 1, normalized},
	} {
		if _, err := db.DB.Exec(`INSERT INTO users (username, password_hash, role, is_enabled, auth_provider, oidc_subject, oidc_issuer)
			VALUES (?, '', ?, ?, 'oidc', 'user-sub-1', ?)`, row.username, row.role, row.enabled, row.issuer); err != nil {
			t.Fatalf("seed identity row %s: %v", row.username, err)
		}
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(`{"display_name":"新展示名"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（身份键迁移冲突必须 fail-visible）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "user-sub-1") {
		t.Fatalf("冲突响应缺少 subject 清单：%s", rec.Body.String())
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE auth_provider='oidc' AND oidc_issuer IN (?, ?)`, legacyIssuer, normalized).Scan(&rows); err != nil {
		t.Fatalf("count identity rows: %v", err)
	}
	if rows != 2 {
		t.Fatalf("冲突后身份行数=%d, want 2（不得部分改写）", rows)
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read stored oidc config: %v", err)
	}
	if !strings.Contains(stored, legacyIssuer) {
		t.Fatalf("冲突拒绝时不得写回配置（仍应保留原值）：%s", stored)
	}
	var auditDetail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新失败' AND resource='OIDC 配置' ORDER BY id DESC LIMIT 1`).Scan(&auditDetail); err != nil {
		t.Fatalf("issuer conflict must write failure audit: %v", err)
	}
	if !strings.Contains(auditDetail, "user-sub-1") || !strings.Contains(auditDetail, "失败") {
		t.Fatalf("issuer conflict audit detail=%q, want subject and failure", auditDetail)
	}
}

// Given 旧 issuer 下已有一行被禁用的 OIDC 身份。
// When 管理员把 issuer 改为另一个值（不是归一化写回）。
// Then 响应与审计都明示旧身份行不再可达；新 issuer 首登仍按既有 JIT 契约建行。
func TestOIDCSettingsUpdate_reportsStaleIdentitiesOnIssuerChange(t *testing.T) {
	oldIDP := newMockIdP(t)
	newIDP := newMockIdP(t)
	router, _ := setupOIDCTest(t, oldIDP)
	putOIDCConfig(t, router, `{"issuer":"`+oldIDP.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	if _, err := db.DB.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer)
		VALUES ('old-oidc-admin','','admin',0,'oidc','user-sub-1',?)`, oldIDP.issuer); err != nil {
		t.Fatalf("seed old issuer identity: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(`{"issuer":"`+newIDP.issuer+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var response struct {
		Data struct {
			StaleIdentityRows int `json:"stale_identity_rows"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if response.Data.StaleIdentityRows != 1 {
		t.Fatalf("stale_identity_rows=%d body=%s, want 1", response.Data.StaleIdentityRows, rec.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='OIDC 配置' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	if !strings.Contains(detail, "存量身份行 1 条不再可达") {
		t.Fatalf("审计未提示换 issuer 的身份行后果：%q", detail)
	}

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("新 issuer 首登应沿用 JIT 契约，got redirect: %s", front)
	}
	var role string
	var enabled int
	if err := db.DB.QueryRow(`SELECT role,is_enabled FROM users WHERE auth_provider='oidc' AND oidc_issuer=?`, newIDP.issuer).Scan(&role, &enabled); err != nil {
		t.Fatalf("read new issuer JIT row: %v", err)
	}
	if role != "user" || enabled != 1 {
		t.Fatalf("new JIT row role=%q enabled=%d, want user/1", role, enabled)
	}
}

// 库内 issuer 带尾斜杠时，历史身份行按 rawIssuer 建键；切换到不同 issuer
// 的存量统计必须同时覆盖原值与归一值，不能漏报 raw-only 行。
func TestOIDCSettingsUpdate_countsRawIssuerStaleIdentitiesOnIssuerChange(t *testing.T) {
	oldIDP := newMockIdP(t)
	newIDP := newMockIdP(t)
	router, _ := setupOIDCTest(t, oldIDP)
	rawIssuer := oldIDP.issuer + "/"
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`,
		`{"enabled":true,"issuer":"`+rawIssuer+`","client_id":"test-client","client_secret":"s"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer)
		VALUES ('raw-only-oidc','','user',1,'oidc','raw-subject',?)`, rawIssuer); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(`{"issuer":"`+newIDP.issuer+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var response struct {
		Data struct {
			StaleIdentityRows int `json:"stale_identity_rows"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.StaleIdentityRows != 1 {
		t.Fatalf("stale_identity_rows=%d body=%s, want raw-only row counted as 1", response.Data.StaleIdentityRows, rec.Body.String())
	}
}

func TestOIDCSettingsDelete_reportsResidualIdentitiesAndRecovery(t *testing.T) {
	router, _ := setupOIDCTest(t, newMockIdP(t))
	for _, subject := range []string{"sub-1", "sub-2"} {
		if _, err := db.DB.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer)
			VALUES (?, '', 'user', 1, 'oidc', ?, 'https://idp.example.com')`, "sso-"+subject, subject); err != nil {
			t.Fatal(err)
		}
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/settings/oidc", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Message string `json:"message"`
		Data    struct {
			OIDCIdentityRows int `json:"oidc_identity_rows"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.OIDCIdentityRows != 2 {
		t.Fatalf("oidc_identity_rows=%d body=%s, want 2", response.Data.OIDCIdentityRows, recorder.Body.String())
	}
	for _, want := range []string{"无法登录", "同一 issuer", "重新开户"} {
		if !strings.Contains(response.Message, want) {
			t.Fatalf("delete message=%q, want recovery/rebind hint containing %q", response.Message, want)
		}
	}
}
