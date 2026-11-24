package handlers

// 状态响应 policy_id：ban_missing=binding 时给出「就绪但未关联规则」的那条
// deny 策略 id（黄条「前往绑定规则」入口的深链目标），其余环节与无法定位
// 一律 null。键集恒定——前端类型按 number | null 消费，不得随定位结果漂移
// 整键。

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// seedDenyPolicy 插入一条 deny 模式且 ip_acl_list_refs 引用预置名单的策略并
// 返回 id（enabled=false 时是「引用名单但不就绪」的干扰项）；withRule 时另插
// 一条启用 HTTP 规则（带启用上游）并绑定——与链路生效判据的夹具同形态。
func seedDenyPolicy(t *testing.T, listID int, name string, enabled bool, withRule bool) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,enabled,ip_acl_enabled,ip_acl_mode,ip_acl_list_refs) VALUES (?,?,1,'deny',?)`,
		name, map[bool]int{true: 1, false: 0}[enabled], fmt.Sprintf("[%d]", listID))
	if err != nil {
		t.Fatalf("seed policy %s: %v", name, err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if !withRule {
		return policyID
	}
	ruleID := "lb_" + name
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES (?,?,'http',?,8080,1)`, ruleID, name, name+".test"); err != nil {
		t.Fatalf("seed rule %s: %v", name, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, ruleID); err != nil {
		t.Fatalf("seed upstream %s: %v", name, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, ruleID, policyID); err != nil {
		t.Fatalf("seed binding %s: %v", name, err)
	}
	return policyID
}

// seededEnv：测试库 + 预置名单带一条生效条目，返回路由与预置名单 id。
func seededEnv(t *testing.T) (*gin.Engine, int) {
	t.Helper()
	router := newAutobanTestEnv(t)
	seedAutobanListEntries(t, `[{"value":"198.51.100.8"}]`)
	return router, autobanPresetID(t)
}

func TestAutobanStatus_missingLinkCarriesPolicyID(t *testing.T) {
	type status struct {
		banMissing string
		policyID   *int64
		raw        string
	}
	fetch := func(t *testing.T, router *gin.Engine) status {
		t.Helper()
		rec := getRequest(t, router, "/security/autoban/status")
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var payload struct {
			Data struct {
				BanMissing string `json:"ban_missing"`
				PolicyID   *int64 `json:"policy_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v body=%s", err, rec.Body.String())
		}
		return status{banMissing: payload.Data.BanMissing, policyID: payload.Data.PolicyID, raw: rec.Body.String()}
	}
	// 键集恒定：null 与数值两种取值下键都必须在——缺键与 null 对 *int64 同为
	// nil，只看解码结果分不出来，null 形态另按原文钉。
	assertStatus := func(t *testing.T, got status, wantMissing string, wantID *int64) {
		t.Helper()
		if got.banMissing != wantMissing {
			t.Fatalf("ban_missing=%q want %q body=%s", got.banMissing, wantMissing, got.raw)
		}
		if wantID == nil {
			if got.policyID != nil {
				t.Fatalf("policy_id=%d want null body=%s", *got.policyID, got.raw)
			}
			if !strings.Contains(got.raw, `"policy_id":null`) {
				t.Fatalf("policy_id 键必须以 null 在场 body=%s", got.raw)
			}
			return
		}
		if got.policyID == nil {
			t.Fatalf("policy_id 缺失或为 null want %d body=%s", *wantID, got.raw)
		}
		if *got.policyID != *wantID {
			t.Fatalf("policy_id=%d want %d body=%s", *got.policyID, *wantID, got.raw)
		}
	}

	t.Run("no deny policy references list", func(t *testing.T) {
		router, _ := seededEnv(t)
		assertStatus(t, fetch(t, router), "policy", nil)
	})

	t.Run("ready policy unbound", func(t *testing.T) {
		router, listID := seededEnv(t)
		policyID := seedDenyPolicy(t, listID, "unbound", true, false)
		assertStatus(t, fetch(t, router), "binding", &policyID)
	})

	t.Run("disabled policy referencing the list is not the target", func(t *testing.T) {
		// 干扰项先插入（id 更小）：定位目标必须是「就绪」的那条，而不是
		// 「引用名单的策略里随便一条」。
		router, listID := seededEnv(t)
		seedDenyPolicy(t, listID, "disabled", false, false)
		policyID := seedDenyPolicy(t, listID, "ready", true, false)
		assertStatus(t, fetch(t, router), "binding", &policyID)
	})

	t.Run("target is stable across polls", func(t *testing.T) {
		router, listID := seededEnv(t)
		seedDenyPolicy(t, listID, "ready-b", true, false)
		seedDenyPolicy(t, listID, "ready-a", true, false)
		first := fetch(t, router)
		if first.policyID == nil {
			t.Fatalf("binding 环节必须给出可定位的策略 id, body=%s", first.raw)
		}
		assertStatus(t, fetch(t, router), "binding", first.policyID)
	})

	t.Run("fully wired", func(t *testing.T) {
		router, listID := seededEnv(t)
		seedDenyPolicy(t, listID, "wired", true, true)
		assertStatus(t, fetch(t, router), "", nil)
	})

	// 库缺失是最上游的缺失环节：即便存在就绪未绑定的策略，也不给「前往绑定
	// 规则」的定位目标（修绑定解决不了「安全链根本没渲染」）。
	t.Run("libs missing outranks binding", func(t *testing.T) {
		withIsolatedGlobal(t) // 本用例体直写 autobanSecurityLibsReady 缝
		router, listID := seededEnv(t)
		seedDenyPolicy(t, listID, "unbound-libs", true, false)
		oldProbe := autobanSecurityLibsReady
		autobanSecurityLibsReady = func() (bool, bool) { return true, false }
		t.Cleanup(func() { autobanSecurityLibsReady = oldProbe })
		assertStatus(t, fetch(t, router), "libs", nil)
	})
}

// 文档示例键集与实现双向对账：状态响应新增定位键后示例漏补，按文档取数的
// 调用方会丢掉 binding 环节的策略定位。键集对账拦不住值漂移，另钉示例里
// policy_id 与 ban_missing=binding 同现且为正整数（与实现的取值形态一致）。
func TestAPIDocs_autobanStatusExampleKeysMatchImplementation(t *testing.T) {
	router := newAutobanTestEnv(t)
	rec := getRequest(t, router, "/security/autoban/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	const route = "GET /security/autoban/status"
	example := docResponseExample(t, route)
	assertKeySetsEqual(t, route, mapKeysOf(example), mapKeysOf(impl.Data))
	if example["ban_missing"] != "binding" {
		t.Fatalf("示例 ban_missing=%v want binding（定位键只在 binding 环节出现）", example["ban_missing"])
	}
	policyID, ok := example["policy_id"].(float64)
	if !ok || policyID <= 0 || math.Trunc(policyID) != policyID {
		t.Fatalf("示例 policy_id 必须是正整数, got %#v", example["policy_id"])
	}
}
