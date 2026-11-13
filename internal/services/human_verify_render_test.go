package services

// 人机验证渲染确定性钉：
//   - exempt_paths 渲染序必须确定（同配置多次渲染字节一致）——渲染产物字节
//     漂移会让 errSameConfig 同字节短路失效，autoban 投影热路径回退全量重载；
//   - 挑战页选取与 humanPolicyMerged 的 force>auto 优先序同源——绑定序在前的
//     auto 策略不得遮蔽 force 策略的页（merged mode=force 配 auto 页即分叉）。

import (
	"encoding/json"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 豁免路径并集渲染序确定：多路径输入重复渲染必须逐字节一致，且与输入顺序
// 无关（集合语义）。单路径行为不变（回归形状）。
func TestHumanPolicyMerged_exemptPathsDeterministic(t *testing.T) {
	paths := []string{"/zeta/", "/alpha/", "/mid/", "/beta/", "/omega/", "/kappa/"}
	variants := [][]string{
		paths,
		{"/omega/", "/kappa/", "/zeta/", "/beta/", "/alpha/", "/mid/"},
		{"/mid/", "/alpha/", "/omega/", "/zeta/", "/kappa/", "/beta/"},
	}
	render := func(order []string) string {
		raw, err := json.Marshal(order)
		if err != nil {
			t.Fatalf("marshal paths: %v", err)
		}
		p := &models.SecurityPolicy{HumanVerifyMode: "force", HumanExemptPaths: raw}
		_, _, _, got := humanPolicyMerged([]*models.SecurityPolicy{p})
		out, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal merged paths: %v", err)
		}
		return string(out)
	}
	want := render(paths)
	for round := range 32 {
		for i, order := range variants {
			if got := render(order); got != want {
				t.Fatalf("第 %d 轮变体 %d 渲染字节漂移：got=%s want=%s", round, i, got, want)
			}
		}
	}

	// 跨策略并集同样确定（两策略各持乱序子集）。
	pA := &models.SecurityPolicy{HumanVerifyMode: "force", HumanExemptPaths: []byte(`["/zeta/","/alpha/"]`)}
	pB := &models.SecurityPolicy{HumanVerifyMode: "auto", HumanExemptPaths: []byte(`["/omega/","/mid/"]`)}
	_, _, _, first := humanPolicyMerged([]*models.SecurityPolicy{pA, pB})
	for round := range 32 {
		_, _, _, got := humanPolicyMerged([]*models.SecurityPolicy{pA, pB})
		outA, _ := json.Marshal(first)
		outB, _ := json.Marshal(got)
		if string(outA) != string(outB) {
			t.Fatalf("跨策略并集第 %d 轮字节漂移：%s vs %s", round, outA, outB)
		}
	}

	// 单路径回归形状：内容不变。
	single := &models.SecurityPolicy{HumanVerifyMode: "auto", HumanExemptPaths: []byte(`["/health/"]`)}
	_, _, _, got := humanPolicyMerged([]*models.SecurityPolicy{single})
	if len(got) != 1 || got[0] != "/health/" {
		t.Fatalf("单路径行为漂移：%v", got)
	}
}

// 挑战页选取采用 force>auto 优先序（与 humanPolicyMerged 同源）：
// 绑定序 [auto(页A), force(页B)] 必须选页B。
func TestChallengePageSelection_prefersForceOverAuto(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_cc_sel", "ccsel.example.test", 8080)
	seedSecurityBlockPage(t, database, 7101, "<html>page-A-auto</html>")
	seedSecurityBlockPage(t, database, 7102, "<html>page-B-force</html>")

	autoID := mpGenBindPolicy(t, database, "lb_cc_sel", "cc-auto", mpGenPolicySpec{mode: "off", enabled: true, blockPageID: 7101})
	forceID := mpGenBindPolicy(t, database, "lb_cc_sel", "cc-force", mpGenPolicySpec{mode: "off", enabled: true, blockPageID: 7102})
	if _, err := database.Exec(`UPDATE security_policies SET policy_type='stage2', human_verify_mode='auto', human_verify_type='slider' WHERE id=?`, autoID); err != nil {
		t.Fatalf("mark auto policy: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_policies SET policy_type='stage2', human_verify_mode='force', human_verify_type='js' WHERE id=?`, forceID); err != nil {
		t.Fatalf("mark force policy: %v", err)
	}

	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_cc_sel", "ccsel.example.test"))
	human := findChainHandler(t, mainRoute, "lb_human")
	if human == nil {
		t.Fatalf("chain 必须含 lb_human：%v", handlerNames(t, mainRoute))
	}
	// merged 口径：force 优先 → mode=force、type=force 策略的 js。
	if human["mode"] != "force" || human["type"] != "js" {
		t.Fatalf("merged mode/type=%v/%v，want force/js", human["mode"], human["type"])
	}
	if human["challenge_page_html"] != "<html>page-B-force</html>" {
		t.Fatalf("挑战页必须取 force 策略的页B（与 merged force 同源），实际=%v", human["challenge_page_html"])
	}

	// 回归形状：仅 auto 策略时仍按其页选取（绑定序首条语义不变）。
	if _, err := database.Exec(`UPDATE security_policies SET enabled=0 WHERE id=?`, forceID); err != nil {
		t.Fatalf("disable force policy: %v", err)
	}
	_, mainRoute = mpGenRoutes(t, database, mpGenHTTPRule("lb_cc_sel", "ccsel.example.test"))
	human = findChainHandler(t, mainRoute, "lb_human")
	if human == nil || human["challenge_page_html"] != "<html>page-A-auto</html>" {
		t.Fatalf("仅 auto 策略时挑战页应为页A：%v", human)
	}
}
