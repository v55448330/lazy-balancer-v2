package handlers

// 渲染期名单投影（tp.txt / u-* / p*）在**事务提交之前**落盘——渲染是投影的
// 唯一写入口，而渲染发生在 apply 之前、Commit 之前。因此每个写路径收尾分支
// 都必须把磁盘投影收敛回「部署的已提交视图」，否则稳定命名 + 文件热感知会让
// 运行中的 Caddy 在 ≤1s 内按未提交内容判定（控制面与库分叉）。
//
// 收尾分支表（不变量：磁盘投影 = 库的已提交视图）：
//
//	分支                         触发形态                                 收口                                                              投影终态
//	拒绝                         CLI 预检 / Caddy 4xx（ConfigRejected）    RollbackIPListProjectionsToCommittedInLock（已提交库值重渲染）      回退到请求前已提交内容
//	传输失败（已校验）            admin 5xx / 连接失败 ∧ CLI 已通过        退化提交（DB=候选）+ 横幅                                          提交后视图（=候选内容）
//	传输失败（未校验）            CLI 不可用 ∧ 传输失败（ErrUnvalidated）   回滚 + RollbackIPListProjections + RestoreRuntimeToCommittedInLock   回退到请求前已提交内容
//	提交失败                     Commit 返回错误（结果不可判定）           recoverCommittedViewAfterCommitFailure（重渲染 + /load + LKG 钉回）  回退到请求前已提交内容
//
// 分支收口的实际覆盖关系（机械核实过：临时停用相应收敛函数后逐条观察红/绿）：
//   - 拒绝（CLI 预检拒绝）由两路覆盖——ValidateTxRenderViaCLI 的投影快照
//     自回滚 + 收尾的已提交库值重渲染；既有钉测见
//     securityiplists_rollback_test.go，单停重渲染仍是绿（快照先回滚了）。
//   - 拒绝（预检通过、仅 admin 4xx）：唯一收敛点是收尾重渲染——本文件的
//     adminRejection 用例（停用重渲染即红）。
//   - 传输失败（未校验）/ 提交失败：由收尾重渲染与
//     RestoreRuntimeToCommittedInLock（同一条已提交库值重渲染链）承担，本文件
//     两个用例在停用两条收敛路径时均红。
//   - 传输失败（已校验）：退化提交，投影终态=提交后的新视图——本文件
//     transportFailure 用例（以同一库值独立重渲染对齐字节）。

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given：已提交 inline ACL 投影在役。When：CLI 校验通过但 admin 返回 500
// （系统/传输失败）→ 退化提交。Then：200 带告警、DB 已提交、投影内容与
// 「以新库值独立渲染」逐字节一致（退化提交不得留下未提交内容）。
func TestSecurityPolicySave_transportFailureCommitsCommittedViewProjection(t *testing.T) {
	f := newHotPathIPListFixture(t)
	f.router.PUT("/security/policies/:id", f.h.UpdateSecurityPolicy)
	policyID := seedInlineACLPolicy(t, `["203.0.113.5"]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}

	f.h.caddyService.SetCLIValidatorForTest(func([]byte) error { return nil })
	loadsBefore := f.loadCount()
	f.failNextLoadsStatus(http.StatusInternalServerError, 1)
	// 候选视图必须与运行配置字节不同（否则同字节短路、/load 不发生）：模式
	// deny→allow 翻转否定算子（ACL 名单内容变化本身不改变配置字节——热路径
	// 设计使然），条目同时变化以让投影内容与已提交视图可分。
	rec := f.putJSON(fmt.Sprintf("/security/policies/%d", policyID),
		map[string]any{"ip_acl_list": `["203.0.113.5","198.51.100.7"]`, "ip_acl_mode": "allow"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（传输失败=退化提交）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "但 Caddy 配置应用失败") {
		t.Fatalf("退化提交响应未点名应用失败: %s", rec.Body.String())
	}
	if got := f.loadCount(); got != loadsBefore+1 {
		t.Fatalf("/load 尝试=%d, want %d（候选视图必须真实下发过）", got, loadsBefore+1)
	}
	var acl string
	if err := db.DB.QueryRow(`SELECT ip_acl_list FROM security_policies WHERE id=?`, policyID).Scan(&acl); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if acl != `["203.0.113.5","198.51.100.7"]` {
		t.Fatalf("退化提交后 ip_acl_list=%q, want 已提交的新值", acl)
	}
	degraded := f.projectionContent(policyID)
	if !strings.Contains(degraded, "203.0.113.5/32") || !strings.Contains(degraded, "198.51.100.7/32") {
		t.Fatalf("退化提交后投影=%q, want 含新已提交条目", degraded)
	}
	// 投影终态 = 已提交视图渲染结果：以同一库值独立重渲染，字节不得变化
	// （若投影残留未提交内容，此处会写出不同字节）。
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("已提交视图重渲染: %v", err)
	}
	if got := f.projectionContent(policyID); got != degraded {
		t.Fatalf("投影≠已提交视图渲染结果: after=%q want=%q", got, degraded)
	}
}

// Given：CLI 校验器未装配（生产=二进制缺失/未启用）且 admin 返回 500。
// When：策略更新——ErrUnvalidatedApply（未受任何 Caddy 级校验）。
// Then：500、事务回滚、DB 与投影双双回退到请求前已提交内容。
func TestSecurityPolicySave_unvalidatedTransportFailureRestoresCommittedProjection(t *testing.T) {
	f := newHotPathIPListFixture(t)
	f.router.PUT("/security/policies/:id", f.h.UpdateSecurityPolicy)
	policyID := seedInlineACLPolicy(t, `["203.0.113.5"]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	committed := f.projectionContent(policyID)

	loadsBefore := f.loadCount()
	f.failNextLoadsStatus(http.StatusInternalServerError, 1)
	rec := f.putJSON(fmt.Sprintf("/security/policies/%d", policyID),
		map[string]any{"ip_acl_list": `["203.0.113.5","198.51.100.7"]`, "ip_acl_mode": "allow"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（未校验应用失败=回滚）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "CLI 校验不可用") {
		t.Fatalf("未校验分支响应未点名校验缺失: %s", rec.Body.String())
	}
	// 非恒真前置：事务内 apply 确实发起过 /load（500 只证明尝试存在，但
	// 渲染已在其前完成——投影按候选内容落盘）。
	if got := f.loadCount(); got != loadsBefore+1 {
		t.Fatalf("/load 尝试=%d, want %d（候选视图必须真实下发过，否则回退断言恒真）", got, loadsBefore+1)
	}
	if got := f.projectionContent(policyID); got != committed {
		t.Fatalf("未校验回滚后投影=%q, want 已提交内容 %q", got, committed)
	}
	var acl string
	if err := db.DB.QueryRow(`SELECT ip_acl_list FROM security_policies WHERE id=?`, policyID).Scan(&acl); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if acl != `["203.0.113.5"]` {
		t.Fatalf("回滚后 ip_acl_list=%q, want 已提交值", acl)
	}
}

// Given：已提交 inline ACL 投影在役、CLI 预检通过（快照自回滚不触发——预检
// 成功后不恢复快照）。When：事务内 apply 被 Caddy 以 4xx 拒绝（ConfigRejected）。
// Then：400、DB 未落库、投影回退到请求前已提交内容——该分支唯一收敛点就是
// 拒绝收尾的已提交库值重渲染（RollbackIPListProjectionsToCommittedInLock）。
//
// 说明：CLI 校验拒绝形态（securityiplists_rollback_test.go）由
// ValidateTxRenderViaCLI 的投影快照自回滚与收尾重渲染双路径覆盖，因此不能
// 用来证明收尾重渲染在位；本用例把「预检已通过、仅 admin 拒绝」这一形态单独
// 钉住。
func TestSecurityPolicySave_adminRejectionRestoresCommittedProjection(t *testing.T) {
	f := newHotPathIPListFixture(t)
	f.router.PUT("/security/policies/:id", f.h.UpdateSecurityPolicy)
	policyID := seedInlineACLPolicy(t, `["203.0.113.5"]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	committed := f.projectionContent(policyID)

	f.h.caddyService.SetCLIValidatorForTest(func([]byte) error { return nil })
	f.rejectLoads(1)
	rec := f.putJSON(fmt.Sprintf("/security/policies/%d", policyID),
		map[string]any{"ip_acl_list": `["203.0.113.5","198.51.100.7"]`, "ip_acl_mode": "allow"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（admin 4xx=拒绝）", rec.Code, rec.Body.String())
	}
	if got := f.projectionContent(policyID); got != committed {
		t.Fatalf("admin 拒绝后投影=%q, want 已提交内容 %q", got, committed)
	}
	var acl string
	if err := db.DB.QueryRow(`SELECT ip_acl_list FROM security_policies WHERE id=?`, policyID).Scan(&acl); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if acl != `["203.0.113.5"]` {
		t.Fatalf("拒绝后 ip_acl_list=%q, want 已提交值", acl)
	}
}

// installDeferredCommitFailureOnPolicyUpdate 让下一次 security_policies UPDATE
// 在 COMMIT 阶段失败（延迟外键约束）：事务内 apply 已按候选视图 /load 成功，
// 只有提交失败——正是「投影已写、事务未提交」的最坏收尾形态。
//
// PRAGMA foreign_keys 是**连接级**设置，主库池有 maxOpen 条连接、事务可能派发
// 到任一连接：只 Exec 一次 PRAGMA 不保证事务连接已启用延迟约束（响应会是 200
// 而非 500）。修法有两面：
//   - 不能把池钳到单连接（SetMaxOpenConns(1)）——handler 事务内会经 db.DB 再取
//     连接（GenerateAndApplyConfig 等），单连接池自锁死（实测 1m40s 超时）；
//   - 改为先**占满全部 maxOpen 条连接**并逐条设置 PRAGMA foreign_keys=ON，再
//     放回池中：池里每条连接（含既有连接）都已启用 FK，事务连接必然合规，
//     判据不再依赖池复用顺序（-shuffle/并发下不漂移）。
func installDeferredCommitFailureOnPolicyUpdate(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	maxOpen := db.DB.Stats().MaxOpenConnections
	if maxOpen <= 0 {
		t.Fatalf("主库池 maxOpen=%d, 无法预置 FK 连接", maxOpen)
	}
	primed := make([]*sql.Conn, 0, maxOpen)
	for range maxOpen {
		conn, cerr := db.DB.Conn(ctx)
		if cerr != nil {
			t.Fatalf("acquire connection for FK prime: %v", cerr)
		}
		if _, perr := conn.ExecContext(ctx, "PRAGMA foreign_keys=ON"); perr != nil {
			_ = conn.Close()
			t.Fatalf("prime foreign_keys: %v", perr)
		}
		primed = append(primed, conn)
	}
	for _, conn := range primed {
		if cerr := conn.Close(); cerr != nil {
			t.Fatalf("release primed connection: %v", cerr)
		}
	}
	if _, err := db.DB.Exec(`CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);
		CREATE TABLE commit_guard(parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER fail_policy_commit AFTER UPDATE ON security_policies BEGIN INSERT INTO commit_guard(parent_id) VALUES (999); END`); err != nil {
		t.Fatalf("install deferred commit failure: %v", err)
	}
}

// Given：已提交 inline ACL 投影在役。When：事务内渲染+/load 成功、Commit 失败
// （结果不可判定）。Then：500 表述「提交结果不确定」、DB 未落库、投影回退到
// 请求前已提交内容（恢复链以已提交库值重渲染的副作用）。
func TestSecurityPolicySave_commitFailureRestoresCommittedProjection(t *testing.T) {
	f := newHotPathIPListFixture(t)
	f.router.PUT("/security/policies/:id", f.h.UpdateSecurityPolicy)
	policyID := seedInlineACLPolicy(t, `["203.0.113.5"]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	committed := f.projectionContent(policyID)
	installDeferredCommitFailureOnPolicyUpdate(t)

	rec := f.putJSON(fmt.Sprintf("/security/policies/%d", policyID),
		map[string]any{"ip_acl_list": `["203.0.113.5","198.51.100.7"]`, "ip_acl_mode": "allow"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（提交失败）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "提交结果不确定") {
		t.Fatalf("提交失败响应未表述结果不确定: %s", rec.Body.String())
	}
	// 非恒真前置：事务内 apply 已按候选视图成功下发（提交是唯一的失败点），
	// 否则「投影=已提交内容」无法区分「回退了」与「从未写」。
	if !f.anyLoadBodyContains("!@ipListFast") {
		t.Fatal("候选视图未真实下发：提交失败用例失去保护力（失败发生在 Commit 之前）")
	}
	if got := f.projectionContent(policyID); got != committed {
		t.Fatalf("提交失败后投影=%q, want 已提交内容 %q", got, committed)
	}
	var acl string
	if err := db.DB.QueryRow(`SELECT ip_acl_list FROM security_policies WHERE id=?`, policyID).Scan(&acl); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if acl != `["203.0.113.5"]` {
		t.Fatalf("提交失败后 ip_acl_list=%q, want 已提交值", acl)
	}
}
