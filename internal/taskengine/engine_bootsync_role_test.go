package taskengine

// BootSync 执行面角色契约钉。
//
// ①注册期响亮拒绝 BootSync∧RunsOn≠RoleAny（与 Daemon∧EnabledFn 同风格）——
//   BootSync 是引擎装配尾部的同步启动触发，非角色调度面；声明主/从限定会在
//   对应侧启动期静默跳过成「永不执行的启动任务」。
// ②RunBootSyncTasks 补 roleAllows 门（与 Trigger/RunSync/tick 同款，纵深防御
//   ——Register 之外的直注形态如本测试 ② 仍被该门拦截）。

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func bootsyncDesc(runsOn Role) Descriptor {
	return Descriptor{
		ID: "t-bs-role", Family: "t", Name: "BootSync 角色", Category: "测试",
		Kind: KindOneshot, BootSync: true, RunsOn: runsOn,
		Run: func(rc RunContext) error { return nil },
	}
}

// ① Given BootSync 描述符声明非 RoleAny 的角色门。
// When Register。
// Then 注册期报错（错误信息含 RoleAny 指引），注册表无该任务。
func TestRegister_bootSyncRequiresRoleAny(t *testing.T) {
	for _, runsOn := range []Role{RoleMasterOnly, RoleSlaveOnly, ""} {
		e := newTestEngine(t)
		err := e.Register(bootsyncDesc(runsOn))
		if err == nil {
			t.Fatalf("BootSync RunsOn=%q 注册必须被拒绝（启动执行面无角色语义）", runsOn)
		}
		if !strings.Contains(err.Error(), "RoleAny") {
			t.Fatalf("错误信息须含 RoleAny 指引, got %v", err)
		}
		e.mu.RLock()
		_, exists := e.regs["t-bs-role"]
		e.mu.RUnlock()
		if exists {
			t.Fatalf("被拒描述符不得入注册表 (RunsOn=%q)", runsOn)
		}
	}

	// 对照组：显式 RoleAny 合法注册。
	e := newTestEngine(t)
	if err := e.Register(bootsyncDesc(RoleAny)); err != nil {
		t.Fatalf("BootSync∧RoleAny 注册须通过: %v", err)
	}
}

// ② Given 注册表内直注的 BootSync∧RoleMasterOnly 任务（绕过 Register 的
//
//	注册期拒绝——纵深防御形态）+ 从节点角色引擎。
//
// When RunBootSyncTasks。
// Then Run 体不执行（角色门拦下）；翻转为主节点后同任务可执行。
func TestRunBootSyncTasks_roleGateSkipsRoleMismatch(t *testing.T) {
	e := newTestEngine(t)
	var ran atomic.Int32
	release := make(chan struct{})
	mustRegisterTaskForTest(t, e, Descriptor{ID: "t-bs-any", Family: "t", Name: "对照", Kind: KindOneshot, BootSync: true, RunsOn: RoleAny,
		Run: func(rc RunContext) error { ran.Add(1); close(release); return nil }})
	e.mu.Lock()
	e.regs["t-bs-mo"] = &registration{desc: Descriptor{
		ID: "t-bs-mo", Family: "t", Name: "主仅 BootSync", Kind: KindOneshot, BootSync: true, RunsOn: RoleMasterOnly,
		Run: func(rc RunContext) error { ran.Add(10); return nil },
	}}
	e.mu.Unlock()

	e.SetRole(false) // 从节点
	e.RunBootSyncTasks()
	select {
	case <-release:
	case <-time.After(2 * time.Second):
		t.Fatal("RoleAny BootSync 任务应照常启动执行")
	}
	time.Sleep(50 * time.Millisecond) // 容忍被拒任务的潜在异步执行
	if got := ran.Load(); got != 1 {
		t.Fatalf("从节点角色下 BootSync∧RoleMasterOnly 必须被角色门跳过, ran=%d want 1", got)
	}

	// 幂等：首轮已消费 bootSyncDone，二次调用零动作（既有契约不被角色门破坏）。
	e.RunBootSyncTasks()
	if got := ran.Load(); got != 1 {
		t.Fatalf("RunBootSyncTasks 幂等契约破坏, ran=%d want 1", got)
	}
}
