package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// stopStopCaddyTest 构造可控的 stopCaddy 环境：fake /proc（决定「是否还有
// caddy 进程」）+ 临时 pause 路径 + 可计数的 stop 命令桩。adminURL 由用例给。
type stopCaddyEnv struct {
	procRoot  string
	pauseFile string
	stopCalls atomic.Int32
}

func newStopCaddyEnv(t *testing.T, stopScript string) *stopCaddyEnv {
	t.Helper()
	dir := t.TempDir()
	env := &stopCaddyEnv{
		procRoot:  filepath.Join(dir, "proc"),
		pauseFile: filepath.Join(dir, "paused"),
	}
	if err := os.MkdirAll(env.procRoot, 0o755); err != nil {
		t.Fatalf("mkdir fake proc: %v", err)
	}
	oldProc, oldPause, oldStop := caddyProcRoot, caddyPauseFile, caddyStopCommand
	caddyProcRoot = env.procRoot
	caddyPauseFile = env.pauseFile
	caddyStopCommand = func(string) *exec.Cmd {
		env.stopCalls.Add(1)
		return exec.Command("sh", "-c", stopScript)
	}
	t.Cleanup(func() { caddyProcRoot, caddyPauseFile, caddyStopCommand = oldProc, oldPause, oldStop })
	return env
}

func (env *stopCaddyEnv) seedCaddy(t *testing.T, pid string, state byte) {
	t.Helper()
	seedProcStat(t, env.procRoot, pid, "caddy", state)
}

func (env *stopCaddyEnv) pauseExists() bool {
	_, err := os.Stat(env.pauseFile)
	return err == nil
}

// 已停止态的重试必须是成功（幂等），且不得再调用 caddy stop——旧实现把这条
// 正常路径判成「停止失败」并删除 pause，监督器随即把 Caddy 拉回运行。
func TestStopCaddy_alreadyStoppedIsIdempotentSuccess(t *testing.T) {
	env := newStopCaddyEnv(t, "exit 1")

	if err := stopCaddy("http://127.0.0.1:1"); err != nil {
		t.Fatalf("已停止态 stopCaddy 必须成功, err=%v", err)
	}
	if !env.pauseExists() {
		t.Fatal("已停止态必须保留 pause（管理员要求保持停止，监督器 standby）")
	}
	if got := env.stopCalls.Load(); got != 0 {
		t.Fatalf("已停止态不得调用 caddy stop（命令必然非零退出并被误解）, calls=%d", got)
	}
}

// 命令失败但 Caddy 仍在服务：这是真正的失败——回滚 pause（监督器继续看护）
// 并返回可读原因（含 stderr）。
func TestStopCaddy_commandFailureWithLiveCaddyRollsBackPause(t *testing.T) {
	env := newStopCaddyEnv(t, "echo 'admin endpoint is not responding' >&2; exit 7")
	env.seedCaddy(t, "4242", 'S')

	err := stopCaddy("http://127.0.0.1:1")
	if err == nil {
		t.Fatal("Caddy 仍在运行时停止失败必须返回错误")
	}
	if !strings.Contains(err.Error(), "Caddy 仍在运行") {
		t.Fatalf("err=%v, want 点名「Caddy 仍在运行」", err)
	}
	if !strings.Contains(err.Error(), "admin endpoint is not responding") {
		t.Fatalf("err=%v, want 携带 stderr 原因（不得只回 exit status 7）", err)
	}
	if env.pauseExists() {
		t.Fatal("停止失败必须回滚 pause（监督器需继续看护）")
	}
}

// 命令失败但 Caddy 已不在服务（重复停止/崩溃空窗/admin 已关）：按事实判定为
// 成功，pause 保留——这条分类是「重复停止把服务拉回运行」的直接修复。
func TestStopCaddy_commandFailureWithoutLiveCaddyIsSuccess(t *testing.T) {
	env := newStopCaddyEnv(t, "exit 9")

	if err := stopCaddy("http://127.0.0.1:1"); err != nil {
		t.Fatalf("已无 caddy 进程时命令失败应判定为已停止, err=%v", err)
	}
	if !env.pauseExists() {
		t.Fatal("已停止判定必须保留 pause")
	}
}

// 命令成功但 admin 一直可达：超时分支保留 pause 并报错；随后真实停止完成
// （进程消失）时重试必须成功，pause 仍保留——重试不得反转停止意图。
func TestStopCaddy_timeoutKeepsPauseAndRetrySucceeds(t *testing.T) {
	env := newStopCaddyEnv(t, "exit 0")
	env.seedCaddy(t, "4243", 'S')

	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer admin.Close()

	err := stopCaddy(admin.URL)
	if err == nil {
		t.Fatal("admin 3s 内仍可达时必须返回错误（不得宣称已停止）")
	}
	if !strings.Contains(err.Error(), "仍可达") {
		t.Fatalf("err=%v, want 超时文案", err)
	}
	if !env.pauseExists() {
		t.Fatal("超时分支必须保留 pause（停止意图仍生效）")
	}

	// 停止最终完成：进程消失、admin 关闭 → 重试走「已停止」分支。
	if err := os.RemoveAll(filepath.Join(env.procRoot, "4243")); err != nil {
		t.Fatalf("drop fake proc entry: %v", err)
	}
	admin.Close()
	calls := env.stopCalls.Load()
	if err := stopCaddy(admin.URL); err != nil {
		t.Fatalf("停止完成后的重试必须成功, err=%v", err)
	}
	if env.stopCalls.Load() != calls {
		t.Fatal("已停止态的重试不得再调用 caddy stop")
	}
	if !env.pauseExists() {
		t.Fatal("重试成功后 pause 必须仍在（监督器 standby）")
	}
}

// pause 写失败必须显性报错：没有 pause 的 stop 会被监督器立刻反转，回 200 是假成功。
func TestStopCaddy_pauseWriteFailureIsReported(t *testing.T) {
	for _, live := range []bool{true, false} {
		t.Run(map[bool]string{true: "live-caddy", false: "already-stopped"}[live], func(t *testing.T) {
			env := newStopCaddyEnv(t, "exit 0")
			// 父目录不存在 → os.WriteFile 失败（模拟只读/异常挂载形态）。
			caddyPauseFile = filepath.Join(env.procRoot, "missing-dir", "paused")
			if live {
				env.seedCaddy(t, "4244", 'S')
			}
			err := stopCaddy("http://127.0.0.1:1")
			if err == nil {
				t.Fatal("pause 写失败必须返回错误（不得宣称已停止）")
			}
			if !strings.Contains(err.Error(), "停止标记") {
				t.Fatalf("err=%v, want 点名停止标记写入失败", err)
			}
		})
	}
}
