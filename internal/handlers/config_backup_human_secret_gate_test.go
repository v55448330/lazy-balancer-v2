package handlers

// 备份导入 human_secret 强度门：cookie 签名密钥经通用 UPDATE global_config
// 直接落库，弱值（短串/非字符串）会让已签发挑战凭证可被离线伪造。与启动
// 播种（db.seedHumanSecretAtStartup，32 字节随机 hex）同口径：非字符串拒绝、
// 非空至少 32 字节、空串归一为「重新生成」（现场生成新强密钥，不落空值）。

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func readStoredHumanSecretForGateTest(t *testing.T) string {
	t.Helper()
	var secret string
	if err := db.DB.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&secret); err != nil {
		t.Fatalf("read human_secret: %v", err)
	}
	return secret
}

// humanSecretGateOmit 与既有收敛钉测同形：系统数据分类导入，名单/规则表缺席。
func humanSecretGateOmit() map[string]struct{} {
	return map[string]struct{}{"security_ip_lists": {}, "lb_rules": {}, "upstreams": {}, "security_policies": {}, "security_policy_bindings": {}}
}

// Given 库内已有启动播种的密钥。
// When 导入携带弱值/非字符串 human_secret 的备份。
// Then 整包 400 点名 human_secret，且库内密钥零改写（零写入语义）。
func TestImportConfigBackup_humanSecretWeakValueRejected(t *testing.T) {
	h := newBackupTestHandlers(t)
	before := readStoredHumanSecretForGateTest(t)
	if before == "" {
		t.Fatal("前置：启动必须已播种 human_secret")
	}
	for _, weak := range []any{"short", strings.Repeat("x", 31), 12345, true, nil} {
		backup := buildBackup(t, backupFixtureOptions{
			FillAll: true,
			Omit:    humanSecretGateOmit(),
			Config:  map[string]any{"human_secret": weak},
		})
		response := postBackupImport(t, h, backup)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("弱值 %v 导入 status=%d body=%s, want 400", weak, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), "human_secret") {
			t.Fatalf("弱值 %v 拒绝文案未点名 human_secret: %s", weak, response.Body.String())
		}
		if got := readStoredHumanSecretForGateTest(t); got != before {
			t.Fatalf("弱值 %v 被拒后密钥仍被改写: %q → %q", weak, before, got)
		}
	}
}

// 边界与正常往返：32 字节放行（下界含等号），播种同形 64 位 hex 往返落库。
func TestImportConfigBackup_humanSecretStrengthBoundaryAndRoundTrip(t *testing.T) {
	h := newBackupTestHandlers(t)
	for _, strong := range []string{strings.Repeat("a", 32), strings.Repeat("ab", 32)} {
		backup := buildBackup(t, backupFixtureOptions{
			FillAll: true,
			Omit:    humanSecretGateOmit(),
			Config:  map[string]any{"human_secret": strong},
		})
		response := postBackupImport(t, h, backup)
		if response.Code != http.StatusOK {
			t.Fatalf("强密钥（%d 字节）导入 status=%d body=%s, want 200", len(strong), response.Code, response.Body.String())
		}
		if got := readStoredHumanSecretForGateTest(t); got != strong {
			t.Fatalf("human_secret=%q, want %q（正常往返必须原值落库）", got, strong)
		}
	}
}

// Given 库内已有播种密钥且渲染缓存已装载。
// When 导入携带空串 human_secret 的备份。
// Then 空串归一为重新生成：落库是新的 32 字节 hex 强密钥（非空、非旧值），
// 渲染缓存失效后产物消费新密钥——不得把空值落库留给渲染链惰性兜底。
func TestImportConfigBackup_humanSecretEmptyRegenerates(t *testing.T) {
	h := newBackupTestHandlers(t)
	stubHumanSecretRenderLibs(t)
	seedHumanSecretImportFixture(t)
	old := readStoredHumanSecretForGateTest(t)
	if got := renderedHumanSecrets(t); len(got) != 1 || got[0] != old {
		t.Fatalf("前置渲染 secret=%v, want [%s]", got, old)
	}

	backup := buildBackup(t, backupFixtureOptions{
		FillAll: true,
		Omit:    humanSecretGateOmit(),
		Config:  map[string]any{"human_secret": ""},
	})
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("空串导入 status=%d body=%s, want 200（归一为重新生成）", response.Code, response.Body.String())
	}
	stored := readStoredHumanSecretForGateTest(t)
	if stored == "" || stored == old {
		t.Fatalf("空串必须重新生成强密钥, stored=%q（old=%q）", stored, old)
	}
	raw, err := hex.DecodeString(stored)
	if err != nil || len(raw) != 32 {
		t.Fatalf("重新生成的密钥必须是 32 字节 hex（播种同形）: %q err=%v", stored, err)
	}
	if got := renderedHumanSecrets(t); len(got) != 1 || got[0] != stored {
		t.Fatalf("导入后渲染 secret=%v, want [%s]（缓存必须失效重读）", got, stored)
	}
}
