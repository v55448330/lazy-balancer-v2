package services

// GitHub 加速代理可配置（global_config.github_proxy_url，三内置选项替代
// 硬编码 ghfast.top）：读取、回退、白名单校验与前缀拼接测试。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// setupGitHubProxyDB 初始化隔离 DB 并把 global_config.github_proxy_url 置为
// url（空串表示保持列默认）。ghFastProxy 测试钩子确保归零，走 DB 读取路径。
func setupGitHubProxyDB(t *testing.T, url string) {
	t.Helper()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	oldHook := ghFastProxy
	ghFastProxy = ""
	t.Cleanup(func() { ghFastProxy = oldHook })
	if url != "" {
		if _, err := db.DB.Exec("UPDATE global_config SET github_proxy_url = ? WHERE id = 1", url); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGetGitHubProxyURL_freshInstallUsesDefault(t *testing.T) {
	// Given 全新安装：global_config 行由列默认值填充
	setupGitHubProxyDB(t, "")

	// When
	got := getGitHubProxyURL()

	// Then 返回内置默认（Cloudflare v4）
	if got != "https://v4.gh-proxy.org/" {
		t.Fatalf("getGitHubProxyURL()=%q, want default https://v4.gh-proxy.org/", got)
	}
}

func TestGetGitHubProxyURL_readsConfiguredValue(t *testing.T) {
	// Given 配置为 Fastly v4 线路
	setupGitHubProxyDB(t, "https://cdn.gh-proxy.org/")

	// When
	got := getGitHubProxyURL()

	// Then 返回配置值
	if got != "https://cdn.gh-proxy.org/" {
		t.Fatalf("getGitHubProxyURL()=%q, want https://cdn.gh-proxy.org/", got)
	}
}

func TestGetGitHubProxyURL_missingRowFallsBackToDefault(t *testing.T) {
	// Given global_config 无行（首次启动前的极端态）
	setupGitHubProxyDB(t, "")
	if _, err := db.DB.Exec("DELETE FROM global_config WHERE id = 1"); err != nil {
		t.Fatal(err)
	}

	// When
	got := getGitHubProxyURL()

	// Then 回退默认，不因缺行报错
	if got != "https://v4.gh-proxy.org/" {
		t.Fatalf("getGitHubProxyURL()=%q, want default fallback", got)
	}
}

func TestGetGitHubProxyURL_outOfBandValueFallsBackToDefault(t *testing.T) {
	// Given 带外写入的白名单外取值（历史值 ghfast.top 或任意 URL）
	setupGitHubProxyDB(t, "http://evil.example.com/")

	// When
	got := getGitHubProxyURL()

	// Then 读侧 fail-closed：非内置选项一律回退默认
	if got != "https://v4.gh-proxy.org/" {
		t.Fatalf("getGitHubProxyURL()=%q, want default fallback for out-of-band value", got)
	}
}

func TestGetGitHubProxyURL_testHookTakesPrecedence(t *testing.T) {
	// Given DB 配置为 Fastly，但测试钩子指向 httptest 代理
	setupGitHubProxyDB(t, "https://cdn.gh-proxy.org/")
	ghFastProxy = "http://127.0.0.1:1/"
	t.Cleanup(func() { ghFastProxy = "" })

	// When
	got := getGitHubProxyURL()

	// Then 钩子优先（既有 withGHFastProxy 测试依赖此语义）
	if got != "http://127.0.0.1:1/" {
		t.Fatalf("getGitHubProxyURL()=%q, want test hook precedence", got)
	}
}

func TestValidateGitHubProxyURL(t *testing.T) {
	// Given/When/Then 三个内置选项全部接受
	for _, ok := range []string{
		"https://v4.gh-proxy.org/",
		"https://axisnow.gh-proxy.org/",
		"https://cdn.gh-proxy.org/",
	} {
		if err := ValidateGitHubProxyURL(ok); err != nil {
			t.Fatalf("ValidateGitHubProxyURL(%q)=%v, want nil", ok, err)
		}
	}
	// 白名单外取值一律拒绝（含历史硬编码值、缺尾斜杠、任意内网地址）
	for _, bad := range []string{
		"",
		"https://ghfast.top/",
		"https://v4.gh-proxy.org",
		"http://127.0.0.1:8080/",
		"https://evil.example.com/https://github.com/",
		"https://v4.gh-proxy.org/../../internal/",
	} {
		if err := ValidateGitHubProxyURL(bad); err == nil {
			t.Fatalf("ValidateGitHubProxyURL(%q)=nil, want rejection", bad)
		}
	}
}

func TestGhProxied_prefixesConfiguredProxy(t *testing.T) {
	// Given 配置为 AxisNow v4
	setupGitHubProxyDB(t, "https://axisnow.gh-proxy.org/")

	// When 前缀拼接
	got := ghProxied("https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.28.0.tar.gz")

	// Then 拼接模式与历史一致：代理前缀 + 原始 URL
	want := "https://axisnow.gh-proxy.org/https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.28.0.tar.gz"
	if got != want {
		t.Fatalf("ghProxied()=%q, want %q", got, want)
	}
}
