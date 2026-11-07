package services

// caddyl4sec 模块契约对账（与 geoip_plugin_contract_test.go 同手法）：
// C2 渲染侧发射的模块 ID / handler 字段与 A2 模块注册的字面量必须逐字一致。
// 模块目录缺席（并行实现未落地）时跳过；落地后任一侧改名即在此失败。
import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const l4SecModuleDir = "../../caddyl4sec"

func l4secModuleSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(l4SecModuleDir)
	if err != nil {
		t.Skipf("caddyl4sec 模块目录缺席（并行实现未落地）: %v", err)
	}
	var sb strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(l4SecModuleDir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		sb.Write(raw)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// l4secRendererSource 是载荷键对账的渲染侧取材（路由拼装 + TCP 拦截提示行）。
func l4secRendererSource(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	for _, name := range []string{"l4_security_render.go", "l4_tcp_notice.go"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sb.Write(raw)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func TestL4SecContract_moduleRegistrationsMatchRender(t *testing.T) {
	src := l4secModuleSource(t)
	// 模块注册 ID（契约 C2 固定，两侧不得改名）。lb_ipfile 是仓内模块
	// （绕开 caddy-l4 v0.1.2 上游 remote_ip_list 的 Cleanup 死锁——主审裁定，
	// A2 交付中）：其注册落地前为软钉（PENDING 日志），落地即硬化。
	for _, literal := range []string{
		"layer4.handlers.lb_l4_sec",
		"layer4.handlers.lb_l4_pp",
		"layer4.matchers.lb_geoip",
	} {
		if !strings.Contains(src, literal) {
			t.Errorf("caddyl4sec 模块源码缺注册 ID %q（渲染侧与模块侧契约断裂）", literal)
		}
	}
	ipfileLanded := strings.Contains(src, "layer4.matchers.lb_ipfile")
	if !ipfileLanded {
		t.Logf("PENDING A2: layer4.matchers.lb_ipfile 注册未落地，其形状对账待落地后硬化（渲染侧已切换 lb_ipfile 形状）")
	}
	// 事件上报/采样 handler 的 JSON 字段键（渲染侧字段名，模块侧解码用）。
	for _, field := range []string{"rule_caddy_id", "reason", "policy_id", "allow_sample"} {
		if !strings.Contains(src, field) {
			t.Errorf("caddyl4sec 模块源码缺字段 %q（lb_l4_sec 载荷契约断裂）", field)
		}
	}
	// 地域拦截 matcher 的名单字段键；名单文件 matcher 的单文件键仅在其
	// 注册落地后硬化（PENDING 期间渲染侧形状由结构钉测覆盖）。
	if !strings.Contains(src, "countries") {
		t.Errorf("caddyl4sec 模块源码缺 lb_geoip countries 字段")
	}
	if ipfileLanded && !strings.Contains(src, "\"file\"") {
		t.Errorf("caddyl4sec 模块源码缺 lb_ipfile file 字段（matcher 载荷契约断裂）")
	}
	// 载荷字段键契约两侧成对钉死（任一侧删键/改名即红）：模块侧钉解码
	// json tag 整串——裸词（allow/mode）在模块源码标识符与注释中处处出现，
	// 无判别力；渲染侧钉发射语句（空白归一，gofmt 列对齐不敏感）。
	for _, tag := range []string{
		`json:"block_notice,omitempty"`, // lb_l4_sec 断连路由的拦截提示行
		`json:"allow,omitempty"`,        // lb_l4_pp 受信代理网段
		`json:"mode,omitempty"`,         // lb_geoip 阻断方向 / lb_l4_sec 采样形态
		`json:"xdb_path,omitempty"`,     // ip2region v4 库路径（自定义 data_dir）
		`json:"xdb_v6_path,omitempty"`,  // ip2region v6 库路径
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("caddyl4sec 模块源码缺载荷键 tag %s（渲染侧↔模块侧字段契约断裂）", tag)
		}
	}
	normalized := strings.Join(strings.Fields(l4secRendererSource(t)), " ")
	for _, emission := range []string{
		`handler["block_notice"] = notice`,     // l4_tcp_notice.go 断连路由
		`"allow": allow,`,                      // lb_l4_pp 受信代理网段
		`conf["mode"] = "allow"`,               // lb_geoip allow 方向
		`"mode": l4SecSampleModeValue,`,        // lb_l4_sec 采样形态
		`conf["xdb_path"] = ip2regionLivePath`, // lb_geoip v4
		`h["xdb_path"] = ip2regionLivePath`,    // lb_l4_sec 采样 v4
		`conf["xdb_v6_path"] = ip2regionV6LivePath`,
		`h["xdb_v6_path"] = ip2regionV6LivePath`,
	} {
		if !strings.Contains(normalized, emission) {
			t.Errorf("渲染侧源码缺载荷键发射 %s（渲染侧↔模块侧字段契约断裂）", emission)
		}
	}
}
