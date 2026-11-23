package notify

// 日报布局重排钉测（2026-11-22 用户裁定第四轮）：
//  1. 服务状态前置——运营日报先看「服务是否正常/集群节点」，再看流量统计、
//     安全风险、证书、接入、认证；四种渲染格式共用 dailySections 单源，
//     顺序一致。
//  2. HTML 版式统一宽度——表头带、数据周期行、分区卡、指标表、页脚全部
//     落在同一内容列（同一左右内边距），不再出现表头宽/表格窄的三种错位。
import (
	"strings"
	"testing"
)

func TestDailySections_serviceStatusFirst(t *testing.T) {
	if len(dailySections) < 6 {
		t.Fatalf("分区数=%d，want ≥6", len(dailySections))
	}
	if dailySections[0].title != "服务状态" {
		t.Fatalf("首分区=%q，want 服务状态（先看服务是否正常再看统计）", dailySections[0].title)
	}
	if dailySections[1].title != "全局概览" {
		t.Fatalf("次分区=%q，want 全局概览（流量统计随后）", dailySections[1].title)
	}
	if dailySections[2].title != "安全风险" {
		t.Fatalf("三分区=%q，want 安全风险", dailySections[2].title)
	}
	// 四格式顺序同源：markdown/text 首节也是服务状态
	data := DailyData{Date: "2026-11-21", ClusterNote: "正常（主节点）", Uptime: "3 天", Requests: 10, Blocked: 1}
	for _, format := range []string{"markdown", "text"} {
		got := RenderDaily(data, []string{"cluster_status", "uptime", "requests", "blocked"}, format)
		if strings.Index(got, "服务状态") > strings.Index(got, "全局概览") {
			t.Fatalf("format=%s 服务状态未前置:\n%s", format, got)
		}
	}
}

func TestRenderDailyHTML_unifiedContentColumn(t *testing.T) {
	data := DailyData{Date: "2026-11-21", Requests: 1200, Blocked: 3, ClusterNote: "正常（主节点）",
		NodesSummary: "slave-a：请求 44", Uptime: "3 天", ThreatDB: "CRS 4.0", AppVersion: "v2.4.4"}
	html := RenderDaily(data, []string{"cluster_status", "nodes_summary", "uptime", "threat_db", "app_version",
		"requests", "blocked", "cert_status", "api_calls", "login_status"}, "html")
	// 旧版三种横向错位源必须消失：外层卡内再套 24px 缩进分区卡（margin:0 24px）、
	// 独立白色周期条（自带另一套 padding）、分区表再嵌套一层 td 内表格。
	for _, legacy := range []string{"margin:0 24px", "padding:8px 24px"} {
		if strings.Contains(html, legacy) {
			t.Fatalf("遗留错位样式 %q 仍存在（表头/表格/分区须同一内容列）", legacy)
		}
	}
	// 统一内容列：唯一水平内边距值（28px）贯穿表头带与正文容器
	if !strings.Contains(html, "padding:22px 28px") || !strings.Contains(html, "padding:0 28px") {
		t.Fatal("表头带与正文未共享同一 28px 内容列（宽度仍会错位）")
	}
	if strings.Index(html, "服务状态") > strings.Index(html, "全局概览") {
		t.Fatal("HTML 服务状态未前置")
	}
}

// 分节不重复：拦截/观察属安全风险，威胁库随安全风险；全局概览只留流量。
func TestDailySections_metricsPartitionedWithoutDuplicates(t *testing.T) {
	seen := map[string]string{}
	for _, sec := range dailySections {
		for _, it := range sec.items {
			if prev, ok := seen[it]; ok {
				t.Fatalf("日报项目 %q 同时出现在 %q 与 %q", it, prev, sec.title)
			}
			seen[it] = sec.title
		}
	}
	for item, want := range map[string]string{
		"blocked": "安全风险", "logged": "安全风险", "threat_db": "安全风险",
		"requests": "全局概览", "app_version": "服务状态",
	} {
		if got := seen[item]; got != want {
			t.Fatalf("日报项目 %q 分区=%q, want %q", item, got, want)
		}
	}
}

// 邮件 HTML：服务状态卡用节点表（含主节点行），全局概览/安全风险用指标卡；
// 不再是一张全区块两列表格。
func TestRenderDailyHTML_sectionLayoutsAndMasterNode(t *testing.T) {
	data := DailyData{Date: "2026-11-22", ClusterNote: "正常（主节点）",
		NodesSummary: "主节点(127.0.0.1:8000)：请求 777 · 拦截 7 · 独立IP 5\nslave-a：请求 44 · 拦截 0 · 独立IP 3",
		Requests:     1200, Allowed: 800, Blocked: 34, Logged: 12, CCTriggered: 2, Autobans: 1,
		Uptime: "1 小时", AppVersion: "v2.4.5", ThreatDB: "CRS 4.30"}
	html := RenderDaily(data, []string{"cluster_status", "nodes_summary", "uptime", "app_version",
		"requests", "allowed", "blocked", "logged", "cc_triggered", "autoban", "threat_db"}, "html")
	for _, want := range []string{"主节点(127.0.0.1:8000)", "slave-a", "<th align=\"left\"", "role=\"presentation\"", "拦截次数", "观察次数", "威胁库版本"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML 版式缺 %q:\n%s", want, html)
		}
	}
}
