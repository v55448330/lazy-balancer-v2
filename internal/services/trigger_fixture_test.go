package services

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 本文件是 services 测试侧安装 cert_jobs 集群版本触发器的**唯一字面量来源**
// （及与生产 middleware 单源对账的钉测）。
//
// 生产触发器由 internal/middleware/cluster_version.go 的
// InstallClusterVersionTriggers 装配，services 测试库不会自动安装。此前
// certissuer_test.go 手写了一份自称「镜像生产」的 CREATE TRIGGER 语句，两处
// 独立字面量之间没有任何对账：生产语义漂移（改成员条件 / 增删语义列 / 改
// UPDATE OF 集合）时 services 侧仍按旧镜像绿，版本 bump 契约失去回归网。
//
// 现行形态：测试侧从这里取 DDL，另由
// TestCertJobVersionTriggerFixture_matchesMiddlewareSource 直接解析生产源码
// 文本核对（只读），任一侧漂移都会在 ./internal/services 红。
// 生产文件是别的责任人所有，故生成器不导出、不改生产代码。
var (
	// 与 middleware 的 `semanticCols := []string{...}` 逐项一致：只有这些列
	// 的真实变化才推进 cluster_version（簿记列抖动不 bump）。
	certJobVersionTriggerSemanticColumns = []string{
		"rule_id", "domain", "cert_pem", "key_pem", "expires_at", "ca_provider_id",
	}

	// UPDATE OF 集合 = middleware cert_jobs 的 snapshotColumns（该表未登记
	// clusterVersionRuntimeColumns，OF 不做运行态剔除）。
	certJobVersionTriggerOFColumns = []string{
		"rule_id", "domain", "status", "cert_pem", "key_pem", "expires_at",
		"ca_provider_id", "renewal_attempts", "ca_available_after", "last_error_code",
		"created_at", "updated_at",
	}
)

// 成员条件（材料齐全且未过期且非 disabled）与生产 NEW/OLD 两个同名常量逐字
// 一致——审计口径：证书真实可用性的唯一标准。
const (
	certJobVersionTriggerNewMember = "NEW.status<>'disabled' AND COALESCE(NEW.cert_pem,'')<>'' AND COALESCE(NEW.key_pem,'')<>'' AND datetime(NEW.expires_at)>datetime('now')"
	certJobVersionTriggerOldMember = "OLD.status<>'disabled' AND COALESCE(OLD.cert_pem,'')<>'' AND COALESCE(OLD.key_pem,'')<>'' AND datetime(OLD.expires_at)>datetime('now')"
)

// certJobVersionTriggerDDL 生成与生产同语义的 cert_jobs UPDATE 触发器：
// 主节点守卫 + 成员条件（OLD 或 NEW 任一为成员）+ 语义列值真实变化守卫 +
// disabled 双向例外。
func certJobVersionTriggerDDL(name string) string {
	valueChange := make([]string, 0, len(certJobVersionTriggerSemanticColumns)+2)
	for _, column := range certJobVersionTriggerSemanticColumns {
		valueChange = append(valueChange, fmt.Sprintf("OLD.%s IS NOT NEW.%s", column, column))
	}
	// disabled 例外：证书下线（成员→disabled）与恢复（disabled→成员）都仅
	// 变化 status，必须 bump，否则从端定格旧加载态。
	valueChange = append(valueChange, "(OLD.status<>'disabled' AND NEW.status='disabled')")
	valueChange = append(valueChange, "(OLD.status='disabled' AND NEW.status<>'disabled')")

	when := "(SELECT COALESCE(is_master,1) FROM global_config WHERE id=1)=1" +
		" AND ((" + certJobVersionTriggerOldMember + ") OR (" + certJobVersionTriggerNewMember + "))" +
		" AND (" + strings.Join(valueChange, " OR ") + ")"
	return fmt.Sprintf(`CREATE TRIGGER %s
		AFTER UPDATE OF %s ON cert_jobs
		WHEN %s
		BEGIN UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1; END`,
		name, strings.Join(certJobVersionTriggerOFColumns, ","), when)
}

// installCertJobVersionTrigger 在测试库安装与生产同语义的 cert_jobs 版本
// 触发器（DDL 来自本文件的唯一字面量来源，见文件头注释）。
func installCertJobVersionTrigger(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(certJobVersionTriggerDDL("test_cluster_version_cert_jobs_update")); err != nil {
		t.Fatalf("install certificate job version trigger: %v", err)
	}
}

// 生产单源对账：services 测试侧的字面量（语义列 / 成员条件 / UPDATE OF
// 集合）必须与 internal/middleware/cluster_version.go 中的实际取值一致。
// 解析是只读源码文本（生产文件的单源在 middleware 包内，测试侧无法引用其
// 未导出标识符）。
// 判别力：semanticCols 删掉 expires_at（或其他任何语义列增删）、成员条件
// 改动、OF 集合改动 → 本用例红。
func TestCertJobVersionTriggerFixture_matchesMiddlewareSource(t *testing.T) {
	const middlewarePath = "../middleware/cluster_version.go"
	source, err := os.ReadFile(middlewarePath)
	if err != nil {
		t.Fatalf("read production trigger source %s: %v", middlewarePath, err)
	}
	text := string(source)

	// 1) 成员条件：生产 NEW/OLD 常量字符串必须与测试字面量逐字一致。
	for _, want := range []struct {
		constName string
		value     string
	}{
		{"newCertificateMember", certJobVersionTriggerNewMember},
		{"oldCertificateMember", certJobVersionTriggerOldMember},
	} {
		pattern := regexp.MustCompile(`const\s+` + want.constName + `\s*=\s*"([^"]*)"`)
		match := pattern.FindStringSubmatch(text)
		if match == nil {
			t.Fatalf("生产源码未找到 %s 常量字面量（成员条件已重构？须同步本文件）", want.constName)
		}
		if match[1] != want.value {
			t.Fatalf("%s 漂移：\n生产 = %q\n测试 = %q", want.constName, match[1], want.value)
		}
	}

	// 2) 语义列：生产 `semanticCols := []string{...}` 的集合必须与测试清单
	//    完全一致（顺序无关——SQL 的 OR 链无序）。
	semanticMatch := regexp.MustCompile(`(?s)semanticCols := \[\]string\{(.*?)\}`).FindStringSubmatch(text)
	if semanticMatch == nil {
		t.Fatal("生产源码未找到 semanticCols 字面量（语义列集合已重构？须同步本文件）")
	}
	if got, want := quotedStrings(semanticMatch[1]), certJobVersionTriggerSemanticColumns; !sameStringSet(got, want) {
		t.Fatalf("cert_jobs 语义列漂移：\n生产 = %v\n测试 = %v", got, want)
	}

	// 3) UPDATE OF 集合：生产取 cert_jobs 的 snapshotColumns 减去
	//    clusterVersionRuntimeColumns。该表当前未登记运行态列（若登记了，OF
	//    语义变化必须显式同步本文件，否则下面的集合比较给出定位失败）。
	if strings.Contains(text, `"cert_jobs": columnSet(`) {
		t.Fatal("cert_jobs 已登记 clusterVersionRuntimeColumns——UPDATE OF 集合需要剔除运行态列，须更新本文件的 OF 清单")
	}
	snapshotMatch := regexp.MustCompile(`\{name: "cert_jobs", snapshotColumns: "([^"]*)"\}`).FindStringSubmatch(text)
	if snapshotMatch == nil {
		t.Fatal("生产源码未找到 cert_jobs 的 snapshotColumns 字面量（表定义已重构？须同步本文件）")
	}
	ofColumns := splitTrimmed(snapshotMatch[1])
	if !sameStringSet(ofColumns, certJobVersionTriggerOFColumns) {
		t.Fatalf("cert_jobs UPDATE OF 集合漂移：\n生产 = %v\n测试 = %v", ofColumns, certJobVersionTriggerOFColumns)
	}
}

// quotedStrings 提取 s 中的全部双引号字面量内容（注释不在 []string{...} 体内）。
func quotedStrings(s string) []string {
	matches := regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(s, -1)
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		values = append(values, match[1])
	}
	return values
}

// splitTrimmed 按逗号切分并去空白/空项（列清单口径）。
func splitTrimmed(s string) []string {
	parts := strings.Split(s, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

// sameStringSet 集合比较（顺序无关、重复项视为同一元素）。
func sameStringSet(a, b []string) bool {
	setOf := func(values []string) []string {
		unique := make(map[string]struct{}, len(values))
		out := make([]string, 0, len(values))
		for _, value := range values {
			if _, ok := unique[value]; ok {
				continue
			}
			unique[value] = struct{}{}
			out = append(out, value)
		}
		sort.Strings(out)
		return out
	}
	left, right := setOf(a), setOf(b)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
