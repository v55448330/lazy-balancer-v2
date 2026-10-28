package services

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 威胁情报库/爬虫地址库的版本上报必须与前端
// utils/securityLibraries.summarizeLibrarySources 同口径：各源 version 取最近
// （日期与 semver 通用），空源 → 空串。

func TestReportSecurityLibraryVersions_latestAcrossSources(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	if _, err := database.Exec(`UPDATE security_threat_sources SET version='2026.09.24' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_threat_sources SET version='2026.10.01' WHERE name='firehol_l1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_threat_sources SET version='2026.08.15' WHERE name='et_compromised'`); err != nil {
		t.Fatal(err)
	}
	// 爬虫地址库默认无种子行：显式插入两个来源版本。
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name, display_name, version) VALUES ('googlebot','Googlebot','v2.3.3'), ('gptbot','GPTBot','v2.3.10')`); err != nil {
		t.Fatal(err)
	}

	threat, crawler := reportSecurityLibraryVersions(ctx, database)
	if threat != "2026.10.01" {
		t.Fatalf("threat_version=%q, want 最近日期 2026.10.01", threat)
	}
	if crawler != "v2.3.10" {
		t.Fatalf("crawler_version=%q, want 最近 semver v2.3.10", crawler)
	}
}

func TestReportSecurityLibraryVersions_emptySourcesYieldEmptyString(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE security_threat_sources SET version=''`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`DELETE FROM security_crawler_sources`); err != nil {
		t.Fatal(err)
	}
	threat, crawler := reportSecurityLibraryVersions(ctx, database)
	if threat != "" || crawler != "" {
		t.Fatalf("空源必须为空串（前端显示未更新），got %q/%q", threat, crawler)
	}
}

// 跨栈共享夹具：web/tests/fixtures/version-compare.tsv 同时被前端
// compareVersion 用例读取——两端各自维护一份用例表曾让「缺段 vs 数值 0」
// 的口径分叉（Go 走字符串兜底返回 -1，前端按 0 判等价）而两边都绿。
func TestCompareLibraryVersion_matchesFrontendSemantics(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "web", "tests", "fixtures", "version-compare.tsv"))
	if err != nil {
		t.Fatalf("读取跨栈夹具: %v", err)
	}
	checked := 0
	for lineNo, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("夹具第 %d 行字段数=%d, want 3: %q", lineNo+1, len(fields), line)
		}
		want, convErr := strconv.Atoi(strings.TrimSpace(fields[2]))
		if convErr != nil {
			t.Fatalf("夹具第 %d 行期望符号非法: %q", lineNo+1, fields[2])
		}
		if got := compareLibraryVersion(fields[0], fields[1]); got != want {
			t.Errorf("夹具第 %d 行 compareLibraryVersion(%q,%q)=%d, want %d", lineNo+1, fields[0], fields[1], got, want)
		}
		if got := compareLibraryVersion(fields[1], fields[0]); got != -want {
			t.Errorf("夹具第 %d 行反向比较(%q,%q)=%d, want %d", lineNo+1, fields[1], fields[0], got, -want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("跨栈夹具为空")
	}
}

// 聚合口径与前端 sort+pop 同序：等值（如 1.2 与 1.2.0）取行序后者，
// 与 API ORDER BY id 的稳定排序一致，避免主节点 hover 与从节点列表
// 对同一条库显示不同形态的「最近版本」。
func TestLatestSourceVersion_tieKeepsLastRowLikeFrontend(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE security_threat_sources SET version=''`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_threat_sources SET version='1.2.0' WHERE id=(SELECT MIN(id) FROM security_threat_sources)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_threat_sources SET version='1.2' WHERE id=(SELECT MAX(id) FROM security_threat_sources)`); err != nil {
		t.Fatal(err)
	}
	if got, err := latestSourceVersion(ctx, database, "security_threat_sources"); err != nil || got != "1.2" {
		t.Fatalf("latestSourceVersion=%q err=%v, want 1.2（等值取行序后者，与前端 sort+pop 一致）", got, err)
	}
}

// 跨栈聚合夹具：web/tests/fixtures/library-aggregate.tsv 同时被前端
// summarizeLibrarySources 用例读取（web/tests/securityLibraries.spec.ts）。
// 比较器与取末位收敛后仍有第二处口径分叉——空值过滤：后端 TrimSpace 后
// 跳过纯空白版本，前端曾在 trim 前用 !!v 过滤（" " 是 truthy），同一库在主
// 节点 hover 显示未更新、在两侧规则库页显示已最新。夹具把「trim 后为空即
// 跳过」钉成两端共读的唯一事实源；status 列在 Go 侧只做自相矛盾检查
// （夹具行恒为启用 idle，status 只由 latest 是否为空决定）。
func TestLatestSourceVersion_matchesFrontendAggregateFixture(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	data, err := os.ReadFile(filepath.Join("..", "..", "web", "tests", "fixtures", "library-aggregate.tsv"))
	if err != nil {
		t.Fatalf("读取跨栈聚合夹具: %v", err)
	}
	checked := 0
	for lineNo, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("夹具第 %d 行字段数=%d, want 4: %q", lineNo+1, len(fields), line)
		}
		if _, err := database.Exec(`DELETE FROM security_threat_sources`); err != nil {
			t.Fatalf("夹具第 %d 行清理源行: %v", lineNo+1, err)
		}
		for index, version := range aggregateFixtureVersions(fields[1]) {
			if _, err := database.Exec(`INSERT INTO security_threat_sources (name, version) VALUES (?, ?)`,
				"fixture-src-"+strconv.Itoa(index+1), version); err != nil {
				t.Fatalf("夹具第 %d 行插入源 %q: %v", lineNo+1, version, err)
			}
		}
		wantStatus := "success"
		if fields[2] == "" {
			wantStatus = "never"
		}
		if fields[3] != wantStatus {
			t.Fatalf("夹具第 %d 行自相矛盾：latest=%q 却期望 status=%q（夹具行恒为启用 idle，status 由 latest 是否为空决定）", lineNo+1, fields[2], fields[3])
		}
		if got, err := latestSourceVersion(ctx, database, "security_threat_sources"); err != nil || got != fields[2] {
			t.Errorf("夹具第 %d 行 latestSourceVersion=%q err=%v, want %q（纯空白版本必须 trim 后跳过，与前端同口径）", lineNo+1, got, err, fields[2])
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("跨栈聚合夹具为空")
	}
}

// aggregateFixtureVersions 解码夹具的 versions 字段：';' 分隔，<empty> 为空串、
// <blank> 为单个空白串（「非空但 trim 后为空」的形态），其余原样。
func aggregateFixtureVersions(raw string) []string {
	if raw == "" {
		return nil
	}
	tokens := strings.Split(raw, ";")
	versions := make([]string, 0, len(tokens))
	for _, token := range tokens {
		switch token {
		case "<empty>":
			versions = append(versions, "")
		case "<blank>":
			versions = append(versions, " ")
		default:
			versions = append(versions, token)
		}
	}
	return versions
}
