package services

import (
	"context"
	"database/sql"
	"testing"
)

// 版本聚合必须有唯一的失败口径：读/逐行扫描/遍历任一环节失败都算「版本未知」，
// 由调用方按「未更新」上报；绝不能把基于部分行的最大值当成真实最近版本——
// 被跳过的那一行可能是更大的版本，主节点 hover 便显示陈旧版本且零错误信号
// （上报是热路径，失败只有从端一行 warn，没有别的可观测面）。

func TestReportSecurityLibraryVersions_partialScanYieldsNoBogusVersion(t *testing.T) {
	// Given：威胁库结果集首行可扫、次行不可扫
	fake := sql.OpenDB(&fakeIterErrConnector{partialScanNeedle: "FROM security_threat_sources"})

	// When
	threat, crawler := reportSecurityLibraryVersions(context.Background(), fake)

	// Then：不得把残缺行集的最大值当中「最近版本」
	if threat != "" {
		t.Fatalf("threat_version=%q, want 空串（行集不完整=版本未知，不能报部分结果）", threat)
	}
	if crawler != "" {
		t.Fatalf("crawler_version=%q, want 空串", crawler)
	}
}

func TestLatestSourceVersion_scanFailureIsReported(t *testing.T) {
	// Given：结果集首行不可 Scan（驱动级异常形态，两列对一列目标）
	fake := sql.OpenDB(&fakeIterErrConnector{scanFailNeedle: "FROM security_threat_sources"})

	// When
	version, err := latestSourceVersion(context.Background(), fake, "security_threat_sources")

	// Then：失败必须显式上抛，且不得返回部分聚合结果
	if err == nil {
		t.Fatalf("逐行 Scan 失败被静默吞掉（version=%q），want 错误传播", version)
	}
	if version != "" {
		t.Fatalf("失败时返回 %q，want 空串", version)
	}
}

func TestLatestSourceVersion_rowsIterationFailureIsReported(t *testing.T) {
	// Given：遍历中途驱动失败（Next 后在 rows.Err 暴露）
	fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: "FROM security_crawler_sources"})

	// When
	version, err := latestSourceVersion(context.Background(), fake, "security_crawler_sources")

	// Then：缺 rows.Err() 检查时这里会静默返回空串且 err=nil
	if err == nil {
		t.Fatalf("遍历失败未检查 rows.Err（version=%q）", version)
	}
	if version != "" {
		t.Fatalf("遍历失败时返回 %q，want 空串", version)
	}
}

func TestReportSecurityLibraryVersions_scanFailureYieldsNoVersion(t *testing.T) {
	// Given：威胁库首行即不可扫
	fake := sql.OpenDB(&fakeIterErrConnector{scanFailNeedle: "FROM security_threat_sources"})

	// When
	threat, crawler := reportSecurityLibraryVersions(context.Background(), fake)

	// Then
	if threat != "" || crawler != "" {
		t.Fatalf("版本=(%q,%q), want 空串", threat, crawler)
	}
}

func TestReportSecurityLibraryVersions_nilDatabaseYieldsEmpty(t *testing.T) {
	threat, crawler := reportSecurityLibraryVersions(context.Background(), nil)
	if threat != "" || crawler != "" {
		t.Fatalf("nil 库版本=(%q,%q), want 空串", threat, crawler)
	}
}
