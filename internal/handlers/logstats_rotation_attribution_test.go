package handlers

// 轮转副本归属单源契约：
//   - timberjack 副本按「从右往左最后一个合法时间戳段」切 stem——规则/任务
//     基名含 -<数字>（存量/导入 ID，如 lb_abc-123）时不得串到同前缀兄弟规则；
//   - 移位 .N[.gz]（含两位代次）、同秒碰撞 -N、时间戳、整文件 .gz 全族在
//     dirBytes（单文件口径）与 aggregateDirStats（聚合口径）上必须等值。

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeRotationFixture(t *testing.T, files map[string]int64) string {
	t.Helper()
	dir := t.TempDir()
	for name, size := range files {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	return dir
}

func TestDirBytes_timberjackCopyBelongsToLongestRealBase(t *testing.T) {
	dir := writeRotationFixture(t, map[string]int64{
		"lb_abc.log":                             100,
		"lb_abc-123.log":                         200,
		"lb_abc-123-20261018-101500-64-size.log": 30,
		"lb_abc-123-20261018-111500-64-size.log": 25,
	})

	// Then：副本归到自己（lb_abc-123），同前缀兄弟规则零计入。
	if active, rotated, count := dirBytesWithEntries(filepath.Join(dir, "lb_abc-123.log"), nil); active != 200 || rotated != 55 || count != 2 {
		t.Fatalf("lb_abc-123.log=(%d,%d,%d), want (200,55,2)", active, rotated, count)
	}
	if active, rotated, count := dirBytesWithEntries(filepath.Join(dir, "lb_abc.log"), nil); active != 100 || rotated != 0 || count != 0 {
		t.Fatalf("lb_abc.log=(%d,%d,%d), want (100,0,0)——兄弟规则副本不得串账", active, rotated, count)
	}

	// 聚合口径与单文件口径等值，且不产生幻影键。
	match := func(name string) bool {
		return strings.HasSuffix(strings.TrimSuffix(name, ".gz"), ".log") || isRotationCopyShape(name)
	}
	stats := aggregateDirStatsWithEntries(dir, nil, match)
	if got := stats["lb_abc.log"]; got.Active != 100 || got.Rotated != 0 || got.RotCount != 0 {
		t.Fatalf("aggregate lb_abc.log=%+v, want 100/0/0", got)
	}
	if got := stats["lb_abc-123.log"]; got.Active != 200 || got.Rotated != 55 || got.RotCount != 2 {
		t.Fatalf("aggregate lb_abc-123.log=%+v, want 200/55/2", got)
	}
	keys := make([]string, 0, len(stats))
	for key := range stats {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if want := []string{"lb_abc-123.log", "lb_abc.log"}; len(keys) != 2 || keys[0] != want[0] || keys[1] != want[1] {
		t.Fatalf("aggregate keys=%v, want %v（不得派生幻影基名）", keys, want)
	}
}

// 活跃基名缺席、只留 timberjack 副本时，单文件口径仍按固定基名计入归档。
func TestDirBytes_timberjackCopiesWithoutActiveBase(t *testing.T) {
	dir := writeRotationFixture(t, map[string]int64{
		"certjob-lb_abc-123-20261018-101500-64-size.log": 30,
		"certjob-lb_abc-123-20261018-111500-64-size.log": 25,
	})
	active, rotated, count := dirBytesWithEntries(filepath.Join(dir, "certjob-lb_abc-123.log"), nil)
	if active != 0 || rotated != 55 || count != 2 {
		t.Fatalf("missing-base dirBytes=(%d,%d,%d), want (0,55,2)", active, rotated, count)
	}
}

func TestRotationCopy_shiftGzipCollisionAndWideIndexCountBothPaths(t *testing.T) {
	dir := writeRotationFixture(t, map[string]int64{
		"caddy.log":                             100,
		"caddy.log.1":                           10,
		"caddy.log.1.gz":                        20,
		"caddy.log.2":                           15,
		"caddy.log.10":                          5,
		"caddy.log.20261018-150405":             10,
		"caddy.log.20261018-150405-2":           5,
		"caddy.log.gz":                          40,
		"caddy-tls.log":                         7,
		"caddy-tls-20261018-150405-64-size.log": 3,
	})

	const wantRotated, wantCount = int64(105), 7
	active, rotated, count := dirBytesWithEntries(filepath.Join(dir, "caddy.log"), nil)
	if active != 100 || rotated != wantRotated || count != wantCount {
		t.Fatalf("dirBytes(caddy.log)=(%d,%d,%d), want (100,%d,%d)", active, rotated, count, wantRotated, wantCount)
	}
	stats := aggregateDirStatsWithEntries(dir, nil, caddyLogFamilyMatch)
	if got := stats["caddy.log"]; got.Active != 100 || got.Rotated != wantRotated || got.RotCount != wantCount {
		t.Fatalf("aggregate caddy.log=%+v, want 100/%d/%d", got, wantRotated, wantCount)
	}
	if got := stats["caddy-tls.log"]; got.Active != 7 || got.Rotated != 3 || got.RotCount != 1 {
		t.Fatalf("aggregate caddy-tls.log=%+v, want 7/3/1", got)
	}
}

func TestIsTaskLogFamilyName_coversRotationShapes(t *testing.T) {
	cases := map[string]bool{
		"crs.log":                         true,
		"crs.log.gz":                      true,
		"crs.log.1":                       true,
		"crs.log.1.gz":                    true,
		"crs.log.10":                      true,
		"crs.log.20261018-150405":         true,
		"crs.log.20261018-150405-2":       true,
		"crs-20261018-150405-64-size.log": true,
		"crs.txt":                         false,
		"crs.log.20261018":                false,
	}
	for name, want := range cases {
		if got := isTaskLogFamilyName(name); got != want {
			t.Errorf("isTaskLogFamilyName(%q)=%v, want %v", name, got, want)
		}
	}
}

func TestRuleAccessAggregate_matchesTaskLogFamily(t *testing.T) {
	// 规则访问日志目录聚合（LogStats 的 rule_access 无规则筛选分支）逐文件判定
	// 直传 isTaskLogFamilyName（此前经纯别名 isRuleAccessLogName 间接一层）：
	// 活跃文件、移位副本、.gz 归档全计入；非日志名（同目录的其他任务日志/
	// 杂项）不得混进合计。
	cases := map[string]bool{
		"lb_cooldown.log":          true,
		"lb_cooldown.log.1":        true,
		"lb_cooldown.log.2.gz":     true,
		"lb_cooldown.log.gz":       true,
		"lb_cooldown.log.3":        true,
		"lb_cooldown.txt":          false,
		"task-crs.log":             true, // 族判定不含前缀语义：目录隔离由调用方给
		"lb_cooldown.log.20261018": false,
		"":                         false,
	}
	for name, want := range cases {
		if got := isTaskLogFamilyName(name); got != want {
			t.Errorf("isTaskLogFamilyName(%q)=%v, want %v", name, got, want)
		}
	}
}

// 任务日志族（isTaskLogFamilyName 作聚合 match）与单文件口径等值。
func TestTaskLogFamily_timestampAndShiftGzipCountBothPaths(t *testing.T) {
	dir := writeRotationFixture(t, map[string]int64{
		"crs.log":                         100,
		"crs.log.1":                       10,
		"crs.log.1.gz":                    20,
		"crs.log.20261018-150405":         10,
		"crs.log.20261018-150405-2":       5,
		"crs-20261018-150405-64-size.log": 25,
	})
	stats := aggregateDirStatsWithEntries(dir, nil, isTaskLogFamilyName)
	got := stats["crs.log"]
	want := dirStats{Active: 100, Rotated: 70, RotCount: 5}
	if got != want {
		t.Fatalf("aggregate crs.log=%+v, want %+v", got, want)
	}
	if active, rotated, count := dirBytesWithEntries(filepath.Join(dir, "crs.log"), nil); active != want.Active || rotated != want.Rotated || count != want.RotCount {
		t.Fatalf("dirBytes(crs.log)=(%d,%d,%d), want %+v", active, rotated, count, want)
	}
}
