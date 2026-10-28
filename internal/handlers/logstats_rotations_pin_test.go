package handlers

// 基线钉：timestampedRotationStats/dirBytes 的轮转家族形状判定
// 当前实现正确，本测试钉住四形状防回归（基线钉，非 RED——报告注明）。
// （改靶：原靶 timestampedRotations/mustSecond 生产死代码已删，
// 四形状断言经 dirBytes 不变。）
// 文件名形状按 logstats.go 实读实现构造
//   运行日志族：<base>.（rest 恰 16 字符：. + 8 数字 + - + 6 数字）
//   - timberjack 族：<stem>-<ts>-size.log[.gz]（ts 首字符为数字）
//   - 兄弟文件（caddy-tls-*/caddy-proxy-*）在 stem=caddy 下首段字母开头，不误计
//   - 非数字时间戳形态两侧家族均排除

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTimestampedRotationStats_familyShapes(t *testing.T) {
	cases := []struct {
		name        string
		base        string
		files       map[string]int64 // 文件名 → 字节数（同目录夹具）
		wantActive  int64
		wantRotated int64
	}{
		{
			name: "运行日志族副本计入 rotated",
			base: "lazy-balancer.log",
			files: map[string]int64{
				"lazy-balancer.log":                 100,
				"lazy-balancer.log.20260921-120000": 150,
				"lazy-balancer.log.20260920-115900": 100,
			},
			wantActive: 100, wantRotated: 250,
		},
		{
			name: "timberjack 族副本计入且 active 不双计",
			base: "caddy.log",
			files: map[string]int64{
				"caddy.log":                              200,
				"caddy-20260921T120000-1048576-size.log": 300,
				"caddy-20260920T115900-2048-size.log.gz": 400,
			},
			wantActive: 200, wantRotated: 700,
		},
		{
			name: "兄弟文件不误计",
			base: "caddy.log",
			files: map[string]int64{
				"caddy.log": 200,
				"caddy-tls-20260921T120000-4096-size.log":      500,
				"caddy-proxy-20260921T120000-4096-size.log.gz": 600,
			},
			wantActive: 200, wantRotated: 0,
		},
		{
			name: "运行日志族非数字时间戳排除",
			base: "lazy-balancer.log",
			files: map[string]int64{
				"lazy-balancer.log":                 100,
				"lazy-balancer.log.abcdefgh-120000": 150,
			},
			wantActive: 100, wantRotated: 0,
		},
		{
			name: "timberjack 首字符非数字排除",
			base: "caddy.log",
			files: map[string]int64{
				"caddy.log": 200,
				"caddy-nots-20260921T120000-4096-size.log": 300,
			},
			wantActive: 200, wantRotated: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, size := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			active, rotated, _ := dirBytesWithEntries(filepath.Join(dir, tc.base), nil)
			if active != tc.wantActive || rotated != tc.wantRotated {
				t.Fatalf("dirBytes(%s)=(active=%d, rotated=%d), want (active=%d, rotated=%d)",
					tc.base, active, rotated, tc.wantActive, tc.wantRotated)
			}
		})
	}
}

// gzip 压缩的运行日志族轮转副本（<base>..gz）
// 此前两套实现分叉——聚合路径（aggregateDirStats）归入独立的 .gz 键、
// dirBytes/timestampedRotationStats 完全漏计。统一为「归并到所属 base 的 rotated」。
func TestGzippedRuntimeRotation_mergesIntoBaseBothPaths(t *testing.T) {
	dir := t.TempDir()
	files := map[string]int64{
		"lazy-balancer.log":                    100,
		"lazy-balancer.log.20260921-120000.gz": 150,
		"lazy-balancer.log.20260920-115900":    50,
	}
	for name, size := range files {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// dirBytesWithEntries 路径：.gz 副本计入 rotated
	active, rotated, _ := dirBytesWithEntries(filepath.Join(dir, "lazy-balancer.log"), nil)
	if active != 100 || rotated != 200 {
		t.Fatalf("dirBytes=(active=%d, rotated=%d), want (100, 200)（.gz 副本计入）", active, rotated)
	}

	// 聚合路径：.gz 副本归并到 base，不产生独立键
	match := func(name string) bool {
		return name == "lazy-balancer.log" || strings.HasPrefix(name, "lazy-balancer.log.")
	}
	stats := aggregateDirStatsWithEntries(dir, nil, match)
	st, ok := stats["lazy-balancer.log"]
	if !ok || st.Active != 100 || st.Rotated != 200 || st.RotCount != 2 {
		t.Fatalf("aggregateDirStats base=%+v ok=%v, want active=100 rotated=200 count=2", st, ok)
	}
	if _, stray := stats["lazy-balancer.log.20260921-120000.gz"]; stray {
		t.Fatal("gzipped rotation must not surface as standalone entry")
	}
}

// 整文件 gzip 归档 <base>.gz 属于该文件的轮转副本——两套分类器
// 同输入必须等价，且聚合键不得多出独立 ".gz" 条目（消费侧按固定基名取值，
// 独立键无人读取 → 字节从展示中消失）。
func TestAggregateDirStats_wholeFileGzipArchiveJoinsBase(t *testing.T) {
	dir := t.TempDir()
	files := map[string]int{
		"caddy.log":    200,
		"caddy.log.gz": 40,
	}
	for name, size := range files {
		if err := os.WriteFile(dir+"/"+name, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aggregate := aggregateDirStatsWithEntries(dir, nil, caddyLogFamilyMatch)
	stats := aggregate["caddy.log"]
	if stats.Active != 200 || stats.Rotated != 40 || stats.RotCount != 1 {
		t.Fatalf("aggregate[caddy.log]=(%d,%d,%d), want (200,40,1)", stats.Active, stats.Rotated, stats.RotCount)
	}
	if _, exists := aggregate["caddy.log.gz"]; exists {
		t.Fatal("caddy.log.gz 落成独立键——消费侧按基名取值，该归档字节将被丢弃")
	}
	active, rotated, count := dirBytesWithEntries(dir+"/caddy.log", nil)
	if active != stats.Active || rotated != stats.Rotated || count != stats.RotCount {
		t.Fatalf("dirBytes=(%d,%d,%d) aggregate=(%d,%d,%d)——两套分类器分叉", active, rotated, count, stats.Active, stats.Rotated, stats.RotCount)
	}
}

// timberjack zstd 归档（<stem>-<ts>-<reason>.log.zst）与整文件 .zst 必须和
// .gz 同族进入聚合统计：压缩后缀集合单源（.gz/.zst），family matcher 不得
// 只认 .gz——否则同一文件在命名分类里归族、在聚合行里整份消失（页面少算
// 归档体量）。活动基名在与缺席两种形态都要一致。
func TestAggregateDirStats_zstdCopiesCountIntoBase(t *testing.T) {
	cases := []struct {
		name        string
		base        string
		files       map[string]int
		wantActive  int64
		wantRotated int64
		wantCount   int
	}{
		{
			name: "有活跃基名",
			base: "caddy.log",
			files: map[string]int{
				"caddy.log":                               100,
				"caddy.log.zst":                           15,
				"caddy-20260921-120000-64-size.log.zst":   40,
				"caddy-20260921-120100-64-size_1.log.zst": 20,
				"caddy-20260921-120200-64-size.log.gz":    10,
			},
			wantActive:  100,
			wantRotated: 85,
			wantCount:   4,
		},
		{
			name: "仅剩归档（基名缺席）",
			base: "caddy-tls.log",
			files: map[string]int{
				"caddy-tls-20260921-120000-64-size.log.zst": 30,
			},
			wantActive:  0,
			wantRotated: 30,
			wantCount:   1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, size := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			// 非 caddy 族的同名形态不得被 matcher 收进来（匹配面仍是四份日志）。
			if err := os.WriteFile(filepath.Join(dir, "other-20260921-120000-64-size.log.zst"), make([]byte, 5), 0o644); err != nil {
				t.Fatal(err)
			}

			for name := range tc.files {
				if !caddyLogFamilyMatch(name) {
					t.Fatalf("caddyLogFamilyMatch(%q)=false——压缩归档必须与 .gz 同族", name)
				}
			}
			if caddyLogFamilyMatch("other-20260921-120000-64-size.log.zst") {
				t.Fatal("非 caddy 族文件被 caddy matcher 收录")
			}

			stats := aggregateDirStatsWithEntries(dir, nil, caddyLogFamilyMatch)
			entry := stats[tc.base]
			if entry.Active != tc.wantActive || entry.Rotated != tc.wantRotated || entry.RotCount != tc.wantCount {
				t.Fatalf("aggregate[%s]=(%d,%d,%d), want (%d,%d,%d)",
					tc.base, entry.Active, entry.Rotated, entry.RotCount, tc.wantActive, tc.wantRotated, tc.wantCount)
			}
			// 归档不得落成以副本名/派生名为基名的独立键（消费侧按固定基名取值）。
			for key := range stats {
				if key != tc.base {
					t.Fatalf("聚合出现非规范基名条目 %q（压缩归档必须并入 %s）", key, tc.base)
				}
			}

			// 与单文件 dirBytes 口径一致（同一响应内两行不得分叉）。
			active, rotated, count := dirBytesWithEntries(filepath.Join(dir, tc.base), nil)
			if active != entry.Active || rotated != entry.Rotated || count != entry.RotCount {
				t.Fatalf("dirBytes=(%d,%d,%d) vs aggregate=(%d,%d,%d)——两套口径分叉",
					active, rotated, count, entry.Active, entry.Rotated, entry.RotCount)
			}
		})
	}
}
