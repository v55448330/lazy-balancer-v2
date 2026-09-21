package handlers

// U2-6（第 45 轮审计）基线钉：timestampedRotations/dirBytes 的轮转家族形状判定
// 当前实现正确，本测试钉住四形状防回归（基线钉，非 RED——报告注明）。
// 文件名形状按 logstats.go 实读实现构造（R-8 验证源直取）：
//   - 运行日志族：<base>.YYYYMMDD-HHMMSS（rest 恰 16 字符：. + 8 数字 + - + 6 数字）
//   - timberjack 族：<stem>-<ts>-size.log[.gz]（ts 首字符为数字）
//   - 兄弟文件（caddy-tls-*/caddy-proxy-*）在 stem=caddy 下首段字母开头，不误计
//   - 非数字时间戳形态两侧家族均排除

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTimestampedRotations_familyShapes(t *testing.T) {
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
			active, rotated := dirBytes(filepath.Join(dir, tc.base))
			if active != tc.wantActive || rotated != tc.wantRotated {
				t.Fatalf("dirBytes(%s)=(active=%d, rotated=%d), want (active=%d, rotated=%d)",
					tc.base, active, rotated, tc.wantActive, tc.wantRotated)
			}
		})
	}
}
