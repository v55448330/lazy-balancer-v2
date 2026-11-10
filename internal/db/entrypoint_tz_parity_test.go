package db_test

import (
	"os"
	"regexp"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// audit136-U4-2：容器侧 docker-entrypoint.sh 的 TZ 默认值字面量与
// db.DefaultTimezone 双写，无机械对账——一侧改动另一侧静默漂移（进程 TZ 与
// 面板时区分叉）。本钉测把两侧锁死：字面量改动必须同步两处才可过门禁。
func TestEntrypointTZFallbackParity(t *testing.T) {
	raw, err := os.ReadFile("../../docker-entrypoint.sh")
	if err != nil {
		t.Fatalf("读取 docker-entrypoint.sh: %v", err)
	}
	const pattern = `COALESCE\(timezone,'([^']+)'\)`
	m := regexp.MustCompile(pattern).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("docker-entrypoint.sh 未找到 %s 形态的 TZ 默认值字面量——若读取机制已改，请同步更新本钉测", pattern)
	}
	if m[1] != db.DefaultTimezone {
		t.Fatalf("entrypoint TZ 默认 %q ≠ db.DefaultTimezone %q——两处字面量必须同步",
			m[1], db.DefaultTimezone)
	}
	// fallback 分支（sqlite3 不可用/库缺失）同样必须与库默认一致
	fb := regexp.MustCompile(`echo "([^"]+)"`).FindAllStringSubmatch(string(raw), -1)
	hit := false
	for _, f := range fb {
		if f[1] == db.DefaultTimezone {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("entrypoint TZ fallback echo 字面量与 db.DefaultTimezone %q 不一致", db.DefaultTimezone)
	}
}
