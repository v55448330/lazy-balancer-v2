package db

// 节点角色判定的单源守卫。db 包的后台 flusher、services 的集群写路径与
// middleware 的集群版本触发器 WHEN 子句都依赖同一条谓词
// （COALESCE(is_master,1)，NULL 视为主节点）。此前三处逐字手抄：改口径
// （如回填策略）时只改一处即分裂——写闸放行而从端写被拒，或触发器不 bump
// 版本，两侧日志全绿无人发现。
//
// 本用例扫源码而不是扫拼装结果：拼装后的 SQL 与手抄字面量等价，只有看源码
// 才能发现第二份谓词；空白归一化后比较，避免「多打一个空格」绕过守卫。

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// compactGoSource 去掉全部空白，使空白差异无法绕过字面量守卫。
func compactGoSource(text string) string {
	return strings.Join(strings.Fields(text), "")
}

func TestClusterRolePredicateHasSingleSourceInCode(t *testing.T) {
	// 白名单式谓词：完整比较式只允许由本包的常量拼接产生，源码里不得逐字出现。
	rawPredicate := compactGoSource("(SELECT COALESCE(is_master,1) FROM global_config WHERE id=1)=")
	// 读侧形态（SELECT 单列读角色）同样收口到 IsMasterNode。
	rawRead := compactGoSource("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1")
	packages := []string{".", "../services", "../middleware"}
	var offenders []string
	for _, dir := range packages {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				// 只扫一层包目录，不下钻子包（子包各自有自己的角色口径）。
				if path != dir {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			compact := compactGoSource(string(data))
			if strings.Contains(compact, rawPredicate) {
				offenders = append(offenders, path+" 手抄了节点角色比较谓词（应使用 db.MasterRoleConditionSQL/SlaveRoleConditionSQL）")
			}
			if strings.Contains(compact, rawRead) {
				offenders = append(offenders, path+" 手抄了节点角色读取 SELECT（应使用 db.IsMasterNode）")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("扫描 %s: %v", dir, err)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("节点角色判定出现手工副本（改了单源也同步不到）:\n%s", strings.Join(offenders, "\n"))
	}
}
