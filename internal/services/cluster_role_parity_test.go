package services

// 角色谓词跨包对账：services 的写语句全部经 masterRoleConditionSQL /
// slaveRoleConditionSQL，而这两个常量必须是 db 单源的别名而不是手抄副本。
// 别名一旦被改回字面量，db/apiKey flusher 与 middleware 触发器会继续用旧口径，
// 三处分裂（写闸放行但触发器不 bump 版本 / 从端仍被允许写从端专有列）无人发现；
// 源码字面量守卫在 db 包，本用例钉住「别名指向同一单源」。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestClusterRoleConditionAliasesMatchDB(t *testing.T) {
	if masterRoleConditionSQL != db.MasterRoleConditionSQL {
		t.Fatalf("services.masterRoleConditionSQL 与 db.MasterRoleConditionSQL 不一致:\n services=%q\n db      =%q",
			masterRoleConditionSQL, db.MasterRoleConditionSQL)
	}
	if slaveRoleConditionSQL != db.SlaveRoleConditionSQL {
		t.Fatalf("services.slaveRoleConditionSQL 与 db.SlaveRoleConditionSQL 不一致:\n services=%q\n db      =%q",
			slaveRoleConditionSQL, db.SlaveRoleConditionSQL)
	}
}

// 内联形态扫描：db 包的字面量守卫只认「(SELECT COALESCE(is_master,1) FROM
// global_config WHERE id=1)=」完整比较式；global_config 自身行上的内联
// 「COALESCE(is_master,1)=1/=0」是第二份手抄谓词（UpdateSettings/品牌镜像
// 曾逐字内联），改单源口径时同步不到。本守卫扫 services 全部非测试源码：
// 整份文件 compact（去全部空白）后做子串匹配——SQL 文本跨行拆行同样命中
// （逐行扫描会漏掉字面量内部换行的形态）。注释里出现完整谓词字面量同样
// 命中：角色谓词只允许经 masterRoleConditionSQL/slaveRoleConditionSQL 单源
// 拼接，任何第二份全文副本（含注释）都是漂移源。
func TestClusterRolePredicate_noInlineCopiesInServicesSQL(t *testing.T) {
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	compact := func(s string) string { return strings.Join(strings.Fields(s), "") }
	inlineMaster := compact("COALESCE(is_master,1)=1")
	inlineSlave := compact("COALESCE(is_master,1)=0")
	var offenders []string
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		c := compact(string(data))
		if strings.Contains(c, inlineMaster) || strings.Contains(c, inlineSlave) {
			offenders = append(offenders, path)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("services SQL 出现内联角色谓词手抄副本（应使用 masterRoleConditionSQL/slaveRoleConditionSQL 单源）:\n%s", strings.Join(offenders, "\n"))
	}
}
