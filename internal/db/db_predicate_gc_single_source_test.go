package db

// 两条「谓词/文件命名单源」回归钉：
//  ① TCP 死字段与跨模式 TLS 残留的「探测谓词」与「复位 WHERE」由同一常量
//     拼出——只改一侧会变成「有脏数据但探测看不到 → 永远不清」或反之，且
//     日志全绿。结构断言保证两份 SQL 里各谓词只出现一次（第二份手抄必红）。
//  ② metrics 隔离文件 GC 只处理本函数命名的 .corrupt.<秒>[-序号] 文件：
//     操作者手工留档副本（.corrupt.manual 之类）不得参与保新删旧。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeadFieldPredicatesHaveSingleSource(t *testing.T) {
	// 单源必须按「源码字面量只出现一次」判断：拼装后的 SQL 里常量值与手抄
	// 字面量本身等价（strings.Count 在拼装结果上恒等于 1），只有扫源码才能
	// 发现第二份手写谓词。
	source, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatalf("read db.go: %v", err)
	}
	text := string(source)
	// TCP 死字段：探测与复位共用同一谓词常量。
	if got := strings.Count(text, tcpDeadFieldsStalePredicate); got != 1 {
		t.Fatalf("TCP 死字段谓词在源码中出现 %d 次, want 1（不得手抄第二份）", got)
	}
	// TCP 的 DNS 服务发现清理：探测与复位共用同一谓词常量。
	if got := strings.Count(text, tcpStaleDNSServerPredicate); got != 1 {
		t.Fatalf("TCP DNS 服务发现谓词在源码中出现 %d 次, want 1（不得手抄第二份）", got)
	}

	// 跨模式 TLS 残留：三条谓词各自在探测与对应复位语句中出现恰一次。
	pairs := []struct {
		name      string
		predicate string
		reset     string
	}{
		{"证书材料", ruleTLSResidueCertPredicate, ruleTLSModeResidueResetSQLs[0]},
		{"CA 提供商引用", ruleTLSResidueCAProviderPredicate, ruleTLSModeResidueResetSQLs[1]},
		{"ACME 配置引用", ruleTLSResidueACMEConfigPredicate, ruleTLSModeResidueResetSQLs[2]},
	}
	for _, pair := range pairs {
		if got := strings.Count(text, pair.predicate); got != 1 {
			t.Fatalf("%s 谓词在源码中出现 %d 次, want 1（不得手抄第二份）", pair.name, got)
		}
		if got := strings.Count(pair.reset, pair.predicate); got != 1 {
			t.Fatalf("%s 谓词在复位 SQL 中出现 %d 次, want 1", pair.name, got)
		}
		if !strings.Contains(pair.reset, " WHERE "+pair.predicate) {
			t.Fatalf("%s 复位 SQL 的 WHERE 段不是由同一谓词拼出: %s", pair.name, pair.reset)
		}
	}
}

func TestGCQuarantinedMetricsFiles_keepsHandNamedCopies(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "lazy-balancer-metrics.db")
	mustWriteFile := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("quarantined"), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	// 5 份带时间戳（超出保留份数）+ 1 份操作者手工留档副本。
	for _, seconds := range []string{"1700000001", "1700000002", "1700000003", "1700000004", "1700000005"} {
		mustWriteFile(dbPath + ".corrupt." + seconds)
	}
	manual := dbPath + ".corrupt.before-restore"
	mustWriteFile(manual)

	gcQuarantinedMetricsFiles(dbPath)

	if _, err := os.Stat(manual); err != nil {
		t.Fatalf("手工留档副本被 GC 删除（应按未知时间保留）: %v", err)
	}
	kept := 0
	for _, seconds := range []string{"1700000001", "1700000002", "1700000003", "1700000004", "1700000005"} {
		if _, err := os.Stat(dbPath + ".corrupt." + seconds); err == nil {
			kept++
		}
	}
	if kept != quarantineKeepPerBase {
		t.Fatalf("带时间戳隔离文件保留 %d 份, want %d（保新删旧不变）", kept, quarantineKeepPerBase)
	}
	if _, err := os.Stat(dbPath + ".corrupt.1700000001"); !os.IsNotExist(err) {
		t.Fatalf("最旧时间戳文件未被删除: %v", err)
	}
}

func TestGCQuarantinedMetricsFiles_onlyHandNamedFilesAreUntouched(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "lazy-balancer-metrics.db")
	for _, suffix := range []string{"a", "b", "c", "d"} {
		path := dbPath + ".corrupt." + suffix
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	gcQuarantinedMetricsFiles(dbPath)

	for _, suffix := range []string{"a", "b", "c", "d"} {
		if _, err := os.Stat(dbPath + ".corrupt." + suffix); err != nil {
			t.Fatalf("非本命名文件 %s 被删除: %v", suffix, err)
		}
	}
}
