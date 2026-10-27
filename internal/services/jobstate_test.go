package services

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestJobLifecycle_mapsEveryPersistedStatus(t *testing.T) {
	// Given
	want := map[string]string{
		"queued":              JobLifecycleQueued,
		"pending":             JobLifecycleActive,
		"processing":          JobLifecycleActive,
		"creating_account":    JobLifecycleActive,
		"creating_order":      JobLifecycleActive,
		"order_created":       JobLifecycleActive,
		"cleanup_dns":         JobLifecycleDownloaded,
		"cleanup_warning":     JobLifecycleDownloaded,
		"presenting_dns":      JobLifecycleActive,
		"waiting_propagation": JobLifecycleActive,
		"dns_propagated":      JobLifecycleActive,
		"accepting_challenge": JobLifecycleActive,
		"validating":          JobLifecycleActive,
		"validated":           JobLifecycleActive,
		"finalizing":          JobLifecycleActive,
		"finalized":           JobLifecycleActive,
		"downloading":         JobLifecycleActive,
		"downloaded":          JobLifecycleDownloaded,
		"issued":              JobLifecycleIssued,
		"failed":              JobLifecycleFailed,
		"waiting_ca":          JobLifecycleWaitingCA,
		"disabled":            JobLifecycleDisabled,
		"waiting_order_ready": JobLifecycleActive,
		"order_ready":         JobLifecycleActive,
		"waiting_order_valid": JobLifecycleActive,
		"order_valid":         JobLifecycleActive,
	}

	// When / Then
	if len(want) != 26 {
		t.Fatalf("persisted status fixture has %d entries, want 26", len(want))
	}
	for status, lifecycle := range want {
		if got := JobLifecycle(status); got != lifecycle {
			t.Errorf("JobLifecycle(%q)=%q, want %q", status, got, lifecycle)
		}
	}
}

// 状态枚举单源（db.CertJobStatuses ← DDL CHECK 生成 +
// services 状态机派生）。导出 API 返回副本；集合必须与生命周期映射完全一致
// ——新增状态只改 db 一处即全链生效（映射缺失由本测试的集合对比暴露）。
func TestAllJobStatuses_matchesLifecycleMapAndReturnsCopy(t *testing.T) {
	// Given
	statuses := AllJobStatuses()

	// Then：与 jobLifecycleByStatus 键集完全一致
	got := make(map[string]struct{}, len(statuses))
	for _, status := range statuses {
		if _, exists := got[status]; exists {
			t.Fatalf("duplicate status %q in AllJobStatuses", status)
		}
		got[status] = struct{}{}
	}
	if len(got) != len(jobLifecycleByStatus) {
		t.Fatalf("AllJobStatuses has %d statuses, lifecycle map has %d", len(got), len(jobLifecycleByStatus))
	}
	for status := range jobLifecycleByStatus {
		if _, ok := got[status]; !ok {
			t.Fatalf("status %q in lifecycle map missing from AllJobStatuses", status)
		}
	}

	// And：返回副本，调用方修改不污染全局
	if len(statuses) == 0 {
		t.Fatal("AllJobStatuses must not be empty")
	}
	original := statuses[0]
	statuses[0] = "mutated_by_test"
	if AllJobStatuses()[0] != original {
		t.Fatalf("AllJobStatuses leaked mutable global state")
	}
}

func TestJobLifecycle_classifiesUnknownStatusAsFailed(t *testing.T) {
	// Given
	const status = "future_unmapped_status"

	// When
	got := JobLifecycle(status)

	// Then
	if got != JobLifecycleFailed {
		t.Fatalf("JobLifecycle(%q)=%q, want %q", status, got, JobLifecycleFailed)
	}
}

func TestJobLifecycle_helpersUseLogicalLifecycle(t *testing.T) {
	// JobIsActive 已删（生产死代码）——本测试收敛为仅锁定 JobIsTerminal。
	// Given
	tests := []struct {
		status   string
		terminal bool
	}{
		{status: "issued", terminal: true},
		{status: "failed", terminal: true},
		{status: "disabled", terminal: true},
		{status: "future_unmapped_status", terminal: true},
	}

	// When / Then
	for _, test := range tests {
		if got := JobIsTerminal(test.status); got != test.terminal {
			t.Errorf("JobIsTerminal(%q)=%t, want %t", test.status, got, test.terminal)
		}
	}
}

func TestTransitionJob_updatesFieldsWhenExpectedStatusMatches(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	result, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status,message) VALUES ('lb_cas','example.com','queued','old')")
	if err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate job ID: %v", err)
	}

	// When
	err = transitionJob(database, int(jobID), []string{"queued"}, "creating_account", map[string]any{"message": "starting"})

	// Then
	if err != nil {
		t.Fatalf("transition certificate job: %v", err)
	}
	var status, message string
	if err := db.DB.QueryRow("SELECT status,message FROM cert_jobs WHERE id=?", jobID).Scan(&status, &message); err != nil {
		t.Fatalf("read transitioned certificate job: %v", err)
	}
	if status != "creating_account" || message != "starting" {
		t.Fatalf("transitioned job=(%q,%q), want creating_account/starting", status, message)
	}
}

func TestTransitionJob_returnsConflictWhenExpectedStatusDoesNotMatch(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	result, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_cas_conflict','example.com','disabled')")
	if err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate job ID: %v", err)
	}

	// When
	err = transitionJob(database, int(jobID), []string{"queued"}, "failed", nil)

	// Then
	if !errors.Is(err, ErrJobTransitionConflict) {
		t.Fatalf("transition error=%v, want ErrJobTransitionConflict", err)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read unchanged certificate job: %v", err)
	}
	if status != "disabled" {
		t.Fatalf("conflicted job status=%q, want disabled", status)
	}
}

func TestTransitionJob_allowsOnlyOneConcurrentWriter(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	result, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_cas_race','example.com','queued')")
	if err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate job ID: %v", err)
	}
	start := make(chan struct{})
	errorsByWriter := make(chan error, 2)
	var writers sync.WaitGroup
	for _, target := range []string{"creating_account", "creating_order"} {
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			errorsByWriter <- transitionJob(database, int(jobID), []string{"queued"}, target, nil)
		}()
	}

	// When
	close(start)
	writers.Wait()
	close(errorsByWriter)

	// Then
	var succeeded, conflicted int
	for transitionErr := range errorsByWriter {
		switch {
		case transitionErr == nil:
			succeeded++
		case errors.Is(transitionErr, ErrJobTransitionConflict):
			conflicted++
		default:
			t.Fatalf("unexpected transition error: %v", transitionErr)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent transitions succeeded=%d conflicted=%d, want 1/1", succeeded, conflicted)
	}
}

// cert_jobs.status 写入白名单守卫的扫描器：扫描根是**仓库根**（与同包
// lb_rules 单源门 rule_write_columns_guard_test.go 同口径）——internal/ 之外的
// 顶级包与 cmd/ 同样是「必须经 transitionJob」的覆盖面，只扫 internal/ 会让
// 未来抽出的证书队列包/运维子命令的手写写点静默逃逸。
func certJobStatusWriteViolations(root string, approved map[string]map[string]bool) ([]string, error) {
	var violations []string
	skipDirs := map[string]bool{".git": true, "vendor": true, "node_modules": true, "web": true}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if skipDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fileSet := token.NewFileSet()
		file, parseErr := parser.ParseFile(fileSet, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		// 函数体与包级声明都扫：包级 SQL 常量（var/const）同样能绕过
		// transitionJob，只扫函数体是覆盖面缺口。
		report := func(body ast.Node, owner string) {
			ast.Inspect(body, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				query, unquoteErr := strconv.Unquote(literal.Value)
				if unquoteErr != nil || !mutatesCertJobStatus(query) {
					return true
				}
				if !approved[rel][owner] {
					position := fileSet.Position(literal.Pos())
					violations = append(violations, position.String()+" in "+owner)
				}
				return true
			})
		}
		for _, declaration := range file.Decls {
			switch node := declaration.(type) {
			case *ast.FuncDecl:
				if node.Body != nil {
					report(node.Body, node.Name.Name)
				}
			case *ast.GenDecl:
				report(node, "package-level declaration")
			}
		}
		return nil
	})
	return violations, err
}

func TestCertJobStatusWrites_useApprovedEntryPoints(t *testing.T) {
	// Given：仓库相对路径 → 允许的函数集（比整文件豁免更紧）
	approved := map[string]map[string]bool{
		"internal/db/db.go":             {"createTables": true, "migrateCertJobsStatusConstraint": true},
		"internal/services/jobstate.go": {"transitionJob": true},
		// upsertQueuedCertJob：原 CreateOrRequeueCertJobWithChange 内联的
		// 「排队签发」upsert 闭包（抽为单源，供补建路径复用）——
		// 与原批准点同语义（INSERT..ON CONFLICT 置 queued），不是新绕行写点。
		"internal/services/certificates.go":  {"restoreCertJobsForRule": true, "CreateOrRequeueCertJobWithChange": true, "upsertQueuedCertJob": true},
		"internal/services/cluster_apply.go": {"replaceSnapshotTx": true},
		"internal/handlers/certjobs.go":      {"RetryCertJob": true, "retryCertJobByID": true, "DeleteCertJob": true},
		// UpdateRule/DisableRule 的禁用暂停谓词收敛为
		// disableCertJobsForRuleTx 单源；DisableRule 不再直接持字面量（白名单
		// 移除保持守卫收紧），UpdateRule 保留（域名迁移/恢复两处自有写点）。
		"internal/handlers/rules.go": {"UpdateRule": true, "EnableRule": true, "disableCertJobsForRuleTx": true, "retireCertJobsForDomain": true},
	}
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("扫描根必须为仓库根（含 go.mod）: %v", err)
	}

	// When
	violations, err := certJobStatusWriteViolations(root, approved)

	// Then
	if err != nil {
		t.Fatalf("scan repository Go sources: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("cert_jobs status writes 绕过 transitionJob:\n%s", strings.Join(violations, "\n"))
	}
}

// 扫描面正向控制：internal/ 之外的写点必须被拦（当前仓库零命中——本用例构造
// 夹具证明「零命中」不是扫描器退化）。
func TestCertJobStatusWriteGuard_catchesWritesOutsideInternal(t *testing.T) {
	root := t.TempDir()
	probeDir := filepath.Join(root, "pkg", "certqueue")
	if err := os.MkdirAll(probeDir, 0o755); err != nil {
		t.Fatalf("mkdir probe: %v", err)
	}
	probe := `package certqueue

func StealStatus(db interface{}) {
	_ = db
}

var query = "UPDATE cert_jobs SET status=? WHERE id=?"
`
	if err := os.WriteFile(filepath.Join(probeDir, "queue.go"), []byte(probe), 0o644); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	// 回归形状：internal/ 内的合法写点（白名单内）不得误报。
	legalDir := filepath.Join(root, "internal", "services")
	if err := os.MkdirAll(legalDir, 0o755); err != nil {
		t.Fatalf("mkdir legal: %v", err)
	}
	legal := `package services

func transitionJob(db interface{}) {
	_ = db
	_ = "UPDATE cert_jobs SET status=? WHERE id=? AND status IN (?)"
}
`
	if err := os.WriteFile(filepath.Join(legalDir, "jobstate.go"), []byte(legal), 0o644); err != nil {
		t.Fatalf("write legal: %v", err)
	}

	violations, err := certJobStatusWriteViolations(root, map[string]map[string]bool{
		"internal/services/jobstate.go": {"transitionJob": true},
	})
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(violations) != 1 || !strings.Contains(violations[0], "pkg/certqueue/queue.go") {
		t.Fatalf("internal/ 之外的 cert_jobs 写点必须被拦, violations=%v", violations)
	}
	// 登记白名单后归零（白名单键是仓库相对路径，扩根不改变机制）。
	violations, err = certJobStatusWriteViolations(root, map[string]map[string]bool{
		"internal/services/jobstate.go": {"transitionJob": true},
		"pkg/certqueue/queue.go":        {"package-level declaration": true},
	})
	if err != nil {
		t.Fatalf("scan fixture (package-level): %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("包级声明不得因无函数名而不可登记: %v", violations)
	}
}

func mutatesCertJobStatus(query string) bool {
	normalized := strings.Join(strings.Fields(strings.ToLower(query)), " ")
	if strings.Contains(normalized, "update cert_jobs set") {
		setClause := strings.SplitN(normalized, "update cert_jobs set", 2)[1]
		setClause = strings.SplitN(setClause, " where ", 2)[0]
		return strings.Contains(setClause, "status=") || strings.Contains(setClause, "status =")
	}
	if strings.Contains(normalized, "insert into cert_jobs") {
		columns := strings.SplitN(normalized, "insert into cert_jobs", 2)[1]
		columns = strings.SplitN(columns, ")", 2)[0]
		return strings.Contains(columns, "status")
	}
	return false
}
