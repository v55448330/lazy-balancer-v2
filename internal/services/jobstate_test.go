package services

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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
	// Given
	tests := []struct {
		status   string
		active   bool
		terminal bool
	}{
		{status: "queued", active: true},
		{status: "creating_order", active: true},
		{status: "cleanup_warning", active: true},
		{status: "waiting_ca", active: false},
		{status: "issued", terminal: true},
		{status: "failed", terminal: true},
		{status: "disabled", terminal: true},
		{status: "future_unmapped_status", terminal: true},
	}

	// When / Then
	for _, test := range tests {
		if got := JobIsActive(test.status); got != test.active {
			t.Errorf("JobIsActive(%q)=%t, want %t", test.status, got, test.active)
		}
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

func TestCertJobStatusWrites_useApprovedEntryPoints(t *testing.T) {
	// Given
	approved := map[string]map[string]bool{
		"db/db.go":                  {"createTables": true, "migrateCertJobsStatusConstraint": true},
		"services/jobstate.go":      {"transitionJob": true},
		"services/certificates.go":  {"restoreCertJobsForRule": true, "CreateOrRequeueCertJobWithChange": true},
		"services/cluster_apply.go": {"replaceSnapshotTx": true},
		"handlers/certjobs.go":      {"RetryCertJob": true, "DeleteCertJob": true},
		"handlers/rules.go":         {"UpdateRule": true, "EnableRule": true, "DisableRule": true, "retireCertJobsForDomain": true},
	}
	var violations []string

	// When
	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fileSet := token.NewFileSet()
		file, parseErr := parser.ParseFile(fileSet, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		rel, relErr := filepath.Rel("..", path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				query, unquoteErr := strconv.Unquote(literal.Value)
				if unquoteErr != nil || !mutatesCertJobStatus(query) {
					return true
				}
				if !approved[rel][function.Name.Name] {
					position := fileSet.Position(literal.Pos())
					violations = append(violations, position.String()+" in "+function.Name.Name)
				}
				return true
			})
		}
		return nil
	})

	// Then
	if err != nil {
		t.Fatalf("scan internal Go sources: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("cert_jobs status writes bypass transitionJob:\n%s", strings.Join(violations, "\n"))
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
