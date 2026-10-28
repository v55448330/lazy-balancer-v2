package taskengine

// RunSyncQuiet：执行同一 Run 体但不落 task_runs 行（高频自愈重试降噪），
// RunSync 仍按既有语义落行。

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEngine_RunSyncQuietExecutesWithoutRunRow(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	const id = "t-quiet"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "静默重试", Kind: KindOneshot,
		Run: func(RunContext) error {
			runs.Add(1)
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := e.RunSyncQuiet(id, "caddy-restart", ""); err != nil {
		t.Fatalf("quiet run: %v", err)
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("执行次数=%d, want 1", got)
	}
	if got := countRuns(t, id); got != 0 {
		t.Fatalf("quiet 轮 task_runs=%d, want 0（重试降噪：不落行）", got)
	}

	if history := e.History(id, 10); len(history) != 0 || e.LatestRun(id) != nil {
		t.Fatalf("quiet 轮不得出现在 History/LatestRun: history=%+v latest=%+v", history, e.LatestRun(id))
	}

	if _, err := e.RunSync(id, "caddy-restart", ""); err != nil {
		t.Fatalf("recorded run: %v", err)
	}
	if got := runs.Load(); got != 2 {
		t.Fatalf("执行次数=%d, want 2", got)
	}
	if got := countRuns(t, id); got != 1 {
		t.Fatalf("RunSync 轮 task_runs=%d, want 1", got)
	}
	if history := e.History(id, 10); len(history) != 1 || e.LatestRun(id) == nil {
		t.Fatalf("RunSync 轮必须出现在 History/LatestRun: history=%+v", history)
	}

	const failedID = "t-quiet-failed"
	if err := e.Register(Descriptor{ID: failedID, Family: "t", Name: "静默失败", Kind: KindOneshot,
		Run: func(RunContext) error { return errors.New("boom") }}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RunSyncQuiet(failedID, "caddy-restart", ""); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("quiet 失败必须透传: %v", err)
	}
	if got := countRuns(t, failedID); got != 0 || len(e.History(failedID, 10)) != 0 || e.LatestRun(failedID) != nil {
		t.Fatalf("quiet 失败同样不得落行: runs=%d history=%+v latest=%+v", got, e.History(failedID, 10), e.LatestRun(failedID))
	}
}
