package services

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 部署窗口推进写点必须单源：窗口列 + message + updated_at 必须同写，否则重试
// 冷却门（以 updated_at 为计时基准）看不到本轮重排——「补扫可见但冷却门不可见」
// 的半套状态。五个写点（CA 队列两处 / 快照补偿恢复 / handlers 的两处）曾各写
// 一份内联 SQL 靠注释互相约束，任一处漏写 updated_at 即复活该形态。
func TestPushCertJobDeploymentWindow_writesWindowMessageAndUpdatedAt(t *testing.T) {
	_, database := newClusterTestService(t)
	jobID := seedDeploymentWindowJob(t, database, "downloaded")
	mustExec(t, database, `UPDATE cert_jobs SET updated_at='2020-01-01 00:00:00', deployment_available_after=NULL WHERE id=?`, jobID)

	rows, err := PushCertJobDeploymentWindow(database, jobID, CertJobDeploymentWindowPush{
		Message: "等待重新部署",
		Where:   "status='downloaded'",
	})
	if err != nil {
		t.Fatalf("push deployment window: %v", err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d, want 1", rows)
	}
	assertDeploymentWindowPushed(t, database, jobID, "downloaded", "等待重新部署")
}

// 状态恢复形态（删除失败 disabled→downloaded）：status 与窗口必须同写，
// 否则恢复出来的行停在无窗口态，部署补扫看不到它。
func TestPushCertJobDeploymentWindow_statusRestoreCarriesWindow(t *testing.T) {
	_, database := newClusterTestService(t)
	jobID := seedDeploymentWindowJob(t, database, "disabled")
	mustExec(t, database, `UPDATE cert_jobs SET updated_at='2020-01-01 00:00:00', deployment_available_after=NULL WHERE id=?`, jobID)

	rows, err := PushCertJobDeploymentWindow(database, jobID, CertJobDeploymentWindowPush{
		Status:  "downloaded",
		Message: "删除失败，等待恢复部署",
		Where:   "status='disabled'",
	})
	if err != nil {
		t.Fatalf("push deployment window: %v", err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d, want 1（disabled 行必须被恢复写作命中）", rows)
	}
	assertDeploymentWindowPushed(t, database, jobID, "downloaded", "删除失败，等待恢复部署")
}

// 谓词不命中必须返回 0 行且不改写任何列（CAS 语义由单源保持）。
func TestPushCertJobDeploymentWindow_statusMismatchWritesNothing(t *testing.T) {
	_, database := newClusterTestService(t)
	jobID := seedDeploymentWindowJob(t, database, "issued")
	mustExec(t, database, `UPDATE cert_jobs SET updated_at='2020-01-01 00:00:00', deployment_available_after=NULL WHERE id=?`, jobID)

	rows, err := PushCertJobDeploymentWindow(database, jobID, CertJobDeploymentWindowPush{
		Message: "等待重新部署",
		Where:   "status='downloaded'",
	})
	if err != nil {
		t.Fatalf("push deployment window: %v", err)
	}
	if rows != 0 {
		t.Fatalf("rows=%d, want 0（状态不符不得改写）", rows)
	}
	var updatedAt string
	var window string
	if err := database.QueryRow("SELECT COALESCE(updated_at,''), COALESCE(deployment_available_after,'') FROM cert_jobs WHERE id=?", jobID).Scan(&updatedAt, &window); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if updatedAt != "2020-01-01 00:00:00" || window != "" {
		t.Fatalf("updated_at=%q window=%q, want 未改写", updatedAt, window)
	}
}

// 单源守护：生产代码不得再内联「部署窗口 + updated_at」组合写点。字符串扫描是
// 只读匹配，调代价可忽略；历史事故正是五份副本靠注释互相约束。
func TestCertJobDeploymentWindow_hasNoInlineCopies(t *testing.T) {
	paths := []string{
		"certificates.go", "caqueue.go", "certmaterial.go", "certissuer.go", "certstore.go",
		filepath.Join("..", "handlers", "certificates.go"),
		filepath.Join("..", "handlers", "certjobs.go"),
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		squashed := strings.Join(strings.Fields(string(data)), "")
		if strings.HasSuffix(path, "certmaterial.go") {
			// 单源本体：必须含完整三元组。
			for _, fragment := range []string{"deployment_available_after=datetime('now')", "message=?", "updated_at=datetime('now')"} {
				if !strings.Contains(squashed, strings.Join(strings.Fields(fragment), "")) {
					t.Fatalf("%s: 单源实现缺少 %q", path, fragment)
				}
			}
			continue
		}
		if strings.Contains(squashed, "deployment_available_after=datetime('now')") {
			t.Errorf("%s: 内联部署窗口写点，必须复用 services.PushCertJobDeploymentWindow", path)
		}
	}
}

func seedDeploymentWindowJob(t *testing.T, database *sql.DB, status string) int {
	t.Helper()
	mustExec(t, database, `INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_window','lb_window','window.example.com','http',8080,1,1,'acme_dns')`)
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,ca_provider_id)
		VALUES ('lb_window','window.example.com',?,'cert','key',1)`, status)
	if err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	return int(jobID)
}

func assertDeploymentWindowPushed(t *testing.T, database *sql.DB, jobID int, wantStatus, wantMessage string) {
	t.Helper()
	var status, message, updatedAt string
	var windowFresh bool
	if err := database.QueryRow(`SELECT status, COALESCE(message,''), COALESCE(updated_at,''),
			ABS(strftime('%s', deployment_available_after) - strftime('%s','now')) < 60
		FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &message, &updatedAt, &windowFresh); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != wantStatus {
		t.Fatalf("status=%q, want %q", status, wantStatus)
	}
	if message != wantMessage {
		t.Fatalf("message=%q, want %q", message, wantMessage)
	}
	if !windowFresh {
		t.Fatal("deployment_available_after 未推到当前时刻（部署补扫看不到该行）")
	}
	if updatedAt == "2020-01-01 00:00:00" {
		t.Fatal("updated_at 未同步推进（重试冷却门以它为基准，本轮重排不可见）")
	}
}

func mustExec(t *testing.T, database *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := database.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}
