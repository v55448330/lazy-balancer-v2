package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestDisableCertJobsExceptDomain_disables_only_retired_nonterminal_jobs(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	const ruleID = "lb_retire"
	for _, job := range []struct {
		domain string
		status string
	}{
		{domain: "keep.example.com", status: "queued"},
		{domain: "old.example.com", status: "downloaded"},
		{domain: "issued.example.com", status: "issued"},
		{domain: "failed.example.com", status: "failed"},
	} {
		if _, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status) VALUES (?,?,?)", ruleID, job.domain, job.status); err != nil {
			t.Fatalf("seed %s job: %v", job.domain, err)
		}
	}

	// When
	err := DisableCertJobsExceptDomain(ruleID, "keep.example.com")

	// Then
	if err != nil {
		t.Fatalf("disable retired jobs: %v", err)
	}
	want := map[string]string{
		"keep.example.com":   "queued",
		"old.example.com":    "disabled",
		"issued.example.com": "issued",
		"failed.example.com": "failed",
	}
	rows, err := database.Query("SELECT domain,status FROM cert_jobs WHERE rule_id=?", ruleID)
	if err != nil {
		t.Fatalf("query jobs: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var domain, status string
		if err := rows.Scan(&domain, &status); err != nil {
			t.Fatalf("scan job: %v", err)
		}
		if status != want[domain] {
			t.Fatalf("job %s status=%q, want %q", domain, status, want[domain])
		}
	}
}

func TestCertJobsSnapshot_restore_replaces_upserted_and_new_rows(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	const ruleID = "lb_snapshot"
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,ca_provider_id,renewal_attempts) VALUES (?, 'old.example.com', 'failed', 'old message', 7, 3)`, ruleID)
	if err != nil {
		t.Fatalf("seed old job: %v", err)
	}
	oldID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read old job ID: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot jobs: %v", err)
	}
	if _, err := database.Exec(`UPDATE cert_jobs SET status='queued', message='overwritten', ca_provider_id=9, renewal_attempts=0 WHERE id=?`, oldID); err != nil {
		t.Fatalf("overwrite old job: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES (?, 'new.example.com', 'queued')`, ruleID); err != nil {
		t.Fatalf("seed new job: %v", err)
	}

	// When
	err = RestoreCertJobsForRule(snapshot)

	// Then
	if err != nil {
		t.Fatalf("restore jobs: %v", err)
	}
	var count, gotID, providerID, attempts int
	var status, message string
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&count); err != nil {
		t.Fatalf("count restored jobs: %v", err)
	}
	if err := db.DB.QueryRow("SELECT id,status,message,ca_provider_id,renewal_attempts FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&gotID, &status, &message, &providerID, &attempts); err != nil {
		t.Fatalf("read restored job: %v", err)
	}
	if count != 1 || int64(gotID) != oldID || status != "failed" || message != "old message" || providerID != 7 || attempts != 3 {
		t.Fatalf("restored count=%d id=%d status=%q message=%q provider=%d attempts=%d", count, gotID, status, message, providerID, attempts)
	}
}
