package services

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSelectCertificate_prefersLaterExpiry_overRecentIssuance(t *testing.T) {
	// Given：旧证书剩余有效期更长（90 天），新签发的证书先到期（30 天）——
	// 剩余有效期是主排序键，最近签发不得压过更晚的 NotAfter
	now := time.Now().UTC()
	oldCert, oldKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "example.com")
	newCert, newKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(30*24*time.Hour), "example.com")
	candidates := []CertificateCandidate{
		{ID: 1, Status: "issued", CertPEM: oldCert, KeyPEM: oldKey, UpdatedAt: 1},
		{ID: 2, Status: "issued", CertPEM: newCert, KeyPEM: newKey, UpdatedAt: 2},
	}

	// When
	selected, ok := SelectCertificate(candidates, "example.com", now)

	// Then
	if !ok || selected.Candidate.CertPEM != oldCert {
		t.Fatalf("selected=%v, want later-expiry certificate", ok)
	}
}

func TestCertificateSelection_surfacesUseSameCertificate(t *testing.T) {
	tests := []struct {
		name        string
		ruleDomains string
		jobs        []certificateSelectionFixture
		wantIndex   int
	}{
		{
			name: "single certificate", ruleDomains: "single.example.com", wantIndex: 0,
			jobs: []certificateSelectionFixture{{jobDomains: "single.example.com", sanDomains: []string{"single.example.com"}, updated: 1}},
		},
		{
			name: "dual domain task", ruleDomains: "www.dual.example.com,dual.example.com", wantIndex: 0,
			jobs: []certificateSelectionFixture{{jobDomains: "dual.example.com,www.dual.example.com", sanDomains: []string{"dual.example.com", "www.dual.example.com"}, updated: 1}},
		},
		{
			name: "domain expansion excludes old certificate", ruleDomains: "expand.example.com,www.expand.example.com", wantIndex: 1,
			jobs: []certificateSelectionFixture{
				{jobDomains: "expand.example.com", sanDomains: []string{"expand.example.com"}, updated: 2},
				{jobDomains: "expand.example.com,www.expand.example.com", sanDomains: []string{"expand.example.com", "www.expand.example.com"}, updated: 1},
			},
		},
		{
			name: "longest remaining validity wins over recent issuance", ruleDomains: "renew.example.com,www.renew.example.com", wantIndex: 0,
			jobs: []certificateSelectionFixture{
				{jobDomains: "renew.example.com,www.renew.example.com", sanDomains: []string{"renew.example.com", "www.renew.example.com"}, updated: 1, validity: 90 * 24 * time.Hour},
				{jobDomains: "renew.example.com", sanDomains: []string{"renew.example.com", "www.renew.example.com"}, updated: 2, validity: 30 * 24 * time.Hour},
			},
		},
		{
			name: "same expiry prefers exact domain over covering", ruleDomains: "tie.example.com,www.tie.example.com", wantIndex: 0,
			jobs: []certificateSelectionFixture{
				{jobDomains: "tie.example.com,www.tie.example.com", sanDomains: []string{"tie.example.com", "www.tie.example.com"}, updated: 1, validity: 60 * 24 * time.Hour},
				{jobDomains: "tie.example.com,www.tie.example.com,api.tie.example.com", sanDomains: []string{"tie.example.com", "www.tie.example.com", "api.tie.example.com"}, updated: 2, validity: 60 * 24 * time.Hour},
			},
		},
		{
			name: "SAN set mismatch is excluded", ruleDomains: "set.example.com,www.set.example.com", wantIndex: 1,
			jobs: []certificateSelectionFixture{
				{jobDomains: "set.example.com,api.set.example.com", sanDomains: []string{"set.example.com", "api.set.example.com"}, updated: 2},
				{jobDomains: "set.example.com,www.set.example.com", sanDomains: []string{"set.example.com", "www.set.example.com"}, updated: 1},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			useTemporaryCertDir(t)
			service, database := newClusterTestService(t)
			now := time.Now().UTC()
			service.snapshotNow = func() time.Time { return now }
			ruleID := "lb_selector"
			candidates := make([]CertificateCandidate, 0, len(test.jobs))
			certificates := make([]string, 0, len(test.jobs))
			for index, job := range test.jobs {
				validity := job.validity
				if validity == 0 {
					validity = 60 * 24 * time.Hour
				}
				certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(validity), job.sanDomains...)
				certificates = append(certificates, certPEM)
				jobID := index + 1
				updatedAt := now.Add(time.Duration(job.updated) * time.Hour)
				if index == 0 {
					seedSnapshotCertificate(t, database, ruleID, test.ruleDomains, job.jobDomains, certPEM, keyPEM, now.Add(validity), jobID)
				} else {
					seedSnapshotCertificateJob(t, database, ruleID, job.jobDomains, certPEM, keyPEM, now.Add(validity), jobID)
				}
				if _, err := database.Exec("UPDATE cert_jobs SET updated_at=? WHERE id=?", updatedAt, jobID); err != nil {
					t.Fatalf("set candidate ordering: %v", err)
				}
				candidates = append(candidates, CertificateCandidate{ID: int64(jobID), Domain: job.jobDomains, Status: "issued", CertPEM: certPEM, KeyPEM: keyPEM, UpdatedAt: float64(updatedAt.Unix())})
			}
			wantPEM := certificates[test.wantIndex]

			// When
			generated := generateCaddyConfigFromStore(database)
			snapshot, _, snapshotErr := service.Snapshot(context.Background(), 0, "", "")
			certInfoPEM, certInfoOK := SelectRuleCertificate(candidates, test.ruleDomains, now)

			// Then
			if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
				t.Fatalf("generate Caddy config: %s", message)
			}
			certPath, _ := CertFilePaths(ruleID)
			caddyPEM, err := os.ReadFile(certPath)
			if err != nil {
				t.Fatalf("read Caddy certificate: %v", err)
			}
			if snapshotErr != nil || len(snapshot.Certs) != 1 {
				t.Fatalf("snapshot certificates=%d error=%v", len(snapshot.Certs), snapshotErr)
			}
			if !certInfoOK || string(caddyPEM) != wantPEM || snapshot.Certs[0].CertPEM != wantPEM || certInfoPEM != wantPEM {
				t.Fatalf("selection mismatch: caddy=%v snapshot=%v certinfo=%v", string(caddyPEM) == wantPEM, snapshot.Certs[0].CertPEM == wantPEM, certInfoPEM == wantPEM)
			}
		})
	}
}

func TestCertificateService_CheckExpiration_skipsRenewal_whenSelectedCertificateIsOutsideWindow(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "renewal.example.com")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_selector_renewal','renewal','http','renewal.example.com',443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed renewal rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,updated_at)
		VALUES ('lb_selector_renewal','renewal.example.com','issued',datetime('now','+1 day'),?,?,datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed renewal certificate: %v", err)
	}

	// When
	jobs := NewCertificateService().CheckExpiration()

	// Then
	if len(jobs) != 0 {
		t.Fatalf("renewal jobs=%v, want selected valid certificate to skip renewal", jobs)
	}
}

func TestRequeueNonTerminalCertJobs_skipsIssuance_whenSelectedCertificateIsOutsideWindow(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "recovery.example.com")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_selector_recovery','recovery','http','recovery.example.com',443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed recovery rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,updated_at)
		VALUES ('lb_selector_recovery','recovery.example.com','queued',datetime('now','+90 days'),?,?,datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed recovery certificate: %v", err)
	}
	queued := 0

	// When
	err := requeueNonTerminalCertJobs(context.Background(), func(int, issuedCertificate, time.Duration) { queued++ })

	// Then
	if err != nil {
		t.Fatalf("recover certificate jobs: %v", err)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_selector_recovery'").Scan(&status); err != nil {
		t.Fatalf("read recovery status: %v", err)
	}
	if queued != 0 || status != "issued" {
		t.Fatalf("recovery queued=%d status=%q, want skipped issued job", queued, status)
	}
}

type certificateSelectionFixture struct {
	jobDomains string
	sanDomains []string
	updated    int
	validity   time.Duration
}
