package services

import (
	"testing"
	"time"
)

func TestGetRuleCertInfo_disabledRulesMatchBatchNullSemantics(t *testing.T) {
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(30*24*time.Hour), "disabled.example.test")
	if _, err := database.Exec(`INSERT INTO lb_rules
		(caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_disabled_manual','disabled manual','disabled.example.test','http',8443,0,1,'manual',?,?),
		('lb_disabled_acme','disabled acme','disabled.example.test','http',8444,0,1,'acme_dns','',''),
		('lb_enabled_manual','enabled manual','disabled.example.test','http',8445,1,1,'manual',?,?),
		('lb_enabled_no_tls','enabled without tls','disabled.example.test','http',8080,1,0,'manual',?,?)`,
		certPEM, keyPEM, certPEM, keyPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("seed certificate info rules: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem)
		VALUES ('lb_disabled_acme','disabled.example.test','issued',?,?)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed disabled ACME certificate: %v", err)
	}

	for _, tc := range []struct {
		name    string
		ruleID  string
		wantNil bool
	}{
		{name: "disabled manual", ruleID: "lb_disabled_manual", wantNil: true},
		{name: "disabled ACME", ruleID: "lb_disabled_acme", wantNil: true},
		{name: "enabled manual", ruleID: "lb_enabled_manual", wantNil: false},
		{name: "enabled without TLS", ruleID: "lb_enabled_no_tls", wantNil: true},
		{name: "missing rule", ruleID: "lb_missing", wantNil: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := GetRuleCertInfo(tc.ruleID)
			if err != nil {
				t.Fatalf("GetRuleCertInfo: %v", err)
			}
			if (info == nil) != tc.wantNil {
				t.Fatalf("info=%+v, wantNil=%v", info, tc.wantNil)
			}
		})
	}
}
