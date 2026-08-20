package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// R50 S-2/S-3：域名迁移事务开启失败时的旧域任务退役语句被提取为可单测的
// retireCertJobsForDomain。导入备份可携带非规范 domain 行（大小写/空白/顺序
// 变体，config_backup 只校验 status 不归一 domain），退役必须与 certjobs.go
// 同型按去空白小写归一（lower+replace）与 canonical/reversed 双形式匹配，
// 否则变体行逃逸退役、旧域 'issued'+PEM 行永驻（sweep 跳过终态）。
func TestRetireCertJobsForDomain(t *testing.T) {
	seedJob := func(t *testing.T, ruleID, domain, status string) int {
		t.Helper()
		result, err := db.DB.Exec(
			`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,ca_provider_id) VALUES (?,?,?,'PEM','KEY',1)`,
			ruleID, domain, status)
		if err != nil {
			t.Fatalf("seed cert job (%s,%s): %v", ruleID, domain, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("read seeded job id: %v", err)
		}
		return int(id)
	}
	readJob := func(t *testing.T, id int) (status, domain, pem string) {
		t.Helper()
		if err := db.DB.QueryRow(`SELECT status,domain,COALESCE(cert_pem,'') FROM cert_jobs WHERE id=?`, id).
			Scan(&status, &domain, &pem); err != nil {
			t.Fatalf("read cert job %d: %v", id, err)
		}
		return status, domain, pem
	}

	t.Run("canonical domain hit", func(t *testing.T) {
		// Given：规范存储的旧域任务
		initializeRuleFeatureTestDB(t)
		canonical := "example.test,www.example.test"
		jobID := seedJob(t, "lb_retire_canon", canonical, "issued")

		// When
		err := retireCertJobsForDomain(db.DB, "lb_retire_canon", canonical, reversedACMEDomainForm(canonical))

		// Then：退役为 disabled 终态且保留 PEM（域名未实际迁移，旧证留作历史无副作用）
		if err != nil {
			t.Fatalf("retire err=%v, want nil", err)
		}
		status, domain, pem := readJob(t, jobID)
		if status != "disabled" || domain != canonical || pem != "PEM" {
			t.Fatalf("job=(%q,%q,pem=%q), want disabled 终态、域名不改、PEM 保留", status, domain, pem)
		}
	})

	t.Run("non-canonical variant hit via dual form", func(t *testing.T) {
		// Given：导入可携带的变体行——逆序+大小写+空白变体、纯大小写变体，
		// 以及一条不相关的其他域任务（不得被误退役）
		initializeRuleFeatureTestDB(t)
		canonical := "example.test,www.example.test"
		variantID := seedJob(t, "lb_retire_variant", "WWW.example.test, example.test", "issued")
		caseID := seedJob(t, "lb_retire_variant", "Example.TEST,WWW.EXAMPLE.TEST", "queued")
		otherID := seedJob(t, "lb_retire_variant", "other.example.test", "issued")

		// When
		err := retireCertJobsForDomain(db.DB, "lb_retire_variant", canonical, reversedACMEDomainForm(canonical))

		// Then：两条变体行均被退役，其他域行原样保留
		if err != nil {
			t.Fatalf("retire err=%v, want nil", err)
		}
		for _, id := range []int{variantID, caseID} {
			if status, _, _ := readJob(t, id); status != "disabled" {
				t.Fatalf("variant job %d status=%q, want disabled（变体行不得逃逸退役）", id, status)
			}
		}
		if status, domain, pem := readJob(t, otherID); status != "issued" || domain != "other.example.test" || pem != "PEM" {
			t.Fatalf("other-domain job=(%q,%q), want 不受影响", status, domain)
		}
	})

	t.Run("zero rows harmless", func(t *testing.T) {
		// Given：无任何匹配行（含表为空）
		initializeRuleFeatureTestDB(t)
		canonical := "absent.example.test"

		// When
		err := retireCertJobsForDomain(db.DB, "lb_retire_none", canonical, reversedACMEDomainForm(canonical))

		// Then：SQLite UPDATE 零行命中 → err=nil，无害无操作
		if err != nil {
			t.Fatalf("retire err=%v, want nil（零行命中须无害）", err)
		}
	})
}

// R50 S-5：域名迁移前必须先取消在途旧域签发——否则 worker 可能在迁移把行改写为
// 新域后仍完成签发，confirmCertificateDeployment 见到 job.domain==rule.domain
// （同为新域）便放行，把旧域证书部署到新域（瞬时 TLS 名称不匹配）。测试直接
// 观测取消回调触发时任务行仍是旧域（取消先于迁移 UPDATE）。
func TestUpdateRule_cancels_in_flight_job_before_domain_migration(t *testing.T) {
	// Given：一条 acme_dns 规则 + 旧域已签发任务
	harness := newUpdateAuditRuleHandlers(t, "lb_migrate_cancel", 0, false)
	seedAuditRule(t, "lb_migrate_cancel", "before", "mc-old.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_migrate_cancel")
	var providerID int
	if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
		t.Fatalf("read CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=1,ca_provider_id=? WHERE caddy_id='lb_migrate_cancel'", providerID); err != nil {
		t.Fatalf("set rule CA provider: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES
		('lb_migrate_cancel','mc-old.example.test','issued',?)`, providerID); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	var originalJobID int
	if err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id='lb_migrate_cancel'").Scan(&originalJobID); err != nil {
		t.Fatalf("read original job ID: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldCancel := cancelCertJob
	type cancelObservation struct {
		jobID          int
		domainAtCancel string
	}
	observed := make(chan cancelObservation, 4)
	cancelCertJob = func(jobID int) {
		var domain string
		_ = db.DB.QueryRow("SELECT domain FROM cert_jobs WHERE id=?", jobID).Scan(&domain)
		observed <- cancelObservation{jobID: jobID, domainAtCancel: domain}
	}
	t.Cleanup(func() { cancelCertJob = oldCancel })
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_migrate_cancel", strings.NewReader(`{"domain":"mc-new.example.test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：更新成功；迁移前恰好取消一次旧任务，且取消时刻任务行仍是旧域；
	// 迁移完成后该行为新域
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	select {
	case observation := <-observed:
		if observation.jobID != originalJobID {
			t.Fatalf("cancelled job=%d, want 在途旧域任务 %d", observation.jobID, originalJobID)
		}
		if observation.domainAtCancel != "mc-old.example.test" {
			t.Fatalf("取消时刻任务域名=%q, want 旧域 mc-old.example.test（取消必须先于迁移 UPDATE）", observation.domainAtCancel)
		}
	default:
		t.Fatal("域名迁移前未取消在途旧域任务")
	}
	select {
	case extra := <-observed:
		t.Fatalf("成功路径不应有第二次取消（job=%d）", extra.jobID)
	default:
	}
	var migratedDomain string
	if err := db.DB.QueryRow("SELECT domain FROM cert_jobs WHERE id=?", originalJobID).Scan(&migratedDomain); err != nil {
		t.Fatalf("read migrated job: %v", err)
	}
	if migratedDomain != "mc-new.example.test" {
		t.Fatalf("migrated job domain=%q, want mc-new.example.test", migratedDomain)
	}
}
