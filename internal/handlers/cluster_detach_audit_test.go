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

func detachedReportRouter(h *Handlers, nodeID int) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/cluster/nodes/report", func(c *gin.Context) {
		c.Set("cluster_node_id", nodeID)
		h.ReportClusterNode(c)
	})
	return router
}

func postDetachedReport(router *gin.Engine, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/report", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	return recorder
}

func detachedAuditDetails(t *testing.T) []string {
	t.Helper()
	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action='脱离' AND resource='集群节点' ORDER BY id`)
	if err != nil {
		t.Fatalf("query detach audits: %v", err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	return details
}

func seedDetachedNode(t *testing.T, id int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,is_approved) VALUES (?,?,?,?,?,1)`,
		id, "slave-detach", "slave", "10.9.9.9", 8000); err != nil {
		t.Fatalf("seed node: %v", err)
	}
}

func TestReportClusterNode_detachedFailureLeavesAuditTrail(t *testing.T) {
	t.Run("demoted master", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		seedDetachedNode(t, 7)
		recorder := postDetachedReport(detachedReportRouter(h, 7), `{"detached":true,"service_status":"ok"}`)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
		}
		details := detachedAuditDetails(t)
		if len(details) != 1 || !strings.Contains(details[0], "节点 7") || !strings.Contains(details[0], "重试被阻止") {
			t.Fatalf("audits=%v, want one blocked detach audit for node 7", details)
		}
	})

	t.Run("role lookup failure", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		h.clusterService = services.NewClusterService(closedTestDB(t), "")
		recorder := postDetachedReport(detachedReportRouter(h, 7), `{"detached":true,"service_status":"ok"}`)
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
		}
		details := detachedAuditDetails(t)
		if len(details) != 1 || !strings.Contains(details[0], "节点 7") || !strings.Contains(details[0], "失败") {
			t.Fatalf("audits=%v, want one failed detach audit for node 7", details)
		}
	})

	t.Run("delete failure", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		if _, err := db.DB.Exec(`DROP TABLE nodes`); err != nil {
			t.Fatalf("inject delete failure: %v", err)
		}
		recorder := postDetachedReport(detachedReportRouter(h, 7), `{"detached":true,"service_status":"ok"}`)
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
		}
		details := detachedAuditDetails(t)
		if len(details) != 1 || !strings.Contains(details[0], "节点 7") || !strings.Contains(details[0], "失败") {
			t.Fatalf("audits=%v, want one failed detach audit for node 7", details)
		}
	})
}

func TestReportClusterNode_detachedSuccessAndOrdinaryReportAuditScope(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedDetachedNode(t, 7)
	router := detachedReportRouter(h, 7)

	recorder := postDetachedReport(router, `{"detached":true,"service_status":"ok"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("detached status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if details := detachedAuditDetails(t); len(details) != 1 || !strings.Contains(details[0], "成功") {
		t.Fatalf("success audits=%v, want exactly one", details)
	}

	recorder = postDetachedReport(router, `{"detached":true,"service_status":"ok"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("idempotent detached status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if details := detachedAuditDetails(t); len(details) != 1 {
		t.Fatalf("idempotent detach duplicated audit: %v", details)
	}

	recorder = postDetachedReport(router, `{"service_status":"ok"}`)
	if recorder.Code == http.StatusInternalServerError {
		t.Fatalf("ordinary report setup failed unexpectedly: %s", recorder.Body.String())
	}
	if details := detachedAuditDetails(t); len(details) != 1 {
		t.Fatalf("ordinary report added detach audit: %v", details)
	}
}
