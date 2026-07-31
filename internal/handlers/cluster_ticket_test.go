package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestRecordTicketLoginFailureAuditsSanitizedReasons(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	gin.SetMode(gin.TestMode)
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("POST", "/api/v1/auth/ticket-login", nil)
	const ticket = "secret-ticket-body"
	for _, reason := range []string{"invalid_request", "invalid_signature", "expired", "replay", "user_unavailable", "database_error"} {
		recordTicketLoginFailure(context, "alice", reason)
	}
	rows, err := db.AuditDB.Query("SELECT detail FROM audit_log WHERE resource='集群登录票据' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, ticket) {
			t.Fatalf("audit detail leaked ticket: %q", detail)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 6 {
		t.Fatalf("ticket failure audit count=%d, want 6", count)
	}
}
