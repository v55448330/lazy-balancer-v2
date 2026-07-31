package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func issueClusterLoginTicket(t *testing.T, now time.Time) (*ClusterService, string) {
	t.Helper()
	service, database := newClusterTestService(t)
	clusterToken := "lb_cluster_login-ticket-secret"
	key := sha256.Sum256([]byte(clusterToken))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash) VALUES (7,'slave','10.0.0.7',8000,'online',1,?)`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	response, err := service.GenerateLoginTicket(context.Background(), models.ClusterLoginTicketClaims{UserID: 3, Username: "alice", Role: "admin", NodeID: 7}, now)
	if err != nil {
		t.Fatalf("generate ticket: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0,cluster_token=?,registration_id=7 WHERE id=1", clusterToken); err != nil {
		t.Fatal(err)
	}
	return service, response.Ticket
}

func TestClusterLoginTicketRejectsExpiredTicket(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	if _, err := service.ValidateLoginTicket(context.Background(), ticket, now.Add(61*time.Second)); !errors.Is(err, ErrInvalidLoginTicket) {
		t.Fatalf("expired ticket error=%v", err)
	}
}

func TestClusterLoginTicketRejectsInvalidSignature(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	parts := strings.Split(ticket, ".")
	if parts[1][0] == 'A' {
		parts[1] = "B" + parts[1][1:]
	} else {
		parts[1] = "A" + parts[1][1:]
	}
	if _, err := service.ValidateLoginTicket(context.Background(), strings.Join(parts, "."), now); !errors.Is(err, ErrInvalidLoginTicket) {
		t.Fatalf("invalid signature error=%v", err)
	}
}

func TestClusterLoginTicketRejectsReplay(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	if _, err := service.ValidateLoginTicket(context.Background(), ticket, now); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	if _, err := service.ValidateLoginTicket(context.Background(), ticket, now); !errors.Is(err, ErrInvalidLoginTicket) {
		t.Fatalf("replayed ticket error=%v", err)
	}
}
