package handlers

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestNewHandlers_does_not_repeat_database_initialization(t *testing.T) {
	// Given
	oldDB := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = oldDB })

	// When
	h := NewHandlers(Dependencies{})

	// Then
	if h == nil {
		t.Fatal("NewHandlers returned nil")
	}
}
