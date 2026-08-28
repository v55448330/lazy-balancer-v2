package ownership

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	return store
}

// writeRawStore persists a raw ownership file, simulating records written by
// an older binary (no value / created_at fields).
func writeRawStore(t *testing.T, store *Store, records []map[string]any) {
	t.Helper()
	payload := map[string]any{"version": 1, "records": records}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal raw store: %v", err)
	}
	if err := os.WriteFile(store.path, data, 0600); err != nil {
		t.Fatalf("write raw store: %v", err)
	}
}

func readStoreRecords(t *testing.T, store *Store) []Record {
	t.Helper()
	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	var current state
	if err := json.Unmarshal(data, &current); err != nil {
		t.Fatalf("decode store: %v", err)
	}
	return current.Records
}

func TestStore_MatchingValue_spares_concurrent_same_name_value(t *testing.T) {
	// Given: two concurrent issuances presented different values for the
	// same challenge name
	store := newStore(t)
	alpha := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}
	beta := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "beta", RecordID: "201"}
	if err := store.Add(alpha); err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	if err := store.Add(beta); err != nil {
		t.Fatalf("add beta: %v", err)
	}

	// When: the alpha issuance looks up the records it may clean
	matching, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "alpha")
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}

	// Then: only alpha's record is returned; beta's live record is spared
	if len(matching) != 1 {
		t.Fatalf("matching=%v, want only alpha", matching)
	}
	if matching[0].Value != "alpha" || matching[0].RecordID != "200" {
		t.Fatalf("matching[0]=%+v, want alpha/200", matching[0])
	}
}

func TestStore_MatchingValue_includes_legacy_entries_best_effort(t *testing.T) {
	// Given: a legacy file from before value tracking, plus a live record
	// with a known value
	store := newStore(t)
	writeRawStore(t, store, []map[string]any{
		{"provider": "dnspod", "zone": "example.com", "fqdn": "_acme-challenge.example.com.", "record_id": "100"},
	})
	live := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "beta", RecordID: "201"}
	if err := store.Add(live); err != nil {
		t.Fatalf("add live: %v", err)
	}

	// When
	matching, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "alpha")
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}

	// Then: the legacy entry (empty value) is included best-effort; the live
	// beta record is not
	if len(matching) != 1 {
		t.Fatalf("matching=%v, want legacy entry only", matching)
	}
	if matching[0].RecordID != "100" || matching[0].Value != "" {
		t.Fatalf("matching[0]=%+v, want legacy 100", matching[0])
	}
}

func TestStore_MatchingValue_includes_stale_but_spares_recent(t *testing.T) {
	// Given: a provably stale record (older than any live issuance budget),
	// a recent record of another value, and our own record
	store := newStore(t)
	stale := Record{
		Provider:  "dnspod",
		Zone:      "example.com",
		FQDN:      "_acme-challenge.example.com.",
		Value:     "abandoned-order",
		RecordID:  "100",
		CreatedAt: time.Now().Add(-(staleOwnershipAge + time.Minute)),
	}
	if err := store.Add(stale); err != nil {
		t.Fatalf("add stale: %v", err)
	}
	recent := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "beta", RecordID: "201"}
	if err := store.Add(recent); err != nil {
		t.Fatalf("add recent: %v", err)
	}
	mine := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "202"}
	if err := store.Add(mine); err != nil {
		t.Fatalf("add mine: %v", err)
	}

	// When
	matching, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "alpha")
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}

	// Then: mine and the stale record are cleanable; beta's recent record
	// may belong to a live concurrent challenge and is spared
	byID := make(map[string]bool)
	for _, record := range matching {
		byID[record.RecordID] = true
	}
	if !byID["202"] || !byID["100"] {
		t.Fatalf("matching IDs=%v, want 202 (mine) and 100 (stale)", byID)
	}
	if byID["201"] {
		t.Fatalf("matching IDs=%v, recent concurrent record 201 must be spared", byID)
	}
}

func TestStore_MatchingValue_empty_value_falls_back_to_name_match(t *testing.T) {
	// Given: two records with different values under the same name
	store := newStore(t)
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}); err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "beta", RecordID: "201"}); err != nil {
		t.Fatalf("add beta: %v", err)
	}

	// When: no value filter
	matching, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "")
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}

	// Then: legacy name-based semantics return both
	if len(matching) != 2 {
		t.Fatalf("matching=%v, want both records", matching)
	}
}

func TestStore_Add_timestamps_new_records(t *testing.T) {
	// Given
	store := newStore(t)
	record := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}

	// When
	if err := store.Add(record); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Then: new writes carry created_at so future staleness decisions work
	records := readStoreRecords(t, store)
	if len(records) != 1 || records[0].CreatedAt.IsZero() {
		t.Fatalf("records=%+v, want created_at persisted", records)
	}
}

func TestStore_Remove_missing_record_is_idempotent(t *testing.T) {
	// Given
	store := newStore(t)
	present := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}
	if err := store.Add(present); err != nil {
		t.Fatalf("add: %v", err)
	}
	neverAdded := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "ghost", RecordID: "999"}

	// When: cleanup deletes a record that is no longer tracked
	if err := store.Remove(neverAdded); err != nil {
		t.Fatalf("remove missing record: %v", err)
	}
	if err := store.Remove(neverAdded); err != nil {
		t.Fatalf("remove missing record twice: %v", err)
	}

	// Then: the file is unchanged and the present record survives
	records := readStoreRecords(t, store)
	if len(records) != 1 || records[0].RecordID != "200" {
		t.Fatalf("records=%+v, want only record 200", records)
	}
}

func TestStore_loads_legacy_file_without_value_fields(t *testing.T) {
	// Given: a file written by the previous format
	store := newStore(t)
	writeRawStore(t, store, []map[string]any{
		{"provider": "dnspod", "zone": "example.com", "fqdn": "_acme-challenge.example.com.", "record_id": "100"},
	})

	// When
	matching, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com.")
	if err != nil {
		t.Fatalf("matching: %v", err)
	}

	// Then
	if len(matching) != 1 || matching[0].RecordID != "100" || matching[0].Value != "" {
		t.Fatalf("matching=%+v, want legacy record 100", matching)
	}
}

func TestStore_ownership_file_name(t *testing.T) {
	// Given/When
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	// Then: stable file name so existing deployments keep their ownership data
	if store.path != filepath.Join(dir, ownershipFileName) {
		t.Fatalf("path=%s, want %s", store.path, filepath.Join(dir, ownershipFileName))
	}
}
