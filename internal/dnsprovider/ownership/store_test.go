package ownership

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
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

func TestStore_quarantines_undecodable_state_file(t *testing.T) {
	// Given: an undecodable ownership file (e.g. truncated by a crash) that
	// would otherwise brick every Add/MatchingValue/Remove
	store := newStore(t)
	corrupt := `{"version":1,"records":[{`
	if err := os.WriteFile(store.path, []byte(corrupt), 0600); err != nil {
		t.Fatalf("seed corrupt store: %v", err)
	}

	// When: the next operation needs the state
	fresh := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}
	if err := store.Add(fresh); err != nil {
		t.Fatalf("add after corruption: %v", err)
	}

	// Then: the corrupt bytes are preserved under .corrupt-* for inspection
	// and the state file was rewritten clean with only the new record
	quarantined, err := filepath.Glob(store.path + ".corrupt-*")
	if err != nil {
		t.Fatalf("glob quarantined files: %v", err)
	}
	if len(quarantined) != 1 {
		t.Fatalf("quarantined files=%v, want exactly one", quarantined)
	}
	original, err := os.ReadFile(quarantined[0])
	if err != nil {
		t.Fatalf("read quarantined file: %v", err)
	}
	if string(original) != corrupt {
		t.Fatalf("quarantined content=%q, want original corrupt bytes %q", original, corrupt)
	}
	records := readStoreRecords(t, store)
	if len(records) != 1 || records[0].RecordID != "200" {
		t.Fatalf("records=%+v, want fresh record 200 only", records)
	}
}

func TestStore_quarantines_unsupported_version_state_file(t *testing.T) {
	// Given: a state file written by a future binary (unknown version)
	store := newStore(t)
	if err := os.WriteFile(store.path, []byte(`{"version":2,"records":[]}`), 0600); err != nil {
		t.Fatalf("seed future-version store: %v", err)
	}

	// When: reads keep working and a later write republishes a clean file
	if _, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "alpha"); err != nil {
		t.Fatalf("matching after version mismatch: %v", err)
	}
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}); err != nil {
		t.Fatalf("add after version mismatch: %v", err)
	}

	// Then: the future-version file was quarantined, not silently reset
	quarantined, err := filepath.Glob(store.path + ".corrupt-*")
	if err != nil {
		t.Fatalf("glob quarantined files: %v", err)
	}
	if len(quarantined) != 1 {
		t.Fatalf("quarantined files=%v, want exactly one", quarantined)
	}
	if records := readStoreRecords(t, store); len(records) != 1 || records[0].RecordID != "200" {
		t.Fatalf("records=%+v, want fresh record 200 only", records)
	}
}

func TestStore_concurrent_stores_mixed_operations(t *testing.T) {
	// Given: two Store instances over the same file (writer plus a
	// restarted reader) and concurrent goroutines mixing Add / Remove /
	// MatchingValue; the package-level fileMu must serialize every access
	dir := t.TempDir()
	storeA, err := New(dir)
	if err != nil {
		t.Fatalf("create store A: %v", err)
	}
	storeB, err := New(dir)
	if err != nil {
		t.Fatalf("create store B: %v", err)
	}

	const goroutines = 8
	const iterations = 25
	fqdn := "_acme-challenge.example.com."
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			store := storeA
			if g%2 == 1 {
				store = storeB
			}
			for i := 0; i < iterations; i++ {
				record := Record{
					Provider:  "dnspod",
					Zone:      "example.com",
					FQDN:      fqdn,
					Value:     fmt.Sprintf("v-%d-%d", g, i),
					RecordID:  strconv.Itoa(g*1000 + i),
					CreatedAt: time.Now(),
				}
				if err := store.Add(record); err != nil {
					t.Errorf("goroutine %d add %d: %v", g, i, err)
					return
				}
				if i%2 == 0 {
					// Remove must receive the disk-round-tripped record (as
					// the providers do via MatchingValue): the local struct's
					// CreatedAt keeps nanosecond precision and would not
					// compare equal after the JSON round trip
					matching, err := store.MatchingValue("dnspod", "example.com", fqdn, record.Value)
					if err != nil {
						t.Errorf("goroutine %d matching %d: %v", g, i, err)
						return
					}
					found := false
					for _, candidate := range matching {
						if candidate.RecordID == record.RecordID {
							found = true
							if err := store.Remove(candidate); err != nil {
								t.Errorf("goroutine %d remove %d: %v", g, i, err)
								return
							}
						}
					}
					if !found {
						t.Errorf("goroutine %d: added record %d not visible to matching", g, i)
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()

	// Then: the final file decodes and holds exactly the never-removed
	// records — odd iterations of every goroutine, each exactly once
	records := readStoreRecords(t, storeA)
	got := make(map[string]int, len(records))
	for _, record := range records {
		got[record.RecordID]++
	}
	if len(records) != goroutines*(iterations/2) {
		t.Fatalf("records=%d, want %d", len(records), goroutines*(iterations/2))
	}
	for g := 0; g < goroutines; g++ {
		for i := 0; i < iterations; i++ {
			count := got[strconv.Itoa(g*1000+i)]
			if i%2 == 0 && count != 0 {
				t.Fatalf("removed record %d-%d still present %d time(s)", g, i, count)
			}
			if i%2 == 1 && count != 1 {
				t.Fatalf("record %d-%d present %d time(s), want exactly 1", g, i, count)
			}
		}
	}
}
