package ownership

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const ownershipFileName = "acme_dns_ownership.json"

// staleOwnershipAge is the age beyond which an ownership entry can no longer
// belong to a live issuance: the CA queue caps execution at 60 minutes and the
// deferred cleanup window adds 2 more, so anything older is provably abandoned
// and may be removed by any later cleanup without endangering a concurrent
// challenge.
const staleOwnershipAge = 75 * time.Minute

var fileMu sync.Mutex

// Record is one owned DNS TXT record. Value and CreatedAt were added later;
// files written by older binaries decode with zero values and are handled as
// legacy entries (see MatchingValue).
type Record struct {
	Provider  string    `json:"provider"`
	Zone      string    `json:"zone"`
	FQDN      string    `json:"fqdn"`
	Value     string    `json:"value"`
	RecordID  string    `json:"record_id"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

type Store struct {
	path string
}

type state struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

func New(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("DNS ownership data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create DNS ownership directory: %w", err)
	}
	return &Store{path: filepath.Join(dataDir, ownershipFileName)}, nil
}

func (s *Store) Add(record Record) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return err
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now()
	}
	current.Records = append(current.Records, record)
	return s.save(current)
}

func (s *Store) Matching(provider, zone, fqdn string) ([]Record, error) {
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return nil, err
	}
	matching := make([]Record, 0)
	for _, record := range current.Records {
		if record.Provider == provider && record.Zone == zone && record.FQDN == fqdn {
			matching = append(matching, record)
		}
	}
	return matching, nil
}

// MatchingValue returns the name-matching records that a cleanup for one
// challenge value may remove: the record created with that value, legacy
// entries persisted before value tracking (empty Value, best-effort), and
// provably stale entries. A recent record of another value may belong to a
// live concurrent issuance and is spared. An empty value disables the value
// filter (legacy name-based matching).
func (s *Store) MatchingValue(provider, zone, fqdn, value string) ([]Record, error) {
	if value == "" {
		return s.Matching(provider, zone, fqdn)
	}
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	matching := make([]Record, 0)
	for _, record := range current.Records {
		if record.Provider != provider || record.Zone != zone || record.FQDN != fqdn {
			continue
		}
		legacy := record.Value == ""
		stale := !record.CreatedAt.IsZero() && now.Sub(record.CreatedAt) > staleOwnershipAge
		if record.Value == value || legacy || stale {
			matching = append(matching, record)
		}
	}
	return matching, nil
}

func (s *Store) Remove(removed Record) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return err
	}
	remaining := make([]Record, 0, len(current.Records))
	for _, record := range current.Records {
		if record != removed {
			remaining = append(remaining, record)
		}
	}
	current.Records = remaining
	return s.save(current)
}

func (s *Store) load() (state, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state{Version: 1}, nil
	}
	if err != nil {
		return state{}, fmt.Errorf("read DNS ownership: %w", err)
	}
	var current state
	if err := json.Unmarshal(data, &current); err != nil {
		return state{}, fmt.Errorf("decode DNS ownership: %w", err)
	}
	if current.Version != 1 {
		return state{}, fmt.Errorf("unsupported DNS ownership version %d", current.Version)
	}
	return current, nil
}

func (s *Store) save(current state) error {
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("encode DNS ownership: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write DNS ownership: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		removeErr := os.Remove(tmp)
		return fmt.Errorf("replace DNS ownership: %w", errors.Join(err, removeErr))
	}
	return nil
}
