package ownership

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const ownershipFileName = "acme_dns_ownership.json"

var fileMu sync.Mutex

type Record struct {
	Provider string `json:"provider"`
	Zone     string `json:"zone"`
	FQDN     string `json:"fqdn"`
	Value    string `json:"value"`
	RecordID string `json:"record_id"`
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
