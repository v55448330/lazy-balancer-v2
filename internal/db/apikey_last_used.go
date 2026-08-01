package db

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

var apiKeyLastUsed = struct {
	sync.Mutex
	dirty  map[int]struct{}
	cancel context.CancelFunc
	done   chan struct{}
}{dirty: make(map[int]struct{})}

func MarkAPIKeyUsed(keyID int) {
	apiKeyLastUsed.Lock()
	apiKeyLastUsed.dirty[keyID] = struct{}{}
	apiKeyLastUsed.Unlock()
}

func FlushAPIKeyLastUsed() error {
	apiKeyLastUsed.Lock()
	if len(apiKeyLastUsed.dirty) == 0 {
		apiKeyLastUsed.Unlock()
		return nil
	}
	ids := make([]int, 0, len(apiKeyLastUsed.dirty))
	for id := range apiKeyLastUsed.dirty {
		ids = append(ids, id)
	}
	apiKeyLastUsed.dirty = make(map[int]struct{})
	apiKeyLastUsed.Unlock()

	database := GetDB()
	if database == nil {
		restoreDirtyAPIKeys(ids)
		return nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for index, id := range ids {
		placeholders[index] = "?"
		args[index] = id
	}
	if _, err := database.Exec("UPDATE api_keys SET last_used=datetime('now') WHERE id IN ("+strings.Join(placeholders, ",")+")", args...); err != nil {
		restoreDirtyAPIKeys(ids)
		return fmt.Errorf("flush API key last_used: %w", err)
	}
	return nil
}

func restoreDirtyAPIKeys(ids []int) {
	apiKeyLastUsed.Lock()
	defer apiKeyLastUsed.Unlock()
	for _, id := range ids {
		apiKeyLastUsed.dirty[id] = struct{}{}
	}
}

func startAPIKeyLastUsedFlusher() {
	stopAPIKeyLastUsedFlusher()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	apiKeyLastUsed.Lock()
	apiKeyLastUsed.cancel = cancel
	apiKeyLastUsed.done = done
	apiKeyLastUsed.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		cleanupTicker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		defer cleanupTicker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := FlushAPIKeyLastUsed(); err != nil {
					logDBError("flush API key usage", err)
				}
			case <-cleanupTicker.C:
				if database := GetDB(); database != nil {
					if _, err := database.Exec("DELETE FROM revoked_jti WHERE expires_at<=datetime('now')"); err != nil {
						logDBError("cleanup revoked JWT IDs", err)
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func stopAPIKeyLastUsedFlusher() {
	apiKeyLastUsed.Lock()
	cancel, done := apiKeyLastUsed.cancel, apiKeyLastUsed.done
	apiKeyLastUsed.cancel = nil
	apiKeyLastUsed.done = nil
	apiKeyLastUsed.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
