package db

import (
	"database/sql"
	"fmt"
)

// GetDefaultCAProvider returns the configured default CA provider ID from global_config.
// Returns 0 if the value is NULL or the row does not exist.
func GetDefaultCAProvider() (int, error) {
	var id sql.NullInt64
	err := DB.QueryRow("SELECT default_ca_provider_id FROM global_config WHERE id = 1").Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("get default CA provider: %w", err)
	}
	if !id.Valid {
		return 0, nil
	}
	return int(id.Int64), nil
}

// IsCAProviderEnabled reports whether a CA provider with the given ID exists and is enabled.
func IsCAProviderEnabled(id int) (bool, error) {
	var enabled bool
	err := DB.QueryRow("SELECT enabled FROM ca_providers WHERE id = ?", id).Scan(&enabled)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check CA provider enabled: %w", err)
	}
	return enabled, nil
}
