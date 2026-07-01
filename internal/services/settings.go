package services

import (
	"fmt"

	"lazy-balancer-v2/internal/db"
)

// GetDefaultCAProvider returns the configured default CA provider ID, or 0 if unset.
func GetDefaultCAProvider() (int, error) {
	return db.GetDefaultCAProvider()
}

// ValidateDefaultCAProvider checks that the provider ID exists and is enabled.
// An ID of 0 is valid and means "use runtime fallback to first enabled provider".
func ValidateDefaultCAProvider(id int) error {
	if id == 0 {
		return nil
	}
	enabled, err := db.IsCAProviderEnabled(id)
	if err != nil {
		return fmt.Errorf("validate default CA provider: %w", err)
	}
	if !enabled {
		return fmt.Errorf("CA provider %d does not exist or is disabled", id)
	}
	return nil
}

// SetDefaultCAProvider validates and persists the default CA provider ID.
// Pass 0 to clear the explicit default (runtime will fall back to the first enabled provider).
func SetDefaultCAProvider(id int) error {
	if err := ValidateDefaultCAProvider(id); err != nil {
		return err
	}
	return db.SetDefaultCAProvider(id)
}
