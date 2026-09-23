package db

import (
	"database/sql"
	"encoding/json"
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

// SetDefaultCAProvider persists the default CA provider ID in global_config.
func SetDefaultCAProvider(id int) error {
	res, err := DB.Exec(
		"UPDATE global_config SET default_ca_provider_id = ?, updated_at = datetime('now') WHERE id = 1",
		id,
	)
	if err != nil {
		return fmt.Errorf("set default CA provider: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check default CA provider update: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("global_config row not found")
	}
	return nil
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

// GetTrustedProxySettings 读取受信代理（CDN 回源）四设置；ranges/headers 为
// 有序 JSON 数组文本。读错返回零值+err——调用方（渲染层）必须 fail-closed。
func GetTrustedProxySettings() (enabled bool, ranges, headers []string, strict bool, err error) {
	var enabledInt, strictInt int
	var rangesJSON, headersJSON string
	err = DB.QueryRow(`SELECT trusted_proxy_enabled, trusted_proxy_ranges, trusted_proxy_headers, trusted_proxy_strict FROM global_config WHERE id = 1`).
		Scan(&enabledInt, &rangesJSON, &headersJSON, &strictInt)
	if err != nil {
		return false, nil, nil, false, fmt.Errorf("get trusted proxy settings: %w", err)
	}
	if err = json.Unmarshal([]byte(rangesJSON), &ranges); err != nil {
		return false, nil, nil, false, fmt.Errorf("decode trusted proxy ranges: %w", err)
	}
	if err = json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		return false, nil, nil, false, fmt.Errorf("decode trusted proxy headers: %w", err)
	}
	return enabledInt != 0, ranges, headers, strictInt != 0, nil
}

// SetTrustedProxySettings 持久化受信代理四设置（列表字段 JSON 序列化）。
func SetTrustedProxySettings(enabled, strict bool, ranges, headers []string) error {
	rangesJSON, err := json.Marshal(ranges)
	if err != nil {
		return fmt.Errorf("encode trusted proxy ranges: %w", err)
	}
	headersJSON, err := json.Marshal(headers)
	if err != nil {
		return fmt.Errorf("encode trusted proxy headers: %w", err)
	}
	res, err := DB.Exec(
		`UPDATE global_config SET trusted_proxy_enabled = ?, trusted_proxy_ranges = ?, trusted_proxy_headers = ?, trusted_proxy_strict = ?, updated_at = datetime('now') WHERE id = 1`,
		enabled, string(rangesJSON), string(headersJSON), strict,
	)
	if err != nil {
		return fmt.Errorf("set trusted proxy settings: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check trusted proxy settings update: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("global_config row not found")
	}
	return nil
}
