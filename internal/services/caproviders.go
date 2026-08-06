package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

const (
	ProviderLetsEncrypt = "letsencrypt"
	ProviderZeroSSL     = "zerossl"

	// MaskedHMACKey is the sentinel value clients send for eab_hmac_key to
	// indicate that the existing stored HMAC key should be preserved.
	MaskedHMACKey = "__MASKED__"

	// Official directory URLs. These are fixed and not user-editable.
	LetsEncryptDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	ZeroSSLDirectoryURL     = "https://acme.zerossl.com/v2/DV90"
	caProviderColumns       = "id, name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled, created_at, updated_at"
)

type caProviderScanner interface {
	Scan(...any) error
}

func scanCAProvider(scanner caProviderScanner, provider *models.CAProvider) error {
	var createdAt, updatedAt sql.NullTime
	if err := scanner.Scan(&provider.ID, &provider.Name, &provider.Provider, &provider.DirectoryURL, &provider.Credentials, &provider.MaxConcurrent, &provider.MinIntervalMS, &provider.Enabled, &createdAt, &updatedAt); err != nil {
		return err
	}
	if createdAt.Valid {
		provider.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		provider.UpdatedAt = updatedAt.Time
	}
	return nil
}

// CAProviderListItem is a credential-safe view of a CA provider for list endpoints.
type CAProviderListItem struct {
	ID            int       `json:"id"`
	Name          string    `json:"name"`
	Provider      string    `json:"provider"`
	DirectoryURL  string    `json:"directory_url"`
	Credentials   string    `json:"credentials"`
	MaxConcurrent int       `json:"max_concurrent"`
	MinIntervalMS int       `json:"min_interval_ms"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

// CAProviderService manages CA provider business logic.
type CAProviderService struct {
	dataDir string
}

// NewCAProviderService creates a new CAProviderService.
func NewCAProviderService(dataDir ...string) *CAProviderService {
	service := &CAProviderService{}
	if len(dataDir) > 0 {
		service.dataDir = dataDir[0]
	}
	return service
}

// maskCredentials masks the EAB HMAC key in a credentials JSON string.
// If the credentials are not valid JSON, it returns an empty object "{}".
func maskCredentials(credentials string) string {
	if credentials == "" {
		return ""
	}
	var credMap map[string]json.RawMessage
	if err := json.Unmarshal([]byte(credentials), &credMap); err != nil {
		log.Printf("warning: CA provider credentials are not valid JSON, masking as empty")
		return "{}"
	}
	if existing, ok := credMap["eab_hmac_key"]; ok && string(existing) != `""` {
		credMap["eab_hmac_key"] = json.RawMessage(`"` + MaskedHMACKey + `"`)
		masked, err := json.Marshal(credMap)
		if err != nil {
			log.Printf("warning: failed to marshal masked CA provider credentials, masking as empty")
			return "{}"
		}
		return string(masked)
	}
	return credentials
}

// ListCAProviders returns all CA providers with masked credentials.
func (s *CAProviderService) ListCAProviders() ([]CAProviderListItem, error) {
	rows, err := db.DB.Query("SELECT " + caProviderColumns + " FROM ca_providers ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]CAProviderListItem, 0)
	for rows.Next() {
		var provider models.CAProvider
		if err := scanCAProvider(rows, &provider); err != nil {
			return nil, err
		}
		p := CAProviderListItem{
			ID: provider.ID, Name: provider.Name, Provider: provider.Provider,
			DirectoryURL: provider.DirectoryURL, Credentials: maskCredentials(provider.Credentials),
			MaxConcurrent: provider.MaxConcurrent, MinIntervalMS: provider.MinIntervalMS,
			Enabled: provider.Enabled, CreatedAt: provider.CreatedAt, UpdatedAt: provider.UpdatedAt,
		}
		list = append(list, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

// GetCAProvider returns a CA provider by ID, including credentials.
// The EAB HMAC key in credentials is masked to limit credential exposure.
func (s *CAProviderService) GetCAProvider(id int) (models.CAProvider, error) {
	var p models.CAProvider
	err := scanCAProvider(db.DB.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=?", id), &p)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return p, ErrCAProviderNotFound
		}
		return p, err
	}
	if p.Credentials != "" {
		p.Credentials = maskCredentials(p.Credentials)
	}
	return p, nil
}

// ErrCAProviderNotFound is returned when a CA provider does not exist.
var ErrCAProviderNotFound = errors.New("CA provider not found")

// ErrCAProviderLastEnabled is returned when attempting to disable the only enabled CA provider.
var ErrCAProviderLastEnabled = errors.New("cannot disable the last enabled CA provider")

// ErrCAProviderInvalidProvider is returned when the provider type is unsupported.
var ErrCAProviderInvalidProvider = errors.New("provider must be letsencrypt or zerossl")

// ErrCAProviderInvalidName is returned when the provider name is empty.
var ErrCAProviderInvalidName = errors.New("name is required")

// ErrCAProviderNameTooLong is returned when the provider name exceeds 100 characters.
var ErrCAProviderNameTooLong = errors.New("name must be <= 100 characters")

// ErrCAProviderInvalidDirectoryURL is returned when the directory URL is not a valid HTTPS URL.
var ErrCAProviderInvalidDirectoryURL = errors.New("directory_url must be a valid HTTPS URL")

// ErrCAProviderDirectoryURLTooLong is returned when the directory URL exceeds 255 characters.
var ErrCAProviderDirectoryURLTooLong = errors.New("directory_url must be <= 255 characters")

// ErrCAProviderInvalidCredentials is returned when credentials are not valid JSON.
var ErrCAProviderInvalidCredentials = errors.New("credentials must be valid JSON")

// ErrCAProviderLetsEncryptCredentialsNotEmpty is returned when letsencrypt credentials are provided.
var ErrCAProviderLetsEncryptCredentialsNotEmpty = errors.New("letsencrypt credentials must be empty")

// ErrCAProviderMaxConcurrentTooHigh is returned when max_concurrent exceeds the allowed upper bound.
var ErrCAProviderMaxConcurrentTooHigh = errors.New("max_concurrent must be <= 100")

// ErrCAProviderMinIntervalTooHigh is returned when min_interval_ms exceeds the allowed upper bound.
var ErrCAProviderMinIntervalTooHigh = errors.New("min_interval_ms must be <= 60000")

// ErrCAProviderMaskedHMACNotAvailable is returned when the existing HMAC key cannot be determined for a masked update.
var ErrCAProviderMaskedHMACNotAvailable = errors.New("existing HMAC key is not available")

// UpdateCAProvider updates a CA provider. Returns ErrCAProviderNotFound if no rows were affected.
func (s *CAProviderService) UpdateCAProvider(id int, req models.UpdateCAProviderRequest) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existing models.CAProvider
	err = scanCAProvider(tx.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=?", id), &existing)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCAProviderNotFound
		}
		return err
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Provider != nil {
		existing.Provider = *req.Provider
	}
	if req.DirectoryURL != nil {
		existing.DirectoryURL = *req.DirectoryURL
	}
	originalCredentials := existing.Credentials
	if req.Credentials != nil {
		existing.Credentials = *req.Credentials
	}
	if req.MaxConcurrent != nil {
		existing.MaxConcurrent = *req.MaxConcurrent
	}
	if req.MinIntervalMS != nil {
		existing.MinIntervalMS = *req.MinIntervalMS
	}
	wasEnabled := existing.Enabled
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	if existing.Provider != ProviderLetsEncrypt && existing.Provider != ProviderZeroSSL {
		return ErrCAProviderInvalidProvider
	}
	if existing.Provider == ProviderLetsEncrypt {
		existing.DirectoryURL = LetsEncryptDirectoryURL
	} else {
		existing.DirectoryURL = ZeroSSLDirectoryURL
	}
	if existing.Name == "" {
		return ErrCAProviderInvalidName
	}
	if len(existing.Name) > 100 {
		return ErrCAProviderNameTooLong
	}

	var creds models.CAProviderCredentials
	if existing.Credentials != "" {
		if err := json.Unmarshal([]byte(existing.Credentials), &creds); err != nil {
			return ErrCAProviderInvalidCredentials
		}
	}
	if existing.Provider == ProviderLetsEncrypt {
		trimmed := strings.TrimSpace(existing.Credentials)
		if trimmed != "" && trimmed != "{}" {
			return ErrCAProviderLetsEncryptCredentialsNotEmpty
		}
	}

	if existing.MaxConcurrent <= 0 {
		existing.MaxConcurrent = 1
	}
	if existing.MaxConcurrent > 100 {
		return ErrCAProviderMaxConcurrentTooHigh
	}
	if existing.MinIntervalMS <= 0 {
		existing.MinIntervalMS = 1000
	}
	if existing.MinIntervalMS > 60000 {
		return ErrCAProviderMinIntervalTooHigh
	}

	if req.Enabled != nil && !*req.Enabled && wasEnabled {
		var enabledCount int
		err := tx.QueryRow(`
			SELECT COUNT(*) FROM ca_providers WHERE id != ? AND enabled=1
		`, id).Scan(&enabledCount)
		if err != nil {
			return err
		}
		if enabledCount == 0 {
			return ErrCAProviderLastEnabled
		}
	}

	if req.Credentials != nil && creds.EABHMACKey == MaskedHMACKey {
		if originalCredentials == "" {
			return ErrCAProviderMaskedHMACNotAvailable
		}
		var existingCreds models.CAProviderCredentials
		if err := json.Unmarshal([]byte(originalCredentials), &existingCreds); err != nil {
			return fmt.Errorf("%w: %w", ErrCAProviderInvalidCredentials, err)
		}
		if existingCreds.EABHMACKey == "" || existingCreds.EABHMACKey == MaskedHMACKey {
			return ErrCAProviderMaskedHMACNotAvailable
		}
		creds.EABHMACKey = existingCreds.EABHMACKey
		updated, err := json.Marshal(creds)
		if err != nil {
			return err
		}
		existing.Credentials = string(updated)
	}

	res, err := tx.Exec(`
		UPDATE ca_providers SET name=?, provider=?, directory_url=?, credentials=?, max_concurrent=?, min_interval_ms=?, enabled=?, updated_at=datetime('now')
		WHERE id=?
	`, existing.Name, existing.Provider, existing.DirectoryURL, existing.Credentials, existing.MaxConcurrent, existing.MinIntervalMS, existing.Enabled, id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrCAProviderNotFound
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// CAProviderTestError records a failure during the ACME test phase.
type CAProviderTestError struct {
	Phase string
	Err   error
}

func (e *CAProviderTestError) Error() string { return e.Err.Error() }
func (e *CAProviderTestError) Unwrap() error { return e.Err }

// AutoProvisionZeroSSLEAB fetches EAB credentials from the ZeroSSL API using
// the configured ACME email when the provider lacks them. Credentials are
// persisted to ca_providers.credentials for reuse.
func AutoProvisionZeroSSLEAB(ctx context.Context, provider *models.CAProvider) error {
	var creds models.CAProviderCredentials
	if provider.Credentials != "" {
		if err := json.Unmarshal([]byte(provider.Credentials), &creds); err != nil {
			return fmt.Errorf("parse existing credentials: %w", err)
		}
	}
	if creds.EABKID != "" && creds.EABHMACKey != "" {
		log.Printf("AutoProvisionZeroSSLEAB: provider %d already has EAB credentials, skipping", provider.ID)
		return nil
	}
	log.Printf("AutoProvisionZeroSSLEAB: provider %d missing EAB, auto-fetching", provider.ID)
	var acmeEmail string
	if err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(acme_email,'') FROM global_config WHERE id=1").Scan(&acmeEmail); err != nil {
		return fmt.Errorf("read acme email: %w", err)
	}
	if acmeEmail == "" {
		return fmt.Errorf("ACME email is required for ZeroSSL EAB auto-provision")
	}

	log.Printf("AutoProvisionZeroSSLEAB: fetching EAB from ZeroSSL API for email %s", maskEmail(acmeEmail))
	const zerosslEABURL = "https://api.zerossl.com/acme/eab-credentials-email"
	reqBody := strings.NewReader("email=" + strings.TrimSpace(acmeEmail))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, zerosslEABURL, reqBody)
	if err != nil {
		return fmt.Errorf("build zerossl EAB request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Round 35 B1: http.DefaultClient 无超时，ZeroSSL API 卡住会永久阻塞签发 worker。
	// 显式指定 30 秒超时兜底，与 ctx 取消形成双重保护。
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("call zerossl EAB API: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		Success    bool   `json:"success"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
		Error      string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("parse zerossl EAB response: %w", err)
	}
	if !body.Success || body.EABKID == "" || body.EABHMACKey == "" {
		reason := body.Error
		if reason == "" {
			reason = "empty credentials"
		}
		return fmt.Errorf("zerossl EAB auto-provision failed: %s", reason)
	}

	creds.EABKID = body.EABKID
	creds.EABHMACKey = body.EABHMACKey
	credsJSON, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("encode EAB credentials: %w", err)
	}
	result, err := db.DB.ExecContext(ctx,
		"UPDATE ca_providers SET credentials=? WHERE id=? AND (credentials='' OR credentials IS NULL OR credentials=?)",
		string(credsJSON), provider.ID, provider.Credentials)
	if err != nil {
		return fmt.Errorf("persist zerossl EAB: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		log.Printf("AutoProvisionZeroSSLEAB: provider %d credentials already set by concurrent worker, skipping persist", provider.ID)
	}
	provider.Credentials = string(credsJSON)
	log.Printf("AutoProvisionZeroSSLEAB: success, EAB persisted for provider %d (%s)", provider.ID, maskEmail(acmeEmail))
	return nil
}

// maskEmail 脱敏邮箱地址：保留首字符与域名，中间用 *** 替代。
// 例如：admin@example.com → a***@example.com
func maskEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "***"
	}
	if at <= 3 {
		return "***" + email[at:]
	}
	return string(email[:2]) + "***" + email[at:]
}

func (s *CAProviderService) TestCAProviderWithContext(ctx context.Context, id int) error {
	log.Printf("Testing CA provider %d", id)
	if err := ctx.Err(); err != nil {
		return err
	}

	var p models.CAProvider
	err := scanCAProvider(db.DB.QueryRowContext(ctx, "SELECT "+caProviderColumns+" FROM ca_providers WHERE id=? AND enabled=1", id), &p)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCAProviderNotFound
		}
		return err
	}

	var acmeEmail string
	if err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(acme_email,'') FROM global_config WHERE id=1").Scan(&acmeEmail); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &CAProviderTestError{Phase: "email", Err: errors.New("ACME email is not configured")}
		}
		return err
	}
	if acmeEmail == "" {
		return &CAProviderTestError{Phase: "email", Err: errors.New("ACME email is not configured")}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if p.Provider == ProviderZeroSSL {
		log.Printf("TestCAProvider: ensuring ZeroSSL EAB for provider %d", id)
		if err := AutoProvisionZeroSSLEAB(ctx, &p); err != nil {
			return &CAProviderTestError{Phase: "config", Err: fmt.Errorf("ZeroSSL EAB 自动获取失败: %w", err)}
		}
	}

	client, err := acme.NewClientForProvider(p, acmeEmail, s.dataDir)
	if err != nil {
		return &CAProviderTestError{Phase: "config", Err: err}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := client.RegisterAccount(ctx); err != nil {
		return &CAProviderTestError{Phase: "register", Err: err}
	}
	return nil
}
