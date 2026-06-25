package services

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services/dnsproviders"
)

// CaddyService handles Caddy configuration management
type CaddyService struct {
	adminURL     string
	client       *http.Client
	mu           sync.Mutex
	backupConfig map[string]interface{}
}

func NewCaddyService(adminURL string) *CaddyService {
	return &CaddyService{
		adminURL: adminURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GenerateCaddyID() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	id := make([]byte, 13)
	id[0] = 'l'
	id[1] = 'b'
	id[2] = '_'
	for i := 3; i < 13; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		id[i] = charset[idx.Int64()]
	}
	return string(id), nil
}

// BackupConfig stores the current Caddy configuration for potential rollback
func (s *CaddyService) BackupConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.GetConfig()
	if err != nil {
		log.Printf("Failed to backup Caddy config: %v", err)
		s.backupConfig = nil
		return nil
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		log.Printf("Failed to marshal backup config: %v", err)
		s.backupConfig = nil
		return nil
	}

	var backupConfig map[string]interface{}
	if err := json.Unmarshal(configBytes, &backupConfig); err != nil {
		log.Printf("Failed to unmarshal backup config: %v", err)
		s.backupConfig = nil
		return nil
	}

	s.backupConfig = backupConfig
	log.Printf("Caddy config backed up successfully")
	return nil
}

// Rollback restores the Caddy configuration to the previously backed up state
func (s *CaddyService) Rollback() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.backupConfig == nil {
		log.Printf("No backup config available for rollback")
		return fmt.Errorf("no backup config available for rollback")
	}

	log.Printf("Rolling back Caddy config to backup...")

	data, err := json.Marshal(s.backupConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal rollback config: %w", err)
	}

	resp, err := s.client.Post(s.adminURL+"/load", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to rollback config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rollback failed: %s", string(body))
	}

	log.Printf("Caddy config rolled back successfully")
	s.backupConfig = nil
	return nil
}

// ClearBackup clears the backup config after successful apply
func (s *CaddyService) ClearBackup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backupConfig = nil
}

// ApplyConfig pushes configuration to Caddy
func (s *CaddyService) ApplyConfig(config map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	resp, err := s.client.Post(s.adminURL+"/load", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to apply config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("config apply failed: %s", string(body))
	}

	log.Println("Caddy config applied successfully")
	return nil
}

// ValidateConfig validates Caddy configuration using the /load API with validate=true
func (s *CaddyService) ValidateConfig(config map[string]interface{}, uniqueID string) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	validateURL := s.adminURL + "/load?validate=true"
	resp, err := s.client.Post(validateURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("validation failed: %s", string(body))
	}

	return nil
}

// ValidateRouteMergedConfig simulates PrependRouteToServer and validates the merged full config
// This ensures the final merged config (existing routes + new route) is valid before any DB write
func (s *CaddyService) ValidateRouteMergedConfig(serverName string, routeConfig map[string]interface{}, uniqueID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fullConfig, err := s.GetConfig()
	if err != nil {
		// Server might not exist yet, which is fine - validation will be done on standalone config
		// Treat this as validation passing (will be validated again when actually created)
		return nil
	}

	apps, ok := fullConfig["apps"].(map[string]interface{})
	if !ok {
		return nil
	}
	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return nil
	}
	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return nil
	}

	server, ok := servers[serverName].(map[string]interface{})
	if !ok {
		// Server doesn't exist, so prepend won't cause merge issues
		return nil
	}

	routes, ok := server["routes"].([]interface{})
	if !ok {
		routes = []interface{}{}
	}

	// Find default route (keep it at the end)
	var defaultRoute interface{}
	newRoutes := make([]interface{}, 0, len(routes)+1)

	for i, r := range routes {
		if routeMap, ok := r.(map[string]interface{}); ok {
			handle, ok := routeMap["handle"].([]interface{})
			if ok && len(handle) > 0 {
				if h, ok := handle[0].(map[string]interface{}); ok {
					if h["handler"] == "static_response" && h["body"] == "Lazy Balancer V2 is running!" {
						if i == 0 {
							defaultRoute = r
							continue
						}
					}
				}
			}
		}
		newRoutes = append(newRoutes, r)
	}

	// Prepend the new route (same logic as PrependRouteToServer)
	newRoutes = append(newRoutes, routeConfig)

	if defaultRoute != nil {
		newRoutes = append(newRoutes, defaultRoute)
	}

	server["routes"] = newRoutes
	servers[serverName] = server
	httpApp["servers"] = servers
	apps["http"] = httpApp
	fullConfig["apps"] = apps

	// Validate the merged full config
	return s.validateConfigInternal(fullConfig, uniqueID)
}

// validateConfigInternal validates config using Caddy /load API with validate=true
func (s *CaddyService) validateConfigInternal(config map[string]interface{}, uniqueID string) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	validateURL := s.adminURL + "/load?validate=true"
	resp, err := s.client.Post(validateURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("validation failed: %s", string(body))
	}

	return nil
}

func (s *CaddyService) ValidateRouteConfig(serverName string, routeConfig map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(routeConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal route: %w", err)
	}

	path := fmt.Sprintf("/config/apps/http/servers/%s/routes", serverName)
	req, err := http.NewRequest("POST", s.adminURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("route validation failed: %s", string(body))
	}

	return nil
}

func (s *CaddyService) PatchConfigByID(id string, patch map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("failed to marshal patch: %w", err)
	}

	req, err := http.NewRequest("PATCH", s.adminURL+"/id/"+id, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to patch config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("patch failed: %s", string(body))
	}

	return nil
}

func (s *CaddyService) DeleteConfigByID(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := http.NewRequest("DELETE", s.adminURL+"/id/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed: %s", string(body))
	}

	return nil
}

func (s *CaddyService) DeleteServer(serverName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := fmt.Sprintf("/config/apps/http/servers/%s", serverName)
	req, err := http.NewRequest("DELETE", s.adminURL+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete server failed: %s", string(body))
	}

	return nil
}

func (s *CaddyService) SetConfigByID(id string, config map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	configResp, err := s.client.Get(s.adminURL + "/config/")
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}
	var fullConfig map[string]interface{}
	if err := json.NewDecoder(configResp.Body).Decode(&fullConfig); err != nil {
		configResp.Body.Close()
		return fmt.Errorf("failed to decode config: %w", err)
	}
	configResp.Body.Close()

	apps, ok := fullConfig["apps"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("apps not found")
	}
	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("http app not found")
	}
	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("servers not found")
	}

	replaced := false
	for serverName, serverData := range servers {
		server, ok := serverData.(map[string]interface{})
		if !ok {
			continue
		}
		routes, ok := server["routes"].([]interface{})
		if !ok {
			continue
		}

		newRoutes := make([]interface{}, 0, len(routes))

		for _, r := range routes {
			routeMap, ok := r.(map[string]interface{})
			if !ok {
				continue
			}

			existingID, hasID := routeMap["@id"].(string)

			if hasID && existingID == id {
				newRoutes = append(newRoutes, config)
				replaced = true
				continue
			}

			if hasID {
				newRoutes = append(newRoutes, r)
				continue
			}

			handle, ok := routeMap["handle"].([]interface{})
			if ok && len(handle) > 0 {
				if h, ok := handle[0].(map[string]interface{}); ok {
					if h["handler"] == "static_response" && h["body"] == "Lazy Balancer V2 is running!" {
						newRoutes = append(newRoutes, r)
						continue
					}
				}
			}
		}

		if replaced {
			server["routes"] = newRoutes
			servers[serverName] = server
		}
	}

	if !replaced {
		return fmt.Errorf("route with @id '%s' not found in config", id)
	}

	apps["http"] = httpApp
	fullConfig["apps"] = apps

	data, err := json.Marshal(fullConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	resp, err := s.client.Post(s.adminURL+"/config/", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to apply config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set config failed: %s", string(body))
	}

	return nil
}

func (s *CaddyService) GetConfigByID(id string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", s.adminURL+"/id/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get config failed: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

func (s *CaddyService) GetServerRoutes(serverName string) ([]interface{}, error) {
	config, err := s.GetConfig()
	if err != nil {
		return nil, err
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	server, ok := servers[serverName].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	routes, ok := server["routes"].([]interface{})
	if !ok {
		return nil, nil
	}

	return routes, nil
}

func (s *CaddyService) RouteExistsInServer(serverName string, routeID string) bool {
	routes, err := s.GetServerRoutes(serverName)
	if err != nil || routes == nil {
		return false
	}

	for _, r := range routes {
		if routeMap, ok := r.(map[string]interface{}); ok {
			if id, ok := routeMap["@id"].(string); ok && id == routeID {
				return true
			}
		}
	}
	return false
}

func (s *CaddyService) AddRouteToServer(serverName string, routeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("apps not found in config")
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("http app not found")
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("servers not found")
	}

	server, ok := servers[serverName].(map[string]interface{})
	if !ok {
		return fmt.Errorf("server %s not found", serverName)
	}

	routes, ok := server["routes"].([]interface{})
	if !ok {
		routes = []interface{}{}
	}

	for _, r := range routes {
		if routeMap, ok := r.(map[string]interface{}); ok {
			if existingID, ok := routeMap["@id"].(string); ok && existingID == routeID {
				return nil
			}
		}
	}

	routes = append(routes, map[string]interface{}{
		"@id": routeID,
	})

	server["routes"] = routes
	servers[serverName] = server
	httpApp["servers"] = servers
	apps["http"] = httpApp
	config["apps"] = apps

	return s.applyConfigRaw(config)
}

func (s *CaddyService) AddRouteToServerWithRoute(serverName string, routeConfig map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	port := getPortFromServerName(serverName)

	newServer := map[string]interface{}{
		"listen": []string{port},
		"routes": []interface{}{routeConfig},
	}

	data, err := json.Marshal(newServer)
	if err != nil {
		return fmt.Errorf("failed to marshal server config: %w", err)
	}

	path := fmt.Sprintf("/config/apps/http/servers/%s", serverName)
	req, err := http.NewRequest("POST", s.adminURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to add route to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add route failed: %s", string(body))
	}

	return nil
}

func (s *CaddyService) AppendRouteToServer(serverName string, routeConfig map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(routeConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal route config: %w", err)
	}

	path := fmt.Sprintf("/config/apps/http/servers/%s/routes", serverName)
	req, err := http.NewRequest("POST", s.adminURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to append route: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("append route failed: %s", string(body))
	}

	return nil
}

func (s *CaddyService) PrependRouteToServer(serverName string, routeConfig map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fullConfig, err := s.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get current config: %w", err)
	}

	apps, ok := fullConfig["apps"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("apps not found in config")
	}
	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("http app not found")
	}
	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("servers not found")
	}

	server, ok := servers[serverName].(map[string]interface{})
	if !ok {
		return fmt.Errorf("server %s not found", serverName)
	}

	routes, ok := server["routes"].([]interface{})
	if !ok {
		routes = []interface{}{}
	}

	var defaultRoute interface{}
	newRoutes := make([]interface{}, 0, len(routes)+1)

	for i, r := range routes {
		if routeMap, ok := r.(map[string]interface{}); ok {
			handle, ok := routeMap["handle"].([]interface{})
			if ok && len(handle) > 0 {
				if h, ok := handle[0].(map[string]interface{}); ok {
					if h["handler"] == "static_response" && h["body"] == "Lazy Balancer V2 is running!" {
						if i == 0 {
							defaultRoute = r
							continue
						}
					}
				}
			}
		}
		newRoutes = append(newRoutes, r)
	}

	newRoutes = append(newRoutes, routeConfig)

	if defaultRoute != nil {
		newRoutes = append(newRoutes, defaultRoute)
	}

	server["routes"] = newRoutes
	servers[serverName] = server
	httpApp["servers"] = servers
	apps["http"] = httpApp
	fullConfig["apps"] = apps

	data, err := json.Marshal(fullConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	resp, err := s.client.Post(s.adminURL+"/config/", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to apply config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("prepend route failed: %s", string(body))
	}

	return nil
}

// VerifyRouteExists checks if a route with the given @id exists in the Caddy config
func (s *CaddyService) VerifyRouteExists(caddyID string) error {
	config, err := s.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get config for verification: %w", err)
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("apps not found in config")
	}
	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("http app not found")
	}
	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("servers not found")
	}

	for _, server := range servers {
		serverMap, ok := server.(map[string]interface{})
		if !ok {
			continue
		}
		routes, ok := serverMap["routes"].([]interface{})
		if !ok {
			continue
		}
		for _, route := range routes {
			routeMap, ok := route.(map[string]interface{})
			if !ok {
				continue
			}
			if routeMap["@id"] == caddyID {
				return nil // Found the route
			}
		}
	}

	return fmt.Errorf("route with @id '%s' not found in Caddy config - write may have failed", caddyID)
}

func (s *CaddyService) ServerExists(serverName string) (bool, error) {
	config, err := s.GetConfig()
	if err != nil {
		return false, err
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return false, nil
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return false, nil
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return false, nil
	}

	_, ok = servers[serverName]
	return ok, nil
}

func (s *CaddyService) CreateServerIfNotExists(serverName string, listenPort int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	exists, _ := s.ServerExists(serverName)
	if exists {
		return nil
	}

	server := map[string]interface{}{
		"listen": []string{fmt.Sprintf(":%d", listenPort)},
		"routes": []interface{}{},
	}

	data, err := json.Marshal(server)
	if err != nil {
		return fmt.Errorf("failed to marshal server config: %w", err)
	}

	path := fmt.Sprintf("/config/apps/http/servers/%s", serverName)
	req, err := http.NewRequest("PUT", s.adminURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create server failed: %s", string(body))
	}

	return nil
}

// ApplyTLSCertificate configures TLS certificate for a server and domain
func (s *CaddyService) ApplyTLSCertificate(serverName string, caddyID string, domain string, certPEM string, keyPEM string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Add TLS certificate to apps.tls.certificates.load_pem
	certConfig := map[string]interface{}{
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
		"tags":     []string{caddyID},
	}

	certData, err := json.Marshal(certConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal cert config: %w", err)
	}

	// Try to append to existing load_pem array
	req, err := http.NewRequest("POST", s.adminURL+"/config/apps/tls/certificates/load_pem", bytes.NewReader(certData))
	if err != nil {
		return fmt.Errorf("failed to create cert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to apply TLS certificate: %w", err)
	}
	resp.Body.Close()

	// 2. Add tls_connection_policies to the server
	domainHosts := strings.Split(domain, ",")
	for i, d := range domainHosts {
		domainHosts[i] = strings.TrimSpace(d)
	}

	tlsPolicy := map[string]interface{}{
		"match": map[string]interface{}{
			"sni": domainHosts,
		},
		"certificate_selection": map[string]interface{}{
			"any_tag": []string{caddyID},
		},
	}

	policyData, err := json.Marshal(tlsPolicy)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS policy: %w", err)
	}

	req, err = http.NewRequest("POST", s.adminURL+fmt.Sprintf("/config/apps/http/servers/%s/tls_connection_policies", serverName), bytes.NewReader(policyData))
	if err != nil {
		return fmt.Errorf("failed to create policy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err = s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to apply TLS policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("apply TLS policy failed: %s", string(body))
	}

	return nil
}

func getPortFromServerName(serverName string) string {
	parts := strings.Split(serverName, "_")
	if len(parts) >= 2 {
		return parts[1]
	}
	return "80"
}

func (s *CaddyService) RemoveRouteFromServer(serverName string, routeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("apps not found in config")
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("http app not found")
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("servers not found")
	}

	server, ok := servers[serverName].(map[string]interface{})
	if !ok {
		return nil
	}

	routes, ok := server["routes"].([]interface{})
	if !ok {
		return nil
	}

	filteredRoutes := make([]interface{}, 0, len(routes))
	for _, r := range routes {
		routeMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		existingID, hasID := routeMap["@id"].(string)
		if hasID && existingID == routeID {
			continue
		}

		if !hasID {
			handle, ok := routeMap["handle"].([]interface{})
			if ok && len(handle) > 0 {
				if h, ok := handle[0].(map[string]interface{}); ok {
					if h["handler"] == "static_response" && h["body"] == "Lazy Balancer V2 is running!" {
						filteredRoutes = append(filteredRoutes, r)
						continue
					}
				}
			}
			continue
		}

		filteredRoutes = append(filteredRoutes, r)
	}

	server["routes"] = filteredRoutes
	servers[serverName] = server
	httpApp["servers"] = servers
	apps["http"] = httpApp
	config["apps"] = apps

	return s.applyConfigRaw(config)
}

func (s *CaddyService) DeleteRouteByID(serverName string, caddyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return nil
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return nil
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return nil
	}

	server, ok := servers[serverName].(map[string]interface{})
	if !ok {
		return nil
	}

	routes, ok := server["routes"].([]interface{})
	if !ok {
		return nil
	}

	filteredRoutes := make([]interface{}, 0, len(routes))
	for _, r := range routes {
		routeMap, ok := r.(map[string]interface{})
		if !ok {
			filteredRoutes = append(filteredRoutes, r)
			continue
		}

		if existingID, hasID := routeMap["@id"].(string); hasID && existingID == caddyID {
			continue
		}

		filteredRoutes = append(filteredRoutes, r)
	}

	server["routes"] = filteredRoutes
	servers[serverName] = server
	httpApp["servers"] = servers
	apps["http"] = httpApp
	config["apps"] = apps

	return s.applyConfigRaw(config)
}

func (s *CaddyService) CreateServerForRoute(serverName string, listenPort int, routeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("apps not found in config")
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		httpApp = make(map[string]interface{})
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		servers = make(map[string]interface{})
	}

	server := map[string]interface{}{
		"listen": []string{fmt.Sprintf(":%d", listenPort)},
		"routes": []interface{}{
			map[string]interface{}{
				"@id": routeID,
			},
		},
	}

	servers[serverName] = server
	httpApp["servers"] = servers
	apps["http"] = httpApp
	config["apps"] = apps

	return s.applyConfigRaw(config)
}

func (s *CaddyService) applyConfigRaw(config map[string]interface{}) error {
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	resp, err := s.client.Post(s.adminURL+"/config/", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to apply config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("config apply failed: %s", string(body))
	}

	return nil
}

// GetConfig gets current Caddy configuration
func (s *CaddyService) GetConfig() (map[string]interface{}, error) {
	resp, err := s.client.Get(s.adminURL + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

// GetUpstreamHealth returns health status of all upstreams from Caddy
func (s *CaddyService) GetUpstreamHealth() (map[string]map[string]bool, error) {
	healthStatus := make(map[string]map[string]bool)

	upstreamHealth := s.getUpstreamHealthFromMetrics()

	resp, err := s.client.Get(s.adminURL + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return healthStatus, nil
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return healthStatus, nil
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return healthStatus, nil
	}

	for serverName, serverVal := range servers {
		server, ok := serverVal.(map[string]interface{})
		if !ok {
			continue
		}

		routes, ok := server["routes"].([]interface{})
		if !ok {
			continue
		}

		for _, route := range routes {
			routeMap, ok := route.(map[string]interface{})
			if !ok {
				continue
			}

			handleGroups, ok := routeMap["handle"].([]interface{})
			if !ok {
				continue
			}

			for _, handleGroup := range handleGroups {
				handle, ok := handleGroup.(map[string]interface{})
				if !ok || handle["handler"] != "reverse_proxy" {
					continue
				}

				upstreams, ok := handle["upstreams"].([]interface{})
				if !ok {
					continue
				}

				healthStatus[serverName] = make(map[string]bool)
				for _, upstream := range upstreams {
					up, ok := upstream.(map[string]interface{})
					if !ok {
						continue
					}

					dial := up["dial"].(string)
					if len(upstreamHealth) > 0 {
						isHealthy := upstreamHealth[dial]
						healthStatus[serverName][dial] = isHealthy
					} else {
						healthStatus[serverName][dial] = true
					}
				}
			}
		}
	}

	return healthStatus, nil
}

// UpstreamHealthDetail contains detailed health information for an upstream
type UpstreamHealthDetail struct {
	Healthy     bool `json:"healthy"`
	Unknown     bool `json:"unknown"`
	NumRequests int  `json:"num_requests"`
	Fails       int  `json:"fails"`
}

// GetUpstreamHealthDetailed returns detailed health status of all upstreams from Caddy
func (s *CaddyService) GetUpstreamHealthDetailed() (map[string]map[string]*UpstreamHealthDetail, error) {
	healthStatus := make(map[string]map[string]*UpstreamHealthDetail)

	upstreamHealth := s.getUpstreamHealthFromMetrics()
	upstreamMetrics := s.getUpstreamMetrics()

	resp, err := s.client.Get(s.adminURL + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return healthStatus, nil
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return healthStatus, nil
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return healthStatus, nil
	}

	for serverName, serverVal := range servers {
		server, ok := serverVal.(map[string]interface{})
		if !ok {
			continue
		}

		routes, ok := server["routes"].([]interface{})
		if !ok {
			continue
		}

		for _, route := range routes {
			routeMap, ok := route.(map[string]interface{})
			if !ok {
				continue
			}

			handleGroups, ok := routeMap["handle"].([]interface{})
			if !ok {
				continue
			}

			for _, handleGroup := range handleGroups {
				handle, ok := handleGroup.(map[string]interface{})
				if !ok || handle["handler"] != "reverse_proxy" {
					continue
				}

				healthStatus[serverName] = make(map[string]*UpstreamHealthDetail)

				// Handle static upstreams (dial addresses)
				if upstreams, ok := handle["upstreams"].([]interface{}); ok {
					for _, upstream := range upstreams {
						up, ok := upstream.(map[string]interface{})
						if !ok {
							continue
						}

						dial, ok := up["dial"].(string)
						if !ok {
							continue
						}

						// Determine whether this rule uses active health checks.
						usesActive := false
						if hc, ok := handle["health_checks"].(map[string]interface{}); ok {
							if active, ok := hc["active"].(map[string]interface{}); ok && active != nil {
								usesActive = true
							}
						}

						detail := &UpstreamHealthDetail{}

						if metrics, ok := upstreamMetrics[dial]; ok {
							detail.NumRequests = metrics.NumRequests
							detail.Fails = metrics.Fails
						}

						if observedHealthy, ok := upstreamHealth[dial]; ok {
							if usesActive {
								// Active health check: Caddy's observed result is authoritative.
								detail.Healthy = observedHealthy
							} else {
								// Passive: if Caddy has not recorded any failures, treat as unknown
								// until real traffic tests it.
								if detail.Fails == 0 && detail.NumRequests == 0 {
									detail.Unknown = true
								} else {
									detail.Healthy = observedHealthy
								}
							}
						} else {
							// No observation from Caddy at all.
							detail.Unknown = true
						}

						healthStatus[serverName][dial] = detail
					}
				}

				// Handle dynamic upstreams (SRV/A record resolution)
				if dynamicUpstreams, ok := handle["dynamic_upstreams"].(map[string]interface{}); ok {
					name, _ := dynamicUpstreams["name"].(string)
					port, _ := dynamicUpstreams["port"].(string)
					if name != "" {
						dial := name + ":" + port
						usesActive := false
						if hc, ok := handle["health_checks"].(map[string]interface{}); ok {
							if active, ok := hc["active"].(map[string]interface{}); ok && active != nil {
								usesActive = true
							}
						}

						detail := &UpstreamHealthDetail{}

						if metrics, ok := upstreamMetrics[dial]; ok {
							detail.NumRequests = metrics.NumRequests
							detail.Fails = metrics.Fails
						}

						if observedHealthy, ok := upstreamHealth[dial]; ok {
							if usesActive {
								detail.Healthy = observedHealthy
							} else {
								if detail.Fails == 0 && detail.NumRequests == 0 {
									detail.Unknown = true
								} else {
									detail.Healthy = observedHealthy
								}
							}
						} else {
							detail.Unknown = true
						}

						healthStatus[serverName][dial] = detail
					}
				}
			}
		}
	}

	return healthStatus, nil
}

// upstreamMetric stores num_requests and fails for an upstream
type upstreamMetric struct {
	NumRequests int
	Fails       int
}

// getUpstreamMetrics fetches num_requests and fails from /reverse_proxy/upstreams
func (s *CaddyService) getUpstreamMetrics() map[string]*upstreamMetric {
	result := make(map[string]*upstreamMetric)

	resp, err := s.client.Get(s.adminURL + "/reverse_proxy/upstreams")
	if err != nil {
		log.Printf("Failed to get reverse_proxy/upstreams: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("reverse_proxy/upstreams returned status %d", resp.StatusCode)
		return result
	}

	var upstreams []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&upstreams); err != nil {
		log.Printf("Failed to decode reverse_proxy/upstreams: %v", err)
		return result
	}

	for _, up := range upstreams {
		dial, ok := up["dial"].(string)
		if !ok {
			continue
		}

		metric := &upstreamMetric{}

		if numReq, ok := up["num_requests"].(float64); ok {
			metric.NumRequests = int(numReq)
		}

		if fails, ok := up["fails"].(float64); ok {
			metric.Fails = int(fails)
		}

		result[dial] = metric
	}

	return result
}

func (s *CaddyService) getUpstreamHealthFromMetrics() map[string]bool {
	result := make(map[string]bool)

	resp, err := s.client.Get(s.adminURL + "/metrics")
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "caddy_reverse_proxy_upstreams_healthy{") {
			continue
		}

		upstream := ""

		upstreamStart := strings.Index(line, "upstream=\"")
		if upstreamStart >= 0 {
			upstreamEnd := strings.Index(line[upstreamStart+10:], "\"")
			if upstreamEnd > 0 {
				upstream = line[upstreamStart+10 : upstreamStart+10+upstreamEnd]
			}
		}

		spaceIdx := strings.LastIndex(line, " ")
		var isHealthy float64
		if spaceIdx > 0 {
			fmt.Sscanf(line[spaceIdx+1:], "%f", &isHealthy)
		}

		if upstream != "" {
			result[upstream] = isHealthy == 1
		}
	}

	log.Printf("Health metrics parsed: %v", result)
	return result
}

// GenerateCaddyConfig generates Caddy configuration from database
func GenerateCaddyConfig(cfg *config.Config) map[string]interface{} {
	type lbRule struct {
		CaddyID                       string
		Name                          string
		Protocol                      string
		Domain                        string
		ListenPort                    int
		Strategy                      string
		DynamicDNS                    bool
		EnableDnsServer               bool
		DnsServer                     string
		DnsFamily                     string
		HealthCheckPath               string
		HealthCheckInterval           int
		HealthCheckTimeout            int
		HealthCheckUnhealthyThreshold int
		HealthCheckHealthyThreshold   int
		EnableTLS                     bool
		TLSSource                     string
		ACMEConfigID                  int
		ACMEEmail                     string
		TLSCert                       string
		TLSKey                        string
		TLSAutoCert                   bool
		TLSEmail                      string
		TLSHTTPRedirect               bool
		Enabled                       bool
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		HostHeader                    string
	}

	type upstream struct {
		Host       string
		Port       int
		Weight     int
		Domain     string
		DynamicDNS bool
		Enabled    bool
		Protocol   string
	}

	type ruleWithUpstreams struct {
		rule      lbRule
		upstreams []upstream
	}

	// Load all enabled rules into memory first to avoid holding cursor while querying upstreams/global_config
	rows, err := db.DB.Query(`
		SELECT COALESCE(caddy_id,''), name, protocol, COALESCE(domain,''), listen_port, strategy,
		       IIF(dynamic_dns IN ('1',1),1,0), IIF(enable_dns_server IN ('1',1),1,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       COALESCE(health_check_timeout,5), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
		       IIF(enable_tls IN ('1',1),1,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       IIF(tls_auto_cert IN ('1',1),1,0), COALESCE(tls_email,''), IIF(tls_http_redirect IN ('1',1),1,0),
		       IIF(enabled IN ('1',1),1,0), IIF(enable_compress IN ('1',1),1,0), COALESCE(compress_types,'gzip'),
		       IIF(enable_active_health_check IN ('1',1),1,0), COALESCE(host_header,'')
		FROM lb_rules WHERE enabled = 1
	`)
	if err != nil {
		log.Printf("Failed to get rules: %v", err)
		return defaultCaddyConfig()
	}

	var allRules []ruleWithUpstreams
	for rows.Next() {
		var r lbRule
		err := rows.Scan(&r.CaddyID, &r.Name, &r.Protocol, &r.Domain, &r.ListenPort, &r.Strategy,
			&r.DynamicDNS, &r.EnableDnsServer, &r.DnsServer, &r.DnsFamily, &r.HealthCheckPath, &r.HealthCheckInterval,
			&r.HealthCheckTimeout, &r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
			&r.EnableTLS, &r.TLSSource, &r.ACMEConfigID, &r.TLSCert, &r.TLSKey, &r.TLSAutoCert, &r.TLSEmail,
			&r.TLSHTTPRedirect, &r.Enabled, &r.EnableCompress, &r.CompressTypes,
			&r.EnableActiveHealthCheck, &r.HostHeader)

		if err != nil {
			log.Printf("Failed to scan rule: %v", err)
			continue
		}

		if r.Strategy == "" {
			r.Strategy = "round_robin"
		}

		if !r.Enabled {
			continue
		}

		allRules = append(allRules, ruleWithUpstreams{rule: r})
	}
	rows.Close()

	// Load upstreams for each rule after closing rules cursor
	for i := range allRules {
		r := &allRules[i]
		upstreamRows, err := db.DB.Query(`
			SELECT host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http')
			FROM upstreams WHERE rule_id = ? AND enabled = 1
		`, r.rule.CaddyID)
		if err != nil {
			log.Printf("Failed to get upstreams for rule %s: %v", r.rule.CaddyID, err)
			continue
		}
		for upstreamRows.Next() {
			var u upstream
			upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
			r.upstreams = append(r.upstreams, u)
		}
		upstreamRows.Close()
	}

	// Filter out rules with no enabled upstreams
	var filteredRules []ruleWithUpstreams
	for _, ru := range allRules {
		if len(ru.upstreams) > 0 {
			filteredRules = append(filteredRules, ru)
		}
	}
	allRules = filteredRules

	var dnsProvider, letsencryptEmail, acmeEmail string
	var isMaster bool
	db.DB.QueryRow("SELECT COALESCE(dns_provider,''), COALESCE(letsencrypt_email,''), COALESCE(acme_email,''), is_master FROM global_config WHERE id = 1").Scan(&dnsProvider, &letsencryptEmail, &acmeEmail, &isMaster)

	servers := make(map[string]interface{})

	httpServersByPort := make(map[int][]ruleWithUpstreams)
	tcpServersByPort := make(map[int][]ruleWithUpstreams)

	for _, ru := range allRules {
		r := ru.rule
		ups := ru.upstreams

		var upstreamDial []string
		for _, u := range ups {
			if u.Enabled {
				upstreamDial = append(upstreamDial, fmt.Sprintf("%s:%d", u.Host, u.Port))
			}
		}

		if len(upstreamDial) == 0 {
			continue
		}

		upstreamList := make([]interface{}, len(upstreamDial))
		for i, dial := range upstreamDial {
			upstreamList[i] = map[string]interface{}{"dial": dial}
		}

		if r.Protocol == "http" {
			httpServersByPort[r.ListenPort] = append(httpServersByPort[r.ListenPort], ru)
		} else {
			tcpServersByPort[r.ListenPort] = append(tcpServersByPort[r.ListenPort], ru)
		}
	}

	for port, rules := range httpServersByPort {
		server := map[string]interface{}{
			"listen": []string{fmt.Sprintf(":%d", port)},
		}

		var routes []interface{}

		for _, ru := range rules {
			r := ru.rule
			ups := ru.upstreams

			ruleConfig := SingleRuleConfig{
				CaddyID:                 r.CaddyID,
				Protocol:                r.Protocol,
				Domain:                  r.Domain,
				ListenPort:              r.ListenPort,
				Strategy:                r.Strategy,
				DynamicDNS:              r.DynamicDNS,
				EnableDnsServer:         r.EnableDnsServer,
				DnsServer:               r.DnsServer,
				DnsFamily:               r.DnsFamily,
				HealthCheckPath:         r.HealthCheckPath,
				HealthCheckInterval:     r.HealthCheckInterval,
				HealthCheckTimeout:      r.HealthCheckTimeout,
				EnableTLS:               r.EnableTLS,
				TLSCert:                 r.TLSCert,
				TLSKey:                  r.TLSKey,
			TLSHTTPRedirect:         r.TLSHTTPRedirect,
			EnableCompress:          r.EnableCompress,
				CompressTypes:           r.CompressTypes,
				EnableActiveHealthCheck: r.EnableActiveHealthCheck,
				HostHeader:              r.HostHeader,
			}
			for _, u := range ups {
				if u.Enabled {
					weight := u.Weight
					if weight == 0 {
						weight = 1
					}
					protocol := u.Protocol
					if protocol == "" {
						protocol = "http"
					}
					ruleConfig.Upstreams = append(ruleConfig.Upstreams, UpstreamConfig{
						Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
					})
				}
			}

			if len(ruleConfig.Upstreams) == 0 {
				continue
			}

			route, err := GenerateRouteObject(ruleConfig)
			if err != nil {
				continue
			}
			routes = append(routes, route)

			if r.EnableTLS && r.TLSHTTPRedirect {
				domainHosts := strings.Split(r.Domain, ",")
				for i, d := range domainHosts {
					domainHosts[i] = strings.TrimSpace(d)
				}
				redirectRoute := map[string]interface{}{
					"match": []interface{}{
						map[string]interface{}{
							"host": domainHosts,
						},
					},
					"handle": []interface{}{
						map[string]interface{}{
							"handler":     "static_response",
							"status_code": 301,
							"headers": map[string]interface{}{
								"Location": []string{fmt.Sprintf("https://%s", r.Domain)},
							},
						},
					},
				}
				routes = append(routes, redirectRoute)
			}
		}

		server["routes"] = routes

		// Configure TLS for manual certificates
		var tlsPolicies []interface{}
		for _, ru := range rules {
			r := ru.rule
			if r.EnableTLS && !r.TLSAutoCert && r.TLSCert != "" && r.TLSKey != "" {
				domainHosts := strings.Split(r.Domain, ",")
				for i, d := range domainHosts {
					domainHosts[i] = strings.TrimSpace(d)
				}
				tlsPolicies = append(tlsPolicies, map[string]interface{}{
					"match": map[string]interface{}{
						"sni": domainHosts,
					},
					"certificate_selection": map[string]interface{}{
						"any_tag": []string{r.CaddyID},
					},
				})
			}
		}
		if len(tlsPolicies) > 0 {
			server["tls_connection_policies"] = tlsPolicies
		}

		servers[fmt.Sprintf("http_%d", port)] = server
	}

	// Collect manual TLS certificates for all rules
	var tlsCertificates []map[string]interface{}
	for _, ru := range allRules {
		r := ru.rule
		if r.EnableTLS && !r.TLSAutoCert && r.TLSCert != "" && r.TLSKey != "" {
				tlsCertificates = append(tlsCertificates, map[string]interface{}{
					"certificate": r.TLSCert,
					"key":         r.TLSKey,
					"tags":        []string{r.CaddyID},
				})
		}
	}

	for port, rules := range tcpServersByPort {
		server := map[string]interface{}{
			"listen": []string{fmt.Sprintf(":%d", port)},
		}

		var upstreamDial []string
		var upstreamList []interface{}
		var hasHTTPSUpstream bool

		for _, ru := range rules {
			for _, u := range ru.upstreams {
				if u.Enabled {
					dial := fmt.Sprintf("%s:%d", u.Host, u.Port)
					upstreamDial = append(upstreamDial, dial)
					dialWithScheme := dial
					if u.Protocol == "https" {
						dialWithScheme = "https://" + dial
						hasHTTPSUpstream = true
					}
					upstreamList = append(upstreamList, map[string]interface{}{"dial": dialWithScheme})
				}
			}
		}

		if len(upstreamDial) == 0 {
			continue
		}

		var proxyTransport map[string]interface{}
		if hasHTTPSUpstream {
			proxyTransport = map[string]interface{}{
				"protocol": "http",
				"tls": map[string]interface{}{
					"insecure_skip_verify": true,
				},
			}
		}

		server["routes"] = []interface{}{
			map[string]interface{}{
				"handle": []interface{}{
					map[string]interface{}{
						"handler":   "reverse_proxy",
						"upstreams": upstreamList,
						"transport": proxyTransport,
					},
				},
			},
		}

		servers[fmt.Sprintf("tcp_%d", port)] = server
	}

	if len(servers) == 0 {
		servers = make(map[string]interface{})
	}

	defaultSite := map[string]interface{}{
		"listen": []string{":80"},
		"routes": []interface{}{
			map[string]interface{}{
				"handle": []interface{}{
					map[string]interface{}{
						"handler": "static_response",
						"body":    "Lazy Balancer V2 is running!",
					},
				},
			},
		},
	}

	if _, exists := servers["http_80"]; !exists {
		servers["http_80"] = defaultSite
	} else {
		server := servers["http_80"].(map[string]interface{})
		routes, ok := server["routes"].([]interface{})
		if !ok {
			routes = []interface{}{}
		}
		defaultRoute := map[string]interface{}{
			"handle": []interface{}{
				map[string]interface{}{
					"handler": "static_response",
					"body":    "Lazy Balancer V2 is running!",
				},
			},
		}
		routes = append(routes, defaultRoute)
		server["routes"] = routes
		servers["http_80"] = server
	}

	apps := map[string]interface{}{
		"http": map[string]interface{}{
			"metrics": map[string]interface{}{
				"per_host":               true,
				"observe_catchall_hosts": true,
			},
			"servers": servers,
		},
	}

	// Add TLS automation policies for ACME DNS challenge
	var automationRules []tlsAutomationRule
	for _, rwu := range allRules {
		automationRules = append(automationRules, tlsAutomationRule{
			EnableTLS:    rwu.rule.EnableTLS,
			TLSSource:    rwu.rule.TLSSource,
			ACMEConfigID: rwu.rule.ACMEConfigID,
			ACMEEmail:    rwu.rule.ACMEEmail,
			Domain:       rwu.rule.Domain,
		})
	}
	automationPolicies := buildTLSAutomationPolicies(automationRules, acmeEmail)
	if len(automationPolicies) > 0 || len(tlsCertificates) > 0 {
		tlsApp := map[string]interface{}{}
		if len(tlsCertificates) > 0 {
			tlsApp["certificates"] = map[string]interface{}{
				"load_pem": tlsCertificates,
			}
		}
		if len(automationPolicies) > 0 {
			tlsApp["automation"] = map[string]interface{}{
				"policies": automationPolicies,
			}
		}
		apps["tls"] = tlsApp
	}

	conf := map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": "0.0.0.0:2019",
		},
		"apps": apps,
	}

	conf["admin"] = map[string]interface{}{
		"listen": "0.0.0.0:2019",
	}

	return conf
}

func defaultCaddyConfig() map[string]interface{} {
	return map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": "0.0.0.0:2019",
		},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"metrics": map[string]interface{}{
					"per_host":               true,
					"observe_catchall_hosts": true,
				},
				"servers": map[string]interface{}{
					"http_80": map[string]interface{}{
						"listen": []string{":80"},
						"routes": []interface{}{
							map[string]interface{}{
								"handle": []interface{}{
									map[string]interface{}{
										"handler": "static_response",
										"body":    "Lazy Balancer V2 is running!",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func buildTLSAutomationPolicies(rules []tlsAutomationRule, acmeEmail string) []map[string]interface{} {
	policies := []map[string]interface{}{}
	for _, rule := range rules {
		if !rule.EnableTLS || rule.TLSSource != "acme_dns" || rule.ACMEConfigID == 0 {
			continue
		}

		var provider, credentials string
		err := db.DB.QueryRow("SELECT dns_provider, dns_credentials FROM certificate_configs WHERE id=? AND enabled=1", rule.ACMEConfigID).Scan(&provider, &credentials)
		if err != nil {
			log.Printf("Failed to load certificate config %d: %v", rule.ACMEConfigID, err)
			continue
		}

		p, ok := dnsproviders.Get(provider)
		if !ok {
			log.Printf("Unknown DNS provider %s for config %d", provider, rule.ACMEConfigID)
			continue
		}

		var creds map[string]string
		if err := json.Unmarshal([]byte(credentials), &creds); err != nil {
			log.Printf("Failed to unmarshal DNS credentials for config %d: %v", rule.ACMEConfigID, err)
			continue
		}
		providerJSON, err := p.BuildCredentialsJSON(creds)
		if err != nil {
			log.Printf("Failed to build DNS credentials JSON for config %d: %v", rule.ACMEConfigID, err)
			continue
		}

		for _, domain := range strings.Split(rule.Domain, ",") {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}

			providerCfg := map[string]interface{}{
				"name": p.Code(),
			}
			for k, v := range providerJSON {
				providerCfg[k] = v
			}

			email := rule.ACMEEmail
			if email == "" {
				email = acmeEmail
			}

			policies = append(policies, map[string]interface{}{
				"subjects": []string{domain},
				"issuers": []map[string]interface{}{
					{
						"module": "acme",
						"email":  email,
						"challenges": map[string]interface{}{
							"dns": map[string]interface{}{
								"provider":  providerCfg,
								"resolvers": []string{"119.29.29.29", "1.1.1.1"},
							},
						},
					},
				},
			})
		}
	}
	return policies
}

type tlsAutomationRule struct {
	EnableTLS    bool
	TLSSource    string
	ACMEConfigID int
	ACMEEmail    string
	Domain       string
}

type SingleRuleConfig struct {
	ID                      int
	CaddyID                 string
	Name                    string
	Protocol                string
	Domain                  string
	ListenPort              int
	Strategy                string
	DynamicDNS              bool
	EnableDnsServer         bool
	DnsServer               string
	DnsFamily               string
	HealthCheckPath         string
	HealthCheckInterval     int
	HealthCheckTimeout      int
	EnableTLS               bool
	TLSSource               string
	ACMEConfigID            int
	ACMEEmail               string
	TLSCert                 string
	TLSKey                  string
	TLSAutoCert             bool
	TLSEmail                string
	TLSHTTPRedirect         bool
	EnableCompress          bool
	CompressTypes           string
	EnableActiveHealthCheck bool
	HostHeader              string
	Upstreams               []UpstreamConfig
}

type UpstreamConfig struct {
	Host      string
	Port      int
	Weight    int
	Protocol  string
	Enabled   bool
	DnsServer string
}

func GenerateSingleRuleCaddyConfig(rule SingleRuleConfig) map[string]interface{} {
	if rule.Strategy == "" {
		rule.Strategy = "round_robin"
	}

	domainHosts := strings.Split(rule.Domain, ",")
	for i, d := range domainHosts {
		domainHosts[i] = strings.TrimSpace(d)
	}

	enabledUpstreams := make([]UpstreamConfig, 0)
	for _, u := range rule.Upstreams {
		if u.Enabled {
			enabledUpstreams = append(enabledUpstreams, u)
		}
	}

	if len(enabledUpstreams) == 0 {
		return map[string]interface{}{
			"error": "no enabled upstreams",
		}
	}

	servers := make(map[string]interface{})

	if rule.Protocol == "http" {
		var upstreamList []interface{}
		hasHTTPSUpstream := false

		for _, u := range enabledUpstreams {
			if rule.DynamicDNS {
				versions := map[string]bool{"ipv4": false, "ipv6": false}
				switch rule.DnsFamily {
				case "ipv4":
					versions["ipv4"] = true
				case "ipv6":
					versions["ipv6"] = true
				case "both":
					versions["ipv4"] = true
					versions["ipv6"] = true
				}
				upstreamEntry := map[string]interface{}{
					"source":   "a",
					"name":     u.Host,
					"port":     fmt.Sprintf("%d", u.Port),
					"versions": versions,
				}
				upstreamList = append(upstreamList, upstreamEntry)
			} else {
				dial := fmt.Sprintf("%s:%d", u.Host, u.Port)
				upstreamEntry := map[string]interface{}{"dial": dial}
				upstreamList = append(upstreamList, upstreamEntry)
			}

			if u.Protocol == "https" {
				hasHTTPSUpstream = true
			}
		}

		var handleChain []interface{}

		if rule.EnableCompress && rule.CompressTypes != "" {
			encodings := make(map[string]interface{})
			for _, ct := range splitAndTrim(rule.CompressTypes) {
				if ct == "gzip" || ct == "zstd" {
					encodings[ct] = map[string]interface{}{}
				}
			}
			if len(encodings) > 0 {
				handleChain = append(handleChain, map[string]interface{}{
					"handler":        "encode",
					"encodings":      encodings,
					"minimum_length": 512,
				})
			}
		}

		proxyConfig := map[string]interface{}{
			"handler": "reverse_proxy",
		}
		if rule.DynamicDNS && len(upstreamList) > 0 {
			proxyConfig["dynamic_upstreams"] = upstreamList[0]
		} else if !rule.DynamicDNS {
			proxyConfig["upstreams"] = upstreamList
		}

		if rule.Strategy != "" {
			proxyConfig["load_balancing"] = map[string]interface{}{
				"selection_policy": map[string]interface{}{
					"policy": rule.Strategy,
				},
			}
		}

		if true { // HTTP protocol always supports health checks
			healthChecks := map[string]interface{}{
				"passive": map[string]interface{}{
					"fail_duration": fmt.Sprintf("%ds", rule.HealthCheckInterval*3),
					"max_fails":     3,
				},
			}

			if rule.EnableActiveHealthCheck && rule.HealthCheckPath != "" {
				healthChecks["active"] = map[string]interface{}{
					"uri":      rule.HealthCheckPath,
					"timeout":  fmt.Sprintf("%ds", rule.HealthCheckTimeout),
					"interval": fmt.Sprintf("%ds", rule.HealthCheckInterval),
				}
			}

			proxyConfig["health_checks"] = healthChecks
		}

		needsTransport := hasHTTPSUpstream || rule.EnableDnsServer
		if needsTransport {
			transportConfig := map[string]interface{}{
				"protocol": "http",
			}
			if hasHTTPSUpstream {
				transportConfig["tls"] = map[string]interface{}{
					"insecure_skip_verify": true,
					"server_name":          rule.HostHeader,
				}
			}
			if rule.EnableDnsServer && rule.DnsServer != "" {
				transportConfig["resolver"] = map[string]interface{}{
					"addresses": []string{rule.DnsServer},
				}
				if rule.HealthCheckTimeout > 0 {
					transportConfig["dial_timeout"] = fmt.Sprintf("%ds", rule.HealthCheckTimeout)
				}
			}
			proxyConfig["transport"] = transportConfig
		}

		if rule.HostHeader != "" {
			proxyConfig["headers"] = map[string]interface{}{
				"request": map[string]interface{}{
					"set": map[string]interface{}{
						"Host": []string{rule.HostHeader},
					},
				},
			}
		}

		handleChain = append(handleChain, proxyConfig)

		var routes []interface{}
		route := map[string]interface{}{
			"match": []interface{}{
				map[string]interface{}{
					"host": domainHosts,
				},
			},
			"handle": handleChain,
		}
		if rule.CaddyID != "" {
			route["@id"] = rule.CaddyID
		}
		routes = append(routes, route)

		if rule.EnableTLS && rule.TLSHTTPRedirect {
			redirectRoute := map[string]interface{}{
				"match": []interface{}{
					map[string]interface{}{
						"host": domainHosts,
					},
				},
				"handle": []interface{}{
					map[string]interface{}{
						"handler":     "static_response",
						"status_code": 301,
						"headers": map[string]interface{}{
							"Location": []string{fmt.Sprintf("https://%s", rule.Domain)},
						},
					},
				},
			}
			routes = append(routes, redirectRoute)
		}

		serverName := fmt.Sprintf("http_%d", rule.ListenPort)
		if rule.EnableTLS {
			serverName = fmt.Sprintf("https_%d", rule.ListenPort)
		}

		server := map[string]interface{}{
			"listen": []string{fmt.Sprintf(":%d", rule.ListenPort)},
			"routes": routes,
		}

		// Add TLS configuration for manual certificates
		if rule.EnableTLS && !rule.TLSAutoCert && rule.TLSCert != "" && rule.TLSKey != "" {
			server["tls_connection_policies"] = []interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"sni": domainHosts,
					},
					"certificate_selection": map[string]interface{}{
						"any_tag": []string{rule.CaddyID},
					},
				},
			}
		}

		servers[serverName] = server
	} else {
		var upstreamList []interface{}
		hasHTTPSUpstream := false

		for _, u := range enabledUpstreams {
			dial := fmt.Sprintf("%s:%d", u.Host, u.Port)
			dialWithScheme := dial
			if u.Protocol == "https" {
				dialWithScheme = "https://" + dial
				hasHTTPSUpstream = true
			}
			upstreamList = append(upstreamList, map[string]interface{}{"dial": dialWithScheme})
		}

		var proxyTransport map[string]interface{}
		if hasHTTPSUpstream {
			proxyTransport = map[string]interface{}{
				"protocol": "http",
				"tls": map[string]interface{}{
					"insecure_skip_verify": true,
				},
			}
		}

		server := map[string]interface{}{
			"listen": []string{fmt.Sprintf(":%d", rule.ListenPort)},
			"routes": []interface{}{
				map[string]interface{}{
					"handle": []interface{}{
						map[string]interface{}{
							"handler":   "reverse_proxy",
							"upstreams": upstreamList,
							"transport": proxyTransport,
						},
					},
				},
			},
		}

		servers[fmt.Sprintf("tcp_%d", rule.ListenPort)] = server
	}

	apps := map[string]interface{}{
		"http": map[string]interface{}{
			"servers": servers,
		},
	}

	// Add TLS certificates configuration for manual certificates
	if rule.EnableTLS && !rule.TLSAutoCert && rule.TLSCert != "" && rule.TLSKey != "" {
		apps["tls"] = map[string]interface{}{
			"certificates": map[string]interface{}{
				"load_pem": []map[string]interface{}{
					{
						"certificate": rule.TLSCert,
						"key":         rule.TLSKey,
						"tags":        []string{rule.CaddyID},
					},
				},
			},
		}
	}

	conf := map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": "0.0.0.0:2019",
		},
		"apps": apps,
	}

	return conf
}

// GenerateRouteObject generates a Caddy route object (not full config) for a single rule
// This is used for @id-based incremental updates via SetConfigByID/PatchConfigByID
func GenerateRouteObject(rule SingleRuleConfig) (map[string]interface{}, error) {
	if rule.Strategy == "" {
		rule.Strategy = "round_robin"
	}

	enabledUpstreams := make([]UpstreamConfig, 0)
	for _, u := range rule.Upstreams {
		if u.Enabled {
			enabledUpstreams = append(enabledUpstreams, u)
		}
	}

	if len(enabledUpstreams) == 0 {
		return nil, fmt.Errorf("no enabled upstreams")
	}

	if rule.Protocol != "http" && rule.Protocol != "https" && rule.Protocol != "tcp" {
		return nil, fmt.Errorf("unsupported protocol: %s", rule.Protocol)
	}

	var handleChain []interface{}

	if rule.Protocol == "http" || rule.Protocol == "https" {
		hasHTTPSUpstream := false
		upstreamList := make([]interface{}, 0)

		for _, u := range enabledUpstreams {
			if rule.DynamicDNS {
				versions := map[string]bool{"ipv4": false, "ipv6": false}
				switch rule.DnsFamily {
				case "ipv4":
					versions["ipv4"] = true
				case "ipv6":
					versions["ipv6"] = true
				case "both":
					versions["ipv4"] = true
					versions["ipv6"] = true
				}
				upstreamEntry := map[string]interface{}{
					"source":   "a",
					"name":     u.Host,
					"port":     fmt.Sprintf("%d", u.Port),
					"versions": versions,
				}
				upstreamList = append(upstreamList, upstreamEntry)
			} else {
				dial := fmt.Sprintf("%s:%d", u.Host, u.Port)
				upstreamEntry := map[string]interface{}{"dial": dial}
				upstreamList = append(upstreamList, upstreamEntry)
			}

			if u.Protocol == "https" {
				hasHTTPSUpstream = true
			}
		}

		if rule.EnableCompress && rule.CompressTypes != "" {
			encodings := make(map[string]interface{})
			for _, ct := range splitAndTrim(rule.CompressTypes) {
				if ct == "gzip" || ct == "zstd" {
					encodings[ct] = map[string]interface{}{}
				}
			}
			if len(encodings) > 0 {
				handleChain = append(handleChain, map[string]interface{}{
					"handler":        "encode",
					"encodings":      encodings,
					"minimum_length": 512,
				})
			}
		}

		proxyConfig := map[string]interface{}{
			"handler": "reverse_proxy",
		}
		if rule.DynamicDNS && len(upstreamList) > 0 {
			proxyConfig["dynamic_upstreams"] = upstreamList[0]
		} else if !rule.DynamicDNS {
			proxyConfig["upstreams"] = upstreamList
		}

		if rule.Strategy != "" {
			proxyConfig["load_balancing"] = map[string]interface{}{
				"selection_policy": map[string]interface{}{
					"policy": rule.Strategy,
				},
			}
		}

		if rule.Protocol == "http" {
			healthChecks := map[string]interface{}{
				"passive": map[string]interface{}{
					"fail_duration": fmt.Sprintf("%ds", rule.HealthCheckInterval*3),
					"max_fails":     3,
				},
			}

			if rule.EnableActiveHealthCheck && rule.HealthCheckPath != "" {
				healthChecks["active"] = map[string]interface{}{
					"uri":      rule.HealthCheckPath,
					"timeout":  fmt.Sprintf("%ds", rule.HealthCheckTimeout),
					"interval": fmt.Sprintf("%ds", rule.HealthCheckInterval),
				}
			}

			proxyConfig["health_checks"] = healthChecks
		}

		needsTransport := hasHTTPSUpstream || rule.EnableDnsServer
		if needsTransport {
			transportConfig := map[string]interface{}{
				"protocol": "http",
			}
			if hasHTTPSUpstream {
				transportConfig["tls"] = map[string]interface{}{
					"insecure_skip_verify": true,
					"server_name":          rule.HostHeader,
				}
			}
			if rule.EnableDnsServer && rule.DnsServer != "" {
				transportConfig["resolver"] = map[string]interface{}{
					"addresses": []string{rule.DnsServer},
				}
				if rule.HealthCheckTimeout > 0 {
					transportConfig["dial_timeout"] = fmt.Sprintf("%ds", rule.HealthCheckTimeout)
				}
			}
			proxyConfig["transport"] = transportConfig
		}

		if rule.HostHeader != "" {
			proxyConfig["headers"] = map[string]interface{}{
				"request": map[string]interface{}{
					"set": map[string]interface{}{
						"Host": []string{rule.HostHeader},
					},
				},
			}
		}

		handleChain = append(handleChain, proxyConfig)
	} else {
		// TCP protocol
		upstreamList := make([]interface{}, 0)
		hasHTTPSUpstream := false

		for _, u := range enabledUpstreams {
			dial := fmt.Sprintf("%s:%d", u.Host, u.Port)
			dialWithScheme := dial
			if u.Protocol == "https" {
				dialWithScheme = "https://" + dial
				hasHTTPSUpstream = true
			}
			upstreamList = append(upstreamList, map[string]interface{}{"dial": dialWithScheme})
		}

		var proxyTransport map[string]interface{}
		if hasHTTPSUpstream {
			proxyTransport = map[string]interface{}{
				"protocol": "http",
				"tls": map[string]interface{}{
					"insecure_skip_verify": true,
				},
			}
		}

		handleChain = append(handleChain, map[string]interface{}{
			"handler":   "reverse_proxy",
			"upstreams": upstreamList,
			"transport": proxyTransport,
		})
	}

	// Split domain by comma to support multiple domains
	domainHosts := strings.Split(rule.Domain, ",")
	for i, d := range domainHosts {
		domainHosts[i] = strings.TrimSpace(d)
	}

	route := map[string]interface{}{
		"match": []interface{}{
			map[string]interface{}{
				"host": domainHosts,
			},
		},
		"handle": handleChain,
	}

	// Set @id if CaddyID is provided
	if rule.CaddyID != "" {
		route["@id"] = rule.CaddyID
	}

	return route, nil
}
