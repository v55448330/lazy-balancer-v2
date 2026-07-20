package services

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
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

	if httpApp, ok := apps["http"].(map[string]interface{}); ok {
		if servers, ok := httpApp["servers"].(map[string]interface{}); ok {
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

						if _, exists := healthStatus[serverName]; !exists {
							healthStatus[serverName] = make(map[string]bool)
						}
						for _, upstream := range upstreams {
							up, ok := upstream.(map[string]interface{})
							if !ok {
								continue
							}

							dial, _ := up["dial"].(string)
							if dial == "" {
								continue
							}
							if observedHealthy, ok := upstreamHealth[dial]; ok {
								healthStatus[serverName][dial] = observedHealthy
							} else {
								// No metric observation yet; assume healthy so the UI does not
								// show everything as unknown while Caddy is still collecting.
								healthStatus[serverName][dial] = true
							}
						}
					}
				}
			}
		}
	}

	if layer4App, ok := apps["layer4"].(map[string]interface{}); ok {
		if servers, ok := layer4App["servers"].(map[string]interface{}); ok {
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
						if !ok || handle["handler"] != "proxy" {
							continue
						}
						upstreams, ok := handle["upstreams"].([]interface{})
						if !ok {
							continue
						}
						if _, exists := healthStatus[serverName]; !exists {
							healthStatus[serverName] = make(map[string]bool)
						}
						for _, upstream := range upstreams {
							up, ok := upstream.(map[string]interface{})
							if !ok {
								continue
							}
							dialList, ok := up["dial"].([]interface{})
							if !ok || len(dialList) == 0 {
								continue
							}
							dial, _ := dialList[0].(string)
							if dial == "" {
								continue
							}
							if observedHealthy, ok := upstreamHealth[dial]; ok {
								healthStatus[serverName][dial] = observedHealthy
							} else {
								// No metric observation yet; assume healthy.
								healthStatus[serverName][dial] = true
							}
						}
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

	if httpApp, ok := apps["http"].(map[string]interface{}); ok {
		if servers, ok := httpApp["servers"].(map[string]interface{}); ok {
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

						if _, exists := healthStatus[serverName]; !exists {
							healthStatus[serverName] = make(map[string]*UpstreamHealthDetail)
						}

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

								detail := &UpstreamHealthDetail{}

								if metrics, ok := upstreamMetrics[dial]; ok {
									detail.NumRequests = metrics.NumRequests
									detail.Fails = metrics.Fails
								}

								if observedHealthy, ok := upstreamHealth[dial]; ok {
									// Caddy reports a definitive health status for this upstream.
									detail.Healthy = observedHealthy
								} else if detail.Fails > 0 {
									// Passive health observed failures.
									detail.Healthy = false
								} else {
									// No observation from Caddy at all.
									detail.Unknown = true
								}

								if detail.Unknown {
									// Avoid showing "unknown" as the default for healthy-looking upstreams:
									// if there are no failures and the upstream is configured, treat it as
									// healthy until Caddy reports otherwise.
									detail.Unknown = false
									detail.Healthy = true
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

								detail := &UpstreamHealthDetail{}

								if metrics, ok := upstreamMetrics[dial]; ok {
									detail.NumRequests = metrics.NumRequests
									detail.Fails = metrics.Fails
								}

								if observedHealthy, ok := upstreamHealth[dial]; ok {
									detail.Healthy = observedHealthy
								} else if detail.Fails > 0 {
									detail.Healthy = false
								} else {
									detail.Unknown = true
								}

								if detail.Unknown {
									detail.Unknown = false
									detail.Healthy = true
								}

								healthStatus[serverName][dial] = detail
							}
						}
					}
				}
			}
		}
	}

	if layer4App, ok := apps["layer4"].(map[string]interface{}); ok {
		if servers, ok := layer4App["servers"].(map[string]interface{}); ok {
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
						if !ok || handle["handler"] != "proxy" {
							continue
						}
						upstreams, ok := handle["upstreams"].([]interface{})
						if !ok {
							continue
						}
						if _, exists := healthStatus[serverName]; !exists {
							healthStatus[serverName] = make(map[string]*UpstreamHealthDetail)
						}
						for _, upstream := range upstreams {
							up, ok := upstream.(map[string]interface{})
							if !ok {
								continue
							}
							dialList, ok := up["dial"].([]interface{})
							if !ok || len(dialList) == 0 {
								continue
							}
							dial, _ := dialList[0].(string)
							if dial == "" {
								continue
							}
							detail := &UpstreamHealthDetail{}
							if metrics, ok := upstreamMetrics[dial]; ok {
								detail.NumRequests = metrics.NumRequests
								detail.Fails = metrics.Fails
							}
							if observedHealthy, ok := upstreamHealth[dial]; ok {
								detail.Healthy = observedHealthy
							} else if detail.Fails > 0 {
								detail.Healthy = false
							} else {
								detail.Unknown = true
							}
							healthStatus[serverName][dial] = detail
						}
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
		// Caddy uses "address" for the upstream key in this endpoint.
		key, ok := up["address"].(string)
		if !ok {
			key, ok = up["dial"].(string)
		}
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

		result[key] = metric
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
		if strings.HasPrefix(line, "caddy_reverse_proxy_upstreams_healthy{") || strings.HasPrefix(line, "caddy_layer4_proxy_upstream_healthy{") {
			upstream := extractMetricLabel(line, "upstream")
			spaceIdx := strings.LastIndex(line, " ")
			var isHealthy float64
			if spaceIdx > 0 {
				fmt.Sscanf(line[spaceIdx+1:], "%f", &isHealthy)
			}
			if upstream != "" {
				result[upstream] = isHealthy == 1
			}
		}
	}

	log.Printf("Health metrics parsed: %v", result)
	return result
}

func extractMetricLabel(metricName string, label string) string {
	idx := strings.Index(metricName, label+`="`)
	if idx == -1 {
		return ""
	}
	start := idx + len(label) + 2
	end := strings.Index(metricName[start:], `"`)
	if end == -1 {
		return ""
	}
	return metricName[start : start+end]
}

// GenerateCaddyConfig generates Caddy configuration from database
type caddyConfigStore interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
	Exec(string, ...any) (sql.Result, error)
}

func GenerateCaddyConfig(cfg *config.Config, overrides ...*models.UpdateConfigRequest) map[string]interface{} {
	return generateCaddyConfigFromStore(cfg, db.DB, overrides...)
}

func generateCaddyConfigFromStore(cfg *config.Config, store caddyConfigStore, overrides ...*models.UpdateConfigRequest) map[string]interface{} {
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
		TLSHTTPRedirect               bool
		Enabled                       bool
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		TCPHealthCheckPort            int
		TCPTryDuration                int
		TCPTryInterval                int
		RequestBodyMaxSizeMB          int
		UpstreamKeepaliveTimeout      int
		ServerTokensHidden            int
		HostHeader                    string
		LogEnabled                    bool
	}

	type upstream struct {
		Host           string
		Port           int
		Weight         int
		Domain         string
		DynamicDNS     bool
		Enabled        bool
		Protocol       string
		MaxConnections int
		ProxyProtocol  string
	}

	type ruleWithUpstreams struct {
		rule      lbRule
		upstreams []upstream
	}

	// Load all enabled rules into memory first to avoid holding cursor while querying upstreams/global_config
	rows, err := store.Query(`
		SELECT COALESCE(caddy_id,''), name, protocol, COALESCE(domain,''), listen_port, strategy,
		       IIF(dynamic_dns IN ('1',1),1,0), IIF(enable_dns_server IN ('1',1),1,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       COALESCE(health_check_timeout,5), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
		       IIF(enable_tls IN ('1',1),1,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       IIF(tls_http_redirect IN ('1',1),1,0),
		       IIF(enabled IN ('1',1),1,0), IIF(enable_compress IN ('1',1),1,0), COALESCE(compress_types,'gzip'),
		       IIF(enable_active_health_check IN ('1',1),1,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		       COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0), COALESCE(host_header,''),
		       IIF(log_enabled IN ('1',1),1,0)
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
			&r.EnableTLS, &r.TLSSource, &r.ACMEConfigID, &r.TLSCert, &r.TLSKey,
			&r.TLSHTTPRedirect, &r.Enabled, &r.EnableCompress, &r.CompressTypes,
			&r.EnableActiveHealthCheck, &r.TCPHealthCheckPort, &r.TCPTryDuration, &r.TCPTryInterval,
			&r.RequestBodyMaxSizeMB, &r.UpstreamKeepaliveTimeout, &r.ServerTokensHidden, &r.HostHeader, &r.LogEnabled)

		if err != nil {
			log.Printf("Failed to scan rule: %v", err)
			continue
		}

		if r.Strategy == "" {
			r.Strategy = "weighted_round_robin"
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
		upstreamRows, err := store.Query(`
			SELECT host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(proxy_protocol,'')
			FROM upstreams WHERE rule_id = ? AND enabled = 1
		`, r.rule.CaddyID)
		if err != nil {
			log.Printf("Failed to get upstreams for rule %s: %v", r.rule.CaddyID, err)
			continue
		}
		for upstreamRows.Next() {
			var u upstream
			upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.ProxyProtocol)
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

	var dnsProvider, acmeEmail string
	var isMaster bool
	var caddyLogPath, caddyLogLevel string
	var caddyLogSizeMB int
	var accessLogJSON bool
	var accessLogFormat string
	var global struct {
		requestBodyMaxSizeMB, httpReadTimeout, httpWriteTimeout, httpIdleTimeout, upstreamKeepaliveTimeout int
		serverTokensHidden                                                                                 bool
	}
	if err := store.QueryRow(`
		SELECT COALESCE(dns_provider,''), COALESCE(acme_email,''), is_master,
		       COALESCE(caddy_log_path,'/app/logs/caddy.log'), COALESCE(caddy_log_level,'info'), COALESCE(caddy_log_size_mb,100),
		       COALESCE(request_body_max_size_mb,0), COALESCE(http_read_timeout,0), COALESCE(http_write_timeout,0),
		       COALESCE(http_idle_timeout,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,FALSE),
		       COALESCE(access_log_json,TRUE), COALESCE(access_log_format,'')
		FROM global_config WHERE id = 1
	`).Scan(&dnsProvider, &acmeEmail, &isMaster, &caddyLogPath, &caddyLogLevel, &caddyLogSizeMB,
		&global.requestBodyMaxSizeMB, &global.httpReadTimeout, &global.httpWriteTimeout, &global.httpIdleTimeout,
		&global.upstreamKeepaliveTimeout, &global.serverTokensHidden, &accessLogJSON, &accessLogFormat); err != nil {
		log.Printf("Failed to load global config, using zero defaults: %v", err)
	}

	if len(overrides) > 0 && overrides[0] != nil {
		o := overrides[0]
		if o.CaddyLogPath != nil {
			caddyLogPath = *o.CaddyLogPath
		}
		if o.CaddyLogLevel != nil {
			caddyLogLevel = *o.CaddyLogLevel
		}
		if o.CaddyLogSizeMB != nil {
			caddyLogSizeMB = *o.CaddyLogSizeMB
		}
		if o.RequestBodyMaxSizeMB != nil {
			global.requestBodyMaxSizeMB = *o.RequestBodyMaxSizeMB
		}
		if o.HTTPReadTimeout != nil {
			global.httpReadTimeout = *o.HTTPReadTimeout
		}
		if o.HTTPWriteTimeout != nil {
			global.httpWriteTimeout = *o.HTTPWriteTimeout
		}
		if o.HTTPIdleTimeout != nil {
			global.httpIdleTimeout = *o.HTTPIdleTimeout
		}
		if o.UpstreamKeepaliveTimeout != nil {
			global.upstreamKeepaliveTimeout = *o.UpstreamKeepaliveTimeout
		}
		if o.ServerTokensHidden != nil {
			global.serverTokensHidden = *o.ServerTokensHidden
		}
		if o.AccessLogJSON != nil {
			accessLogJSON = *o.AccessLogJSON
		}
		if o.AccessLogFormat != nil {
			accessLogFormat = *o.AccessLogFormat
		}
		if o.DNSProvider != nil {
			dnsProvider = *o.DNSProvider
		}
		if o.ACMEEmail != nil {
			acmeEmail = *o.ACMEEmail
		}
	}

	applyTimeouts := func(server map[string]interface{}) {
		if global.httpReadTimeout > 0 {
			server["read_timeout"] = fmt.Sprintf("%ds", global.httpReadTimeout)
		}
		if global.httpWriteTimeout > 0 {
			server["write_timeout"] = fmt.Sprintf("%ds", global.httpWriteTimeout)
		}
		if global.httpIdleTimeout > 0 {
			server["idle_timeout"] = fmt.Sprintf("%ds", global.httpIdleTimeout)
		}
	}

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
		applyTimeouts(server)

		var routes []interface{}

		for _, ru := range rules {
			r := ru.rule
			ups := ru.upstreams

			ruleConfig := SingleRuleConfig{
				CaddyID:                        r.CaddyID,
				Protocol:                       r.Protocol,
				Domain:                         r.Domain,
				ListenPort:                     r.ListenPort,
				Strategy:                       r.Strategy,
				DynamicDNS:                     r.DynamicDNS,
				EnableDnsServer:                r.EnableDnsServer,
				DnsServer:                      r.DnsServer,
				DnsFamily:                      r.DnsFamily,
				HealthCheckPath:                r.HealthCheckPath,
				HealthCheckInterval:            r.HealthCheckInterval,
				HealthCheckTimeout:             r.HealthCheckTimeout,
				HealthCheckUnhealthyThreshold:  r.HealthCheckUnhealthyThreshold,
				HealthCheckHealthyThreshold:    r.HealthCheckHealthyThreshold,
				EnableTLS:                      r.EnableTLS,
				TLSSource:                      r.TLSSource,
				ACMEConfigID:                   r.ACMEConfigID,
				ACMEEmail:                      r.ACMEEmail,
				TLSCert:                        r.TLSCert,
				TLSKey:                         r.TLSKey,
				TLSHTTPRedirect:                r.TLSHTTPRedirect,
				EnableCompress:                 r.EnableCompress,
				CompressTypes:                  r.CompressTypes,
				EnableActiveHealthCheck:        r.EnableActiveHealthCheck,
				HostHeader:                     r.HostHeader,
				RequestBodyMaxSizeMB:           r.RequestBodyMaxSizeMB,
				UpstreamKeepaliveTimeout:       r.UpstreamKeepaliveTimeout,
				ServerTokensHidden:             r.ServerTokensHidden,
				GlobalRequestBodyMaxSizeMB:     global.requestBodyMaxSizeMB,
				GlobalUpstreamKeepaliveTimeout: global.upstreamKeepaliveTimeout,
				GlobalServerTokensHidden:       global.serverTokensHidden,
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
		}

		server["routes"] = routes

		// Configure TLS for manual and ACME certificates
		var tlsPolicies []interface{}
		for _, ru := range rules {
			r := ru.rule
			if !r.EnableTLS {
				continue
			}
			hasCert := false
			if r.TLSSource == "manual" && r.TLSCert != "" && r.TLSKey != "" {
				hasCert = true
			} else if r.TLSSource == "acme_dns" {
				_, _, issued := loadACMECertificateFromStore(store, r.CaddyID, r.Domain)
				hasCert = issued
			}
			if hasCert {
				domainHosts := splitAndTrim(r.Domain)
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

		// Add HTTPS server automatic HTTPS disable marker when using non-standard ports to avoid Caddy auto redirect conflicts
		if port != 443 && port != 80 {
			server["automatic_https"] = map[string]interface{}{
				"disable": true,
			}
		}

		servers[fmt.Sprintf("http_%d", port)] = server
	}

	// Collect HTTP->HTTPS redirect routes from all TLS-enabled rules and place them on the HTTP (port 80) server.
	var redirectRoutes []interface{}
	for _, ru := range allRules {
		r := ru.rule
		if r.Protocol == "http" && r.EnableTLS && r.TLSHTTPRedirect {
			// Only redirect to HTTPS if the certificate is actually available.
			if r.TLSSource == "acme_dns" && !isACMECertIssuedFromStore(store, r.CaddyID, r.Domain) {
				continue
			}
			domainHosts := splitAndTrim(r.Domain)
			if len(domainHosts) > 0 {
				redirectRoutes = append(redirectRoutes, map[string]interface{}{
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
								"Location": []string{fmt.Sprintf("https://%s", domainHosts[0])},
							},
						},
					},
				})
			}
		}
	}

	// Collect TLS certificate file paths for all rules (manual + ACME from cert_jobs)
	var tlsCertFiles []map[string]interface{}
	for _, ru := range allRules {
		r := ru.rule
		if !r.EnableTLS {
			continue
		}
		certPath, keyPath := CertFilePaths(r.CaddyID)
		if r.TLSSource == "manual" && r.TLSCert != "" && r.TLSKey != "" {
			WriteCertFiles(r.CaddyID, r.TLSCert, r.TLSKey)
			tlsCertFiles = append(tlsCertFiles, map[string]interface{}{
				"certificate": certPath,
				"key":         keyPath,
				"tags":        []string{r.CaddyID},
			})
		} else if r.TLSSource == "acme_dns" {
			certPEM, keyPEM, issued := loadACMECertificateFromStore(store, r.CaddyID, r.Domain)
			if issued {
				WriteCertFiles(r.CaddyID, certPEM, keyPEM)
				tlsCertFiles = append(tlsCertFiles, map[string]interface{}{
					"certificate": certPath,
					"key":         keyPath,
					"tags":        []string{r.CaddyID},
				})
			}
		}
	}

	layer4Servers := make(map[string]interface{})

	for port, rules := range tcpServersByPort {
		r := rules[0].rule
		ruleConfig := SingleRuleConfig{
			CaddyID:                       r.CaddyID,
			Protocol:                      "tcp",
			ListenPort:                    r.ListenPort,
			Strategy:                      r.Strategy,
			HealthCheckInterval:           r.HealthCheckInterval,
			HealthCheckTimeout:            r.HealthCheckTimeout,
			HealthCheckUnhealthyThreshold: r.HealthCheckUnhealthyThreshold,
			HealthCheckHealthyThreshold:   r.HealthCheckHealthyThreshold,
			EnableActiveHealthCheck:       r.EnableActiveHealthCheck,
			TCPHealthCheckPort:            r.TCPHealthCheckPort,
			TCPTryDuration:                r.TCPTryDuration,
			TCPTryInterval:                r.TCPTryInterval,
		}
		for _, ru := range rules {
			for _, u := range ru.upstreams {
				if !u.Enabled {
					continue
				}
				weight := u.Weight
				if weight <= 0 {
					weight = 1
				}
				ruleConfig.Upstreams = append(ruleConfig.Upstreams, UpstreamConfig{
					Host: u.Host, Port: u.Port, Weight: weight, Protocol: u.Protocol, Enabled: u.Enabled,
					MaxConnections: u.MaxConnections, ProxyProtocol: u.ProxyProtocol,
				})
			}
		}
		if len(ruleConfig.Upstreams) == 0 {
			continue
		}

		layer4Servers[fmt.Sprintf("tcp_%d", port)] = buildTCPServer(ruleConfig)
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
	applyTimeouts(defaultSite)

	if _, exists := servers["http_80"]; !exists {
		if len(redirectRoutes) > 0 {
			defaultSite["routes"] = append(redirectRoutes, defaultSite["routes"].([]interface{})...)
		}
		servers["http_80"] = defaultSite
	} else {
		server := servers["http_80"].(map[string]interface{})
		applyTimeouts(server)
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
		// Ensure redirect routes come before the default catch-all route.
		if len(redirectRoutes) > 0 {
			routes = append(redirectRoutes, routes...)
		}
		routes = append(routes, defaultRoute)
		server["routes"] = routes
		servers["http_80"] = server
	}

	loggerNames := map[string]interface{}{}
	for _, ru := range allRules {
		r := ru.rule
		if !r.LogEnabled || r.Protocol != "http" || r.Domain == "" {
			continue
		}
		for _, d := range strings.Split(r.Domain, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				loggerNames[d] = "rule_" + r.CaddyID
			}
		}
	}
	if len(loggerNames) > 0 {
		for _, serverVal := range servers {
			srv, _ := serverVal.(map[string]interface{})
			if srv == nil {
				continue
			}
			srv["logs"] = map[string]interface{}{"logger_names": loggerNames}
		}
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

	if len(layer4Servers) > 0 {
		apps["layer4"] = map[string]interface{}{
			"servers": layer4Servers,
		}
	}

	// TLS app: load certificates from database (manual + ACME), no Caddy ACME automation.
	if len(tlsCertFiles) > 0 {
		tlsApp := map[string]interface{}{
			"certificates": map[string]interface{}{
				"load_files": tlsCertFiles,
			},
		}
		apps["tls"] = tlsApp
	}

	logging := buildCaddyLogging(caddyLogLevel, caddyLogSizeMB)

	if logsMap, ok := logging["logs"].(map[string]interface{}); ok {
		var encoder map[string]interface{}
		if accessLogJSON {
			filterFields := parseAccessLogFormat(accessLogFormat)
			encoder = map[string]interface{}{
				"format": "filter",
				"wrap":   map[string]interface{}{"format": "json"},
				"fields": filterFields,
			}
		} else {
			encoder = map[string]interface{}{"format": "json"}
		}
		for _, ru := range allRules {
			r := ru.rule
			if !r.LogEnabled || r.Protocol != "http" {
				continue
			}
			os.MkdirAll(ruleLogDir, 0755)
			logsMap["rule_"+r.CaddyID] = map[string]interface{}{
				"writer": map[string]interface{}{
					"output":       "file",
					"filename":     RuleLogPath(r.CaddyID),
					"roll_size_mb": caddyLogSizeMB,
					"roll_keep":    5,
				},
				"encoder": encoder,
				"include": []string{"http.log.access.rule_" + r.CaddyID},
			}
		}
	}

	conf := map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": "0.0.0.0:2019",
		},
		"apps":    apps,
		"logging": logging,
	}

	return conf
}

func parseAccessLogFormat(format string) map[string]interface{} {
	fields := map[string]interface{}{}
	for _, line := range strings.Split(format, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "->", 2)
		if len(parts) != 2 {
			continue
		}
		path := strings.TrimSpace(parts[0])
		action := strings.TrimSpace(parts[1])
		if path == "" {
			continue
		}
		if action == "delete" {
			fields[path] = map[string]interface{}{"filter": "delete"}
		} else if action != "" {
			fields[path] = map[string]interface{}{"filter": "rename", "name": action}
		}
	}
	return fields
}

func buildCaddyLogging(level string, sizeMB int) map[string]interface{} {
	if level == "" {
		level = "info"
	}
	level = strings.ToUpper(level)
	if sizeMB <= 0 {
		sizeMB = 100
	}
	consoleEncoder := map[string]interface{}{"format": "console"}
	fileWriter := func(filename string) map[string]interface{} {
		return map[string]interface{}{
			"output":       "file",
			"filename":     filename,
			"roll_size_mb": sizeMB,
			"roll_keep":    5,
		}
	}
	return map[string]interface{}{
		"logs": map[string]interface{}{
			"default": map[string]interface{}{
				"level":   level,
				"writer":  fileWriter("/app/logs/caddy.log"),
				"encoder": consoleEncoder,
				"exclude": []string{"http", "tls", "http.log.access"},
			},
			"caddy_tls": map[string]interface{}{
				"level":   level,
				"writer":  fileWriter("/app/logs/caddy-tls.log"),
				"encoder": consoleEncoder,
				"include": []string{"tls"},
			},
			"caddy_server": map[string]interface{}{
				"level":   level,
				"writer":  fileWriter("/app/logs/caddy-server.log"),
				"encoder": consoleEncoder,
				"exclude": []string{"admin", "tls", "events", "http.log.access", "http.handlers.reverse_proxy"},
			},
			"caddy_proxy": map[string]interface{}{
				"level":   level,
				"writer":  fileWriter("/app/logs/caddy-proxy.log"),
				"encoder": consoleEncoder,
				"include": []string{"http.handlers.reverse_proxy"},
			},
		},
	}
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
		"logging": buildCaddyLogging("info", 100),
	}
}

// loadACMECertificate reads the issued ACME certificate and key from cert_jobs
// for the given rule and domain. Returns (certPEM, keyPEM, true) if issued.
func loadACMECertificate(caddyID, domain string) (string, string, bool) {
	return loadACMECertificateFromStore(db.DB, caddyID, domain)
}

func loadACMECertificateFromStore(store caddyConfigStore, caddyID, domain string) (string, string, bool) {
	parts := strings.Split(domain, ",")
	domains := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		return "", "", false
	}
	for _, d := range domains {
		var id int
		var status string
		var certPEM, keyPEM string
		err := store.QueryRow(`
			SELECT id, status, cert_pem, key_pem
			FROM cert_jobs
			WHERE rule_id=? AND (domain=? OR domain=?)
			  AND cert_pem IS NOT NULL AND cert_pem <> ''
			  AND key_pem IS NOT NULL AND key_pem <> ''
			ORDER BY updated_at DESC LIMIT 1`,
			caddyID, d, domains[0],
		).Scan(&id, &status, &certPEM, &keyPEM)
		if err != nil {
			if err != sql.ErrNoRows {
				log.Printf("loadACMECertificate: query failed for rule %s: %v", caddyID, err)
			}
			continue
		}
		if certPEM == "" || keyPEM == "" {
			// Defensive: only mark as failed if the job was already issued.
			// Don't disrupt in-progress jobs (creating_account, waiting_ca, etc.).
			if status == "issued" {
				if _, updErr := store.Exec(
					"UPDATE cert_jobs SET status='failed', message='证书数据缺失', updated_at=datetime('now') WHERE id=?",
					id,
				); updErr != nil {
					log.Printf("loadACMECertificate: failed to mark issued job %d as failed: %v", id, updErr)
				} else {
					RecordAuditLog("system", "签发失败", "证书签发任务", FormatAuditDetail(AuditJobPart(id), AuditRulePart(caddyID), AuditResultPart("missing_material")), "")
				}
			}
			continue
		}
		return certPEM, keyPEM, true
	}
	return "", "", false
}

// IsACMECertIssued returns true if cert_jobs has an issued certificate for the
// given rule (by caddy_id) and domain.
func IsACMECertIssued(caddyID, domain string) bool {
	return isACMECertIssuedFromStore(db.DB, caddyID, domain)
}

func isACMECertIssuedFromStore(store caddyConfigStore, caddyID, domain string) bool {
	_, _, issued := loadACMECertificateFromStore(store, caddyID, domain)
	return issued
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

type SingleRuleConfig struct {
	ID                             int
	CaddyID                        string
	Name                           string
	Protocol                       string
	Domain                         string
	ListenPort                     int
	Strategy                       string
	DynamicDNS                     bool
	EnableDnsServer                bool
	DnsServer                      string
	DnsFamily                      string
	HealthCheckPath                string
	HealthCheckInterval            int
	HealthCheckTimeout             int
	HealthCheckUnhealthyThreshold  int
	HealthCheckHealthyThreshold    int
	EnableTLS                      bool
	TLSSource                      string
	ACMEConfigID                   int
	ACMEEmail                      string
	TLSCert                        string
	TLSKey                         string
	TLSHTTPRedirect                bool
	EnableCompress                 bool
	CompressTypes                  string
	EnableActiveHealthCheck        bool
	TCPHealthCheckPort             int
	TCPTryDuration                 int
	TCPTryInterval                 int
	RequestBodyMaxSizeMB           int
	UpstreamKeepaliveTimeout       int
	ServerTokensHidden             int
	GlobalRequestBodyMaxSizeMB     int
	GlobalUpstreamKeepaliveTimeout int
	GlobalServerTokensHidden       bool
	HostHeader                     string
	Upstreams                      []UpstreamConfig
}

type UpstreamConfig struct {
	Host           string
	Port           int
	Weight         int
	Protocol       string
	Enabled        bool
	DnsServer      string
	MaxConnections int
	ProxyProtocol  string
}

func resolveRuleOverrides(rule SingleRuleConfig) (requestBodyMaxSizeMB int, upstreamKeepalive int, hideServer bool) {
	requestBodyMaxSizeMB = rule.RequestBodyMaxSizeMB
	if requestBodyMaxSizeMB <= 0 {
		requestBodyMaxSizeMB = rule.GlobalRequestBodyMaxSizeMB
	}

	upstreamKeepalive = rule.UpstreamKeepaliveTimeout
	if upstreamKeepalive <= 0 {
		upstreamKeepalive = rule.GlobalUpstreamKeepaliveTimeout
	}

	hideServer = rule.GlobalServerTokensHidden
	if rule.ServerTokensHidden == 1 {
		hideServer = true
	} else if rule.ServerTokensHidden == 2 {
		hideServer = false
	}

	return requestBodyMaxSizeMB, upstreamKeepalive, hideServer
}

func GenerateSingleRuleCaddyConfig(rule SingleRuleConfig) map[string]interface{} {
	if rule.Strategy == "" {
		rule.Strategy = "weighted_round_robin"
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
		var upstreamWeights []int
		hasHTTPSUpstream := false

		for _, u := range enabledUpstreams {
			weight := u.Weight
			if weight <= 0 {
				weight = 1
			}
			upstreamWeights = append(upstreamWeights, weight)
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

		effectiveRequestBodyMaxSizeMB, effectiveUpstreamKeepaliveTimeout, effectiveServerTokensHidden := resolveRuleOverrides(rule)

		if effectiveRequestBodyMaxSizeMB > 0 {
			handleChain = append([]interface{}{
				map[string]interface{}{
					"handler":  "request_body",
					"max_size": int64(effectiveRequestBodyMaxSizeMB) * 1024 * 1024,
				},
			}, handleChain...)
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
			selectionPolicy := map[string]interface{}{"policy": rule.Strategy}
			if rule.Strategy == "cookie" {
				selectionPolicy["name"] = "lb_sticky"
			}
			if rule.Strategy == "weighted_round_robin" && len(upstreamWeights) > 0 {
				selectionPolicy["weights"] = upstreamWeights
			}
			proxyConfig["load_balancing"] = map[string]interface{}{
				"selection_policy": selectionPolicy,
			}
		}

		{
			hcInterval := rule.HealthCheckInterval
			if hcInterval <= 0 {
				hcInterval = 10
			}
			hcThreshold := rule.HealthCheckUnhealthyThreshold
			if hcThreshold <= 0 {
				hcThreshold = 3
			}
			healthChecks := map[string]interface{}{
				"passive": map[string]interface{}{
					"fail_duration": fmt.Sprintf("%ds", hcInterval*3),
					"max_fails":     hcThreshold,
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

		needsTransport := hasHTTPSUpstream || rule.EnableDnsServer || effectiveUpstreamKeepaliveTimeout > 0
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
			if effectiveUpstreamKeepaliveTimeout > 0 {
				transportConfig["keep_alive"] = map[string]interface{}{
					"idle_timeout": fmt.Sprintf("%ds", effectiveUpstreamKeepaliveTimeout),
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

		if effectiveServerTokensHidden {
			handleChain = append(handleChain, map[string]interface{}{
				"handler": "headers",
				"response": map[string]interface{}{
					"delete": []string{"Server"},
				},
			})
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
							"Location": []string{fmt.Sprintf("https://%s", domainHosts[0])},
						},
					},
				},
			}
			routes = append(routes, redirectRoute)
		}

		serverName := fmt.Sprintf("http_%d", rule.ListenPort)

		server := map[string]interface{}{
			"listen": []string{fmt.Sprintf(":%d", rule.ListenPort)},
			"routes": routes,
		}

		// Add TLS configuration for manual certificates
		if rule.EnableTLS && rule.TLSSource == "manual" && rule.TLSCert != "" && rule.TLSKey != "" {
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

		if rule.ListenPort != 443 && rule.ListenPort != 80 {
			server["automatic_https"] = map[string]interface{}{
				"disable": true,
			}
		}

		servers[serverName] = server
	} else {
		apps := map[string]interface{}{
			"layer4": map[string]interface{}{
				"servers": map[string]interface{}{
					fmt.Sprintf("tcp_%d", rule.ListenPort): buildTCPServer(rule),
				},
			},
		}

		conf := map[string]interface{}{
			"admin": map[string]interface{}{
				"listen": "0.0.0.0:2019",
			},
			"apps": apps,
		}

		return conf
	}

	apps := map[string]interface{}{
		"http": map[string]interface{}{
			"servers": servers,
		},
	}

	// Add TLS certificates configuration for manual certificates
	if rule.EnableTLS && rule.TLSSource == "manual" && rule.TLSCert != "" && rule.TLSKey != "" {
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
		rule.Strategy = "weighted_round_robin"
	}
	if rule.Protocol == "tcp" {
		return buildTCPProxyRoute(rule), nil
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
		upstreamWeights := make([]int, 0)

		effectiveRequestBodyMaxSizeMB, effectiveUpstreamKeepaliveTimeout, effectiveServerTokensHidden := resolveRuleOverrides(rule)

		if effectiveRequestBodyMaxSizeMB > 0 {
			handleChain = append([]interface{}{
				map[string]interface{}{
					"handler":  "request_body",
					"max_size": int64(effectiveRequestBodyMaxSizeMB) * 1024 * 1024,
				},
			}, handleChain...)
		}

		for _, u := range enabledUpstreams {
			weight := u.Weight
			if weight <= 0 {
				weight = 1
			}
			upstreamWeights = append(upstreamWeights, weight)
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
			selectionPolicy := map[string]interface{}{"policy": rule.Strategy}
			if rule.Strategy == "cookie" {
				selectionPolicy["name"] = "lb_sticky"
			}
			if rule.Strategy == "weighted_round_robin" && len(upstreamWeights) > 0 {
				selectionPolicy["weights"] = upstreamWeights
			}
			proxyConfig["load_balancing"] = map[string]interface{}{
				"selection_policy": selectionPolicy,
			}
		}

		if rule.Protocol == "http" {
			hcInterval := rule.HealthCheckInterval
			if hcInterval <= 0 {
				hcInterval = 10
			}
			hcThreshold := rule.HealthCheckUnhealthyThreshold
			if hcThreshold <= 0 {
				hcThreshold = 3
			}
			healthChecks := map[string]interface{}{
				"passive": map[string]interface{}{
					"fail_duration": fmt.Sprintf("%ds", hcInterval*3),
					"max_fails":     hcThreshold,
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

		needsTransport := hasHTTPSUpstream || rule.EnableDnsServer || effectiveUpstreamKeepaliveTimeout > 0
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
			if effectiveUpstreamKeepaliveTimeout > 0 {
				transportConfig["keep_alive"] = map[string]interface{}{
					"idle_timeout": fmt.Sprintf("%ds", effectiveUpstreamKeepaliveTimeout),
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

		if effectiveServerTokensHidden {
			handleChain = append(handleChain, map[string]interface{}{
				"handler": "headers",
				"response": map[string]interface{}{
					"delete": []string{"Server"},
				},
			})
		}

		handleChain = append(handleChain, proxyConfig)
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

// ApplyConfigFromTx renders the Caddy config from an uncommitted transaction
// and applies it, keeping the database unchanged when Caddy rejects the config.
func (s *CaddyService) ApplyConfigFromTx(cfg *config.Config, tx *sql.Tx) error {
	return s.ApplyConfig(generateCaddyConfigFromStore(cfg, tx))
}

// buildTCPProxyRoute generates the layer4 proxy handler and route for a TCP rule.
func buildTCPProxyRoute(rule SingleRuleConfig) map[string]interface{} {
	upstreamList := make([]interface{}, 0)
	enabledPorts := make([]int, 0)
	proxyProtocol := ""
	for _, u := range rule.Upstreams {
		if !u.Enabled {
			continue
		}
		enabledPorts = append(enabledPorts, u.Port)
		dial := fmt.Sprintf("%s:%d", u.Host, u.Port)
		upstreamEntry := map[string]interface{}{
			"dial": []string{dial},
		}
		weight := u.Weight
		if weight > 1 {
			upstreamEntry["weight"] = weight
		}
		if u.Protocol == "https" || u.Protocol == "tls" {
			upstreamEntry["tls"] = map[string]interface{}{
				"insecure_skip_verify": true,
			}
		}
		if u.MaxConnections > 0 {
			upstreamEntry["max_connections"] = u.MaxConnections
		}
		if u.ProxyProtocol == "v1" || u.ProxyProtocol == "v2" {
			proxyProtocol = u.ProxyProtocol
		}
		upstreamList = append(upstreamList, upstreamEntry)
	}

	strategy := rule.Strategy
	if strategy == "" {
		strategy = "weighted_round_robin"
	}
	if strategy == "cookie" {
		strategy = "weighted_round_robin"
	}

	proxyHandler := map[string]interface{}{
		"handler":   "proxy",
		"upstreams": upstreamList,
	}
	if proxyProtocol != "" {
		proxyHandler["proxy_protocol"] = proxyProtocol
	}

	loadBalancing := map[string]interface{}{
		"selection": map[string]interface{}{
			"policy": strategy,
		},
	}
	if rule.TCPTryDuration > 0 {
		loadBalancing["try_duration"] = fmt.Sprintf("%dms", rule.TCPTryDuration)
	}
	if rule.TCPTryInterval > 0 {
		loadBalancing["try_interval"] = fmt.Sprintf("%dms", rule.TCPTryInterval)
	}
	if len(upstreamList) > 1 || rule.TCPTryDuration > 0 || rule.TCPTryInterval > 0 {
		proxyHandler["load_balancing"] = loadBalancing
	}

	healthCheckInterval := rule.HealthCheckInterval
	if healthCheckInterval <= 0 {
		healthCheckInterval = 10
	}
	unhealthyThreshold := rule.HealthCheckUnhealthyThreshold
	if unhealthyThreshold <= 0 {
		unhealthyThreshold = 3
	}
	healthChecks := map[string]interface{}{
		"passive": map[string]interface{}{
			"fail_duration": fmt.Sprintf("%ds", healthCheckInterval*3),
			"max_fails":     unhealthyThreshold,
		},
	}
	if rule.EnableActiveHealthCheck {
		activePort := rule.TCPHealthCheckPort
		if activePort <= 0 && len(enabledPorts) > 0 {
			activePort = enabledPorts[0]
		}
		healthCheckTimeout := rule.HealthCheckTimeout
		if healthCheckTimeout <= 0 {
			healthCheckTimeout = 5
		}
		healthyThreshold := rule.HealthCheckHealthyThreshold
		if healthyThreshold <= 0 {
			healthyThreshold = 2
		}
		healthChecks["active"] = map[string]interface{}{
			"interval": fmt.Sprintf("%ds", healthCheckInterval),
			"port":     activePort,
			"timeout":  fmt.Sprintf("%ds", healthCheckTimeout),
			"rise":     healthyThreshold,
			"fall":     unhealthyThreshold,
		}
	}
	proxyHandler["health_checks"] = healthChecks

	route := map[string]interface{}{
		"handle": []interface{}{proxyHandler},
	}
	if rule.CaddyID != "" {
		route["@id"] = rule.CaddyID
	}
	return route
}

// buildTCPServer generates a layer4 server entry (listen + routes) for a TCP rule.
func buildTCPServer(rule SingleRuleConfig) map[string]interface{} {
	return map[string]interface{}{
		"listen": []string{fmt.Sprintf(":%d", rule.ListenPort)},
		"routes": []interface{}{buildTCPProxyRoute(rule)},
	}
}
