package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

const snapshotSchemaV2 = 2

type snapshotV2Fixture struct {
	SchemaVersion    int                         `json:"schema_version"`
	MinReaderVersion int                         `json:"min_reader_version"`
	Version          int                         `json:"version"`
	Fingerprint      string                      `json:"fingerprint"`
	Signature        string                      `json:"signature,omitempty"`
	CanonicalPayload json.RawMessage             `json:"canonical_payload,omitempty"`
	Rules            []models.LbRule             `json:"rules"`
	Users            []models.ClusterUser        `json:"users"`
	APIKeys          []models.ClusterAPIKey      `json:"api_keys"`
	BasicSettings    models.ClusterBasicSettings `json:"basic_settings"`
	CaddyConfig      *string                     `json:"caddy_config,omitempty"`
	Certs            []models.ClusterCertificate `json:"certs"`
}

func (snapshot snapshotV2Fixture) canonicalBytes() ([]byte, error) {
	snapshot.Fingerprint = ""
	snapshot.Signature = ""
	snapshot.CanonicalPayload = nil
	return json.Marshal(snapshot)
}

func signedSnapshotV2Fixture(version int, token string) snapshotV2Fixture {
	snapshot := snapshotV2Fixture{
		SchemaVersion:    snapshotSchemaV2,
		MinReaderVersion: snapshotSchemaV2,
		Version:          version,
		Rules:            []models.LbRule{},
		Users:            []models.ClusterUser{},
		APIKeys:          []models.ClusterAPIKey{},
		Certs:            []models.ClusterCertificate{},
	}
	canonical, err := snapshot.canonicalBytes()
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(canonical)
	snapshot.Fingerprint = hex.EncodeToString(hash[:])
	snapshot.CanonicalPayload = canonical
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(canonical)
	snapshot.Signature = hex.EncodeToString(mac.Sum(nil))
	return snapshot
}

func readSnapshotAsV2(response *http.Response, token string) error {
	defer response.Body.Close()
	var envelope struct {
		Data snapshotV2Fixture `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("解析 v2 快照响应: %w", err)
	}
	snapshot := envelope.Data
	if snapshot.MinReaderVersion > snapshotSchemaV2 {
		return fmt.Errorf("要求 schema v%d，当前支持 v%d", snapshot.MinReaderVersion, snapshotSchemaV2)
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(snapshot.CanonicalPayload)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(snapshot.Signature)) {
		return fmt.Errorf("v2 快照签名校验失败")
	}
	return nil
}

func TestSnapshotV2ReaderFixture_verifiesOriginalCanonicalBytes(t *testing.T) {
	// Given
	const token = "cluster-token"
	snapshot := signedSnapshotV2Fixture(1, token)
	snapshot.CanonicalPayload = json.RawMessage(`{"certs":[],"basic_settings":{},"api_keys":[],"users":[],"rules":[],"fingerprint":"","version":1,"schema_version":2,"min_reader_version":2}`)
	hash := sha256.Sum256(snapshot.CanonicalPayload)
	snapshot.Fingerprint = hex.EncodeToString(hash[:])
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(snapshot.CanonicalPayload)
	snapshot.Signature = hex.EncodeToString(mac.Sum(nil))
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{"data": snapshot})
	}))
	defer master.Close()

	// When
	response, err := master.Client().Get(master.URL + "/api/v1/cluster/sync/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	readErr := readSnapshotAsV2(response, token)

	// Then
	if readErr != nil {
		t.Fatalf("v2 reader rejected raw signed canonical payload: %v", readErr)
	}
}

func TestSnapshotV2ReaderFixture_rejectsCurrentV3PublisherResponse(t *testing.T) {
	// Given
	const token = "cluster-token"
	publisher, _ := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		snapshot, _, err := publisher.Snapshot(request.Context(), 0, "", token)
		if err != nil {
			t.Errorf("publish snapshot: %v", err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(response).Encode(models.APIResponse{Code: 0, Data: snapshot})
	}))
	defer master.Close()

	// When
	response, err := master.Client().Get(master.URL + "/api/v1/cluster/sync/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	readErr := readSnapshotAsV2(response, token)

	// Then
	if readErr == nil || !strings.Contains(readErr.Error(), "要求 schema v3，当前支持 v2") {
		t.Fatalf("v2 reader error=%v", readErr)
	}
}

func TestSyncService_Pull_rejectsValidV2PublisherFixture(t *testing.T) {
	// Given
	const token = "cluster-token"
	_, database := newClusterTestService(t)
	v2 := signedSnapshotV2Fixture(1, token)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{"data": v2})
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=? WHERE id=1", master.URL, token); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, pullErr := service.Pull(context.Background())

	// Then
	if pullErr == nil || !strings.Contains(pullErr.Error(), "快照 schema v2 过旧：主节点需升级到支持 schema v3 的版本") {
		t.Fatalf("v3 reader error=%v", pullErr)
	}
}

func TestClusterSnapshot_HTTPPublisherPullAndFingerprint304(t *testing.T) {
	// Given
	const token = "cluster-token"
	publisher, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET cluster_version=7"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := publisher.Snapshot(context.Background(), 0, "", token); err != nil {
		t.Fatal(err)
	}
	var fullResponses, notModifiedResponses int
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		sinceVersion, _ := strconv.Atoi(request.URL.Query().Get("since_version"))
		snapshot, changed, err := publisher.Snapshot(request.Context(), sinceVersion, request.URL.Query().Get("fingerprint"), request.Header.Get("X-Cluster-Token"))
		if err != nil {
			t.Errorf("publish snapshot: %v", err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !changed {
			notModifiedResponses++
			response.WriteHeader(http.StatusNotModified)
			return
		}
		fullResponses++
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(models.APIResponse{Code: 0, Data: snapshot})
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=?, applied_version=0, sync_fingerprint='' WHERE id=1", master.URL, token); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddy.URL}, NewCaddyService(caddy.URL))

	// When
	first, firstErr := service.Pull(context.Background())
	second, secondErr := service.Pull(context.Background())

	// Then
	if firstErr != nil || !first.Changed || first.AppliedVersion != 7 {
		t.Fatalf("first pull=%#v error=%v", first, firstErr)
	}
	if secondErr != nil || second.Changed || second.AppliedVersion != 7 {
		t.Fatalf("second pull=%#v error=%v", second, secondErr)
	}
	if fullResponses != 1 || notModifiedResponses != 1 {
		t.Fatalf("full responses=%d not-modified responses=%d", fullResponses, notModifiedResponses)
	}
}
