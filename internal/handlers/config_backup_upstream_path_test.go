package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// 旧版本备份（path_rules 行缺 upstream_path 列 / 显式 null）导入必须成功且
// 该列落默认空串（原样转发语义），不得炸、不得毒化备份往返。
func TestImportConfigBackup_legacyBackupWithoutUpstreamPath_restoresEmptyDefault(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,created_at,last_login,password_version,
		mfa_enabled,mfa_secret,mfa_recovery_codes,mfa_last_timestep)
		VALUES (1,'uplegacy-admin','hash','admin','UpLegacy Admin',1,'2026-01-02 03:04:05',NULL,5,0,'','[]',0)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress,custom_routes_enabled) VALUES ('lb_uplegacy','legacy','','http','legacy.example.test',8080,'weighted_round_robin','',1,1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_uplegacy','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path) VALUES ('lb_uplegacy',0,'prefix','/api','/v1')`); err != nil {
		t.Fatalf("seed path rule: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)

	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%.300s", exportResponse.Code, exportResponse.Body.String())
	}
	var exportPayload map[string]any
	if err := json.Unmarshal(unpackExportBody(t, exportResponse.Body.Bytes()), &exportPayload); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	tables := exportPayload["tables"].(map[string]any)
	pathRows := tables["path_rules"].([]any)
	if len(pathRows) != 1 {
		t.Fatalf("export path_rules rows=%d, want 1", len(pathRows))
	}
	// 旧版本备份形态：首行剥掉 upstream_path 键，再造一行显式 null
	firstRow := pathRows[0].(map[string]any)
	delete(firstRow, "upstream_path")
	pathRows = append(pathRows, map[string]any{
		"rule_id": "lb_uplegacy", "sort_order": 1, "match_type": "exact", "path": "/health", "upstream_path": nil,
	})
	tables["path_rules"] = pathRows

	// 与导入侧同构重算校验和（sha256 over {tables, config} 重编组）
	remarshaled, err := json.Marshal(exportPayload)
	if err != nil {
		t.Fatalf("encode mutated backup: %v", err)
	}
	var rebackup struct {
		Tables map[string][]map[string]any `json:"tables"`
		Config map[string]any              `json:"config"`
	}
	if err := json.Unmarshal(remarshaled, &rebackup); err != nil {
		t.Fatalf("decode mutated backup: %v", err)
	}
	checksumPayload, err := json.Marshal(struct {
		Tables map[string][]map[string]any `json:"tables"`
		Config map[string]any              `json:"config"`
	}{rebackup.Tables, rebackup.Config})
	if err != nil {
		t.Fatalf("encode checksum payload: %v", err)
	}
	checksum := sha256.Sum256(checksumPayload)
	exportPayload["meta"].(map[string]any)["checksum"] = hex.EncodeToString(checksum[:])
	legacyBackup, err := json.Marshal(exportPayload)
	if err != nil {
		t.Fatalf("encode legacy backup: %v", err)
	}

	// When：改写现网行作哨兵后导入旧形态备份
	if _, err := db.DB.Exec(`UPDATE path_rules SET upstream_path='/sentinel' WHERE rule_id='lb_uplegacy'`); err != nil {
		t.Fatalf("sentinel write: %v", err)
	}
	importResponse := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(legacyBackup)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResponse, request)

	// Then：导入成功，两行 upstream_path 均落默认空串
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%.400s", importResponse.Code, importResponse.Body.String())
	}
	var upstreamPath string
	if err := db.DB.QueryRow(`SELECT upstream_path FROM path_rules WHERE rule_id='lb_uplegacy' AND path='/api'`).Scan(&upstreamPath); err != nil {
		t.Fatalf("read restored path rule: %v", err)
	}
	if upstreamPath != "" {
		t.Fatalf("restored legacy row upstream_path=%q, want empty", upstreamPath)
	}
	var nullRowPath string
	if err := db.DB.QueryRow(`SELECT upstream_path FROM path_rules WHERE rule_id='lb_uplegacy' AND path='/health'`).Scan(&nullRowPath); err != nil {
		t.Fatalf("read null-row path rule: %v", err)
	}
	if nullRowPath != "" {
		t.Fatalf("explicit-null row upstream_path=%q, want empty", nullRowPath)
	}
}
