package mcpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"lazy-balancer-v2/internal/db"
)

type readOnlyResolver func(apiKey string) (bool, error)

// ReadOnlyProbeTools 只读 Key 可见的读探测 POST 工具清单（REST 白名单
// auditpolicy.go readOnlyWriteRoutes 同口径）——serveWithToolVisibility 与
// 可见性钉测试（server_test.go）共用的单一事实源（第 51 轮审计 P5-4：
// 原工具侧/测试侧两份手工平行清单收敛为一份）。
var ReadOnlyProbeTools = map[string]struct{}{
	"test_ca_provider": {}, "test_certificate_config": {}, "parse_certificate": {},
	"validate_import": {}, "preview_config": {},
}

func serveWithToolVisibility(writer http.ResponseWriter, request *http.Request, next http.Handler, resolver readOnlyResolver) {
	requestBody, err := io.ReadAll(request.Body)
	if err != nil {
		next.ServeHTTP(writer, request)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(requestBody))
	var rpcRequest struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(requestBody, &rpcRequest) != nil || rpcRequest.Method != "tools/list" || resolver == nil {
		next.ServeHTTP(writer, request)
		return
	}
	readOnly, err := resolver(extractAPIKey(request.Header))
	if err != nil || !readOnly {
		next.ServeHTTP(writer, request)
		return
	}
	recorder := newResponseRecorder()
	next.ServeHTTP(recorder, request)
	filtered, err := filterReadOnlyTools(recorder.body.Bytes())
	if err != nil {
		filtered = recorder.body.Bytes()
	}
	for name, values := range recorder.header {
		writer.Header()[name] = append([]string(nil), values...)
	}
	writer.WriteHeader(recorder.statusCode)
	_, _ = writer.Write(filtered)
}

func resolveAPIKeyReadOnly(apiKey string) (bool, error) {
	if apiKey == "" || db.DB == nil {
		return false, nil
	}
	hash := sha256.Sum256([]byte(apiKey))
	var readOnly bool
	err := db.DB.QueryRow(`
		SELECT COALESCE(k.read_only,0)
		FROM api_keys k
		JOIN users u ON u.id = k.created_by
		WHERE k.key_hash = ?
		  AND k.is_enabled = 1
		  AND u.is_enabled = 1
		  AND (k.expires_at IS NULL OR datetime(k.expires_at) > datetime('now'))
	`, fmt.Sprintf("%x", hash[:])).Scan(&readOnly)
	return readOnly, err
}

func filterReadOnlyTools(response []byte) ([]byte, error) {
	// APIMCP44-1(第 44 轮审计 P3):错误形态(含 error 成员)或缺 result/
	// result.tools 的响应原样透传——下方固定结构体重建会把 error 形态改写为
	// 「result.tools:null」假成功,吞掉上游错误信号。
	var envelope struct {
		Error  json.RawMessage `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil {
		return nil, fmt.Errorf("解析 tools/list 响应: %w", err)
	}
	// W3-R44-4(第 44 轮 W3 评审):显式 "error":null 经 RawMessage 得 4 字节
	// "null",须排除——否则错误判定把正常响应当错误形态透传、跳过过滤。
	if (len(envelope.Error) > 0 && string(envelope.Error) != "null") || len(envelope.Result) == 0 {
		return response, nil
	}
	var resultProbe struct {
		Tools json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(envelope.Result, &resultProbe); err != nil || len(resultProbe.Tools) == 0 {
		return response, nil
	}
	var payload struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Result  struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response, &payload); err != nil {
		return nil, fmt.Errorf("解析 tools/list 响应: %w", err)
	}
	// readOnlyHiddenTools：GET 但对只读 Key 禁用的工具（M8：export_config 走
	// apiKeyReadOnlyGuard 403，只读 Key 不可见，避免呈现必然 403 的工具）。
	readOnlyHiddenTools := map[string]struct{}{"export_config": {}}
	// ApiMcp-新1(第 2 轮审计):REST 只读白名单(auditpolicy.go readOnlyWriteRoutes)
	// 对只读 Key 开放的读探测 POST 对应的 MCP 工具——转发侧守卫可通过,
	// tools/list 须对只读 Key 可见(消除能力与可见性漂移)。清单=包级
	// ReadOnlyProbeTools 单一事实源（第 51 轮 P5-4，钉测试直接消费）。
	readOnlyNames := make(map[string]struct{}, len(tools))
	for _, spec := range tools {
		if spec.method == http.MethodGet {
			if _, hidden := readOnlyHiddenTools[spec.name]; !hidden {
				readOnlyNames[spec.name] = struct{}{}
			}
		}
		// 只读 Key 可见的读探测 POST 工具(REST 白名单同口径)
		if _, probe := ReadOnlyProbeTools[spec.name]; probe {
			readOnlyNames[spec.name] = struct{}{}
		}
	}
	filtered := make([]json.RawMessage, 0, len(payload.Result.Tools))
	for _, rawTool := range payload.Result.Tools {
		var tool struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(rawTool, &tool); err != nil {
			return nil, fmt.Errorf("解析 MCP 工具: %w", err)
		}
		if _, exists := readOnlyNames[tool.Name]; exists {
			filtered = append(filtered, rawTool)
		}
	}
	payload.Result.Tools = filtered
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化 tools/list 响应: %w", err)
	}
	return data, nil
}

type responseRecorder struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: make(http.Header), statusCode: http.StatusOK}
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	return r.body.Write(data)
}
