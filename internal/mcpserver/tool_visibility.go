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
	err := db.DB.QueryRow("SELECT COALESCE(read_only,0) FROM api_keys WHERE key_hash = ?", fmt.Sprintf("%x", hash[:])).Scan(&readOnly)
	return readOnly, err
}

func filterReadOnlyTools(response []byte) ([]byte, error) {
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
	readOnlyNames := make(map[string]struct{}, len(tools))
	for _, spec := range tools {
		if spec.method == http.MethodGet {
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
