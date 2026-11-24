package handlers

// 任务日志截断披露单源：两个日志端点（统一任务引擎 /system/tasks/:id/logs 与
// 证书任务 /certificates/jobs/:id/logs）只下发 truncated 布尔，content 本体是
// 纯日志——提示行由渲染层按语言生成。此前提示行写进响应内容（「[日志过长，仅
// 显示最近 256KB]」前置行），英文界面与机器消费方都会把它当成第一条日志正文。
//
// 本钉两层：①两形状行为（未截断 truncated=false 且内容原样；截断 truncated=true
// 且内容不含提示行）；②五载体源码对账（两个 handler 函数、apidocs 两条端点描述、
// mcpserver 两个工具描述）——把提示行写回内容是回归，描述漏 truncated 会让
// 消费端把尾窗误读为全部日志。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/taskengine"
)

func TestSystemTaskLogs_truncationFlagShapes(t *testing.T) {
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })

	readLogs := func(t *testing.T, taskID string) (string, bool) {
		t.Helper()
		router := gin.New()
		router.GET("/system/tasks/:id/logs", (&Handlers{}).GetSystemTaskLogs)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/"+taskID+"/logs", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var payload struct {
			Data struct {
				Content   string `json:"content"`
				Truncated bool   `json:"truncated"`
			} `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return payload.Data.Content, payload.Data.Truncated
	}

	t.Run("small log reports false and keeps content verbatim", func(t *testing.T) {
		if err := os.WriteFile(taskengine.TaskLogPath("flag-small"), []byte("small-line\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		content, truncated := readLogs(t, "flag-small")
		if truncated {
			t.Fatal("truncated=true, want false（小日志不做尾窗截断）")
		}
		if content != "small-line\n" {
			t.Fatalf("content=%q, want 原样", content)
		}
	})

	t.Run("budget cut reports true and content has no notice line", func(t *testing.T) {
		path := taskengine.TaskLogPath("flag-big")
		if err := os.WriteFile(path+".1", []byte(strings.Repeat("old-line\n", 30000)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.Repeat("active-line\n", 6250)), 0o644); err != nil {
			t.Fatal(err)
		}
		content, truncated := readLogs(t, "flag-big")
		if !truncated {
			t.Fatal("truncated=false, want true（轮转副本超出 256KB 预算）")
		}
		if strings.Contains(content, "日志过长") || strings.Contains(content, "仅显示最近") {
			t.Fatalf("内容混入提示行，首 80 字符: %q", content[:min(len(content), 80)])
		}
		if !strings.Contains(content, "active-line") {
			t.Fatal("截断标志不得挤掉活动日志尾窗")
		}
	})
}

func TestTaskLogTruncation_noticeOnlyRenderedByConsumers(t *testing.T) {
	// ①两个 handler 函数体内不得再出现提示行字面量（AST 邻域文本扫描足够：
	// 提示行只可能以字符串字面量形式写回 content）；②响应必须携带 truncated。
	handlerFaces := []struct{ file, fn string }{
		{"taskmonitor.go", "GetSystemTaskLogs"},
		{"certjobs.go", "GetCertJobLogs"},
	}
	for _, face := range handlerFaces {
		raw, err := os.ReadFile(face.file)
		if err != nil {
			t.Fatalf("read %s: %v", face.file, err)
		}
		body := string(raw)
		if idx := strings.Index(body, "func (h *Handlers) "+face.fn+"("); idx >= 0 {
			if end := strings.Index(body[idx:], "\nfunc "); end > 0 {
				body = body[idx : idx+end]
			}
		}
		if strings.Contains(body, "日志过长") || strings.Contains(body, "仅显示最近") {
			t.Errorf("%s.%s 仍把提示行写回响应内容（提示行由消费端按 truncated 渲染）", face.file, face.fn)
		}
		if !strings.Contains(body, "truncated") {
			t.Errorf("%s.%s 响应缺 truncated 标志", face.file, face.fn)
		}
	}

	// ③apidocs 两条日志端点描述必须登记 truncated 语义，且不再声称首行提示行。
	docs, err := os.ReadFile("apidocs.go")
	if err != nil {
		t.Fatalf("read apidocs.go: %v", err)
	}
	for _, route := range []string{`/system/tasks/:id/logs`, `/certificates/jobs/:id/logs`} {
		idx := strings.Index(string(docs), `"`+route+`"`)
		if idx < 0 {
			t.Fatalf("apidocs 缺 %s 条目", route)
		}
		entry := string(docs)[idx:]
		if end := strings.Index(entry, "\n"); end >= 0 {
			entry = entry[:end]
		}
		if !strings.Contains(entry, "truncated") || !strings.Contains(entry, "256KB") {
			t.Errorf("apidocs %s 未披露 truncated/256KB 口径", route)
		}
		if strings.Contains(entry, "日志过长") || strings.Contains(entry, "前置提示行") {
			t.Errorf("apidocs %s 仍在描述首行提示行（提示行已移出响应内容）", route)
		}
	}

	// ④mcpserver 两个日志工具的描述必须披露 truncated（Agent 依赖该标志判断
	// 尾窗是否完整），且不得再声称首行提示行。
	for _, file := range []string{"server.go", "tools.go"} {
		raw, err := os.ReadFile(filepath.Join("..", "mcpserver", file))
		if err != nil {
			t.Fatalf("read mcpserver/%s: %v", file, err)
		}
		for _, tool := range []string{"get_system_task_logs", "get_cert_job_logs"} {
			idx := strings.Index(string(raw), tool)
			if idx < 0 {
				t.Fatalf("mcpserver/%s 缺少 %s 工具登记", file, tool)
			}
			seg := string(raw)[idx:]
			if end := strings.Index(seg, "\n"); end > 0 {
				seg = seg[:end]
			}
			if !strings.Contains(seg, "truncated") || !strings.Contains(seg, "256KB") {
				t.Errorf("mcpserver/%s %s 描述缺 truncated/256KB 披露: %s", file, tool, seg)
			}
			if strings.Contains(seg, "日志过长") || strings.Contains(seg, "前置提示行") {
				t.Errorf("mcpserver/%s %s 描述仍在声称首行提示行: %s", file, tool, seg)
			}
		}
	}
}
