package lbreqmon

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
)

// ReqMonAdmin admin.api 模块：把 /lb/reqmon/snapshot 注册进 Caddy admin
// 服务（caddygeoip TrafficStatsAdmin 同模式：admin.api 模块随编译自动
// 挂载，无需配置启用，无实例状态、读全局环形缓冲）。
type ReqMonAdmin struct{}

// CaddyModule returns the Caddy module information.
func (ReqMonAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.lb_reqmon",
		New: func() caddy.Module { return new(ReqMonAdmin) },
	}
}

// Routes registers the read-only endpoint.
func (ReqMonAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/lb/reqmon/snapshot",
			Handler: caddy.AdminHandlerFunc(serveReqMonSnapshot),
		},
	}
}

// reqMonSnapshotPayload 快照响应（契约锁定：LB 消费端按此解码）。
type reqMonSnapshotPayload struct {
	Capacity int             `json:"capacity"`
	Entries  []RequestRecord `json:"entries"`
}

func serveReqMonSnapshot(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	// limit=N：仅返回最新 N 条（LB 弹框展示上限 500，无需全量 50k JSON
	// 编解码——2s 轮询下的 Caddy 进程 CPU 从 O(50k 排序+序列化) 降为 O(N)）。
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= RingCapacity {
			limit = n
		}
	}
	entries := Snapshot()
	if entries == nil {
		entries = []RequestRecord{}
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit] // Snapshot 最新优先，截尾即最旧丢弃
	}
	raw, err := json.Marshal(reqMonSnapshotPayload{Capacity: RingCapacity, Entries: entries})
	if err != nil {
		raw = []byte(`{"capacity":0,"entries":[]}`)
	}
	_, _ = w.Write(raw)
	return nil
}

// Interface guards（编译期契约）。
var (
	_ caddy.AdminRouter = (*ReqMonAdmin)(nil)
	_ caddy.Module      = (*ReqMonAdmin)(nil)
)

func init() {
	caddy.RegisterModule(ReqMonHandler{})
	caddy.RegisterModule(ReqMonAdmin{})
}
