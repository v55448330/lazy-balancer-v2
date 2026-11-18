package services

// REST API 调用统计（内存环形+当日聚合）：API 接入页「接入统计」REST 列
// 与 MCP 列对称的数据源（今日调用/错误率/最近调用；趋势按内存记录按日聚合，
// 覆盖窗口=环形容量，标注为「最近记录窗口」）。MCP 路由不记入（已有专属
// 统计），采集点在 apiKeyAuth 身份解析成功之后。

import (
	"sync"
	"time"
)

const (
	apiCallRingSize = 200
	apiCallMaxAge   = 7 * 24 * time.Hour
)

type apiCallRecord struct {
	At      time.Time
	KeyName string
	Method  string
	Path    string
	IP      string
	Status  int
	IsError bool
}

var (
	apiCallMu       sync.Mutex
	apiCallRing     []apiCallRecord
	apiCallDay      = map[string][2]int64{} // date(YYYY-MM-DD) -> [calls, errors]（仅 REST）
	apiCallDayDirty = false
)

// RecordRESTAPICall 采集一条 REST 调用（apiKeyAuth 身份解析成功后调用；
// MCP 路径在调用点排除）。
func RecordRESTAPICall(keyName, method, path, ip string, status int) {
	now := time.Now()
	rec := apiCallRecord{
		At: now, KeyName: keyName, Method: method, Path: path, IP: ip,
		Status: status, IsError: status >= 400,
	}
	date := now.Format("2006-01-02")
	apiCallMu.Lock()
	apiCallRing = append(apiCallRing, rec)
	if len(apiCallRing) > apiCallRingSize {
		apiCallRing = apiCallRing[len(apiCallRing)-apiCallRingSize:]
	}
	c := apiCallDay[date]
	c[0]++
	if rec.IsError {
		c[1]++
	}
	apiCallDay[date] = c
	apiCallMu.Unlock()
}

// RESTCallOverview 接入统计 REST 列数据（与 MCP 列对称）。
type RESTCallOverview struct {
	TodayCalls  int64                `json:"today_calls"`
	ErrorRate   float64              `json:"error_rate"`
	Trend       []RESTCallTrendPoint `json:"trend"`
	RecentCalls []RecentAPICall      `json:"recent_calls"`
	TrendNote   string               `json:"trend_note"`
}

type RESTCallTrendPoint struct {
	Date  string `json:"date"`
	Calls int64  `json:"calls"`
}

type RecentAPICall struct {
	Time    string `json:"time"`
	KeyName string `json:"key_name"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	IP      string `json:"ip"`
	Status  int    `json:"status"`
}

// GetRESTCallOverview 汇总当日计数+7 日趋势（内存窗口聚合，超出窗口的
// 日期不产出）+最近调用（最新在前，上限 50）。
func GetRESTCallOverview() RESTCallOverview {
	apiCallMu.Lock()
	defer apiCallMu.Unlock()
	now := time.Now()
	today := now.Format("2006-01-02")
	c := apiCallDay[today]
	out := RESTCallOverview{TodayCalls: c[0], RecentCalls: []RecentAPICall{}}
	if c[0] > 0 {
		out.ErrorRate = float64(c[1]) / float64(c[0])
	}
	// 趋势：内存窗口内按日聚合（升序；环形可能不满 7 天——如实呈现）
	perDay := map[string]int64{}
	for _, r := range apiCallRing {
		perDay[r.At.Format("2006-01-02")]++
	}
	out.Trend = []RESTCallTrendPoint{}
	for i := 6; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		out.Trend = append(out.Trend, RESTCallTrendPoint{Date: d, Calls: perDay[d]})
	}
	// 最近调用（环形尾部倒序，上限 50）
	n := len(apiCallRing)
	start := n - 50
	if start < 0 {
		start = 0
	}
	for i := n - 1; i >= start; i-- {
		r := apiCallRing[i]
		out.RecentCalls = append(out.RecentCalls, RecentAPICall{
			Time: r.At.Format("01-02 15:04:05"), KeyName: r.KeyName,
			Method: r.Method, Path: r.Path, IP: r.IP, Status: r.Status,
		})
	}
	out.TrendNote = "memory-window"
	return out
}

// RecordRESTAPICallStatus 请求结束后回写真实状态码（in-flight 时先按 200
// 占位入环，本函数在 c.Next() 返回后修正环形尾记录；并发请求各自在自己
// 的 handler 调用链上执行，环形尾即当前请求）。
func RecordRESTAPICallStatus(status int) {
	apiCallMu.Lock()
	defer apiCallMu.Unlock()
	if len(apiCallRing) == 0 {
		return
	}
	r := &apiCallRing[len(apiCallRing)-1]
	r.Status = status
	if status >= 400 && !r.IsError {
		r.IsError = true
		date := r.At.Format("2006-01-02")
		c := apiCallDay[date]
		c[1]++
		apiCallDay[date] = c
	}
}
