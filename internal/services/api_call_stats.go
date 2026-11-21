package services

// REST API 调用统计（内存环形+当日聚合）：API 接入页「接入统计」REST 列
// 与 MCP 列对称的数据源（今日调用/错误率/最近调用；趋势按内存记录按日聚合，
// 覆盖窗口=环形容量，标注为「最近记录窗口」）。MCP 路由不记入（已有专属
// 统计），采集点在 apiKeyAuth 身份解析成功之后。
//
// 请求级回写：入环时分配单调 token，中间件保存并传给 RecordRESTAPICallStatus
// ——并发下环形尾不一定是当前请求，按尾回写会把状态码记到别人的记录上。

import (
	"sync"
	"time"
)

const apiCallRingSize = 200

type apiCallRecord struct {
	Token   uint64
	At      time.Time
	KeyName string
	Method  string
	Path    string
	IP      string
	Status  int
	IsError bool
}

// APICallToken 一次 REST 调用在环形内的身份（RecordRESTAPICallStart 分配，
// 请求结束回写状态码时凭它定位本请求记录；环被裁剪后回写变为空操作）。
type APICallToken uint64

var (
	apiCallMu   sync.Mutex
	apiCallSeq  uint64
	apiCallRing []apiCallRecord
	apiCallDay  = map[string][2]int64{} // date(YYYY-MM-DD) -> [calls, errors]（仅 REST）
)

// RecordRESTAPICallStart 采集一条 REST 调用（apiKeyAuth 身份解析成功后调用；
// MCP 路径在调用点排除）。状态码先按 200 占位入环，请求结束后由
// RecordRESTAPICallStatus 用返回的 token 回写真实状态码。
func RecordRESTAPICallStart(keyName, method, path, ip string) APICallToken {
	now := time.Now()
	date := now.Format("2006-01-02")
	apiCallMu.Lock()
	defer apiCallMu.Unlock()
	apiCallSeq++
	rec := apiCallRecord{
		Token: apiCallSeq, At: now, KeyName: keyName, Method: method, Path: path, IP: ip,
		Status: 200, IsError: false,
	}
	apiCallRing = append(apiCallRing, rec)
	if len(apiCallRing) > apiCallRingSize {
		apiCallRing = apiCallRing[len(apiCallRing)-apiCallRingSize:]
	}
	// 当日聚合只保留今日+昨日：日期键按天累积（长期运行下无界增长），
	// 新日期首次出现时顺手清理更早的键；趋势面由环形窗口承载，不受影响。
	if _, seen := apiCallDay[date]; !seen {
		pruneAPICallDayLocked(now)
	}
	c := apiCallDay[date]
	c[0]++
	apiCallDay[date] = c
	return APICallToken(rec.Token)
}

// pruneAPICallDayLocked 删除早于「昨日」的日期键（保留今日与昨日）。
func pruneAPICallDayLocked(now time.Time) {
	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")
	for d := range apiCallDay {
		if d < yesterday {
			delete(apiCallDay, d)
		}
	}
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

// RecordRESTAPICallStatus 请求结束后回写本请求的真实状态码：按 token 逆序
// 定位环形内本请求记录（并发请求各自持不同 token，环形尾即当前请求的旧
// 假设在并发下不成立）。记录已被环裁剪时为无操作。占位态 200 不计错误，
// 回写 ≥400 时补记当日错误计数。
func RecordRESTAPICallStatus(token APICallToken, status int) {
	apiCallMu.Lock()
	defer apiCallMu.Unlock()
	for i := len(apiCallRing) - 1; i >= 0; i-- {
		r := &apiCallRing[i]
		if r.Token != uint64(token) {
			continue
		}
		r.Status = status
		if status >= 400 && !r.IsError {
			r.IsError = true
			date := r.At.Format("2006-01-02")
			c := apiCallDay[date]
			c[1]++
			apiCallDay[date] = c
		}
		return
	}
}
