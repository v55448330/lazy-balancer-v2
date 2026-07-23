package services

import (
	"strings"
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

type RuleLogStatItem struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type RuleLogStats struct {
	Total     int64            `json:"total"`
	StartedAt string           `json:"started_at"`
	TopIPs    []RuleLogStatItem `json:"top_ips"`
	TopUAs    []RuleLogStatItem `json:"top_uas"`
	TopURIs   []RuleLogStatItem `json:"top_uris"`
}

type ruleLogAggregator struct {
	offset    int64
	total     int64
	ip        map[string]int64
	ua        map[string]int64
	uri       map[string]int64
	startedAt time.Time
	lastPoll  time.Time
}

var (
	ruleLogAggs   = map[string]*ruleLogAggregator{}
	ruleLogAggsMu sync.Mutex
)

func init() {
	go func() {
		for range time.Tick(time.Minute) {
			ruleLogAggsMu.Lock()
			for id, agg := range ruleLogAggs {
				if time.Since(agg.lastPoll) > 5*time.Minute {
					delete(ruleLogAggs, id)
				}
			}
			ruleLogAggsMu.Unlock()
		}
	}()
}

// GetRuleLogStats incrementally parses the rule access log (JSON lines) and
// returns top IPs/UAs/URIs. reset restarts aggregation from the tail of the
// file; aggregators self-expire after 5 idle minutes.
func GetRuleLogStats(ruleID string, reset bool) RuleLogStats {
	ruleLogAggsMu.Lock()
	agg, ok := ruleLogAggs[ruleID]
	if !ok || reset {
		agg = &ruleLogAggregator{
			ip:  map[string]int64{},
			ua:  map[string]int64{},
			uri: map[string]int64{},
		}
		if reset || !ok {
			agg.startedAt = time.Now()
		}
		ruleLogAggs[ruleID] = agg
	}
	agg.lastPoll = time.Now()
	ruleLogAggsMu.Unlock()

	agg.consume(ruleID)
	return agg.snapshot()
}

const ruleLogInitialReadLimit = 16 << 20

func (a *ruleLogAggregator) consume(ruleID string) {
	path := RuleLogPath(ruleID)
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}
	if info.Size() < a.offset {
		a.offset = 0
	}
	start := a.offset
	if start == 0 && info.Size() > ruleLogInitialReadLimit {
		start = info.Size() - ruleLogInitialReadLimit
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return
	}
	reader := bufio.NewReader(f)
	if start > 0 {
		reader.ReadString('\n')
	}
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			a.consumeLine(line)
		}
		if err != nil {
			break
		}
	}
	pos, _ := f.Seek(0, io.SeekCurrent)
	a.offset = pos
}

func (a *ruleLogAggregator) consumeLine(line string) {
	var entry struct {
		Request map[string]any `json:"request"`
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil || entry.Request == nil {
		return
	}
	a.total++
	ip := firstString(entry.Request, "client_ip", "src_ip", "src", "remote_ip")
	if ip == "" {
		ip = "-"
	}
	a.ip[ip]++
	uri := firstString(entry.Request, "uri", "uri_path")
	if i := strings.Index(uri, "?"); i >= 0 {
		uri = uri[:i]
	}
	if uri == "" {
		uri = "-"
	}
	a.uri[uri]++
	ua := firstString(entry.Request, "user_agent")
	if ua == "" {
		if headers, ok := entry.Request["headers"].(map[string]any); ok {
			if list, ok := headers["User-Agent"].([]any); ok && len(list) > 0 {
				ua, _ = list[0].(string)
			}
		}
	}
	a.ua[generalizeUA(ua)]++
}

// generalizeUA collapses full User-Agent strings into a compact
// "Client Version / OS" form so top stats stay readable. Matching is a few
// ordered substring checks to keep per-line cost negligible.
func generalizeUA(ua string) string {
	if ua == "" {
		return "未知"
	}
	client, version := "其他", ""
	pickVersion := func(marker string) string {
		i := strings.Index(ua, marker)
		if i < 0 {
			return ""
		}
		rest := ua[i+len(marker):]
		end := strings.IndexAny(rest, ". )")
		if end < 0 {
			end = len(rest)
		}
		return rest[:end]
	}
	switch {
	case strings.Contains(ua, "Edg/"):
		client, version = "Edge", pickVersion("Edg/")
	case strings.Contains(ua, "Chrome/"):
		client, version = "Chrome", pickVersion("Chrome/")
	case strings.Contains(ua, "Firefox/"):
		client, version = "Firefox", pickVersion("Firefox/")
	case strings.Contains(ua, "Version/") && strings.Contains(ua, "Safari/"):
		client, version = "Safari", pickVersion("Version/")
	case strings.Contains(ua, "curl/"):
		client, version = "curl", pickVersion("curl/")
	case strings.Contains(ua, "PostmanRuntime"):
		client = "Postman"
	case strings.Contains(ua, "python-requests"):
		client = "Python Requests"
	case strings.Contains(ua, "Go-http-client"):
		client = "Go Client"
	case strings.Contains(ua, "Health") || strings.Contains(ua, "health") || strings.Contains(ua, "probe"):
		client = "探测"
	}
	osName := "其他系统"
	switch {
	case strings.Contains(ua, "Windows NT"):
		osName = "Windows"
	case strings.Contains(ua, "Mac OS X"):
		osName = "macOS"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		osName = "iOS"
	case strings.Contains(ua, "Android"):
		osName = "Android"
	case strings.Contains(ua, "Linux"):
		osName = "Linux"
	}
	if version != "" {
		return client + " " + version + " / " + osName
	}
	return client + " / " + osName
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func topN(m map[string]int64, n int) []RuleLogStatItem {
	items := make([]RuleLogStatItem, 0, len(m))
	for v, c := range m {
		items = append(items, RuleLogStatItem{Value: v, Count: c})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Value < items[j].Value
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}

func (a *ruleLogAggregator) snapshot() RuleLogStats {
	return RuleLogStats{
		Total:     a.total,
		StartedAt: a.startedAt.In(CurrentLocation()).Format("2006-01-02 15:04:05"),
		TopIPs:    topN(a.ip, 10),
		TopUAs:    topN(a.ua, 10),
		TopURIs:   topN(a.uri, 10),
	}
}
