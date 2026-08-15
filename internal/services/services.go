package services

import (
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

var (
	prometheusRequestTotalPattern    = regexp.MustCompile(`caddy_http_requests_total\{[^}]*\}\s+(\S+)`)
	prometheusStatusCountPattern     = regexp.MustCompile(`caddy_http_request_duration_seconds_count\{[^}]*code="(\d+)"[^}]*\}\s+(\S+)`)
	prometheusResponseSizePattern    = regexp.MustCompile(`caddy_http_response_size_bytes_sum.*?\}\s+(\S+)`)
	prometheusRequestSizePattern     = regexp.MustCompile(`caddy_http_request_size_bytes_sum.*?\}\s+(\S+)`)
	prometheusLatencyBucketPattern   = regexp.MustCompile(`caddy_http_request_duration_seconds_bucket\{[^}]*le="([^"]+)"[^}]*\}\s+(\S+)`)
	prometheusHostStatusPattern      = regexp.MustCompile(`caddy_http_request_duration_seconds_count\{[^}]*code="(\d+)"[^}]*host="([^"]+)"[^}]*\}\s+(\S+)`)
	prometheusHostResponsePattern    = regexp.MustCompile(`caddy_http_response_size_bytes_sum\{[^}]*host="([^"]+)"[^}]*\}\s+(\S+)`)
	prometheusHostRequestSizePattern = regexp.MustCompile(`caddy_http_request_size_bytes_sum\{[^}]*host="([^"]+)"[^}]*\}\s+(\S+)`)
)

// MetricsService collects and stores metrics from Caddy
type MetricsService struct {
	metricsURL                 string
	interval                   int
	client                     *http.Client
	stopCh                     chan struct{}
	stopOnce                   sync.Once
	overview                   models.MetricsOverview
	mu                         sync.RWMutex
	lastTotal                  int64
	lastSampleAt               time.Time
	hasLastSample              bool
	domainConflictMu           sync.Mutex
	domainConflictFingerprints map[string]string
}

func NewMetricsService(metricsURL string, interval int) *MetricsService {
	return &MetricsService{
		metricsURL: metricsURL,
		interval:   interval,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		stopCh:   make(chan struct{}),
		overview: models.MetricsOverview{},
	}
}

func (m *MetricsService) Start() {
	ticker := time.NewTicker(time.Duration(m.interval) * time.Second)
	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	defer cleanupTicker.Stop()
	m.cleanupHistory()

	for {
		select {
		case <-ticker.C:
			m.collect()
		case <-cleanupTicker.C:
			m.cleanupHistory()
		case <-m.stopCh:
			return
		}
	}
}

func (m *MetricsService) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
}

func (m *MetricsService) collect() {
	resp, err := m.client.Get(m.metricsURL)
	if err != nil {
		log.Printf("Failed to collect metrics: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Metrics endpoint returned status %d, skipping sample", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	metrics, err := m.parsePrometheusMetrics(string(body))
	if err != nil {
		log.Printf("Failed to parse metrics: %v", err)
		return
	}
	m.storeMetrics(metrics)
	if err := m.storePerHostMetrics(string(body)); err != nil {
		log.Printf("Failed to store per-host metrics: %v", err)
	}
	m.updateOverview(metrics)
}

type parsedMetrics struct {
	requestsTotal int64
	requests2xx   int64
	requests3xx   int64
	requests4xx   int64
	requests5xx   int64
	bytesIn       int64
	bytesOut      int64
	latencyP50    int
	latencyP95    int
	latencyP99    int
}

type statusClassCounts struct {
	status2xx int64
	status3xx int64
	status4xx int64
	status5xx int64
	other     int64
}

func classifyStatusCodes(codes map[int]int64) statusClassCounts {
	var counts statusClassCounts
	for code, value := range codes {
		switch {
		case code >= 200 && code < 300:
			counts.status2xx += value
		case code >= 300 && code < 400:
			counts.status3xx += value
		case code >= 400 && code < 500:
			counts.status4xx += value
		case code >= 500 && code < 600:
			counts.status5xx += value
		default:
			counts.other += value
		}
	}
	return counts
}

func (m *MetricsService) parsePrometheusMetrics(text string) (parsedMetrics, error) {
	metrics := parsedMetrics{}
	codes := make(map[int]int64)

	// Request totals come from caddy_http_requests_total, which carries no
	// code label; status classes come from caddy_http_request_duration_seconds_count.
	for _, match := range prometheusRequestTotalPattern.FindAllStringSubmatch(text, -1) {
		if len(match) >= 2 {
			value, err := parsePrometheusInteger(match[1])
			if err != nil {
				return parsedMetrics{}, fmt.Errorf("parse request count %q: %w", match[1], err)
			}
			metrics.requestsTotal += value
		}
	}
	for _, match := range prometheusStatusCountPattern.FindAllStringSubmatch(text, -1) {
		if len(match) >= 3 {
			code, err := strconv.ParseInt(match[1], 10, 64)
			if err != nil {
				return parsedMetrics{}, fmt.Errorf("parse HTTP status code %q: %w", match[1], err)
			}
			value, err := parsePrometheusInteger(match[2])
			if err != nil {
				return parsedMetrics{}, fmt.Errorf("parse status class count %q: %w", match[2], err)
			}
			codes[int(code)] += value
		}
	}
	classified := classifyStatusCodes(codes)
	metrics.requests2xx = classified.status2xx
	metrics.requests3xx = classified.status3xx
	metrics.requests4xx = classified.status4xx
	metrics.requests5xx = classified.status5xx

	// Parse response size
	// caddy_http_response_size_bytes_sum{...}
	matches := prometheusResponseSizePattern.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			value, err := parsePrometheusInteger(match[1])
			if err != nil {
				return parsedMetrics{}, fmt.Errorf("parse response size %q: %w", match[1], err)
			}
			metrics.bytesOut += value
		}
	}

	// Parse request size
	matches = prometheusRequestSizePattern.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			value, err := parsePrometheusInteger(match[1])
			if err != nil {
				return parsedMetrics{}, fmt.Errorf("parse request size %q: %w", match[1], err)
			}
			metrics.bytesIn += value
		}
	}

	latencyP50, latencyP95, latencyP99, err := estimateLatencyPercentiles(text)
	if err != nil {
		return parsedMetrics{}, err
	}
	metrics.latencyP50, metrics.latencyP95, metrics.latencyP99 = latencyP50, latencyP95, latencyP99

	return metrics, nil
}

func parsePrometheusInteger(raw string) (int64, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || value > math.MaxInt64 || value < math.MinInt64 {
		return 0, fmt.Errorf("value is not a finite int64")
	}
	return int64(value), nil
}

// estimateLatencyPercentiles computes p50/p95/p99 in milliseconds from the
// cumulative caddy_http_request_duration_seconds_bucket histogram.
func estimateLatencyPercentiles(text string) (int, int, int, error) {
	matches := prometheusLatencyBucketPattern.FindAllStringSubmatch(text, -1)
	type bucket struct {
		le    float64
		count int64
	}
	byLE := map[float64]int64{}
	for _, m := range matches {
		le, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("parse latency bucket boundary %q: %w", m[1], err)
		}
		count, err := parsePrometheusInteger(m[2])
		if err != nil {
			return 0, 0, 0, fmt.Errorf("parse latency bucket count %q: %w", m[2], err)
		}
		if count < 0 {
			return 0, 0, 0, fmt.Errorf("latency bucket count %q is negative", m[2])
		}
		byLE[le] += count
	}
	if len(byLE) == 0 {
		return 0, 0, 0, nil
	}
	buckets := make([]bucket, 0, len(byLE))
	var total int64
	for le, count := range byLE {
		buckets = append(buckets, bucket{le, count})
		if count > total {
			total = count
		}
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].le < buckets[j].le })
	percentile := func(q float64) int {
		target := int64(math.Ceil(float64(total) * q))
		if target < 1 {
			target = 1
		}
		for _, b := range buckets {
			if b.count >= target {
				if math.IsInf(b.le, 1) {
					// The +Inf bucket only tells us the tail exists; fall back
					// to the largest finite bucket instead of a bogus value.
					if len(buckets) > 1 {
						return int(buckets[len(buckets)-2].le * 1000)
					}
					return 0
				}
				return int(b.le * 1000)
			}
		}
		return 0
	}
	return percentile(0.5), percentile(0.95), percentile(0.99), nil
}

type perHostMetrics struct {
	requests int64
	codes    map[int]int64
	bytesIn  int64
	bytesOut int64
}

// parsePerHostMetrics extracts cumulative request/byte counters grouped by
// host label so per-rule history rows can be stored alongside the global row.
func parsePerHostMetrics(text string) (map[string]*perHostMetrics, error) {
	hosts := map[string]*perHostMetrics{}
	get := func(host string) *perHostMetrics {
		h, ok := hosts[host]
		if !ok {
			h = &perHostMetrics{codes: map[int]int64{}}
			hosts[host] = h
		}
		return h
	}
	for _, m := range prometheusHostStatusPattern.FindAllStringSubmatch(text, -1) {
		if len(m) < 4 {
			continue
		}
		code, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("parse per-host HTTP status code %q: %w", m[1], err)
		}
		v, err := parsePrometheusInteger(m[3])
		if err != nil {
			return nil, fmt.Errorf("parse per-host request count %q: %w", m[3], err)
		}
		h := get(m[2])
		h.requests += v
		h.codes[code] += v
	}
	for _, m := range prometheusHostResponsePattern.FindAllStringSubmatch(text, -1) {
		v, err := parsePrometheusInteger(m[2])
		if err != nil {
			return nil, fmt.Errorf("parse per-host response size %q: %w", m[2], err)
		}
		get(m[1]).bytesOut += v
	}
	for _, m := range prometheusHostRequestSizePattern.FindAllStringSubmatch(text, -1) {
		v, err := parsePrometheusInteger(m[2])
		if err != nil {
			return nil, fmt.Errorf("parse per-host request size %q: %w", m[2], err)
		}
		get(m[1]).bytesIn += v
	}
	return hosts, nil
}

// storePerHostMetrics maps host labels to HTTP rules by domain and writes a
// cumulative history row per rule; TCP rules produce no rows because caddy-l4
// exports no per-rule traffic counters.
func (m *MetricsService) storePerHostMetrics(text string) error {
	hosts, err := parsePerHostMetrics(text)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return nil
	}
	rows, err := db.DB.Query(`SELECT caddy_id, COALESCE(domain,'') FROM lb_rules WHERE protocol='http' AND enabled=1 ORDER BY caddy_id`)
	if err != nil {
		return fmt.Errorf("query enabled HTTP rules for per-host metrics: %w", err)
	}
	defer rows.Close()
	domainToRule := map[string]string{}
	domainConflicts := map[string][]string{}
	for rows.Next() {
		var id, domains string
		if err := rows.Scan(&id, &domains); err != nil {
			return fmt.Errorf("scan enabled HTTP rule for per-host metrics: %w", err)
		}
		for _, d := range strings.Split(domains, ",") {
			if d = strings.TrimSpace(d); d != "" {
				if existingID, exists := domainToRule[d]; exists {
					if existingID != id {
						if _, recorded := domainConflicts[d]; !recorded {
							domainConflicts[d] = []string{existingID}
						}
						domainConflicts[d] = append(domainConflicts[d], id)
					}
					continue
				}
				domainToRule[d] = id
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate enabled HTTP rules for per-host metrics: %w", err)
	}
	currentConflicts := make(map[string]string, len(domainConflicts))
	type conflictLog struct {
		domain  string
		ruleIDs []string
	}
	newConflicts := make([]conflictLog, 0, len(domainConflicts))
	m.domainConflictMu.Lock()
	for domain, ruleIDs := range domainConflicts {
		fingerprint := strings.Join(ruleIDs, "\x00")
		currentConflicts[domain] = fingerprint
		if m.domainConflictFingerprints[domain] != fingerprint {
			newConflicts = append(newConflicts, conflictLog{domain: domain, ruleIDs: ruleIDs})
		}
	}
	m.domainConflictFingerprints = currentConflicts
	m.domainConflictMu.Unlock()
	for _, conflict := range newConflicts {
		log.Printf("Metrics domain conflict: domain %q maps to rules %q; keeping %q", conflict.domain, strings.Join(conflict.ruleIDs, ","), conflict.ruleIDs[0])
	}
	for host, h := range hosts {
		ruleID, ok := domainToRule[host]
		if !ok {
			if bare, _, err := net.SplitHostPort(host); err == nil {
				ruleID, ok = domainToRule[bare]
			}
		}
		if !ok {
			continue
		}
		classified := classifyStatusCodes(h.codes)
		if _, err := db.MetricsDB.Exec(`
			INSERT INTO metrics_history
			(rule_id, timestamp, requests_total, requests_2xx, requests_3xx,
			 requests_4xx, requests_5xx, bytes_in, bytes_out,
			 latency_p50, latency_p95, latency_p99)
			VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, 0, 0, 0)
		`, ruleID, h.requests, classified.status2xx, classified.status3xx, classified.status4xx, classified.status5xx, h.bytesIn, h.bytesOut); err != nil {
			return fmt.Errorf("store per-rule metrics for %s: %w", ruleID, err)
		}
	}
	return nil
}

func (m *MetricsService) cleanupHistory() {
	retentionDays := 7
	if err := db.DB.QueryRow("SELECT COALESCE(metrics_retention_days,7) FROM global_config WHERE id=1").Scan(&retentionDays); err != nil {
		return
	}
	if retentionDays < 1 {
		retentionDays = 7
	}
	if err := db.CleanupMetricsHistory(retentionDays); err != nil {
		log.Printf("Failed to clean up metrics history: %v", err)
	}
}

func (m *MetricsService) storeMetrics(metrics parsedMetrics) {
	// Store global metrics in independent metrics database
	_, err := db.MetricsDB.Exec(`
		INSERT INTO metrics_history 
		(rule_id, timestamp, requests_total, requests_2xx, requests_3xx, 
		 requests_4xx, requests_5xx, bytes_in, bytes_out, 
		 latency_p50, latency_p95, latency_p99)
		VALUES (NULL, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, metrics.requestsTotal, metrics.requests2xx, metrics.requests3xx,
		metrics.requests4xx, metrics.requests5xx, metrics.bytesIn, metrics.bytesOut,
		metrics.latencyP50, metrics.latencyP95, metrics.latencyP99)

	if err != nil {
		log.Printf("Failed to store metrics: %v, values: %d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
			err, metrics.requestsTotal, metrics.requests2xx, metrics.requests3xx,
			metrics.requests4xx, metrics.requests5xx, metrics.bytesIn, metrics.bytesOut,
			metrics.latencyP50, metrics.latencyP95, metrics.latencyP99)
	}
}

func (m *MetricsService) updateOverview(metrics parsedMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get active rules count (fast read-only query)
	// Round 35 B3: 错误必须显式处理，否则 DB 故障时 overview 三项指标静默归零。
	var activeRules, totalRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE enabled = 1").Scan(&activeRules); err != nil {
		log.Printf("updateOverview: query active rules failed: %v (keeping previous value=%d)", err, activeRules)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules").Scan(&totalRules); err != nil {
		log.Printf("updateOverview: query total rules failed: %v (keeping previous value=%d)", err, totalRules)
	}

	// 在线节点数口径与 ComputeNodeStatus 统一：nodes.status 只在注册/上报时写入、
	// 从不回写为 'offline'，按 status 字段统计会拿到陈旧值，改为动态判定——
	// 已批准且 last_seen 未超过 2×sync_interval 秒（倍率常量 nodeOfflineMultiplier 共用）。
	var onlineNodes int
	if err := db.DB.QueryRow(`
		SELECT COUNT(*) FROM nodes
		WHERE is_approved = 1
		  AND last_seen IS NOT NULL
		  AND datetime(last_seen) > datetime('now', printf('-%d seconds', ? * COALESCE((SELECT sync_interval FROM global_config WHERE id=1), 60)))
	`, nodeOfflineMultiplier).Scan(&onlineNodes); err != nil {
		log.Printf("updateOverview: query online nodes failed: %v (keeping previous value=%d)", err, onlineNodes)
	}

	var rps float64
	now := time.Now()
	if m.hasLastSample && metrics.requestsTotal >= m.lastTotal {
		if elapsed := now.Sub(m.lastSampleAt).Seconds(); elapsed > 0 {
			rps = float64(metrics.requestsTotal-m.lastTotal) / elapsed
		}
	}
	m.lastTotal = metrics.requestsTotal
	m.lastSampleAt = now
	m.hasLastSample = true

	m.overview = models.MetricsOverview{
		TotalRequests:  metrics.requestsTotal,
		RequestsPerSec: rps,
		BytesIn:        metrics.bytesIn,
		BytesOut:       metrics.bytesOut,
		Status2xx:      metrics.requests2xx,
		Status3xx:      metrics.requests3xx,
		Status4xx:      metrics.requests4xx,
		Status5xx:      metrics.requests5xx,
		LatencyP50:     metrics.latencyP50,
		LatencyP95:     metrics.latencyP95,
		LatencyP99:     metrics.latencyP99,
		ActiveRules:    activeRules,
		TotalRules:     totalRules,
		OnlineNodes:    onlineNodes,
	}
}

func (m *MetricsService) GetOverview() models.MetricsOverview {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.overview
}
