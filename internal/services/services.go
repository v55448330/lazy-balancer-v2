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

// MetricsService collects and stores metrics from Caddy
type MetricsService struct {
	metricsURL    string
	interval      int
	client        *http.Client
	stopCh        chan struct{}
	stopOnce      sync.Once
	overview      models.MetricsOverview
	mu            sync.RWMutex
	lastTotal     int64
	lastSampleAt  time.Time
	hasLastSample bool
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
	reTotal := regexp.MustCompile(`caddy_http_requests_total\{[^}]*\}\s+(\S+)`)
	for _, match := range reTotal.FindAllStringSubmatch(text, -1) {
		if len(match) >= 2 {
			value, err := parsePrometheusInteger(match[1])
			if err != nil {
				return parsedMetrics{}, fmt.Errorf("parse request count %q: %w", match[1], err)
			}
			metrics.requestsTotal += value
		}
	}
	reCodes := regexp.MustCompile(`caddy_http_request_duration_seconds_count\{[^}]*code="(\d+)"[^}]*\}\s+(\S+)`)
	for _, match := range reCodes.FindAllStringSubmatch(text, -1) {
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
	reSize := regexp.MustCompile(`caddy_http_response_size_bytes_sum.*?\}\s+(\S+)`)
	matches := reSize.FindAllStringSubmatch(text, -1)
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
	reReqSize := regexp.MustCompile(`caddy_http_request_size_bytes_sum.*?\}\s+(\S+)`)
	matches = reReqSize.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			value, err := parsePrometheusInteger(match[1])
			if err != nil {
				return parsedMetrics{}, fmt.Errorf("parse request size %q: %w", match[1], err)
			}
			metrics.bytesIn += value
		}
	}

	metrics.latencyP50, metrics.latencyP95, metrics.latencyP99 = estimateLatencyPercentiles(text)

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
func estimateLatencyPercentiles(text string) (int, int, int) {
	re := regexp.MustCompile(`caddy_http_request_duration_seconds_bucket\{[^}]*le="([^"]+)"[^}]*\} (\d+)`)
	matches := re.FindAllStringSubmatch(text, -1)
	type bucket struct {
		le    float64
		count int64
	}
	byLE := map[float64]int64{}
	for _, m := range matches {
		le, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			continue
		}
		count, _ := strconv.ParseInt(m[2], 10, 64)
		byLE[le] += count
	}
	if len(byLE) == 0 {
		return 0, 0, 0
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
	return percentile(0.5), percentile(0.95), percentile(0.99)
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
	reCount := regexp.MustCompile(`caddy_http_request_duration_seconds_count\{[^}]*code="(\d+)"[^}]*host="([^"]+)"[^}]*\}\s+(\S+)`)
	for _, m := range reCount.FindAllStringSubmatch(text, -1) {
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
	reRespSize := regexp.MustCompile(`caddy_http_response_size_bytes_sum\{[^}]*host="([^"]+)"[^}]*\}\s+(\S+)`)
	for _, m := range reRespSize.FindAllStringSubmatch(text, -1) {
		v, err := parsePrometheusInteger(m[2])
		if err != nil {
			return nil, fmt.Errorf("parse per-host response size %q: %w", m[2], err)
		}
		get(m[1]).bytesOut += v
	}
	reReqSize := regexp.MustCompile(`caddy_http_request_size_bytes_sum\{[^}]*host="([^"]+)"[^}]*\}\s+(\S+)`)
	for _, m := range reReqSize.FindAllStringSubmatch(text, -1) {
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
	rows, err := db.DB.Query(`SELECT caddy_id, COALESCE(domain,'') FROM lb_rules WHERE protocol='http' AND enabled=1`)
	if err != nil {
		return fmt.Errorf("query enabled HTTP rules for per-host metrics: %w", err)
	}
	defer rows.Close()
	domainToRule := map[string]string{}
	for rows.Next() {
		var id, domains string
		if err := rows.Scan(&id, &domains); err != nil {
			return fmt.Errorf("scan enabled HTTP rule for per-host metrics: %w", err)
		}
		for _, d := range strings.Split(domains, ",") {
			if d = strings.TrimSpace(d); d != "" {
				domainToRule[d] = id
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate enabled HTTP rules for per-host metrics: %w", err)
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
	var activeRules, totalRules int
	db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE enabled = 1").Scan(&activeRules)
	db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules").Scan(&totalRules)

	// Get online nodes count
	var onlineNodes int
	db.DB.QueryRow("SELECT COUNT(*) FROM nodes WHERE status = 'online'").Scan(&onlineNodes)

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
