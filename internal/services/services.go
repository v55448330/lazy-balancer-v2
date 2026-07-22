package services

import (
	"math"
	"sort"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
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
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collect()
		case <-m.stopCh:
			return
		}
	}
}

func (m *MetricsService) Stop() {
	close(m.stopCh)
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

	metrics := m.parsePrometheusMetrics(string(body))
	m.storeMetrics(metrics)
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

func (m *MetricsService) parsePrometheusMetrics(text string) parsedMetrics {
	metrics := parsedMetrics{}

	// Parse request counters
	// caddy_http_requests_total{code="200",...}
	re := regexp.MustCompile(`caddy_http_requests_total\{[^}]*code="(\d+)".*?\} (\d+)`)
	matches := re.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			code, _ := strconv.ParseInt(match[1], 10, 64)
			value, _ := strconv.ParseInt(match[2], 10, 64)
			metrics.requestsTotal += value
			if code >= 200 && code < 300 {
				metrics.requests2xx += value
			} else if code >= 300 && code < 400 {
				metrics.requests3xx += value
			} else if code >= 400 && code < 500 {
				metrics.requests4xx += value
			} else if code >= 500 {
				metrics.requests5xx += value
			}
		}
	}

	// Parse response size
	// caddy_http_response_size_bytes_sum{...}
	reSize := regexp.MustCompile(`caddy_http_response_size_bytes_sum.*?\} (\d+\.?\d*)`)
	matches = reSize.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			value, _ := strconv.ParseInt(match[1], 10, 64)
			metrics.bytesOut += value
		}
	}

	// Parse request size
	reReqSize := regexp.MustCompile(`caddy_http_request_size_bytes_sum.*?\} (\d+\.?\d*)`)
	matches = reReqSize.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			value, _ := strconv.ParseInt(match[1], 10, 64)
			metrics.bytesIn += value
		}
	}

	metrics.latencyP50, metrics.latencyP95, metrics.latencyP99 = estimateLatencyPercentiles(text)

	return metrics
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
				return int(b.le * 1000)
			}
		}
		return 0
	}
	return percentile(0.5), percentile(0.95), percentile(0.99)
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

func (m *MetricsService) GetHistory(limit int) []models.MetricsHistory {
	rows, err := db.MetricsDB.Query(`
		SELECT id, rule_id, timestamp, requests_total, requests_2xx, requests_3xx,
		       requests_4xx, requests_5xx, bytes_in, bytes_out,
		       latency_p50, latency_p95, latency_p99
		FROM metrics_history
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		log.Printf("Failed to query metrics history: %v", err)
		return nil
	}
	defer rows.Close()

	var history []models.MetricsHistory
	for rows.Next() {
		var h models.MetricsHistory
		if err := rows.Scan(&h.ID, &h.RuleID, &h.Timestamp,
			&h.RequestsTotal, &h.Requests2xx, &h.Requests3xx,
			&h.Requests4xx, &h.Requests5xx,
			&h.BytesIn, &h.BytesOut,
			&h.LatencyP50, &h.LatencyP95, &h.LatencyP99); err != nil {
			continue
		}
		history = append(history, h)
	}
	return history
}
