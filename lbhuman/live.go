package lbhuman

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// 实时挑战运行态（只存在进程内存）：发放交互挑战时登记请求上下文，
// 校验/过期推进状态；已结束会话短保留供面板查看最近结果，不落库。
const (
	challengeSessionRetention = 5 * time.Minute
	challengeSessionCap       = 200
)

const (
	challengeStatusWaiting = "waiting"
	challengeStatusPassed  = "passed"
	challengeStatusFailed  = "failed"
	challengeStatusExpired = "expired"
)

type challengeSession struct {
	ID          string
	Kind        string // slider | js
	RuleID      string
	ClientIP    string
	Method      string
	URI         string
	UserAgent   string
	IssuedAtMS  int64
	ExpiresAtMS int64
	UpdatedAtMS int64
	Attempts    int
	MaxAttempts int
	Status      string
	LastResult  string // pass | fail | ""
}

var (
	challengeSessions   = map[string]*challengeSession{}
	challengeSessionsMu sync.Mutex
)

// registerChallengeSession 登记一次交互挑战发放。ID=滑块 puzzle id / JS token，
// 与校验材料同生命周期；TTL 来自真实挑战材料（滑块 2min、JS PoW 5min）。
func registerChallengeSession(id, kind, ruleID, clientIP, method, uri, ua string, ttl time.Duration, maxAttempts int) {
	if id == "" {
		return
	}
	now := time.Now()
	s := &challengeSession{
		ID: id, Kind: kind, RuleID: ruleID, ClientIP: clientIP,
		Method: method, URI: uri, UserAgent: ua,
		IssuedAtMS: now.UnixMilli(), ExpiresAtMS: now.Add(ttl).UnixMilli(),
		UpdatedAtMS: now.UnixMilli(), MaxAttempts: maxAttempts,
		Status: challengeStatusWaiting, LastResult: "",
	}
	challengeSessionsMu.Lock()
	defer challengeSessionsMu.Unlock()
	challengeSessions[id] = s
	pruneChallengeSessionsLocked(now)
	if len(challengeSessions) <= challengeSessionCap {
		return
	}
	ids := make([]string, 0, len(challengeSessions))
	for key := range challengeSessions {
		ids = append(ids, key)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := challengeSessions[ids[i]], challengeSessions[ids[j]]
		if a.IssuedAtMS != b.IssuedAtMS {
			return a.IssuedAtMS < b.IssuedAtMS
		}
		return a.ID < b.ID
	})
	for _, key := range ids[:len(challengeSessions)-challengeSessionCap] {
		delete(challengeSessions, key)
	}
}

// pruneChallengeSessionsLocked 清理过期超过保留窗的会话（调用方持锁）。
func pruneChallengeSessionsLocked(now time.Time) {
	retentionMS := challengeSessionRetention.Milliseconds()
	for id, s := range challengeSessions {
		if now.UnixMilli()-s.ExpiresAtMS > retentionMS {
			delete(challengeSessions, id)
		}
	}
}

// markChallengeAttempt 记录一次校验尝试；非终态失败（滑块可重试）保持 waiting。
func markChallengeAttempt(id string, pass, final bool) {
	challengeSessionsMu.Lock()
	defer challengeSessionsMu.Unlock()
	s, ok := challengeSessions[id]
	if !ok || s.Status != challengeStatusWaiting {
		return
	}
	s.Attempts++
	s.UpdatedAtMS = time.Now().UnixMilli()
	if pass {
		s.LastResult = "pass"
		s.Status = challengeStatusPassed
		return
	}
	s.LastResult = "fail"
	if final {
		s.Status = challengeStatusFailed
	}
}

// markChallengeInvalid 挑战材料缺失/耗尽/过期：结束 waiting 会话。
func markChallengeInvalid(id string) {
	challengeSessionsMu.Lock()
	defer challengeSessionsMu.Unlock()
	s, ok := challengeSessions[id]
	if !ok || s.Status != challengeStatusWaiting {
		return
	}
	s.Attempts++
	s.LastResult = "fail"
	s.UpdatedAtMS = time.Now().UnixMilli()
	if time.Now().UnixMilli() > s.ExpiresAtMS {
		s.Status = challengeStatusExpired
		return
	}
	s.Status = challengeStatusFailed
}

type challengeSessionJSON struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	LastResult  string `json:"last_result"`
	RuleID      string `json:"rule_id"`
	ClientIP    string `json:"client_ip"`
	Method      string `json:"method"`
	URI         string `json:"uri"`
	UserAgent   string `json:"user_agent"`
	IssuedAtMS  int64  `json:"issued_at_ms"`
	ExpiresAtMS int64  `json:"expires_at_ms"`
	RemainingMS int64  `json:"remaining_ms"`
	Attempts    int    `json:"attempts"`
	MaxAttempts int    `json:"max_attempts"`
}

type challengeLiveJSON struct {
	NowMS       int64                  `json:"now_ms"`
	ActiveCount int                    `json:"active_count"`
	Sessions    []challengeSessionJSON `json:"sessions"`
}

// snapshotChallengeSessions 返回运行态副本；waiting 但超过 TTL 的会话按 expired 呈现。
func snapshotChallengeSessions(scope string) challengeLiveJSON {
	now := time.Now()
	nowMS := now.UnixMilli()
	challengeSessionsMu.Lock()
	pruneChallengeSessionsLocked(now)
	rows := make([]challengeSessionJSON, 0, len(challengeSessions))
	activeCount := 0
	for _, s := range challengeSessions {
		row := challengeSessionJSON{
			ID: s.ID, Kind: s.Kind, Status: s.Status, LastResult: s.LastResult,
			RuleID: s.RuleID, ClientIP: s.ClientIP, Method: s.Method, URI: s.URI,
			UserAgent: s.UserAgent, IssuedAtMS: s.IssuedAtMS, ExpiresAtMS: s.ExpiresAtMS,
			RemainingMS: s.ExpiresAtMS - nowMS, Attempts: s.Attempts, MaxAttempts: s.MaxAttempts,
		}
		if row.RemainingMS < 0 {
			row.RemainingMS = 0
		}
		if s.Status == challengeStatusWaiting {
			if row.RemainingMS > 0 {
				activeCount++
			} else {
				row.Status = challengeStatusExpired
			}
		}
		rows = append(rows, row)
	}
	challengeSessionsMu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].IssuedAtMS != rows[j].IssuedAtMS {
			return rows[i].IssuedAtMS > rows[j].IssuedAtMS
		}
		return rows[i].ID > rows[j].ID
	})
	if scope != "recent" {
		filtered := rows[:0]
		for _, row := range rows {
			if row.Status == challengeStatusWaiting && row.RemainingMS > 0 {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	return challengeLiveJSON{NowMS: nowMS, ActiveCount: activeCount, Sessions: rows}
}

// serveHumanLive GET /lb/human/live?scope=active|recent。
func serveHumanLive(w http.ResponseWriter, r *http.Request) error {
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "active"
	}
	if scope != "active" && scope != "recent" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid scope"}`))
		return nil
	}
	raw, err := json.Marshal(snapshotChallengeSessions(scope))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"encode failed"}`))
		return nil
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
	return nil
}
