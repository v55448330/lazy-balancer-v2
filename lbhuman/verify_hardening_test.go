package lbhuman

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// JS PoW 校验端点与滑块同口径：匿名端点请求体硬上限 64KiB，超限 400，
// 且不得在拒绝前消费一次性 token（否则攻击者可用超大 body 烧掉他人挑战）。
func TestServeJSVerify_oversizedBodyRejected(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "js", RuleID: "lb-js-body", Secret: "test-secret", TTLMinutes: 30}}
	token := issueChallengeToken()
	// token 位于 body 前部：旧实现无帽时 ParseForm 会读到它并消费。
	body := "token=" + token + "&nonce=" + strings.Repeat("9", 70<<10)
	req := httptest.NewRequest(http.MethodPost, humanVerifyPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.serveJSVerify(rec, req, "203.0.113.230")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized JS verify body status=%d, want 400", rec.Code)
	}
	challengeTokensMu.Lock()
	tok, ok := challengeTokens[token]
	challengeTokensMu.Unlock()
	if !ok || tok.used {
		t.Fatal("oversized body must be rejected before one-time token consumption")
	}
}

// 边界形状：合法小 body 的校验路径不受体帽影响（错误 nonce 仍走正常失败）。
func TestServeJSVerify_smallBodyStillParses(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "js", RuleID: "lb-js-small", Secret: "test-secret", TTLMinutes: 30}}
	token := issueChallengeToken()
	req := httptest.NewRequest(http.MethodPost, humanVerifyPath, strings.NewReader("token="+token+"&nonce=0"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.serveJSVerify(rec, req, "203.0.113.231")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong-nonce verify status=%d, want 400", rec.Code)
	}
	challengeTokensMu.Lock()
	tok := challengeTokens[token]
	challengeTokensMu.Unlock()
	if !tok.used {
		t.Fatal("small valid-shape body must consume token (normal failure path intact)")
	}
}

// 滑块 attempts 读取必须持锁：同一拼图的并发消耗（锁内自增/删除）与
// attempts_left 响应组装（锁外读 p.attempts）不得数据竞争（-race 下跑）。
func TestServeSliderVerify_attemptsLeftConcurrent(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-race", Secret: "test-secret", TTLMinutes: 30}}
	pid := issueSliderPuzzle(t, h)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for range 6 {
				rec := postSliderVerify(t, h, pid, 1) // 远离缺口，必失败
				if rec.Code != http.StatusBadRequest {
					t.Errorf("g%d status=%d, want 400", g, rec.Code)
					return
				}
				var payload struct {
					OK           bool `json:"ok"`
					Retryable    bool `json:"retryable"`
					AttemptsLeft int  `json:"attempts_left"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
					t.Errorf("g%d decode: %v", g, err)
					return
				}
				if payload.AttemptsLeft < 0 || payload.AttemptsLeft > sliderMaxAttempts {
					t.Errorf("g%d attempts_left=%d out of range", g, payload.AttemptsLeft)
					return
				}
				if payload.Retryable != (payload.AttemptsLeft > 0) {
					t.Errorf("g%d retryable=%v inconsistent with left=%d", g, payload.Retryable, payload.AttemptsLeft)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
