package handlers

import (
	"encoding/json"
	"io"
	"lazy-balancer-v2/internal/apimsg"
	"net/http"
	"net/url"
	"time"

	"lazy-balancer-v2/internal/models"

	"github.com/gin-gonic/gin"
)

// humanLiveChallengeSession Caddy lbhuman 运行态行；rule_name/policy_name 由
// LB 侧按 rule_id 就地补全（插件只知道 caddy_id，不读主库）。
type humanLiveChallengeSession struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	LastResult  string `json:"last_result"`
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	PolicyName  string `json:"policy_name"`
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

type humanLiveChallengePayload struct {
	NowMS       int64                       `json:"now_ms"`
	ActiveCount int                         `json:"active_count"`
	Sessions    []humanLiveChallengeSession `json:"sessions"`
}

// GetHumanLiveChallenges GET /security/human/live?scope=active|recent：
// 代理 Caddy admin /lb/human/live。scope 原样转发；插件端点缺失（旧二进制）
// 返回空运行态而非 5xx，与 /security/human/stats 同容错口径。
func (h *Handlers) GetHumanLiveChallenges(c *gin.Context) {
	scope := c.DefaultQuery("scope", "active")
	if scope != "active" && scope != "recent" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_3d85d047"), MessageKey: "k_3d85d047"})
		return
	}
	target := h.cfg.CaddyAdminURL + "/lb/human/live?scope=" + url.QueryEscape(scope)
	out := humanLiveChallengePayload{Sessions: []humanLiveChallengeSession{}}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(target)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
		}
	}
	if out.Sessions == nil {
		out.Sessions = []humanLiveChallengeSession{}
	}
	enrichHumanLiveAttribution(out.Sessions)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: out})
}

// enrichHumanLiveAttribution 按 rule_id 批量补全规则/阶段 2 策略名。
func enrichHumanLiveAttribution(rows []humanLiveChallengeSession) {
	if len(rows) == 0 {
		return
	}
	cache := make(map[string]humanEventAttribution, len(rows))
	for i := range rows {
		ruleID := rows[i].RuleID
		if ruleID == "" {
			continue
		}
		attr, ok := cache[ruleID]
		if !ok {
			attr = lookupHumanEventAttribution(ruleID)
			cache[ruleID] = attr
		}
		rows[i].RuleName = attr.ruleName
		rows[i].PolicyName = attr.policyName
	}
}
