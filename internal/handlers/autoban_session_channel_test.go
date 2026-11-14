package handlers

// ban_effective 双通道钉测：
//   - IP 级通道：预置名单被启用 deny 策略引用（现有判据，真值表回归）；
//   - 会话级通道：挑战链装配（lb_human 渲染面存在）∧ 会话封禁非空——
//     NAT 态会话执法不经 IP 名单，IP 通道不生效时会话通道可独立生效；
//   - /status 披露双通道状态（ban_effective_ip / ban_effective_session /
//     session_bans），ban_effective=两通道析取（黄条判据不变）；
//   - 挑战链未装配时会话封禁不构成生效（无执法点，封禁不拦截）。

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// seedSessionBanHumanChain 装配「启用 + human_verify_mode=force」策略并绑定到
// 「启用 + 至少一个启用上游」的 HTTP 规则——lb_human 渲染面存在的库形态
// （buildHumanHandler 的 mode!=off 门 + 渲染层规则/上游门）。
func seedSessionBanHumanChain(t *testing.T) {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,enabled,human_verify_mode) VALUES ('session-ban-human',1,'force')`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_session_ban','session-ban','http','session-ban.test',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_session_ban','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_session_ban',?)`, policyID); err != nil {
		t.Fatal(err)
	}
}

func autobanDualChannelStatus(t *testing.T, router *gin.Engine) (banEffective, ipEffective, sessionEffective bool, sessionBans int) {
	t.Helper()
	rec := getRequest(t, router, "/security/autoban/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data struct {
			BanEffective        bool `json:"ban_effective"`
			BanEffectiveIP      bool `json:"ban_effective_ip"`
			BanEffectiveSession bool `json:"ban_effective_session"`
			SessionBans         int  `json:"session_bans"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	d := payload.Data
	return d.BanEffective, d.BanEffectiveIP, d.BanEffectiveSession, d.SessionBans
}

// Given 挑战链已装配 + 会话封禁在役；IP 名单为空（无 IP 引用面）。
// When GET /security/autoban/status。
// Then IP 通道不生效、会话通道生效，ban_effective=true（析取），
// session_bans 披露生效会话封禁数。
func TestAutobanStatus_sessionChannelEffectiveWithoutIPList(t *testing.T) {
	router := newAutobanTestEnv(t)
	seedSessionBanHumanChain(t)
	services.AutobanSeedSessionBanForTest("203.0.113.50|c:evil", time.Hour)
	t.Cleanup(services.AutobanResetSessionBansForTest)

	effective, ipEff, sessionEff, bans := autobanDualChannelStatus(t, router)
	if ipEff {
		t.Fatal("空名单无 deny 引用，IP 通道不得生效")
	}
	if !sessionEff {
		t.Fatal("挑战链装配 + 会话封禁非空，会话通道必须生效")
	}
	if !effective {
		t.Fatal("ban_effective 必须是双通道析取（会话通道独立生效）")
	}
	if bans != 1 {
		t.Fatalf("session_bans=%d, want 1", bans)
	}
}

// Given 会话封禁在役，但无任何启用人机验证的策略（挑战链未装配）。
// When GET /security/autoban/status。
// Then 会话通道不生效（无 lb_human 执法点，封禁不产生拦截）。
func TestAutobanStatus_sessionChannelRequiresChallengeChain(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.AutobanSeedSessionBanForTest("203.0.113.51|c:evil", time.Hour)
	t.Cleanup(services.AutobanResetSessionBansForTest)

	effective, ipEff, sessionEff, _ := autobanDualChannelStatus(t, router)
	if sessionEff || effective || ipEff {
		t.Fatalf("挑战链未装配时会话通道不得生效: effective=%v ip=%v session=%v", effective, ipEff, sessionEff)
	}
}

// Given 会话封禁全部到期（执法点已自动解封）。
// When GET /security/autoban/status。
// Then 会话通道不生效、session_bans=0（与执法面同口径，不虚报）。
func TestAutobanStatus_expiredSessionBansNotEffective(t *testing.T) {
	router := newAutobanTestEnv(t)
	seedSessionBanHumanChain(t)
	services.AutobanSeedSessionBanForTest("203.0.113.52|c:evil", -time.Minute)
	t.Cleanup(services.AutobanResetSessionBansForTest)

	effective, _, sessionEff, bans := autobanDualChannelStatus(t, router)
	if sessionEff || effective {
		t.Fatal("到期会话封禁不得构成生效")
	}
	if bans != 0 {
		t.Fatalf("session_bans=%d, want 0（到期条目不计）", bans)
	}
}

// Given IP 通道生效（deny 引用 + 未到期条目），会话封禁为空。
// When GET /security/autoban/status。
// Then IP 通道生效、会话通道不生效，ban_effective=true（现有黄条判据回归）。
func TestAutobanStatus_ipChannelUnchangedBySessionSplit(t *testing.T) {
	router := newAutobanTestEnv(t)
	seedAutobanListEntries(t, `[{"value":"198.51.100.8"}]`)
	listID := autobanPresetID(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,enabled,ip_acl_enabled,ip_acl_mode,ip_acl_list_refs) VALUES ('ip-channel',1,1,'deny',?)`, "["+strconv.Itoa(listID)+"]")
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_ip_channel','ip-channel','http','ip-channel.test',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_ip_channel','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_ip_channel',?)`, policyID); err != nil {
		t.Fatal(err)
	}

	effective, ipEff, sessionEff, bans := autobanDualChannelStatus(t, router)
	if !ipEff || !effective {
		t.Fatalf("IP 通道判据必须保持现有行为: effective=%v ip=%v", effective, ipEff)
	}
	if sessionEff || bans != 0 {
		t.Fatalf("无会话封禁时会话通道不得生效: session=%v bans=%d", sessionEff, bans)
	}
}
