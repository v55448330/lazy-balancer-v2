package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 规则级阶段拦截页引用门（U1-1）：lb_rules.block_page_stage1_id /
// block_page_stage3_id 指向的页面被 DeleteSecurityBlockPage 静默删除后，
// 该规则的阶段 1/3 拦截页回落「跟随策略」或 Caddy 默认页——删除前必须
// 409 拒绝并要求先解除规则级引用（与启用策略引用门同事务；W3 N1：本门更严——
// 含禁用规则，防重启用悬空引用）。
func TestDeleteSecurityBlockPage_rejectsWhenRuleStagePageReferences(t *testing.T) {
	cases := []struct {
		name   string
		seedS1 bool
		seedS3 bool
	}{
		{"stage1 列引用", true, false},
		{"stage3 列引用", false, true},
		{"双列同时引用", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given：一个非默认拦截页面被一条规则的阶段拦截页列引用
			setupSecurityPolicyTestDB(t)
			router := newSecurityR26Router(t)
			res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default) VALUES ('规则引用页面', '<html></html>', 0)`)
			if err != nil {
				t.Fatalf("seed block page: %v", err)
			}
			pageID, err := res.LastInsertId()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,block_page_stage1_id,block_page_stage3_id)
				VALUES ('lb_stage_ref','ref','http','ref.example.test',8080,1,?,?)`,
				boolInt(tc.seedS1, pageID), boolInt(tc.seedS3, pageID)); err != nil {
				t.Fatalf("seed rule: %v", err)
			}

			// When
			recorder := deleteRequest(t, router, fmt.Sprintf("/security/block-pages/%d", pageID))

			// Then：409 拒绝、页面保留
			if recorder.Code != http.StatusConflict {
				t.Fatalf("delete status=%d body=%s, want 409", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "条规则的阶段拦截页引用") {
				t.Fatalf("body=%s, want rule-reference message", recorder.Body.String())
			}
			var pages int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE id=?", pageID).Scan(&pages); err != nil {
				t.Fatal(err)
			}
			if pages != 1 {
				t.Fatalf("block page rows=%d, want 1（被规则引用时不得删除）", pages)
			}
		})
	}
}

func boolInt(use bool, id int64) int64 {
	if use {
		return id
	}
	return 0
}

// 畸形形状：页不存在 → 404（引用门不得把 404 吞成 409/500）。
func TestDeleteSecurityBlockPage_missingPageReturns404(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityR26Router(t)

	recorder := deleteRequest(t, router, "/security/block-pages/999")

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("delete status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
}
