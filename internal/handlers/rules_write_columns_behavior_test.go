package handlers

// UpdateRule 的 SET 列清单虽由文本守卫与单源 specs 对账，但「列名在文本里」
// 不等于「值与列一一对应」——args 追加顺序写错（错位/漏 append）时列集合仍
// 完全相等，文本守卫给绿而落库值被写进相邻列。本钉测以行为口径验证三种
// 请求形态的终态值：同协议改名（条件列 tls_* 不写入、存量材料存活）、
// 显式提交证书材料（条件列写入新值）、协议切 TCP（条件列按归一值写入）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateRuleWriteColumns_valuesAlignWithColumns(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_wc_http", "wc-http", "wc.example.test", 18031, true, "manual", false)
	seedAuditUpstream(t, "lb_wc_http")
	if _, err := db.DB.Exec(`UPDATE lb_rules SET tls_cert='CERT-OLD', tls_key='KEY-OLD',
		description='d-old', log_enabled=1, health_check_host='hc.example.test',
		dns_family='ipv6', block_page_stage1_id=7, block_page_stage1_status=403,
		host_header='hh.example.test' WHERE caddy_id='lb_wc_http'`); err != nil {
		t.Fatalf("seed stored values: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("user_id", 42) })
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	put := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_wc_http", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	type storedRow struct {
		Name, Description, Protocol, Domain, Strategy string
		TLSCert, TLSKey, HealthCheckHost, DnsFamily   string
		HostHeader                                    string
		LogEnabled                                    bool
		Stage1ID, Stage1Status                        int
		UpdatedBy                                     int64
	}
	readRow := func() storedRow {
		var row storedRow
		if err := db.DB.QueryRow(`SELECT name, COALESCE(description,''), protocol, COALESCE(domain,''),
			COALESCE(strategy,''), COALESCE(tls_cert,''), COALESCE(tls_key,''),
			COALESCE(health_check_host,''), COALESCE(dns_family,''), COALESCE(host_header,''),
			COALESCE(log_enabled,0), COALESCE(block_page_stage1_id,0), COALESCE(block_page_stage1_status,0),
			COALESCE(updated_by,0)
			FROM lb_rules WHERE caddy_id='lb_wc_http'`).Scan(
			&row.Name, &row.Description, &row.Protocol, &row.Domain, &row.Strategy,
			&row.TLSCert, &row.TLSKey, &row.HealthCheckHost, &row.DnsFamily, &row.HostHeader,
			&row.LogEnabled, &row.Stage1ID, &row.Stage1Status, &row.UpdatedBy); err != nil {
			t.Fatalf("read stored row: %v", err)
		}
		return row
	}

	// 形态一：HTTP 同协议只改名——显式列写入、条件列（tls_cert/tls_key）不参与
	// SET，存量材料必须原样存活；尾部 updated_by 必须等于上下文用户（args 对齐）。
	rec := put(`{"name":"wc-renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename status=%d body=%s", rec.Code, rec.Body.String())
	}
	row := readRow()
	if row.Name != "wc-renamed" || row.Description != "d-old" || row.TLSCert != "CERT-OLD" || row.TLSKey != "KEY-OLD" {
		t.Fatalf("rename row=%+v, want name changed / 存量材料与描述保留", row)
	}
	if !row.LogEnabled || row.HealthCheckHost != "hc.example.test" || row.Stage1ID != 7 || row.Stage1Status != 403 {
		t.Fatalf("rename row=%+v, want 无关列原值保留", row)
	}
	if row.UpdatedBy != 42 {
		t.Fatalf("updated_by=%d, want 42（尾参数错位）", row.UpdatedBy)
	}

	// 形态二：显式提交证书材料——条件列写入新值，其余列沿用。
	certPEM, keyPEM := testCertPEMShared(t, "wc.example.test")
	payload, err := json.Marshal(map[string]any{"tls_cert": certPEM, "tls_key": keyPEM})
	if err != nil {
		t.Fatalf("marshal cert payload: %v", err)
	}
	rec = put(string(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("cert material status=%d body=%s", rec.Code, rec.Body.String())
	}
	row = readRow()
	if row.TLSCert != certPEM || row.TLSKey != keyPEM {
		t.Fatalf("tls material not written as submitted (cert_len=%d key_len=%d)", len(row.TLSCert), len(row.TLSKey))
	}
	if row.Name != "wc-renamed" || !row.LogEnabled {
		t.Fatalf("cert material row=%+v, want 无关列沿用", row)
	}

	// 形态三：协议切 TCP——条件列与 TCP 归一列都必须以归一值落库，
	// 且与相邻列不错位（domain/log_enabled/dns_family/host_header/health_check_host/阶段页）。
	rec = put(`{"protocol":"tcp","listen_port":18032,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("switch to tcp status=%d body=%s", rec.Code, rec.Body.String())
	}
	row = readRow()
	if row.Protocol != "tcp" || row.Domain != "" || row.LogEnabled || row.DnsFamily != "ipv4" ||
		row.HostHeader != "" || row.HealthCheckHost != "" {
		t.Fatalf("tcp row=%+v, want domain/log/dns_family/host_header/health_check_host 归一", row)
	}
	if row.TLSCert != "" || row.TLSKey != "" {
		t.Fatalf("tcp row cert/key 未清空（条件列未按 TCP 写入）")
	}
	// 阶段页列已停用（写侧停写）：任意协议更新都不触碰，存量值原样保留。
	if row.Stage1ID != 7 || row.Stage1Status != 403 {
		t.Fatalf("tcp stage1=(%d,%d), want preserved 7/403（写侧停写）", row.Stage1ID, row.Stage1Status)
	}
	if row.Strategy != "weighted_round_robin" || row.Name != "wc-renamed" {
		t.Fatalf("tcp row=%+v, want strategy 默认与名称沿用", row)
	}
}
