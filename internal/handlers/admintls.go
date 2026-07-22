package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type adminTLSCertInfo struct {
	Domain   string `json:"domain"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	DaysLeft int    `json:"days_left"`
}

func parseAdminTLSCertInfo(certPEM string) (*adminTLSCertInfo, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errInvalidCert
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	domain := cert.Subject.CommonName
	if len(cert.DNSNames) > 0 {
		domain = strings.Join(cert.DNSNames, ", ")
	}
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		issuer = cert.Issuer.String()
	}
	info := &adminTLSCertInfo{
		Domain:   domain,
		Issuer:   issuer,
		NotAfter: cert.NotAfter.In(services.CurrentLocation()).Format("2006-01-02 15:04:05"),
		DaysLeft: int(time.Until(cert.NotAfter).Hours() / 24),
	}
	return info, nil
}

var errInvalidCert = fmtErrorf("无效的证书 PEM")

func fmtErrorf(msg string) error { return &adminTLSError{msg} }

type adminTLSError struct{ msg string }

func (e *adminTLSError) Error() string { return e.msg }

// InspectAdminTLSCert parses uploaded cert/key files without saving, so the
// UI can show what will be installed before the user confirms.
func (h *Handlers) InspectAdminTLSCert(c *gin.Context) {
	certPEM, keyPEM, err := readAdminTLSFiles(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书与私钥不匹配: " + err.Error()})
		return
	}
	info, err := parseAdminTLSCertInfo(certPEM)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书解析失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

func readAdminTLSFiles(c *gin.Context) (string, string, error) {
	read := func(field string) (string, error) {
		f, _, err := c.Request.FormFile(field)
		if err != nil {
			return "", &adminTLSError{"请上传" + field + " 文件"}
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 1<<20))
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	certPEM, err := read("cert_file")
	if err != nil {
		return "", "", err
	}
	keyPEM, err := read("key_file")
	if err != nil {
		return "", "", err
	}
	return certPEM, keyPEM, nil
}

func (h *Handlers) GetAdminTLS(c *gin.Context) {
	cfg := services.LoadAdminTLSConfig()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"enabled":      cfg.Enabled,
		"mode":         cfg.Mode,
		"port":         cfg.Port,
		"acme_rule_id": cfg.ACMERuleID,
		"has_uploaded": cfg.Cert != "" && cfg.Key != "",
		"restart_hint": true,
	}})
}

func (h *Handlers) UpdateAdminTLS(c *gin.Context) {
	c.Request.ParseMultipartForm(2 << 20)
	form := c.Request.Form

	current := services.LoadAdminTLSConfig()
	enabled := current.Enabled
	if v := form.Get("enabled"); v != "" {
		enabled = v == "true" || v == "1"
	}
	mode := current.Mode
	if v := form.Get("mode"); v != "" {
		mode = v
	}
	cert, key, ruleID := current.Cert, current.Key, current.ACMERuleID
	port := h.cfg.Port
	if mode == "upload" {
		certPEM, keyPEM, err := readAdminTLSFiles(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		cert, key = certPEM, keyPEM
	}

	if enabled {
		if mode != "selfsigned" && mode != "upload" && mode != "acme" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的证书来源"})
			return
		}
		probe := services.AdminTLSConfig{Enabled: true, Mode: mode, Cert: cert, Key: key, ACMERuleID: ruleID, Port: port}
		if _, err := probe.ResolveCertificate(h.cfg.DataDir); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书不可用: " + err.Error()})
			return
		}
	}

	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=?, admin_tls_mode=?, admin_tls_cert=?, admin_tls_key=?, admin_tls_acme_rule_id=?, admin_tls_port=?, updated_at=datetime('now') WHERE id=1`,
		enabled, mode, cert, key, ruleID, port); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 HTTPS 配置失败: " + err.Error()})
		return
	}

	recordAudit(c, "更新", "HTTPS 访问", services.FormatAuditDetail(
		map[bool]string{true: "启用", false: "禁用"}[enabled],
		"证书来源："+mode,
		services.AuditResultPart("success"),
	))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已保存，请在系统信息中重启服务生效"})
}
