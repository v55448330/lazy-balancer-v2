package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math"
	"net/http"
	"os"
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
	Expired  bool   `json:"expired"`
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
	remaining := time.Until(cert.NotAfter)
	daysLeft := int(math.Floor(remaining.Hours() / 24))
	expired := remaining <= 0
	if !expired {
		daysLeft = int(math.Ceil(remaining.Hours() / 24))
	}
	info := &adminTLSCertInfo{
		Domain:   domain,
		Issuer:   issuer,
		NotAfter: cert.NotAfter.In(services.CurrentLocation()).Format("2006-01-02 15:04:05"),
		DaysLeft: daysLeft,
		Expired:  expired,
	}
	return info, nil
}

func validateAdminTLSCertPeriod(certPEM string, now time.Time) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errInvalidCert
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if now.Before(cert.NotBefore) {
		return fmtErrorf("证书尚未生效，生效时间：" + cert.NotBefore.In(services.CurrentLocation()).Format("2006-01-02 15:04:05"))
	}
	if !now.Before(cert.NotAfter) {
		return fmtErrorf("证书已过期，过期时间：" + cert.NotAfter.In(services.CurrentLocation()).Format("2006-01-02 15:04:05"))
	}
	return nil
}

var errInvalidCert = fmtErrorf("无效的证书 PEM")

// validateAdminTLSConfigValues 校验启用态管理面板 HTTPS 配置形态：mode 白名单
// （selfsigned/upload）+ upload 模式证书私钥配对与有效期（与 UpdateAdminTLS
// 同口径）。R55 C-4：v2 备份导入写 admin_tls_* 复用本门——坏配置落库会使下次
// 启动 ResolveCertificate 失败即进程退出（崩溃循环）。
func validateAdminTLSConfigValues(cfg services.AdminTLSConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Mode != "selfsigned" && cfg.Mode != "upload" {
		return fmtErrorf("无效的证书来源：当前仅支持自签名或上传证书")
	}
	if cfg.Mode == "upload" {
		if _, err := tls.X509KeyPair([]byte(cfg.Cert), []byte(cfg.Key)); err != nil {
			return fmtErrorf("证书与私钥不匹配: " + err.Error())
		}
		if err := validateAdminTLSCertPeriod(cfg.Cert, time.Now()); err != nil {
			return err
		}
	}
	return nil
}

func fmtErrorf(msg string) error { return &adminTLSError{msg} }

type adminTLSError struct{ msg string }

func (e *adminTLSError) Error() string { return e.msg }

var exitProcess = os.Exit

// InspectAdminTLSCert parses uploaded cert/key files without saving, so the
// UI can show what will be installed before the user confirms.
func (h *Handlers) InspectAdminTLSCert(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
	certPEM, keyPEM, err := readAdminTLSFiles(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书与私钥不匹配: " + err.Error()})
		return
	}
	if err := validateAdminTLSCertPeriod(certPEM, time.Now()); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
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
	resp := gin.H{
		"enabled": cfg.Enabled,
		"mode":    cfg.Mode,
	}
	if cfg.Cert != "" {
		if info, err := parseAdminTLSCertInfo(cfg.Cert); err == nil {
			resp["cert_info"] = info
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: resp})
}

func (h *Handlers) UpdateAdminTLS(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
	if err := c.Request.ParseMultipartForm(2 << 20); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "表单解析失败: " + err.Error()})
		return
	}
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
	cert, key := current.Cert, current.Key
	uploadedCertificate := false
	if mode == "upload" {
		certFiles := c.Request.MultipartForm.File["cert_file"]
		keyFiles := c.Request.MultipartForm.File["key_file"]
		if len(certFiles) > 0 || len(keyFiles) > 0 {
			certPEM, keyPEM, err := readAdminTLSFiles(c)
			if err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
				return
			}
			cert, key = certPEM, keyPEM
			uploadedCertificate = true
		}
	}

	if enabled {
		if mode != "selfsigned" && mode != "upload" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的证书来源：当前仅支持自签名或上传证书"})
			return
		}
		probe := services.AdminTLSConfig{Enabled: true, Mode: mode, Cert: cert, Key: key}
		if _, err := probe.ResolveCertificate(h.cfg.DataDir); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书不可用: " + err.Error()})
			return
		}
	}
	if mode == "upload" && (enabled || uploadedCertificate) {
		if _, err := tls.X509KeyPair([]byte(cert), []byte(key)); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书与私钥不匹配: " + err.Error()})
			return
		}
		if err := validateAdminTLSCertPeriod(cert, time.Now()); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=?, admin_tls_mode=?, admin_tls_cert=?, admin_tls_key=?, updated_at=datetime('now') WHERE id=1`,
		enabled, mode, cert, key); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 HTTPS 配置失败: " + err.Error()})
		return
	}

	recordAudit(c, "更新", "基础设置", services.FormatAuditDetail(
		map[bool]string{true: "启用", false: "禁用"}[enabled],
		"证书来源："+mode,
		services.AuditResultPart("success"),
	))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已保存，服务正在重启以应用 HTTPS 配置"})
	go func() {
		time.Sleep(500 * time.Millisecond)
		exitProcess(0)
	}()
}
