package handlers

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
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

// adminTLSInput 抹平管理面板 HTTPS 入参的两种形态：multipart 表单（面板 UI
// 文件上传）与 JSON 对象（MCP 转发等程序化通道——forward() 只发
// application/json）。字段名与表单一致（enabled/mode/cert_file/key_file），
// JSON 通道的 cert_file/key_file 为 PEM 字符串；两条通道共用完全相同的
// 校验与落盘链路。
type adminTLSInput struct {
	c *gin.Context // multipart 通道：经 FormFile 读取上传文件

	jsonMode     bool
	enabledValue string // 归一化为与表单 Get 同构的字符串；""=未提交
	modeValue    string // ""=未提交
	certValue    string // JSON 通道提交的证书 PEM
	keyValue     string // JSON 通道提交的私钥 PEM
}

// decodeAdminTLSInput 解析请求入参：Content-Type 为 multipart 表单时走原
// multipart 路径（含 2 MiB 上限与原错误文案）；否则嗅探 body 为 JSON 对象
// （含显式 application/json）时走 JSON 路径；其余请求回落 multipart 解析，
// 行为与仅支持表单时一致。
func decodeAdminTLSInput(c *gin.Context) (*adminTLSInput, error) {
	if !strings.Contains(c.GetHeader("Content-Type"), "multipart/form-data") {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return nil, fmtErrorf("请求体读取失败: " + err.Error())
		}
		if bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("{")) {
			return parseAdminTLSJSONInput(body)
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
	}
	if err := c.Request.ParseMultipartForm(2 << 20); err != nil {
		return nil, fmtErrorf("表单解析失败: " + err.Error())
	}
	return &adminTLSInput{
		c:            c,
		enabledValue: c.Request.Form.Get("enabled"),
		modeValue:    c.Request.Form.Get("mode"),
	}, nil
}

func parseAdminTLSJSONInput(body []byte) (*adminTLSInput, error) {
	var req struct {
		Enabled  json.RawMessage `json:"enabled"`
		Mode     string          `json:"mode"`
		CertFile string          `json:"cert_file"`
		KeyFile  string          `json:"key_file"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmtErrorf("JSON 解析失败: " + err.Error())
	}
	input := &adminTLSInput{
		jsonMode:  true,
		modeValue: req.Mode,
		certValue: req.CertFile,
		keyValue:  req.KeyFile,
	}
	// enabled 归一化为字符串（bool → "true"/"false"，字符串原样），使后续
	// 「"true"或"1"」判定与 multipart 通道完全同语义；null/缺省=未提交。
	if len(req.Enabled) > 0 && string(req.Enabled) != "null" {
		var boolValue bool
		if err := json.Unmarshal(req.Enabled, &boolValue); err == nil {
			input.enabledValue = strconv.FormatBool(boolValue)
		} else {
			var stringValue string
			if err := json.Unmarshal(req.Enabled, &stringValue); err == nil {
				input.enabledValue = stringValue
			} else {
				return nil, fmtErrorf("enabled 字段须为布尔或字符串")
			}
		}
	}
	return input, nil
}

// hasUploadPayload 报告本次请求是否携带新证书材料（仅 upload 模式读取）。
func (in *adminTLSInput) hasUploadPayload() bool {
	if in.jsonMode {
		return in.certValue != "" || in.keyValue != ""
	}
	return len(in.c.Request.MultipartForm.File["cert_file"]) > 0 ||
		len(in.c.Request.MultipartForm.File["key_file"]) > 0
}

// certificatePair 读取证书/私钥 PEM：multipart 通道读上传文件（单文件 1 MiB
// 上限与原 readAdminTLSFiles 一致），JSON 通道取 PEM 字符串字段。
func (in *adminTLSInput) certificatePair() (string, string, error) {
	if in.jsonMode {
		if in.certValue == "" {
			return "", "", fmtErrorf("缺少 cert_file 字段（PEM 字符串）")
		}
		if in.keyValue == "" {
			return "", "", fmtErrorf("缺少 key_file 字段（PEM 字符串）")
		}
		return in.certValue, in.keyValue, nil
	}
	return readAdminTLSFiles(in.c)
}

var exitProcess = os.Exit

// InspectAdminTLSCert parses uploaded cert/key files without saving, so the
// UI can show what will be installed before the user confirms.
func (h *Handlers) InspectAdminTLSCert(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
	input, err := decodeAdminTLSInput(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	certPEM, keyPEM, err := input.certificatePair()
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
	input, err := decodeAdminTLSInput(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	current := services.LoadAdminTLSConfig()
	enabled := current.Enabled
	if v := input.enabledValue; v != "" {
		enabled = v == "true" || v == "1"
	}
	mode := current.Mode
	if v := input.modeValue; v != "" {
		mode = v
	}
	cert, key := current.Cert, current.Key
	uploadedCertificate := false
	if mode == "upload" && input.hasUploadPayload() {
		certPEM, keyPEM, err := input.certificatePair()
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		cert, key = certPEM, keyPEM
		uploadedCertificate = true
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
	// M22：改走统一重启触发器（restartProcess，见 system.go）——与集群同步的
	// Admin TLS 热切换同一优雅停机信号；测试环境回退 exitProcess。
	restartProcess()
}
