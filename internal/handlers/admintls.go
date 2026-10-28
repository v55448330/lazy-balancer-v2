package handlers

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	domain := services.CertificateDomainsDisplay(cert)
	issuer := services.CertificateIssuerDisplay(cert)
	if issuer == "" {
		issuer = "-"
	}
	// 与 (services/certinfo.go)同口径向零截断——未过期 23h→0、
	// 过期 1天3h→-1;此前未过期 Ceil/已过期 Floor 与规则证书展示相差一天。
	// 表达式收敛 CertDaysRemaining 单源。
	now := time.Now()
	daysLeft := services.CertDaysRemaining(cert.NotAfter, now)
	expired := !now.Before(cert.NotAfter)
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
		return errors.New("证书尚未生效，生效时间：" + cert.NotBefore.In(services.CurrentLocation()).Format("2006-01-02 15:04:05"))
	}
	if !now.Before(cert.NotAfter) {
		return errors.New("证书已过期，过期时间：" + cert.NotAfter.In(services.CurrentLocation()).Format("2006-01-02 15:04:05"))
	}
	return nil
}

var errInvalidCert = errors.New("无效的证书 PEM")

// validateAdminTLSConfigValues 校验启用态管理面板 HTTPS 配置形态：mode 白名单
// （selfsigned/upload）+ upload 模式证书私钥配对与有效期（与 UpdateAdminTLS
// 同口径）。v2 备份导入写 admin_tls_* 复用本门——坏配置落库会使下次
// 启动 ResolveCertificate 失败即进程退出（崩溃循环）。
func validateAdminTLSConfigValues(cfg services.AdminTLSConfig) error {
	// mode 值域门与启用态无关：禁用态也不得落库白名单外值。
	if cfg.Mode != "" && cfg.Mode != "selfsigned" && cfg.Mode != "upload" {
		return errors.New("无效的证书来源：当前仅支持自签名或上传证书")
	}
	if !cfg.Enabled {
		return nil
	}
	if cfg.Mode == "" {
		return errors.New("无效的证书来源：启用时必须选择证书来源（自签名或上传证书）")
	}
	if cfg.Mode == "upload" {
		if err := validateUploadCertificatePair(cfg.Cert, cfg.Key, time.Now()); err != nil {
			return err
		}
	}
	return nil
}

// validateUploadCertificatePair 校验上传证书对：证书私钥匹配 + 有效期（未生效/
// 已过期）。validateAdminTLSConfigValues（启用态 upload）与 UpdateAdminTLS
// （禁用态但本次上传新证书材料）共用同一实现（收敛：原两处各自内联
// X509KeyPair+validateAdminTLSCertPeriod）。
func validateUploadCertificatePair(certPEM, keyPEM string, now time.Time) error {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return errors.New("证书与私钥不匹配: " + err.Error())
	}
	return validateAdminTLSCertPeriod(certPEM, now)
}

// adminTLSInput 抹平管理面板 HTTPS 入参的两种形态：multipart 表单（面板 UI
// 文件上传）与 JSON 对象（MCP 转发等程序化通道——forward() 只发
// application/json）。字段名与表单一致（enabled/mode/cert_file/key_file），
// JSON 通道的 cert_file/key_file 为 PEM 字符串；两条通道共用完全相同的
// 校验与落盘链路。
//
// 取值只认请求体：multipart 通道读 PostForm（URL query 同名参数不参与本端点
// 语义），JSON 通道读 body 字段——同一请求的 query 不得静默覆盖提交意图。
type adminTLSInput struct {
	c *gin.Context // multipart 通道：经 FormFile 读取上传文件

	jsonMode bool
	// enabledPresent 区分「未提交」与「显式空串」：空串必须走同一白名单 400，
	// 不得静默按「未提交」返回 200「配置未变更」（脚本拼模板缺值时排障误导）。
	enabledValue   string
	enabledPresent bool
	modeValue      string // ""=未提交
	certValue      string // JSON 通道提交的证书 PEM
	keyValue       string // JSON 通道提交的私钥 PEM
}

// decodeAdminTLSInput 解析请求入参：为 multipart 表单时走原
// multipart 路径（解析器内存阈值 2 MiB，超出部分落临时文件；整体体积由调用方
// MaxBytesReader 把关，错误文案维持原样）；否则嗅探 body 为 JSON 对象
// （含显式 application/json）时走 JSON 路径；其余请求回落 multipart 解析，
// 行为与仅支持表单时一致。
func decodeAdminTLSInput(c *gin.Context) (*adminTLSInput, error) {
	if !strings.Contains(c.GetHeader("Content-Type"), "multipart/form-data") {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			// %w 保留 *http.MaxBytesError 链——上层映射 413
			return nil, fmt.Errorf("请求体读取失败: %w", err)
		}
		if bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("{")) {
			return parseAdminTLSJSONInput(body)
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
	}
	if err := c.Request.ParseMultipartForm(2 << 20); err != nil {
		return nil, fmt.Errorf("表单解析失败: %w", err)
	}
	// PostForm 只含请求体字段：ParseMultipartForm 会把 URL query 合并进
	// Form 且 query 值排在前面，用 Form.Get 会让 `?enabled=false` 静默覆盖
	// 表单里的 enabled=true（落库与提交意图相反）。
	_, enabledPresent := c.Request.PostForm["enabled"]
	return &adminTLSInput{
		c:              c,
		enabledValue:   c.Request.PostForm.Get("enabled"),
		enabledPresent: enabledPresent,
		modeValue:      c.Request.PostForm.Get("mode"),
	}, nil
}

const adminTLSEnabledWhitelistMessage = "enabled 仅支持 true、1、false 或 0"

// parseAdminTLSEnabledValue 归一 enabled 取值：true/1/false/0 两种通道同一
// 白名单（multipart 表单字符串与 JSON 布尔/数值字面量归一后同域）。
func parseAdminTLSEnabledValue(value string) (string, bool) {
	switch value {
	case "true", "1", "false", "0":
		return value, true
	}
	return "", false
}

// adminTLSFileTooLargeError 单文件/单字段 1 MiB 上限的统一文案。
func adminTLSFileTooLargeError(label string) error {
	return fmt.Errorf("%s 超过 1 MiB 上限，请裁剪后重试", label)
}

func parseAdminTLSJSONInput(body []byte) (*adminTLSInput, error) {
	var req struct {
		Enabled  json.RawMessage `json:"enabled"`
		Mode     string          `json:"mode"`
		CertFile string          `json:"cert_file"`
		KeyFile  string          `json:"key_file"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errors.New("JSON 解析失败: " + err.Error())
	}
	input := &adminTLSInput{
		jsonMode:  true,
		modeValue: req.Mode,
		certValue: req.CertFile,
		keyValue:  req.KeyFile,
	}
	// enabled 归一化为字符串（bool → "true"/"false"，字符串/数值字面量原样），
	// 使后续白名单判定与 multipart 通道完全同语义；null/缺省=未提交。
	// 数值形态（1/0）经 UseNumber 保留字面量后同样交白名单——错误文案承诺的
	// true/1/false/0 取值域对两条通道一致，2/1.5 等其余数值显式 400。
	if len(req.Enabled) > 0 && string(req.Enabled) != "null" {
		input.enabledPresent = true
		dec := json.NewDecoder(bytes.NewReader(req.Enabled))
		dec.UseNumber()
		var raw any
		if err := dec.Decode(&raw); err != nil {
			return nil, errors.New("enabled 字段格式无效")
		}
		switch v := raw.(type) {
		case bool:
			input.enabledValue = strconv.FormatBool(v)
		case string:
			// 字符串原样交给 UpdateAdminTLS 的同一白名单判定（那里同时记审计
			// 「enabled 取值不在白名单」，保留可归因的失败原因）。
			input.enabledValue = v
		case json.Number:
			// 数值形态在此收口：错误文案承诺的 true/1/false/0 域对 JSON 数值
			// 同样成立，2/1.5 等其余数值显式 400。
			if _, ok := parseAdminTLSEnabledValue(v.String()); !ok {
				return nil, errors.New(adminTLSEnabledWhitelistMessage)
			}
			input.enabledValue = v.String()
		default:
			return nil, errors.New("enabled 字段须为布尔、字符串或 0/1 数值")
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
			return "", "", errors.New("缺少 cert_file 字段（PEM 字符串）")
		}
		if in.keyValue == "" {
			return "", "", errors.New("缺少 key_file 字段（PEM 字符串）")
		}
		// 单字段上限与 multipart 单文件同口径（1 MiB）：同一份材料在两条
		// 通道的接受面必须一致，超限同样显式 400 而非落到「证书与私钥不匹配」。
		if len(in.certValue) > maxAdminTLSFileBytes {
			return "", "", adminTLSFileTooLargeError("证书文件")
		}
		if len(in.keyValue) > maxAdminTLSFileBytes {
			return "", "", adminTLSFileTooLargeError("私钥文件")
		}
		return in.certValue, in.keyValue, nil
	}
	return readAdminTLSFiles(in.c)
}

// respondAdminTLSBodyError 把入参解析错误映射为响应：*http.MaxBytesError
// （整体 body 上限）→ 413，其余 → 400。UpdateAdminTLS 与 InspectAdminTLSCert
// 共用（原超限 body 恒 400，与规则域 413 口径不一致）。
func respondAdminTLSBodyError(c *gin.Context, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体超过 4 MiB 上限"})
		return
	}
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
}

// InspectAdminTLSCert parses uploaded cert/key files without saving, so the
// UI can show what will be installed before the user confirms.
func (h *Handlers) InspectAdminTLSCert(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAdminTLSBodyBytes)
	input, err := decodeAdminTLSInput(c)
	if err != nil {
		respondAdminTLSBodyError(c, err)
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

// maxAdminTLSFileBytes 证书/私钥单文件（multipart）与单字段（JSON）的共用
// 上限。整体 body 上限见 maxAdminTLSBodyBytes。
const maxAdminTLSFileBytes = 1 << 20

// maxAdminTLSBodyBytes 整体请求体上限：须容纳「证书 + 私钥各取满单字段
// 上限」的净内容（2×1 MiB）再计 multipart 边界/头与 JSON 转义开销——沿用
// 2 MiB 会让两条对外契约（单文件 1 MiB / 整体 2 MiB）在同一次提交里互相
// 否定，用户收到的是「整体超限」而非单字段归因。
const maxAdminTLSBodyBytes = 4 << 20

func readAdminTLSFiles(c *gin.Context) (string, string, error) {
	// limit+1 探测：超限必须显式 400——静默截断后的 PEM 进入
	// tls.X509KeyPair/证书解析只会得到「证书与私钥不匹配」这类误导性材料
	// 错误，用户无从知道是大小超限。
	read := func(field, label string) (string, error) {
		f, _, err := c.Request.FormFile(field)
		if err != nil {
			return "", errors.New("请上传" + field + " 文件")
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxAdminTLSFileBytes+1))
		if err != nil {
			return "", err
		}
		if len(data) > maxAdminTLSFileBytes {
			return "", adminTLSFileTooLargeError(label)
		}
		return string(data), nil
	}
	certPEM, err := read("cert_file", "证书文件")
	if err != nil {
		return "", "", err
	}
	keyPEM, err := read("key_file", "私钥文件")
	if err != nil {
		return "", "", err
	}
	return certPEM, keyPEM, nil
}

func (h *Handlers) GetAdminTLS(c *gin.Context) {
	// 读失败必须显式披露：此时返回的 enabled/mode 只是占位形态，静默展示会让
	// 运维在 DB 故障/迁移窗口看到与真实启用态相反的视图，故以
	// config_unavailable=true 单独标注（写路径读失败会中止，不会回写占位值，
	// 无二次破坏）。
	cfg, cfgErr := services.LoadAdminTLSConfigE()
	if cfgErr != nil {
		services.Logf("warn", "管理面板 HTTPS 配置读取失败，按未启用/自签名占位展示（config_unavailable=true）: %v", cfgErr)
	}
	resp := gin.H{
		"enabled":            cfg.Enabled,
		"mode":               cfg.Mode,
		"config_unavailable": cfgErr != nil,
	}
	if cfg.Cert != "" {
		info, err := parseAdminTLSCertInfo(cfg.Cert)
		if err != nil {
			// 库内证书损坏/非 PEM（带外改库、旧版本导入）
			// 时此前静默省略 cert_info——UI 只见 enabled=true 却无证书信息，
			// 运维零信号。读路径与写路径口径对齐：显式暴露不可读状态。
			services.Logf("warn", "管理面板 HTTPS 证书解析失败（库内证书不可读）: %v", err)
			resp["cert_info"] = nil
			resp["cert_info_error"] = "证书内容不可读"
		} else {
			resp["cert_info"] = info
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: resp})
}

// auditAdminTLSFailure 记录管理面板 HTTPS 保存失败尝试。
// 词条沿用 UpdateConfig 的「更新失败/基础设置」（既有 danger 词表，不新增
// 动作名）。detail 不落证书/私钥材料，只落原因。
func auditAdminTLSFailure(c *gin.Context, reason string) {
	recordAudit(c, "更新失败", "基础设置", services.FormatAuditDetail(
		"操作：保存管理面板 HTTPS 配置",
		"原因："+reason,
		services.AuditResultPart("failure"),
	))
}

func (h *Handlers) UpdateAdminTLS(c *gin.Context) {
	// global_config(admin_tls_*) 写者：导入窗口内提交会被导入静默覆盖，事务
	// 开启后排队至导入结束——与同族 settings 写者同口径 409 fast-fail。
	if rejectWriteDuringImport(c, "保存管理面板 HTTPS 配置（配置导入进行中）") {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAdminTLSBodyBytes)
	input, err := decodeAdminTLSInput(c)
	if err != nil {
		auditAdminTLSFailure(c, "请求体无法解析")
		respondAdminTLSBodyError(c, err)
		return
	}
	if input.enabledPresent {
		if _, ok := parseAdminTLSEnabledValue(input.enabledValue); !ok {
			auditAdminTLSFailure(c, "enabled 取值不在白名单（仅 true/1/false/0）")
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: adminTLSEnabledWhitelistMessage})
			return
		}
	}

	// 本端点是读改写（读 current → 合并四列 → 整体 UPDATE）。同域全局配置
	// 写者 UpdateConfig/PutCaddyConfig 均持 caddyOpMu；
	// 此处不取锁时，UI 与 JSON/MCP 通道并发保存会以各自读到的 current 为基线
	// 整体覆盖，前一次变更静默丢失，且各自排期一次进程重启。锁只覆盖
	// 「读当前值 → 校验/探针 → 写库」，restartProcess 在解锁后执行。
	// 锁序：caddyOpMu → wafFileMu（ResolveCertificate 只碰证书文件），与全仓
	// 既有顺序一致，不存在反向取锁。
	h.caddyOpMu.Lock()
	locked := true
	defer func() {
		if locked {
			h.caddyOpMu.Unlock()
		}
	}()
	// 写路径用严格 loader——读失败必须中止（降级默认值当基线会把
	// 已上传证书/私钥合并成空值）。
	current, err := services.LoadAdminTLSConfigE()
	if err != nil {
		auditAdminTLSFailure(c, "读取当前 HTTPS 配置失败: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取当前 HTTPS 配置失败，已中止保存: " + err.Error()})
		return
	}
	enabled := current.Enabled
	if v := input.enabledValue; v != "" {
		enabled = v == "true" || v == "1"
	}
	mode := current.Mode
	if v := input.modeValue; v != "" {
		mode = v
	}
	// 携带证书材料但生效来源不是 upload 时此前静默
	// 丢弃材料（甚至回「配置未变更，无需重启」200），与 fail-visible 原则不符。
	// 现显式 400 点名两种正确做法（补 mode=upload 或移除材料字段）。
	if input.hasUploadPayload() && mode != "upload" {
		modeText := mode
		if modeText == "" {
			modeText = "未设置"
		}
		auditAdminTLSFailure(c, "证书材料来源与 mode 不一致（当前 mode："+modeText+"）")
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "提交了证书材料但证书来源不是 upload（当前：" + modeText + "）；如需上传证书请同时提交 mode=upload，否则请移除 cert_file/key_file 后重试"})
		return
	}
	cert, key := current.Cert, current.Key
	uploadedCertificate := false
	if mode == "upload" && input.hasUploadPayload() {
		certPEM, keyPEM, err := input.certificatePair()
		if err != nil {
			auditAdminTLSFailure(c, "证书材料读取失败: "+err.Error())
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		cert, key = certPEM, keyPEM
		uploadedCertificate = true
	}
	// 切换到非 upload 来源时清空已上传证书材料——
	// selfsigned 由 ResolveCertificate 自生成，残留 upload 材料无消费者，
	// 且会随备份/导入继续传播（upload 模式禁用保留既有钉测锁定，不受影响）。
	if mode != "upload" {
		cert, key = "", ""
	}
	// 值未变更不写库不重启——此前无条件 UPDATE+
	// restartProcess，设置页重复保存产生无谓进程重启。
	unchanged := enabled == current.Enabled && mode == current.Mode && cert == current.Cert && key == current.Key

	// 形态校验（mode 值域 + 启用态必选来源 + upload 配对/有效期）与 v2 备份
	// 导入（config_backup.go）共用同一实现（收敛：原内联校验与
	// validateAdminTLSConfigValues 双份——改一处漏一处即分叉）。
	// 校验前置于「未变更」短路：存量值可能来自带外改库/坏导入，原样提交若直接
	// 200「未变更」会把非法组合无声固化且不给修复提示（纯 CPU 校验、无副作用）。
	if err := validateAdminTLSConfigValues(services.AdminTLSConfig{Enabled: enabled, Mode: mode, Cert: cert, Key: key}); err != nil {
		if unchanged {
			auditAdminTLSFailure(c, "存量配置无效（本次值未变更）: "+err.Error())
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "当前已保存的管理面板 HTTPS 配置无效（" + err.Error() + "），本次提交未做修改；请重新选择证书来源或上传证书后保存以修复"})
			return
		}
		auditAdminTLSFailure(c, "配置校验失败: "+err.Error())
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if unchanged {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置未变更，无需重启"})
		return
	}
	// 独有探针：启用态以真实落盘目录探测证书可用性（自签名生成/文件读写），
	// 覆盖 validateAdminTLSConfigValues 不涉的 ResolveCertificate 路径。
	if enabled {
		probe := services.AdminTLSConfig{Enabled: true, Mode: mode, Cert: cert, Key: key}
		if _, err := probe.ResolveCertificate(h.cfg.DataDir); err != nil {
			auditAdminTLSFailure(c, "证书不可用: "+err.Error())
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书不可用: " + err.Error()})
			return
		}
	}
	// 独有：禁用态但本次上传了新证书材料——仍校验配对/有效期（不落启用门；
	// 契约见 TestUpdateAdminTLSJSONBody_rejectsMismatchedPairWithoutSaving）。
	if mode == "upload" && uploadedCertificate && !enabled {
		if err := validateUploadCertificatePair(cert, key, time.Now()); err != nil {
			auditAdminTLSFailure(c, "证书材料校验失败: "+err.Error())
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	res, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=?, admin_tls_mode=?, admin_tls_cert=?, admin_tls_key=?, updated_at=datetime('now') WHERE id=1`,
		enabled, mode, cert, key)
	if err != nil {
		auditAdminTLSFailure(c, "写入 HTTPS 配置失败: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 HTTPS 配置失败: " + err.Error()})
		return
	}
	if n, rowsErr := res.RowsAffected(); rowsErr != nil || n != 1 {
		// global_config 行缺失/损坏时不能报成功并重启。
		reason := "配置行不存在"
		if rowsErr != nil {
			reason = "读取更新结果失败: " + rowsErr.Error()
		}
		auditAdminTLSFailure(c, "HTTPS 配置未落库（"+reason+"）")
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "HTTPS 配置未落库（配置行不存在）"})
		return
	}

	modePart := ""
	if mode != "" { // 禁用路径未提交 mode——空值段不拼
		modePart = "证书来源：" + mode
	}
	// cert/key 可能被本次上传替换，此前审计只记启用态+
	// 来源——「只开关未换证书」与「换证书」在审计里不可区分。显式留痕（不落
	// 证书本体）。
	certPart := "证书：未更换"
	switch {
	case uploadedCertificate:
		certPart = "证书：已更换（来源 upload）"
	case current.Cert != "" && cert == "":
		// 上传证书材料被本次切换到非 upload 来源清空——安全相关动作，
		// 审计必须与「只切来源、材料原样保留」可区分。
		certPart = "证书：已清除（切换到 selfsigned）"
	}
	recordAudit(c, "更新", "基础设置", services.FormatAuditDetail(
		map[bool]string{true: "启用", false: "禁用"}[enabled],
		modePart,
		certPart,
		services.AuditResultPart("success"),
	))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已保存，服务正在重启以应用 HTTPS 配置"})
	// 改走统一重启触发器（restartProcess，见 system.go）——与集群同步的
	// Admin TLS 热切换同一优雅停机信号；测试环境回退 exitProcess。
	// 先解锁再重启：重启期间不得让并发的配置写请求阻塞在 caddyOpMu 上。
	h.caddyOpMu.Unlock()
	locked = false
	restartProcess()
}
