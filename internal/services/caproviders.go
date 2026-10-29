package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

const (
	ProviderLetsEncrypt = "letsencrypt"
	ProviderZeroSSL     = "zerossl"

	// Official directory URLs. These are fixed and not user-editable.
	LetsEncryptDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	ZeroSSLDirectoryURL     = "https://acme.zerossl.com/v2/DV90"
)

// caProviderColumns 的可空列统一 COALESCE（带外 NULL 不得让整表扫描/解析
// 500）：max_concurrent/min_interval_ms 的兜底值由 db 治理常量派生（与 fresh
// DDL DEFAULT 双向钉死）；enabled 取 0 而非 DDL 默认 1——所有取用门都是
// `WHERE enabled=1`，SQL 三值逻辑下 NULL 本就不会命中，读成「启用」会让列表
// 显示与队列准入自相矛盾（fail-closed 口径）。非编译期常量：默认值必须来自
// 治理常量而非第二份字面量。
var caProviderColumns = "id, name, provider, directory_url, COALESCE(credentials,''), COALESCE(max_concurrent," +
	strconv.Itoa(db.DefaultCAProviderMaxConcurrent) + "), COALESCE(min_interval_ms," +
	strconv.Itoa(db.DefaultCAProviderMinIntervalMS) + "), COALESCE(enabled,0), created_at, updated_at"

// CredentialsSemanticallyEqual 报告两段凭证 JSON 语义相等（键序/空白无关）：
// 解析后按规范化形态比较。
// CA 提供商与 DNS 配置两处写路径必须共用本判定——同一次「只改名保存」在两个
// 页面若口径不同，会让审计记出「凭证变更」噪声，并额外重写 dns_credentials。
// 任一侧不是合法 JSON 时退化为字符串比较（判别本身不吞错——合法 JSON 门
// 由服务层写侧负责）。
func CredentialsSemanticallyEqual(a, b string) bool {
	var left, right any
	if err := json.Unmarshal([]byte(a), &left); err != nil {
		return a == b
	}
	if err := json.Unmarshal([]byte(b), &right); err != nil {
		return a == b
	}
	return reflect.DeepEqual(left, right)
}

// zerosslEABURL 是包级变量以便测试注入伪 ZeroSSL 端点。
var zerosslEABURL = "https://api.zerossl.com/acme/eab-credentials-email"

// zerosslEABProvisionTimeout 是 CA 测试路径 EAB 自动获取的超时上界；
// 包级变量以便测试注入缩短时限。
var zerosslEABProvisionTimeout = 10 * time.Second

type caProviderScanner interface {
	Scan(...any) error
}

// NormalizeCAProviderMaxConcurrent 是「最大并发」钳制的单源实现：<=0 视为
// 默认 DefaultCAProviderMaxConcurrent（保留「0 即默认」的 API 兼容语义）。
// 落库与审计比对必须共用它——handler 按请求原值比对会把「提交 0、库值 1、
// 落库仍 1」记成一次变更（审计假阳性）。
func NormalizeCAProviderMaxConcurrent(value int) int {
	if value <= 0 {
		return db.DefaultCAProviderMaxConcurrent
	}
	return value
}

// NormalizeCAProviderMinIntervalMS 同 NormalizeCAProviderMaxConcurrent：
// <=0 视为默认 DefaultCAProviderMinIntervalMS——该默认值与 fresh DDL DEFAULT、
// 读侧 COALESCE、导入回填同一常量，不得出现第二套节流数字。
func NormalizeCAProviderMinIntervalMS(value int) int {
	if value <= 0 {
		return db.DefaultCAProviderMinIntervalMS
	}
	return value
}

func scanCAProvider(scanner caProviderScanner, provider *models.CAProvider) error {
	var createdAt, updatedAt sql.NullTime
	if err := scanner.Scan(&provider.ID, &provider.Name, &provider.Provider, &provider.DirectoryURL, &provider.Credentials, &provider.MaxConcurrent, &provider.MinIntervalMS, &provider.Enabled, &createdAt, &updatedAt); err != nil {
		return err
	}
	if createdAt.Valid {
		provider.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		provider.UpdatedAt = updatedAt.Time
	}
	return nil
}

// CAProviderService manages CA provider business logic.
type CAProviderService struct {
	dataDir string
}

// NewCAProviderService creates a new CAProviderService.
func NewCAProviderService(dataDir ...string) *CAProviderService {
	service := &CAProviderService{}
	if len(dataDir) > 0 {
		service.dataDir = dataDir[0]
	}
	return service
}

// ListCAProviders returns all CA providers with actual credentials.
// CA 凭证（含 ZeroSSL EAB）对全体登录用户明文可读为 2026-09-05 用户裁定口径
// （所有登录用户至少全局只读、内部可信）；勿按 DNS 凭证掩码口径「修复」——
// DNS 掩码与 CA 明文并存是有意差异。
// 列表直接返回 []models.CAProvider，删除与模型 1:1
// 同形的 CAProviderListItem 拷贝层（无脱敏/投影价值；JSON 键完全同形，
// 唯一差异=credentials 空串时省略键，前端 parseCACredentials 对 falsy 兼容）。
func (s *CAProviderService) ListCAProviders() ([]models.CAProvider, error) {
	rows, err := db.DB.Query("SELECT " + caProviderColumns + " FROM ca_providers ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]models.CAProvider, 0)
	for rows.Next() {
		var provider models.CAProvider
		if err := scanCAProvider(rows, &provider); err != nil {
			return nil, err
		}
		list = append(list, provider)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

// GetCAProvider returns a CA provider by ID, including credentials.
// 凭证明文可读口径同 ListCAProviders：2026-09-05 用户裁定，全员可读、仅
// admin 可写（写侧收敛见路由分组），与 DNS 凭证掩码为有意差异。
func (s *CAProviderService) GetCAProvider(id int) (models.CAProvider, error) {
	var p models.CAProvider
	err := scanCAProvider(db.DB.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=?", id), &p)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return p, ErrCAProviderNotFound
		}
		return p, err
	}
	return p, nil
}

// ErrCAProviderNotFound is returned when a CA provider does not exist.
var ErrCAProviderNotFound = errors.New("CA provider not found")

// ErrCAProviderLastEnabled is returned when attempting to disable the only enabled CA provider.
var ErrCAProviderLastEnabled = errors.New("cannot disable the last enabled CA provider")

// ErrCAProviderInvalidProvider is returned when the provider type is unsupported.
var ErrCAProviderInvalidProvider = errors.New("provider must be letsencrypt or zerossl")

// ErrCAProviderInvalidName is returned when the provider name is empty.
var ErrCAProviderInvalidName = errors.New("name is required")

// ErrCAProviderNameTooLong is returned when the provider name exceeds 100 characters.
var ErrCAProviderNameTooLong = errors.New("name must be <= 100 characters")

// ErrCAProviderInvalidCredentials is returned when credentials are not valid JSON.
var ErrCAProviderInvalidCredentials = errors.New("credentials must be valid JSON")

// ErrCAProviderLetsEncryptCredentialsNotEmpty is returned when letsencrypt credentials are provided.
var ErrCAProviderLetsEncryptCredentialsNotEmpty = errors.New("letsencrypt credentials must be empty")

// ErrCAProviderMaxConcurrentTooLow is returned when max_concurrent is negative
// (0 = 「未设置/默认」，写侧与读侧统一归一为 DefaultCAProviderMaxConcurrent).
var ErrCAProviderMaxConcurrentTooLow = errors.New("max_concurrent must be >= 0")

// ErrCAProviderMaxConcurrentTooHigh is returned when max_concurrent exceeds the allowed upper bound.
var ErrCAProviderMaxConcurrentTooHigh = errors.New("max_concurrent must be <= 100")

// ErrCAProviderMinIntervalTooLow is returned when min_interval_ms is negative
// (0 = 「未设置/默认」，归一为 DefaultCAProviderMinIntervalMS).
var ErrCAProviderMinIntervalTooLow = errors.New("min_interval_ms must be >= 0")

// ErrCAProviderMinIntervalTooHigh is returned when min_interval_ms exceeds the allowed upper bound.
var ErrCAProviderMinIntervalTooHigh = errors.New("min_interval_ms must be <= 60000")

// ErrCAProviderInUse 标记「禁用被启用中 ACME 规则引用的 CA 提供商」。
// 与 DNS 配置禁用守卫（handlers/certificates.go）同口径：引用方存在即拒绝，
// 避免禁用后新签发/续签静默改用其它 CA（改写 cert_jobs.ca_provider_id、消耗
// 另一 CA 配额）而队列内旧任务却按「CA Provider 不可用」失败的行为分裂。
var ErrCAProviderInUse = errors.New("CA 提供商正被启用中的 ACME 规则引用")

// ErrCAProviderDefault：当前默认 CA 提供商不得禁用（否则 0 值引用/未显式
// 选择 CA 的规则会在下次签发时静默改派）。
var ErrCAProviderDefault = errors.New("默认 CA 提供商不能禁用，请先切换默认提供商")

// CAProviderInUseError 携带引用明细，供 handler 回显 409 文案（列表最多 5 条，
// Total 为完整引用数）。
type CAProviderInUseError struct {
	Rules []string
	Total int
}

func (e *CAProviderInUseError) Error() string {
	if e == nil {
		return ErrCAProviderInUse.Error()
	}
	message := fmt.Sprintf("该 CA 提供商正被 %d 条启用中的 ACME 规则引用，禁用后这些规则将无法自动签发/续签证书，请先修改规则的 CA 提供商后再禁用", e.Total)
	if len(e.Rules) > 0 {
		message += "：" + strings.Join(e.Rules, "、")
		if e.Total > len(e.Rules) {
			message += fmt.Sprintf(" 等 %d 条规则", e.Total)
		}
	}
	return message
}

func (e *CAProviderInUseError) Unwrap() error { return ErrCAProviderInUse }

// caProviderReferences 统计引用指定 CA 提供商的启用中 ACME 规则（最多返回
// 5 条明细用于 409 文案）。
func caProviderReferences(tx *sql.Tx, providerID int) ([]string, int, error) {
	rows, err := tx.Query(`SELECT caddy_id, COALESCE(domain,'') FROM lb_rules
		WHERE ca_provider_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns'
		ORDER BY caddy_id`, providerID)
	if err != nil {
		return nil, 0, fmt.Errorf("查询 CA 提供商规则引用: %w", err)
	}
	defer rows.Close()
	var references []string
	total := 0
	for rows.Next() {
		var caddyID, domain string
		if err := rows.Scan(&caddyID, &domain); err != nil {
			return nil, 0, fmt.Errorf("读取 CA 提供商规则引用: %w", err)
		}
		total++
		if len(references) >= 5 {
			continue
		}
		if domain != "" {
			references = append(references, fmt.Sprintf("%s (%s)", domain, caddyID))
		} else {
			references = append(references, caddyID)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("遍历 CA 提供商规则引用: %w", err)
	}
	return references, total, nil
}

// UpdateCAProvider updates a CA provider and returns the pre-update row as read
// inside the same transaction （调用方（handler 审计 changed
// 清单）以事务内旧行为比对基线，消除「事务外预读 → 事务提交」窗口内并发
// 写入导致的清单失真）。Returns ErrCAProviderNotFound if no rows were affected.
func (s *CAProviderService) UpdateCAProvider(id int, req models.UpdateCAProviderRequest) (models.CAProvider, error) {
	tx, err := db.DB.Begin()
	if err != nil {
		return models.CAProvider{}, err
	}
	defer tx.Rollback()

	var existing models.CAProvider
	err = scanCAProvider(tx.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=?", id), &existing)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.CAProvider{}, ErrCAProviderNotFound
		}
		return models.CAProvider{}, err
	}
	// 事务内旧行快照——existing 就地应用 req 变更后用于写库，
	// old 保持 SELECT 读到的原值供调用方做审计比对。
	old := existing
	if req.Name != nil {
		// 与证书配置名称归一化同口径：纯空白名会被当作合法名称落库，
		// 列表/选择器出现无法辨识的行；API 可绕过前端 trim，必须在写入口归一。
		existing.Name = strings.TrimSpace(*req.Name)
	}
	if req.Provider != nil {
		existing.Provider = *req.Provider
	}
	// DirectoryURL 非用户可写字段（任何取值都被官方固定 URL 覆写，
	// 裁定删除死参数与审计失真源）。
	if req.Credentials != nil {
		existing.Credentials = *req.Credentials
	}
	if req.MaxConcurrent != nil {
		existing.MaxConcurrent = *req.MaxConcurrent
	}
	if req.MinIntervalMS != nil {
		existing.MinIntervalMS = *req.MinIntervalMS
	}
	wasEnabled := existing.Enabled
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	if existing.Provider != ProviderLetsEncrypt && existing.Provider != ProviderZeroSSL {
		return models.CAProvider{}, ErrCAProviderInvalidProvider
	}
	if existing.Provider == ProviderLetsEncrypt {
		existing.DirectoryURL = LetsEncryptDirectoryURL
	} else {
		existing.DirectoryURL = ZeroSSLDirectoryURL
	}
	if existing.Name == "" {
		return models.CAProvider{}, ErrCAProviderInvalidName
	}
	if len([]rune(existing.Name)) > 100 {
		return models.CAProvider{}, ErrCAProviderNameTooLong
	}

	// LE 分支前移到 JSON 门之前——LE 凭证本就必须为空，
	// 纯空白输入（用户清空 EAB 字段的残留）此前在 JSON 门被「凭证必须是有效
	// 的 JSON」拒绝，永远无法保存；现在归一为空串落库（前端 parseCACredentials
	// 对空串走 falsy 分支）。非 LE 提供商仍走完整 JSON 门。
	if existing.Provider == ProviderLetsEncrypt {
		trimmed := strings.TrimSpace(existing.Credentials)
		if trimmed != "" && trimmed != "{}" {
			return models.CAProvider{}, ErrCAProviderLetsEncryptCredentialsNotEmpty
		}
		if trimmed == "" {
			existing.Credentials = ""
		}
	} else if existing.Credentials != "" {
		var creds models.CAProviderCredentials
		if err := json.Unmarshal([]byte(existing.Credentials), &creds); err != nil {
			return models.CAProvider{}, ErrCAProviderInvalidCredentials
		}
	}

	// 负值与超上限同口径显性 400（导入校验 min=0 本就拒绝负值；写侧此前把
	// 负值静默钳成默认值，两条 TooLow 哨兵实际恒不触发）。0 仍表示
	// 「未设置/默认」，保持既有 API 兼容语义。
	if existing.MaxConcurrent < 0 {
		return models.CAProvider{}, ErrCAProviderMaxConcurrentTooLow
	}
	existing.MaxConcurrent = NormalizeCAProviderMaxConcurrent(existing.MaxConcurrent)
	if existing.MaxConcurrent > 100 {
		return models.CAProvider{}, ErrCAProviderMaxConcurrentTooHigh
	}
	if existing.MinIntervalMS < 0 {
		return models.CAProvider{}, ErrCAProviderMinIntervalTooLow
	}
	existing.MinIntervalMS = NormalizeCAProviderMinIntervalMS(existing.MinIntervalMS)
	if existing.MinIntervalMS > 60000 {
		return models.CAProvider{}, ErrCAProviderMinIntervalTooHigh
	}

	// 「最后一个启用」守卫收敛进 UPDATE 的 WHERE 子查询——
	// 旧形态为 check-then-act（COUNT 读 + 裸 UPDATE 两句分置），守卫判定与写入不原子，
	// 并发禁用仅剩的两个启用提供商时存在同穿窗口；原子形态下守卫在写锁内求值，
	// 后提交者恒 0 行 → ErrCAProviderLastEnabled，不再依赖 _txlock=immediate 的
	// 事务序列化兜底。
	disabling := req.Enabled != nil && !*req.Enabled && wasEnabled
	// 禁用引用守卫与 DNS 配置禁用同口径（失败即 409，点名引用方）。
	// 放在事务内、UPDATE 之前：与写锁同事务，判定与写入原子。
	if disabling {
		// 默认提供商守卫不得 fail-open——读失败时此前静默跳过守卫，
		// 只剩「最后一个启用」兜底，可禁用当前默认提供商，令 ca_provider_id=0
		// 的规则/未显式选择 CA 的规则在下次签发时静默改派。行缺失（ErrNoRows）
		// 语义=未配置默认提供商（无守卫对象），DB 读故障则显性失败（fail-closed）。
		var defaultID int
		derr := tx.QueryRow(`SELECT COALESCE(default_ca_provider_id,0) FROM global_config WHERE id=1`).Scan(&defaultID)
		if derr != nil && !errors.Is(derr, sql.ErrNoRows) {
			return models.CAProvider{}, fmt.Errorf("读取默认 CA 提供商: %w", derr)
		}
		if derr == nil && defaultID == id {
			return models.CAProvider{}, ErrCAProviderDefault
		}
		references, total, refErr := caProviderReferences(tx, id)
		if refErr != nil {
			return models.CAProvider{}, refErr
		}
		if total > 0 {
			return models.CAProvider{}, &CAProviderInUseError{Rules: references, Total: total}
		}
	}
	// 凭证列只在「请求值与事务内旧行语义不等」时写（动态 SET，与 DNS 配置更新
	// 同型）：TestCAProvider / 签发预检会在不持 caddyOpMu 的情况下自动申请并写入
	// ZeroSSL EAB，整行 UPDATE 会把它静默回滚——①前端「测试成功→编辑陈旧表单→
	// 保存」提交的是测试前的空 EAB；②并发路径请求在旧行读取后、UPDATE 前提交了
	// EAB。不写该列即两个路径都无损失，而真实修改（含切 CA 时的空值归一）照常落库。
	credentialsChanged := !CredentialsSemanticallyEqual(existing.Credentials, old.Credentials)
	setClauses := []string{"name=?", "provider=?", "directory_url=?"}
	args := []any{existing.Name, existing.Provider, existing.DirectoryURL}
	if credentialsChanged {
		setClauses = append(setClauses, "credentials=?")
		args = append(args, existing.Credentials)
	}
	setClauses = append(setClauses, "max_concurrent=?", "min_interval_ms=?", "enabled=?", "updated_at=datetime('now')")
	args = append(args, existing.MaxConcurrent, existing.MinIntervalMS, existing.Enabled, id)
	query := `UPDATE ca_providers SET ` + strings.Join(setClauses, ", ") + ` WHERE id=?`
	if disabling {
		query += ` AND enabled=1 AND (SELECT COUNT(*) FROM ca_providers WHERE enabled=1 AND id != ?) >= 1`
		args = append(args, id)
	}
	res, err := tx.Exec(query, args...)
	if err != nil {
		return models.CAProvider{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return models.CAProvider{}, err
	}
	if rows == 0 {
		// 禁用分支的 0 行即守卫子查询拒绝（行存在性已由本事务内 SELECT 证明），
		// 归因为 ErrCAProviderLastEnabled 而非 ErrCAProviderNotFound。
		if disabling {
			return models.CAProvider{}, ErrCAProviderLastEnabled
		}
		return models.CAProvider{}, ErrCAProviderNotFound
	}

	if err := tx.Commit(); err != nil {
		return models.CAProvider{}, err
	}
	// 配置提交后发布失效事件——队列 tick 见版本变化即按新值
	// 复核 max_concurrent/min_interval，不再等 running 归零或缓存间隔到期。
	caProviderConfigVersion.Add(1)
	return old, nil
}

// CAProviderTestError records a failure during the ACME test phase.
type CAProviderTestError struct {
	Phase string
	Err   error
}

func (e *CAProviderTestError) Error() string { return e.Err.Error() }
func (e *CAProviderTestError) Unwrap() error { return e.Err }

// AutoProvisionZeroSSLEAB fetches EAB credentials from the ZeroSSL API using
// the configured ACME email when the provider lacks them. Credentials are
// persisted to ca_providers.credentials for reuse.
func AutoProvisionZeroSSLEAB(ctx context.Context, provider *models.CAProvider) error {
	var creds models.CAProviderCredentials
	if provider.Credentials != "" {
		if err := json.Unmarshal([]byte(provider.Credentials), &creds); err != nil {
			return fmt.Errorf("parse existing credentials: %w", err)
		}
	}
	if creds.EABKID != "" && creds.EABHMACKey != "" {
		// 正常态：ZeroSSL 首次成功获取 EAB 后每次签发/测试预检都会走到这里，
		// warn 会按签发频率持续刷屏并淹没真正的 EAB/凭据异常。
		Logf("info", "AutoProvisionZeroSSLEAB: provider %d already has EAB credentials, skipping", provider.ID)
		return nil
	}
	Logf("info", "AutoProvisionZeroSSLEAB: provider %d missing EAB, auto-fetching", provider.ID)
	var acmeEmail string
	if err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(acme_email,'') FROM global_config WHERE id=1").Scan(&acmeEmail); err != nil {
		return fmt.Errorf("read acme email: %w", err)
	}
	if acmeEmail == "" {
		return fmt.Errorf("ACME email is required for ZeroSSL EAB auto-provision")
	}

	Logf("info", "AutoProvisionZeroSSLEAB: fetching EAB from ZeroSSL API for email %s", maskEmail(acmeEmail))
	reqBody := strings.NewReader("email=" + url.QueryEscape(strings.TrimSpace(acmeEmail)))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, zerosslEABURL, reqBody)
	if err != nil {
		return fmt.Errorf("build zerossl EAB request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// http.DefaultClient 无超时，ZeroSSL API 卡住会永久阻塞签发 worker。
	// 显式指定 30 秒超时兜底，与 ctx 取消形成双重保护。
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("call zerossl EAB API: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		Success    bool   `json:"success"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
		Error      string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return fmt.Errorf("parse zerossl EAB response: %w", err)
	}
	if !body.Success || body.EABKID == "" || body.EABHMACKey == "" {
		reason := body.Error
		if reason == "" {
			reason = "empty credentials"
		}
		return fmt.Errorf("zerossl EAB auto-provision failed: %s", reason)
	}

	creds.EABKID = body.EABKID
	creds.EABHMACKey = body.EABHMACKey
	credsJSON, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("encode EAB credentials: %w", err)
	}
	result, err := db.DB.ExecContext(ctx,
		"UPDATE ca_providers SET credentials=? WHERE id=? AND (credentials='' OR credentials IS NULL OR credentials=?)",
		string(credsJSON), provider.ID, provider.Credentials)
	if err != nil {
		return fmt.Errorf("persist zerossl EAB: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		// 并发 worker 已先行持久化：内存凭据必须回读 DB 实际值，
		// 否则内存持有未持久化的新值，造成 DB/运行时凭据分裂。
		var persisted string
		if err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(credentials,'') FROM ca_providers WHERE id=?", provider.ID).Scan(&persisted); err != nil {
			return fmt.Errorf("re-read zerossl EAB credentials: %w", err)
		}
		provider.Credentials = persisted
		// DB 凭据已被并发写入者改变——同样递增配置版本，令队列缓存的
		// provider 快照（可能仍持空 EAB）按新凭据刷新，避免每个后续任务再请求
		// 一次 ZeroSSL API（虽有 CAS 兜底，但外部调用重复且无谓）。
		caProviderConfigVersion.Add(1)
		Logf("warn", "AutoProvisionZeroSSLEAB: provider %d credentials already set by concurrent worker, skipping persist", provider.ID)
		return nil
	}
	provider.Credentials = string(credsJSON)
	// EAB 落库后递增配置版本（与 UpdateCAProvider 同口径）——队列
	// 积压时缓存的 provider 快照仍持空 EAB，纯版本失效即可避免签发前再次
	// 请求 ZeroSSL API；CAS 兜底只保证正确性、不消除这次外部调用。
	caProviderConfigVersion.Add(1)
	Logf("info", "AutoProvisionZeroSSLEAB: success, EAB persisted for provider %d (%s)", provider.ID, maskEmail(acmeEmail))
	return nil
}

// maskEmail 脱敏邮箱地址（2026-09-05 证书域：注释此前与实现不符；
// 起按 rune 截断——多字节 UTF-8 本地部分（如 CJK 邮箱）按字节切
// 前两个「字符」会切在 rune 中间产出非法 UTF-8 残片）。
// 三分支真实行为：@ 前缀 rune 数 >3 时保留前两个字符与域名（ad***@example.com）；
// @ 前缀过短（rune 数 <=3，如 ab@x.cn）时仅保留域名、连首字符也不保留（***@x.cn）；
// 无 @ 或 @ 恰在首/尾时整体 ***。
func maskEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "***"
	}
	local := []rune(email[:at])
	if len(local) <= 3 {
		return "***" + email[at:]
	}
	return string(local[:2]) + "***" + email[at:]
}

func (s *CAProviderService) TestCAProviderWithContext(ctx context.Context, id int) error {
	_, err := s.testCAProvider(ctx, id)
	return err
}

// testCAProvider 预检内核：装配校验 + ZeroSSL EAB 自动获取（含独立超时界）+
// 账户注册/复用验证，返回已注册账户的 ACME client。签发路径（certissuer）
// 直接复用该 client——同一 client 的 KID 已缓存，Issuer 跳过重复注册
// （此前预检与正式签发各建 client 各 RegisterAccount 一次，
// 每次签发 EAB 双调用、ACME 账户双注册）。
func (s *CAProviderService) testCAProvider(ctx context.Context, id int) (*acme.Client, error) {
	Logf("info", "Testing CA provider %d", id)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var p models.CAProvider
	err := scanCAProvider(db.DB.QueryRowContext(ctx, "SELECT "+caProviderColumns+" FROM ca_providers WHERE id=? AND enabled=1", id), &p)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCAProviderNotFound
		}
		return nil, err
	}

	var acmeEmail string
	if err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(acme_email,'') FROM global_config WHERE id=1").Scan(&acmeEmail); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &CAProviderTestError{Phase: "email", Err: errors.New("ACME email is not configured")}
		}
		return nil, err
	}
	if acmeEmail == "" {
		return nil, &CAProviderTestError{Phase: "email", Err: errors.New("ACME email is not configured")}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if p.Provider == ProviderZeroSSL {
		Logf("info", "TestCAProvider: ensuring ZeroSSL EAB for provider %d", id)
		// EAB 自动获取与 RegisterAccount 同界 10s——原实现先无界
		// 调用 AutoProvisionZeroSSLEAB、超时只裹其后的注册，ZeroSSL EAB API
		// 挂起时 CA 测试页无限阻塞。
		eabCtx, eabCancel := context.WithTimeout(ctx, zerosslEABProvisionTimeout)
		eabErr := AutoProvisionZeroSSLEAB(eabCtx, &p)
		eabCancel()
		if eabErr != nil {
			return nil, &CAProviderTestError{Phase: "config", Err: fmt.Errorf("ZeroSSL EAB 自动获取失败: %w", eabErr)}
		}
	}

	client, err := acme.NewClientForProvider(p, acmeEmail, s.dataDir)
	if err != nil {
		return nil, &CAProviderTestError{Phase: "config", Err: err}
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.RegisterAccount(ctx); err != nil {
		return nil, &CAProviderTestError{Phase: "register", Err: err}
	}
	return client, nil
}
