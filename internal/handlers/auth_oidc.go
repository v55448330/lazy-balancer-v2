package handlers

// OIDC 集成(2026-09-17 v2.3.0,用户裁定方案):
//   · 单提供商,核心 4 项配置(issuer/client_id/client_secret/enabled)——端点经
//     OIDC Discovery 自动获取,用户零高级配置;另支持可选访问白名单
//     (allowed_email_domains/allowed_groups,缺省空=不限制,fail-visible 拒登)
//   · OIDC 用户不绑定本地账号:每次首登独立 JIT 开户(auth_provider='oidc',
//     默认普通角色),重复登录按 (issuer, subject) 命中
//   · 写保护矩阵:绑本地 MFA→TOTP 弹码;OIDC 会话(auth_method=oidc)与本地
//     MFA 体系完全解耦,经 mfaStepUpGuard 显式直通(v2.3.0 用户裁定);
//     锁定仅密码路径(OIDC 失败不计入,防「伪造回调锁死账号」DoS)
//   · 配置随 global_config 集群快照自动同步;从节点回调独立闭环（注：主端 users 节变更触发重放时会抹除本节点 JIT 行——该行存续期内签发的 JWT 将 401「用户不存在」，经 IdP 重新登录即自愈重建。 历史补证：抹除由漂移守卫自触发（本地 users 节哈希分叉→强制重放），首次仅在从节点登录的 OIDC 用户每个同步周期需重认证，直至在主端登录。裁定：最小动作=声明，不采用保留模式）→只读 JWT

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// OIDCConfig 存 global_config.oidc_config(JSON 列)。
type OIDCConfig struct {
	Enabled      bool   `json:"enabled"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	DisplayName  string `json:"display_name"`
	// AllowedEmailDomains / AllowedGroups JIT 与重复登录的访问白名单
	// （可选，均空=不限制，保持历史行为）。JIT 开户默认 user 角色 ×
	// 「所有登录用户全局只读（含证书私钥，已裁定设计）」意味着开启 OIDC 即对
	// IdP 全体可认证用户开放面板只读——白名单是面板侧唯一收口。
	// fail-visible：配置了名单但 IdP 未返回 email/groups 声明 → 拒登，
	// 不静默放行。登录每次回调都判定（IdP 侧变更即时生效），不止首登 JIT。
	AllowedEmailDomains []string `json:"allowed_email_domains,omitempty"`
	AllowedGroups       []string `json:"allowed_groups,omitempty"`
	// rawIssuer 是库中 issuer 的原值（loadOIDCConfig 归一前的形态），不参与
	// JSON 序列化。仅用于历史身份行兼容查询：JIT 行按 (auth_issuer,auth_subject)
	// 建键，归一后直接查会 miss 并重复开户（带外写入的带尾斜杠 issuer）。
	rawIssuer string
}

// usable 是「可对外提供 OIDC 登录」的单一判据。库值可经导入/快照绕过面板
// 保存门，因此公开状态与保存侧启用门必须共用完整性与 issuer 合规校验。
func (cfg OIDCConfig) usable() error {
	if !cfg.Enabled {
		return errors.New("OIDC 未启用")
	}
	if cfg.Issuer == "" || strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientSecret) == "" {
		return errors.New("OIDC 配置不完整：服务地址、Client ID 与 Client Secret 均须配置")
	}
	return validateOIDCIssuerURL(cfg.Issuer)
}

// oidcStateEntry 登录跳转与回调之间的一次性状态(state 防 CSRF,nonce 防
// 重放,PKCE verifier 防授权码拦截)。
type oidcStateEntry struct {
	nonce    string
	verifier string
	returnTo string
	created  time.Time
}

var (
	oidcStates   sync.Map // state -> oidcStateEntry
	oidcProvMu   sync.Mutex
	oidcProvCach = map[string]oidcProvEntry{} // issuer -> discovery 产物(含短 TTL 负缓存)
	// oidcProvCacheMax 硬上限：管理员探测接口接受任意 issuer，无上限会导致
	// 每个唯一 issuer 永久占位。满员淘汰任一条目，
	// 下个请求按需重新 discovery。
	oidcProvCacheMax = 64
	// oidcProvFlight 合并同 issuer 的在途 discovery（冷缓存下的并发登录风暴/
	// 公开端点打点不得逐请求放大出站）。失败负缓存仍由 leader 写入下表。
	oidcProvFlight singleflight.Group
	// oidcStateCount 在册 state 条目计数（未认证泛洪封顶,计数与
	// Store/Delete/TTL 清理同点维护)
	oidcStateCount atomic.Int32
)

// oidcProvEntry:成功缓存 provider;失败缓存 err+failedAt(负缓存,短 TTL——
// IdP 故障时不逐请求回源放大,恢复后 5s 内自动重试)。
type oidcProvEntry struct {
	provider *oidc.Provider
	err      error
	failedAt time.Time
}

const (
	oidcStateTTL    = 10 * time.Minute
	oidcNegCacheTTL = 5 * time.Second // discovery 失败负缓存 TTL
	// oidcReturnToMaxBytes 登录 return_to 的字节上限：
	// state 条目按条数封顶但此前单条 return_to 无界——未认证攻击者可用
	// 4096 条 ~1MB 的 return_to 近似保留数 GB 内存。站内前端页面键远短于此，
	// 超限一律按非法值丢弃（fail-safe，跳回默认首页）。
	oidcReturnToMaxBytes = 2048
	// oidcDisplayNameMaxRunes 登录页展示名预算，与设置页输入框 maxlength 30
	// 同源：保存侧超限 400，公开状态端点对存量坏值按同一预算截断。
	oidcDisplayNameMaxRunes = 30
	// oidcAllowListMaxEntries 访问白名单（allowed_groups /
	// allowed_email_domains）的条目上限，与 apiKeyMaxWhitelistEntries 同族：
	// 名单整块落进 global_config 单列、随集群快照搬运，OIDC 回调按
	// len(AllowedGroups)×len(claims.Groups) 线性扫描。
	oidcAllowListMaxEntries = 100
	// oidcAllowListEntryMaxRunes 单条白名单项长度上限（域名字面量远短于此）。
	oidcAllowListEntryMaxRunes = 128
)

// oidcStateMaxEntries 在册 state 条目上限（未认证泛洪内存封顶;
// var 供测试收窄)。
var oidcStateMaxEntries = 4096

// reserveOIDCStateSlot 原子预留一个在册 state 槽位。
// 旧实现「先 Load 判定上限、discovery/随机数之后再 Store + Add(1)」是
// TOCTOU：并发未认证登录可在检查与入册之间同时通过上限判定，越过 4096
// 硬上限。CAS 循环不持锁、不阻塞昂贵的 discovery；上限 <=0 表示一律拒绝
// （测试用 0 表达禁用登录）。调用方必须在成功 Store 前可回滚预留。
func reserveOIDCStateSlot() bool {
	max := int32(oidcStateMaxEntries)
	if max <= 0 {
		return false
	}
	for {
		cur := oidcStateCount.Load()
		if cur >= max {
			return false
		}
		if oidcStateCount.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// ── 配置读写 ──

// loadOIDCConfig 读取 OIDC 配置。
// 读失败/JSON 损坏必须与「未配置」区分——旧实现把
// 两者折叠为 false，更新端点据此以零值整体回写，会把 issuer/client_id/secret
// 清空（fail-open 破坏性写）。现在：未配置=(零值, nil)，读取失败=(零值, err)。
//
// issuer 在读侧归一是单点收口：库里可由配置导入、自动备份还原、集群快照或
// 带外改库带入未归一值（写侧校验只覆盖面板保存路径）。归一放读侧后，
// 登录/回调/状态/探测与 provider 缓存键全部使用同一形态——否则「测试通过、
// 真实登录必然失败」（Entra issuer 缺 /v2.0 时 discovery 恒失败，错误文案还会
// 被归一为「服务不可达」而误导排障）。原值保留在 rawIssuer 供历史身份行兼容。
func loadOIDCConfig() (OIDCConfig, error) {
	var raw string
	if err := db.DB.QueryRow("SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1").Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OIDCConfig{}, nil // 行缺失=未配置（初始化/迁移建行）
		}
		return OIDCConfig{}, fmt.Errorf("读取 OIDC 配置失败: %w", err)
	}
	if raw == "" {
		return OIDCConfig{}, nil
	}
	var cfg OIDCConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return OIDCConfig{}, fmt.Errorf("OIDC 配置损坏: %w", err)
	}
	cfg.rawIssuer = cfg.Issuer
	cfg.Issuer = normalizeOIDCIssuer(cfg.Issuer)
	return cfg, nil
}

func saveOIDCConfig(cfg OIDCConfig) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	res, err := db.DB.Exec("UPDATE global_config SET oidc_config=? WHERE id=1", string(raw))
	if err != nil {
		return err
	}
	// 与 UpdateConfig 同口径——影响行数非 1 即失败，不得报成功。
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return fmt.Errorf("保存 OIDC 配置失败：影响行数 %d（global_config 行缺失）", affected)
	}
	return nil
}

// oidcIssuerMigration 描述一次「归一值写回库」对历史身份行的迁移结果：
// moved=实际改写的行数，conflicts=迁移后会出现同 (issuer,subject) 双行的
// subject 集合（此时整体回滚，由管理员人工合并）。
type oidcIssuerMigration struct {
	from      string
	to        string
	moved     int
	conflicts []string
}

// auditText 返回审计 delta 片段（无迁移返回空串）：写回归一值本身无字段差异
// （before/after 都是归一值），不显式留痕会显示「无字段变化」而身份键已被
// 改写——长期取证面必须可解释。
func (m oidcIssuerMigration) auditText() string {
	if m.from == "" || m.from == m.to {
		return ""
	}
	return fmt.Sprintf("服务地址归一：%s→%s（迁移历史身份行 %d 条）", m.from, m.to, m.moved)
}

// migrateOIDCIdentityIssuer 把按原值建键的历史身份行迁到归一值（同一事务内，
// 与配置写回同生共死）。读取阶段先查冲突：同 subject 已存在归一值行时迁移会
// 触发 (oidc_issuer,oidc_subject) 唯一索引，且意味着同一自然人有两行身份
// （角色/禁用状态分叉）——必须拒绝并列出 subject 交人工合并，绝不静默二选一。
func migrateOIDCIdentityIssuer(tx *sql.Tx, from, to string) (oidcIssuerMigration, error) {
	mig := oidcIssuerMigration{from: from, to: to}
	if from == "" || to == "" || from == to {
		return mig, nil
	}
	rows, err := tx.Query(`SELECT oidc_subject FROM users
		WHERE auth_provider='oidc' AND oidc_subject<>'' AND oidc_issuer=?
		  AND oidc_subject IN (SELECT oidc_subject FROM users WHERE auth_provider='oidc' AND oidc_subject<>'' AND oidc_issuer=?)
		ORDER BY oidc_subject`, from, to)
	if err != nil {
		return mig, err
	}
	for rows.Next() {
		var subject string
		if scanErr := rows.Scan(&subject); scanErr != nil {
			rows.Close()
			return mig, scanErr
		}
		mig.conflicts = append(mig.conflicts, subject)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return mig, err
	}
	rows.Close()
	if len(mig.conflicts) > 0 {
		return mig, nil
	}
	res, err := tx.Exec(`UPDATE users SET oidc_issuer=? WHERE auth_provider='oidc' AND oidc_subject<>'' AND oidc_issuer=?`, to, from)
	if err != nil {
		return mig, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return mig, err
	}
	mig.moved = int(affected)
	return mig, nil
}

// saveOIDCConfigWithIssuerMigration 在同一事务内写配置并迁移历史身份行。
// 读侧归一保留 rawIssuer 只是为了「库中还存着原值」时能回退查询；配置一旦
// 写回库，原值即消失、兼容通道失效——若不同步迁移身份行，该自然人再登录会
// 被当成首次登录并新建启用账号（封禁/角色旁路）。conflicts 非空时函数不提交，
// 由调用方回 409。
func saveOIDCConfigWithIssuerMigration(cfg OIDCConfig, migrateFrom string) (oidcIssuerMigration, error) {
	mig := oidcIssuerMigration{from: migrateFrom, to: cfg.Issuer}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return mig, err
	}
	tx, err := db.DB.Begin()
	if err != nil {
		return mig, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec("UPDATE global_config SET oidc_config=? WHERE id=1", string(raw))
	if err != nil {
		return mig, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return mig, err
	}
	if affected != 1 {
		return mig, fmt.Errorf("保存 OIDC 配置失败：影响行数 %d（global_config 行缺失）", affected)
	}
	mig, err = migrateOIDCIdentityIssuer(tx, migrateFrom, cfg.Issuer)
	if err != nil {
		return mig, err
	}
	if len(mig.conflicts) > 0 {
		return mig, nil
	}
	if err := tx.Commit(); err != nil {
		return mig, err
	}
	return mig, nil
}

// oidcAccessClaims 是访问白名单判定的输入（claims 解析后单源传递）。
type oidcAccessClaims struct {
	Email string
	// EmailVerified/EmailVerifiedSeen 来自 email_verified 声明：缺失或非布尔
	// 形态时 Seen=false（配置了域名单即 fail-visible 拒登）。
	EmailVerified     bool
	EmailVerifiedSeen bool
	Groups            []string
	// GroupsMalformed=groups 声明存在但形态不可解析（既非字符串数组也非
	// 分隔字符串）——配置了组名单时与「声明缺失」分开表述，排障能定位到
	// IdP 声明类型不兼容而不是「没配组」。
	GroupsMalformed bool
}

// oidcAccessAllowed 访问白名单判定（单源，OIDC 回调每次登录调用）。
// 两项名单均空=不限制（历史行为）。配置了 email 域名单 → email 声明必须
// 存在、email_verified 必须为 true 且其域（@ 后部分，大小写不敏感）在名单内；
// 配置了组名单 → groups 声明必须存在且交集非空。IdP 不返回对应声明 = fail-visible
// 拒登，不静默放行。
//
// 域名单必须叠加 email_verified：白名单是面板侧唯一收口，若 IdP 允许用户
// 自定义邮箱且不做验证（自建 Keycloak/Authentik 的常见配置），任何可登录该
// IdP 的人把邮箱改成 someone@被允许域即通过域比对。返回 (false, reason) 时
// reason 供审计留痕。
func oidcAccessAllowed(cfg OIDCConfig, claims oidcAccessClaims) (bool, string) {
	if len(cfg.AllowedEmailDomains) > 0 {
		if strings.TrimSpace(claims.Email) == "" {
			return false, "IdP 未返回 email 声明（已配置域名单）"
		}
		if !claims.EmailVerifiedSeen {
			return false, "IdP 未返回 email_verified 声明（已配置域名单）"
		}
		if !claims.EmailVerified {
			return false, "email 未经 IdP 验证（email_verified=false）"
		}
		domain := ""
		if at := strings.LastIndex(claims.Email, "@"); at >= 0 {
			domain = strings.ToLower(strings.TrimSpace(claims.Email[at+1:]))
		}
		matched := false
		for _, d := range cfg.AllowedEmailDomains {
			// 读侧再规范化（写侧 normalizeOIDCAllowedDomains 已 trim+小写）：
			// 带外写入/旧值（未小写、带空格）时逐字比较会永远不匹配 →
			// 全员拒登。比较两侧同口径，成本可忽略。
			if domain == strings.ToLower(strings.TrimSpace(d)) {
				matched = true
				break
			}
		}
		if !matched {
			return false, "email 域不在允许范围"
		}
	}
	if len(cfg.AllowedGroups) > 0 {
		if claims.GroupsMalformed {
			return false, "groups 声明类型不支持（需字符串数组或以空白/逗号分隔的字符串）"
		}
		if len(claims.Groups) == 0 {
			return false, "IdP 未返回 groups 声明（已配置组名单）"
		}
		matched := false
		for _, want := range cfg.AllowedGroups {
			for _, got := range claims.Groups {
				if got == want {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false, "groups 不在允许范围"
		}
	}
	return true, ""
}

// oidcEmailVerified 解析 email_verified 声明：布尔或 "true"/"false" 字符串
// （部分 IdP 以字符串返回）；缺失/null/其他形态=未知（known=false）。
func oidcEmailVerified(raw json.RawMessage) (verified, known bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return false, false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// oidcGroups 解析 groups 声明，与 email_verified 同族的「IdP 声明形态差异」
// 归一：
//   - 标准形态=字符串数组；
//   - 单个字符串（自建 Keycloak 自定义 mapper / SAML 桥接 / ADFS 常见）按
//     空白、逗号、分号切分；
//   - 缺失/null → 空集（malformed=false，由白名单判定按「未返回」拒登）；
//   - 其他形态（数字数组、对象等）→ malformed=true，调用方据此把审计 reason
//     与「声明缺失」区分开。
//
// 元素逐项 trim 并丢弃空项：白名单比较是逐字匹配，IdP 的多余空白不得造成
// 全员拒登。
func oidcGroups(raw json.RawMessage) (groups []string, malformed bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return normalizeOIDCGroupValues(arr), false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return normalizeOIDCGroupValues(strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || r == ';' || unicode.IsSpace(r)
		})), false
	}
	return nil, true
}

// normalizeOIDCGroupValues trim + 丢空（保持 IdP 顺序）。
func normalizeOIDCGroupValues(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, g := range raw {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// oidcAllowedDomainRe 允许的 email 域条目形态（小写字母/数字/点/连字符，
// 不含 @ 与空白）。规范化在写入侧完成（trim+小写+去空），校验失败 400。
var oidcAllowedDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// normalizeOIDCAllowedDomains 写入侧规范化 email 域名单：trim+小写、去空去重、
// 逐条形态校验、条目数与单项长度预算。顺序保持（管理语义：列表即配置）。
func normalizeOIDCAllowedDomains(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := map[string]struct{}{}
	for _, item := range raw {
		d := strings.ToLower(strings.TrimSpace(item))
		if d == "" {
			continue
		}
		if truncateRunes(d, oidcAllowListEntryMaxRunes) != d {
			return nil, fmt.Errorf("允许的 email 域条目过长（最多 %d 字符）", oidcAllowListEntryMaxRunes)
		}
		if !oidcAllowedDomainRe.MatchString(d) || strings.Contains(d, "..") {
			return nil, fmt.Errorf("允许的 email 域 %q 无效（应形如 example.com）", item)
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	if len(out) > oidcAllowListMaxEntries {
		return nil, fmt.Errorf("允许的 email 域最多 %d 条（当前 %d 条）", oidcAllowListMaxEntries, len(out))
	}
	return out, nil
}

// normalizeOIDCAllowedGroups 写入侧规范化组名单：trim、去空去重
// （组名大小写敏感——IdP 组声明原样匹配）、条目数与单项长度预算。
func normalizeOIDCAllowedGroups(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := map[string]struct{}{}
	for _, item := range raw {
		g := strings.TrimSpace(item)
		if g == "" {
			continue
		}
		if truncateRunes(g, oidcAllowListEntryMaxRunes) != g {
			return nil, fmt.Errorf("允许的组条目过长（最多 %d 字符）", oidcAllowListEntryMaxRunes)
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	if len(out) > oidcAllowListMaxEntries {
		return nil, fmt.Errorf("允许的组最多 %d 条（当前 %d 条）", oidcAllowListMaxEntries, len(out))
	}
	return out, nil
}

// normalizeOIDCIssuer 通用规范化：去首尾空白与尾斜杠；主机按 RFC 3986 归一到
// 小写并去掉协议默认端口（https:443 / http:80）；随后按主机名匹配 Entra 家族
// 登录主机，缺 /v2.0 时自动补——Entra 的 v1 端点无 OIDC 发现文档，漏写 /v2.0
// 是最高频配置错误。
//
// 主机归一后 :443 与大写主机形态才真正可用：go-oidc 要求配置的 issuer 与发现
// 文档宣告的 issuer **逐字节相等**（Issuers must match exactly），而 IdP 宣告值
// 恒为小写、不带默认端口。旧实现只按 Hostname 查表、原样保留 :443 与大小写，
// 这类地址保存能过、测试端点报英文 mismatch、登录恒失败——注释曾声称「同样
// 命中」，与实际能力不符。路径/查询保持原样（只有主机不区分大小写）。
func normalizeOIDCIssuer(raw string) string {
	issuer := strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return issuer
	}
	hostName := u.Hostname()
	if hostName != "" {
		port := u.Port()
		if (strings.EqualFold(u.Scheme, "https") && port == "443") || (strings.EqualFold(u.Scheme, "http") && port == "80") {
			port = ""
		}
		normalizedHost := strings.ToLower(hostName)
		if port != "" {
			normalizedHost = net.JoinHostPort(normalizedHost, port)
		} else if strings.Contains(normalizedHost, ":") && !strings.HasPrefix(normalizedHost, "[") {
			// IPv6 字面量在 URL 中必须带方括号。
			normalizedHost = "[" + normalizedHost + "]"
		}
		if normalizedHost != u.Host {
			u.Host = normalizedHost
			issuer = u.String()
		}
		if !entraIssuerHosts[strings.ToLower(hostName)] {
			return issuer
		}
	} else if !entraIssuerHosts[strings.ToLower(u.Hostname())] {
		return issuer
	}
	if !strings.HasSuffix(issuer, "/v2.0") {
		issuer += "/v2.0"
	}
	return issuer
}

// entraIssuerHosts Entra 家族登录主机（全球与各主权云）。仅这些主机适用
// 「补 /v2.0」兼容特例。
var entraIssuerHosts = map[string]bool{
	"login.microsoftonline.com":        true,
	"login.microsoftonline.us":         true,
	"login.partner.microsoftonline.cn": true,
	"login.chinacloudapi.cn":           true,
}

// oidcProvider 按 issuer 获取(带缓存的 discovery;:网络发现移出全局锁,
// 失败负缓存 oidcNegCacheTTL——IdP 故障时不再持锁串行 8s 逐请求回源)。
func oidcProvider(issuer string) (*oidc.Provider, error) {
	// 入口复验出站地址策略：库中 issuer 可能来自配置导入、自动备份还原、
	// 集群快照或带外改库（写侧校验只覆盖面板保存路径）。discovery 会把它
	// 当作唯一出站目标，策略不合格必须零出站拒绝。
	if err := validateOIDCIssuerURL(issuer); err != nil {
		return nil, fmt.Errorf("OIDC 服务地址不合规: %w", err)
	}
	oidcProvMu.Lock()
	e, ok := oidcProvCach[issuer]
	oidcProvMu.Unlock()
	if ok {
		if e.provider != nil {
			return e.provider, nil
		}
		if time.Since(e.failedAt) < oidcNegCacheTTL {
			return nil, e.err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// per-issuer singleflight：冷缓存/IdP 恢复后的登录风暴（或公开登录端点的
	// 并发打点）此前各自发起 discovery（8s + 完整 JWKS 拉取），可被用于放大
	// 出站连接。合并同 issuer 的在途请求；结果（含失败负缓存）由 leader 写入
	// 缓存，等待者在 flight 内复用。
	value, err, _ := oidcProvFlight.Do(issuer, func() (any, error) {
		// leader 复核缓存：等待期间其他请求可能已填充（含失败负缓存）。
		oidcProvMu.Lock()
		entry, cached := oidcProvCach[issuer]
		oidcProvMu.Unlock()
		if cached {
			if entry.provider != nil {
				return entry.provider, nil
			}
			if time.Since(entry.failedAt) < oidcNegCacheTTL {
				return nil, entry.err
			}
		}
		// 出站客户端注入（discovery 与其后的 JWKS 验签同源）：issuer 基准策略
		// 编入客户端（go-oidc 的 RemoteKeySet 以 context.Background() 重建
		// keyset，context 里的策略值会丢），同时随 context 注入供重定向复验。
		policyCtx := oidcOutboundContext(ctx, issuer)
		p, derr := oidc.NewProvider(oidc.ClientContext(policyCtx, newOIDCOutboundClient(issuer)), issuer)
		oidcProvMu.Lock()
		if derr != nil {
			werr := fmt.Errorf("OIDC 发现失败(检查服务地址可达性与 .well-known 配置): %w", derr)
			oidcProvCachePutLocked(issuer, oidcProvEntry{err: werr, failedAt: time.Now()})
			oidcProvMu.Unlock()
			return nil, werr
		}
		oidcProvCachePutLocked(issuer, oidcProvEntry{provider: p})
		oidcProvMu.Unlock()
		return p, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*oidc.Provider), nil
}

// oidcProvCachePutLocked 写入缓存并维持容量上限；调用方须持有 oidcProvMu。
func oidcProvCachePutLocked(issuer string, entry oidcProvEntry) {
	if _, exists := oidcProvCach[issuer]; !exists && len(oidcProvCach) >= oidcProvCacheMax {
		for key := range oidcProvCach {
			delete(oidcProvCach, key)
			break
		}
	}
	oidcProvCach[issuer] = entry
}

func oidcProviderInvalidate(issuer string) {
	oidcProvMu.Lock()
	delete(oidcProvCach, issuer)
	oidcProvMu.Unlock()
}

func oidcOAuthConfig(cfg OIDCConfig, p *oidc.Provider, callbackURL string) oauth2.Config {
	return oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  callbackURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// ── 公开端点 ──

var oidcStatusFailureLog = struct {
	sync.Mutex
	at time.Time
}{}

const oidcStatusFailureLogWindow = time.Minute

func logOIDCStatusFailure(err error) {
	now := time.Now()
	oidcStatusFailureLog.Lock()
	if !oidcStatusFailureLog.at.IsZero() && now.Sub(oidcStatusFailureLog.at) < oidcStatusFailureLogWindow {
		oidcStatusFailureLog.Unlock()
		return
	}
	oidcStatusFailureLog.at = now
	oidcStatusFailureLog.Unlock()
	services.Logf("warn", "读取 OIDC 状态失败: %v", err)
}

// logOIDCStatusUnusable 记录「库内 issuer 不合规或启用凭证不完整」的公开端点
// 降级：与读失败同一防放大思路（60s 节流），独立状态窗口（两类故障不互相吞没）。
var oidcStatusIssuerLog = struct {
	sync.Mutex
	at time.Time
}{}

func logOIDCStatusUnusable(err error) {
	now := time.Now()
	oidcStatusIssuerLog.Lock()
	if !oidcStatusIssuerLog.at.IsZero() && now.Sub(oidcStatusIssuerLog.at) < oidcStatusFailureLogWindow {
		oidcStatusIssuerLog.Unlock()
		return
	}
	oidcStatusIssuerLog.at = now
	oidcStatusIssuerLog.Unlock()
	services.Logf("warn", "库内 OIDC 配置不可用（issuer 不合规或凭证不完整），登录页按未启用呈现（需管理员修正配置）: %v", err)
}

// OIDCStatus GET /auth/oidc/status(公开):登录页按钮显隐与展示名。
func (h *Handlers) OIDCStatus(c *gin.Context) {
	cfg, cfgErr := loadOIDCConfig()
	if cfgErr != nil {
		// 公开端点：读失败按未启用展示（fail-closed）；持续故障按 60s 窗口留痕，
		// 避免无鉴权请求形成日志放大。
		logOIDCStatusFailure(cfgErr)
	}
	if cfgErr != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"enabled": false}})
		return
	}
	// 导入/自动备份还原/集群快照可绕过面板保存门，带入不合规 issuer 或
	// enabled=true 但凭证不全的配置。不得宣告必然失败的登录按钮；按未启用
	// 呈现并沿用 60s 节流留痕。
	if err := cfg.usable(); err != nil {
		if cfg.Enabled {
			logOIDCStatusUnusable(err)
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"enabled": false}})
		return
	}
	name := cfg.DisplayName
	if name == "" {
		if u, err := url.Parse(cfg.Issuer); err == nil {
			name = u.Host
		} else {
			name = "OIDC"
		}
	}
	// 展示名上限兜底：带外写入/历史坏值可能是任意长度，公开响应必须按
	// 与保存侧同一口径（30 字符）截断。
	name = truncateRunes(name, oidcDisplayNameMaxRunes)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"enabled": true, "display_name": name}})
}

// trustedProxyRemoteAddr（2026-09-19 用户裁定按建议收窄)
// 仅当直连对端为回环/私网(RFC1918+ULA+链路本地,即可信反代)时才采信
// X-Forwarded-Proto/Host。解析失败(畸形/空)一律 false——宁可回退请求自身
// 基址也不采信可疑来源。
func trustedProxyRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // 容忍无端口形态(测试构造/非 TCP  listener)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// requestOrigin 推导回调基址(反向代理场景尊重 X-Forwarded-Proto/Host)。
// 转发头仅当直连对端可信时采信——路由器 SetTrustedProxies(nil)
// 意味着任何公网客户端都能伪造 X-Forwarded-Host,无来源校验会把回调
// redirect_uri 与成功回跳基址(令牌走 fragment)指向攻击者域。
func requestOrigin(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	host := c.Request.Host
	if trustedProxyRemoteAddr(c.Request.RemoteAddr) {
		// scheme 取值白名单（与 oidcCookieSecure 同判据）：只采信 http/https，
		// 其余取值（javascript:/data: 等任意串）回退默认——受信反代也可能
		// 原样透传客户端伪造的转发头，scheme 不校验会把回调基址与成功回跳
		// 拼成非 HTTP(S) 形态。
		if proto := c.GetHeader("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
			scheme = "https"
		} else if strings.EqualFold(proto, "http") {
			scheme = "http"
		}
		if fwdHost := c.GetHeader("X-Forwarded-Host"); fwdHost != "" {
			host = fwdHost
		}
	}
	return scheme + "://" + host
}

func oidcCallbackURL(c *gin.Context) string {
	return requestOrigin(c) + "/api/v1/auth/oidc/callback"
}

// oidcStandardErrorCodes OAuth2/OIDC 规范错误码全集(RFC 6749 §5.2 + OIDC
// Core §3.1.2.6)——回调 error 参数白名单。
var oidcStandardErrorCodes = map[string]struct{}{
	"invalid_request":            {},
	"unauthorized_client":        {},
	"access_denied":              {},
	"unsupported_response_type":  {},
	"invalid_scope":              {},
	"server_error":               {},
	"temporarily_unavailable":    {},
	"interaction_required":       {},
	"login_required":             {},
	"account_selection_required": {},
	"consent_required":           {},
	"invalid_request_uri":        {},
	"invalid_request_object":     {},
	"invalid_client":             {},
	"invalid_grant":              {},
	"unsupported_grant_type":     {},
	"unsupported_token_type":     {},
	"expired_token":              {},
}

// sanitizeOIDCErrorParam:回调 error 参数仅放行标准错误码(大小写
// 不敏感,保留原形回显);超长或非白名单值返回空串——外部可控文本不得经
// 前端错误页当系统提示渲染。
func sanitizeOIDCErrorParam(raw string) string {
	code := strings.TrimSpace(raw)
	if len(code) > 64 {
		return ""
	}
	if _, ok := oidcStandardErrorCodes[strings.ToLower(code)]; !ok {
		return ""
	}
	return code
}

// oidcStateCookieName 是 OIDC state↔浏览器绑定的 cookie 名。
const oidcStateCookieName = "oidc_state"

// oidcStateBindingEnabled 是绑定校验开关（默认开）。既有流程测试（无 cookie
// 容器）在 setupOIDCTest 中显式关闭；绑定行为由
// TestOIDCCallback_stateBoundToBrowser 专题覆盖。
var oidcStateBindingEnabled = true

// oidcStateBinding 计算 state 的 HMAC-SHA256 绑定值（十六进制）。cookie 只承载
// 绑定值（非明文 state），且绝不作为认证凭证——它的唯一用途是证明「发起
// 授权的浏览器」与「回调的浏览器」是同一个。
func oidcStateBinding(secret, state string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(state))
	return hex.EncodeToString(mac.Sum(nil))
}

// oidcCookieSecure 判定是否加 Secure：直连 TLS，或受信代理声明的 https。
// 不可信来源的 X-Forwarded-Proto 不得影响 cookie 属性（与 requestOrigin 同门）。
func oidcCookieSecure(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	if !trustedProxyRemoteAddr(c.Request.RemoteAddr) {
		return false
	}
	return strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}

// setOIDCStateCookie 下发 state 绑定 cookie（HttpOnly，10 分钟，Lax）。
func setOIDCStateCookie(c *gin.Context, secret, state string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    oidcStateBinding(secret, state),
		Path:     "/",
		MaxAge:   int(oidcStateTTL / time.Second),
		HttpOnly: true,
		Secure:   oidcCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearOIDCStateCookie 回调消费后清除绑定 cookie。
func clearOIDCStateCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   oidcCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	})
}

// OIDCLogin GET /auth/oidc/login?return_to=...
// 生成 state/nonce/PKCE 后跳转提供商授权页。
func (h *Handlers) OIDCLogin(c *gin.Context) {
	// login 是浏览器整页导航(登录页按钮/链接触发)——失败一律 302
	// 回前端登录页错误位(oidc_error 经 URL fragment 携带,不发给服务器),
	// 与回调同型,不渲染裸 JSON。
	fail := func(msg string) {
		c.Redirect(http.StatusFound, requestOrigin(c)+"/#/login?oidc_error="+url.QueryEscape(msg))
	}
	cfg, cfgErr := loadOIDCConfig()
	if cfgErr != nil {
		services.Logf("warn", "OIDC 登录读取配置失败: %v", cfgErr)
		fail("OIDC 配置读取失败")
		return
	}
	// 启用门与 status 端点、保存侧启用门同源（usable）：库值可经导入/快照
	// 绕过保存门，此时 status 已隐藏按钮，公开入口若只判 Enabled+Issuer 非空
	// 仍会 302 跳 IdP（client_id 为空 → 用户停在 IdP 报错页）。
	if err := cfg.usable(); err != nil {
		fail("OIDC 未启用")
		return
	}
	// 过期清理先行:封顶判定必须在自愈清理之后——
	// 否则死条目(未被回调消费的过期 state)永无清理机会,4096 次未完成
	// 登录即可把 OIDC 登录永久 429 直至重启(防护自身被武器化)。
	oidcStates.Range(func(k, v any) bool {
		if e, ok := v.(oidcStateEntry); ok && time.Since(e.created) > oidcStateTTL {
			// LoadAndDelete 原子扣减——与回调消费方竞争同键时恰好一个
			// 赢家,计数不向负漂移(封顶判定因此不被侵蚀)。
			if _, loaded := oidcStates.LoadAndDelete(k); loaded {
				oidcStateCount.Add(-1)
			}
		}
		return true
	})
	// 在册 state 条目封顶——未认证泛洪不得无限放大内存(上限远高于
	// 正常未完成登录量级;到达即拒绝,不影响「回调失败不计锁定」裁定)。
	// 改为原子预留（CAS 递增），后续失败路径经 defer 释放——
	// 检查与入册不再有 TOCTOU 窗口。
	if !reserveOIDCStateSlot() {
		fail("登录请求过于频繁，请稍后再试")
		return
	}
	reserved := true
	defer func() {
		if reserved {
			oidcStateCount.Add(-1)
		}
	}()
	p, err := oidcProvider(cfg.Issuer)
	if err != nil {
		// 登录页错误位对未认证访问者可见——原始 discovery
		// 错误（含 IdP 地址/网络细节）此前直接回显；归一为固定短句，原始错误
		// 仅落日志（管理员侧 test 端点保留详细错误，已 admin 门）。
		services.Logf("warn", "OIDC 登录服务发现失败: %v", err)
		fail("OIDC 服务不可达，请检查配置")
		return
	}
	stateRaw := make([]byte, 16)
	nonceRaw := make([]byte, 16)
	if _, err := rand.Read(stateRaw); err != nil {
		fail("生成状态失败")
		return
	}
	if _, err := rand.Read(nonceRaw); err != nil {
		fail("生成 nonce 失败")
		return
	}
	// PKCE verifier 由 oauth2.GenerateVerifier() 内部自行取随机（历史
	// 原 verifierRaw 随机读取从未消费，死代码已删）。
	state := hex.EncodeToString(stateRaw)
	nonce := hex.EncodeToString(nonceRaw)
	verifier := oauth2.GenerateVerifier()
	returnTo := sanitizeOIDCReturnTo(c.Query("return_to"))
	oidcStates.Store(state, oidcStateEntry{nonce: nonce, verifier: verifier, returnTo: returnTo, created: time.Now()})
	reserved = false // 槽位已由预留提交，计数保持 +1
	// state 与发起登录的浏览器绑定——回调侧校验同名 cookie 的 HMAC
	// 绑定值，跨浏览器/跨会话的 code+state 组合无法完成登录。
	setOIDCStateCookie(c, h.cfg.JWTSecret, state)

	oauthCfg := oidcOAuthConfig(cfg, p, oidcCallbackURL(c))
	authURL := oauthCfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	c.Redirect(http.StatusFound, authURL)
}

// isUniqueConstraintError 判定 SQLite 唯一约束冲突——modernc 驱动错误文本口径
// 「UNIQUE constraint failed」+ 历史驱动兼容段「already exists」（users.go
// 用户名 409 的两处双段判定并入本 helper 单一源）。
func isUniqueConstraintError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "already exists"))
}

// truncateRunes 按 rune 截断（display_name 与 username 共用 50 rune
// 预算，避免 byte 截断切坏 UTF-8 或超列宽）。
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

// oidcDisplayName 派生 OIDC 用户的显示名，重复登录刷新与 JIT 首登共用。
// 统一「trim → rune 截断（列宽 50 的单位是字符不是字节）→ 空值回退
// fallback」：IdP 是显示名的唯一来源（UI 明示「由认证服务管理」），claims
// 里的纯空白不得落库；IdP 侧删除显示名后回退本地用户名，避免既有用户长期
// 停留在首次开户的陈旧快照上。
func oidcDisplayName(claimName, fallback string) string {
	if name := truncateRunes(strings.TrimSpace(claimName), 50); name != "" {
		return name
	}
	return truncateRunes(strings.TrimSpace(fallback), 50)
}

// oidcIdentity 是 (issuer,subject) 命中的 OIDC 身份行。
type oidcIdentity struct {
	id              int
	username        string
	role            string
	isEnabled       int
	passwordVersion int64
}

// lookupOIDCIdentity 按 (issuer,subject) 查身份行（命中分支、JIT 并发回退
// 共用同一查询口径——收敛）。
func lookupOIDCIdentity(issuer, subject string) (oidcIdentity, error) {
	var ident oidcIdentity
	err := db.DB.QueryRow(`SELECT id, username, role, COALESCE(is_enabled,0), COALESCE(password_version,0)
		FROM users WHERE auth_provider='oidc' AND oidc_issuer=? AND oidc_subject=?`, issuer, subject).
		Scan(&ident.id, &ident.username, &ident.role, &ident.isEnabled, &ident.passwordVersion)
	return ident, err
}

// lookupOIDCIdentityCompat 读侧归一后的身份查询：库中原值可能与归一值不同
// （带外写入的 Entra issuer 缺 /v2.0、带尾斜杠的 issuer），历史 JIT 行按原值
// 建键——只查归一值会 miss 并重复开户。归一值未命中且原值不同时回退原值查询。
// 命中后不在读路径改写该行（避免两行竞争）；改写由保存路径的
// saveOIDCConfigWithIssuerMigration 在写回归一值时同批完成。
func lookupOIDCIdentityCompat(cfg OIDCConfig, subject string) (oidcIdentity, error) {
	ident, err := lookupOIDCIdentity(cfg.Issuer, subject)
	if err == nil || !errors.Is(err, sql.ErrNoRows) || cfg.rawIssuer == "" || cfg.rawIssuer == cfg.Issuer {
		return ident, err
	}
	return lookupOIDCIdentity(cfg.rawIssuer, subject)
}

// oidcCandidateUsername 选择未被占用的 JIT 用户名。无冲突保持一次唯一索引
// 点查；base 已占用时一次批量载入相关候选，在内存中选择首个空档，查询数不随
// 冲突数增长。并发写入者的唯一冲突仍由 createOIDCUserWithRetry 兜底重试。
func oidcCandidateUsername(base string) (string, error) {
	var exists int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username=?", base).Scan(&exists); err != nil {
		return "", err
	}
	if exists == 0 {
		return base, nil
	}

	// 50 字符预算会让长 base 在不同后缀宽度下截到 48/47… 位；批量查询使用
	// 共同前 47 位覆盖全部截断形态。LIKE 元字符按字面转义，额外相似用户名
	// 由下方精确 map 判定过滤，不影响结果。
	baseRunes := []rune(base)
	prefix := base
	if len(baseRunes) >= 48 {
		prefix = string(baseRunes[:47])
	}
	escapedPrefix := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix)
	rows, err := db.DB.Query(`SELECT username FROM users WHERE username LIKE ? ESCAPE '\'`, escapedPrefix+"%")
	if err != nil {
		return "", err
	}
	occupied := map[string]struct{}{}
	for rows.Next() {
		var username string
		if scanErr := rows.Scan(&username); scanErr != nil {
			rows.Close()
			return "", scanErr
		}
		occupied[username] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()

	for i := 2; ; i++ {
		suffix := fmt.Sprintf("-%d", i)
		candidate := base + suffix
		if len(baseRunes)+len(suffix) > 50 {
			budget := 50 - len(suffix)
			if budget < 0 {
				budget = 0
			}
			candidate = string(baseRunes[:budget]) + suffix
		}
		if _, taken := occupied[candidate]; !taken {
			return candidate, nil
		}
	}
}

// oidcJITInsertAttempts JIT 开户唯一冲突的重试上限（每次重试重新选择候选名）。
const oidcJITInsertAttempts = 3

// oidcJITInsertAttemptHook 测试缝（生产恒 nil）：在每次 INSERT 前调用，
// attempt 从 1 起；返回非 nil 即按该错误处理（模拟「候选检查已通过、INSERT
// 前并发者抢占候选名」的竞态），不执行真实 INSERT。
var oidcJITInsertAttemptHook func(attempt int) error

// createOIDCUserWithRetry JIT 开户：候选检查与 INSERT 之间
// 在「不同 subject、相同 preferred_username 并发首登」下仍会撞 username
// 唯一约束——旧实现只按 (issuer,subject) 回查，身份行不存在即令本次登录
// 失败。新语义：唯一冲突且身份行不存在时重算候选名并有限重试；同一 subject
// 的并发回调仍按命中分支收口，不补「创建」审计。
// 返回 (身份行, 是否本次创建, 错误)。
func createOIDCUserWithRetry(issuer, subject, base, displayName string) (oidcIdentity, bool, error) {
	for attempt := 1; attempt <= oidcJITInsertAttempts; attempt++ {
		candidate, err := oidcCandidateUsername(base)
		if err != nil {
			return oidcIdentity{}, false, err
		}
		var res sql.Result
		if oidcJITInsertAttemptHook != nil {
			err = oidcJITInsertAttemptHook(attempt)
		}
		if err == nil {
			// password_hash 置空:bcrypt 对空哈希恒败,OIDC 用户密码登录天然不可用。
			res, err = db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled, auth_provider, oidc_subject, oidc_issuer) VALUES (?, '', 'user', ?, 1, 'oidc', ?, ?)",
				candidate, displayName, subject, issuer)
		}
		if err == nil {
			newID, idErr := res.LastInsertId()
			if idErr != nil {
				return oidcIdentity{}, false, idErr
			}
			return oidcIdentity{id: int(newID), username: candidate, role: "user", isEnabled: 1}, true, nil
		}
		if !isUniqueConstraintError(err) {
			return oidcIdentity{}, false, err
		}
		// 同 subject 并发回调：对端已建身份行 → 沿用其账号状态。
		ident, lookupErr := lookupOIDCIdentity(issuer, subject)
		if lookupErr == nil {
			return ident, false, nil
		}
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			return oidcIdentity{}, false, lookupErr
		}
		// 冲突发生在 username（不同 subject 同名竞态）→ 重算候选名重试。
	}
	return oidcIdentity{}, false, fmt.Errorf("OIDC JIT 用户创建冲突重试耗尽")
}

// oidcDisplayNameRefreshFailing 记录显示名刷新的连续失败状态（留痕分级用）。
// 登录热路径不得刷屏：连续失败的首条升级 error 级，后续降回 warn，成功后复位
// ——与 touchLastLogin 同一留痕口径。
var oidcDisplayNameRefreshFailing atomic.Bool

// refreshOIDCDisplayName 按 IdP 最新 claims 刷新展示名（best-effort）。
// 显示名是 IdP 派生的展示属性而非授权前提：写失败不得中断登录（旧实现 302
// 到「更新用户资料失败」，把排障方向引向认证而非存储），下次登录自愈。
func refreshOIDCDisplayName(userID int, username, name string) {
	_, err := db.DB.Exec("UPDATE users SET display_name=? WHERE id=? AND COALESCE(display_name,'')<>?", name, userID, name)
	if err == nil {
		oidcDisplayNameRefreshFailing.Store(false)
		return
	}
	level := "warn"
	if !oidcDisplayNameRefreshFailing.Swap(true) {
		level = "error"
	}
	services.Logf(level, "OIDC 登录刷新显示名失败（非凭据问题，下次登录重试；user_id=%d username=%s）: %v", userID, username, err)
}

// OIDCCallback GET /auth/oidc/callback——授权码换令牌→ID Token 验签→
// 用户命中/禁用检查/JIT 开户→签发本站 JWT(与密码登录同构,auth_method=oidc)。
func (h *Handlers) OIDCCallback(c *gin.Context) {
	// 回调是浏览器整页导航——失败一律 302 回前端错误页(error 经 URL
	// fragment 携带,不渲染裸 JSON)。审计归因用占位用户名:失败路径身份尚未
	// 验证,不落请求方可控的用户名。fail 必须先于配置读取定义：配置读失败 /
	// 未启用同样发生在导航链上，返回裸 JSON 会让浏览器停在一个 JSON 页面。
	fail := func(msg, auditDetail string) {
		if auditDetail != "" {
			services.RecordAuditLog("oidc-user", "认证拒绝", "用户认证", services.FormatAuditDetail(auditDetail, services.AuditResultPart("failure")), c.ClientIP())
		}
		c.Redirect(http.StatusFound, requestOrigin(c)+"/#/oidc/callback?error="+url.QueryEscape(msg))
	}
	cfg, cfgErr := loadOIDCConfig()
	if cfgErr != nil {
		services.Logf("warn", "OIDC 回调读取配置失败: %v", cfgErr)
		fail("OIDC 配置读取失败", "")
		return
	}
	// 同 login：启用门单源（usable），不完整配置下不得继续走到 discovery/换码。
	if err := cfg.usable(); err != nil {
		fail("OIDC 未启用", "")
		return
	}
	// 先验 state↔浏览器绑定，再消费 state（失败不消耗合法 state 之外
	// 的语义：cookie 缺失/不匹配一律拒绝，不回显 token）。
	queryState := c.Query("state")
	if oidcStateBindingEnabled {
		bindingCookie, cookieErr := c.Cookie(oidcStateCookieName)
		if cookieErr != nil || bindingCookie == "" {
			fail("登录状态与当前浏览器不匹配,请重新登录", "OIDC state 缺少浏览器绑定")
			return
		}
		if subtle.ConstantTimeCompare([]byte(bindingCookie), []byte(oidcStateBinding(h.cfg.JWTSecret, queryState))) != 1 {
			fail("登录状态与当前浏览器不匹配,请重新登录", "OIDC state 浏览器绑定不匹配")
			return
		}
		clearOIDCStateCookie(c)
	}
	stateEntryRaw, ok := oidcStates.LoadAndDelete(queryState)
	if ok {
		oidcStateCount.Add(-1)
	}
	if !ok {
		fail("登录状态无效或已过期,请重新登录", "")
		return
	}
	entry := stateEntryRaw.(oidcStateEntry)
	if time.Since(entry.created) > oidcStateTTL {
		fail("登录状态已过期,请重新登录", "")
		return
	}
	if errParam := c.Query("error"); errParam != "" {
		// +:仅回显 OAuth2/OIDC 标准错误码——description 与自造
		// error 值均为外部可控文本,回显会被登录页当系统提示渲染(社工文案
		// 注入面);非白名单短码一律吞掉,只保留「提供商拒绝授权」事实。
		msg := "提供商拒绝授权"
		if code := sanitizeOIDCErrorParam(errParam); code != "" {
			msg += ": " + code
		}
		fail(msg, "OIDC 提供商拒绝授权")
		return
	}
	p, err := oidcProvider(cfg.Issuer)
	if err != nil {
		services.Logf("warn", "OIDC 回调服务发现失败: %v", err)
		fail("OIDC 服务不可达，请检查配置", "OIDC 服务发现失败")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	// 令牌交换同样走单源出站客户端（oauth2 消费 oidc.ClientContext 写入的同一
	// context key）：token_endpoint 的重定向不得把 client_secret 带向非 https
	// 地址；基准 issuer 一并注入，端点策略不接受「https issuer + 回环 http 端点」。
	ctx = oidc.ClientContext(oidcOutboundContext(ctx, cfg.Issuer), oidcOutboundClient)
	oauthCfg := oidcOAuthConfig(cfg, p, oidcCallbackURL(c))
	oauth2Token, err := oauthCfg.Exchange(ctx, c.Query("code"),
		oauth2.SetAuthURLParam("code_verifier", entry.verifier))
	if err != nil {
		// 同族：交换错误含 token_endpoint 地址/HTTP 细节，不得
		// 回显给未认证浏览器——固定短句 + 原始错误仅日志。
		services.Logf("warn", "OIDC 令牌交换失败: %v", err)
		fail("OIDC 令牌交换失败，请稍后重试", "OIDC 令牌交换失败")
		return
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	if rawIDToken == "" {
		fail("提供商未返回 id_token", "OIDC 缺少 id_token")
		return
	}
	verifier := p.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		services.Logf("warn", "OIDC id_token 校验失败: %v", err)
		fail("ID Token 校验失败，请稍后重试", "OIDC id_token 校验失败")
		return
	}
	var claims struct {
		Sub               string          `json:"sub"`
		Nonce             string          `json:"nonce"`
		Email             string          `json:"email"`
		EmailVerified     json.RawMessage `json:"email_verified"`
		PreferredUsername string          `json:"preferred_username"`
		Name              string          `json:"name"`
		Groups            json.RawMessage `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		fail("解析用户信息失败", "OIDC claims 解析失败")
		return
	}
	if claims.Nonce != entry.nonce {
		fail("nonce 不匹配(疑似重放)", "OIDC nonce 不匹配")
		return
	}
	// sub 是 (issuer,subject) 身份主键，空 sub 会把多个自然人折叠到
	// oidc_subject='' 同一行——fail-visible，不建空主体身份。
	if strings.TrimSpace(claims.Sub) == "" {
		fail("提供商未返回用户标识(sub)", "OIDC 缺少 sub")
		return
	}
	// 访问白名单（可选，缺省空=不限制）：每次回调都判定（IdP 侧变更即时
	// 生效），先于身份命中/JIT——不在名单内的主体连 JIT 开户都不发生。
	// 域名单叠加 email_verified（缺失/false 一律拒登）：域白名单信任的是
	// 「IdP 已验证该邮箱归属」，未验证的自定义邮箱声明可被任何人指向允许域。
	emailVerified, emailVerifiedSeen := oidcEmailVerified(claims.EmailVerified)
	groups, groupsMalformed := oidcGroups(claims.Groups)
	if allowed, reason := oidcAccessAllowed(cfg, oidcAccessClaims{
		Email:             claims.Email,
		EmailVerified:     emailVerified,
		EmailVerifiedSeen: emailVerifiedSeen,
		Groups:            groups,
		GroupsMalformed:   groupsMalformed,
	}); !allowed {
		fail("账号不在允许登录的范围，请联系管理员", "OIDC 白名单拒绝："+reason)
		return
	}

	// 用户命中:OIDC 用户独立行(不绑定本地账号),按 (issuer, subject) 定位。
	// 同查 password_version——OIDC JWT 携带 pwd_ver,与本地会话同构,
	// 配置导入的版本递增不再把 OIDC 会话打入永久 401 死循环。
	ident, err := lookupOIDCIdentityCompat(cfg, claims.Sub)
	switch {
	case err == nil:
		if ident.isEnabled != 1 {
			services.RecordAuditLog(ident.username, "登录失败", "用户认证", services.FormatAuditDetail(fmt.Sprintf("OIDC 登录 %s(账号已禁用)", services.AuditUserPart(ident.id, ident.username)), services.AuditResultPart("failure")), c.ClientIP())
			fail("账号已被禁用", "")
			return
		}
		// 显示名是 IdP 源属性——重复登录按最新 claims 刷新（否则
		// 永久停留在首次开户快照，而 UI 明示「由认证服务管理」）。role/
		// is_enabled/username 仍由本地管理；username 刷新涉及唯一冲突与历史
		// 链接，本轮保留本地值（报告裁定：单独策略）。
		// 刷新失败不阻断登录（与 touchLastLogin 同口径）：显示名是派生展示
		// 属性、非授权前提，瞬时写失败（WAL 长占/锁）不应把用户挡在认证之外，
		// 下次登录自愈。写侧 SQL 自带「值有变才写」判据，claims 空白回退
		// 用户名同样只在值确实变化时落库。
		refreshOIDCDisplayName(ident.id, ident.username, oidcDisplayName(claims.Name, ident.username))
	case errors.Is(err, sql.ErrNoRows):
		// JIT 开户:默认普通角色;用户名取 preferred_username→email 本地部分→sub,
		// 冲突时后缀去重(不绑定本地账号,同名共存)。TrimSpace 先于空值兜底
		// （纯空白 preferred_username 不得穿过兜底产出空用户名)。
		// 用户名策略（auth.go usernamePolicyRe
		// `^[a-z][a-z0-9]*$`）仅约束本地创建/改名，OIDC JIT 有意豁免——
		// preferred_username 是 IdP 源属性，强行归一会破坏身份链（JIT 命中键是
		// (issuer,subject)，撞 username 走后缀去重，无身份混同）。
		base := strings.TrimSpace(claims.PreferredUsername)
		if base == "" && claims.Email != "" {
			base = strings.TrimSpace(strings.SplitN(claims.Email, "@", 2)[0])
		}
		if base == "" {
			base = "oidc-" + claims.Sub
		}
		// 截断按 rune 计数——byte 截断会把中文/emoji 切成无效 UTF-8
		// 落库(前端展示乱码);列宽 VARCHAR(50) 的语义单位是字符不是字节。
		base = truncateRunes(base, 50)
		displayName := oidcDisplayName(claims.Name, base)
		// 不同 subject 同名并发首登仍会撞 username 唯一约束——
		// 唯一冲突后重算候选名有限重试（含 同 subject 并发回退）。
		var created bool
		var cerr error
		ident, created, cerr = createOIDCUserWithRetry(cfg.Issuer, claims.Sub, base, displayName)
		if cerr != nil {
			// 登录族（含 OIDC 回调）刻意不挂 rejectWriteDuringImport：登录必须在
			// 任何窗口内可用，写库操作由 DSN busy_timeout 串行等待而非 409 拒绝
			//（与密码 Login 同口径）。窗口内写锁竞争会让本步超时，故文案明示可重试。
			fail("创建 OIDC 用户失败，请稍后重试", "OIDC JIT 开户失败")
			return
		}
		if ident.isEnabled != 1 {
			services.RecordAuditLog(ident.username, "登录失败", "用户认证", services.FormatAuditDetail(fmt.Sprintf("OIDC 登录 %s(账号已禁用)", services.AuditUserPart(ident.id, ident.username)), services.AuditResultPart("failure")), c.ClientIP())
			fail("账号已被禁用", "")
			return
		}
		if created {
			services.RecordAuditLog(ident.username, "创建", "用户认证", services.FormatAuditDetail(fmt.Sprintf("OIDC 首次登录自动开户(%s)", cfg.Issuer), services.AuditResultPart("success")), c.ClientIP())
		}
	default:
		fail("查询用户失败", "")
		return
	}
	userID, username, role, passwordVersion := ident.id, ident.username, ident.role, ident.passwordVersion

	// 签发本站 JWT(与密码登录同构;auth_method=oidc 标记会话来源——本地
	// MFA 族功能对 OIDC 用户整体豁免,v2.3.0 用户裁定)。
	token, expiresAt, err := signSessionJWT(h.cfg.JWTSecret, userID, username, role, passwordVersion, 0, "oidc")
	if err != nil {
		fail("签发登录令牌失败", "")
		return
	}
	services.RecordAuditLog(username, "登录成功", "用户认证", services.FormatAuditDetail(fmt.Sprintf("OIDC 登录 %s", services.AuditUserPart(userID, username)), services.AuditResultPart("success")), c.ClientIP())
	// 与密码登录同序同源（touchLastLogin 单源）：成功审计已在上方落库，
	// last_login 尽力更新。记账失败不撤销已签发登录（不 500/不改 302），
	// 但必须留痕（连续失败首条升级 error 级）。
	touchLastLogin(userID, username, c.ClientIP())

	// 回跳前端:令牌走 URL fragment(不发给服务器),前端路由接收后入会话。
	returnTo := entry.returnTo
	if returnTo == "" {
		returnTo = "/"
	}
	front := requestOrigin(c)
	c.Redirect(http.StatusFound, front+"/#/oidc/callback?token="+url.QueryEscape(token)+"&expires_at="+fmt.Sprintf("%d", expiresAt.Unix())+"&return_to="+url.QueryEscape(returnTo))
}

// ── 管理端点(显示/测试/修改/删除) ──

// OIDCSettings GET /settings/oidc(admin)——secret 掩码返回。
// client_secret_masked 为文档性字段（apidocs 登记；核实
// 前端不消费——前端仅用 has_secret 显隐），保留供 API 消费者辨别 secret 已配置。
func (h *Handlers) OIDCSettings(c *gin.Context) {
	cfg, err := loadOIDCConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 OIDC 配置失败"})
		return
	}
	masked := cfg.ClientSecret
	if masked != "" {
		if len(masked) > 4 {
			masked = masked[:2] + "****" + masked[len(masked)-2:]
		} else {
			masked = "****"
		}
	}
	allowedEmailDomains := cfg.AllowedEmailDomains
	if allowedEmailDomains == nil {
		allowedEmailDomains = []string{}
	}
	allowedGroups := cfg.AllowedGroups
	if allowedGroups == nil {
		allowedGroups = []string{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"enabled": cfg.Enabled, "issuer": cfg.Issuer, "client_id": cfg.ClientID,
		"client_secret_masked": masked, "has_secret": cfg.ClientSecret != "",
		"display_name":  cfg.DisplayName,
		"callback_hint": "/api/v1/auth/oidc/callback",
		// 访问白名单回显（admin 端点，值非敏感——域/组名本就是配置面数据）。
		"allowed_email_domains": allowedEmailDomains,
		"allowed_groups":        allowedGroups,
	}})
}

// OIDCSettingsUpdate PUT /settings/oidc(admin)。
// 空 client_secret=保持现值(掩码回显不应逼用户重填)。
func (h *Handlers) OIDCSettingsUpdate(c *gin.Context) {
	// oidc_config 是 global_config 列，导入全量替换——窗口内提交会被静默覆盖
	// （用户以为已启用而实际被清空），与同族 global_config 写者同口径 409。
	if rejectWriteDuringImport(c, "保存 OIDC 设置（配置导入进行中）") {
		return
	}
	var req struct {
		Enabled             *bool     `json:"enabled"`
		Issuer              *string   `json:"issuer"`
		ClientID            *string   `json:"client_id"`
		ClientSecret        *string   `json:"client_secret"`
		DisplayName         *string   `json:"display_name"`
		AllowedEmailDomains *[]string `json:"allowed_email_domains"`
		AllowedGroups       *[]string `json:"allowed_groups"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	cfg, cfgErr := loadOIDCConfig()
	if cfgErr != nil {
		// 读失败/损坏时不得以零值继续合并——否则会清空 issuer/
		// client_id/secret（破坏性写）。整体拒绝，保留库中现值。
		services.Logf("error", "OIDC 配置更新前读取失败（已拒绝写入）: %v", cfgErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 OIDC 配置失败"})
		return
	}
	// 自由文本上限与前端 maxlength/实际用途对齐（此前无上限：任意长度
	// 直接落库，公开状态端点把超大展示名回给未认证请求，也撑大集群快照）。
	for _, field := range []struct {
		name  string
		value *string
		max   int
	}{
		{"显示名", req.DisplayName, oidcDisplayNameMaxRunes},
		{"Client ID", req.ClientID, 255},
		{"服务地址", req.Issuer, 512},
		{"Client Secret", req.ClientSecret, 512},
	} {
		if field.value == nil {
			continue
		}
		if trimmed := strings.TrimSpace(*field.value); truncateRunes(trimmed, field.max) != trimmed {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("%s 过长（最多 %d 字符）", field.name, field.max)})
			return
		}
	}
	before := cfg // 字段级变更留痕基线
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.Issuer != nil {
		issuer := normalizeOIDCIssuer(*req.Issuer)
		// url.Parse + scheme 白名单单源——HasPrefix("http") 放行
		// 「httpxy://…」类伪 scheme。判空用归一后的值：纯空白与空串同义
		//（清除语义），否则输入框残留空格会得到「地址须为 https URL」的
		// 误导报错。
		if issuer != "" {
			if err := validateOIDCIssuerURL(issuer); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
				return
			}
		}
		if issuer != cfg.Issuer {
			oidcProviderInvalidate(cfg.Issuer)
		}
		cfg.Issuer = issuer
	}
	if req.ClientID != nil {
		cfg.ClientID = strings.TrimSpace(*req.ClientID)
	}
	if req.ClientSecret != nil {
		// 先 trim 再判空：纯空白不是「未提供」——按原串判空会让 "   " 进入
		// 赋值分支把已存密钥覆盖成空串，保存还返回成功。secret 无清除语义
		//（仅 DELETE 可清），空白与空串同义=保持现值。
		if secret := strings.TrimSpace(*req.ClientSecret); secret != "" {
			cfg.ClientSecret = secret
		}
	}
	if req.DisplayName != nil {
		cfg.DisplayName = strings.TrimSpace(*req.DisplayName)
	}
	// 访问白名单（可选）：nil=不动，空数组=清除（恢复不限制）。
	if req.AllowedEmailDomains != nil {
		domains, derr := normalizeOIDCAllowedDomains(*req.AllowedEmailDomains)
		if derr != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: derr.Error()})
			return
		}
		cfg.AllowedEmailDomains = domains
	}
	if req.AllowedGroups != nil {
		groups, gerr := normalizeOIDCAllowedGroups(*req.AllowedGroups)
		if gerr != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: gerr.Error()})
			return
		}
		cfg.AllowedGroups = groups
	}
	// 启用前置门与公开状态共用 usable：issuer 合规且 client_id/secret 齐备。
	if cfg.Enabled {
		if err := cfg.usable(); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "启用前需完整配置服务地址、Client ID 与 Client Secret"})
			return
		}
	}
	// 本次保存会把归一值写回库（原值消失）：若库中原值正是新 issuer 归一前的
	// 形态，历史身份行必须同批迁移——否则兼容查询失效，同一 subject 再登录被
	// 当成首登新建一行（封禁/角色旁路），且这次改写不留任何审计 delta。
	migrateFrom := ""
	if before.rawIssuer != "" && before.rawIssuer != cfg.Issuer && normalizeOIDCIssuer(before.rawIssuer) == cfg.Issuer {
		migrateFrom = before.rawIssuer
	}
	// 换成不同 issuer 不会迁移旧身份行。保存前统计并在响应/审计中明示，
	// 让管理员知道旧行的角色与禁用状态不会传播到新 issuer 的 JIT 账号。
	// 身份行可能按 rawIssuer（如尾斜杠原值）或归一值建键，两种形态都要计数。
	reportStaleIdentities := cfg.Issuer != before.Issuer && migrateFrom == ""
	staleIdentityRows := 0
	if reportStaleIdentities {
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE auth_provider='oidc' AND oidc_issuer IN (?,?)`, before.Issuer, before.rawIssuer).Scan(&staleIdentityRows); err != nil {
			services.Logf("error", "OIDC 服务地址变更前统计存量身份行失败: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 OIDC 身份记录失败"})
			return
		}
	}
	migration, err := saveOIDCConfigWithIssuerMigration(cfg, migrateFrom)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 OIDC 配置失败"})
		return
	}
	if len(migration.conflicts) > 0 {
		services.Logf("warn", "OIDC 设置保存被拒绝：服务地址归一后与既有身份行冲突（%d 个 subject）", len(migration.conflicts))
		recordAudit(c, "更新失败", "OIDC 配置", services.FormatAuditDetail(
			"服务地址归一与既有身份行冲突", "subject："+strings.Join(migration.conflicts, "、"), services.AuditResultPart("failure")))
		c.JSON(http.StatusConflict, models.APIResponse{
			Code:    409,
			Message: fmt.Sprintf("服务地址归一后与既有身份记录冲突（%d 个 subject 已存在归一值身份行），请先人工合并重复账号再保存", len(migration.conflicts)),
			Data:    gin.H{"conflicts": migration.conflicts},
		})
		return
	}
	detail := oidcConfigUpdateAuditDetail(before, cfg)
	if text := migration.auditText(); text != "" {
		detail = services.FormatAuditDetail(detail, text)
	}
	if staleIdentityRows > 0 {
		detail = services.FormatAuditDetail(detail, fmt.Sprintf("服务地址变更：存量身份行 %d 条不再可达", staleIdentityRows))
	}
	recordAudit(c, "更新", "OIDC 配置", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
	response := models.APIResponse{Code: 0, Message: "OIDC 配置已保存"}
	if reportStaleIdentities {
		response.Data = gin.H{"stale_identity_rows": staleIdentityRows}
	}
	c.JSON(http.StatusOK, response)
}

// oidcConfigUpdateAuditDetail 生成字段级 delta。
// 该端点为 AuditPolicyExplicit，中间件不补字段——此前详情仅有「认证集成 成功」，
// 启用/禁用、issuer、client_id 的任何变更在审计中不可区分。secret 只记
// 「已更换/已清除」，绝不落值（对齐 config_changes.go GitHub token 口径）。
func oidcConfigUpdateAuditDetail(before, after OIDCConfig) string {
	changed := make([]string, 0, 5)
	enabledText := func(v bool) string {
		if v {
			return "启用"
		}
		return "禁用"
	}
	shown := func(v string) string {
		if v == "" {
			return "（空）"
		}
		return v
	}
	if before.Enabled != after.Enabled {
		changed = append(changed, "启用状态："+enabledText(before.Enabled)+"→"+enabledText(after.Enabled))
	}
	if before.Issuer != after.Issuer {
		changed = append(changed, "服务地址："+shown(before.Issuer)+"→"+shown(after.Issuer))
	}
	if before.ClientID != after.ClientID {
		changed = append(changed, "Client ID："+shown(before.ClientID)+"→"+shown(after.ClientID))
	}
	if before.ClientSecret != after.ClientSecret {
		if after.ClientSecret == "" {
			changed = append(changed, "Client Secret：已清除")
		} else {
			changed = append(changed, "Client Secret：已更换")
		}
	}
	if before.DisplayName != after.DisplayName {
		changed = append(changed, "展示名称："+shown(before.DisplayName)+"→"+shown(after.DisplayName))
	}
	listText := func(v []string) string {
		if len(v) == 0 {
			return "（不限制）"
		}
		return strings.Join(v, ",")
	}
	if !slices.Equal(before.AllowedEmailDomains, after.AllowedEmailDomains) {
		changed = append(changed, "允许的 email 域："+listText(before.AllowedEmailDomains)+"→"+listText(after.AllowedEmailDomains))
	}
	if !slices.Equal(before.AllowedGroups, after.AllowedGroups) {
		changed = append(changed, "允许的组："+listText(before.AllowedGroups)+"→"+listText(after.AllowedGroups))
	}
	if len(changed) == 0 {
		return "认证集成（无字段变化）"
	}
	return "认证集成（" + strings.Join(changed, "；") + "）"
}

// OIDCSettingsTest POST /settings/oidc/test(admin)——完整发现+JWKS 探测。
func (h *Handlers) OIDCSettingsTest(c *gin.Context) {
	var req struct {
		Issuer       string `json:"issuer"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	// 只有真正的空 body 才回退「测试已保存配置」；语法畸形/字段
	// 类型错误必须 400（旧实现吞掉绑定错误，客户端格式错误会收到 200）。
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	issuer := normalizeOIDCIssuer(req.Issuer)
	if issuer == "" {
		cfg, cfgErr := loadOIDCConfig()
		if cfgErr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 OIDC 配置失败"})
			return
		}
		issuer = cfg.Issuer
	}
	if issuer == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请提供服务地址"})
		return
	}
	// 探测路径与保存路径同一 scheme 策略——任何出站
	// (discovery/token/jwks) 前先拒绝非 https（回环除外）。
	if err := validateOIDCIssuerURL(issuer); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 机器身份(API Key/MCP)不开放「任指 URL」探测——issuer 须与已
	// 保存配置一致(先例端点探测的都是已存实体);管理员 JWT 面板编辑流不受限。
	if c.GetString("auth_type") == "api_key" {
		stored, cfgErr := loadOIDCConfig()
		if cfgErr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 OIDC 配置失败"})
			return
		}
		if normalizeOIDCIssuer(req.Issuer) != "" && issuer != stored.Issuer {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "API Key 仅支持测试已保存的 OIDC 配置"})
			return
		}
	}
	oidcProviderInvalidate(issuer) // 测试总是新鲜发现,不喂缓存
	p, err := oidcProvider(issuer)
	if err != nil {
		recordAudit(c, "测试失败", "OIDC 配置", services.FormatAuditDetail(issuer, services.AuditResultPart("failure")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"ok": false, "error": oidcTestFailureText(err)}})
		return
	}
	// JWKS 可达性——此前注释声称「一次签验失败即证可达性」，实际
	// 只反序列化 discovery 文档，jwks_uri 不可达/格式错误直到首次登录验签才炸。
	// 测试阶段必须显式 GET jwks_uri（有界客户端 + 响应上限 + keys 非空）。
	var providerClaims struct {
		Issuer  string   `json:"issuer"`
		Name    string   `json:"name"`
		Scopes  []string `json:"scopes_supported"`
		JWKSURI string   `json:"jwks_uri"`
	}
	if err := p.Claims(&providerClaims); err != nil {
		recordAudit(c, "测试失败", "OIDC 配置", services.FormatAuditDetail(issuer, services.AuditResultPart("failure")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"ok": false, "error": "读取发现文档失败: " + err.Error()}})
		return
	}
	jwksErr := probeOIDCJWKS(providerClaims.JWKSURI, issuer)
	name := providerClaims.Name
	if name == "" {
		if u, err := url.Parse(issuer); err == nil {
			name = u.Host
		}
	}
	if jwksErr != nil {
		recordAudit(c, "测试失败", "OIDC 配置", services.FormatAuditDetail(fmt.Sprintf("%s(%s)", name, issuer), services.AuditResultPart("failure")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"ok": false, "error": "JWKS 探测失败: " + jwksErr.Error()}})
		return
	}
	// 凭证离线校验:client_credentials 探测——invalid_client 即凭证错(secret
	// 值/ID 混淆等),在「测试」阶段暴露而非登录才炸;其余错误(unsupported_grant_type
	// /invalid_scope 等)=客户端认证已过或该服务不支持离线探测,降级为可达性通过。
	clientID, clientSecret := strings.TrimSpace(req.ClientID), strings.TrimSpace(req.ClientSecret)
	if clientID == "" || clientSecret == "" {
		if cfg, cfgErr := loadOIDCConfig(); cfgErr != nil {
			services.Logf("warn", "OIDC 测试回填已保存凭证失败: %v", cfgErr)
		} else if cfg.Issuer == issuer {
			if clientID == "" {
				clientID = cfg.ClientID
			}
			if clientSecret == "" {
				clientSecret = cfg.ClientSecret
			}
		}
	}
	credentialsChecked, credErr := probeClientCredentials(p.Endpoint().TokenURL, clientID, clientSecret, issuer)
	if credErr != nil {
		recordAudit(c, "测试失败", "OIDC 配置", services.FormatAuditDetail(fmt.Sprintf("%s(%s)", name, issuer), services.AuditResultPart("failure")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"ok": false, "error": credErr.Error()}})
		return
	}
	detail := name + "(" + issuer + ")"
	if credentialsChecked {
		detail += " 凭证校验通过"
	}
	recordAudit(c, "测试成功", "OIDC 配置", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"ok": true, "issuer": providerClaims.Issuer, "provider_name": name,
		"authorization_endpoint": p.Endpoint().AuthURL,
		"token_endpoint":         p.Endpoint().TokenURL,
		"scopes":                 providerClaims.Scopes,
		"credentials_checked":    credentialsChecked,
		"jwks_checked":           true,
	}})
}

// oidcTestFailureText 把发现阶段错误翻译为可操作提示（仅「测试连接」端点；
// 未认证登录页保持固定短句，不泄露配置细节）。issuer 与发现文档逐字节不等
// 是最高频配置错误，go-oidc 原文为英文且不提端口/大小写，管理员会误查网络。
func oidcTestFailureText(err error) string {
	var mismatch *oidc.IssuerMismatchError
	if errors.As(err, &mismatch) {
		return fmt.Sprintf("服务地址与认证服务宣告的 issuer 不一致：配置 %s，宣告 %s（常见原因：多了 :443 等默认端口、主机大小写不同或尾斜杠差异——请按宣告值填写）", mismatch.Provided, mismatch.Discovered)
	}
	return err.Error()
}

// oidcProbeClient 凭证探测专用客户端:出站请求必须有界(挂起的 token 端点
// 不得挂起 handler goroutine),与 discovery 8s 口径同族;重定向与
// discovery/token 共用同一 scheme 复验策略。
var oidcProbeClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: oidcCheckRedirect}

// probeOIDCJWKS 探测 jwks_uri：HTTP 200 + 合法 JSON（keys 非空）才算通过。
// 响应上限 1MB（密钥集远小于此），URL 与 discovery/token 同一端点策略——
// issuer 一并传入：https issuer 的 jwks_uri 不得落在回环 http 豁免里。
func probeOIDCJWKS(jwksURI, issuer string) error {
	if jwksURI == "" {
		return errors.New("发现文档缺少 jwks_uri")
	}
	if err := validateOIDCEndpointURL(jwksURI, issuer); err != nil {
		return fmt.Errorf("jwks_uri 不合规: %w", err)
	}
	request, err := http.NewRequestWithContext(oidcOutboundContext(context.Background(), issuer), http.MethodGet, jwksURI, nil)
	if err != nil {
		return fmt.Errorf("请求构造失败: %w", err)
	}
	resp, err := oidcProbeClient.Do(request)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("读取失败: %w", err)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("格式错误: %w", err)
	}
	if len(doc.Keys) == 0 {
		return errors.New("密钥集为空")
	}
	return nil
}

// probeClientCredentials 用 client_credentials 向令牌端点探测凭证:
//   - 200:凭证正确(checked=true)
//   - 401/400 且 error=invalid_client:凭证错误(返回 err,含提供商描述)
//   - 其余错误(unsupported_grant_type/invalid_scope…):客户端认证未拒绝,
//     该服务不支持离线凭证探测(checked=false,可达性仍算通过)
//   - 网络/解析失败:返回 err(测试失败)
func probeClientCredentials(tokenURL, clientID, clientSecret, issuer string) (bool, error) {
	if clientID == "" || clientSecret == "" {
		return false, nil // 无凭证可验(仅探测发现可达性)
	}
	// discovery 的 token_endpoint 同样受端点策略约束（基准 issuer 传入）——
	// 不得把 client_secret 明文 POST 到非 https 的非回环地址，也不得借
	// 「https issuer」的回环 http 豁免打到本机任意端口。
	if err := validateOIDCEndpointURL(tokenURL, issuer); err != nil {
		return false, fmt.Errorf("令牌端点地址不合规: %w", err)
	}
	ctx := oidcOutboundContext(context.Background(), issuer)
	// scope 候选:①api://<client_id>/.default(Entra 等先验 scope 后验 secret 的
	// 提供商——实测 openid 会被 AADSTS1002012 拒而漏检 invalid_client);②openid(常规)。
	// 任一候选 invalid_client 即凭证错;全部非 invalid_client 错误=不支持离线探测。
	scopes := []string{"api://" + clientID + "/.default", "openid"}
	for _, scope := range scopes {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {clientID},
			"client_secret": {clientSecret},
			"scope":         {scope},
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return false, fmt.Errorf("凭证探测请求构造失败: %w", err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := oidcProbeClient.Do(request)
		if err != nil {
			return false, fmt.Errorf("凭证探测请求失败: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true, nil
		}
		var e struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "invalid_client" {
			msg := e.ErrorDescription
			if msg == "" {
				msg = e.Error
			}
			return false, fmt.Errorf("Client ID/Secret 被提供商拒绝(%s): %s", e.Error, msg)
		}
	}
	return false, nil // 无候选触达客户端认证:不支持离线探测,可达性通过
}

// OIDCSettingsDelete DELETE /settings/oidc(admin)——清空配置(等效禁用+抹除)。
func (h *Handlers) OIDCSettingsDelete(c *gin.Context) {
	// 同 OIDCSettingsUpdate：删除写 global_config.oidc_config，导入窗口内必须
	// 409 fast-fail（否则清空动作被导入结果静默覆盖或撞写锁 500）。
	if rejectWriteDuringImport(c, "删除 OIDC 配置（配置导入进行中）") {
		return
	}
	cfg, cfgErr := loadOIDCConfig()
	if cfgErr != nil {
		// 配置损坏正是 DELETE 的用途之一：读不出旧值只影响「删除前快照」与
		// provider 缓存失效，清空仍必须可执行（不留死锁局面）。
		services.Logf("warn", "OIDC 配置删除前读取失败（继续清空）: %v", cfgErr)
	} else {
		oidcProviderInvalidate(cfg.Issuer)
	}
	var oidcIdentityRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE auth_provider='oidc'`).Scan(&oidcIdentityRows); err != nil {
		services.Logf("error", "OIDC 配置删除前统计存量身份行失败: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 OIDC 身份记录失败"})
		return
	}
	if err := saveOIDCConfig(OIDCConfig{}); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除 OIDC 配置失败"})
		return
	}
	// 删除留痕「删除前的字段值」（secret 只记是否配置），供取证
	// 重建被抹除的接入参数。
	detail := "认证集成"
	if cfgErr == nil {
		yn := func(v string) string {
			if v == "" {
				return "（空）"
			}
			return v
		}
		secretState := "未配置"
		if cfg.ClientSecret != "" {
			secretState = "已配置"
		}
		enabledState := "禁用"
		if cfg.Enabled {
			enabledState = "启用"
		}
		detail += fmt.Sprintf("（删除前：服务地址 %s；Client ID %s；Client Secret %s；启用状态 %s）",
			yn(cfg.Issuer), yn(cfg.ClientID), secretState, enabledState)
	}
	if oidcIdentityRows > 0 {
		detail = services.FormatAuditDetail(detail, fmt.Sprintf("存量 OIDC 身份行 %d 条已不可登录", oidcIdentityRows))
	}
	recordAudit(c, "删除", "OIDC 配置", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
	message := "OIDC 配置已删除"
	if oidcIdentityRows > 0 {
		message = fmt.Sprintf("OIDC 配置已删除；%d 个存量 OIDC 用户已无法登录。重新配置同一 issuer 可恢复原身份绑定；改用不同 issuer 会按新身份重新开户。请删除不再需要的残留用户。", oidcIdentityRows)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message, Data: gin.H{"oidc_identity_rows": oidcIdentityRows}})
}

// sanitizeOIDCReturnTo 归一 OIDC 登录的 return_to
// 仅放行站内相对路径。此前只校验前导 "/"，协议相对值 `//evil.example.com`（以及
// `/\evil.example.com` 变体）可绕过后端并写入 OIDC state——浏览器把 `//host`
// 视为跨域跳转目标，最终拦截点只剩前端页面键白名单（App.vue isPageId），开放
// 重定向防护成为跨层单点依赖。此处收紧为「前导单个 / 且非 // 与 /\」，前端白名单
// 退化为第二道防线（纵深防御）。
func sanitizeOIDCReturnTo(raw string) string {
	if raw == "" || len(raw) > oidcReturnToMaxBytes {
		// 超长值直接丢弃——未认证入口不得承载任意大小的内存驻留。
		return ""
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return ""
	}
	return raw
}

// validateOIDCIssuerURL 校验 OIDC issuer 的 scheme/host 策略
// 收敛为单源）：仅允许 https；http 仅允许回环地址（127.0.0.0/8、::1）
// 供本机 mock/测试。保存路径与「测试」探测路径（discovery/token/jwks）必须在
// 任何出站请求前执行同一校验——此前测试端点绕过保存校验，管理员会话被借用时
// 可探测内网或把 client_secret 明文 POST 到任指地址。
//
// 本函数只管 issuer 自身；issuer 宣告的端点（token/jwks/authorization）用
// validateOIDCEndpointURL——回环 http 豁免不得外溢到发现文档里的任意地址。
func validateOIDCIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("服务地址须为 https URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
			return errors.New("OIDC 服务地址须为 https（http 仅允许回环地址用于本机测试）")
		}
		return nil
	default:
		return errors.New("服务地址须为 https URL")
	}
}

// oidcIssuerPolicyKey 把「本次出站的基准 issuer」随 context 传给共用出站
// 客户端（令牌交换/重定向等仍用全局客户端）。端点策略需要区分「https issuer」
// 与「本机 mock issuer」。discovery/JWKS 用 newOIDCOutboundClient 把 issuer
// 绑进客户端本身——go-oidc 的 RemoteKeySet 以 context.Background() 重建
// keyset，只保留 ctx 里的 http.Client，context 值到不了验签取钥请求。
type oidcIssuerPolicyKey struct{}

func oidcOutboundContext(ctx context.Context, issuer string) context.Context {
	return context.WithValue(ctx, oidcIssuerPolicyKey{}, issuer)
}

func oidcOutboundIssuer(ctx context.Context) string {
	issuer, _ := ctx.Value(oidcIssuerPolicyKey{}).(string)
	return issuer
}

// validateOIDCEndpointURL 校验 issuer 宣告的端点是否落在该 issuer 的出站策略内。
// 回环 http 豁免只对 issuer 自身成立（本机 mock IdP），不得被 IdP 宣告的
// token_endpoint/jwks_uri/authorization_endpoint 继承：issuer 合规（https）时
// 只要 discovery 把 token_endpoint 指向 http://127.0.0.1:<port>，面板就会把
// client_id/client_secret 明文 POST 到本机任意 HTTP 服务（本机 SSRF + 凭据外泄）。
// 规则：https issuer 下所有端点必须 https；http 回环 issuer（仅本机测试形态）
// 下端点沿用回环 http 豁免；基准 issuer 缺失按最严处理（仅 https）。
func validateOIDCEndpointURL(raw, issuer string) error {
	if err := validateOIDCIssuerURL(raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("OIDC 端点地址无效")
	}
	if u.Scheme == "https" {
		return nil
	}
	if base, err := url.Parse(issuer); err != nil || base.Scheme != "http" {
		return errors.New("OIDC 端点须为 https（http 仅限 issuer 自身为本机回环的测试形态）")
	}
	return nil
}

// oidcCheckRedirect 出站重定向逐跳复验端点策略（与 validateOIDCEndpointURL
// 单源）：初始 URL 合规不代表重定向目标合规——跟一次 302 到 http://内网 或任意
// 主机就能绕过「仅 https（回环例外）」，token 交换还会把 client_secret 带过去。
// 跳数封顶与 Go 默认一致（10 跳）。基准 issuer 取请求 context 注入值。
func oidcCheckRedirect(req *http.Request, via []*http.Request) error {
	return oidcCheckRedirectForIssuer(req, via, oidcOutboundIssuer(req.Context()))
}

func oidcCheckRedirectForIssuer(req *http.Request, via []*http.Request, issuer string) error {
	if len(via) >= 10 {
		return errors.New("OIDC 出站请求重定向次数过多")
	}
	if err := validateOIDCEndpointURL(req.URL.String(), issuer); err != nil {
		return fmt.Errorf("重定向目标不合规: %w", err)
	}
	return nil
}

// oidcOutboundGuardTransport 出站请求逐一复验目标 URL 的端点策略。
// discovery 文档内容由 IdP 提供、不受本机控制：一个合规的 https issuer 完全
// 可以把 token_endpoint / jwks_uri 指向内网主机或本机端口，go-oidc 不校验
// endpoint 与 issuer 同源——只验 issuer 会让 client_secret 明文发往任意地址。
// 因此在传输层对每次出站的初始 URL 复验同一策略（重定向另由
// oidcCheckRedirect 逐跳复验）。基准 issuer 优先取传输层绑定值（per-issuer
// 客户端），否则取请求 context 注入值，两者都缺失时按最严策略（仅 https）。
type oidcOutboundGuardTransport struct {
	base   http.RoundTripper
	issuer string
}

func (t oidcOutboundGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	issuer := t.issuer
	if issuer == "" {
		issuer = oidcOutboundIssuer(req.Context())
	}
	if err := validateOIDCEndpointURL(req.URL.String(), issuer); err != nil {
		return nil, fmt.Errorf("OIDC 出站地址不合规: %w", err)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// oidcOutboundClient discovery/令牌交换共用出站客户端：有界超时 + 初始地址
// 策略复验 + 逐跳重定向复验。go-oidc 通过 oidc.ClientContext 注入（同一
// context key 也被 oauth2 的令牌交换消费）；基准 issuer 随 context 注入
// （oidcOutboundContext）。
var oidcOutboundClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: oidcCheckRedirect,
	Transport:     oidcOutboundGuardTransport{},
}

// newOIDCOutboundClient 构造绑定 issuer 基准策略的出站客户端，供 discovery 与
// 其后的 JWKS 验签共用：go-oidc v3.21 的 Provider.remoteKeySet 以
// context.Background() 重建 keyset（只保留 ctx 里的 http.Client），context
// 里的策略值会在验签取钥时丢失——把 issuer 编进客户端本身，jwks_uri 依旧受
// 端点策略约束。每个 provider 创建时构造一次（provider 有缓存 + singleflight），
// 不做无界缓存。
func newOIDCOutboundClient(issuer string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return oidcCheckRedirectForIssuer(req, via, issuer)
		},
		Transport: oidcOutboundGuardTransport{issuer: issuer},
	}
}
