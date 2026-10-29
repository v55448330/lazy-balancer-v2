package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 受信代理（CDN 真实 IP）写侧校验与归一（v2.3.x）：UpdateConfig 与
// PreviewConfigUpdate 共用——未过校验的载荷不得落库、也不得给出变更清单。
//
// 归一（原地回写 req 字段）：
//   - ranges：裸 IP 补 /32（v4）//128（v6）；随后统一按
//     services.TrustedProxyPrefixCanonical 归一（Masked 剥主机位 + 4in6
//     映射折成等价 v4 前缀）；条数 ≤64；归一后覆盖全部地址空间或前缀长度
//     <8（v4，mapped 折合 /104）/<29（v6）一律拒绝——过宽网段会让伪造的
//     头在任意来源被采信。
//   - range_refs（2026-10-12）：引用的 IP 地址列表 id（JSON 整数数组）；
//     每个 id 必须存在且为自定义名单（system=1 内置名单拒绝）；
//     引用名单条目须为合法 IP/CIDR 且与内联通道同宽度判据；总
//     CIDR 数（内联 + 引用展开）≤ trustedProxyMaxTotalCIDRs。
//   - headers：条数 ≤8；字符集 ^[A-Za-z0-9-]{1,64}$；去重保序；
//     空数组 = 仅 X-Forwarded-For（渲染层省略 client_ip_headers）。
var trustedProxyHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// errTrustedProxyRead 标记受信代理校验中的数据库读取失败：这不是载荷问题，
// 调用方必须映射为 500 + 固定文案并留痕——回 400 会让管理员误以为网段填错而
// 反复修改，且把 SQL/驱动错误文本透给客户端。格式/宽度/存在性校验仍走 400。
var errTrustedProxyRead = errors.New("读取受信代理配置失败")

// trustedProxyReadError 携带底层原因供日志使用；Error() 只返回固定文案，
// 避免经 400/响应体把底层错误文本外泄。
type trustedProxyReadError struct {
	cause error
}

func (e *trustedProxyReadError) Error() string { return errTrustedProxyRead.Error() }
func (e *trustedProxyReadError) Unwrap() error { return e.cause }

func trustedProxyReadFailure(cause error) error { return &trustedProxyReadError{cause: cause} }

// trustedProxyMaxTotalCIDRs 受信网段总量上限（内联 ∪ 引用展开，按规范化
// 前缀集合去重后计，与渲染层 seen 同源——重叠网段只计一次）：Caddy static
// ranges 是逐条装载的集合，无聚合链路——上限防御单一名单（≤2000 条写侧门，
// 2026-10-14 裁定 500→2000）×多引用的组合膨胀。
const trustedProxyMaxTotalCIDRs = 2000

// trustedProxyListSource 名单解析源行（id → 名单行）。builtin 标记
// system=1 的内置名单（威胁情报/爬虫/自动封禁）——受信代理不允许引用
// （威胁名单真实条目在.iplist 文件，DB entries 恒空，按 DB 列
// 校验会同时失去条格式门与 2000 条总量门；前端本已只列自定义名单）。
type trustedProxyListSource struct {
	name    string
	entries string
	builtin bool
}

// trustedProxyBackupSource 导入通道的名单解析源。
// 按「备份是否携带 security_ip_lists 表」分流：
//
//	carried=true：名单表随备份**全量替换**（先例——备份行才是导入后的
//	  真实数据），refs 存在性仅按备份行集合解析；指向库内但不在备份内的 id
//	  导入后必然悬空，校验期 400 拒绝（旧「备份内优先 ∪ 库内」口径会借库内
//	  命中放行为导入后悬空引用）。
//	- carried=false：备份未携带名单表——导入后名单表保持本地现状（「缺席=
//	  保留本地」语义），refs 存在性按库内解析（与保存通道同口径）。
//
// 零值=仅库内解析（保存通道）。
type trustedProxyBackupSource struct {
	lists   map[int64]trustedProxyListSource
	carried bool
}

// validateTrustedProxyFields 保存侧入口（UpdateConfig/PreviewConfigUpdate）：
// 名单解析仅走库内（零值 source）。
func validateTrustedProxyFields(req *models.UpdateConfigRequest) error {
	return validateTrustedProxyFieldsWithSource(req, trustedProxyBackupSource{})
}

func validateTrustedProxyFieldsWithSource(req *models.UpdateConfigRequest, source trustedProxyBackupSource) error {
	if req.TrustedProxyRanges != nil {
		normalized, err := normalizeTrustedProxyRanges(*req.TrustedProxyRanges)
		if err != nil {
			return err
		}
		*req.TrustedProxyRanges = normalized
		// 总量门对称面：refs 未随载荷时按库中存量引用展开合计——内联面与引用面
		// 合并才是真实展开规模（refs 载荷分支在下方做同口径判定，此处不重复）。
		if req.TrustedProxyRangeRefs == nil {
			inlineKeys, err := trustedProxyInlinePrefixes(req)
			if err != nil {
				return err
			}
			refKeys, err := trustedProxyStoredRefPrefixesWithSource(source)
			if err != nil {
				return err
			}
			if err := trustedProxyTotalGate(inlineKeys, refKeys); err != nil {
				return err
			}
		}
	}
	if req.TrustedProxyRangeRefs != nil {
		normalized, refKeys, err := normalizeTrustedProxyRangeRefsWithSource(*req.TrustedProxyRangeRefs, source)
		if err != nil {
			return err
		}
		// 总量门（内联 ∪ 引用展开）：载荷未携带 ranges 时按存量值计——
		// 引用面与内联面合并才是真实展开规模。
		inlineKeys, err := trustedProxyInlinePrefixes(req)
		if err != nil {
			return err
		}
		if err := trustedProxyTotalGate(inlineKeys, refKeys); err != nil {
			return err
		}
		*req.TrustedProxyRangeRefs = normalized
	}
	if req.TrustedProxyHeaders != nil {
		normalized, err := normalizeTrustedProxyHeaders(*req.TrustedProxyHeaders)
		if err != nil {
			return err
		}
		*req.TrustedProxyHeaders = normalized
	}
	return nil
}

// trustedProxyPrefixKeys 把条目集合解析为渲染层同一去重键集合（裸 IP 补齐、
// prefix.String()）——总量门与 expandTrustedProxyRanges 的 seen 键同口径；
// 无法解析的条目由上游格式门拒绝或渲染层 fail-closed 跳过，此处按 0 计。
func trustedProxyPrefixKeys(values []string) map[string]struct{} {
	keys := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := parseTrustedProxyPrefix(value)
		if err != nil {
			continue
		}
		keys[prefix.String()] = struct{}{}
	}
	return keys
}

// trustedProxyTotalGate 按「规范化前缀集合大小」判总量门（与渲染侧去重同源）：
// 同一网段既内联又列在引用名单时只计一次——按条目数累加会把实际展开集合
// 远小于上限的合法载荷 400 拒绝。
func trustedProxyTotalGate(inline, refs map[string]struct{}) error {
	union := len(inline)
	for key := range refs {
		if _, ok := inline[key]; !ok {
			union++
		}
	}
	if union > trustedProxyMaxTotalCIDRs {
		return fmt.Errorf("受信网段总数超过 %d 上限（去重后合计 %d：内联 %d + 引用展开 %d；重叠网段只计一次），请收窄范围", trustedProxyMaxTotalCIDRs, union, len(inline), len(refs))
	}
	return nil
}

// trustedProxyInlinePrefixes 返回总量门所需的内联网段规范前缀集合：载荷携带
// ranges 时用归一后值（validateTrustedProxyFields 先归一 ranges 再进本函数）；
// 未携带（nil=保留原值）时读库取存量。
func trustedProxyInlinePrefixes(req *models.UpdateConfigRequest) (map[string]struct{}, error) {
	if req.TrustedProxyRanges != nil {
		var entries []string
		if err := json.Unmarshal([]byte(*req.TrustedProxyRanges), &entries); err != nil {
			return nil, fmt.Errorf("受信代理网段必须是 JSON 数组: %v", err)
		}
		return trustedProxyPrefixKeys(entries), nil
	}
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_ranges,'[]') FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		return nil, trustedProxyReadFailure(fmt.Errorf("读取当前受信代理网段失败: %w", err))
	}
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		// 存量畸形（仅见于带外改库）：按 0 计——渲染层对畸形同样 fail-closed
		// 不注入，总量门不因存量畸形拒绝合法的引用清理载荷。
		return map[string]struct{}{}, nil
	}
	return trustedProxyPrefixKeys(entries), nil
}

// idChunk 是一个 id 分片及其预构造的 IN 子句占位符与参数。chunkIDs 是全部
// 500 分片样板的单源（受信代理校验、备份导入、IP 名单、威胁筛查四处消费），
// 仅共享分片构造，不合并各处的查询/校验语义。
type idChunk struct {
	placeholders string
	args         []any
}

// chunkIDs 把 id 列表按 chunkSize 切分为若干分片，每片预构造
// `?,?,...` 占位符与配套参数（SQLite 变量数上限下的分批口径）。
func chunkIDs(ids []int64, chunkSize int) []idChunk {
	if len(ids) == 0 {
		return nil
	}
	chunks := make([]idChunk, 0, (len(ids)+chunkSize-1)/chunkSize)
	for start := 0; start < len(ids); start += chunkSize {
		end := start + chunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		chunks = append(chunks, idChunk{placeholders: placeholders, args: args})
	}
	return chunks
}

// resolveTrustedProxyRefLists 解析 refs 引用的名单行
// 备份行命中直取；未命中且备份未携带名单表（carried=false）时分片查库。
// 两通道都带 system 列映射 builtin。
// carried=true 不回落库内——名单表随备份全量替换，库内命中不代表导入后存在。
func resolveTrustedProxyRefLists(ids []int64, source trustedProxyBackupSource) (map[int64]trustedProxyListSource, error) {
	resolved := make(map[int64]trustedProxyListSource, len(ids))
	var missing []int64
	for _, id := range ids {
		if row, ok := source.lists[id]; ok {
			resolved[id] = row
		} else if !source.carried {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return resolved, nil
	}
	for _, ch := range chunkIDs(missing, 500) {
		rows, err := db.DB.Query(`SELECT id, COALESCE(entries,'[]'), COALESCE(name,''), COALESCE(system,0) FROM security_ip_lists WHERE id IN (`+ch.placeholders+`)`, ch.args...)
		if err != nil {
			return nil, trustedProxyReadFailure(fmt.Errorf("校验受信代理引用列表失败: %w", err))
		}
		for rows.Next() {
			var id int64
			var entriesJSON, name string
			var system int
			if err := rows.Scan(&id, &entriesJSON, &name, &system); err != nil {
				rows.Close()
				return nil, trustedProxyReadFailure(fmt.Errorf("校验受信代理引用列表失败: %w", err))
			}
			resolved[id] = trustedProxyListSource{name: name, entries: entriesJSON, builtin: system == 1}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, trustedProxyReadFailure(fmt.Errorf("校验受信代理引用列表失败: %w", err))
		}
		rows.Close()
	}
	return resolved, nil
}

// trustedProxyStoredRefPrefixesWithSource 库中存量 trusted_proxy_range_refs 的
// 引用展开规范前缀集合（总量门的引用面——不做存在性门）。source.carried=true
// （导入通道携表）时未命中备份行的存量 ref 不参与计数（导入后该名单不复存在，
// 展开面归零）；载荷未携带 refs 键而备份携带名单表的残留悬空形态（仅手造备份
// 可达——真实导出恒携带全列）不在本门范围内，由渲染层 fail-closed 与名单删除
// 守卫兜底。存量 refs JSON 畸形/条目不可解析（仅见于带外改库）按空集计。
//
// 内置名单（system=1）引用自写侧拒绝；升级前存量引用仍按 DB entries 计数
// （威胁名单恒 0 条——其真实条目不参与本门，属既有配置的遗留边界：下次保存
// refs 载荷时被 400 拒绝并要求改用自定义名单）。
func trustedProxyStoredRefPrefixesWithSource(source trustedProxyBackupSource) (map[string]struct{}, error) {
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		return nil, trustedProxyReadFailure(fmt.Errorf("读取当前受信代理引用列表失败: %w", err))
	}
	var ids []int64
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &ids); err != nil || len(ids) == 0 {
		return map[string]struct{}{}, nil
	}
	resolved, err := resolveTrustedProxyRefLists(ids, source)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]struct{})
	for _, row := range resolved {
		var entries []models.IPListEntry
		if row.entries == "" || json.Unmarshal([]byte(row.entries), &entries) != nil {
			continue
		}
		values := make([]string, 0, len(entries))
		for _, entry := range entries {
			if strings.TrimSpace(entry.Value) != "" {
				values = append(values, entry.Value)
			}
		}
		for key := range trustedProxyPrefixKeys(values) {
			keys[key] = struct{}{}
		}
	}
	return keys, nil
}

// normalizeTrustedProxyRangeRefsWithSource 校验并归一引用载荷：空白归一 "[]"；
// 非空须为整数数组 JSON（字符串/对象条目拒绝）；逐 id 校验存在性（内置名单
// 拒绝）与条目格式/宽度（parseTrustedProxyPrefix + services 宽度
// 判据，与内联通道同口径）；去重保序。
// source 按备份是否携带名单表分流（trustedProxyBackupSource）：carried=true
// 时存在性仅按备份行集合解析（全量替换后库内行不复存在，悬空 400）；
// carried=false 时未命中备份行的 id 按库内存量解析（保存通道同口径）。
// 返回归一 JSON 与引用名单的规范前缀集合（总量门的判定面，与渲染层去重同源）。
func normalizeTrustedProxyRangeRefsWithSource(raw string, source trustedProxyBackupSource) (string, map[string]struct{}, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "[]", map[string]struct{}{}, nil
	}
	var ids []int64
	if err := json.Unmarshal([]byte(trimmed), &ids); err != nil {
		return "", nil, fmt.Errorf("受信代理引用列表必须是整数 id 的 JSON 数组: %v", err)
	}
	seen := make(map[int64]struct{}, len(ids))
	unique := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return "", nil, fmt.Errorf("受信代理引用列表含无效 id：%d", id)
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return "[]", map[string]struct{}{}, nil
	}
	// 分流单点：备份行命中直取；未命中仅当备份未携名单表才回落库内
	// （resolveTrustedProxyRefLists——chunkIDs 保留 SQLite 变量数上限的批量
	// 口径，手造备份可携带任意长的 refs 数组）。
	resolved, err := resolveTrustedProxyRefLists(unique, source)
	if err != nil {
		return "", nil, err
	}
	keys := make(map[string]struct{})
	for _, id := range unique {
		row, ok := resolved[id]
		if !ok {
			return "", nil, fmt.Errorf("受信代理引用的地址列表不存在：#%d", id)
		}
		// 内置名单（威胁情报/爬虫/自动封禁）不得作为受信代理来源——
		// 真实条目在 .iplist 文件、DB entries 恒空，按 DB 列校验会同时失去条
		// 格式门与总量门；且威胁名单与「可信回源」语义相反。与 UI 一致拒绝。
		if row.builtin {
			return "", nil, fmt.Errorf("受信代理不能引用内置地址列表「%s」：内置名单（威胁情报/爬虫/自动封禁）由系统维护，请改用自定义名单", row.name)
		}
		var entries []models.IPListEntry
		if row.entries != "" {
			if err := json.Unmarshal([]byte(row.entries), &entries); err != nil {
				return "", nil, fmt.Errorf("引用的地址列表「%s」条目不可解析，请先修复该列表", row.name)
			}
		}
		for _, entry := range entries {
			value := strings.TrimSpace(entry.Value)
			if value == "" {
				continue
			}
			prefix, err := parseTrustedProxyPrefix(value)
			if err != nil {
				return "", nil, fmt.Errorf("引用的地址列表「%s」含无效 IP/CIDR 条目：%s（受信网段仅接受 IP/CIDR）", row.name, value)
			}
			// 与内联通道同一宽度判据——名单通道不得成为过宽网段的
			// 等价绕过入口（否则伪造头可在任意来源被采信）。
			if services.TrustedProxyPrefixAllSpace(prefix) {
				return "", nil, fmt.Errorf("引用的地址列表「%s」含过宽网段 %s：该网段覆盖全部地址空间，等同信任任意来源", row.name, prefix.String())
			}
			if services.TrustedProxyPrefixBelowMinBits(prefix) {
				return "", nil, fmt.Errorf("引用的地址列表「%s」含过宽网段 %s：最小允许 /8（IPv4）与 /29（IPv6），请收窄到该 CDN 的回源网段", row.name, prefix.String())
			}
			// 计数口径=通过校验的规范前缀集合（空 value 已跳过），跨名单/跨来源
			// 重叠只计一次——与渲染层实际注入的 seen 集合同口径。
			keys[prefix.String()] = struct{}{}
		}
	}
	out, err := json.Marshal(unique)
	if err != nil {
		return "", nil, fmt.Errorf("序列化受信代理引用列表失败: %v", err)
	}
	return string(out), keys, nil
}

// parseTrustedProxyPrefix 解析受信网段条目：合法 CIDR 或裸 IP（补 /32 或
// /128），并归一为 services.TrustedProxyPrefixCanonical 的规范形态（Masked
// 剥主机位 + 4in6 映射折成等价 v4）——格式门与渲染层 appendCIDR 同口径，
// 判宽、去重与总量门都在规范形态上执行（两通道不得分叉）。
func parseTrustedProxyPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		addr, addrErr := netip.ParseAddr(value)
		if addrErr != nil {
			return netip.Prefix{}, addrErr
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	return services.TrustedProxyPrefixCanonical(prefix), nil
}

// trustedProxyListLimit 同族条数门的单一实现：对去重后的规范集合判条数
// （内联网段与请求头同口径——重复条目不占额度；与 trustedProxyTotalGate 的
// 「重叠网段只计一次」同源）。
func trustedProxyListLimit(label string, normalized []string, limit int) error {
	if len(normalized) > limit {
		return fmt.Errorf("%s条数上限 %d（当前 %d）", label, limit, len(normalized))
	}
	return nil
}

func normalizeTrustedProxyRanges(raw string) (string, error) {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", fmt.Errorf("受信代理网段必须是 JSON 数组: %v", err)
	}
	normalized := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		prefix, err := parseTrustedProxyPrefix(entry)
		if err != nil {
			return "", fmt.Errorf("无效的受信代理网段: %s", entry)
		}
		// 全空间形态与最小前缀长度判据
		// 单源在 services（内联/引用/渲染三处同口径）：判据作用在规范形态上
		// （Masked 剥主机位 + 4in6 映射折成等价 v4），因此 0.0.0.0/8、
		// 0.0.0.0/0、::/0 与 mapped 变体（::ffff:0.0.0.1/96 等）同判
		// 「信任任意来源的伪造头」。
		if services.TrustedProxyPrefixAllSpace(prefix) {
			return "", fmt.Errorf("受信代理网段过宽（%s）：该网段覆盖全部地址空间，等同信任任意来源，请收窄到该 CDN 的回源网段", prefix.String())
		}
		if services.TrustedProxyPrefixBelowMinBits(prefix) {
			return "", fmt.Errorf("受信代理网段过宽（%s）：最小允许 /8（IPv4）与 /29（IPv6），请收窄到该 CDN 的回源网段", prefix.String())
		}
		// 去重保序（与 headers 侧同口径）
		if _, dup := seen[prefix.String()]; dup {
			continue
		}
		seen[prefix.String()] = struct{}{}
		normalized = append(normalized, prefix.String())
	}
	if err := trustedProxyListLimit("受信代理网段", normalized, 64); err != nil {
		return "", err
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("序列化受信代理网段失败: %v", err)
	}
	return string(out), nil
}

func normalizeTrustedProxyHeaders(raw string) (string, error) {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", fmt.Errorf("受信代理请求头必须是 JSON 数组: %v", err)
	}
	seen := make(map[string]struct{}, len(entries))
	normalized := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !trustedProxyHeaderPattern.MatchString(entry) {
			return "", fmt.Errorf("无效的受信代理请求头: %s（仅允许字母/数字/连字符，1-64 字符）", entry)
		}
		key := strings.ToLower(entry)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, entry)
	}
	if err := trustedProxyListLimit("受信代理请求头", normalized, 8); err != nil {
		return "", err
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("序列化受信代理请求头失败: %v", err)
	}
	return string(out), nil
}
