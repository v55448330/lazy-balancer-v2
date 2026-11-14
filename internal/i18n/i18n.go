// Package i18n 提供后端 API 消息的最小双语能力:语言协商、词条目录、
// 服务层中文错误串的模板级英文翻译。设计原则:
//   - 中文为母本(fallback),英文目录缺译时一律回落,绝不丢消息
//   - 词条键由 codemod 生成(k_<hash>),人工不可手写新键(走 Register)
package i18n

import (
	"math"
	"strconv"
	"strings"
	"sync"
)

// 仅支持的语言;任何其他值回落 zh。
const (
	ZH = "zh"
	EN = "en"
)

var (
	mu       sync.RWMutex
	catalog  = map[string][2]string{} // key -> {zh, en}
	errTpls  = map[string]string{}    // zh 模板(%s 占位) -> en 模板
	errZh    []string                 // zh 模板切片,保证遍历顺序稳定
	hdrMu    sync.Mutex
	hdrCache = map[string]string{} // Accept-Language 头 -> lang(热路径缓存)
)

// CtxLangKey 为语言在 gin 上下文中的键;FromCtx 安全取用。
const CtxLangKey = "i18n.lang"

// FromCtx 从 gin 上下文取语言(默认 zh;nil/未挂中间件安全)。
func FromCtx(c Ctx) string {
	if c == nil {
		return ZH
	}
	if v, ok := c.Get(CtxLangKey); ok {
		if s, _ := v.(string); s == ZH || s == EN {
			return s
		}
	}
	return ZH
}

// Ctx 最小上下文接口(gin.Context 满足),避免 i18n 直依赖 gin。
type Ctx interface {
	Get(key any) (value any, exists bool)
}

// Negotiate 从 Accept-Language 头解析目标语言,默认 zh。
// 仅识别 zh/en;多候选按 q 权重(顺序权重近似)取最优。
func Negotiate(header string) string {
	hdrMu.Lock()
	if v, ok := hdrCache[header]; ok {
		hdrMu.Unlock()
		return v
	}
	hdrMu.Unlock()
	lang := negotiate(header)
	hdrMu.Lock()
	// 防缓存膨胀:仅缓存有头的;空头高频但分支极快
	if header != "" && len(hdrCache) < 512 {
		hdrCache[header] = lang
	}
	hdrMu.Unlock()
	return lang
}

func negotiate(header string) string {
	type cand struct {
		lang string
		q    float64
	}
	var cs []cand
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lang, q := part, 1.0
		if j := strings.IndexByte(part, ';'); j >= 0 {
			lang = part[:j]
			if v := strings.TrimSpace(part[j+1:]); strings.HasPrefix(v, "q=") {
				// q 按 RFC 9110 解析为 [0,1] 实数:硬编码集外的 q(0.3/0.95…)
				// 此前默认 1.0,语言排序失真。非法/NaN 按 0(该候选不优先),
				// 越界钳到 [0,1]。
				q = 0
				if parsed, perr := strconv.ParseFloat(strings.TrimPrefix(v, "q="), 64); perr == nil && !math.IsNaN(parsed) {
					q = math.Min(1, math.Max(0, parsed))
				}
			}
		}
		lang = strings.ToLower(strings.TrimSpace(lang))
		switch {
		case lang == "zh" || strings.HasPrefix(lang, "zh-"):
			cs = append(cs, cand{"zh", q})
		case lang == "en" || strings.HasPrefix(lang, "en-"):
			cs = append(cs, cand{"en", q})
		}
	}
	best, bestQ := ZH, -1.0
	// 同权重按出现顺序(先者优先:补 q 递减的次序偏置)
	for i, c := range cs {
		score := c.q - float64(i)*0.001
		if score > bestQ {
			best, bestQ = c.lang, score
		}
	}
	return best
}

// Register 登记词条(zh 母本 + en 译文)。仅由 catalog 生成文件与测试调用。
func Register(key, zh, en string) {
	mu.Lock()
	defer mu.Unlock()
	catalog[key] = [2]string{zh, en}
}

// T 查词条;缺译/未知键回落 key 本身(调用方通常已把消息原文存为 key 场景外)。
func T(lang, key string) string {
	mu.RLock()
	v, ok := catalog[key]
	mu.RUnlock()
	if !ok {
		return key
	}
	if lang == EN && v[1] != "" {
		return v[1]
	}
	return v[0]
}

// RegisterErrTpl 登记服务层中文错误模板(含 %s/%d 占位)与英文对应模板。
func RegisterErrTpl(zhTpl, enTpl string) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := errTpls[zhTpl]; !dup {
		errZh = append(errZh, zhTpl)
	}
	errTpls[zhTpl] = enTpl
}

// TrErr 把服务层产生的中文错误串翻成目标语言:
// 先精确匹配,再按模板逐个尝试占位对齐;未命中返回原文(中文母本兜底)。
func TrErr(msg, lang string) string {
	if lang != EN || msg == "" || !strings.ContainsFunc(msg, isZh) {
		return msg
	}
	mu.RLock()
	defer mu.RUnlock()
	if en, ok := errTpls[msg]; ok && en != "" {
		return en
	}
	for _, zhTpl := range errZh {
		en := errTpls[zhTpl]
		if en == "" {
			continue
		}
		if out, ok := matchTpl(msg, zhTpl, en); ok {
			return out
		}
	}
	return msg
}

func isZh(r rune) bool { return r >= 0x4E00 && r <= 0x9FFF }

// splitTplPlaceholders 按 %s 占位符切分模板为字面量段；%% 是转义的百分号
// 字面量（fmt 渲染后为单个 %），不是占位符——裸 strings.Split 会把 %%s 形态
// 的 "%s" 误判成占位符，含百分号字面量的模板（可解析率 50%% 等）永不命中。
// 返回 len(占位符)+1 个字面量段。
func splitTplPlaceholders(tpl string) []string {
	var parts []string
	var lit strings.Builder
	for i := 0; i < len(tpl); i++ {
		if tpl[i] != '%' {
			lit.WriteByte(tpl[i])
			continue
		}
		if i+1 < len(tpl) && tpl[i+1] == '%' {
			lit.WriteByte('%')
			i++
			continue
		}
		if i+1 < len(tpl) && tpl[i+1] == 's' {
			parts = append(parts, lit.String())
			lit.Reset()
			i++
			continue
		}
		lit.WriteByte('%')
	}
	parts = append(parts, lit.String())
	return parts
}

// matchTpl 尝试把 msg 按 zh 模板(占位符 %s)切开并按 en 模板重装。
// 仅支持 %s 占位;字面量必须全序对齐,尾字面量必须闭合到串尾。
func matchTpl(msg, zhTpl, enTpl string) (string, bool) {
	parts := splitTplPlaceholders(zhTpl)
	n := len(parts)
	if n < 2 {
		return "", false
	}
	if !strings.HasPrefix(msg, parts[0]) {
		return "", false
	}
	rest := msg[len(parts[0]):]
	var args []string
	for k := 1; k < n; k++ {
		lit := parts[k]
		if lit == "" {
			// 模板以 %s 结尾:占位吃剩余全部
			if k == n-1 {
				args = append(args, rest)
				rest = ""
			}
			continue
		}
		j := strings.Index(rest, lit)
		if j < 0 {
			return "", false
		}
		args = append(args, rest[:j])
		rest = rest[j+len(lit):]
		if k == n-1 && rest != "" {
			return "", false
		}
	}
	if rest != "" {
		return "", false
	}
	enParts := splitTplPlaceholders(enTpl)
	if len(enParts) != n {
		return "", false
	}
	var b strings.Builder
	b.WriteString(enParts[0])
	for i, a := range args {
		b.WriteString(a)
		b.WriteString(enParts[i+1])
	}
	return b.String(), true
}
