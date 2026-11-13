package services

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
)

// 缺库降级（2026-09-24 用户裁定）：CRS 规则库或 IP2Region 库缺失时，安全链
// （预检/ACL/CC 防护/WAF/GeoIP/信任直通包裹）整体不渲染——所有安全规则不生效。
// 背景：coraza 指令 Include 缺失文件会让 caddy validate 拒绝整份配置，
// 负载均衡也被拖死；降级为安全段缺席 + 告警日志，补库后渲染自动恢复。
// 面板侧提示：规则库卡片头部摘要（缺库异常描述）+ 本渲染告警日志。

// SecurityLibraryStatus 探测安全链依赖的两类规则库可用性：
// CRS=规则树满足安装完整性探针（≥1 个 .conf + 901 探针文件，与安装/恢复
// 门 crsRulesTreeIntact 同口径；空树/残树下 Include glob 虽可能编译但运行时
// 偏执级守卫空转，面板不得宣称“库可用”）；IP2Region=库文件存在且非空。
func SecurityLibraryStatus() (crsOK, ip2regionOK bool) {
	if crsRulesTreeIntact(filepath.Join(crsDirectivesDir, "rules")) {
		crsOK = true
	}
	if st, err := os.Stat(ip2regionLivePath); err == nil && st.Size() > 0 {
		ip2regionOK = true
	}
	return
}

// securityLibrariesMissingDesc 供告警日志的缺失描述（如「CRS 规则库」）。
// 接收已探测结果——调用方刚做过 SecurityLibraryStatus（rules 树 WalkDir +
// xdb stat），不得在描述里再探一轮。
func securityLibrariesMissingDesc(crsOK, ip2regionOK bool) string {
	missing := ""
	if !crsOK {
		missing = "CRS 规则库"
	}
	if !ip2regionOK {
		if missing != "" {
			missing += "、"
		}
		missing += "IP 地址库（IP2Region）"
	}
	return missing
}

// errCRSTreeSwapInFlight 表示渲染恰好落在 CRS 规则树交换窗口内。窗口内规则树
// 可能整体缺失（RemoveAll 后、rename 前）或只拷入一部分（copyDir 回退中断）：
// 前者会让安全链探测失败后「成功发布无安全链配置」，后者探测通过但只匹配到
// 部分 CRS 文件（WAF 静默弱化）。两种形态都必须在生成期拒绝，而不是发布一份
// 降级/弱化配置（窗口为百毫秒级，调用方重试即可）。
var errCRSTreeSwapInFlight = errors.New("CRS 规则树正在更新（树交换中），本轮配置生成已中止；请稍后重试")

// crsTreeSwapDepth 是树交换窗口的嵌套深度（>0=有树搬移正在进行）。所有会
// 搬移 live rules 树的路径都必须进入窗口：swapCRSTreeFromStaging 的
// RemoveAll→moveTree→setup 落盘段、restoreRulesBackup 的
// live→rules.old→bak 搬移、replaceDirFrom（快照恢复/播种）的
// live→.old 与 .tmp→live 搬移段，以及 seed 的残缺树清除段。渲染侧不持 wafFileMu——
// 渲染/重载在 CaddyOpLock 临界区内，而全局锁序为导入=排空→wafFileMu→
// CaddyOpLock，持 CaddyOpLock 再取 wafFileMu 即反向嵌套（AB-BA），故以
// 代际标记代替加锁：窗口内生成直接失败，窗口结束后由调用方重试。
// 用计数而非布尔：内层窗口（swap 段的恢复路径、seed 内的 replaceDirFrom）
// 退出时不得清除外层仍在进行的标记。
var crsTreeSwapDepth atomic.Int32

// crsTreeSwapInFlightNow 报告是否处于 CRS 树交换窗口（生成期互斥探针）。
func crsTreeSwapInFlightNow() bool { return crsTreeSwapDepth.Load() > 0 }

// enterCRSTreeSwapWindow 进入树交换窗口并返回退出函数。窗口可嵌套（同一
// 时刻只有一个持 wafFileMu 的树搬移在跑，内层只是外层调用的收窄段）。
func enterCRSTreeSwapWindow() (leave func()) {
	crsTreeSwapDepth.Add(1)
	return func() { crsTreeSwapDepth.Add(-1) }
}

// withTreeSwapWindow 在 fn 执行期间置位树交换窗口标记（含 panic/早退的
// 对称清除）。
func withTreeSwapWindow(fn func() error) error {
	leave := enterCRSTreeSwapWindow()
	defer leave()
	return fn()
}

// SetSecurityLibsDirsForTest 注入 CRS/IP2Region 库路径（handlers 等跨包渲染类
// 测试用——缺库形态安全链整体不渲染，名单投影/热路径无从谈起）。返回恢复函数。
// CRSRuleIndexDir 必须同步派生（与 ConfigureWafDirs 同口径）：否则跨包测试注入
// 库目录后索引仍指向生产 /app/waf/crs/rules（不存在→空索引），「选组/排除
// 存在性」行为在测试中不可复现。
func SetSecurityLibsDirsForTest(crsDir, xdbPath string) (restore func()) {
	oldLive, oldCRS, oldXdb, oldIndexDir := crsLiveDir, crsDirectivesDir, ip2regionLivePath, CRSRuleIndexDir
	oldV6Live, oldV6Dist := ip2regionV6LivePath, ip2regionV6DistPath
	crsLiveDir, crsDirectivesDir, ip2regionLivePath = crsDir, crsDir, xdbPath
	CRSRuleIndexDir = filepath.Join(crsDir, "rules")
	// v6 路径同步注入到 xdbPath 同目录的 hermetic 形态——跨包测试注入后，
	// 任何启用 v6 的用例不得再指向生产 /app/data/ip2region_v6.xdb。
	ip2regionV6LivePath = filepath.Join(filepath.Dir(xdbPath), "ip2region_v6.xdb")
	ip2regionV6DistPath = filepath.Join(filepath.Dir(crsDir), "waf.dist", "ip2region_v6.xdb")
	return func() {
		crsLiveDir, crsDirectivesDir, ip2regionLivePath, CRSRuleIndexDir = oldLive, oldCRS, oldXdb, oldIndexDir
		ip2regionV6LivePath, ip2regionV6DistPath = oldV6Live, oldV6Dist
	}
}
