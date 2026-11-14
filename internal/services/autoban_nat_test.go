package services

// 自动封禁 NAT 检测与会话复合键钉测：
//   - 会话指纹采集稳定性（cookie 签名段优先，UA+Accept-Language 兜底）；
//   - NAT 检测：同 /64 窗口内 ≥N 个不同指纹且恶意事件集中少数指纹 → NAT 态；
//   - 复合键（/64×指纹）独立计数桶；常态键=/64；
//   - IPv6 隐私扩展 /64 锚定：NAT 态同指纹不分裂；
//   - NatDetection off 保持 IP 级；保留地址排除继承；
//   - NAT 配置三通道（默认/校验/写读）与变更清桶；
//   - 复合候选不落 IP 名单/不污染 IP 累犯（会话执法隔离）。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// natTestCfg NAT 开启的喂入配置（阈值 3 次/5 分钟窗口，blocked 口径）。
func natTestCfg(natThreshold int) AutobanConfig {
	return AutobanConfig{
		Enabled: true, Threshold: 3, WindowMinutes: 5, Duration: "1h", Scope: "blocked",
		NatDetection: true, NatFingerprintThreshold: natThreshold,
	}
}

// natFeed 经生产喂入门计一条 blocked 事件（携带会话指纹）。
func natFeed(cfg AutobanConfig, ip, fp string) {
	autobanObserveEventScopedAt(cfg, ip, "blocked", "942100", fp, autobanNow())
}

// natWindowKeys 快照当前计数桶键集。
func natWindowKeys(t *testing.T) map[string]int {
	t.Helper()
	autobanMu.Lock()
	defer autobanMu.Unlock()
	out := make(map[string]int, len(autobanWindows))
	for k, w := range autobanWindows {
		out[k] = w.Count
	}
	return out
}

// ---- 会话指纹采集（面板侧镜像） ----

// Given 同一 cookie 值/同一 UA+语言组合。
// When 多次提取指纹。
// Then 指纹稳定（同会话同指纹）；cookie 签名段优先于 UA 兜底；
// 不同 nonce 的 cookie 指纹不同；畸形 cookie 回落 UA 兜底。
func TestAutobanSessionFingerprint_stabilityAndCookiePriority(t *testing.T) {
	cookieA := natTestCookieValue(t, "203.0.113.7", "ua-A", 1700000001)
	cookieB := natTestCookieValue(t, "203.0.113.7", "ua-A", 1700000002)

	fpA := autobanSessionFingerprint(cookieA, "ua-A", "zh-CN")
	if fpA == "" || !strings.HasPrefix(fpA, "c:") {
		t.Fatalf("有效 cookie 必须产出 c: 前缀签名段指纹, got %q", fpA)
	}
	for range 3 {
		if got := autobanSessionFingerprint(cookieA, "ua-A", "zh-CN"); got != fpA {
			t.Fatalf("同 cookie 指纹漂移: %q != %q", got, fpA)
		}
	}
	// UA/语言变化不改变 cookie 指纹（签名段优先）。
	if got := autobanSessionFingerprint(cookieA, "other-ua", "en"); got != fpA {
		t.Fatalf("cookie 在场时 UA 变化不得改变指纹: %q != %q", got, fpA)
	}
	// 不同 nonce → 不同签名 → 不同指纹。
	if fpB := autobanSessionFingerprint(cookieB, "ua-A", "zh-CN"); fpB == fpA {
		t.Fatal("不同 nonce 的 cookie 必须产出不同指纹")
	}
	// 无 cookie → UA+Accept-Language 兜底，稳定且与 cookie 指纹不同形。
	u1 := autobanSessionFingerprint("", "ua-A", "zh-CN")
	u2 := autobanSessionFingerprint("", "ua-A", "zh-CN")
	if u1 == "" || !strings.HasPrefix(u1, "u:") || u1 != u2 {
		t.Fatalf("UA 兜底指纹必须稳定且 u: 前缀: %q %q", u1, u2)
	}
	if u3 := autobanSessionFingerprint("", "ua-A", "en"); u3 == u1 {
		t.Fatal("Accept-Language 不同必须产出不同兜底指纹")
	}
	if u4 := autobanSessionFingerprint("", "ua-B", "zh-CN"); u4 == u1 {
		t.Fatal("UA 不同必须产出不同兜底指纹")
	}
	// 畸形 cookie（裸伪造/垃圾签名段）不得成为指纹身份，回落 UA 兜底。
	for _, bad := range []string{"garbage", "payload.not-hex!", "a.b", ".", "c29tZQ.zzzz"} {
		if got := autobanSessionFingerprint(bad, "ua-A", "zh-CN"); got != u1 {
			t.Fatalf("畸形 cookie %q 必须回落 UA 兜底 %q, got %q", bad, u1, got)
		}
	}
}

// natTestCookieValue 按 lbhuman.signCookie 同形态构造 cookie（测试参照，
// 不引入 lbhuman 依赖树）：base64url(exp|nonce) + "." + 64 位 hex 签名段。
// 签名段内容无需真实 HMAC——指纹只取签名段（不可裸伪造由 lbhuman 校验侧
// 密钥绑定承担），此处用确定性伪签名驱动形态分支。
func natTestCookieValue(t *testing.T, ip, ua string, exp int64) string {
	t.Helper()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d|%s", exp, "nonce0123456789ab")))
	sum := sha256.Sum256([]byte(ip + "|" + ua + "|" + payload))
	return payload + "." + hex.EncodeToString(sum[:])
}

// Given Cookie 头含多个 cookie。
// When 提取 __lb_human 值。
// Then 精确命中目标 cookie（不误取同名前缀/其它 cookie）。
func TestAutobanCookieValue_extractsTargetCookie(t *testing.T) {
	header := "other=1; __lb_human=payload.sig; __lb_human_extra=evil; tail=2"
	if got := autobanCookieValue(header, "__lb_human"); got != "payload.sig" {
		t.Fatalf("autobanCookieValue=%q, want payload.sig", got)
	}
	if got := autobanCookieValue("__lb_human=only", "__lb_human"); got != "only" {
		t.Fatalf("单 cookie 提取=%q, want only", got)
	}
	if got := autobanCookieValue("a=1; b=2", "__lb_human"); got != "" {
		t.Fatalf("缺席必须返空, got %q", got)
	}
	if got := autobanCookieValue("", "__lb_human"); got != "" {
		t.Fatalf("空头必须返空, got %q", got)
	}
}

// Given 审计头 Cookie 值的两种形态（完整头/裸值）。
// When autobanHumanCookieFromHeader 提取。
// Then 完整头精确名匹配；裸值须过签名形态门；无关 cookie 不误采。
func TestAutobanHumanCookieFromHeader_bothForms(t *testing.T) {
	cookie := natTestCookieValue(t, "203.0.113.7", "ua-A", 1700000001)
	// 完整 Cookie 头形态。
	if got := autobanHumanCookieFromHeader("other=1; __lb_human=" + cookie + "; tail=2"); got != cookie {
		t.Fatalf("完整头提取=%q, want %q", got, cookie)
	}
	// 裸值形态（审计写插件单头快照）。
	if got := autobanHumanCookieFromHeader(cookie); got != cookie {
		t.Fatalf("裸值提取=%q, want %q", got, cookie)
	}
	// 含其它 cookie 但无 __lb_human：不得误采裸值。
	if got := autobanHumanCookieFromHeader("session=abc; other=def"); got != "" {
		t.Fatalf("无 __lb_human 的完整头必须返空, got %q", got)
	}
	// 裸值但非签名形态：回落空（UA 兜底）。
	for _, bad := range []string{"garbage", "a.b", "sessionid", ""} {
		if got := autobanHumanCookieFromHeader(bad); got != "" {
			t.Fatalf("非签名裸值 %q 必须返空, got %q", bad, got)
		}
	}
}

// ---- NAT 检测触发 ----

// Given NAT 开启、指纹阈值 3。
// When 同 IP 窗口内出现 3 个不同指纹且事件集中于其中一个。
// Then 切 NAT 态；2 个指纹不触发；均匀分布（无集中）不触发。
func TestAutobanNAT_detectionTriggersOnConcentratedFingerprints(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := natTestCfg(3)
	ip := "45.33.32.100"

	// 2 个指纹（集中）——未达阈值 3，不触发。
	natFeed(cfg, ip, "c:aaa")
	natFeed(cfg, ip, "c:aaa")
	natFeed(cfg, ip, "c:bbb")
	if natIsNAT(t, ip) {
		t.Fatal("2 个指纹不得触发 NAT（阈值 3）")
	}
	// 第 3 个指纹出现且多数事件集中于 c:aaa → 触发。
	natFeed(cfg, ip, "c:ccc")
	if !natIsNAT(t, ip) {
		t.Fatal("≥3 指纹且事件集中必须触发 NAT")
	}

	// 均匀分布对照：另一 IP 3 指纹各 1 事件——无集中，不触发。
	even := "45.33.32.101"
	natFeed(cfg, even, "c:111")
	natFeed(cfg, even, "c:222")
	natFeed(cfg, even, "c:333")
	if natIsNAT(t, even) {
		t.Fatal("3 指纹均匀分布（无集中）不得触发 NAT")
	}
}

// natIsNAT 读 NAT 剖面状态（测试观测）。
func natIsNAT(t *testing.T, ip string) bool {
	t.Helper()
	autobanMu.Lock()
	defer autobanMu.Unlock()
	p := autobanNATProfiles[autobanNormalizeIP(ip)]
	return p != nil && p.NAT
}

// Given NAT 已触发。
// When 窗口过期后新事件到达。
// Then 剖面重置（指纹集清空、NAT 态解除），重新按窗口检测。
func TestAutobanNAT_windowExpiryResetsProfile(t *testing.T) {
	f := installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := natTestCfg(3)
	ip := "45.33.32.102"
	natFeed(cfg, ip, "c:aaa")
	natFeed(cfg, ip, "c:aaa")
	natFeed(cfg, ip, "c:bbb")
	natFeed(cfg, ip, "c:ccc")
	if !natIsNAT(t, ip) {
		t.Fatal("前置：NAT 必须已触发")
	}
	f.Advance(6 * time.Minute) // 跨过 5 分钟窗口
	natFeed(cfg, ip, "c:aaa")
	if natIsNAT(t, ip) {
		t.Fatal("窗口过期后 NAT 态必须重置（单指纹重新起算）")
	}
}

// ---- 复合键独立计数 ----

// Given NAT 已触发（攻击指纹 c:evil 集中）。
// When 攻击指纹与无辜指纹继续喂入。
// Then 复合键 /64×指纹 各自独立桶；IP 级桶在切换沿清空（混合证据不得
// 产生 IP 级封禁）；无辜指纹不达阈值不产生候选，攻击指纹独立达标。
func TestAutobanNAT_compositeKeysCountIndependently(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := natTestCfg(3)
	ip := "45.33.32.103"

	// 触发 NAT：c:evil 4 事件 + 两个无辜指纹各 1（第 3 指纹出现且集中 →
	// 切换沿清空 IP 级混合计数桶）。
	for range 4 {
		natFeed(cfg, ip, "c:evil")
	}
	natFeed(cfg, ip, "c:innocent1")
	natFeed(cfg, ip, "c:innocent2")
	if !natIsNAT(t, ip) {
		t.Fatal("前置：NAT 必须已触发")
	}
	if keys := natWindowKeys(t); keys[ip] != 0 {
		t.Fatalf("NAT 切换沿必须清空 IP 级混合计数桶, keys=%v", keys)
	}

	// NAT 态后续事件：攻击指纹独立累计，无辜指纹独立累计。
	for range 3 {
		natFeed(cfg, ip, "c:evil")
	}
	natFeed(cfg, ip, "c:innocent1")

	keys := natWindowKeys(t)
	eviKey := autobanIdentityKey(ip, "c:evil")
	innKey := autobanIdentityKey(ip, "c:innocent1")
	if !strings.HasPrefix(eviKey, ip+"|") {
		t.Fatalf("复合键形态=%q, want %q×指纹", eviKey, ip)
	}
	if keys[eviKey] != 3 {
		t.Fatalf("攻击指纹复合桶计数=%d, want 3（NAT 态后独立起算）", keys[eviKey])
	}
	if keys[innKey] != 1 {
		t.Fatalf("无辜指纹复合桶计数=%d, want 1", keys[innKey])
	}
	if keys[ip] != 0 {
		t.Fatalf("NAT 态带指纹事件不得回流 IP 级桶: %d", keys[ip])
	}

	// 候选：攻击复合键达标（阈值 3），无辜复合键不达。
	candidates := autobanCandidates(3, 5*time.Minute)
	var found bool
	for _, c := range candidates {
		if c.IP == eviKey {
			found = true
		}
		if c.IP == innKey {
			t.Fatal("无辜指纹未达阈值不得成为候选")
		}
	}
	if !found {
		t.Fatalf("攻击指纹复合键必须独立达标成为候选: %+v", candidates)
	}
}

// Given NAT 态。
// When 无指纹事件到达（旧客户端/无 cookie 且 feed 未携带指纹）。
// Then 仍计 IP 级桶（无法归属会话的事件不丢计数）。
func TestAutobanNAT_fingerprintlessEventsStayIPLevel(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := natTestCfg(3)
	ip := "45.33.32.104"
	for range 4 {
		natFeed(cfg, ip, "c:evil")
	}
	natFeed(cfg, ip, "c:a")
	natFeed(cfg, ip, "c:b")
	if !natIsNAT(t, ip) {
		t.Fatal("前置：NAT 必须已触发")
	}
	natFeed(cfg, ip, "")
	keys := natWindowKeys(t)
	if keys[ip] != 1 { // 切换沿清空混合计数，无指纹事件重新起算
		t.Fatalf("无指纹事件必须计 IP 级桶, keys=%v", keys)
	}
}

// ---- IPv6 /64 锚定 ----

// Given NAT 开启，同 /64 的隐私扩展地址轮换。
// When 不同接口 ID 携带同一指纹喂入。
// Then NAT 剖面锚定 /64（不分裂）；复合键=同一 /64×指纹（单桶聚合）。
func TestAutobanNAT_ipv6PrivacyRotationAnchorsPer64(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := natTestCfg(3)
	addrs := []string{
		"2606:4700:abcd:1234:1111:2222:3333:4444",
		"2606:4700:abcd:1234:aaaa:bbbb:cccc:dddd",
		"2606:4700:abcd:1234::9",
	}
	// 三个指纹经轮换地址喂入，事件集中 c:evil → 单 /64 剖面触发 NAT。
	for range 4 {
		natFeed(cfg, addrs[0], "c:evil")
	}
	natFeed(cfg, addrs[1], "c:x")
	natFeed(cfg, addrs[2], "c:y")
	if !natIsNAT(t, "2606:4700:abcd:1234::") {
		t.Fatal("NAT 剖面必须锚定 /64（隐私扩展轮换不分裂）")
	}
	autobanMu.Lock()
	nProfiles := len(autobanNATProfiles)
	autobanMu.Unlock()
	if nProfiles != 1 {
		t.Fatalf("同 /64 轮换必须单剖面, got %d", nProfiles)
	}

	// NAT 态：同指纹经不同接口 ID → 同一复合键（/64 锚定不分裂）。
	natFeed(cfg, addrs[1], "c:evil")
	natFeed(cfg, addrs[2], "c:evil")
	keys := natWindowKeys(t)
	want := autobanIdentityKey("2606:4700:abcd:1234::", "c:evil")
	if keys[want] != 2 {
		t.Fatalf("同 /64 同指纹必须聚合单复合桶 %q=2, keys=%v", want, keys)
	}
	// 触发事件（c:y）自身计入其复合桶——不同指纹各自独立桶是复合键本义；
	// 分裂只指「同指纹因接口 ID 轮换而建多桶」，此处断言无 c:evil 的分裂桶。
	for k := range keys {
		if strings.HasSuffix(k, "|c:evil") && k != want {
			t.Fatalf("同指纹不得因隐私扩展轮换分裂复合键: %v", keys)
		}
	}
}

// ---- NatDetection off 保持 IP 级 ----

// Given NatDetection=false（默认）。
// When 同 IP 多指纹大量喂入。
// Then 恒 IP 级单桶（现行行为零变化），无 NAT 剖面。
func TestAutobanNAT_disabledKeepsIPLevel(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := natTestCfg(3)
	cfg.NatDetection = false
	ip := "45.33.32.105"
	for _, fp := range []string{"c:a", "c:b", "c:c", "c:d"} {
		for range 2 {
			natFeed(cfg, ip, fp)
		}
	}
	keys := natWindowKeys(t)
	if len(keys) != 1 || keys[ip] != 8 {
		t.Fatalf("NatDetection off 必须恒 IP 级单桶, keys=%v", keys)
	}
	autobanMu.Lock()
	nProfiles := len(autobanNATProfiles)
	autobanMu.Unlock()
	if nProfiles != 0 {
		t.Fatalf("off 态不得建立 NAT 剖面, got %d", nProfiles)
	}
}

// ---- 保留地址排除继承 ----

// Given NAT 开启。
// When 保留/私网/回环地址携带指纹喂入。
// Then 与 IP 级同门排除：零计数桶、零 NAT 剖面。
func TestAutobanNAT_reservedIPsExcluded(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := natTestCfg(3)
	for _, ip := range []string{"192.168.1.10", "10.0.0.1", "::1", "fe80::1", "2001:db8::1"} {
		for range 4 {
			natFeed(cfg, ip, "c:evil")
		}
		natFeed(cfg, ip, "c:a")
		natFeed(cfg, ip, "c:b")
	}
	autobanMu.Lock()
	nWindows, nProfiles := len(autobanWindows), len(autobanNATProfiles)
	autobanMu.Unlock()
	if nWindows != 0 || nProfiles != 0 {
		t.Fatalf("保留地址必须整体排除（桶=%d 剖面=%d）", nWindows, nProfiles)
	}
	// 对照：公网地址照常计数。
	natFeed(cfg, "45.33.32.9", "c:ok")
	if keys := natWindowKeys(t); keys["45.33.32.9"] != 1 {
		t.Fatalf("公网对照必须计数, keys=%v", keys)
	}
}

// ---- 复合候选执法隔离（阶段3前不落 IP 名单/累犯） ----

// Given NAT 态复合候选达标。
// When merge。
// Then 复合候选不写入 IP 名单（会话级执法未接入）、不写 IP 累犯表；
// IP 级候选照常封禁。
func TestAutobanNAT_compositeCandidatesDoNotPolluteIPListOrRecidivism(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := natTestCfg(3)
	cfg.Escalation = AutobanEscalationStandard
	ip := "45.33.32.106"
	for range 4 {
		natFeed(cfg, ip, "c:evil")
	}
	natFeed(cfg, ip, "c:a")
	natFeed(cfg, ip, "c:b")
	// NAT 态攻击指纹独立达标。
	for range 3 {
		natFeed(cfg, ip, "c:evil")
	}
	candidates := autobanCandidates(3, 5*time.Minute)
	out, err := autobanMergeEntries(cfg, candidates)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	for _, e := range presetEntries(t) {
		if strings.Contains(e.Value, "|") {
			t.Fatalf("复合键不得落 IP 名单: %+v", e)
		}
	}
	for _, banned := range out.Banned {
		if strings.Contains(banned, "|") {
			t.Fatalf("复合键不得宣称封禁: %v", out.Banned)
		}
	}
	var n int
	if err := db.GetDB().QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&n); err != nil {
		t.Fatalf("count recidivism: %v", err)
	}
	if n != 0 {
		t.Fatalf("复合候选不得污染 IP 累犯表, rows=%d", n)
	}
}

// Given NAT 态复合桶有计数。
// When 手动解封该 IP（AutobanForgetIPs）。
// Then IP 桶与其全部复合子桶一并清空（删除即解封不被旧计数撤销）。
func TestAutobanNAT_forgetIPClearsCompositeBuckets(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := natTestCfg(3)
	ip := "45.33.32.107"
	for range 4 {
		natFeed(cfg, ip, "c:evil")
	}
	natFeed(cfg, ip, "c:a")
	natFeed(cfg, ip, "c:b")
	for range 2 {
		natFeed(cfg, ip, "c:evil")
	}
	AutobanForgetIPs([]string{ip})
	keys := natWindowKeys(t)
	if len(keys) != 0 {
		t.Fatalf("解封必须清 IP 桶与全部复合子桶, keys=%v", keys)
	}
	if natIsNAT(t, ip) {
		t.Fatal("解封必须同步清除 NAT 剖面")
	}
}

// ---- 配置三通道 ----

// Given 全新库。
// When 读配置。
// Then NatDetection 默认 off、NatFingerprintThreshold 默认 3（现行 IP 级不变）。
func TestAutobanConfig_natDefaults(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg, err := GetAutobanConfig()
	if err != nil {
		t.Fatalf("GetAutobanConfig: %v", err)
	}
	if cfg.NatDetection {
		t.Fatal("NatDetection 默认必须 off")
	}
	if cfg.NatFingerprintThreshold != 3 {
		t.Fatalf("NatFingerprintThreshold 默认=%d, want 3", cfg.NatFingerprintThreshold)
	}
}

// Given 写侧保存 NAT 配置。
// When 回读。
// Then 值落库且回读一致；缺省阈值（0=旧客户端未携带）归一 3。
func TestAutobanConfig_setAndReadNAT(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 10, WindowMinutes: 5, Duration: "1h", Scope: "blocked",
		NatDetection: true, NatFingerprintThreshold: 5}
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("SetAutobanConfig: %v", err)
	}
	got, err := GetAutobanConfig()
	if err != nil {
		t.Fatalf("GetAutobanConfig: %v", err)
	}
	if !got.NatDetection || got.NatFingerprintThreshold != 5 {
		t.Fatalf("回读 NAT 配置=%+v, want on/5", got)
	}
	// 缺省阈值归一（旧客户端零值）。
	cfg.NatFingerprintThreshold = 0
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("SetAutobanConfig 缺省阈值: %v", err)
	}
	got, err = GetAutobanConfig()
	if err != nil {
		t.Fatalf("GetAutobanConfig: %v", err)
	}
	if got.NatFingerprintThreshold != 3 {
		t.Fatalf("缺省阈值必须归一 3, got %d", got.NatFingerprintThreshold)
	}
}

// Given 写侧校验。
// When 阈值越界/合法。
// Then 2-100 外拒绝（含负值），边界与合法值通过。
func TestAutobanConfig_natThresholdValidation(t *testing.T) {
	base := AutobanConfig{Enabled: true, Threshold: 10, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "off"}
	for _, n := range []int{2, 3, 100} {
		cfg := base
		cfg.NatFingerprintThreshold = n
		if err := ValidateAutobanConfig(cfg); err != nil {
			t.Fatalf("阈值 %d 必须合法: %v", n, err)
		}
	}
	for _, n := range []int{-1, 1, 101} {
		cfg := base
		cfg.NatFingerprintThreshold = n
		if err := ValidateAutobanConfig(cfg); err == nil {
			t.Fatalf("阈值 %d 必须拒绝", n)
		}
	}
}

// Given 已有计数桶。
// When NAT 开关/指纹阈值变更（SetAutobanConfig）。
// Then 清空计数桶与 NAT 剖面（身份键口径变化，旧计数不可混算）。
func TestAutobanConfig_natChangeResetsCounters(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "off"}
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	natFeed(cfg, "45.33.32.108", "c:a")
	if len(natWindowKeys(t)) == 0 {
		t.Fatal("前置：必须有计数")
	}
	cfg.NatDetection = true
	cfg.NatFingerprintThreshold = 3
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("enable NAT: %v", err)
	}
	if keys := natWindowKeys(t); len(keys) != 0 {
		t.Fatalf("NAT 开关变更必须清桶, keys=%v", keys)
	}
	// 再改阈值同样清桶。
	natFeed(cfg, "45.33.32.108", "c:a")
	cfg.NatFingerprintThreshold = 4
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatalf("change threshold: %v", err)
	}
	if keys := natWindowKeys(t); len(keys) != 0 {
		t.Fatalf("指纹阈值变更必须清桶, keys=%v", keys)
	}
}

// ---- 人机批喂入指纹传递 ----

// Given NAT 开启，人机事件携带指纹。
// When ObserveHumanEvents 批喂入。
// Then 指纹进入同一 NAT 检测/复合键管线（挑战失败集中 → NAT 态复合计数）。
func TestObserveHumanEvents_fingerprintFlowsIntoNAT(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "challenge_failed", false)
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_nat_detection=1, autoban_nat_fingerprint_threshold=3 WHERE id=1`); err != nil {
		t.Fatalf("seed NAT config: %v", err)
	}
	ip := "45.33.32.109"
	items := make([]HumanObserveItem, 0, 6)
	for range 4 {
		items = append(items, HumanObserveItem{IP: ip, Kind: "fail", Fingerprint: "c:evil", At: autobanNow()})
	}
	items = append(items,
		HumanObserveItem{IP: ip, Kind: "fail", Fingerprint: "c:a", At: autobanNow()},
		HumanObserveItem{IP: ip, Kind: "fail", Fingerprint: "c:b", At: autobanNow()},
	)
	ObserveHumanEvents(items)
	if !natIsNAT(t, ip) {
		t.Fatal("人机事件指纹必须进入 NAT 检测")
	}
	ObserveHumanEvents([]HumanObserveItem{{IP: ip, Kind: "fail", Fingerprint: "c:evil", At: autobanNow()}})
	keys := natWindowKeys(t)
	if keys[autobanIdentityKey(ip, "c:evil")] != 1 {
		t.Fatalf("人机复合桶必须独立计数, keys=%v", keys)
	}
}

// ---- 名单条目值形态回归 ----

// Given 复合键与裸 IP。
// When autobanBanValue。
// Then 复合键不得被误判为 IPv6 网络地址补 CIDR（形态门回归）。
func TestAutobanBanValue_compositeKeyNotCIDR(t *testing.T) {
	composite := autobanIdentityKey("2606:4700:abcd:1234::", "c:evil")
	if got := autobanBanValue(composite); got != composite {
		t.Fatalf("复合键 banValue=%q, want 原样 %q", got, composite)
	}
}

// ---- WAF 摄取端到端：审计头 → 指纹 → NAT 复合计数 ----

// natWAFixture 生成携带 __lb_human cookie/UA/Accept-Language 头的可摄取
// blocked 事务（时间取当前时钟以通过喂入窗口）。
func natWAFixture(txID, ip, cookie string) string {
	now := time.Now().UTC()
	fixture := securityEvents历史Fixture(txID, ip, "/attack")
	fixture = strings.Replace(fixture, "1786447017841320426", fmt.Sprintf("%d", now.UnixNano()), 1)
	headers := fmt.Sprintf(`"headers": { "host": ["go029.com"], "User-Agent": ["nat-agent"], "Accept-Language": ["zh-CN"], "Cookie": [%q] }`, cookie)
	fixture = strings.Replace(fixture, `"headers": { "host": ["go029.com"] }`, headers, 1)
	return fixture
}

// Given NAT 开启，同 IP 的 WAF blocked 事件携带不同会话 cookie。
// When 经真实摄取管线（解析→提交→喂入）累计。
// Then 审计头提取的指纹进入 NAT 检测；触发后攻击指纹独立复合计数，
// IP 级混合桶在切换沿清空（端到端贯穿 parse→feed→NAT）。
func TestSecurityEventsAutoban_natFingerprintFromAuditHeaders(t *testing.T) {
	installSecurityEventsAutobanFixture(t)
	setAutobanConfigRaw(t, true, 3, 60, "1h", "blocked", false)
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_nat_detection=1, autoban_nat_fingerprint_threshold=3 WHERE id=1`); err != nil {
		t.Fatalf("seed NAT config: %v", err)
	}
	ip := "45.33.32.200"
	evilCookie := natTestCookieValue(t, ip, "nat-agent", time.Now().Add(time.Hour).Unix())
	xCookie := natTestCookieValue(t, ip, "nat-agent-x", time.Now().Add(time.Hour).Unix())
	yCookie := natTestCookieValue(t, ip, "nat-agent-y", time.Now().Add(time.Hour).Unix())

	var docs []string
	for i := range 4 {
		docs = append(docs, natWAFixture(fmt.Sprintf("tx-nat-evil-%d", i), ip, evilCookie))
	}
	docs = append(docs, natWAFixture("tx-nat-x", ip, xCookie), natWAFixture("tx-nat-y", ip, yCookie))
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	if err := os.WriteFile(logPath, []byte(strings.Join(docs, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := securityEventsNewTailer(logPath, offsetPath).securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}

	if !natIsNAT(t, ip) {
		t.Fatal("审计头指纹必须经摄取管线触发 NAT 检测")
	}
	evilFP := autobanSessionFingerprint(evilCookie, "nat-agent", "zh-CN")
	keys := natWindowKeys(t)
	evilKey := autobanIdentityKey(ip, evilFP)
	// 触发事件（第 3 指纹 y）自身计入复合桶；evil 的 4 事件全部在 NAT 态前
	// 计 IP 级（切换沿清空），故 evil 复合桶此刻为 0——再喂一条 evil 验证独立计数。
	if keys[ip] != 0 {
		t.Fatalf("NAT 切换沿必须清空 IP 级混合桶, keys=%v", keys)
	}
	autobanObserveEventScopedAt(natTestCfg(3), ip, "blocked", "942100", evilFP, time.Now().UTC())
	keys = natWindowKeys(t)
	if keys[evilKey] != 1 {
		t.Fatalf("攻击指纹复合桶必须独立计数, keys=%v", keys)
	}
}
