package caddygeoip

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// securityTimingHeader 是耗时关联头——blocked_counter 注入、coraza 审计日志
// request.headers 收录、审计写插件（auditwriter.go）从审计事务头提取后作
// 进程内计时注册表（auditTiming*）的关联键。该头在本进程内即完成全部关联
// （注册表+审计注入同进程），不再跨进程——耗时侧车文件已于
// 历史退役，耗时随审计行 lb_timing 字段内嵌流转。渲染链在该头抵达
// reverse_proxy 前删除（caddy.go 渲染层），不上泄上游。
const securityTimingHeader = "X-Lb-Security-Timing-Id"

// securityTimingStartHeader 是起始纳秒时间戳头——blocked_counter 注入(注入原值
// 兼作「链未过预检收点」判定基准:拦截检出时头仍=原值即预检段拦);SecurityTimingPre
// 记 :pre 后把它重写为预检完成锚点,SecurityTimingEnd 读锚点计算 logged 事件的
// WAF 段耗时(拦截事件的耗时由 blocked_counter 写,不经此头)。与 timing ID 头
// 同清单剥离。
const securityTimingStartHeader = "X-Lb-Security-Timing-Start-Ns"

// 计时分段键（注册表 segment 参数；审计行内 pre_us/end_us 字段）。
const (
	timingSegmentPre = "pre"
	timingSegmentEnd = "end"
)

// recordSecurityTiming 读耗时关联头对（timing ID + 起始纳秒）并把一段耗时写入
// 进程内计时注册表——SecurityTimingPre/End 两 ServeHTTP
// 原逐字重复，收敛为 本 helper，segment 区分收点。分段键语义：
// pre=预检段（放行由 timing_pre 记；预检拦由 blocked_counter 代记，决策口径）；
// end 二态——拦截事件=链首→中断全链（blocked_counter），logged 事件=预检完成后
// →链末（timing_end 读重写后的分段锚点）。头对缺失或起始时间戳不可解析时静默
// 跳过（耗时是增强信息，不产生请求路径错误）。
//
// 写入目标从旧侧车逐行追加（有界 channel 非阻塞丢行）改为进程内
// 注册表（auditTimingRecord）——写入恒成功，由审计写插件的 drain goroutine
// 注入审计行后落盘（零丢弃）。
func recordSecurityTiming(r *http.Request, segment string) {
	timingID := r.Header.Get(securityTimingHeader)
	startNsStr := r.Header.Get(securityTimingStartHeader)
	// 计时 ID 是进程内注册表 key，头值客户端可控
	// （无 counter 的路由无服务端注入/覆盖）——只接受与服务端 securityTimingID
	// 同形态的 16 字符小写 hex，其余（含超长/非 hex 伪造头）一律静默忽略，
	// 不得进入注册表（内存 DoS 面）。
	if timingID != "" && startNsStr != "" && isValidSecurityTimingID(timingID) {
		if startNs, perr := strconv.ParseInt(startNsStr, 10, 64); perr == nil {
			us := (time.Now().UnixNano() - startNs) / 1000 // ns→µs
			// 挂钟回拨（或异常起始头解析出的未来时刻）会产生负时长，
			// 直接注入审计行/UI 是脏数据；耗时下限钳 0（0µs 是合法计时值）。
			if us < 0 {
				us = 0
			}
			auditTimingRecord(timingID, segment, us)
		}
	}
}

// securityTimingID 生成 16 字符随机 hex 作 timing 关联 ID
// 原 4 字节生日界下 1 万在途即 ~1.2% 任意对碰撞概率——扩到 8 字节对齐
// coraza tx.ID 长度,碰撞面消除;rand 失败返回空串=该请求不计耗时,静默降级)。
func securityTimingID() string {
	b := make([]byte, 8)
	if _, err := securityTimingRandRead(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// securityTimingRandRead 是 crypto/rand.Read 的注入缝：只用于在测试里构造
// 「ID 生成失败」形态（该形态下客户端自带的计时头必须已被剥离），生产不得替换。
var securityTimingRandRead = cryptorand.Read

// isValidSecurityTimingID 校验计时 ID 与服务端生成形态（securityTimingID，
// 8 字节小写 hex）逐形一致——该 ID 是计时注册表 key 且头值客户端
// 可控，消费侧（recordSecurityTiming/auditTimingRecord）只认 16 字符小写
// hex，把 key 长度与字符集钉死在生成侧形态上，伪造头灌注册表的内存 DoS
// 面闭合。
func isValidSecurityTimingID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
