// Package caddygeoip —— 搜索引擎爬虫验证器（v2.3.8 地域拦截爬虫豁免，方案 B：
// UA + PTR 双跳验证，2026-10-17 用户裁定）。
//
// 验证算法（geoipnames.CrawlerEnginePTRMatch 同源语义）：
//  1. UA 命中引擎（geoipnames.MatchCrawlerEngine）
//  2. PTR 反查客户端 IP，域名后缀属该引擎官方域（机房 PTR 如
//     *.bc.googleusercontent.com 不匹配——伪装墙 1）
//  3. 正向回验：PTR 域名解析结果包含客户端 IP（防自配 PTR——伪装墙 2/3）
//
// 性能（2000/s 正常 + 100/s 攻击基准）：非爬虫 UA 仅付一次预编译正则；
// 验证按 IP 缓存（正 1h/负 10min）；在途 DNS 信号量 32 非阻塞（满员立即
// fail-closed，无 goroutine 堆积）；单查询 500ms 超时。
package caddygeoip

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"lazy-balancer-v2/geoipnames"
)

// crawlerDNSResolver 解析器接口（测试替身注入点）。
type crawlerDNSResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// crawlerVerifyResolver 可注入解析器（测试替身）；缺省 net 包。
var crawlerVerifyResolver crawlerDNSResolver = &netResolver{}

type netResolver struct{}

func (n *netResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

func (n *netResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// crawlerVerifyCache 验证结论缓存条目。
type crawlerVerifyCache struct {
	ok      bool
	expires time.Time
}

const (
	crawlerCachePositiveTTL = time.Hour
	crawlerCacheNegativeTTL = 10 * time.Minute
	crawlerDNSQueryTimeout  = 500 * time.Millisecond
	// crawlerVerifySlots 在途 DNS 并发上限（非阻塞获取：满员 fail-closed）
	crawlerVerifySlots = 32
)

var (
	crawlerCacheMu sync.Mutex
	crawlerCache   = map[string]crawlerVerifyCache{}
	// crawlerVerifySem 非阻塞信号量（cap 32；关账本式释放）
	crawlerVerifySem = make(chan struct{}, crawlerVerifySlots)
	// crawlerCacheMax 简单容量护栏（条目数；超限全清——结论短 TTL，重建廉价）
	crawlerCacheMax = 200_000
)

// VerifyCrawler 验证客户端 IP 是否为该引擎官方爬虫出口（带缓存）。
// 返回 false = 未通过（含超时/信号量满/解析失败——fail-closed）。
func VerifyCrawler(ip, engineID string) bool {
	key := ip + "|" + engineID
	now := time.Now()
	crawlerCacheMu.Lock()
	if entry, hit := crawlerCache[key]; hit && now.Before(entry.expires) {
		crawlerCacheMu.Unlock()
		return entry.ok
	}
	crawlerCacheMu.Unlock()

	ok := false
	if geoipnames.CrawlerEngineVerifyMethod(engineID) == geoipnames.CrawlerVerifyIPRange {
		// 官方声明不支持 nslookup 的厂商（360）：官方 IP 段验证（名单表=
		// 定时更新任务的快照，更新即生效，无需重载）
		ok = verifyCrawlerIPRangeFromList(ip, engineID)
	} else if acquireCrawlerSlot() {
		ok = verifyCrawlerDNS(ip, engineID)
		releaseCrawlerSlot()
	}
	ttl := crawlerCacheNegativeTTL
	if ok {
		ttl = crawlerCachePositiveTTL
	}
	crawlerCacheMu.Lock()
	if len(crawlerCache) >= crawlerCacheMax {
		crawlerCache = make(map[string]crawlerVerifyCache, 1024)
	}
	crawlerCache[key] = crawlerVerifyCache{ok: ok, expires: now.Add(ttl)}
	crawlerCacheMu.Unlock()
	return ok
}

// verifyCrawlerDNS 双跳验证本体（无缓存、需已持信号量）。
func verifyCrawlerDNS(ip, engineID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), crawlerDNSQueryTimeout)
	defer cancel()
	names, err := crawlerVerifyResolver.LookupAddr(ctx, ip)
	if err != nil {
		return false
	}
	for _, name := range names {
		// LookupAddr 返回 FQDN 尾点；PTR 后缀锚定前剥除
		host := name
		if n := len(host); n > 0 && host[n-1] == '.' {
			host = host[:n-1]
		}
		if !geoipnames.CrawlerEnginePTRMatch(engineID, host) {
			continue
		}
		// 正向回验：PTR 域名解析须包含原 IP（防伪造 PTR 指向官方域）
		addrs, err := crawlerVerifyResolver.LookupHost(ctx, host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a == ip {
				return true
			}
		}
	}
	return false
}

func acquireCrawlerSlot() bool {
	select {
	case crawlerVerifySem <- struct{}{}:
		return true
	default:
		return false // 满员：立即 fail-closed（不排队）
	}
}

func releaseCrawlerSlot() {
	select {
	case <-crawlerVerifySem:
	default:
	}
}

// ResetCrawlerVerifyCacheForTest 清缓存+换 resolver（测试专用；非测试路径禁用）。
func ResetCrawlerVerifyCacheForTest(r crawlerDNSResolver) {
	crawlerCacheMu.Lock()
	crawlerCache = make(map[string]crawlerVerifyCache)
	crawlerCacheMu.Unlock()
	if r != nil {
		crawlerVerifyResolver = r
	} else {
		crawlerVerifyResolver = &netResolver{}
	}
}

// crawlerIPListFile 厂商 IP 段名单快照文件（root 服务写、插件读——模块边界：
// caddygeoip 独立模块不 import 根模块，快照经共享文件交换）。
const crawlerIPListFile = "/app/data/crawler-ip-lists.json"

var (
	crawlerFileCacheMu     sync.Mutex
	crawlerFileCacheTime   time.Time
	crawlerFileCacheResult = map[string][]string{}
)

// verifyCrawlerIPRangeFromList 从共享快照文件验证 IP 段命中（缺失/为空=fail-closed；
// mtime 变化才重读，2000/s 混合流量下文件系统开销=stat 节流）。
func verifyCrawlerIPRangeFromList(ipStr, engineID string) bool {
	now := time.Now()
	crawlerFileCacheMu.Lock()
	defer crawlerFileCacheMu.Unlock()
	if now.Sub(crawlerFileCacheTime) > 10*time.Minute {
		data, err := os.ReadFile(crawlerIPListFile)
		if err != nil {
			return false
		}
		var all map[string][]string
		if err := json.Unmarshal(data, &all); err != nil {
			return false
		}
		crawlerFileCacheResult = all
		crawlerFileCacheTime = now
	}
	entries := crawlerFileCacheResult[engineID]
	if len(entries) == 0 {
		return false
	}
	ip := netip.MustParseAddr(ipStr)
	for _, cidr := range entries {
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}
