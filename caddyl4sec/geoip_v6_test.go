package caddyl4sec

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// —— IPv6 双协议引擎级实证（L4 侧）——
//
// 夹具与 caddygeoip/handler_v6_test.go 同构（独立模块无共享包，跨模块复制
// 是本仓既定形态）：结构 3.0/IPv6 xdb，38B 段索引。断言面是真实
// L4GeoIPMatcher.Match(layer4.Connection)：deny「海外」模式中国 v6 不命中
// （放行）、海外 v6 命中（断连）；allow 模式反向；v6 禁用/缺失 → fail-open
// 放行（用户裁定语义不变，仅作用于不可解析形态）。

type v6Seg struct {
	start, end [16]byte
	region     string
}

func v6Bytes(t *testing.T, s string) [16]byte {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("v6 fixture ip invalid: %s", s)
	}
	var out [16]byte
	copy(out[:], ip.To16())
	return out
}

func writeV6FixtureXDB(t *testing.T, path string, segments []v6Seg) {
	t.Helper()
	const (
		headerSize      = 256
		vectorIndexSize = 256 * 256 * 8
		segmentSize     = 38
	)
	buf := make([]byte, headerSize+vectorIndexSize)
	regionPtr := map[string]uint32{}
	next := uint32(headerSize + vectorIndexSize)
	appendRegion := func(region string) uint32 {
		if ptr, ok := regionPtr[region]; ok {
			return ptr
		}
		ptr := next
		buf = append(buf, region...)
		next = uint32(len(buf))
		regionPtr[region] = ptr
		return ptr
	}
	for _, seg := range segments {
		appendRegion(seg.region)
	}
	blocks := make([]uint32, len(segments))
	for i, seg := range segments {
		blocks[i] = next
		block := make([]byte, segmentSize)
		copy(block[0:16], seg.start[:])
		copy(block[16:32], seg.end[:])
		binary.LittleEndian.PutUint16(block[32:], uint16(len(seg.region)))
		binary.LittleEndian.PutUint32(block[34:], regionPtr[seg.region])
		buf = append(buf, block...)
		next = uint32(len(buf))
	}
	for i, seg := range segments {
		idx := headerSize + (int(seg.start[0])*256+int(seg.start[1]))*8
		binary.LittleEndian.PutUint32(buf[idx:], blocks[i])
		binary.LittleEndian.PutUint32(buf[idx+4:], blocks[i]+segmentSize)
	}
	binary.LittleEndian.PutUint16(buf[0:], 3)
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[8:], blocks[0])
	binary.LittleEndian.PutUint32(buf[12:], blocks[len(blocks)-1])
	binary.LittleEndian.PutUint16(buf[16:], 6)
	binary.LittleEndian.PutUint16(buf[18:], 4)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
}

func defaultV6Fixtures(t *testing.T) []v6Seg {
	t.Helper()
	return []v6Seg{
		{start: v6Bytes(t, "240e::"), end: v6Bytes(t, "240e:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), region: "中国|北京市|北京市|电信|CN"},
		{start: v6Bytes(t, "2606:4700::"), end: v6Bytes(t, "2606:4700:0:0:ffff:ffff:ffff:ffff"), region: "United States|California|San Francisco|Cloudflare, Inc.|US"},
	}
}

// v4FixtureForL4 是 findTestXdb 的兜底（跨模块无法共享 caddygeoip 夹具定位）。
func v4FixtureForL4(t *testing.T) string {
	t.Helper()
	for _, cand := range []string{"../caddygeoip/testdata/ip2region_v4.xdb", "/app/data/ip2region.xdb"} {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

func v6MatcherForTest(t *testing.T, m *L4GeoIPMatcher) *L4GeoIPMatcher {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("provision: %v", err)
	}
	return m
}

// TestL4GeoIPMatcher_v6Enabled_regionVerdict：deny「海外」中国 v6 放行、
// 海外 v6 断连；allow 模式反向。引擎级（真实 Match + 真实 xdb 搜索）。
func TestL4GeoIPMatcher_v6Enabled_regionVerdict(t *testing.T) {
	v4 := v4FixtureForL4(t)
	if v4 == "" {
		t.Skip("no v4 xdb fixture available")
	}
	v6 := filepath.Join(t.TempDir(), "ip2region_v6.xdb")
	writeV6FixtureXDB(t, v6, defaultV6Fixtures(t))

	deny := &L4GeoIPMatcher{Countries: []string{"海外"}, XdbPath: v4, XdbV6Path: v6}
	v6MatcherForTest(t, deny)
	matched, err := deny.Match(newTestConn("240e:56:1:2::9"))
	if err != nil || matched {
		t.Fatalf("china v6 under deny-overseas must pass: matched=%v err=%v", matched, err)
	}
	matched, err = deny.Match(newTestConn("2606:4700::1111"))
	if err != nil || !matched {
		t.Fatalf("overseas v6 under deny-overseas must block: matched=%v err=%v", matched, err)
	}

	// allow 模式：名单外断连。名单仅「北京市」——北京市 v6 ∈名单放行，
	// 海外 v6 ∉名单断连（海外行 Loc=国名，不命中省条目）。
	allow := &L4GeoIPMatcher{Countries: []string{"北京市"}, Mode: "allow", XdbPath: v4, XdbV6Path: v6}
	v6MatcherForTest(t, allow)
	matched, err = allow.Match(newTestConn("240e:56:1:2::9"))
	if err != nil || matched {
		t.Fatalf("china v6 under allow must pass: matched=%v err=%v", matched, err)
	}
	matched, err = allow.Match(newTestConn("2606:4700::1111"))
	if err != nil || !matched {
		t.Fatalf("overseas v6 under allow must block: matched=%v err=%v", matched, err)
	}
}

// TestL4GeoIPMatcher_v6Disabled_failOpen：v6 禁用/缺失 → 全量 IPv6 不可解析
// → fail-open 放行（裁定语义不变）；v4 查询同 handler 不受影响（对照）。
func TestL4GeoIPMatcher_v6Disabled_failOpen(t *testing.T) {
	v4 := v4FixtureForL4(t)
	if v4 == "" {
		t.Skip("no v4 xdb fixture available")
	}
	disabled := &L4GeoIPMatcher{Countries: []string{"海外"}, XdbPath: v4}
	v6MatcherForTest(t, disabled)
	matched, err := disabled.Match(newTestConn("240e:56:1:2::9"))
	if err != nil || matched {
		t.Fatalf("disabled v6 must fail open: matched=%v err=%v", matched, err)
	}
	missing := &L4GeoIPMatcher{Countries: []string{"海外"}, XdbPath: v4, XdbV6Path: filepath.Join(t.TempDir(), "missing.xdb")}
	v6MatcherForTest(t, missing)
	matched, err = missing.Match(newTestConn("240e:56:1:2::9"))
	if err != nil || matched {
		t.Fatalf("missing v6 file must fail open: matched=%v err=%v", matched, err)
	}
}

// TestSharedGeoIPSearcher_v6CacheKeySeparates：同一 v4 路径不同 v6 形态必须
// 取到不同实例（v6 开关/换库经键与形态判定收敛）。
func TestSharedGeoIPSearcher_v6CacheKeySeparates(t *testing.T) {
	v4 := v4FixtureForL4(t)
	if v4 == "" {
		t.Skip("no v4 xdb fixture available")
	}
	v6 := filepath.Join(t.TempDir(), "ip2region_v6.xdb")
	writeV6FixtureXDB(t, v6, defaultV6Fixtures(t))
	keyOff := v4 + "\x00"
	keyOn := v4 + "\x00" + v6
	t.Cleanup(func() {
		delete(sharedSearchers, keyOff)
		delete(sharedSearchers, keyOn)
	})
	off, err := sharedGeoIPSearcher(v4, "")
	if err != nil {
		t.Fatalf("acquire off: %v", err)
	}
	on, err := sharedGeoIPSearcher(v4, v6)
	if err != nil {
		t.Fatalf("acquire on: %v", err)
	}
	if off == on {
		t.Fatal("v6 enabled instance must be rebuilt separately (v6 family attached)")
	}
}

// TestSharedGeoIPSearcher_probeTTLThrottlesFileIO：探测节流——TTL 窗口内连续
// 采样复用上次探测投影（头读/stat 计数不随采样次数增长），窗口过界后下一次
// 调用重新实测；节流不改变取值形态（窗口内外恒返回同实例，重建只由形态
// 漂移驱动）。
func TestSharedGeoIPSearcher_probeTTLThrottlesFileIO(t *testing.T) {
	v4 := v4FixtureForL4(t)
	if v4 == "" {
		t.Skip("no ip2region xdb available")
	}
	v6 := filepath.Join(t.TempDir(), "ip2region_v6.xdb")
	writeV6FixtureXDB(t, v6, defaultV6Fixtures(t))
	keyOn := v4 + "\x00" + v6

	// 进程级缓存隔离：本用例同键的实例/探测投影先清，用后恢复。
	resetSharedSearcherProbesForTest()
	sharedSearcherMu.Lock()
	delete(sharedSearchers, keyOn)
	sharedSearcherMu.Unlock()
	t.Cleanup(func() {
		sharedSearcherMu.Lock()
		delete(sharedSearchers, keyOn)
		sharedSearcherMu.Unlock()
		resetSharedSearcherProbesForTest()
	})

	headerLoads, stats := 0, 0
	savedHeaderLoad, savedStat := v6HeaderLoadFromFile, probeFileStat
	v6HeaderLoadFromFile = func(path string) (*xdb.Header, error) {
		headerLoads++
		return savedHeaderLoad(path)
	}
	probeFileStat = func(path string) (os.FileInfo, error) {
		stats++
		return savedStat(path)
	}
	t.Cleanup(func() { v6HeaderLoadFromFile, probeFileStat = savedHeaderLoad, savedStat })

	now := time.Unix(1_700_000_000, 0)
	sharedSearcherProbes.nowFunc = func() time.Time { return now }
	t.Cleanup(func() { sharedSearcherProbes.nowFunc = time.Now })

	s1, err := sharedGeoIPSearcher(v4, v6)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if headerLoads != 1 || stats != 2 {
		t.Fatalf("first acquire must probe for real (one header read, v4+v6 stat): headerLoads=%d stats=%d", headerLoads, stats)
	}

	for i := range 8 {
		s, err := sharedGeoIPSearcher(v4, v6)
		if err != nil || s != s1 {
			t.Fatalf("sample %d within TTL must serve the same instance: err=%v", i, err)
		}
	}
	if headerLoads != 1 || stats != 2 {
		t.Fatalf("probes within TTL must reuse the previous result (counts must not grow with samples): headerLoads=%d stats=%d", headerLoads, stats)
	}

	now = now.Add(sharedSearcherProbeTTL)
	s2, err := sharedGeoIPSearcher(v4, v6)
	if err != nil || s2 != s1 {
		t.Fatalf("post-TTL acquire must not rebuild an unchanged form: err=%v", err)
	}
	if headerLoads != 2 || stats != 4 {
		t.Fatalf("expired probe must hit disk again: headerLoads=%d stats=%d", headerLoads, stats)
	}
}
