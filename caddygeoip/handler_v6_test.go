package caddygeoip

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	caddyhttp "github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// —— IPv6 双协议引擎级实证 ——
//
// 夹具为生成的小型结构 3.0/IPv6 xdb（38B 段索引：startIP 16 + endIP 16 +
// dataLen 2 + dataPtr 4，16 字节大端 IP，向量索引按 IP 前两字节键入），布局
// 锚定绑定库 xdb/version.go（IPv6 SegmentIndexSize=38、IPCompare=bytes.Compare）
// 与 xdb/header.go（256B 头 [0:2]=3、[16:18]=6）。断言面是真实 ServeHTTP
// 渲染链：v6 客户端命中中国段 → province/省-市 Loc；海外段 → 国名 Loc；
// v6 禁用/缺库 → 「海外」fail-closed 哨兵（裁定语义不变，仅作用于不可解析
// 形态——v6 关闭即全量 IPv6 客户端不可解析）。

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
		{start: v6Bytes(t, "2400:3200::"), end: v6Bytes(t, "2400:3200:0:0:ffff:ffff:ffff:ffff"), region: "中国|浙江省|杭州市|阿里|CN"},
		{start: v6Bytes(t, "2606:4700::"), end: v6Bytes(t, "2606:4700:0:0:ffff:ffff:ffff:ffff"), region: "United States|California|San Francisco|Cloudflare, Inc.|US"},
	}
}

// v6ServeRequest 以真实 Provision+ServeHTTP 链渲染 v6 客户端请求，返回
// 下游可观测的 vars 与**请求头**（X-LB-GeoIP-* 是发给 coraza 的请求头镜像，
// 不是响应头——必须从 next 捕获的 request 读取）。
func v6ServeRequest(t *testing.T, h *GeoIPHandler, clientIP string) (vars map[string]any, header http.Header) {
	t.Helper()
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	vars = make(map[string]any)
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)
	req.RemoteAddr = clientIP
	rec := httptest.NewRecorder()
	var captured http.Header
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		captured = r.Header
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("serve: %v", err)
	}
	return vars, captured
}

func assertVars(t *testing.T, vars map[string]any, key, want string) {
	t.Helper()
	if got, _ := vars[key].(string); got != want {
		t.Fatalf("%s=%q, want %q (vars=%v)", key, got, want, vars)
	}
}

func assertHeader(t *testing.T, header http.Header, key, want string) {
	t.Helper()
	if got := header.Get(key); got != want {
		t.Fatalf("%s=%q, want %q", key, got, want)
	}
}

// TestServeHTTP_v6Enabled_resolvesRealRegion：v6 开启且库健康 → 240e 段命中
// 北京市（X-LB-GeoIP-Loc=省-市形态）、海外 v6 → 国名 Loc；哨兵被真实行覆盖。
func TestServeHTTP_v6Enabled_resolvesRealRegion(t *testing.T) {
	dir := t.TempDir()
	v4 := findTestXdb()
	if v4 == "" {
		t.Skip("no v4 xdb fixture available")
	}
	v6 := filepath.Join(dir, "ip2region_v6.xdb")
	writeV6FixtureXDB(t, v6, defaultV6Fixtures(t))

	h := &GeoIPHandler{XdbPath: v4, XdbV6Path: v6}
	vars, header := v6ServeRequest(t, h, "240e:56:1:2::9")
	assertVars(t, vars, "geoip.country_name", "中国")
	assertVars(t, vars, "geoip.province", "北京市")
	assertHeader(t, header, "X-LB-GeoIP-Loc", "北京市/北京市")

	h2 := &GeoIPHandler{XdbPath: v4, XdbV6Path: v6}
	vars2, header2 := v6ServeRequest(t, h2, "2606:4700::1111")
	assertVars(t, vars2, "geoip.country_name", "United States")
	assertHeader(t, header2, "X-LB-GeoIP-Loc", "United States")
}

// TestServeHTTP_v6Disabled_keepsOverseasSentinel：v6 关闭（无 xdb_v6_path）
// → 全量 IPv6 客户端按不可解析处理：四变量空串哨兵 + X-LB-GeoIP-Loc=海外
// （fail-closed 裁定不变）；同时 v4 查询不受影响（对照）。
func TestServeHTTP_v6Disabled_keepsOverseasSentinel(t *testing.T) {
	v4 := findTestXdb()
	if v4 == "" {
		t.Skip("no v4 xdb fixture available")
	}
	h := &GeoIPHandler{XdbPath: v4}
	vars, header := v6ServeRequest(t, h, "240e:56:1:2::9")
	assertVars(t, vars, "geoip.country_name", "")
	assertVars(t, vars, "geoip.province", "")
	assertVars(t, vars, "geoip.city", "")
	assertHeader(t, header, "X-LB-GeoIP-Loc", "海外")
	// 对照：v4 客户端在同一个 handler 上正常解析。
	h2 := &GeoIPHandler{XdbPath: v4}
	vars2, header2 := v6ServeRequest(t, h2, "114.114.114.114")
	if name, _ := vars2["geoip.country_name"].(string); name == "" {
		t.Fatalf("v4 lookup must stay healthy: vars=%v header=%v", vars2, header2)
	}
}

// TestServeHTTP_v6MissingFile_degradesToSentinel：v6 开启但文件缺失 → 健康
// 门降级为禁用 → 哨兵；v4 不受影响（fail-stale 链路对 v6 同样不拖垮主链）。
func TestServeHTTP_v6MissingFile_degradesToSentinel(t *testing.T) {
	v4 := findTestXdb()
	if v4 == "" {
		t.Skip("no v4 xdb fixture available")
	}
	h := &GeoIPHandler{XdbPath: v4, XdbV6Path: filepath.Join(t.TempDir(), "missing_v6.xdb")}
	vars, header := v6ServeRequest(t, h, "240e:56:1:2::9")
	assertHeader(t, header, "X-LB-GeoIP-Loc", "海外")
	assertVars(t, vars, "geoip.province", "")
}

// TestSharedGeoIPSearcher_v6FormChangeTriggersRebuild：v6 文件换库（mtime
// 变化）必须触发共享 searcher 重建——双源更新两次 rename 依赖本判定收敛。
func TestSharedGeoIPSearcher_v6FormChangeTriggersRebuild(t *testing.T) {
	v4 := findTestXdb()
	if v4 == "" {
		t.Skip("no v4 xdb fixture available")
	}
	dir := t.TempDir()
	v6 := filepath.Join(dir, "ip2region_v6.xdb")
	writeV6FixtureXDB(t, v6, defaultV6Fixtures(t))
	key := v4 + "\x00" + v6
	t.Cleanup(func() { delete(geoipSharedSearchers, key) })

	s1, err := sharedGeoIPSearcher(v4, v6)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	s2, err := sharedGeoIPSearcher(v4, v6)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if s1 != s2 {
		t.Fatal("same paths must share one searcher instance")
	}
	// 换库（内容/mtime 变化）→ 下一次获取必须重建（实例指针变化）。
	if err := os.Chtimes(v6, timeNowPlusSecond(), timeNowPlusSecond()); err != nil {
		t.Fatal(err)
	}
	s3, err := sharedGeoIPSearcher(v4, v6)
	if err != nil {
		t.Fatalf("rebuild acquire: %v", err)
	}
	if s3 == s1 {
		t.Fatal("v6 form change must rebuild the shared searcher")
	}
}

func timeNowPlusSecond() time.Time { return time.Now().Add(2 * time.Second) }
