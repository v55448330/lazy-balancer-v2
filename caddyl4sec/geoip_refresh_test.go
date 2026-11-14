package caddyl4sec

// L4 GeoIP matcher 的共享 searcher 刷新契约：matcher 不得在 Provision 期钉死
// searcher 实例——换库（xdb rename，modTime/size 变化）后 Match 必须随共享
// 单例重建收敛到新库，无需 Caddy reload；缺库→恢复同样随采样收敛。
// 夹具=自构造结构 2.0/IPv4 xdb（14B 段索引），两版库对同一 IP 给不同归属，
// 断言面是真实 Match 判定翻转（不是实例指针比较）。

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeV4FixtureXDB 造单段 IPv4 xdb：region 覆盖 [start,end]。
func writeV4FixtureXDB(t *testing.T, path, start, end, region string) {
	t.Helper()
	const (
		headerSize      = 256
		vectorIndexSize = 256 * 256 * 8
		segmentSize     = 14
	)
	buf := make([]byte, headerSize+vectorIndexSize)
	regionPtr := uint32(len(buf))
	buf = append(buf, region...)
	blockPtr := uint32(len(buf))
	block := make([]byte, segmentSize)
	copy(block[0:4], net.ParseIP(start).To4())
	copy(block[4:8], net.ParseIP(end).To4())
	binary.LittleEndian.PutUint16(block[8:], uint16(len(region)))
	binary.LittleEndian.PutUint32(block[10:], regionPtr)
	buf = append(buf, block...)
	// 向量索引：start 的前两字节定位槽位。
	sip := net.ParseIP(start).To4()
	idx := headerSize + (int(sip[0])*256+int(sip[1]))*8
	binary.LittleEndian.PutUint32(buf[idx:], blockPtr)
	binary.LittleEndian.PutUint32(buf[idx+4:], blockPtr+segmentSize)
	binary.LittleEndian.PutUint16(buf[0:], 2) // Structure20
	binary.LittleEndian.PutUint16(buf[2:], 1) // VectorIndexPolicy
	binary.LittleEndian.PutUint32(buf[8:], blockPtr)
	binary.LittleEndian.PutUint32(buf[12:], blockPtr+segmentSize)
	binary.LittleEndian.PutUint16(buf[16:], 4) // IPv4
	binary.LittleEndian.PutUint16(buf[18:], 4)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
}

// TestL4GeoIPMatcher_refreshesSharedSearcherOnSwap 换库后 Match 判定必须翻转
// （旧库=中国不命中 deny「海外」；新库=United States 命中）。
func TestL4GeoIPMatcher_refreshesSharedSearcherOnSwap(t *testing.T) {
	dir := t.TempDir()
	xdb := filepath.Join(dir, "ip2region.xdb")
	writeV4FixtureXDB(t, xdb, "8.8.8.0", "8.8.8.255", "中国|0|0|0|CN")

	key := xdb + "\x00"
	resetSharedSearcherProbesForTest()
	sharedSearcherMu.Lock()
	delete(sharedSearchers, key)
	sharedSearcherMu.Unlock()
	t.Cleanup(func() {
		sharedSearcherMu.Lock()
		delete(sharedSearchers, key)
		sharedSearcherMu.Unlock()
		resetSharedSearcherProbesForTest()
	})
	// 旧实例延迟关闭拉到测试尺度外，避免 AfterFunc 干扰。
	oldDelay := sharedOldInstanceDelay
	sharedOldInstanceDelay = time.Hour
	t.Cleanup(func() { sharedOldInstanceDelay = oldDelay })

	m := newMatcherForTest(t, xdb, []string{"海外"})
	if got, err := m.Match(newTestConn("8.8.8.8")); err != nil || got {
		t.Fatalf("旧库（中国）deny 海外应放行: got=%v err=%v", got, err)
	}

	// When：换库（同路径 rename 新内容，modTime/size 变化）+ 探测窗口过界。
	writeV4FixtureXDB(t, xdb, "8.8.8.0", "8.8.8.255", "United States|California|0|Cloudflare|US")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(xdb, future, future); err != nil {
		t.Fatal(err)
	}
	resetSharedSearcherProbesForTest()

	// Then：无需重新 Provision，Match 随共享单例重建查新库。
	if got, err := m.Match(newTestConn("8.8.8.8")); err != nil || !got {
		t.Fatalf("换库后 deny 海外应断连（matcher 钉死旧实例则恒放行）: got=%v err=%v", got, err)
	}
}

// TestL4GeoIPMatcher_recoversAfterDatabaseAppears 缺库 Provision（fail-open）
// 后库文件就位：Match 必须随采样恢复判定，不得永久 fail-open。
func TestL4GeoIPMatcher_recoversAfterDatabaseAppears(t *testing.T) {
	dir := t.TempDir()
	xdb := filepath.Join(dir, "ip2region.xdb")

	key := xdb + "\x00"
	resetSharedSearcherProbesForTest()
	sharedSearcherMu.Lock()
	delete(sharedSearchers, key)
	sharedSearcherMu.Unlock()
	t.Cleanup(func() {
		sharedSearcherMu.Lock()
		delete(sharedSearchers, key)
		sharedSearcherMu.Unlock()
		resetSharedSearcherProbesForTest()
	})

	m := newMatcherForTest(t, xdb, []string{"海外"})
	if got, err := m.Match(newTestConn("8.8.8.8")); err != nil || got {
		t.Fatalf("缺库必须 fail-open: got=%v err=%v", got, err)
	}

	// When：库就位（探测缓存此前未落——v4 stat 失败不落缓存，下次采样实测）。
	writeV4FixtureXDB(t, xdb, "8.8.8.0", "8.8.8.255", "United States|California|0|Cloudflare|US")

	// Then：恢复判定。
	if got, err := m.Match(newTestConn("8.8.8.8")); err != nil || !got {
		t.Fatalf("库就位后应恢复判定（Provision 钉死 nil 则恒 fail-open）: got=%v err=%v", got, err)
	}
}
