package handlers

import "testing"

// 省级/国家级质心表方向守卫（第 77 轮主审发现：省级表曾按 {lat,lon} 编写而
// 消费端按 {lon,lat} 取值——国内 detect 的经纬度互换，lat>90 物理非法）。
// 约定：两表一律 {lon,lat}；lat 越界即表方向被改反。
func TestThreatScreenCentroids_DirectionGuard(t *testing.T) {
	for name, c := range threatScreenProvinceCentroids {
		lat := c[1]
		if lat < -90 || lat > 90 {
			t.Fatalf("省级质心 %s lat=%v 越界（表方向疑被改反，约定 {lon,lat}）", name, lat)
		}
	}
	for name, c := range threatScreenCountryCentroids {
		lat := c[1]
		if lat < -90 || lat > 90 {
			t.Fatalf("国家级质心 %s lat=%v 越界（表方向疑被改反，约定 {lon,lat}）", name, lat)
		}
	}
	// 抽样语义锚：陕西 lon≈108.87 lat≈35.19（西安）
	if c := threatScreenProvinceCentroids["陕西"]; c[0] < 108 || c[0] > 109 || c[1] < 35 || c[1] > 36 {
		t.Fatalf("陕西质心方向错误: got {lon:%v, lat:%v}, want ≈{108.87, 35.19}", c[0], c[1])
	}
}
