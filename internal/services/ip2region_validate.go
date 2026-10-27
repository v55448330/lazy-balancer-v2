package services

import "fmt"

// ResetIP2RegionSearcherForTest 清空全局 ip2region searcher（仅测试使用）。
// 导入落盘实测会经 Reload 装载真实 xdb——测试结束后必须复位，
// 否则「未装载 GeoIP」形态的用例（GeoIP 空结果/保留地址口径）会串扰。
// 生产代码禁止调用。
func ResetIP2RegionSearcherForTest() {
	ip2regionMu.Lock()
	swapIP2RegionSearcher(nil, "")
	ip2regionMu.Unlock()
}

// ValidateIP2RegionFile 验证一份 xdb 文件能否被 ip2region 装载。
//
// 备份导入（lbbak）在落盘前必须用与运行时同一条打开路径（
// openValidatedIP2RegionSearcher，BufferCache 全量读入 + 探针搜索）验证文件：此前导入链只校验
// manifest sha256（完整性≠可装载性），坏 xdb 落盘后 Reload 失败、内存继续用
// 旧库而磁盘/版本记录已换——重启后 GeoIP 静默失效。失败即拒绝该条目并保留
// 本地文件（调用方负责版本记录同批丢弃）。
//
// 与 Reload/启动装载共用 openValidatedIP2RegionSearcher：结构门之外还做探针
// 搜索（段指针越界的文件结构门通过、真实搜索 panic——弱门会让坏文件落盘，
// 随后 Reload 装载成功、请求期 LookupRegion 崩溃）。
// 打开成功后立即 Close，不触碰全局 searcher（本函数只读探测）。
func ValidateIP2RegionFile(path string) error {
	searcher, err := openValidatedIP2RegionSearcher(path)
	if err != nil {
		return fmt.Errorf("ip2region 文件无法装载: %w", err)
	}
	if searcher != nil {
		searcher.Close()
	}
	return nil
}
