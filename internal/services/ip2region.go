package services

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"lazy-balancer-v2/internal/db"

	ip2regionService "github.com/lionsoul2014/ip2region/binding/golang/service"
)

// GeoIP database locations. Vars rather than constants so tests can point
// them at fixtures; production uses the container layout.
var (
	ip2regionLivePath = "/app/data/ip2region.xdb"
	ip2regionDistPath = "/app/waf.dist/ip2region.xdb"
)

var (
	ip2regionMu       sync.RWMutex
	ip2regionSearcher *ip2regionService.Ip2Region
	// ip2regionSearchMu serializes Search calls: the xdb Searcher writes its
	// ioCount diagnostics field on every search and is not race-safe for
	// concurrent searches, even in BufferCache mode.
	ip2regionSearchMu sync.Mutex
)

// InitIP2Region loads the GeoIP database into the singleton searcher using
// BufferCache mode (whole xdb in memory, zero-contention reads). The live
// xdb wins when present; otherwise the bundled distribution copy is copied
// into the live path first. A missing xdb is not fatal: Lookup returns an
// empty country code until one is installed.
func InitIP2Region() {
	if _, err := os.Stat(ip2regionLivePath); err != nil {
		if _, distErr := os.Stat(ip2regionDistPath); distErr != nil {
			log.Printf("ip2region: no xdb found at %s or %s; GeoIP lookups return empty", ip2regionLivePath, ip2regionDistPath)
			return
		}
		if err := copyFile(ip2regionDistPath, ip2regionLivePath); err != nil {
			log.Printf("ip2region: failed to copy %s to %s: %v", ip2regionDistPath, ip2regionLivePath, err)
			return
		}
	}
	searcher, err := openIP2RegionSearcher(ip2regionLivePath)
	if err != nil {
		log.Printf("ip2region: failed to load %s: %v", ip2regionLivePath, err)
		return
	}
	ip2regionMu.Lock()
	swapIP2RegionSearcher(searcher)
	ip2regionMu.Unlock()

	cachePath := ip2regionLivePath + ".provinces.json"
	if _, err := os.Stat(cachePath); err != nil {
		provinces := GetIP2RegionProvinces()
		if data, mErr := json.Marshal(provinces); mErr == nil {
			writeProvincesCache(cachePath, data)
		}
	}
	// R72 二十三次：省→市树缓存（首次装载或缺失时全量扫描重建）。
	// R72 二十四次：缓存含 ASCII 城市/省名（拼音规范化前的旧产物）也视为过期
	// 重建——升级部署后旧缓存不会自动消失。
	if staleRegionTreeCache(ip2RegionLivePathForTreeCache()) {
		writeRegionTreeCache(regionTreeFromXDB(ip2regionLivePath))
	}
	log.Printf("ip2region: loaded %s", ip2regionLivePath)
}

// Reload hot-swaps the singleton searcher from the live xdb path. The
// previous searcher stays in service if the new file cannot be loaded; the
// open failure is returned so update/rollback callers can treat a failed
// hot-swap as a failed install/restore level instead of silently diverging
// memory from disk (R46 B-F1).
func Reload() error {
	searcher, err := openIP2RegionSearcher(ip2regionLivePath)
	if err != nil {
		log.Printf("ip2region: reload failed: %v (keeping current searcher)", err)
		return err
	}
	ip2regionMu.Lock()
	swapIP2RegionSearcher(searcher)
	ip2regionMu.Unlock()
	return nil
}

// reloadIP2RegionSearcher 是测试 seam（镜像 crsinstall.go 的 osRename）：
// 更新/回滚管线经它调用 Reload，测试可注入内存热换失败。
var reloadIP2RegionSearcher = Reload

// swapIP2RegionSearcher installs the new searcher and closes the old one.
// Callers must hold ip2regionMu. Closing happens under ip2regionSearchMu so a
// concurrent in-flight Search on the retired instance is serialized against
// Close instead of racing it.
func swapIP2RegionSearcher(searcher *ip2regionService.Ip2Region) {
	old := ip2regionSearcher
	ip2regionSearcher = searcher
	if old != nil {
		ip2regionSearchMu.Lock()
		old.Close()
		ip2regionSearchMu.Unlock()
	}
}

// Lookup returns the alpha-2 country code for the given IP address, or ""
// when no database is loaded, the IP is unknown, or the region string
// cannot be parsed.
func Lookup(ip string) string {
	ip2regionMu.RLock()
	searcher := ip2regionSearcher
	ip2regionMu.RUnlock()
	if searcher == nil {
		return ""
	}
	ip2regionSearchMu.Lock()
	region, err := searcher.Search(ip)
	ip2regionSearchMu.Unlock()
	if err != nil {
		return ""
	}
	return parseCountryCode(region)
}

// parseCountryCode extracts the alpha-2 country code stored in the fifth
// pipe-separated field of an ip2region region string.
func parseCountryCode(region string) string {
	fields := strings.Split(region, "|")
	if len(fields) < 5 {
		return ""
	}
	return fields[4]
}

// GetIP2RegionVersion returns the installed GeoIP database version, or ""
// when the version row is unavailable.
func GetIP2RegionVersion() string {
	var version string
	if err := db.DB.QueryRow("SELECT version FROM security_ip2region_version WHERE id=1").Scan(&version); err != nil {
		return ""
	}
	return version
}

// SetIP2RegionVersion records the installed GeoIP database version and caches provinces.
func SetIP2RegionVersion(version string) {
	if _, err := db.DB.Exec(`INSERT INTO security_ip2region_version (id, version, updated_at, auto_update)
		VALUES (1, ?, datetime('now'), 0)
		ON CONFLICT(id) DO UPDATE SET version=excluded.version, updated_at=excluded.updated_at`, version); err != nil {
		log.Printf("ip2region: failed to store version %q: %v", version, err)
	}
	provinces := GetIP2RegionProvinces()
	if data, err := json.Marshal(provinces); err == nil {
		writeProvincesCache(ip2regionLivePath+".provinces.json", data)
	}
	// R72 二十三次：版本更新即新库——树缓存同步重建。
	writeRegionTreeCache(regionTreeFromXDB(ip2regionLivePath))
}

// writeProvincesCache atomically writes the province JSON cache by writing to a
// temporary file then renaming, so concurrent readers never see a partial file.
func writeProvincesCache(path string, data []byte) {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return
	}
	os.Rename(tmpPath, path)
}

// GetCachedProvinces returns the province list from the JSON cache file,
// falling back to a live lookup if the cache is missing or stale.
func GetCachedProvinces() []string {
	data, err := os.ReadFile(ip2regionLivePath + ".provinces.json")
	if err != nil {
		return GetIP2RegionProvinces()
	}
	var provinces []string
	if err := json.Unmarshal(data, &provinces); err != nil {
		return GetIP2RegionProvinces()
	}
	return provinces
}

// openIP2RegionSearcher opens the xdb at path with the whole file buffered
// in memory for concurrent read safety.
func openIP2RegionSearcher(path string) (*ip2regionService.Ip2Region, error) {
	config, err := ip2regionService.NewV4Config(ip2regionService.BufferCache, path, 1)
	if err != nil {
		return nil, err
	}
	return ip2regionService.NewIp2Region(config, nil)
}

func GetIP2RegionEntryCount() int {
	ip2regionMu.RLock()
	defer ip2regionMu.RUnlock()
	f, err := os.Open(ip2regionLivePath)
	if err != nil {
		return 0
	}
	defer f.Close()
	var minPtr, maxPtr uint32
	cell := make([]byte, 8)
	for i := 0; i < 65536; i++ {
		if _, err := f.ReadAt(cell, int64(8+i*8)); err != nil {
			break
		}
		s := binary.LittleEndian.Uint32(cell[0:4])
		e := binary.LittleEndian.Uint32(cell[4:8])
		if s == 0 && e == 0 {
			continue
		}
		if minPtr == 0 || s < minPtr {
			minPtr = s
		}
		if e > maxPtr {
			maxPtr = e
		}
	}
	if maxPtr <= minPtr {
		return 0
	}
	return int((maxPtr-minPtr)/14) + 1
}

// GetIP2RegionProvinces returns the province list from the live searcher, or
// ["海外"] when no database is loaded.
// ip2RegionLiveProvincesOverride 仅供测试注入「live 已装载」形态（模拟 xdb
// 在位），生产代码不设置。nil 时走真实 searcher 路径。
var ip2RegionLiveProvincesOverride []string

// SetIP2RegionLiveProvincesForTest 注入/清除测试用 live 省份列表。
func SetIP2RegionLiveProvincesForTest(provinces []string) {
	ip2RegionLiveProvincesOverride = provinces
}

func GetIP2RegionProvinces() []string {
	if ip2RegionLiveProvincesOverride != nil {
		return ip2RegionLiveProvincesOverride
	}
	ip2regionMu.RLock()
	searcher := ip2regionSearcher
	ip2regionMu.RUnlock()
	if searcher == nil {
		return []string{"海外"}
	}
	ip2regionSearchMu.Lock()
	defer ip2regionSearchMu.Unlock()
	chineseBlocks := []int{1, 14, 27, 36, 39, 42, 49, 58, 59, 60, 61, 101, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 139, 175, 180, 182, 183, 202, 210, 211, 218, 219, 220, 221, 222, 223}
	seen := make(map[string]bool)
	for _, b := range chineseBlocks {
		for _, sub := range []int{0, 32, 64, 96, 128, 160, 192, 224} {
			ip := fmt.Sprintf("%d.%d.1.1", b, sub)
			region, err := searcher.Search(ip)
			if err != nil {
				continue
			}
			fields := strings.Split(region, "|")
			if len(fields) >= 2 && fields[0] == "中国" {
				// R72 二十三次：采样列表与地域树同款规范化（normalizeIP2Province），
				// 消除双形态省名（上海/上海市）在同一列表中重复出现。
				prov := normalizeIP2Province(fields[1])
				if prov != "" {
					seen[prov] = true
				}
			}
		}
	}
	result := make([]string, 0, len(seen)+1)
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	result = append(result, "海外")
	return result
}

// GetIP2RegionProvinceList 返回省份列表，live searcher 优先、缓存兜底：仅供
// UI 列表端（GetIP2RegionRegions）——校验端（ValidateGeoIPCountries）R57 B-#1
// 起改用 live-only 的 GetIP2RegionProvinces 判 loaded，避免 xdb 失效后缓存
// 放行而发射端静默零强制。ip2region 未加载且无缓存时仅返回 ["海外"]。
func GetIP2RegionProvinceList() []string {
	provinces := GetIP2RegionProvinces()
	if len(provinces) <= 1 {
		provinces = GetCachedProvinces()
	}
	return provinces
}

// ip2ProvinceAliases 省列别名规范化（R72 二十三次）：xdb 原始省列存在双形态
// （上海/上海市、广西/广西壮族自治区）、台湾城市误入省列（台中市等）与个别
// 乱码（UEruemqi）。选项树与 CEL 发射变量（caddygeoip 同款表，见
// caddygeoip/handler.go 的 sync 注释）统一用规范名，两边一致才能命中。
// treeCacheRevision 地域树缓存修订号——规范化规则（映射/别名/结构）变更时
// 递增，旧缓存据此判定过期重建。ASCII 残留探测只能发现「缓存里有脏数据」，
// 发现不了「该有而没有」的条目（如 r25 前整段被丢的 新疆/乌鲁木齐市）。
const treeCacheRevision = "r25"

var ip2ProvinceAliases = map[string]string{
	// v3.17.0 段 (UEruemqi, Wulumuqi)：省列是城市名 Ürümqi 的乱码转写、城市列
	// 拼音已可映射——别名把该段回收为 新疆维吾尔自治区/乌鲁木齐市（此前整段
	// 被丢弃，树缺这对省市）。发射侧 provinceAliases 同步。
	"UEruemqi": "新疆维吾尔自治区",
	"北京":       "北京市", "上海市": "上海市", "上海": "上海市", "天津市": "天津市", "天津": "天津市",
	"重庆市": "重庆市", "重庆": "重庆市",
	"广西壮族自治区": "广西壮族自治区", "广西": "广西壮族自治区",
	"内蒙古自治区": "内蒙古自治区", "内蒙古": "内蒙古自治区",
	"西藏自治区": "西藏自治区", "西藏": "西藏自治区",
	"宁夏回族自治区": "宁夏回族自治区", "宁夏": "宁夏回族自治区",
	"新疆维吾尔自治区": "新疆维吾尔自治区", "新疆": "新疆维吾尔自治区",
	"台湾省": "台湾省", "台湾": "台湾省",
	"香港特别行政区": "香港特别行政区", "澳门特别行政区": "澳门特别行政区",
}

// ip2TaiwanCities 台湾地区在 xdb 中误置于省列的城市——归入台湾省城市集。
var ip2TaiwanCities = map[string]bool{
	"台北市": true, "新北市": true, "台中市": true, "台南市": true, "高雄市": true,
	"基隆市": true, "新竹市": true, "嘉义市": true, "新竹县": true, "彰化县": true,
	"桃园市": true, "云林县": true, "苗栗县": true,
}

// normalizeIP2Province 把 xdb 省列原始值规范化为规范省名：别名表归一（上海→
// 上海市）、带「省」后缀原样通过；其余候选（精简 fixture 的「广东」、潜在非
// 标准库形态）保守通过——只有明确误置形态（台湾城市）返回空（由调用方归入
// 台湾省城市集），乱码由选项树按去重自然呈现但不会与规范名冲突。
func normalizeIP2Province(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "0" {
		return ""
	}
	if canonical, ok := ip2ProvinceAliases[trimmed]; ok {
		return canonical
	}
	if ip2TaiwanCities[trimmed] {
		return ""
	}
	// ASCII 省名是乱码/拼音残片（如 UEruemqi），xdb 中文省列恒为多字节——
	// 过滤（城市级拼音由 normalizeIP2City 映射表处理，省级无可靠映射）。
	if trimmed[0] < 0x80 {
		return ""
	}
	return trimmed
}

// ip2PinyinCityFixes xdb 部分段的城市列为拼音/英文形态（v3.17.0 实测 45 条，
// 如 Guangzhou Shi/Shanghai/Taipei City）——映射为规范中文名；不在此表的
// ASCII 城市直接过滤（宁缺勿乱，无法可靠音译）。R72 二十五次起发射侧
// （caddygeoip normalizeCity）用同款表同步映射——城市级 CEL 规则对拼音段
// 可命中，两侧表修改需同步。
var ip2PinyinCityFixes = map[string]string{
	"Wulumuqi": "乌鲁木齐市", "Shanghai": "上海市", "Beijing": "北京市",
	"Fengyuan": "丰原市", "Taipei City": "台北市", "Zhongli District": "中坜区",
	"Changchun Shi": "长春市", "Chengdu Shi": "成都市", "Tianjin": "天津市",
	"Fuyang Shi": "阜阳市", "Hefei Shi": "合肥市", "Heze Shi": "菏泽市",
	"Jining Shi": "济宁市", "Linyi Xian": "临沂县", "Weifang Shi": "潍坊市",
	"Dongguan Shi": "东莞市", "Foshan Shi": "佛山市", "Guangzhou Shi": "广州市",
	"Maoming Shi": "茂名市", "Shenzhen": "深圳市", "Zhuhai Shi": "珠海市",
	"Nanning Shi": "南宁市", "Nanjing Shi": "南京市", "Nantong Shi": "南通市",
	"Tongshan": "铜山区", "Yancheng Shi": "盐城市", "Ganzhou Shi": "赣州市",
	"Baoding Shi": "保定市", "Hanshan Qu": "含山区", "Langfang Shi": "廊坊市",
	"Shijiazhuang Shi": "石家庄市", "Nanyang Shi": "南阳市", "Zhengzhou Shi": "郑州市",
	"Zhoukou Shi": "周口市", "Zhumadian Shi": "驻马店市", "Ningbo Shi": "宁波市",
	"Wuhan Shi": "武汉市", "Xiangyang": "襄阳市", "Changsha Shi": "长沙市",
	"Hengyang Xian": "衡阳县", "Shenyang Shi": "沈阳市", "Chongqing": "重庆市",
	"Guozhen": "郭镇", "Xi'an Shi": "西安市", "Kowloon": "九龙",
}

// normalizeIP2City 规范城市列：拼音映射为中文；无法映射的 ASCII 城市返回空
// （过滤）。中文城市原样通过。
func normalizeIP2City(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "0" {
		return ""
	}
	if fixed, ok := ip2PinyinCityFixes[trimmed]; ok {
		return fixed
	}
	if trimmed[0] < 0x80 {
		return "" // 未映射的拼音/英文段
	}
	return trimmed
}

// IP2RegionRegionTree 地域树（R72 二十三次，用户裁决：区域精确到市）：省级
// 列表 + 省→城市集映射，海外统一定为一级条目（不细分国家）。数据源为 xdb
// 段索引全量扫描（每段 14B：startIP 4 + endIP 4 + dataLen 2 + dataPtr 4），
// region 数据按 dataPtr 去重读取（大量段共享同一 region 指针，实际读取量为
// 唯一 region 数，远小于 77.5 万段）。
type IP2RegionRegionTree struct {
	Revision  string              `json:"revision,omitempty"`
	Provinces []string            `json:"provinces"`
	Cities    map[string][]string `json:"cities"`
	// DroppedASCIIProvinces / DroppedASCIICities：扫描中因不在映射表而被过滤的
	// ASCII 省/城市段数（宁缺勿乱）。当前 v3.17.0 实测均为 0；未来 xdb 版本
	// 新增拼音/乱码段时计数 >0 并进重建日志——丢失可见而非静默。
	DroppedASCIIProvinces int `json:"dropped_ascii_provinces"`
	DroppedASCIICities    int `json:"dropped_ascii_cities"`
}

func regionTreeFromXDB(path string) *IP2RegionRegionTree {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	// 1) 段区范围从 header 读取（offset 8 StartIndexPtr / offset 12 EndIndexPtr，
	// v3 双栈布局：向量索引推导的范围起点会早于真实段区——把 header/向量区
	// 当段解析出乱码 region，实测 262148 < 真实 3365968）。
	var minPtr, maxPtr uint32
	header := make([]byte, 16)
	if _, err := f.ReadAt(header, 0); err == nil {
		minPtr = binary.LittleEndian.Uint32(header[8:12])
		maxPtr = binary.LittleEndian.Uint32(header[12:16])
	}
	if maxPtr <= minPtr {
		return nil
	}
	// 2) 遍历段索引，按 dataPtr 去重读 region。
	seg := make([]byte, 14)
	provinces := map[string]bool{}
	cities := map[string]map[string]bool{}
	var droppedASCIIProvinces, droppedASCIICities int
	seen := map[uint32]bool{}
	for ptr := minPtr; ptr <= maxPtr; ptr += 14 {
		if _, err := f.ReadAt(seg, int64(ptr)); err != nil {
			break
		}
		dataLen := int(binary.LittleEndian.Uint16(seg[8:10]))
		dataPtr := binary.LittleEndian.Uint32(seg[10:14])
		if dataLen == 0 || seen[dataPtr] {
			continue
		}
		seen[dataPtr] = true
		region := make([]byte, dataLen)
		if _, err := f.ReadAt(region, int64(dataPtr)); err != nil {
			continue
		}
		fields := strings.Split(string(region), "|")
		if len(fields) < 3 {
			continue
		}
		if strings.TrimSpace(fields[0]) != "中国" {
			continue // 海外统一一级条目，不细分
		}
		prov := normalizeIP2Province(fields[1])
		if prov == "" {
			// 台湾城市误入省列：归入台湾省城市集（其省列值即城市名）。
			rawProv := strings.TrimSpace(fields[1])
			if ip2TaiwanCities[rawProv] {
				provinces["台湾省"] = true
				set := cities["台湾省"]
				if set == nil {
					set = map[string]bool{}
					cities["台湾省"] = set
				}
				set[rawProv] = true
			}
			// ASCII 省名（乱码/拼音残片，如旧版 UEruemqi）过滤计数。
			if rawProv != "" && rawProv != "0" && rawProv[0] < 0x80 {
				droppedASCIIProvinces++
			}
			continue
		}
		provinces[prov] = true
		city := normalizeIP2City(fields[2])
		if city == "" {
			// 未映射 ASCII 城市（宁缺勿乱）计数——提醒未来版本补映射表。
			if rawCity := strings.TrimSpace(fields[2]); rawCity != "" && rawCity != "0" && rawCity[0] < 0x80 {
				droppedASCIICities++
			}
			continue
		}
		set := cities[prov]
		if set == nil {
			set = map[string]bool{}
			cities[prov] = set
		}
		set[city] = true
	}
	if len(provinces) == 0 {
		return nil
	}
	tree := &IP2RegionRegionTree{
		Revision:              treeCacheRevision,
		Provinces:             make([]string, 0, len(provinces)+1),
		Cities:                make(map[string][]string, len(cities)),
		DroppedASCIIProvinces: droppedASCIIProvinces,
		DroppedASCIICities:    droppedASCIICities,
	}
	for prov := range provinces {
		tree.Provinces = append(tree.Provinces, prov)
	}
	sort.Strings(tree.Provinces)
	// 海外统一为一级条目（用户裁决：不区分国家/省市），固定末位——「海外」
	// 的 UTF-8 字节序落在中文省名中间，参与排序会插在省份列表中间；校验端
	// known 集合不依赖顺序，选项树展示与采样列表口径一致（海外恒在最后）。
	tree.Provinces = append(tree.Provinces, "海外")
	for prov, set := range cities {
		list := make([]string, 0, len(set))
		for city := range set {
			list = append(list, city)
		}
		sort.Strings(list)
		tree.Cities[prov] = list
	}
	return tree
}

// GetIP2RegionRegionTree 返回地域树：live 扫描优先，文件缓存兜底（与省份
// 列表同口径——searcher 加载失败时 UI 仍能展示上次成功的树）。
func GetIP2RegionRegionTree() *IP2RegionRegionTree {
	if tree := regionTreeFromXDB(ip2regionLivePath); tree != nil {
		return tree
	}
	return getCachedRegionTree()
}

func getCachedRegionTree() *IP2RegionRegionTree {
	data, err := os.ReadFile(ip2RegionLivePathForTreeCache())
	if err != nil {
		return nil
	}
	var tree IP2RegionRegionTree
	if err := json.Unmarshal(data, &tree); err != nil {
		return nil
	}
	return &tree
}

func ip2RegionLivePathForTreeCache() string { return ip2regionLivePath + ".regions.json" }

// staleRegionTreeCache 缓存过期判定：缺失、解析失败，或仍含 ASCII 城市/
// 省名（拼音规范化落地前的旧产物；「海外」除外）。
func staleRegionTreeCache(path string) bool {
	tree := getCachedRegionTree()
	if tree == nil {
		return true
	}
	if tree.Revision != treeCacheRevision {
		return true
	}
	for _, prov := range tree.Provinces {
		if prov != "海外" && prov[0] < 0x80 {
			return true
		}
	}
	for _, cities := range tree.Cities {
		for _, city := range cities {
			if city[0] < 0x80 {
				return true
			}
		}
	}
	return false
}

// writeRegionTreeCache 原子写树缓存（在库装载/更新成功时调用）。留 INFO 更新
// 日志（R72 二十四次）：缓存是派生数据不进审计，但静默重建会让「选项树何时
// 变化」在排障时不可见。
func writeRegionTreeCache(tree *IP2RegionRegionTree) {
	if tree == nil {
		return
	}
	data, err := json.Marshal(tree)
	if err != nil {
		return
	}
	writeProvincesCache(ip2RegionLivePathForTreeCache(), data)
	cityTotal := 0
	for _, cities := range tree.Cities {
		cityTotal += len(cities)
	}
	writeIP2RegionUpdateLog("INFO", "idle", fmt.Sprintf("地域树缓存已重建：%d 省级 / %d 城市（未映射 ASCII 段已过滤：省 %d / 城市 %d）", len(tree.Provinces), cityTotal, tree.DroppedASCIIProvinces, tree.DroppedASCIICities))
}
