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
func GetIP2RegionProvinces() []string {
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
				prov := strings.TrimSpace(fields[1])
				if prov != "" && prov != "0" {
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

// GetIP2RegionProvinceList 返回省份列表，live searcher 优先、缓存兜底：校验端
// （ValidateGeoIPCountries）与 UI 列表端（GetIP2RegionRegions）共用同一口径，
// 避免带外替换 xdb 后缓存陈旧导致两端分叉。ip2region 未加载且无缓存时仅返回
// ["海外"]（len<=1 即表示不可用）。
func GetIP2RegionProvinceList() []string {
	provinces := GetIP2RegionProvinces()
	if len(provinces) <= 1 {
		provinces = GetCachedProvinces()
	}
	return provinces
}
