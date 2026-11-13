package services

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"

	ip2regionService "github.com/lionsoul2014/ip2region/binding/golang/service"
)

// GeoIP database locations. Vars rather than constants so tests can point
// them at fixtures; production uses the container layout.
// defaultIP2RegionLivePath 与 caddygeoip 插件 Provision 的 xdb 兜底默认同值
// ——渲染侧仅在派生值不同于此默认时发射 xdb_path（字节稳定
// 裁定，见 buildGeoipHandler）。
const defaultIP2RegionLivePath = "/app/data/ip2region.xdb"

// defaultIP2RegionV6LivePath 是 IPv6 库的 live 路径出厂值（与 v4 同目录命名
// 后缀 _v6；镜像内置副本在 waf.dist 同名）。caddygeoip/caddyl4sec 插件对 v6
// 无路径兜底默认——空 = v6 关闭（渲染侧不发射 xdb_v6_path），因此 live 路径
// 恒由本包派生并显式发射，不存在「渲染省略键 + 插件读另一路径」的分叉形态。
const defaultIP2RegionV6LivePath = "/app/data/ip2region_v6.xdb"

var (
	ip2regionLivePath = defaultIP2RegionLivePath
	ip2regionDistPath = "/app/waf.dist/ip2region.xdb"
	// IPv6 库双路径（live 数据卷 / dist 镜像内置），与 v4 同生命周期：
	// 更新任务单任务双源安装、启动期 dist 播种、集群同步随 bundle 传播。
	ip2regionV6LivePath = defaultIP2RegionV6LivePath
	ip2regionV6DistPath = "/app/waf.dist/ip2region_v6.xdb"
)

var (
	ip2regionMu       sync.RWMutex
	ip2regionSearcher *ip2regionService.Ip2Region
	// ip2regionSearcherSource 是在役 searcher 的装载来源文件（swap 时记录，
	// nil 卸载清空；受 ip2regionMu 保护）。条目数展示必须与查询同源——在役
	// searcher 可能来自镜像内置库（只读降级）或热换失败后保留的旧库，与 live
	// 路径上的文件不是同一份。
	ip2regionSearcherSource string
	// ip2regionSearchMu serializes Search calls: the xdb Searcher writes its
	// ioCount diagnostics field on every search and is not race-safe for
	// concurrent searches, even in BufferCache mode.
	ip2regionSearchMu sync.Mutex
	// ip2regionGeneration 归属地库代际（0=从未加载；每次安装/热换 +1）。
	// 威胁大屏 rollup 据此判定历史空归属地维度是否值得重固。
	ip2regionGeneration atomic.Int64
)

// GeoIPDataGeneration 返回当前归属地库代际（0=库从未加载；每次启动加载/
// 更新热换递增）。纯读，供上层判断派生聚合是否需要按新库重算。
func GeoIPDataGeneration() int64 { return ip2regionGeneration.Load() }

// —— IPv6 库用户开关（security_ip2region_version.v6_enabled）——
//
// 语义：v6 关闭（默认）= HTTP 链对 IPv6 客户端维持既有「海外」fail-closed
// 哨兵、L4 链维持 fail-open 放行（两裁定不变，仅作用于不可解析形态）；v6
// 开启且库可用 = IPv6 客户端与 v4 同语义解析（海外精确到国家、国内精确到
// 省）。默认关闭是最小惊讶选择：开启会收窄既有策略的「海外」兜底面（HTTP
// deny 海外策略对真实中国 v6 客户端从拦截转为放行），属阻断语义变化，须由
// 用户显式决定。
func IsIP2RegionV6Enabled() bool {
	// 测试缝：非 nil 时直读（无 DB 的纯函数级用例；生产恒 nil）。
	if ip2RegionV6EnabledOverride != nil {
		return *ip2RegionV6EnabledOverride
	}
	if db.DB == nil {
		return false
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT COALESCE(v6_enabled,0) FROM security_ip2region_version WHERE id=1").Scan(&enabled); err != nil {
		// 行缺失/读故障按关闭处理（默认语义），故障留痕。
		if !errors.Is(err, sql.ErrNoRows) {
			Logf("warn", "ip2region: 读取 v6 开关失败，按关闭处理: %v", err)
		}
		return false
	}
	return enabled
}

// ip2RegionV6EnabledOverride 是 IsIP2RegionV6Enabled 的测试缝（nil=真实读）。
var ip2RegionV6EnabledOverride *bool

// SetIP2RegionV6Enabled 写入 v6 开关。行缺失时先播种（与 ensureIP2RegionVersionRow
// 同口径），写失败原样上抛由调用方定夺。
func SetIP2RegionV6Enabled(enabled bool) error {
	if db.DB == nil {
		return errors.New("数据库未初始化")
	}
	ensureIP2RegionVersionRow()
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET v6_enabled=?, v6_updated_at=datetime('now') WHERE id=1", enabled); err != nil {
		Logf("error", "ip2region: failed to store v6_enabled %v: %v", enabled, err)
		return err
	}
	return nil
}

// GetIP2RegionV6Version 返回已安装的 IPv6 库版本行（空=从未安装）。
func GetIP2RegionV6Version() (string, error) {
	if db.DB == nil {
		return "", errors.New("数据库未初始化")
	}
	var version string
	if err := db.DB.QueryRow("SELECT COALESCE(v6_version,'') FROM security_ip2region_version WHERE id=1").Scan(&version); err != nil {
		return "", err
	}
	return version, nil
}

// SetIP2RegionV6Version 记录 IPv6 库版本并重建地域树缓存（v6 段并入同一棵
// 树——选项树/校验端是 v4+v6 的并集口径）。
func SetIP2RegionV6Version(version string) error {
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET v6_version=?, v6_updated_at=datetime('now') WHERE id=1`, version); err != nil {
		Logf("error", "ip2region: failed to store v6 version %q: %v", version, err)
		return err
	}
	writeRegionTreeCache(regionTreeForSettings())
	return nil
}

// SetIP2RegionV6SourceStatus 记录更新任务里 v6 数据源的独立终态（success/
// failed + message）：单任务双源形态下 v6 失败不拖垮 v4 安装，两源状态分列
// 展示。写失败仅留痕（展示面损失，不反噬安装）。
func SetIP2RegionV6SourceStatus(status, message string) {
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET v6_update_status=?, v6_message=? WHERE id=1", status, message); err != nil {
		Logf("error", "ip2region: failed to store v6 source status %q: %v", status, err)
	}
}

// ip2RegionV6PathForAttach 返回面板 searcher 装载 v6 库的路径：关闭=空串；
// 开启时 live 优先、live 缺失回落 dist（只读降级节点以 dist 服务本地查询，
// 与 v4 同形）。dist 也缺失=空串（v6 关闭语义：查询回落哨兵）。
func ip2RegionV6PathForAttach() string {
	if !IsIP2RegionV6Enabled() {
		return ""
	}
	if _, err := os.Stat(ip2regionV6LivePath); err == nil {
		return ip2regionV6LivePath
	}
	if _, err := os.Stat(ip2regionV6DistPath); err == nil {
		return ip2regionV6DistPath
	}
	return ""
}

// ip2RegionStartupRepairWritesAllowed 启动期本地修复（版本行/.version sidecar
// 写入）是否允许执行：从节点的 IP 库文件与版本行都由集群同步治理，本地改写
// 会与主端声明打架并触发/延长整库漂移重拉（镜像 ReconcileCRSState 的显式
// 口径）。角色读故障按「不写」处理并留痕——角色不可证实时宁停勿写，由下次
// 启动或集群同步自愈。内存 searcher 装载/回退与审计不受此门约束（本地读面/
// 节点本地面）。
func ip2RegionStartupRepairWritesAllowed() bool {
	return wafFileStartupWritesAllowed("ip2region")
}

// loadIP2RegionDistReadOnly 以镜像内置库作只读降级装载——live 库缺失/不可
// 装载、且本节点不写（从节点/角色不可证实）或写 live 失败时的唯一安全降级
// 路径。返回 nil 表示镜像库也不可装载（调用方放弃本次装载，Lookup 返回空）。
// 只读语义由调用方置 readOnlyDist 承担（版本行/sidecar/派生缓存不落盘）：
// 主节点写 live 失败时只读装载不掩盖失败（ERROR 已先落），却让面板归属地与
// 库状态保持可用，与从节点分支同一形态。
func loadIP2RegionDistReadOnly(scene string) *ip2regionService.Ip2Region {
	s, err := openValidatedIP2RegionSearcher(ip2regionDistPath)
	if err != nil {
		Logf("error", "ip2region: %s，镜像内置库只读装载失败: %v", scene, err)
		return nil
	}
	Logf("warn", "ip2region: %s，以镜像内置库只读装载（不写 live/版本行，等待修复或集群同步）", scene)
	return s
}

// InitIP2Region loads the GeoIP database into the singleton searcher using
// BufferCache mode (whole xdb in memory, zero-contention reads). The live
// xdb wins when present; otherwise, on the master node, the bundled
// distribution copy is copied into the live path first. A missing xdb is not
// fatal: Lookup returns an empty country code until one is installed.
// 从节点/角色不可证实时以镜像内置库只读装载（不写 live 文件、版本行与
// 派生缓存）——文件由集群同步治理，见 ip2RegionStartupRepairWritesAllowed。
func InitIP2Region() {
	// 写入门一次性取值：live 文件替换、版本行/sidecar、派生缓存同口径——
	// 从节点的 IP 库文件与版本行都由集群同步治理，本地改写会与主端声明打架
	// （契约见 ip2RegionStartupRepairWritesAllowed）。非主节点/角色不可证实
	// 时以镜像内置库只读装载，绝不落盘 live。
	writesAllowed := ip2RegionStartupRepairWritesAllowed()
	readOnlyDist := false
	var searcher *ip2regionService.Ip2Region
	if _, err := os.Stat(ip2regionLivePath); err != nil {
		if _, distErr := os.Stat(ip2regionDistPath); distErr != nil {
			Logf("info", "ip2region: no xdb found at %s or %s; GeoIP lookups return empty", ip2regionLivePath, ip2regionDistPath)
			return
		}
		if !writesAllowed {
			// live 由集群同步治理，本地补齐会与主端声明打架并延长整库漂移
			// 重拉——只读装载镜像库供本地查询，文件/版本行/派生缓存一律不写。
			searcher = loadIP2RegionDistReadOnly("live 库缺失且非主节点（或角色不可证实）")
			if searcher == nil {
				return
			}
			readOnlyDist = true
			RecordAuditLog("system", "更新", "IP数据库", "启动时 live IP 库缺失且本节点非主节点，按镜像内置库只读装载（不覆盖 live 文件/版本行）", "")
		} else if err := copyFile(ip2regionDistPath, ip2regionLivePath); err != nil {
			// 主节点判定可写却写失败（/app/data 只读、磁盘满、权限变更）：
			// 与从节点分支同一降级——只读装载镜像库，面板归属地/库状态保持
			// 可用。写失败本身已 ERROR 留痕，降级不掩盖故障；live 缺失意味着
			// 数据面同样不可用，属待修复形态而非静默降级。
			Logf("error", "ip2region: failed to copy %s to %s: %v", ip2regionDistPath, ip2regionLivePath, err)
			searcher = loadIP2RegionDistReadOnly("主节点 live 库写入失败")
			if searcher == nil {
				return
			}
			readOnlyDist = true
			RecordAuditLog("system", "更新", "IP数据库", "启动时主节点 live IP 库写入失败，按镜像内置库只读装载（live 文件/版本行未写，GeoIP 库待修复）", "")
		}
	}
	if searcher == nil {
		loaded, err := openValidatedIP2RegionSearcher(ip2regionLivePath)
		if err != nil {
			Logf("error", "ip2region: failed to load %s: %v", ip2regionLivePath, err)
			// live 存在但不可装载（掉电半写/带外损坏）：旧行为直接放弃——
			// 面板归属地全空、渲染侧 size>0 仍照常发射 geoip 策略而 Caddy 侧
			// Provision 失败 pass-through，地域拦截静默失效且无自愈通道。
			// 回退镜像内置库（仅在装载失败时，不做任何版本优劣判断），
			// 版本行/sidecar 写保守标识 bundled 并记审计——回退必须可见，
			// 否则等于静默降级为旧库。
			if _, distErr := os.Stat(ip2regionDistPath); distErr == nil {
				if !writesAllowed {
					// 从节点同样不覆盖 live（集群同步自愈），只读装载镜像库。
					if searcher = loadIP2RegionDistReadOnly("损坏 live 库且非主节点（或角色不可证实）"); searcher != nil {
						readOnlyDist = true
						RecordAuditLog("system", "更新", "IP数据库", "启动检测到 IP 数据库文件损坏且本节点非主节点，按镜像内置库只读装载（不覆盖 live 文件/版本行）", "")
					}
				} else if cErr := copyFile(ip2regionDistPath, ip2regionLivePath); cErr != nil {
					// 主节点写 live 失败：与从节点分支同一只读降级（写失败已
					// ERROR 留痕），避免面板归属地全空而 live 仍是损坏文件。
					Logf("error", "ip2region: 损坏 live 库的 dist 回退拷贝失败: %v", cErr)
					if searcher = loadIP2RegionDistReadOnly("损坏 live 库且主节点回退拷贝失败"); searcher != nil {
						readOnlyDist = true
						RecordAuditLog("system", "更新", "IP数据库", "启动检测到 IP 数据库文件损坏且镜像库回退拷贝失败，按镜像内置库只读装载（live 文件/版本行未写，待修复）", "")
					}
				} else if fallback, oErr := openValidatedIP2RegionSearcher(ip2regionLivePath); oErr != nil {
					Logf("error", "ip2region: dist 回退库装载失败: %v", oErr)
				} else {
					searcher = fallback
					Logf("warn", "ip2region: 损坏的 live 库已回退为镜像内置库（标记 bundled，待下次成功更新自愈）")
					RecordAuditLog("system", "更新", "IP数据库", "启动检测到 IP 数据库文件损坏不可装载，已回退镜像内置库（待下次成功更新恢复）", "")
					// 版本行/sidecar 只在主节点写：从节点由集群同步治理（见
					// ip2RegionStartupRepairWritesAllowed）；审计照记（节点本地面）。
					if writesAllowed {
						if _, uErr := db.DB.Exec("UPDATE security_ip2region_version SET version='bundled', updated_at=datetime('now') WHERE id=1"); uErr != nil {
							Logf("error", "ip2region: 写入 dist 回退标识失败: %v", uErr)
						}
						if rErr := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", "bundled"); rErr != nil {
							Logf("error", "ip2region: 写入 dist 回退 sidecar 失败: %v", rErr)
						}
					}
					// dist 回退把 live 换成镜像旧库（内容代际变化）：树缓存有效性
					// 判据只看修订号/ASCII 残留，不参与内容代际比较——不显式重建会
					// 留下「新库的省市树」给在役旧库用（扫描失败时展示错误选项树）。
					// 与更新路径 SetIP2RegionVersion 的无条件重建口径对齐。
					writeRegionTreeCache(regionTreeForSettings())
				}
			}
			if searcher == nil {
				return
			}
		} else {
			searcher = loaded
		}
	}
	// 条目数展示的数据源与在役 searcher 同源：只读降级装载的是镜像内置库，
	// live 路径上的文件此时可能缺失/损坏（展示 0 或乱值会让运维误判库状态）。
	searcherSource := ip2regionLivePath
	if readOnlyDist {
		searcherSource = ip2regionDistPath
	}
	ip2regionMu.Lock()
	swapIP2RegionSearcher(searcher, searcherSource)
	ip2regionMu.Unlock()

	if readOnlyDist {
		// 只读装载形态：live 文件、版本行/sidecar、派生缓存均由主节点同步
		// 治理，本节点不落盘（等待 waf_files 同步收敛）。
		Logf("info", "ip2region: 以镜像内置库只读模式装载完成，文件/版本行/派生缓存不落盘")
		return
	}

	// 版本同步：xdb 文件存在但 DB 版本仍为种子值 'unknown' 时，从 .version
	// 伴生文件读取实际版本写回 DB；伴生文件缺失（清理/手工删除后仅 xdb 残留）
	// 则写 'bundled' 标记为镜像内置版本——消除 unknown+已最新 矛盾态。
	// 写入门与 CRS 同口径（从节点的文件与版本行由集群同步治理）；角色读故障
	// 按不写处理并留痕。
	if writesAllowed {
		// 只有「行缺失」或哨兵值才同步种子版本——读取故障（非
		// ErrNoRows）时保留原版本行并留痕，否则会把真实版本覆盖成 bundled
		// （版本溯源丢失、下次更新按哨兵重装）。
		current, verr := GetIP2RegionVersion()
		switch {
		case verr != nil && !errors.Is(verr, sql.ErrNoRows):
			Logf("warn", "ip2region: 读取版本行失败，保留原版本记录（不覆盖为哨兵值）: %v", verr)
		case current == "" || current == "unknown" || errors.Is(verr, sql.ErrNoRows):
			tag := "bundled"
			if raw, err := os.ReadFile(ip2regionLivePath + ".version"); err == nil {
				if v := sanitizeBundleVersion(strings.TrimSpace(string(raw))); v != "" {
					tag = v
				}
			}
			if err := SetIP2RegionVersion(tag); err != nil {
				Logf("warn", "ip2region: DB 版本种子值同步失败: %v", err)
			} else {
				Logf("info", "ip2region: DB 版本种子值已同步为 %s", tag)
			}
		}
	}

	// 派生缓存（省份列表/省→市树）同属写入门：从节点上它们由本地 live 推导，
	// 内容无正确性风险，但「文件/版本行/派生缓存一律不落盘」是本节点只读不变量
	// 的显式契约（见 ip2RegionStartupRepairWritesAllowed）——只在 readOnlyDist
	// 分支跳过会让「从节点 + live 可装载」形态成为契约例外，且本地派生文件会被
	// 排障误判为与主端不一致的本地状态。缺缓存时由 GetIP2RegionProvinces /
	// regionTreeFromXDB 在内存重建（进程内记忆化，成本一次性）。
	if writesAllowed {
		cachePath := ip2regionLivePath + ".provinces.json"
		if _, err := os.Stat(cachePath); err != nil {
			provinces := GetIP2RegionProvinces()
			if data, mErr := json.Marshal(provinces); mErr == nil {
				if err := writeProvincesCache(cachePath, data); err != nil {
					Logf("warn", "ip2region: 省份列表缓存落盘失败（下次启动重建）: %v", err)
				}
			}
		}
		// 省→市树缓存（首次装载或缺失时全量扫描重建）。
		// 缓存含 ASCII 城市/省名（拼音规范化前的旧产物）也视为过期
		// 重建——升级部署后旧缓存不会自动消失。
		if staleRegionTreeCache(ip2RegionLivePathForTreeCache()) {
			writeRegionTreeCache(regionTreeForSettings())
		}
	}
	// —— IPv6 库启动期播种（与 v4 同生命周期，写入门同口径）——
	// 开启时 live 缺失而镜像内置副本在位：主节点拷贝 dist→live（只读降级
	// 节点不落盘，attach 已按 dist 只读服务本地查询）。播种失败不致命——
	// openIP2RegionSearcherDual 的 v6 健康门会把缺失/损坏降级为「v6 禁用」
	// 哨兵语义，等待更新任务或集群同步自愈。
	if IsIP2RegionV6Enabled() && writesAllowed {
		if _, err := os.Stat(ip2regionV6LivePath); err != nil {
			if _, distErr := os.Stat(ip2regionV6DistPath); distErr == nil {
				if err := copyFile(ip2regionV6DistPath, ip2regionV6LivePath); err != nil {
					Logf("error", "ip2region: IPv6 库 dist 播种失败（待下次成功更新恢复）: %v", err)
				} else {
					Logf("info", "ip2region: IPv6 库已从镜像内置副本播种到 %s", ip2regionV6LivePath)
					RecordAuditLog("system", "更新", "IP数据库", "启动时 live IPv6 库缺失，已按镜像内置副本播种", "")
				}
			}
		}
		// v6 版本种子同步（与 v4 同形，仅行缺失/哨兵值时）：sidecar 缺失写
		// bundled——版本溯源保留「镜像内置」事实，下次数值 tag 可建立基线。
		if current, verr := GetIP2RegionV6Version(); verr == nil && (current == "" || current == "unknown") {
			tag := "bundled"
			if raw, err := os.ReadFile(ip2regionV6LivePath + ".version"); err == nil {
				if v := sanitizeBundleVersion(strings.TrimSpace(string(raw))); v != "" {
					tag = v
				}
			}
			if _, err := db.DB.Exec("UPDATE security_ip2region_version SET v6_version=? WHERE id=1", tag); err != nil {
				Logf("warn", "ip2region: v6 版本种子值同步失败: %v", err)
			}
		}
	}
	Logf("info", "ip2region: loaded %s", ip2regionLivePath)
}

// Reload hot-swaps the singleton searcher from the live xdb path. The
// previous searcher stays in service if the new file cannot be loaded; the
// open failure is returned so update/rollback callers can treat a failed
// hot-swap as a failed install/restore level instead of silently diverging
// memory from disk.
func Reload() error {
	searcher, err := openValidatedIP2RegionSearcher(ip2regionLivePath)
	if err != nil {
		Logf("error", "ip2region: reload failed: %v (keeping current searcher)", err)
		return err
	}
	return installValidatedIP2RegionSearcher(searcher, ip2regionLivePath)
}

// installValidatedIP2RegionSearcher 接管已校验 searcher 的所有权并原子热换。
func installValidatedIP2RegionSearcher(searcher *ip2regionService.Ip2Region, sourcePath string) error {
	if searcher == nil {
		return errors.New("不能热换空 IP2Region searcher")
	}
	ip2regionMu.Lock()
	swapIP2RegionSearcher(searcher, sourcePath)
	ip2regionMu.Unlock()
	return nil
}

// reloadIP2RegionSearcher 是更新/回滚的热换缝：调用方已完成统一校验，
// 成功时由本函数接管 searcher，失败时调用方负责 Close。
var reloadIP2RegionSearcher = func(searcher *ip2regionService.Ip2Region) error {
	return installValidatedIP2RegionSearcher(searcher, ip2regionLivePath)
}

// swapIP2RegionSearcher installs the new searcher and closes the old one.
// Callers must hold ip2regionMu. Closing happens under ip2regionSearchMu so a
// concurrent in-flight Search on the retired instance is serialized against
// Close instead of racing it.
func swapIP2RegionSearcher(searcher *ip2regionService.Ip2Region, sourcePath string) {
	old := ip2regionSearcher
	ip2regionSearcher = searcher
	if searcher == nil {
		sourcePath = ""
	}
	ip2regionSearcherSource = sourcePath
	ip2regionGeneration.Add(1)
	if old != nil {
		ip2regionSearchMu.Lock()
		old.Close()
		ip2regionSearchMu.Unlock()
	}
}

// Lookup returns the alpha-2 country code for the given IP address, or ""
// when no database is loaded, the IP is unknown, or the region string
// cannot be parsed.：取锁+搜索序列委托 LookupRegion
// 单点，本函数只做第五段解析。
func Lookup(ip string) string {
	return parseCountryCode(LookupRegion(ip))
}

// LookupRegion returns the raw pipe-separated region string for the IP
// ("国家|省|市|ISP|国家代码"，如 "中国|广东省|深圳市|电信|CN")，or "" when no
// database is loaded, the IP cannot be resolved, or the search fails. Search
// runs under the same serialization lock as Lookup; display formatting is the
// caller's concern.
func LookupRegion(ip string) string {
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
	return region
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

// GetIP2RegionVersion returns the installed GeoIP database version.
// 读故障与「行缺失」必须可区分——调用方（InitIP2Region）只对
// ErrNoRows 走种子同步，真实 DB 故障不得折叠成空串后覆盖版本行。
// db.DB 为 nil（半初始化/单测）同样视为不可读错误。
func GetIP2RegionVersion() (string, error) {
	if db.DB == nil {
		return "", errors.New("数据库未初始化")
	}
	var version string
	if err := db.DB.QueryRow("SELECT version FROM security_ip2region_version WHERE id=1").Scan(&version); err != nil {
		return "", err
	}
	return version, nil
}

// SetIP2RegionVersion records the installed GeoIP database version and caches provinces.
func SetIP2RegionVersion(version string) error {
	// 插入不写 auto_update——沿用 schema DEFAULT TRUE（与迁移播种
	// ensureIP2RegionVersionRow 的 TRUE、用户裁定一致）；硬编码 0 会让
	// 「行缺失 + Init 先跑」形态静默关闭自动更新。
	if _, err := db.DB.Exec(`INSERT INTO security_ip2region_version (id, version, updated_at)
		VALUES (1, ?, datetime('now'))
		ON CONFLICT(id) DO UPDATE SET version=excluded.version, updated_at=excluded.updated_at`, version); err != nil {
		Logf("error", "ip2region: failed to store version %q: %v", version, err)
		return err
	}
	provinces := GetIP2RegionProvinces()
	if data, err := json.Marshal(provinces); err == nil {
		if err := writeProvincesCache(ip2regionLivePath+".provinces.json", data); err != nil {
			Logf("warn", "ip2region: 省份列表缓存落盘失败（下次重建）: %v", err)
		}
	}
	// 版本更新即新库——树缓存同步重建（v6 启用时为 v4+v6 并集）。
	writeRegionTreeCache(regionTreeForSettings())
	return nil
}

// writeProvincesCache atomically writes the province JSON cache by writing to a
// temporary file then renaming, so concurrent readers never see a partial file.
// 写/换名错误沿返回值上抛——此前静默吞错，调用点
// 无从留痕。改用单源原子落盘（tmp+fsync+父目录 fsync）。
func writeProvincesCache(path string, data []byte) error {
	return writeFileAtomicSynced(path, data, 0644)
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

// xdb v4/v6 文件布局（绑定库 xdb/header.go、version.go 锚定 structure
// 2.0/3.0 形态）：256B 头 + 256*256*8B 向量索引 + 数据区 + 段索引区；头内
// [8:12]/[12:16] 为段索引区首/末段起点指针。段索引条目 v4=14B（startIP 4 +
// endIP 4 + dataLen 2 + dataPtr 4，IP 为小端反转比较），v6=38B（16+16+2+4，
// IP 为大端字节序比较）；向量索引两族同形（按 IP 前两字节键入）。BufferCache
// 打开路径对内容缓冲区做无边界切片（向量索引/段索引/region 读取），头部完好
// 的截断文件能通过装载却在首次搜索时进程级 panic——打开前必须先过结构自检门。
const (
	ip2RegionXDBHeaderSize      = 256
	ip2RegionXDBVectorIndexSize = 256 * 256 * 8
	ip2RegionXDBSegmentSize     = 14
	ip2RegionXDBSegmentSizeV6   = 38
	// xdbStructure20/30 是头 [0:2] 的结构版本号（xdb.Structure20/30 同值）：
	// 2.0 = 旧 v4 专属形态（[16:20] 无定义，实测为 0）；3.0 起双栈，[16:18]
	// 为 IP 版本（4/6）、[18:20] 为指针字节数。
	xdbStructure20 = 2
	xdbStructure30 = 3
)

// ip2RegionXDBLayout 从 20B 头判定文件布局：返回（段索引条目字节数, IP 版本）。
// 结构 2.0 → v4（旧库 [16:20] 为 0，不参与判定）；结构 3.0 → 按 [16:18] 分派
// 4/6。其余组合显式报错（含「v4 文件被换名到 v6 路径」的交叉形态——v6 侧
// 必须按 38B 解段索引，误用 14B 会把 v4 头指针当段起点扫出乱码树）。
func ip2RegionXDBLayout(header []byte) (segmentSize, ipVersion int, err error) {
	if len(header) < 20 {
		return 0, 0, fmt.Errorf("xdb 头不足 20 字节")
	}
	structure := binary.LittleEndian.Uint16(header[0:2])
	ipVer := int(binary.LittleEndian.Uint16(header[16:18]))
	switch structure {
	case xdbStructure20:
		if ipVer == 6 {
			return 0, 0, fmt.Errorf("xdb 结构 2.0 不支持 IPv6（头 ip_version=%d）", ipVer)
		}
		return ip2RegionXDBSegmentSize, 4, nil
	case xdbStructure30:
		switch ipVer {
		case 4:
			return ip2RegionXDBSegmentSize, 4, nil
		case 6:
			return ip2RegionXDBSegmentSizeV6, 6, nil
		default:
			return 0, 0, fmt.Errorf("xdb 头 ip_version 非法: %d", ipVer)
		}
	default:
		return 0, 0, fmt.Errorf("xdb 结构版本非法: %d", structure)
	}
}

// checkIP2RegionXDBStructure 结构自检门：最小尺寸（头+完整向量索引+至少
// 一段）+ 头内段索引指针边界（段索引区恒在向量索引之后、末段终点不越出
// 文件）+ 布局判定（结构版本/IP 版本交叉校验）。不满足即按「不可装载」
// 显式报错，绝不交给绑定库的无边界切片。
func checkIP2RegionXDBStructure(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat xdb: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open xdb: %w", err)
	}
	defer f.Close()
	header := make([]byte, 20)
	if _, err := f.ReadAt(header, 0); err != nil {
		return fmt.Errorf("read xdb header: %w", err)
	}
	segmentSize, _, err := ip2RegionXDBLayout(header)
	if err != nil {
		return fmt.Errorf("xdb 布局判定失败: %w", err)
	}
	minSize := int64(ip2RegionXDBHeaderSize + ip2RegionXDBVectorIndexSize + segmentSize)
	if fi.Size() < minSize {
		return fmt.Errorf("xdb 文件大小 %d 小于最小结构尺寸 %d（截断/残缺）", fi.Size(), minSize)
	}
	startPtr := binary.LittleEndian.Uint32(header[8:12])
	endPtr := binary.LittleEndian.Uint32(header[12:16])
	const segmentRegionMin = uint64(ip2RegionXDBHeaderSize + ip2RegionXDBVectorIndexSize)
	if uint64(startPtr) < segmentRegionMin || endPtr < startPtr ||
		uint64(endPtr)+uint64(segmentSize) > uint64(fi.Size()) {
		return fmt.Errorf("xdb 头段索引指针越界（start=%d end=%d size=%d，截断/损坏）", startPtr, endPtr, fi.Size())
	}
	return nil
}

// openIP2RegionSearcher opens the v4 xdb at path with the whole file buffered
// in memory for concurrent read safety, attaching the IPv6 database when the
// user toggle is on and a healthy v6 file is resolvable. v6 缺失/损坏只降级
// 本族（查询回落哨兵），绝不拖垮 v4 装载——两族健康门独立（见 dual 注释）。
func openIP2RegionSearcher(path string) (*ip2regionService.Ip2Region, error) {
	return openIP2RegionSearcherDual(path, ip2RegionV6PathForAttach())
}

// openIP2RegionSearcherDual 按显式路径构造双协议 searcher：v4 必选（结构
// 自检 + NewV4Config），v6 可选（v6Path 非空时经独立健康门附加）。更新任务
// 用 staged 路径构造热换 searcher，启动/回滚用 live 路径——同一实现保证
// 「面板在役 searcher 的 v6 形态」只有一种构造口径。v6 健康门失败只降级
// 本族（查询回落哨兵），绝不拖垮 v4 装载。
func openIP2RegionSearcherDual(v4Path, v6Path string) (*ip2regionService.Ip2Region, error) {
	if err := checkIP2RegionXDBStructure(v4Path); err != nil {
		return nil, err
	}
	config, err := ip2regionService.NewV4Config(ip2regionService.BufferCache, v4Path, 1)
	if err != nil {
		return nil, err
	}
	return ip2regionService.NewIp2Region(config, openIP2RegionV6Config(v6Path))
}

// openIP2RegionV6Config 构造 v6 BufferCache 配置：v6Path 为空（开关关闭/两族
// 文件皆缺失）返回 nil（绑定库双协议 API 的「该族禁用」形态——Search 对
// 16 字节 IP 返回空串，查询面回落既有哨兵语义）。文件健康门（结构自检 +
// 探针搜索）独立于 v4：损坏的 v6 库降级为禁用并 WARN 留痕，不影响 v4 装载。
func openIP2RegionV6Config(v6Path string) *ip2regionService.Config {
	if v6Path == "" {
		return nil
	}
	if err := validateIP2RegionV6XDB(v6Path); err != nil {
		Logf("warn", "ip2region: IPv6 库不可装载，v6 查询按禁用处理（哨兵语义）: %v", err)
		return nil
	}
	config, err := ip2regionService.NewV6Config(ip2regionService.BufferCache, v6Path, 1)
	if err != nil {
		Logf("warn", "ip2region: IPv6 库配置构造失败，v6 查询按禁用处理: %v", err)
		return nil
	}
	return config
}

// ip2RegionV6ProbeIP 是 v6 装载校验的探针地址：中国电信 240e::/20 段内地址，
// 真实 v6 库（v3.17.0）中必然命中「中国|北京|北京市|电信|CN」段——探针搜索
// 同时覆盖向量索引与段索引/region 数据区的读取路径。
const ip2RegionV6ProbeIP = "240e:56:4000:8000::1"

// validateIP2RegionV6XDB 是 v6 xdb 的「可装载」校验：结构自检（v6 布局门）
// + 探针搜索 + panic 收敛，与 v4 的 openValidatedIP2RegionSearcher 同强度——
// 「结构合法、段指针越界」的文件必须在校验期显性失败，不得进入 live 后在
// 请求期 panic。
func validateIP2RegionV6XDB(path string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			Logf("error", "ip2region: v6 probe search panicked on %s: %v\n%s", path, r, debug.Stack())
			err = fmt.Errorf("v6 探针搜索触发内部异常（文件损坏）: %v", r)
		}
	}()
	if err := checkIP2RegionXDBStructure(path); err != nil {
		return err
	}
	config, err := ip2regionService.NewV6Config(ip2regionService.BufferCache, path, 1)
	if err != nil {
		return err
	}
	searcher, err := ip2regionService.NewIp2Region(nil, config)
	if err != nil {
		return err
	}
	defer searcher.Close()
	if _, serr := searcher.Search(ip2RegionV6ProbeIP); serr != nil {
		// 探针未命中与结构损坏文案区分——上游库重组缺失探针
		// 段时一切合法 v6 库被判「损坏」不可区分;未命中是库内容覆盖面问题
		// (可更新探针或放宽),损坏是文件完整性问题(必须拒绝装载)。
		return fmt.Errorf("v6 探针地址未命中(库内容未覆盖 %s,非结构损坏): %w", ip2RegionV6ProbeIP, serr)
	}
	return nil
}

// ip2regionProbeIP 是装载校验的探针地址：114 段在真实库中必然存在，且损坏
// 夹具（段指针越界）的注入点正在该向量条目上。
const ip2regionProbeIP = "114.114.114.114"

// openValidatedIP2RegionSearcher 是 xdb「可装载」的唯一校验入口：结构自检 +
// 探针搜索 + panic 收敛。结构自检只覆盖已知布局（头 + 段索引指针边界），
// 绑定库对内容缓冲区其余无边界切片（段数据 dataPtr 带外等）仍以 panic
// 呈现——导入校验/Reload/启动装载三入口必须同强度，否则「结构合法、段指针
// 越界」的文件会经弱门进入 live，随后请求期 Search panic（请求 500）或启动
// 期省份采样 panic（main 无 recover=进程退出）。
func openValidatedIP2RegionSearcher(path string) (searcher *ip2regionService.Ip2Region, err error) {
	defer func() {
		if r := recover(); r != nil {
			if searcher != nil {
				searcher.Close()
				searcher = nil
			}
			Logf("error", "ip2region: probe search panicked on %s: %v\n%s", path, r, debug.Stack())
			err = fmt.Errorf("探针搜索触发内部异常（文件损坏）: %v", r)
		}
	}()
	searcher, err = openIP2RegionSearcher(path)
	if err != nil {
		return nil, err
	}
	if _, serr := searcher.Search(ip2regionProbeIP); serr != nil {
		searcher.Close()
		return nil, fmt.Errorf("探针搜索失败: %w", serr)
	}
	return searcher, nil
}

// GetIP2RegionEntryCount 返回**在役 searcher** 装载文件的条目数（与归属地查询
// 同源），未装载时返回 0。
//
// 不得改读 live 路径：在役 searcher 在两条既有分支上与 live 文件不同源——
// 只读降级（从节点/写入失败）装载的是镜像内置库，热换失败保留的是旧库实例。
// 读 live 会把「库其实可用」显示成 0，或按损坏文件 header 算出越界值。
func GetIP2RegionEntryCount() int {
	ip2regionMu.RLock()
	source := ip2regionSearcherSource
	loaded := ip2regionSearcher != nil
	ip2regionMu.RUnlock()
	if !loaded || source == "" {
		return 0
	}
	return entryCountFromXDBHeader(source)
}

// entryCountFromXDBHeader 从一个 xdb 文件的 header 边界推导条目数。
// xdb v2 官方边界（[8:16]，2 次 ReadAt）——原实现扫 65536 格 vector 推导
// （BufferCache 已全内存，每调用 65536 次 8B ReadAt 纯浪费；且 vector 端点
// 语义含末条结尾，推导 off-by-one）。段条目字节数按头布局判定（v4=14/v6=38）。
func entryCountFromXDBHeader(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	header := make([]byte, 20)
	if _, err := f.ReadAt(header, 0); err != nil {
		return 0
	}
	segmentSize, _, err := ip2RegionXDBLayout(header)
	if err != nil {
		return 0
	}
	startPtr := binary.LittleEndian.Uint32(header[8:12])
	endPtr := binary.LittleEndian.Uint32(header[12:16])
	// 单段 xdb 的 StartIndexPtr == EndIndexPtr 是合法边界（条目数 1），
	// 只有 end < start 才是空库/坏库。
	if endPtr < startPtr {
		return 0
	}
	return int((endPtr-startPtr)/uint32(segmentSize)) + 1
}

// GetIP2RegionV6EntryCount 返回 IPv6 库 live 文件的条目数（未启用/文件缺失
// /不可解析时返回 0）。与 v4 的 GetIP2RegionEntryCount 不同——v6 卡片展示
// 只关心 live 文件本身（v6 无「热换失败保留旧库」的内存分叉形态：面板
// searcher 构造时 v6 不可用即按禁用处理，展示 0 与查询语义一致）。
func GetIP2RegionV6EntryCount() int {
	path := ip2RegionV6PathForAttach()
	if path == "" {
		return 0
	}
	return entryCountFromXDBHeader(path)
}

// GetIP2RegionProvinces returns the province list from the live searcher, or
// ["海外"] when no database is loaded.
// 契约：返回的是记忆化缓存/注入切片的**共享内部视图**（同一底层数组），
// 调用方只读——就地排序/追加/截断会跨请求污染全局缓存（并影响校验端的
// known 集合）。需要修改时先自行 clone。
// ip2RegionLiveProvincesOverride 仅供测试注入「live 已装载」形态（模拟 xdb
// 在位），生产代码不设置。nil 时走真实 searcher 路径。
var ip2RegionLiveProvincesOverride []string

// SetIP2RegionLiveProvincesForTest 注入/清除测试用 live 省份列表。
// 注入的切片按引用保存（不清洗/不拷贝）——调用方注入后不得再改其内容或
// 依赖 GetIP2RegionProvinces 的返回值可写；清除传 nil。
func SetIP2RegionLiveProvincesForTest(provinces []string) {
	ip2RegionLiveProvincesOverride = provinces
}

func GetIP2RegionProvinces() []string {
	if ip2RegionLiveProvincesOverride != nil {
		return ip2RegionLiveProvincesOverride
	}
	ip2regionMu.RLock()
	searcher := ip2regionSearcher
	sourcePath := ip2regionSearcherSource
	ip2regionMu.RUnlock()
	if searcher == nil {
		return []string{"海外"}
	}
	// stat 键记忆化（与 regionTreeMemo 同构）：下方 336 次采样搜索全程持
	// ip2regionSearchMu 全局锁——校验端（ValidateGeoIPCountries）与缓存重建
	// 在同一份 xdb 上的重复调用是纯重复劳动且拖住全局锁。键含 searcher
	// 指针（测试/热换直换实例不吃陈旧值）+**在役来源** 的 path|size|mtime
	// （xdb 更新落盘后 mtime 变化自然失效）。
	//
	// 来源必须取 ip2regionSearcherSource 而不是恒取 live 路径：只读降级节点
	// （从节点/写入失败：live 缺失、searcher 来自 waf.dist）下 live 的 stat
	// 恒失败 → 键恒空 → 每次调用都重跑 336 次采样并全程持全局搜索锁（面板
	// 地域选项/策略校验的延迟尖峰 + 事件富化被阻塞）。stat 也失败时退化为
	// 仅指针键：searcher 实例不可变（BufferCache 构造期整份读入），实例热换
	// 必然换指针，故键仍然正确、仍然可记忆化。
	key := fmt.Sprintf("%p|%s", searcher, sourcePath)
	if fi, err := os.Stat(sourcePath); err == nil && sourcePath != "" {
		key = fmt.Sprintf("%p|%s|%d:%d", searcher, sourcePath, fi.Size(), fi.ModTime().UnixNano())
	}
	provincesMemoMu.Lock()
	if provincesMemo != nil && provincesMemoKey == key {
		out := provincesMemo
		provincesMemoMu.Unlock()
		return out
	}
	provincesMemoMu.Unlock()
	ip2regionProvinceScans.Add(1)
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
				// 采样列表与地域树同款规范化（normalizeIP2Province），
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
	if key != "" {
		provincesMemoMu.Lock()
		provincesMemo, provincesMemoKey = result, key
		provincesMemoMu.Unlock()
	}
	return result
}

// provincesMemo* 是 GetIP2RegionProvinces 的记忆化状态（语义见函数注释）。
// 并发冷调用可能各扫一次（良性的一次性重复劳动，与 regionTreeMemo 同声明）。
var (
	provincesMemoMu  sync.Mutex
	provincesMemo    []string
	provincesMemoKey string
)

// ip2regionProvinceScans 省份全量采样执行次数（测试观测记忆化命中；
// 生产成本=每冷调用一次原子加，镜像 autobanEntryTimeParses 先例）。
var ip2regionProvinceScans atomic.Int64

// GetIP2RegionProvinceList 返回省份列表，live searcher 优先、缓存兜底：仅供
// UI 列表端（GetIP2RegionRegions）——校验端（ValidateGeoIPCountries）
// 起改用 live-only 的 GetIP2RegionProvinces 判 loaded，避免 xdb 失效后缓存
// 放行而发射端静默零强制。ip2region 未加载且无缓存时仅返回 ["海外"]。
func GetIP2RegionProvinceList() []string {
	provinces := GetIP2RegionProvinces()
	if len(provinces) <= 1 {
		provinces = GetCachedProvinces()
	}
	return provinces
}

// 省列/城市列规范化四张表（别名/台湾城市/拼音城市/自治州）单源在
// lazy-balancer-v2/geoipnames（收敛——此前与 caddygeoip
// 手工镜像双份，漂移曾致城市级地域规则静默恒不命中）。选项树与 CEL 发射
// 变量统一用规范名，两边一致才能命中。
// treeCacheRevision 地域树缓存修订号——规范化规则（映射/别名/结构）变更时
// 递增，旧缓存据此判定过期重建。ASCII 残留探测只能发现「缓存里有脏数据」，
// 发现不了「该有而没有」的条目（如前整段被丢的 新疆/乌鲁木齐市）。
const treeCacheRevision = "r27" // 海外分支收集国家名（Countries）——旧缓存静默缺国名集，必须重建

// normalizeIP2Province 选项树侧省列规范化——单源 geoipnames.ProvinceForTree
// （下沉：此前与 caddygeoip.normalizeProvince 是两份手工镜像，
// 语义分叉靠调用点补偿）。语义：无效值（空/"0"）→ 空串；别名表归一
// （上海→上海市、UEruemqi→新疆维吾尔自治区）；台湾城市误置省列 → 空串
// （由调用方归入台湾省城市集）；未映射 ASCII（乱码/拼音残片）→ 空串；
// 其余中文省名原样通过。
func normalizeIP2Province(raw string) string {
	return geoipnames.ProvinceForTree(raw)
}

// normalizeIP2City 选项树侧城市列规范化——单源 geoipnames.CityForTree：
// 无效值 → 空串；拼音映射/自治州全称 → 规范中文；未映射 ASCII 城市 → 空串
// （过滤）；中文城市原样通过。
func normalizeIP2City(raw string) string {
	return geoipnames.CityForTree(raw)
}

// IP2RegionRegionTree 地域树：省级
// 列表 + 省→城市集映射；「海外」哨兵仍为一级条目（Provinces 末位，承载
// 解析失败/库缺失的 fail-closed 兜底），域 G起海外已解析行细化
// 为国家集（Countries——xdb 国家列归一后去重排序）。数据源为 xdb 段索引
// 全量扫描（每段 14B：startIP 4 + endIP 4 + dataLen 2 + dataPtr 4），
// region 数据按 dataPtr 去重读取（大量段共享同一 region 指针，实际读取量为
// 唯一 region 数，远小于 77.5 万段）。
type IP2RegionRegionTree struct {
	Revision  string              `json:"revision,omitempty"`
	Provinces []string            `json:"provinces"`
	Cities    map[string][]string `json:"cities"`
	// Countries：海外国家名集（域 G）——归一表折叠异体（美国→United States）、
	// 剔除非国家值（Reserved/0/空）；v3.18.0 实测 238 国。前端「海外国家」
	// 分组、校验 known 集、geoipLocOperator 精确集三处消费。
	Countries []string `json:"countries"`
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
	// 0) 布局判定：段条目字节数（v4=14/v6=38）与 dataLen/dataPtr 的段内偏移
	// 随布局变化——用固定 14B 解 v6 段会把 16B 起始 IP 的尾部当长度/指针，
	// 扫出乱码树。
	var minPtr, maxPtr uint32
	header := make([]byte, 20)
	if _, err := f.ReadAt(header, 0); err == nil {
		minPtr = binary.LittleEndian.Uint32(header[8:12])
		maxPtr = binary.LittleEndian.Uint32(header[12:16])
	}
	segmentSize, _, err := ip2RegionXDBLayout(header)
	if err != nil {
		return nil
	}
	// 1) 段区范围从 header 读取（offset 8 StartIndexPtr / offset 12 EndIndexPtr，
	// v3 双栈布局：向量索引推导的范围起点会早于真实段区——把 header/向量区
	// 当段解析出乱码 region，实测 262148 < 真实 3365968）。
	// 单段 xdb 的 header 两端指针相等——max < min 才判空。
	if maxPtr < minPtr {
		return nil
	}
	// 2) 遍历段索引，按 dataPtr 去重读 region。
	// int64 运算 + 文件大小上界钳制——uint32 ptr 在带外 ≥4GB 假 xdb
	//（EndIndexPtr 近 2^32）下 ptr += 14 回绕、扫描永不终止。
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	end := int64(maxPtr)
	if sizeBound := fi.Size() - int64(segmentSize); sizeBound < end {
		end = sizeBound
	}
	seg := make([]byte, segmentSize)
	provinces := map[string]bool{}
	countries := map[string]bool{}
	cities := map[string]map[string]bool{}
	var droppedASCIIProvinces, droppedASCIICities int
	seen := map[uint32]bool{}
	lenOff, ptrOff := segmentSize-6, segmentSize-4
	for ptr := int64(minPtr); ptr <= end; ptr += int64(segmentSize) {
		if _, err := f.ReadAt(seg, ptr); err != nil {
			break
		}
		dataLen := int(binary.LittleEndian.Uint16(seg[lenOff : lenOff+2]))
		dataPtr := binary.LittleEndian.Uint32(seg[ptrOff:])
		if dataLen == 0 || seen[dataPtr] {
			continue
		}
		seen[dataPtr] = true
		region := make([]byte, dataLen)
		if _, err := f.ReadAt(region, int64(dataPtr)); err != nil {
			continue
		}
		fields := strings.Split(string(region), "|")
		// 列数门槛必须与发射侧同口径（caddygeoip handler.parseGeoIPRegion
		// 要求 >=5）：3-4 列行在请求期被判「海外」（ok=false → 哨兵），
		// 树侧若按 >=3 收集省/市，会生成一批永不命中的幽灵省份/城市。
		if len(fields) < 5 {
			continue
		}
		if strings.TrimSpace(fields[0]) != "中国" {
			// 域 G：海外行收集归一化国名（异体折叠/非国家值剔
			// 除，见 geoipnames 包内 overseasCountries 表）；「海外」哨兵仍由 Provinces
			// 末位承载（解析失败/库缺失兜底），已解析海外行发射国名。
			if country := geoipnames.NormalizeCountry(fields[0]); country != "" {
				countries[country] = true
			}
			continue
		}
		prov := normalizeIP2Province(fields[1])
		if prov == "" {
			// 台湾城市误入省列：归入台湾省城市集（其省列值即城市名）。
			rawProv := strings.TrimSpace(fields[1])
			if geoipnames.IsTaiwanCity(rawProv) {
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
		Countries:             make([]string, 0, len(countries)),
		DroppedASCIIProvinces: droppedASCIIProvinces,
		DroppedASCIICities:    droppedASCIICities,
	}
	for prov := range provinces {
		tree.Provinces = append(tree.Provinces, prov)
	}
	sort.Strings(tree.Provinces)
	// 海外哨兵仍为一级条目（域 G 保留）：固定末位——「海外」的 UTF-8 字节序
	// 落在中文省名中间，参与排序会插在省份列表中间；校验端 known 集合不依赖
	// 顺序，选项树展示与采样列表口径一致（海外恒在最后）。已解析海外行的
	// 国家粒度由 Countries 承载（哨兵=解析失败/库缺失兜底，国家=已解析）。
	tree.Provinces = append(tree.Provinces, "海外")
	for country := range countries {
		tree.Countries = append(tree.Countries, country)
	}
	sort.Strings(tree.Countries)
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

// regionTreeForSettings 是树构建的设置感知单源：v4 live 扫描 + v6（启用且
// 文件可用时）并集。v6 与 v4 的 region 行语义相同（国家|省|市|ISP|码），选项
// 树/校验端消费的是两族并集——v6 专属段（如中国电信 240e::/20 的省级段）与
// v6 海外国家必须可被策略配置，否则「v6 解析出的值不在选项树/known 集合里」
// 会让发射端策略静默不匹配。
func regionTreeForSettings() *IP2RegionRegionTree {
	tree := regionTreeFromXDB(ip2regionLivePath)
	if tree == nil {
		return nil
	}
	if v6Path := ip2RegionV6PathForAttach(); v6Path != "" {
		mergeRegionTree(tree, regionTreeFromXDB(v6Path))
	}
	return tree
}

// mergeRegionTree 把 v6 扫描结果并入 v4 树（省/市/国家集并集；「海外」哨兵
// 恒保持 Provinces 末位不重复）。树是不可变共享视图（调用方只读），合并只
// 发生在构建期——整体按集合并集重建，不增量改写共享切片。
func mergeRegionTree(tree *IP2RegionRegionTree, v6 *IP2RegionRegionTree) {
	if v6 == nil {
		return
	}
	provSet := map[string]bool{}
	for _, prov := range tree.Provinces {
		provSet[prov] = true
	}
	citySet := map[string]map[string]bool{}
	for prov, cities := range tree.Cities {
		set := make(map[string]bool, len(cities))
		for _, city := range cities {
			set[city] = true
		}
		citySet[prov] = set
	}
	countrySet := map[string]bool{}
	for _, country := range tree.Countries {
		countrySet[country] = true
	}
	for _, prov := range v6.Provinces {
		if prov != "海外" {
			provSet[prov] = true
		}
	}
	// v4 树自带的「海外」哨兵不进排序集（恒由末位追加承载，防双份）。
	delete(provSet, "海外")
	for prov, cities := range v6.Cities {
		set := citySet[prov]
		if set == nil {
			set = map[string]bool{}
			citySet[prov] = set
		}
		for _, city := range cities {
			set[city] = true
		}
	}
	for _, country := range v6.Countries {
		countrySet[country] = true
	}
	provinces := make([]string, 0, len(provSet))
	for prov := range provSet {
		provinces = append(provinces, prov)
	}
	sort.Strings(provinces)
	tree.Provinces = append(provinces, "海外")
	tree.Cities = make(map[string][]string, len(citySet))
	for prov, set := range citySet {
		list := make([]string, 0, len(set))
		for city := range set {
			list = append(list, city)
		}
		sort.Strings(list)
		tree.Cities[prov] = list
	}
	countries := make([]string, 0, len(countrySet))
	for country := range countrySet {
		countries = append(countries, country)
	}
	sort.Strings(countries)
	tree.Countries = countries
	tree.DroppedASCIIProvinces += v6.DroppedASCIIProvinces
	tree.DroppedASCIICities += v6.DroppedASCIICities
}

// GetIP2RegionRegionTree 返回地域树：live 扫描优先，在役来源（回退的
// waf.dist）次之，文件缓存兜底（与省份列表同口径——searcher 加载失败时
// UI 仍能展示上次成功的树）。
// 扫描按 xdb 的 (path,size,mtime) 记忆化——安全策略页
// 每次打开都调本函数，原实现每次全量扫描 ~220ms（553K+58K preads）。stat
// 键未变即返回上次扫描结果；带外替换 xdb 改变 stat 键、触发重扫，保留
// 替换可见性（regions.json 缓存无法做到这一点，故不直接改用它）。扫描
// 失败（文件损坏/替换中）不记忆化，回退文件缓存，与原语义一致。
// 契约：返回值是记忆化/文件缓存共享的同一 *IP2RegionRegionTree（含
// Provinces/Cities/Countries 可变字段），调用方只读——就地修改会跨请求
// 污染全局预览/校验源（消费侧目前均为只读或浅拷贝后序列化）。
func GetIP2RegionRegionTree() *IP2RegionRegionTree {
	ip2regionMu.RLock()
	sourcePath := ip2regionSearcherSource
	ip2regionMu.RUnlock()
	// live 优先；live 缺失或扫描失败时，在役 searcher 的来源是同一内容代际的
	// 第二读取源。仅文件缓存兜底会让只读降级节点丧失完整地域树。
	scanPath := ip2regionLivePath
	fi, err := os.Stat(scanPath)
	if err != nil || scanPath == "" {
		if sourcePath == "" {
			return getCachedRegionTree()
		}
		if sourceInfo, sourceErr := os.Stat(sourcePath); sourceErr == nil {
			scanPath, fi = sourcePath, sourceInfo
		} else {
			return getCachedRegionTree()
		}
	}
	scan := func(path string, info os.FileInfo) *IP2RegionRegionTree {
		key := path + "|" + fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
		// v6 并集分量进键：开关/文件形态变化即触发重扫（树是 v4+v6 并集口径，
		// 见 regionTreeForSettings）。attach 路径为空串时用固定占位——「关闭」
		// 与「开启但无文件」都对应空并集，二者树内容一致无需区分。
		if v6Path := ip2RegionV6PathForAttach(); v6Path != "" {
			if v6Info, v6Err := os.Stat(v6Path); v6Err == nil {
				key += "|v6:" + v6Path + "|" + fmt.Sprintf("%d:%d", v6Info.Size(), v6Info.ModTime().UnixNano())
			} else {
				key += "|v6:missing"
			}
		} else {
			key += "|v6:off"
		}
		regionTreeMemoMu.Lock()
		if regionTreeMemo != nil && regionTreeMemoKey == key {
			tree := regionTreeMemo
			regionTreeMemoMu.Unlock()
			return tree
		}
		regionTreeMemoMu.Unlock()
		tree := regionTreeFromXDB(path)
		if tree != nil {
			if v6Path := ip2RegionV6PathForAttach(); v6Path != "" {
				mergeRegionTree(tree, regionTreeFromXDB(v6Path))
			}
			regionTreeMemoMu.Lock()
			regionTreeMemo, regionTreeMemoKey = tree, key
			regionTreeMemoMu.Unlock()
		}
		return tree
	}
	tree := scan(scanPath, fi)
	if tree == nil && sourcePath != "" && sourcePath != scanPath {
		if sourceInfo, sourceErr := os.Stat(sourcePath); sourceErr == nil {
			tree = scan(sourcePath, sourceInfo)
		}
	}
	if tree == nil {
		return getCachedRegionTree()
	}
	return tree
}

// regionTreeMemo* 是 GetIP2RegionRegionTree 的记忆化状态：树指针 + 生成
// 它的 xdb stat 键。并发冷调用可能各扫一次（良性的一次性重复劳动），
// 记忆化值对确定性的文件状态是确定的，正确性不受影响。键含 path 以防
// 测试/多实例切换 ip2regionLivePath 后命中同 size+mtime 的陈旧树。
var (
	regionTreeMemoMu  sync.Mutex
	regionTreeMemo    *IP2RegionRegionTree
	regionTreeMemoKey string
)

func getCachedRegionTree() *IP2RegionRegionTree {
	return readRegionTreeCache(ip2RegionLivePathForTreeCache())
}

func readRegionTreeCache(path string) *IP2RegionRegionTree {
	data, err := os.ReadFile(path)
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
	tree := readRegionTreeCache(path)
	if tree == nil {
		return true
	}
	if tree.Revision != treeCacheRevision {
		return true
	}
	for _, prov := range tree.Provinces {
		// 空串条目索引越界——缓存被带外手改(非本
		// 进程写入)时空串可入,prov[0] panic。启动路径,崩溃即启动失败。
		if prov == "" || (prov != "海外" && prov[0] < 0x80) {
			return true
		}
	}
	for _, cities := range tree.Cities {
		for _, city := range cities {
			if city == "" || city[0] < 0x80 {
				return true
			}
		}
	}
	// 域 G：国名条目为英文（ASCII 是规范形态）不做 ASCII 过滤；空串条目
	//（带外手改形态）判过期——空精确条目会让 geoipLocOperator 匹配空串 Loc。
	for _, country := range tree.Countries {
		if country == "" {
			return true
		}
	}
	return false
}

// writeRegionTreeCache 原子写树缓存（在库装载/更新成功时调用）。留 INFO 更新
// 日志：缓存是派生数据不进审计，但静默重建会让「选项树何时
// 变化」在排障时不可见。
func writeRegionTreeCache(tree *IP2RegionRegionTree) {
	if tree == nil {
		return
	}
	data, err := json.Marshal(tree)
	if err != nil {
		return
	}
	// 落盘失败写 WARN「重建落盘失败」并返回——此前
	// 静默吞错且仍写下方 INFO「已重建」成功行（日志谎报，排障误导）。
	if err := writeProvincesCache(ip2RegionLivePathForTreeCache(), data); err != nil {
		Logf("warn", "地域树缓存重建落盘失败（下次重建）: %v", err)
		return
	}
	cityTotal := 0
	for _, cities := range tree.Cities {
		cityTotal += len(cities)
	}
	Logf("info", "地域树缓存已重建：%d 省级 / %d 城市 / %d 海外国家（未映射 ASCII 段已过滤：省 %d / 城市 %d）", len(tree.Provinces), cityTotal, len(tree.Countries), tree.DroppedASCIIProvinces, tree.DroppedASCIICities)
}

// RebuildRegionTreeCacheForSync 供集群同步/lbbak 导入路径在 xdb 变更后调用
// ——与更新器 SetIP2RegionVersion 同款后置:树缓存重建+留痕(2026-09-18
// 用户裁定:同步只是换源,更新流程照走)。
// 写入门与启动路径同口径（ip2RegionStartupRepairWritesAllowed）：「文件/版本行/
// 派生缓存一律不落盘」是本节点只读不变量的显式契约，同步/导入在从节点同样会
// 执行，此前无条件落盘使该契约在这条路径上出现例外。跳过落盘不影响可用性：
// 读侧（GetIP2RegionRegionTree / GetIP2RegionProvinces）缺缓存时按 xdb 在内存
// 重建并记忆化。
func RebuildRegionTreeCacheForSync() {
	if !ip2RegionStartupRepairWritesAllowed() {
		Logf("info", "ip2region: 非主节点（或角色不可证实），跳过地域树派生缓存落盘（读侧按 xdb 内存重建）")
		return
	}
	writeRegionTreeCache(regionTreeForSettings())
}

// WriteIP2RegionTreeCacheForToggle 供 v6 开关切换后调用：树缓存是 v4+v6
// 并集口径，开关翻转改变并集内容但缓存过期判据（修订号/ASCII 残留）不感知
// ——不显式重建会让选项树/校验 known 集滞后到下次版本更新。写入门与启动
// 路径同口径（只读降级节点不落盘，读侧按 xdb 内存重建）。
func WriteIP2RegionTreeCacheForToggle() {
	if !ip2RegionStartupRepairWritesAllowed() {
		return
	}
	writeRegionTreeCache(regionTreeForSettings())
}
