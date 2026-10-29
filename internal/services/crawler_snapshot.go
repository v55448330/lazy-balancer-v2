package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// crawlerIPListFile 快照交换文件（root 服务与插件的唯一交换面）。
// 包级变量以便测试覆盖到临时目录；生产默认容器内 /app/data 不变；
// ConfigureWafDirs 按 data_dir 派生。
// defaultCrawlerIPListFile 与 caddygeoip 插件 Provision 的兜底默认同值——
// 渲染侧仅在派生值不同于此默认时发射 crawler_ip_list_file（字节稳定裁定，
// 见 buildGeoipHandler）。
const defaultCrawlerIPListFile = "/app/data/crawler-ip-lists.json"

var crawlerIPListFile = defaultCrawlerIPListFile

// SetCrawlerIPListFileForTest 重定向快照交换文件路径，仅供测试隔离使用（返回还原函数）。
//
// testseam: 留驻产品文件的测试缝——导出入口被 handlers 测试跨包消费
// （返回还原闭包形态），宿主不可能在同包 *_test.go；已登记 services
// testonly 绊线名单。
func SetCrawlerIPListFileForTest(path string) func() {
	old := crawlerIPListFile
	crawlerIPListFile = path
	return func() { crawlerIPListFile = old }
}

// crawlerSnapshotWriteObserver 测试观测点：每次全量快照写入前回调（生产 nil）。
// 用于断言启动预载只落一次快照——不给生产路径引入计数分支。
var crawlerSnapshotWriteObserver func()

// crawlerBuiltinSnapshot 新实例内置首版（单一事实源见
// geoipnames.BuiltinCrawlerIPLists：官方源快照随 geoipnames 包嵌入，镜像内
// /app/waf.dist 的同名文件由 Dockerfile 从同一路径 COPY）。
// 删除了此处的第二份手写副本——它曾与镜像种子分叉（gptbot 3 条 vs 18 条，
// 且含官方已不发布的 20.191.0.0/16 超网）。消费点仅剩「收缩门基线」
// （crawler_update.go 的 crawlerSnapshotShrinkGuard），运行期名单恒以 DB 为
// 唯一真相。
var crawlerBuiltinSnapshot = geoipnames.BuiltinCrawlerIPLists()

// crawlerDistSeedFile 镜像内置首版（JSON map[engine][]CIDR）。运行期快照
// crawlerIPListFile 同形，均为按引擎隔离的 JSON 对象。
var crawlerDistSeedFile = "/app/waf.dist/crawler-ip-lists.seed.json"

// loadCrawlerIPListsFromDB 以 DB 为唯一真相读取全部爬虫名单，按内部引擎 ID
// 返回；用户可见名单名只用于定位，不写进运行快照。返回值区分两种形态：
// 键存在且为空的引擎=「行存在但条目被清空（显式空集合）」；键缺失=「行缺失」
// ——补种判据只对后者生效（见 seedAndRebuildCrawlerIPListSnapshot）。
func loadCrawlerIPListsFromDB() (map[string][]string, error) {
	all := map[string][]string{}
	for _, src := range crawlerBotSources {
		var raw string
		err := db.DB.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, CrawlerIPListName(src.Name)).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if raw == "" {
			continue
		}
		var values []string
		var objects []models.IPListEntry
		if err := json.Unmarshal([]byte(raw), &objects); err == nil {
			for _, entry := range objects {
				values = append(values, entry.Value)
			}
		} else {
			// 兼容早期字符串数组形态；下次 upsert 自动归一为对象数组。
			if err := json.Unmarshal([]byte(raw), &values); err != nil {
				return nil, fmt.Errorf("名单 %s 条目解析失败: %w", CrawlerIPListName(src.Name), err)
			}
		}
		if len(values) > 0 {
			all[src.Name] = values
			continue
		}
		// 行存在但显式为空（entries='[]'）：登记为空集合（非 nil，JSON 落盘为
		// []），与「行缺失」区分开——补种判据（seedAndRebuildCrawlerIPListSnapshot）
		// 只对缺失行补内置首版；对显式空行补种会把「管理员带外清空该引擎名单
		// （意图=停用其豁免）」的意图静默推翻为内置首版。
		all[src.Name] = []string{}
	}
	return all, nil
}

// loadCrawlerBundledSeed 读镜像内置首版；文件缺失/损坏时回退到嵌入二进制的
// 同一份数据（geoipnames.BuiltinCrawlerIPLists），保证离线新实例也不产生空名单。
// 两条路径内容同源（Dockerfile 从嵌入路径 COPY），不存在「两份数据分叉」。
func loadCrawlerBundledSeed() map[string][]string {
	if data, err := os.ReadFile(crawlerDistSeedFile); err == nil {
		var seed map[string][]string
		if err := json.Unmarshal(data, &seed); err == nil && len(seed) > 0 {
			return seed
		}
	}
	return geoipnames.BuiltinCrawlerIPLists()
}

// Prime 启动预载：DB 缺少任一内置引擎名单时按引擎补种内置首版，随后以 DB
// 为唯一真相重建运行快照（root 服务与插件的唯一交换面）。
//
// 判据必须是「逐引擎缺项」而非「全库为空」：播种中途失败（DB busy/磁盘
// 错误/快照目录异常）会留下部分引擎行，第二次启动若按全库判据就永不再补种
// ——缺失引擎的内置首版豁免从此消失（so360spider 在 geoipnames 走 iprange
// 验证且无 PTR 兜底，名单缺失即该引擎豁免彻底失效），且末尾全量快照会把
// 缺失引擎条目一并删掉。
func (m *CrawlerUpdateManager) Prime() error {
	// 与同包 autoban/ensureAutobanPresetListID 等 nil 门同口径：无库脚手架
	// （测试/嵌入形态）显性报错，不 nil dereference。
	if db.DB == nil {
		return errors.New("数据库未初始化")
	}
	if err := ensureCrawlerSources(); err != nil {
		return err
	}
	// 名单名迁移单轮一次，且必须在读库之前：loadCrawlerIPListsFromDB 以名单名
	// 为键，旧键（crawlerbot:<engine>）若未先迁移，后续逐引擎 upsert 会写到
	// 另一行上。走测试缝以便钉住「单轮只迁移一次」。
	if err := crawlerIPListMigrate(); err != nil {
		return err
	}
	// 启动期把内置源的 canonical url/format 刷新到存量行（用户开关/
	// 状态/排程保持不变），修复「URL/格式修正只对新库生效」的升级盲区。
	if err := refreshCrawlerSources(); err != nil {
		return err
	}
	return seedAndRebuildCrawlerIPListSnapshot()
}

// seedAndRebuildCrawlerIPListSnapshot 逐引擎补种缺失的内置名单（判据同
// Prime：缺哪补哪），随后以 DB 为唯一真相单次写全量运行快照。
//
// 启动（Prime）与备份导入（RestoreCrawlerIPListSnapshot）共用本收敛体：
// 导入是全表替换，旧备份可能不含 system=1 爬虫行（v2.3.8 前导出/用户裁剪），
// 只 rebuild 不补种会让运行快照缺失整引擎——该引擎的地域/ACL 豁免与伪装
// 检测静默失效，直到进程重启或下一轮源更新，面板零告警。
func seedAndRebuildCrawlerIPListSnapshot() error {
	// 与 Prime 同口径的 nil 门：导入/重建路径同样不 nil dereference。
	if db.DB == nil {
		return errors.New("数据库未初始化")
	}
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		return err
	}
	bundled := loadCrawlerBundledSeed()
	var missing []string
	for _, src := range crawlerBotSources {
		if _, ok := all[src.Name]; ok {
			continue
		}
		seed, ok := bundled[src.Name]
		if !ok || len(seed) == 0 {
			missing = append(missing, src.Name)
			continue
		}
		all[src.Name] = append([]string(nil), seed...)
	}
	if len(missing) > 0 {
		// 内置首版也没有该引擎条目：快照将缺该引擎（iprange 引擎在快照缺项时
		// 判 Transient，豁免静默失效），必须留痕而不是成功静默。
		Logf("warn", "爬虫内置名单补种缺引擎 %v：运行快照不含该引擎，其豁免/伪装检测暂不生效", missing)
	}
	// 名单名迁移由调用方在读库前完成一次（逐引擎 upsert 不再各自重跑：那等于
	// 每引擎 N 条 UPDATE，且迁移晚于读库会让旧键行被重复写入）。
	var explicitEmpty []string
	for engineID, entries := range all {
		if len(entries) == 0 {
			// 行存在但显式为空：不补种内置首版（那是「行缺失」的判据，见
			// loadCrawlerIPListsFromDB），也不回写（upsert 对空列表报错，且没有
			// 任何内容可写）。运行快照保留该引擎的空数组——插件对空/缺项均判
			// Transient，语义都是「该引擎豁免不生效」，但空数组让面板/快照读者
			// 能看出是显式空而非漏种。
			explicitEmpty = append(explicitEmpty, engineID)
			continue
		}
		// 逐引擎只落 DB：带快照形态会在 DB 尚未补种完的中间态各写一次全量
		// 快照（插件可能读到只含部分引擎的合法 JSON）。全量快照在循环末尾
		// 单次写——变更/需刷新语义此处不消费（末尾写覆盖全部引擎）。
		if _, _, err := upsertCrawlerIPListChangedInnerNoSnapshot(engineID, entries); err != nil {
			// 部分 upsert 失败时不写全量快照（保留上一份，避免快照缩小），
			// 由调用方错误日志告警后下次启动继续补种。
			return err
		}
	}
	if len(explicitEmpty) > 0 {
		// 显式空名单不改写、不补种，但必须留痕：该引擎的豁免当前不生效。
		Logf("warn", "爬虫名单 %v 在库中显式为空（条目被清空）：运行快照保留空集合，对应引擎的豁免/伪装检测不生效；如需恢复请重新更新该源", explicitEmpty)
	}
	return writeCrawlerIPListSnapshotAll(all)
}

// RestoreCrawlerIPListSnapshot 备份导入后的收敛入口：补种缺失的内置爬虫名单
// 并以 DB 为唯一真相重建运行交换文件（与 Prime 的收敛体同源；不跑启动期的
// 源 canonical 刷新与名单名迁移——那些由重启路径承担，导入请求内保持最小面）。
func RestoreCrawlerIPListSnapshot() error {
	// 与 Prime 同口径的 nil 门（收敛体自检，入口显性报错）。
	if db.DB == nil {
		return errors.New("数据库未初始化")
	}
	return seedAndRebuildCrawlerIPListSnapshot()
}

// RebuildCrawlerIPListSnapshot 以当前 DB 名单为唯一真相重建运行交换文件。
// 与 Prime 不同，不播种、不回写名单；适用于「名单行已由外部全量写定」的
// 无副作用收敛（集群同步）。备份导入是**全表替换**语义，必须走
// RestoreCrawlerIPListSnapshot 才会补种缺失的 system 行。
func RebuildCrawlerIPListSnapshot() error {
	// 与 Prime 同口径的 nil 门。
	if db.DB == nil {
		return errors.New("数据库未初始化")
	}
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		return err
	}
	return writeCrawlerIPListSnapshotAll(all)
}

// upsertCrawlerIPListChangedInner upsert 主体（名单名迁移已由调用方完成——
// RunUpdate/Prime 单轮提升一次）。DB 行落定后才写运行快照（快照写失败须让
// 调用方判失败）。
func upsertCrawlerIPListChangedInner(engineID string, entries []string) (bool, error) {
	changed, snapshotNeeded, err := upsertCrawlerIPListChangedInnerNoSnapshot(engineID, entries)
	if err != nil {
		return false, err
	}
	if !snapshotNeeded {
		return false, nil
	}
	// DB 与运行快照是同一更新事务语义：快照写失败不得继续标记源成功。
	if err := writeCrawlerIPListSnapshot(engineID, entries); err != nil {
		// 部分提交：DB 已落定而快照失败，调用方仍须计入收敛面。
		return changed, err
	}
	// 返回 changed（DB 内容真实变化）而非恒 true：snapshotNeeded 可在 DB 未变、
	// 仅运行快照缺失/陈旧时为真——那种形态只是修好了快照，名单内容没变，
	// 不得让调用方按「名单内容变化」触发投影收敛/热路径日志（口径与事实不符，
	// 排障时会误判源站内容变化）。
	return changed, nil
}

// upsertCrawlerIPListChangedInnerNoSnapshot 只落 DB 行，不写运行快照。
// 返回 (changed, snapshotNeeded, err)：
//   - changed=DB 内容真实变化；
//   - snapshotNeeded=需要按本次内容重建运行快照（DB 实变，或 DB 未变但快照
//     缺失/损坏/陈旧）。
//
// 启动预载（Prime）逐引擎播种时只走本函数、末尾写一次全量快照——逐引擎
// 调用带快照形态会在 DB 尚未补种完的中间态各写一次全量快照，把只含已落库
// 引擎的合法 JSON 暴露给插件（iprange 引擎在快照缺项时判 Transient）。
func upsertCrawlerIPListChangedInnerNoSnapshot(engineID string, entries []string) (changed bool, snapshotNeeded bool, err error) {
	if len(entries) == 0 {
		return false, false, errors.New("空 IP 段列表（解析无产出）")
	}
	payload := make([]models.IPListEntry, 0, len(entries))
	for _, value := range entries {
		payload = append(payload, models.IPListEntry{Value: value})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false, false, err
	}
	name := CrawlerIPListName(engineID)
	var existing string
	scanErr := db.DB.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, name).Scan(&existing)
	if scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
		return false, false, scanErr
	}
	if scanErr == nil && crawlerEntriesUnchanged(existing, entries) {
		// 判定改为内容（多重集）比较而非顺序敏感
		// 字节比较——源站同集合换序曾每轮误判 changed=true（写放大+「更新成功」
		// 噪声）。DB 展示顺序保持不变（未变化不重写）。
		// 未变化仍须校验**快照内容**：不能只看文件存在/DB 值——
		// 文件缺失/坏 JSON/陈旧内容（首轮快照写失败、升级遗留）都要从 DB/entries
		// 重建；writeCrawlerIPListSnapshot 从 DB 全量重建并覆盖本引擎，其他引擎
		// 分片保留。
		return false, !crawlerSnapshotMatchesEngine(engineID, entries), nil
	}
	exists := 0
	if scanErr == nil {
		exists = 1
	}
	if exists == 0 {
		_, err = db.DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
			VALUES (?, ?, '搜索引擎爬虫', ?, 1, datetime('now'), datetime('now'))`, name, crawlerDisplayName(engineID), string(encoded))
	} else {
		_, err = db.DB.Exec(`UPDATE security_ip_lists SET entries=?, updated_at=datetime('now') WHERE name=? AND system=1`, string(encoded), name)
	}
	if err != nil {
		return false, false, err
	}
	return true, true, nil
}

// crawlerSnapshotMatchesEngine 快照文件可解析且本引擎条目集合与期望一致。
func crawlerSnapshotMatchesEngine(engineID string, entries []string) bool {
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		return false
	}
	var all map[string][]string
	if err := json.Unmarshal(data, &all); err != nil {
		return false
	}
	got, ok := all[engineID]
	if !ok {
		return false
	}
	// 多重集比较（与 crawlerEntriesUnchanged 同口径）：长度 + 成员包含
	// 会把 [A,B] 与 [A,A] 判为一致，快照多出的条目会被保留（fail-open 方向）。
	return crawlerSameStringMultiset(got, entries)
}

// crawlerSameStringMultiset 报告两组字符串是否同值多重集（顺序无关）。
func crawlerSameStringMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, v := range a {
		counts[v]++
	}
	for _, v := range b {
		if counts[v] == 0 {
			return false
		}
		counts[v]--
	}
	return true
}

// crawlerEntriesUnchanged 报告已存 entries JSON 与本次解析条目是否同值多重集
// （顺序无关的内容比较；解析失败按「已变化」处理→走完整写入路径
// 重建畸形行）。DB 展示顺序保持原状（未变化不重写）。
func crawlerEntriesUnchanged(existingJSON string, entries []string) bool {
	var stored []models.IPListEntry
	if err := json.Unmarshal([]byte(existingJSON), &stored); err != nil {
		return false
	}
	if len(stored) != len(entries) {
		return false
	}
	storedValues := make([]string, 0, len(stored))
	for _, e := range stored {
		storedValues = append(storedValues, e.Value)
	}
	return crawlerSameStringMultiset(storedValues, entries)
}

// writeCrawlerIPListSnapshotAll 全量快照：写 map[engine][]string JSON
// （与 caddygeoip.crawler_verify.go 的读取契约一致，按引擎隔离命中）。
func writeCrawlerIPListSnapshotAll(all map[string][]string) error {
	if crawlerSnapshotWriteObserver != nil {
		crawlerSnapshotWriteObserver()
	}
	encoded, err := json.Marshal(all)
	if err != nil {
		return err
	}
	// 复用「持久化原子落盘」单源实现——此前是第 4 份
	// 手写 CreateTemp+Sync+Rename（缺 chmod，默认 0600；同目录其它投影/快照
	// 类文件均为 0644），单源修复无法一处生效。
	return writeFileAtomicSynced(crawlerIPListFile, encoded, 0o644)
}

// writeCrawlerIPListSnapshot 单引擎更新后从 DB 重建全量运行快照。
// 运行文件为 map[engine][]string JSON（旧纯文本实现会被插件误读且丢失引擎边界）。
func writeCrawlerIPListSnapshot(engineID string, entries []string) error {
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		return err
	}
	all[engineID] = entries
	return writeCrawlerIPListSnapshotAll(all)
}
