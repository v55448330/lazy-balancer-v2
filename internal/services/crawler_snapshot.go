package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// crawlerIPListFile 快照交换文件（root 服务与插件的唯一交换面）。
// 包级变量以便测试覆盖到临时目录；生产默认容器内 /app/data 不变。
var crawlerIPListFile = "/app/data/crawler-ip-lists.json"

// crawlerBuiltinSnapshot 新实例内置首版（v2.3.8：官方源已核实的快照子集，
// 新实例启动即用，无需等待首轮下载；后续由更新任务覆盖为最新官方数据）。
var crawlerBuiltinSnapshot = map[string][]string{
	"googlebot": {
		"66.249.66.0/24", "66.249.67.0/24", "66.249.68.0/24", "66.249.69.0/24",
	},
	"gptbot": {
		"23.98.142.0/24", "23.98.143.0/24", "20.191.0.0/16",
	},
	"bingbot": {
		"157.55.39.0/24", "207.46.13.0/24", "40.77.167.0/24", "13.66.139.0/24",
		"13.66.144.0/24", "52.167.144.0/24", "13.67.10.16/28", "13.69.66.240/28",
		"13.71.172.224/28", "139.217.52.0/28", "191.233.204.0/24",
	},
	"so360spider": {
		"42.236.12.130/32", "42.236.13.135/32", "42.236.14.108/32", "42.236.15.7/32",
		"180.163.220.41/32", "180.163.220.42/32", "180.163.220.43/32",
	},
}

// crawlerDistSeedFile 镜像内置首版（JSON map[engine][]CIDR）。运行期快照
// crawlerIPListFile 同形，均为按引擎隔离的 JSON 对象。
var crawlerDistSeedFile = "/app/waf.dist/crawler-ip-lists.seed.json"

// loadCrawlerIPListsFromDB 以 DB 为唯一真相读取全部爬虫名单，按内部引擎 ID
// 返回；用户可见名单名只用于定位，不写进运行快照。
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
		}
	}
	return all, nil
}

// loadCrawlerBundledSeed 读镜像内置首版；文件缺失/损坏时保留 Go 内置最小
// 回退，保证离线新实例也不产生空名单。
func loadCrawlerBundledSeed() map[string][]string {
	if data, err := os.ReadFile(crawlerDistSeedFile); err == nil {
		var seed map[string][]string
		if err := json.Unmarshal(data, &seed); err == nil && len(seed) > 0 {
			return seed
		}
	}
	return crawlerBuiltinSnapshot
}

// Prime 启动预载：DB 为空时优先使用镜像内置种子，随后以 DB 为唯一真相
// 重建运行快照（root 服务与插件的唯一交换面）。
func (m *CrawlerUpdateManager) Prime() error {
	if err := ensureCrawlerSources(); err != nil {
		return err
	}
	if err := migrateCrawlerIPListNames(); err != nil {
		return err
	}
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		all = loadCrawlerBundledSeed()
	}
	for engineID, entries := range all {
		if err := upsertCrawlerIPList(engineID, entries); err != nil {
			return err
		}
	}
	return writeCrawlerIPListSnapshotAll(all)
}

// upsertCrawlerIPList 名单行原子快照：内容变化才更新（entries JSON、
// updated_at、entry_count）；失败/空集不写（保留上次快照）。
// 同步推送插件内存态（模块边界友好：caddygeoip 独立模块不能 import 根 DB）。
func upsertCrawlerIPList(engineID string, entries []string) error {
	if len(entries) == 0 {
		return errors.New("空 IP 段列表（解析无产出）")
	}
	payload := make([]models.IPListEntry, 0, len(entries))
	for _, value := range entries {
		payload = append(payload, models.IPListEntry{Value: value})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := migrateCrawlerIPListNames(); err != nil {
		return err
	}
	name := CrawlerIPListName(engineID)
	var existing string
	scanErr := db.DB.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, name).Scan(&existing)
	if scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
		return scanErr
	}
	if scanErr == nil && existing == string(encoded) {
		if _, statErr := os.Stat(crawlerIPListFile); statErr == nil {
			return nil // 内容与快照均在场，跳过重复 DB 回写和快照重写
		}
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
		return err
	}
	// DB 与运行快照是同一更新事务语义：快照写失败不得继续标记源成功。
	return writeCrawlerIPListSnapshot(engineID, entries)
}

// writeCrawlerIPListSnapshotAll 全量快照：写 map[engine][]string JSON
// （与 caddygeoip.crawler_verify.go 的读取契约一致，按引擎隔离命中）。
func writeCrawlerIPListSnapshotAll(all map[string][]string) error {
	encoded, err := json.Marshal(all)
	if err != nil {
		return err
	}
	tmp := crawlerIPListFile + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, crawlerIPListFile)
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
