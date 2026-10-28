package services

// 排程槽域 = 运行域：威胁族的槽只取内置注册表源名的最早槽，注册表外的启用行
// 不得把「最早槽」钉在过去（那会让 auto 轮恒投递、运行体零到期源提前返回、
// 槽永不被消费 → 威胁库自动更新静默停摆）。

import (
	"testing"
	"time"
)

func TestEarliestThreatSlotIgnoresUnregisteredSources(t *testing.T) {
	_, database := newClusterTestService(t)
	// 注册表源：最早槽=2999-01-02；其余两源停用（避免干扰）。
	if _, err := database.Exec(`UPDATE security_threat_sources SET update_enabled=CASE WHEN name='ustc' THEN 1 ELSE 0 END,
		next_update=CASE WHEN name='ustc' THEN '2999-01-02 00:00:00' ELSE NULL END`); err != nil {
		t.Fatalf("seed registry sources: %v", err)
	}
	// 注册表外的启用行，槽已过期（应用升级改名/迁表遗留、带外直写的形态）。
	if _, err := database.Exec(`INSERT INTO security_threat_sources (name, url, update_enabled, next_update)
		VALUES ('legacy-x','https://legacy.example/list.txt',1,'2020-01-01 00:00:00')`); err != nil {
		t.Fatalf("seed unregistered source: %v", err)
	}

	// When
	got := earliestThreatNextUpdate()

	// Then：注册表外的过期槽不参与（旧实现返回 2020-01-01）
	if want := "2999-01-02 00:00:00"; got != want {
		t.Fatalf("earliest threat slot=%q, want %q（槽域必须等于运行域）", got, want)
	}
	// 运行体只处理注册表源（该行零处理=槽无推进写点，即停摆机理的前提）。
	for _, source := range mustThreatDueSources(t) {
		if source.name == "legacy-x" {
			t.Fatalf("运行体处理了注册表外的源 %q（槽域=运行域前提被破坏）", source.name)
		}
	}
}

func mustThreatDueSources(t *testing.T) []threatSourceRow {
	t.Helper()
	sources, err := threatDueSources("manual")
	if err != nil {
		t.Fatalf("threatDueSources: %v", err)
	}
	return sources
}

func TestEarliestCrawlerSlotCountsAllEnabledSources(t *testing.T) {
	_, database := newClusterTestService(t)
	// 爬虫族运行域=全部启用行（不按名单过滤），槽域必须保持同一语义。
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0`); err != nil {
		t.Fatalf("disable crawler sources: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name, url, update_enabled, next_update)
		VALUES ('crawler-any','https://crawler.example/list.txt',1,'2030-05-06 07:08:09')`); err != nil {
		t.Fatalf("seed crawler source: %v", err)
	}

	if got, want := earliestCrawlerNextUpdate(), "2030-05-06 07:08:09"; got != want {
		t.Fatalf("earliest crawler slot=%q, want %q（爬虫族不做名过滤）", got, want)
	}
}

// 启动归一：注册表外启用行的槽被清空（幂等、只清槽不改开关/内容）。
func TestNormalizeUnregisteredThreatSourceSlots(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE security_threat_sources SET next_update='2999-01-02 00:00:00' WHERE name='ustc'`); err != nil {
		t.Fatalf("seed registry slot: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_threat_sources (name, url, update_enabled, next_update)
		VALUES ('legacy-y','https://legacy.example/y.txt',1,'2020-01-01 00:00:00')`); err != nil {
		t.Fatalf("seed unregistered source: %v", err)
	}

	// When
	normalizeUnregisteredThreatSourceSlots()

	// Then：注册表外行的槽清空、开关不动；注册表行不受影响
	var nextNull int
	var enabled int
	if err := database.QueryRow(`SELECT CASE WHEN next_update IS NULL THEN 1 ELSE 0 END, update_enabled
		FROM security_threat_sources WHERE name='legacy-y'`).Scan(&nextNull, &enabled); err != nil {
		t.Fatalf("read unregistered row: %v", err)
	}
	if nextNull != 1 || enabled != 1 {
		t.Fatalf("legacy-y next_update_null=%d update_enabled=%d，want 1/1（只清槽，不改开关）", nextNull, enabled)
	}
	var registrySlot string
	if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&registrySlot); err != nil {
		t.Fatalf("read registry row: %v", err)
	}
	if registrySlot != "2999-01-02 00:00:00" {
		t.Fatalf("注册表源槽=%q，want 保留", registrySlot)
	}

	// 幂等：再跑一轮不改变任何行
	normalizeUnregisteredThreatSourceSlots()
	if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&registrySlot); err != nil {
		t.Fatalf("re-read registry row: %v", err)
	}
	if registrySlot != "2999-01-02 00:00:00" {
		t.Fatalf("第二轮后注册表源槽=%q，want 保留", registrySlot)
	}
}

// 槽域=运行域在**写侧**同样成立：注册表外启用行的槽被清空后，同一次装配的
// 首槽武装与时区重排都不得把槽写回（两者此前无名字过滤，清理刚清空又被
// 武装补回=伪收敛，只剩每次启动重复的误导性告警）。
func TestUnregisteredThreatSlotNotRewrittenByArmOrTimezoneRearm(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET threat_auto_update=1 WHERE id=1`); err != nil {
		t.Fatalf("enable threat auto update: %v", err)
	}
	// Given 注册表源空槽（应被武装）+ 注册表外启用行带过期槽（应被清空）。
	if _, err := database.Exec(`UPDATE security_threat_sources SET update_enabled=1, next_update=NULL`); err != nil {
		t.Fatalf("clear registry slots: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_threat_sources (name, url, update_enabled, next_update)
		VALUES ('legacy-z','https://legacy.example/z.txt',1,'2020-01-01 00:00:00')`); err != nil {
		t.Fatalf("seed unregistered source: %v", err)
	}
	readSlot := func(name string) string {
		t.Helper()
		var slot string
		if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE name=?`, name).Scan(&slot); err != nil {
			t.Fatalf("read %s slot: %v", name, err)
		}
		return slot
	}

	// When 清理 + 首槽武装（同一次装配的两步）
	normalizeUnregisteredThreatSourceSlots()
	ArmThreatFirstSlots()

	// Then 注册表源被武装，注册表外行保持空槽（不得被无过滤武装补回）。
	if readSlot("ustc") == "" {
		t.Fatal("注册表源空槽未被首槽武装")
	}
	if slot := readSlot("legacy-z"); slot != "" {
		t.Fatalf("注册表外行槽被重新武装为 %q（清理被反向抵消）", slot)
	}

	// When 注册表外行带未来槽后再做时区重排
	if _, err := database.Exec(`UPDATE security_threat_sources SET next_update='2999-05-06 07:08:09' WHERE name IN ('legacy-z','ustc')`); err != nil {
		t.Fatalf("seed future registry and unregistered slots: %v", err)
	}
	RearmScheduleSlotsAfterTimezoneChange()

	// Then 注册表外行的槽不被重排路径改写（槽域外行不参与重排）。
	if slot := readSlot("legacy-z"); slot != "2999-05-06 07:08:09" {
		t.Fatalf("注册表外行槽被时区重排改写为 %q（槽域=运行域被破坏）", slot)
	}
	// 正控：注册表源必须从同一个固定未来槽被真实重排；否则 slotFn 失败
	// 整表 continue 时，legacy-z 的负断言会空转假绿。
	registrySlot := readSlot("ustc")
	if registrySlot == "" || registrySlot == "2999-05-06 07:08:09" {
		t.Fatalf("注册表源未被时区重排（正控失败），slot=%q", registrySlot)
	}
	if got := parseSlotUTC(t, registrySlot); !got.After(time.Now().UTC()) {
		t.Fatalf("注册表源重排槽=%v，want 真实未来时间", got)
	}
}
