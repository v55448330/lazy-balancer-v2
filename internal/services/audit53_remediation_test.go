package services

// 第 53 轮补充轮 P2-1（用户裁定方案 A，按建议处理）：名单投影文件 GC 不得在
// 渲染中途执行——writeIPListFile 的 defer GC 会让「安静 >24h 后第一次渲染」按
// 上一轮渲染的陈旧引用集删除在役名单（allow/trust 方向瞬态 403 风暴、deny 方向
// fail-open；渲染中途失败则持续到下次成功渲染）。GC 统一移到整轮渲染 apply
// 成功后（引用集落齐再做差集）。时间语义：全部阈值为 time.Since 时长比较，
// 无挂钟排程，与时区配置天然无关（用户裁定关注点）。

import (
	"os"
	"testing"
	"time"
)

func TestWriteIPListFile_doesNotGCMidRender(t *testing.T) {
	// Given：在役名单 A 上次渲染引用在 48h 前、文件 mtime 48h（stat 命中不刷新
	// mtime）——系统安静 >24h 后的真实形态；GC 节流到期
	pathA, err := writeIPListFile("mid-render-keep", []string{"203.0.113.7"})
	if err != nil {
		t.Fatalf("write A: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(pathA, old, old); err != nil {
		t.Fatal(err)
	}
	ipListRenderRefs.Lock()
	ipListRenderRefs.lastRef[pathA] = old
	ipListRenderRefs.Unlock()
	savedGC := ipListLastGC
	ipListLastGC = time.Now().Add(-2 * time.Hour) // 节流到期——下一次投影必触发
	t.Cleanup(func() { ipListLastGC = savedGC })

	// When：本轮渲染投影另一个名单 B（渲染中途点）
	if _, err := writeIPListFile("mid-render-other", []string{"198.51.100.9"}); err != nil {
		t.Fatalf("write B: %v", err)
	}

	// Then：A 的文件必须存活——GC 不得在渲染中途按陈旧引用集删在役文件
	if _, err := os.Stat(pathA); err != nil {
		t.Fatalf("在役名单文件被渲染中途 GC 删除: %v（P2-1：allow 方向 403 风暴/deny 方向 fail-open 根因）", err)
	}
}

func TestIPListGC_afterFullRenderKeepsInServiceAndDropsOrphans(t *testing.T) {
	// Given：整轮渲染完成——在役名单 A 已在本轮重新 note（渲染会投影全部在役
	// 名单）；孤儿文件 O 超龄未引用；节流到期
	pathA, err := writeIPListFile("post-render-keep", []string{"203.0.113.8"})
	if err != nil {
		t.Fatalf("write A: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(pathA, old, old); err != nil {
		t.Fatal(err)
	}
	orphan := writeOrphanIPListFileForTest(t, "post-render-orphan", old)
	savedGC := ipListLastGC
	ipListLastGC = time.Now().Add(-2 * time.Hour)
	t.Cleanup(func() { ipListLastGC = savedGC })

	// When：渲染 apply 成功后的统一 GC 入口
	maybeGCStaleIPListFiles()

	// Then：在役 A 保留（引用集已落齐），孤儿 O 删除
	if _, err := os.Stat(pathA); err != nil {
		t.Fatalf("在役名单被误删: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("孤儿文件未被 GC 删除（入口失效）")
	}
}

func writeOrphanIPListFileForTest(t *testing.T, scope string, age time.Time) string {
	t.Helper()
	path := IPListDataDir + string(os.PathSeparator) + scope + "-deadbeef0012.txt"
	if err := os.WriteFile(path, []byte("192.0.2.1/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, age, age); err != nil {
		t.Fatal(err)
	}
	return path
}
