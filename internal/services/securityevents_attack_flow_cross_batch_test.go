package services

import "testing"

// 普通检测事件跨批改判为拦截时，攻击光流必须与事件表一致：同一请求键只有一条
// 最终结论。两次 tick 分属不同批次，本批索引（attackFlowIndex）看不到上一批
// 已入环的条目，旧实现直接再追加一条 blocked——大屏同时出现「检测」和「拦截」
// 两条弧，拦截率被放大。爬虫放行族（首轮本就不入环）的补录语义必须保留。
func TestSecurityEventsTick_crossPassUpgradeUpdatesFlowEntryInPlace(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	enableAttackFlowSampling(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeNowFixture("tx-flow-inplace-a", "0077aabbccddeeff", "/flow-inplace", "logged", 942100))
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)

	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 0)
	if len(events) != 1 || events[0].Action != "logged" {
		t.Fatalf("前置形状不成立（普通 logged 攻击事件应已入环一次）: %+v", events)
	}
	firstSeq := events[0].Seq

	// When 同一请求在下一批被改判为拦截
	appendDedupeLogDoc(t, logPath, tailer,
		securityEventsDedupeNowFixture("tx-flow-inplace-b", "0077aabbccddeeff", "/flow-inplace", "blocked", 949110))

	// Then 光流仍只有一条（原地改判），结论为 blocked，序号不回退
	events, _, _ = ThreatScreenAttackFlowSnapshot(0, 0)
	var matched []string
	for _, ev := range events {
		if ev.ClientIP == "45.33.32.9" {
			matched = append(matched, ev.Action+"|"+ev.RuleTriggered)
			if ev.Seq != firstSeq {
				t.Fatalf("原地改判不得重新分配序号（前端游标会回退/重复投递）: seq=%d want %d", ev.Seq, firstSeq)
			}
		}
	}
	if len(matched) != 1 {
		t.Fatalf("光流条目数=%d, want 1（同一请求只能有一条最终结论）: %v", len(matched), matched)
	}
	if matched[0] != "blocked|949110" {
		t.Fatalf("光流条目=%q, want blocked|949110（与事件行改判一致）", matched[0])
	}
}

// 采样租约在两轮之间关闭（大屏关闭/心跳 TTL 过期）时，跨批改判仍必须落到
// 环内既有弧：环里留着首轮 logged，消费者下次打开大屏按 since=0 会读到它。
// 旧实现两道门共同吞掉改判——产生侧按「当下档位=0」不入队，recordBatch 又在
// 采样门整批早退——同一请求残留旧结论直到被容量淘汰（事件表/拦截率按
// blocked 计，同屏两面分叉）。
func TestSecurityEventsTick_crossPassUpgradeAppliesWhenSamplingClosed(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	enableAttackFlowSampling(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeNowFixture("tx-flow-off-a", "0077aabbccddeeff", "/flow-off", "logged", 942100))
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)

	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 0)
	if len(events) != 1 || events[0].Action != "logged" {
		t.Fatalf("前置形状不成立（普通 logged 攻击事件应已入环一次）: %+v", events)
	}
	firstSeq := events[0].Seq

	// 租约关闭：档位归 0（大屏关闭 / 心跳超时后租约被清理）
	ReleaseThreatScreenAttackFlowLease("batch-test")
	if n := ThreatScreenAttackFlowSampleN(); n != 0 {
		t.Fatalf("采样档位=%d, want 0（租约已释放）", n)
	}

	// When 同一请求在下一批被改判为拦截（档位=0，大屏此刻没人看）
	appendDedupeLogDoc(t, logPath, tailer,
		securityEventsDedupeNowFixture("tx-flow-off-b", "0077aabbccddeeff", "/flow-off", "blocked", 949110))

	// Then 环内既有条目必须已原地改判，且不新增第二条
	events, _, _ = ThreatScreenAttackFlowSnapshot(0, 0)
	var matched []string
	for _, ev := range events {
		if ev.ClientIP == "45.33.32.9" {
			matched = append(matched, ev.Action+"|"+ev.RuleTriggered)
			if ev.Seq != firstSeq {
				t.Fatalf("原地改判不得重新分配序号: seq=%d want %d", ev.Seq, firstSeq)
			}
		}
	}
	if len(matched) != 1 || matched[0] != "blocked|949110" {
		t.Fatalf("光流条目=%v, want 唯一一条 blocked|949110（档位 0 时改判仍须落地）", matched)
	}
}
