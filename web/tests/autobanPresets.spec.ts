// 自动封禁预设档位 + 证据分层配置面行为钉：预设映射跨栈对账（标准档==db 默认）、
// 自定义态判定、升级阶梯预览、参数域与后端校验单源同口径。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  AUTOBAN_PRESETS, AUTOBAN_PRESET_IDS, matchAutobanPreset,
  AUTOBAN_SUSPICION_MULTIPLIER_MIN, AUTOBAN_SUSPICION_MULTIPLIER_MAX, AUTOBAN_CONFIRM_FLOOR_RATIOS,
} from '../src/utils/autobanPresets.ts'
import { autobanEscalationLadder } from '../src/utils/autobanStatus.ts'
import { repoCode, goConstInt, section } from './_helpers.ts'

// Go 字符串常量取值（db 默认 duration/escalation/打底比例是字符串形态；
// goConstInt 只覆盖整型）。缺失即抛错——对表断言拿 undefined 会假绿。
const goConstString = (repoPath: string, name: string): string => {
  const m = repoCode(repoPath).match(new RegExp(`^[ \\t]*(?:const\\s+|var\\s+)?${name}(?:\\s+[A-Za-z_][\\w.\\[\\]\\*]*)?\\s*=\\s*"([^"]*)"$`, 'm'))
  if (!m) throw new Error(`goConstString: ${repoPath} 未解析到常量声明 ${name}`)
  return m[1]!
}

test('预设档位：标准档==后端 db 默认（跨栈对账，存量无感）', () => {
  const std = AUTOBAN_PRESETS.standard
  assert.equal(std.threshold, goConstInt('internal/db/db.go', 'DefaultAutobanThreshold'))
  assert.equal(std.window_minutes, goConstInt('internal/db/db.go', 'DefaultAutobanWindowMinutes'))
  assert.equal(std.counting_mode, 'classic')
  // 标准档 scope=四全选（与 DefaultAutobanScope 同集合）。
  assert.deepEqual([...std.scope].sort(), ['blocked', 'challenge_failed', 'challenge_issued', 'logged'])
  // 全字段对账：时长/升级档/倍率/打底比例逐项对齐 db 默认——
  // 任一漂移会让「存量配置」显示为「自定义」，或选预设静默改变升级语义。
  assert.equal(std.duration, goConstString('internal/db/db.go', 'DefaultAutobanDuration'))
  assert.equal(std.escalation, goConstString('internal/db/db.go', 'DefaultAutobanEscalation'))
  assert.equal(std.suspicion_multiplier, goConstInt('internal/db/db.go', 'DefaultAutobanSuspicionMultiplier'))
  assert.equal(std.confirm_floor_ratio, goConstString('internal/db/db.go', 'DefaultAutobanConfirmFloorRatio'))
  // 不静默启用累犯升级：db 默认 off，标准档必须同为 off（选中预设不得改变
  // 升级语义）。
  assert.equal(std.escalation, 'off')
})

test('预设档位：强化档=evidence+阈值减半+standard 升级', () => {
  const enh = AUTOBAN_PRESETS.enhanced
  assert.equal(enh.counting_mode, 'evidence')
  assert.equal(enh.threshold, 50)
  assert.equal(enh.escalation, 'standard')
  assert.equal(enh.suspicion_multiplier, 4)
  assert.equal(enh.confirm_floor_ratio, '0.4')
})

test('预设档位：保守档=只计确证口径+不升级', () => {
  const con = AUTOBAN_PRESETS.conservative
  assert.deepEqual([...con.scope].sort(), ['blocked', 'challenge_failed'])
  assert.equal(con.escalation, 'off')
  assert.equal(con.counting_mode, 'classic')
})

test('matchAutobanPreset：整组相等命中档位；改任一参数落自定义', () => {
  for (const id of AUTOBAN_PRESET_IDS) {
    assert.equal(matchAutobanPreset({ ...AUTOBAN_PRESETS[id], scope: [...AUTOBAN_PRESETS[id].scope] }), id)
  }
  // 改阈值 → 自定义
  assert.equal(matchAutobanPreset({ ...AUTOBAN_PRESETS.standard, threshold: 999 }), null)
  // 改 scope 成员 → 自定义
  assert.equal(matchAutobanPreset({ ...AUTOBAN_PRESETS.standard, scope: ['blocked'] }), null)
  // 改计数模式 → 自定义
  assert.equal(matchAutobanPreset({ ...AUTOBAN_PRESETS.standard, counting_mode: 'evidence' }), null)
})

test('参数域与后端校验单源同口径（跨栈对表）', () => {
  const backend = repoCode('internal/services/autoban.go')
  assert.equal(AUTOBAN_SUSPICION_MULTIPLIER_MIN, goConstInt('internal/services/autoban.go', 'AutobanSuspicionMultiplierMin'))
  assert.equal(AUTOBAN_SUSPICION_MULTIPLIER_MAX, goConstInt('internal/services/autoban.go', 'AutobanSuspicionMultiplierMax'))
  // 打底枚举三档与后端 map 同集合。
  const floorMap = section(backend, 'var autobanConfirmFloorRatios', '\n\n')
  for (const f of AUTOBAN_CONFIRM_FLOOR_RATIOS) {
    assert.ok(floorMap.includes(`"${f}": true`), `后端缺打底档 ${f}`)
  }
  assert.deepEqual([...AUTOBAN_CONFIRM_FLOOR_RATIOS].sort(), ['0.2', '0.4', '0.6'])
})

test('升级阶梯预览：standard 首封→24h→永久；aggressive 首封→永久；off 恒固定', () => {
  assert.deepEqual(autobanEscalationLadder({ duration: '1h', escalation: 'standard' }), ['1h', '24h', 'permanent'])
  assert.deepEqual(autobanEscalationLadder({ duration: '1h', escalation: 'aggressive' }), ['1h', 'permanent', 'permanent'])
  assert.deepEqual(autobanEscalationLadder({ duration: '6h', escalation: 'off' }), ['6h', '6h', '6h'])
  // permanent 配置恒永久（与后端兜底同口径）。
  assert.deepEqual(autobanEscalationLadder({ duration: 'permanent', escalation: 'standard' }), ['permanent', 'permanent', 'permanent'])
})
