// 事件「触发规则」筛选序列化行为验收
// 原实现内联在 SecurityEvents.fetchEvents，只有源码文本钉；本测试钉住可观察契约：
// 空选/全选不发参数、子集按族段展开、自定义 tag 原样并入、段序稳定。
//
// 后端契约：internal/handlers/security.go ruleTriggeredFamilyPrefixes（逐段 OR）。
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  TRIGGERED_CATEGORIES,
  TRIGGERED_FAMILY_SEGMENTS,
  serializeTriggeredFilter,
} from '../src/utils/triggeredFilter.ts'
import { code, openTags, repoCode, section } from './_helpers.ts'

test('空选 = 不过滤（不发 rule_triggered）', () => {
  assert.equal(serializeTriggeredFilter([]), null)
})

test('八类全中且无自定义 tag = 全选，不发参数', () => {
  assert.equal(serializeTriggeredFilter([...TRIGGERED_CATEGORIES]), null)
  // 重复选中不应破坏全选判定
  assert.equal(serializeTriggeredFilter([...TRIGGERED_CATEGORIES, 'WAF·CRS']), null)
})

test('类别子集按族段展开（段序 = 选中顺序）', () => {
  assert.equal(serializeTriggeredFilter(['WAF·CRS']), 'WAF·CRS')
  assert.equal(serializeTriggeredFilter(['信任名单', '地域拦截']), '信任名单,地域拦截')
  // WAF·自定义 保留双段（后端两 token 同族，历史契约）
  assert.equal(serializeTriggeredFilter(['WAF·自定义']), 'WAF·自定义,自定义规则')
})

test('七类子集（缺一类）视为过滤而非全选', () => {
  const missingOne = TRIGGERED_CATEGORIES.filter((c) => c !== '请求体异常')
  assert.equal(serializeTriggeredFilter(missingOne), '爬虫Bot,地域拦截,IP 访问控制,信任名单,威胁情报库,WAF·CRS,WAF·自定义,自定义规则')
})

test('自定义 tag 原样并入末尾（CRS 规则 ID / 消息关键词）', () => {
  assert.equal(serializeTriggeredFilter(['WAF·CRS', '942100']), 'WAF·CRS,942100')
  // 八类全中 + 自定义 tag = 仍需发送（只发自定义 tag，类别段全展开）
  const allPlusCustom = serializeTriggeredFilter([...TRIGGERED_CATEGORIES, '942100'])
  assert.ok(allPlusCustom !== null)
  assert.ok(allPlusCustom.endsWith(',942100'))
  assert.ok(allPlusCustom.includes('WAF·CRS'))
})

test('只有自定义 tag 时不产生类别段', () => {
  assert.equal(serializeTriggeredFilter(['942100']), '942100')
})

test('每个类别的族段非空且与后端 family 键同名（除已登记的双段类别）', () => {
  for (const category of TRIGGERED_CATEGORIES) {
    const segments = TRIGGERED_FAMILY_SEGMENTS[category]
    assert.ok(segments.length > 0, `${category} 必须有族段`)
    for (const segment of segments) assert.ok(segment.trim() !== '', `${category} 段不得为空`)
  }
})

test('族段跨栈对表：前端段必须是后端 ruleTriggeredFamilyPrefixes 键或特判段（机械钉）', () => {
  // 后端遇未知段落到消息回退分支（rule_triggered LIKE ? OR rule_msg LIKE ?）——
  // 段名打错一字筛选即从「该族全部事件」退化为「消息含该串的事件」，纯前端
  // 断言无法发现；必须读 Go 源对表。
  const go = repoCode('internal/handlers/security.go')
  // 后端键 = 手写形态族（buildRuleTriggeredFamilyPrefixes 的 families 字面量）
  // ∪ 单 ID 族（由 legacyRuleFamilies 表派生，key 即族键）——两侧都要读，
  // 只看字面量会在单 ID 族改名时假绿。
  const build = section(go, 'func buildRuleTriggeredFamilyPrefixes() map[string][]string {', '\n}')
  const backendKeys = new Set([...build.matchAll(/"([^"]+)":\s*\{/g)].map((m) => m[1]))
  const table = section(go, 'var legacyRuleFamilies = map[int]legacyRuleFamily{', '\n}')
  for (const [, key] of table.matchAll(/\{key:\s*"([^"]+)"/g)) backendKeys.add(key)
  assert.ok(backendKeys.size >= 8, `后端 family 键解析异常（仅 ${backendKeys.size} 个）`)
  // 「WAF·CRS」为复合 GLOB 特判段（ruleTriggeredFilterSQL 内单独匹配，不在前缀表）
  assert.ok(go.includes('if input == "WAF 规则（CRS）" || input == "WAF·CRS"'), 'WAF·CRS 特判段缺失')
  const frontendSegments = [...new Set(Object.values(TRIGGERED_FAMILY_SEGMENTS).flat())]
  for (const segment of frontendSegments) {
    assert.ok(
      backendKeys.has(segment) || segment === 'WAF·CRS',
      `前端族段「${segment}」在后端 family 键中不存在——筛选会退化为消息关键词匹配`,
    )
  }
  // 反向：后端删除前端依赖的键也必须红（八类除 WAF·CRS 外每个键都在表中）
  for (const category of TRIGGERED_CATEGORIES) {
    if (category === 'WAF·CRS') continue
    for (const segment of TRIGGERED_FAMILY_SEGMENTS[category]) {
      assert.ok(backendKeys.has(segment), `后端缺「${segment}」键（前端「${category}」类别依赖）`)
    }
  }
})

test('事件页「全选」是并集语义：保留自定义规则 ID（不得静默丢弃用户输入）', () => {
  // 该控件 allow-create，用户可输入 CRS 规则 ID（如 942100）。头部「全选」若用
  // 替换语义（checked ? [...八类] : []），半选态点「全选」会把自定义 tag 丢掉，
  // 筛选结果集被改写而界面只表现为「勾上了全选」。
  const page = code('src/views/security/SecurityEvents.vue')
  // allow-create 必须落在绑定 `filters.rule_triggered` 的**同一个** el-select 上：
  // 距离窗口（≤400 字符）会把页面别处的另一个 el-select 的 allow-create 算进来。
  const triggerSelect = openTags(page, 'el-select').find((tag) => tag.includes('v-model="filters.rule_triggered"'))
  assert.ok(triggerSelect !== undefined, '触发阶段筛选项必须绑定 filters.rule_triggered')
  assert.match(triggerSelect, /\sallow-create(?:\s|\/?>)/, '该筛选必须允许自定义 tag（本用例的前提）')
  const toggle = section(page, 'const toggleTriggeredAll = (checked: CheckboxValueType) => {', '\n}')
  assert.match(
    toggle,
    /filter\(\(v\) => !\(TRIGGERED_CATEGORIES as readonly string\[\]\)\.includes\(v\)\)/,
    '必须先摘出自定义 tag（非八类值）',
  )
  assert.match(
    toggle,
    /checked \? \[\.\.\.TRIGGERED_CATEGORIES, \.\.\.custom\] : custom/,
    '全选=八类并入当前选择、取消=只摘八类（替换语义会静默丢弃自定义 tag）',
  )
  // 保留后的选择必须真的落到查询参数：八类全中 + 自定义 tag ≠ 全选，参数含该 ID
  const afterSelectAll = [...TRIGGERED_CATEGORIES, '942100']
  assert.match(serializeTriggeredFilter(afterSelectAll) ?? '', /942100/, '保留的自定义 tag 必须进入 rule_triggered')
})
