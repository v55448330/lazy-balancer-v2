// 触发 id → 阶段族映射行为验收：逐项对照后端 v2.3.8 权威分类
//   internal/handlers/security.go attackFamilyClassOf（ID 形态）
//   internal/handlers/security.go legacyRuleFamilies（固定 SecRule id 族单表）
//   internal/handlers/security_threat_screen.go triggerTypeForRule（数值段）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { detectionModeExplains, triggerStageFamily, type TriggerStageFamily } from '../src/utils/securityStages.ts'
import { code, repoCode, section } from './_helpers.ts'

const cases: ReadonlyArray<readonly [string, TriggerStageFamily]> = [
  // 空 / 请求体异常 / 威胁情报 / 信任（id:5 = 绕过模式占用 id:3 时的信任名单并集）
  ['', 'other'],
  ['11', 'body'],
  ['14', 'threat'],
  ['3', 'trust'],
  ['5', 'trust'],
  ['12', 'trust'],
  // 自定义规则：5 位任意（含 9 开头——5 位恒自定义，CRS 恒 6 位）
  ['10000', 'wafCustom'],
  ['12345', 'wafCustom'],
  ['92000', 'wafCustom'],
  ['99999', 'wafCustom'],
  // 自定义规则：6 位 1-7 开头（DB id 10000-789999 发射 id+10000）——原实现落 other
  ['100000', 'wafCustom'],
  ['499999', 'wafCustom'],
  ['700000', 'wafCustom'],
  ['799999', 'wafCustom'],
  // 自定义规则：≥7 位 1 开头（无 id 规则合成 1000000+n）
  ['1000000', 'wafCustom'],
  ['1999999', 'wafCustom'],
  // CRS：6 位 9 开头
  ['900000', 'wafCrs'],
  ['942100', 'wafCrs'],
  ['959999', 'wafCrs'],
  // 地域 [800000,810000)
  ['800000', 'geoip'],
  ['800012', 'geoip'],
  ['809999', 'geoip'],
  // 爬虫两族 [810000,900000)：豁免 / 伪装——原实现误归 geoip
  ['810000', 'crawler'],
  ['825000', 'crawler'],
  ['849999', 'crawler'],
  ['850000', 'crawler'],
  ['899999', 'crawler'],
  // IP 访问控制
  // （有意设计登记）：'8' 与后端 legacyRuleFamilies（8→地域拦截）不同——
  // 历史共享 id，现代引擎地域事件改发 800xxx，本例外无现实影响且被刻意钉住；
  // 例外集合由下方「legacyRuleFamilies 单表派生」用例显式登记。
  ['2', 'ipAcl'],
  ['4', 'ipAcl'],
  ['7', 'ipAcl'],
  ['8', 'ipAcl'],
  // 其他（429 限流在列表层单独处理，非阶段族）
  ['429', 'other'],
  ['abc', 'other'],
]

test('triggerStageFamily 与后端权威分类逐项一致', () => {
  for (const [id, expected] of cases) {
    assert.equal(triggerStageFamily(id), expected, `id=${JSON.stringify(id)}`)
  }
})

test('爬虫段与地域段互斥（不重叠）', () => {
  // 边界：809999 地域 / 810000 爬虫 / 899999 爬虫 / 900000 CRS
  assert.equal(triggerStageFamily('809999'), 'geoip')
  assert.equal(triggerStageFamily('810000'), 'crawler')
  assert.equal(triggerStageFamily('899999'), 'crawler')
  assert.equal(triggerStageFamily('900000'), 'wafCrs')
})

test('首尾空白归一（事件字段可能带导入残留空白）', () => {
  assert.equal(triggerStageFamily(' 11 '), 'body')
  assert.equal(triggerStageFamily(' 850123 '), 'crawler')
})

// 「所属策略为检测模式：命中只记录」的文案归因门：DetectionOnly
// （id:6）在 ACL/黑名单/自定义规则之后、CRS 与请求体规则之前发射——只有 WAF 族
// 的 logged 可由检测模式解释；阶段 1 族的 logged 成因是信任保留检测（id:3/12），
// 归因「检测模式」会掩盖真正的豁免策略。
test('检测模式归因：仅 WAF 族（CRS/自定义含 body 目标）', () => {
  for (const kind of ['waf-crs', 'waf-custom']) assert.equal(detectionModeExplains(kind), true, kind)
  for (const kind of ['acl', 'geo', 'crawler', 'threat', 'trust', 'body', 'other', '']) {
    assert.equal(detectionModeExplains(kind), false, kind)
  }
})

test('段界与形态分支跨栈对表（后端段界/分支调整必须红）', () => {
  // 段界单一事实源 = services/security.go 段基址常量；attackFamilyClassOf 是
  // 形态判定的唯一入口（固定 id 族的族归属已收敛到 legacyRuleFamilies，
  // 由下一条用例逐 id 对表）。
  const svc = repoCode('internal/services/security.go')
  // 值正则口径（与 severityScale.spec.ts 同）：常量名与 `=` 之间的对齐空白属于
  // gofmt 的排版产物——同 const 块新增/改名一个常量就会重排空白，段界值一个没
  // 变却触发「段界漂移」假红。
  const stageBases: ReadonlyArray<readonly [string, number]> = [
    ['geoipPrecheckRuleBase', 800000],
    ['geoipCrawlerRuleBase', 810000],
    ['geoipCrawlerSpoofRuleBase', 850000],
  ]
  for (const [name, value] of stageBases) {
    assert.match(svc, new RegExp(`\\b${name}\\s*=\\s*${value}\\b`), `段界常量漂移：${name} 应为 ${value}`)
  }
  const handler = repoCode('internal/handlers/security.go')
  const fn = section(handler, 'func attackFamilyClassOf(', '\n}')
  for (const anchor of [
    'case len(ruleTriggered) == 5:',
    "case len(ruleTriggered) == 6 && ruleTriggered[0] >= '1' && ruleTriggered[0] <= '7':",
    'case strings.HasPrefix(ruleTriggered, "1") && len(ruleTriggered) >= 7:',
    'legacyFamily := legacyRuleFamily{}',
    'case legacyFamily.class == attackFamilyTrust:',
  ]) {
    assert.ok(fn.includes(anchor), `attackFamilyClassOf 分支锚漂移：${anchor}`)
  }
  // 筛选表（ruleTriggeredFamilyPrefixes）的单 ID 族必须仍由该表派生——
  // 前端段名与该表键同词，表被改回逐条字面量会让族筛选与触发类型再次分叉。
  const build = section(handler, 'func buildRuleTriggeredFamilyPrefixes() map[string][]string {', '\n}')
  assert.match(build, /legacyRuleFamilies\[id\]\.key/, '筛选表必须由 legacyRuleFamilies 派生')
})

// 固定 id 的族归属单一事实源 = legacyRuleFamilies（事件列表触发类型 / 总览攻击族
// / 事件页族筛选 / 大屏命中标签四处派生）。逐 id 对表而不是逐条抄写：表改族而
// 前端未同步、或前端自造映射，都在此变红（曾把 id:5 的分叉钉进用例当契约）。
const GO_KEY_TO_FAMILY: Readonly<Record<string, TriggerStageFamily>> = {
  'IP 访问控制': 'ipAcl',
  '信任名单': 'trust',
  '地域拦截': 'geoip',
  '威胁情报库': 'threat',
  '请求体异常': 'body',
  // 限流（429）：后端有族键，但无 sec_events 数据源、列表层不设类别与阶段桶
  // （见 triggeredFilter 的固定八类），本函数的阶段族归 other。
  '限流': 'other',
}

// 前端有意的阶段族例外（必须显式登记；除下列 id 外一律按后端表取值）：
// 存量 id 8 按历史共享 id 口径归 IP 访问控制——SecurityEvents.stageLabel 另有
// 「地域拦截（旧 id）」中和文案，现代引擎地域事件改发 800xxx，仅历史/带外
// 数据可见；不按「与后端同步」改回 geoip。
const FRONTEND_FAMILY_EXCEPTIONS: Readonly<Record<string, TriggerStageFamily>> = { '8': 'ipAcl' }

test('存量 id 8 在事件列表与触发详情都标为地域拦截（旧 id）', () => {
  const list = code('src/views/security/SecurityEvents.vue')
  const detail = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(list, /地域拦截（旧 id）/)
  assert.match(detail, /rule_triggered \?\? ''\) === '8'|rule_triggered === '8'/, '详情必须识别存量 id 8')
  assert.match(detail, /地域拦截（旧 id）/, '详情不得再把同一事件写成 IP 黑白名单')
})

test('固定 id 族归属从后端 legacyRuleFamilies 单表派生（改族即红）', () => {
  const handler = repoCode('internal/handlers/security.go')
  const table = section(handler, 'var legacyRuleFamilies = map[int]legacyRuleFamily{', '\n}')
  const entries = [...table.matchAll(/^\s*(\d+):\s*\{key:\s*"([^"]+)"/gm)]
  assert.ok(entries.length >= 10, `legacyRuleFamilies 解析异常（仅 ${entries.length} 条）`)
  for (const [, id, key] of entries) {
    const goFamily = GO_KEY_TO_FAMILY[key]
    assert.ok(goFamily, `后端族键「${key}」未在 GO_KEY_TO_FAMILY 登记（新增族需先定前端投影）`)
    const expected = FRONTEND_FAMILY_EXCEPTIONS[id] ?? goFamily
    assert.equal(triggerStageFamily(id), expected, `id=${id} 后端族「${key}」`)
  }
  // 信任族三兄弟必须都在表内（id:5 是绕过模式占位，曾按 ACL 记账）
  for (const id of ['3', '5', '12']) {
    assert.ok(entries.some(([, entryId]) => entryId === id), `后端表缺信任族 id:${id}`)
    assert.equal(triggerStageFamily(id), 'trust', `id:${id} 必须归信任名单`)
  }
  // 例外集合 = 登记值；新增例外必须显式写进 FRONTEND_FAMILY_EXCEPTIONS
  assert.deepEqual(Object.keys(FRONTEND_FAMILY_EXCEPTIONS).sort(), ['8'])
})
