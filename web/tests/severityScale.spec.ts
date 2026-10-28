// anomaly_score 危险分档单源验收：事件列表评分着色与大屏定级必须同阈值，
// 且大屏的两段动作语义（检测模式降级、0 分行回退族）按行为断言。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { repoCode, section, code, stripComments } from './_helpers.ts'
import {
  ANOMALY_SCORE_HIGH,
  ANOMALY_SCORE_MID,
  GEOIP_CRAWLER_EXEMPT_BASE,
  GEOIP_CRAWLER_SPOOF_BASE,
  GEOIP_PRECHECK_LIMIT,
  ZERO_SCORE_PRECHECK_IDS,
  anomalySeverity,
  overlayDetectionGrade,
  zeroScoreSeverity,
} from '../src/utils/severityScale.ts'

test('分档阈值：≥12 高 / ≥6 中 / 其余低（2026-10-17 大屏裁定口径）', () => {
  assert.equal(ANOMALY_SCORE_HIGH, 12)
  assert.equal(ANOMALY_SCORE_MID, 6)
  assert.equal(anomalySeverity(12), 'high')
  assert.equal(anomalySeverity(11), 'mid')
  assert.equal(anomalySeverity(6), 'mid')
  assert.equal(anomalySeverity(5), 'low')
  assert.equal(anomalySeverity(0), 'low')
})

test('事件列表评分着色引用同一阈值（不得回流 15/5 双口径）', () => {
  const events = code('src/views/security/SecurityEvents.vue')
  const column = section(events, '<el-table-column label="评分"', '</el-table-column>')
  assert.match(column, /row\.anomaly_score >= ANOMALY_SCORE_HIGH/)
  assert.match(column, /row\.anomaly_score >= ANOMALY_SCORE_MID/)
  assert.doesNotMatch(column, /anomaly_score >= 15/, '列表旧阈值不得回流')
  assert.doesNotMatch(column, /anomaly_score >= 5"/, '列表旧阈值不得回流')
})

test('检测模式降级梯：拦截事件保持原档，未拦截整体降一级（高→中、中→低、低保持）', () => {
  assert.equal(overlayDetectionGrade('high', 'blocked'), 'high')
  assert.equal(overlayDetectionGrade('mid', 'blocked'), 'mid')
  assert.equal(overlayDetectionGrade('low', 'blocked'), 'low')
  assert.equal(overlayDetectionGrade('high', 'logged'), 'mid', '检测模式高必须降为中')
  assert.equal(overlayDetectionGrade('mid', 'detected'), 'low', '检测模式中必须降为低')
  assert.equal(overlayDetectionGrade('low', 'detected'), 'low')
  // 与评分分档叠加后的整链：12 分未拦截=中危、6 分未拦截=低危
  assert.equal(overlayDetectionGrade(anomalySeverity(ANOMALY_SCORE_HIGH), 'detected'), 'mid')
  assert.equal(overlayDetectionGrade(anomalySeverity(ANOMALY_SCORE_MID), 'detected'), 'low')
})

test('0 分行回退族：预检固定族（含 4/7）高危，GeoIP 三族按段界分档，其余按动作分中低', () => {
  // 固定预检族（与后端 Stage1PrecheckIDSQLList 去 GeoIP id 8 同集合）：
  // 4=遗留黑名单、7=白名单外拒绝——升级前的历史 0 分拦截行若落兜底会被定成
  // 中危并从大屏「高危」筛选中漏掉；5 为绕过模式信任并集（pass,nolog 不产事件）。
  for (const ruleTriggered of ZERO_SCORE_PRECHECK_IDS) {
    assert.equal(zeroScoreSeverity(ruleTriggered, 'blocked'), 'high', `${ruleTriggered} 拦截应为高危`)
    assert.equal(zeroScoreSeverity(ruleTriggered, 'detected'), 'mid', `${ruleTriggered} 检测模式降为中危`)
  }
  // 普通 GeoIP `[800000,810000)`：后端补分 6（中危），检测模式不再二次下调
  for (const ruleTriggered of ['8', '800001', '809999']) {
    assert.equal(zeroScoreSeverity(ruleTriggered, 'blocked'), 'mid', `${ruleTriggered} 为普通 GeoIP 中危`)
    assert.equal(zeroScoreSeverity(ruleTriggered, 'detected'), 'mid', '存量行检测模式不再二次下调')
  }
  // 爬虫伪装 `[850000,900000)`：后端补分 12（高危），与 12 分族同档
  for (const ruleTriggered of ['850000', '850001', '899999']) {
    assert.equal(zeroScoreSeverity(ruleTriggered, 'blocked'), 'high', `${ruleTriggered} 爬虫伪装应为高危`)
    assert.equal(zeroScoreSeverity(ruleTriggered, 'detected'), 'mid', '检测模式高→中')
  }
  // 爬虫豁免 `[810000,850000)`：后端补分 0（已验证爬虫放行=审计轨迹），
  // 不得被抬成中危；检测/拦截两种动作都不抬档
  for (const ruleTriggered of ['810000', '810001', '849999']) {
    assert.equal(zeroScoreSeverity(ruleTriggered, 'blocked'), 'low', `${ruleTriggered} 爬虫豁免应为低危`)
    assert.equal(zeroScoreSeverity(ruleTriggered, 'detected'), 'low')
  }
  // 8 族边界：必须恰好 8 后跟 5 位（8xxxxx），5 位/7 位落入兜底
  assert.equal(zeroScoreSeverity('80000', 'blocked'), 'mid', '非 8 族兜底=拦截中危')
  assert.equal(zeroScoreSeverity('8000000', 'detected'), 'low', '7 位不是 8xxxxx，走兜底检测低危')
  assert.equal(zeroScoreSeverity('900000', 'blocked'), 'mid', '900000 是右开界，落入普通兜底而非爬虫高危')
  // 兜底按动作区分；429 不产生安全事件行，同样只落兜底
  assert.equal(zeroScoreSeverity('', 'blocked'), 'mid')
  assert.equal(zeroScoreSeverity('', 'detected'), 'low')
  assert.equal(zeroScoreSeverity('429', 'blocked'), 'mid')
  // 481-484 是 HTTP 阻断状态码而非 rule_triggered 值：不得被当作高危族
  assert.equal(zeroScoreSeverity('481', 'blocked'), 'mid')
  assert.equal(zeroScoreSeverity('483', 'detected'), 'low')
})

// 段界是跨栈契约：前端按段界分族，后端按同一编码发射 id。任一侧单改一侧
// 会让大屏颜色与事件列表评分打架（899999 曾被当成普通 GeoIP 中危）。
test('8xxxxx 三族段界与后端 encode/decode 及入库补分同源（跨栈钉）', () => {
  const go = repoCode('internal/services/security.go')
  assert.match(go, /geoipPrecheckRuleBase\s*=\s*800000/, '普通 GeoIP 段基址漂移')
  assert.match(go, /geoipCrawlerRuleBase\s*=\s*810000/, '爬虫豁免段基址漂移')
  assert.match(go, /geoipCrawlerSpoofRuleBase\s*=\s*850000/, '爬虫伪装段基址漂移')
  assert.match(go, /geoipPrecheckRuleLimit\s*=\s*900000/, '预检段右开界漂移')
  assert.equal(GEOIP_CRAWLER_EXEMPT_BASE, 810000)
  assert.equal(GEOIP_CRAWLER_SPOOF_BASE, 850000)
  assert.equal(GEOIP_PRECHECK_LIMIT, 900000)

  // 入库补分：豁免=0（不计威胁）、伪装=12、普通 GeoIP=6
  const events = repoCode('internal/services/securityevents.go')
  assert.match(events, /case securityEventsIsCrawlerExemptRule\(rec\.RuleTriggered\):\s*rec\.AnomalyScore = 0/)
  assert.match(events, /case securityEventsIsCrawlerSpoofRule\(rec\.RuleTriggered\):\s*rec\.AnomalyScore = 12/)
  assert.match(events, /case securityEventsIsGeoIPScoringRule\(rec\.RuleTriggered\):\s*rec\.AnomalyScore = 6/)
})

// 固定族同样是跨栈契约：前端 0 分行回退与后端入库补分（securityEventsIsPrecheckRule
// → 12 分）必须同集合。后端单一事实源 = Stage1PrecheckIDSQLList（与
// IsStage1PrecheckID / IsStage1PrecheckEventID 同文件维护，Go 侧三集合对账钉死）；
// GeoIP 的固定 id 8 由前端段界分支单独处理，不在固定族里。新增/删除预检 id 时
// 任一侧漏改即在此失败（原先前端手抄 2/3/12/14 漏掉 4/7）。
test('0 分行固定预检族与后端 Stage1PrecheckIDSQLList 同集合（跨栈对表）', () => {
  const go = repoCode('internal/services/security.go')
  const decl = /Stage1PrecheckIDSQLList = "\(([^)]*)\)"/.exec(go)
  const raw = decl ? decl[1] : ''
  assert.match(raw, /^'\d+'(,'\d+')*$/, '后端 Stage1PrecheckIDSQLList 声明形态漂移（跨栈对表失去锚点）')
  const backendIDs = raw.split(',').map((token) => token.replace(/'/g, ''))
  assert.ok(backendIDs.length >= 8, `后端清单解析不完整：${raw}`)
  assert.ok(backendIDs.includes('8'), 'GeoIP 固定 id 8 必须在后端清单内')

  const backendFixed = backendIDs.filter((id) => id !== '8')
  assert.deepEqual(
    [...ZERO_SCORE_PRECHECK_IDS].sort((a, b) => Number(a) - Number(b)),
    [...backendFixed].sort((a, b) => Number(a) - Number(b)),
    '前端 0 分行固定族必须与后端预检固定清单（去 GeoIP id 8）同集合',
  )

  // 后端 Go 谓词是入库补分的判定源：固定族 {2,4,7,8,14} ∪ GeoIP 段；
  // 预检族 0 分行补 12（高危）——前端 blocked→high 与之一致。
  assert.match(go, /func IsStage1PrecheckID\(n int\) bool \{\s*switch n \{\s*case 2, 4, 7, 8, 14:/)
  const events = repoCode('internal/services/securityevents.go')
  assert.match(events, /return IsStage1PrecheckEventID\(n\)/)
  assert.match(events, /case securityEventsIsPrecheckRule\(rec\.RuleTriggered\):\s*rec\.AnomalyScore = 12/)
})

test('大屏定级只做取值：视图不重写分档/降级语义', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  const sevCode = stripComments(section(screen, 'function sevOf(', '\nfunction sevLabel'))
  assert.match(sevCode, /anomalySeverity\(score\)/, '分级本体必须走单源函数')
  assert.match(sevCode, /overlayDetectionGrade\(/, '检测模式降级必须走单源函数')
  assert.match(sevCode, /zeroScoreSeverity\(/, '0 分行回退必须走单源函数')
  assert.doesNotMatch(sevCode, /score >= 12|score >= 6|ANOMALY_SCORE_/, '不得内联阈值')
  assert.doesNotMatch(sevCode, /return base === 'high' \? 'mid' : 'low'/, '降级梯不得回流视图')
  assert.doesNotMatch(sevCode, /rt === '8'|\^8\\d\{5\}\$/, '0 分行回退族不得回流视图')
  assert.doesNotMatch(sevCode, /'429'/, '429 不进事件表，回退分支不可达')
})
