// 请求速率阈值的界面口径契约。
//
// 引擎判据：同一规则 × 同一 IP 的统计窗口（W 秒，从该 IP 首个请求起算，满窗口
// 重置）内累计请求 > N×W 次才发起挑战。界面此前把阈值写成「N 次 / W 秒」——读起来
// 是「W 秒内 N 次」，比实际严格 W 倍（默认 40×10 时差 10 倍）。四处渲染点（向导
// 表单、策略列表摘要、策略投影行、触发详情弹框）必须同口径：N 次/秒 + 窗口内
// 总数 N×W。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'
import { ccWindowBudget } from '../src/utils/securityStages.ts'

const zhSec = code('src/locales/zh/security.ts')
const enSec = code('src/locales/en/security.ts')
const zhView = code('src/locales/zh/views.ts')
const enView = code('src/locales/en/views.ts')
const policies = code('src/views/security/SecurityPolicies.vue')
const stages = code('src/utils/securityStages.ts')
const trigDetail = code('src/components/events/TriggerDetailDialog.vue')

test('窗口预算 = 速率 × 窗口秒数；缺值按 0，不产生 NaN', () => {
  assert.equal(ccWindowBudget(40, 10), 400)
  assert.equal(ccWindowBudget(1, 1), 1)
  assert.equal(ccWindowBudget(0, 10), 0)
  assert.equal(ccWindowBudget(undefined, undefined), 0)
  assert.equal(ccWindowBudget(undefined, 30), 0)
})

test('向导表单：标签表达速率语义，后缀自明单位，窗口内总数实时算出', () => {
  assert.match(zhSec, /"ccRpsLabel": "请求速率阈值"/, '标签不得再叫「突刺阈值」（它表达的是速率）')
  assert.match(zhSec, /"ccRpsPer": "次\/秒 ×"/)
  assert.match(zhSec, /"ccRpsSec": "秒窗口"/)
  assert.match(zhSec, /"ccRpsExplain": "[^"]*\{sec\}[^"]*\{total\}[^"]*"/, '说明必须写明「{sec} 秒内累计超过 {total} 次」')
  assert.match(zhSec, /"ccRpsExplain": "[^"]*一次页面加载的瞬时并发不会触发[^"]*"/)
  assert.match(zhSec, /"ccRpsGuide": "/, '参考值引导必须在位')
  assert.doesNotMatch(zhSec, /"ccRpsPer": "次 \/"/, '旧后缀「次 /」把速率读成「W 秒内 N 次」')
  assert.match(enSec, /"ccRpsLabel": "Request rate threshold"/)
  assert.match(enSec, /"ccRpsExplain": "[^"]*\{total\}[^"]*"/)
  assert.match(enSec, /"ccRpsGuide": "/)
  // 页面：说明行经 ccWindowBudget 给出 total，参考值独占一行块级描述
  assert.match(policies, /human\.ccRpsExplain', \{[^}]*total: ccWindowBudget\(form\.cc_rps_limit, form\.cc_rps_window\)/)
  assert.match(policies, /class="form-tip-line">\{\{ t\('app\.security\.policies\.human\.ccRpsGuide'\) \}\}<\/div>/)
})

test('四处渲染点同口径：列表摘要 / 投影行 / 触发详情都给出 N×W', () => {
  assert.match(zhSec, /"ccSpike": "请求速率 \{n\} 次\/秒（\{sec\} 秒内 >\{total\} 次）"/)
  assert.match(zhView, /'ccSpikeRowLabel': '请求速率'/)
  assert.match(zhView, /'ccSpikeSummary': '\{n\} 次\/秒 · \{sec\} 秒内 >\{total\} 次'/)
  assert.match(zhView, /'ccSpikeValue': '\{n\} 次\/秒 · \{sec\} 秒内 >\{total\} 次'/)
  assert.match(enSec, /"ccSpike": "[^"]*\{total\}[^"]*"/)
  assert.match(enView, /'ccSpikeSummary': '[^']*\{total\}[^']*'/)
  assert.match(enView, /'ccSpikeValue': '[^']*\{total\}[^']*'/)
  assert.doesNotMatch(zhView, /\{n\} 次 \/ \{sec\} 秒/, '投影/详情不得再把速率写成「N 次 / W 秒」')
  assert.match(policies, /summary\.ccSpike', \{[^}]*total: ccWindowBudget\(row\.cc_rps_limit, row\.cc_rps_window\)/)
  assert.match(stages, /stages\.ccSpikeSummary', \{ n: policy\.cc_rps_limit \?\? 0, sec: policy\.cc_rps_window \?\? 0, total: ccWindowBudget\(policy\.cc_rps_limit, policy\.cc_rps_window\) \}\)/)
  assert.match(trigDetail, /trigDetail\.ccSpikeValue', \{ n: policy\.cc_rps_limit \?\? 0, sec: policy\.cc_rps_window \?\? 0, total: ccWindowBudget\(policy\.cc_rps_limit, policy\.cc_rps_window\) \}\)/)
})
