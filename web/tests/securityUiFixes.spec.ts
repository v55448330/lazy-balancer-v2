import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code } from './_helpers.ts'

test('任务监控：KPI 不再显示证书工作项括注，筛选组右对齐，操作列保持单行', () => {
  const page = code('src/views/settings/TaskMonitor.vue')
  assert.doesNotMatch(page, /（不含证书工作项）|（含证书工作项）/)
  assert.match(page, /<div class="tm-filter-group">/)
  assert.match(page, /class-name="tm-op-cell"/)
  assert.match(page, /\.tm-filter-group \{ display: flex; align-items: center; gap: 10px; margin-left: auto; \}/)
  assert.match(page, /\.tm-nowrap-table \.tm-op-cell \.cell\) \{ display: flex; flex-wrap: nowrap;/)
  assert.match(page, /\.tm-nowrap-table \.tm-op-cell \.el-button\) \{ margin-left: 0; \}/)
  assert.doesNotMatch(page, /<el-tooltip[\s\S]{0,300}<div>\s*<el-button[\s\S]{0,120}>运行<\/el-button>/)
})

test('安全总览 Top10 源 IP 展示近 10 分钟/近 1 小时频率', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /recent_10m: number; recent_1h: number/)
  assert.doesNotMatch(page, /prop="frequency"/)
  assert.match(page, /prop="blocked" label="拦截" width="100"/)
  assert.match(page, /prop="detected" label="检测" width="100"/)
  assert.match(page, /prop="recent_10m" label="近10分钟" width="120"/)
  assert.match(page, /prop="recent_1h" label="近1小时" width="128"/)
})

test('IP 快捷弹框：无 IP 访问控制策略时提示先创建并绑定', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  assert.match(page, /const hasAclPolicy = computed/)
  assert.match(page, /!hasInterceptPolicy/)
  assert.match(page, /尚未创建 IP 访问控制（黑名单）策略/)
})
