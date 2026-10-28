import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section } from './_helpers.ts'

test('任务监控：KPI 不再显示证书工作项括注，筛选组右对齐，操作列保持单行', () => {
  const page = code('src/views/settings/TaskMonitor.vue')
  assert.doesNotMatch(page, /（不含证书工作项）|（含证书工作项）/)
  assert.match(page, /<div class="tm-filter-group">/)
  assert.match(page, /class-name="tm-op-cell"/)
  const filterCss = section(page, '.tm-filter-group {', '}')
  for (const declaration of ['display: flex', 'align-items: center', 'gap: 10px', 'margin-left: auto']) {
    assert.ok(filterCss.includes(declaration), `筛选组样式缺少 ${declaration}`)
  }
  for (const declaration of ['display: flex', 'flex-wrap: nowrap']) {
    assert.ok(section(page, '.tm-nowrap-table .tm-op-cell .cell) {', '}').includes(declaration), `操作列样式缺少 ${declaration}`)
  }
  assert.ok(section(page, '.tm-nowrap-table .tm-op-cell .el-button) {', '}').includes('margin-left: 0'))
  assert.doesNotMatch(page, /<el-tooltip[\s\S]{0,300}<div>\s*<el-button[\s\S]{0,120}>运行<\/el-button>/)
})

test('安全总览 Top10 源 IP 展示近 10 分钟/近 1 小时/近 24 小时频率', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /recent_10m: number; recent_1h: number; recent_24h: number/)
  assert.doesNotMatch(page, /prop="frequency"/)
  assert.match(page, /prop="blocked" label="拦截" width="100"/)
  assert.match(page, /prop="detected" label="检测" width="100"/)
  assert.match(page, /prop="recent_10m" label="近10分钟" width="120"/)
  assert.match(page, /prop="recent_1h" label="近1小时" width="128"/)
  assert.match(page, /prop="recent_24h" label="近24小时" width="110"/, '近 24 小时列（用户要求 110 宽）')
  // 新增列后不得整体撑破表格：IP 地址与攻击类型让宽
  assert.match(page, /label="IP 地址" min-width="160"/, 'IP 地址列让宽到 160（原 200）')
  assert.match(page, /label="攻击类型" min-width="140"/, '攻击类型列让宽到 140（原 180）')
})
