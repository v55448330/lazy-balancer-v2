// 证书签发任务表列布局：设置页卡片容器内曾出现水平滚动条（原 12 列合计 1660px）。
// 收敛口径：消息列并入状态标签 tooltip、过期时间与剩余天数合并单列、时间列改配置时区
// 完整时间戳、全部定宽且不再用 min-width 撑宽。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, code, member } from './_helpers.ts'
import {
  CERT_JOB_COLUMNS_MIN_WIDTH,
  CERT_JOB_COLUMN_WIDTHS,
  CERT_JOB_COLUMNS_TOTAL_WIDTH,
} from '../src/utils/certJobColumns.ts'
import type { CertJobColumnId } from '../src/utils/certJobColumns.ts'

const page = code('src/views/settings/CertJobs.vue')

const tableBody = section(page, 'class="cert-jobs-table"', '</el-table>')

const columnTags = (): string[] => [...tableBody.matchAll(/<el-table-column\b[^>]*>/g)].map((m) => m[0])

const startOf = (label: string): number => {
  const at = tableBody.indexOf(`label="${label}"`)
  assert.ok(at >= 0, `缺少列「${label}」`)
  return tableBody.lastIndexOf('<el-table-column', at)
}

/** 列块（含模板体，到 </el-table-column> 为止）。 */
const columnBody = (label: string): string => {
  const start = startOf(label)
  const end = tableBody.indexOf('</el-table-column>', start)
  assert.ok(end > start, `列「${label}」缺少模板体`)
  return tableBody.slice(start, end)
}

// 列标签 → 单源列 id：宽度期望一律取自 CERT_JOB_COLUMN_WIDTHS（此前手抄两份，
// 合法调宽时实现与常量表都改了仍被测试字面量拦住——假红）。
const COLUMN_IDS: Record<string, CertJobColumnId> = {
  '规则 ID': 'rule_id',
  域名: 'domain',
  状态: 'status',
  颁发者: 'issuer',
  证书有效期: 'validity',
  自动重签时间: 'renewal',
  更新时间: 'updated',
  重试次数: 'attempts',
  冷却时间: 'cooling',
  操作: 'actions',
}

/** 固定宽列（不参与「宽容器占满」的均分）；其余为弹性 min-width 列。 */
const FIXED_COLUMNS: Partial<Record<CertJobColumnId, true>> = { status: true, attempts: true, actions: true }

test('状态列 hover=派生口径（2026-10-30 裁定）：CA 原文只在「日志」对话框', () => {
  assert.doesNotMatch(tableBody, /label="消息"/)
  const status = columnBody('状态')
  // 旧契约（:content="row.message"）会把 CA 原文挂上状态标签——终态失败的
  // message 即 CA 错误原文，只在「日志」对话框呈现。
  assert.doesNotMatch(status, /row\.message/, '状态列模板不得直接消费 message（CA 原文）')
  assert.match(status, /:disabled="!statusHover\(row(?: as [A-Za-z]+)?\)"/, '派生 hover 为空时不得挂空 tooltip')
  assert.match(status, /:content="statusHover\(row(?: as [A-Za-z]+)?\)"/)
  assert.match(status, /rowStatusLabel\(row(?: as [A-Za-z]+)?\)/, '标签必须走细分单源包装（失败/续签失败/需人工）')
  // 脚本侧：四态走 certJobStatusHover 单源，其余在途行保留在途说明（stage 文本）
  const hoverFn = member(page, 'const statusHover')
  assert.match(hoverFn, /certJobStatusHover\(/, '四态 hover 必须经 utils 单源派生')
  assert.match(hoverFn, /row\.message/, '非四态在途行保留在途说明 tooltip')
})

test('列宽基线取自 CERT_JOB_COLUMN_WIDTHS 单源（弹性 min-width / 固定 width）', () => {
  const tags = columnTags()
  const mappedLabels = Object.keys(COLUMN_IDS)
  assert.equal(tags.length, mappedLabels.length, `列数应为 ${mappedLabels.length}，实际 ${tags.length}`)
  const seen = new Set<CertJobColumnId>()
  for (const tag of tags) {
    const label = /label="([^"]+)"/.exec(tag)?.[1]
    assert.ok(label, `列开标签缺 label：${tag}`)
    const id = COLUMN_IDS[label]
    assert.ok(id, `列「${label}」未登记到 label→columnId 映射（新增列须同步单源常量表）`)
    seen.add(id)
    const width = CERT_JOB_COLUMN_WIDTHS[id]
    if (FIXED_COLUMNS[id] === true) {
      assert.match(tag, new RegExp(`(?<!min-)width="${width}"`), `固定列「${label}」宽度应为 ${width}px`)
      assert.doesNotMatch(tag, /min-width="/, `固定列「${label}」不应弹性伸展`)
    } else {
      assert.match(tag, new RegExp(`\\bmin-width="${width}"`), `弹性列「${label}」应为 min-width ${width}px`)
      assert.doesNotMatch(tag, /(?<!min-)width="/, `弹性列「${label}」不得用固定 width（会留白）`)
    }
  }
  assert.equal(seen.size, mappedLabels.length, 'label→id 映射必须与模板列一一对应（不留死映射）')
  const total = tags.reduce((sum, tag) => sum + Number(tag.match(/(?:min-)?width="(\d+)"/)?.[1] ?? 0), 0)
  assert.equal(total, CERT_JOB_COLUMNS_TOTAL_WIDTH, `列宽基线合计应为 ${CERT_JOB_COLUMNS_TOTAL_WIDTH}px，实际 ${total}px`)
  assert.match(tableBody, /:fit="true"/)
})

test('证书有效期合并单列：日期 + 剩余/已过期天数，精确时间走 tooltip', () => {
  assert.doesNotMatch(tableBody, /label="过期时间"/)
  assert.doesNotMatch(tableBody, /label="剩余天数"/)
  const body = columnBody('证书有效期')
  assert.match(body, new RegExp(`\\bmin-width="${CERT_JOB_COLUMN_WIDTHS.validity}"`))
  assert.match(body, /formatDateShort\(effectiveNotAfter\(row(?: as [A-Za-z]+)?\)\)/)
  assert.ok(body.includes('剩 ${row.days_remaining} 天'), '缺少「剩 N 天」分支')
  assert.ok(body.includes('已过期 ${Math.abs(row.days_remaining)} 天'), '缺少「已过期 N 天」分支')
  assert.match(body, /row\.certificate_status === 'expired'/, '过期判据必须读后端 certificate_status 字段（无第二份派生）')
  assert.match(body, /<el-tooltip[^>]*:content="formatDate\(effectiveNotAfter\(row(?: as [A-Za-z]+)?\)\)"/, '精确过期时间必须进 tooltip')
  assert.match(body, /class="cell-empty"/, '非 issued/缺失必须沿用 cell-empty 占位')
})

test('自动重签时间列经 renewalAt（not_after 派生），不回退 expires_at', () => {
  const body = columnBody('自动重签时间')
  // 与有效期列共用同一到期口径：expires_at 在导入/旧备份/集群回插行上可能为
  // null——若本列回退 row.expires_at，同一行会出现「有效期有值、重签显示 -」的
  // 跨列分叉，运维据空列误判未排期重签。
  assert.match(body, /v-if="row\.status === 'issued' && renewalAt\(row(?: as [A-Za-z]+)?\)"/, '显示门必须用 renewalAt')
  assert.match(body, /formatDate\(renewalAt\(row(?: as [A-Za-z]+)?\)\)/, '本列必须经 renewalAt 渲染')
  assert.doesNotMatch(body, /expires_at/, '不得直接消费 expires_at')
})

test('时间列显示完整时间戳 YYYY-MM-DD HH:mm:ss（配置时区）', () => {
  assert.doesNotMatch(page, /formatDateCompact/)
  for (const [label, id] of [
    ['自动重签时间', 'renewal'],
    ['更新时间', 'updated'],
  ] as const) {
    const body = columnBody(label)
    assert.match(body, new RegExp(`\\bmin-width="${CERT_JOB_COLUMN_WIDTHS[id]}"`), `列「${label}」最小宽度须取单源常量`)
    assert.match(body, /\{\{ formatDate\(/, `列「${label}」必须显示配置时区的完整时间戳`)
    assert.doesNotMatch(body, /toLocaleString|toLocaleDateString|toLocaleTimeString/, `列「${label}」不得绕过配置时区`)
  }
  assert.doesNotMatch(page, /new Date\(\)\.toLocale/)
})

test('容器窄于最小集时切横向滚动：操作列不得被 overflow:hidden 裁到不可达', () => {
  // 最小集 = 不可让位列之和。断言取派生式（单源），不手抄 619——合法调宽
  // （如有效期 155→165）只需改 CERT_JOB_COLUMN_WIDTHS 一处。
  const nonYieldingColumns: CertJobColumnId[] = ['domain', 'status', 'validity', 'attempts', 'actions']
  assert.equal(
    CERT_JOB_COLUMNS_MIN_WIDTH,
    nonYieldingColumns.reduce((sum, id) => sum + CERT_JOB_COLUMN_WIDTHS[id], 0),
    '不可让位列宽度之和必须等于单源下限常量',
  )
  // 独立业务基线锚：下限过小会让窄屏把操作列挤到不可达。
  assert.ok(CERT_JOB_COLUMNS_MIN_WIDTH >= 600, `最小集下限 ${CERT_JOB_COLUMNS_MIN_WIDTH}px 低于业务基线 600px`)
  assert.match(page, /const tableBelowMinWidth = computed\(\(\) => tableWrapWidth\.value < CERT_JOB_COLUMNS_MIN_WIDTH\)/)
  assert.match(page, /:class="\{ 'cert-jobs-wrap--scroll': tableBelowMinWidth \}"/)
  // 规则块语义匹配：注释与否、Prettier 断行都不影响判定
  const ruleStart = page.indexOf('.cert-jobs-wrap--scroll {')
  assert.ok(ruleStart > 0, '缺少窄容器滚动规则块')
  const rule = page.slice(ruleStart, page.indexOf('}', ruleStart))
  assert.match(rule, /overflow-x:\s*auto/, '窄容器必须恢复横向滚动')
  assert.doesNotMatch(rule, /overflow-x:\s*hidden/, '裁切会让右侧操作列不可达')
})
