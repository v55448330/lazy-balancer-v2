import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  certJobRetryReady,
  certJobStatusLabel,
  certJobStatusTone,
  certJobManualNeeded,
  certJobRowStatusLabel,
  certJobStatusHover,
  certJobCooldownTierHours,
  certJobCooldownSpan,
  certJobCooldownCell,
  certManualBannerFingerprint,
  loadCertManualBannerDismissed,
  saveCertManualBannerDismissed,
  CERT_JOB_RENEWAL_ATTEMPTS_FALLBACK,
  type CertJobStatus,
} from '../src/utils/certJobStatus.ts'
import { code, installBrowserHost, member, repoCode, section } from './_helpers.ts'

test('重试冷却由后端「此刻剩余秒」驱动，前端不做二次扣减', () => {
  assert.equal(certJobRetryReady(null), false, 'null=永久不可重试')
  assert.equal(certJobRetryReady(undefined), false, '缺字段=不可判定，不放行')
  assert.equal(certJobRetryReady(0), true, '零冷却立即可重试')
  assert.equal(certJobRetryReady(1), false, '剩余 1 秒仍在冷却')
  assert.equal(certJobRetryReady(300), false, 'failed 冷却窗口内')
  assert.equal(certJobRetryReady(900), false, 'queued 冷却窗口内')
})

test('证书任务页与任务监控页共用同一冷却判据（不再各自按 updated_at 起算）', () => {
  const util = code('src/utils/certJobStatus.ts')
  assert.match(util, /return seconds <= 0/, '判据只能是剩余秒数 ≤0')
  assert.doesNotMatch(util, /updatedAt/, '前端不得再按 updated_at 起算流逝')

  const certJobs = code('src/views/settings/CertJobs.vue')
  assert.match(certJobs, /certJobRetryReady\(row\.retry_cooldown_seconds\)/)

  const monitor = code('src/views/settings/TaskMonitor.vue')
  assert.match(monitor, /if \(certJobRetryReady\(seconds\)\) return ''/)
})

test('证书任务状态表查表防原型键：constructor 等不得把函数当标签/色调', () => {
  const warn = console.warn
  console.warn = () => {}
  try {
    for (const key of ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__']) {
      const label = certJobStatusLabel(key as CertJobStatus)
      assert.equal(typeof label, 'string', `${key} 标签必须是字符串（原型链函数不得外泄）`)
      assert.equal(label, key, `${key} 未识别状态按原文回退`)
      const tone = certJobStatusTone(key as CertJobStatus)
      assert.equal(tone, 'info', `${key} 色调必须回落 info（不得落进 el-tag :type）`)
    }
  } finally {
    console.warn = warn
  }
})

// 证书任务状态 label/tone 全表覆盖后端 db.certJobStatuses（26 态，DB CHECK 单源）。
// 前端枚举漂移会静默落入 unknown 分支（标签显示原始 token、tone 退 info），且无任何
// 运行期用例会失败。穷尽性由生产侧两张表上的 `satisfies Record<CertJobStatus, …>`
// 在编译期锁定（新增状态不补文案即 tsc 报错）；本条在运行期逐态验证「有专属中文
// 标签、tone 合法」，并钉住这两条编译期约束不被悄悄删掉。
test('证书任务状态 label/tone 覆盖后端 db.certJobStatuses 全 26 态', () => {
  const go = repoCode('internal/db/db.go')
  const goBlock = section(go, 'var certJobStatuses = []string{', '\n}\n')
  const backend = [...goBlock.matchAll(/"([a-z_]+)"/g)].map((m) => m[1])
  // 状态联合唯一事实源已迁 types/index.ts（证书任务视图类型族同源处），
  // utils/certJobStatus 只 re-export——枚举漂移检查钉在唯一声明处。
  const sharedTypes = code('src/types/index.ts')
  const tsBlock = section(sharedTypes, 'export type CertJobStatus =', '\n\n')
  const frontend = [...tsBlock.matchAll(/'([a-z_]+)'/g)].map((m) => m[1])
  const ts = code('src/utils/certJobStatus.ts')
  assert.match(ts, /export type \{ CertJobStatus \}/, 'utils/certJobStatus 须保持 CertJobStatus 导入面（re-export）')
  assert.equal(backend.length, 26, '后端枚举应为 26 态（DB CHECK 单源）')
  assert.deepEqual([...frontend].sort(), [...backend].sort(), '证书状态前后端枚举漂移')

  // 编译期穷尽性约束必须存在：删掉 satisfies 后新增状态不再被 typecheck 拦截
  assert.match(ts, /satisfies Record<CertJobStatus, string>/, '标签表必须带 Record<CertJobStatus, string> 约束')
  assert.match(ts, /satisfies Record<CertJobStatus, CertJobStatusTone>/, '色调表必须带 Record<CertJobStatus, CertJobStatusTone> 约束')

  // 运行期逐态：每个状态都有专属中文标签（不落 unknown 分支）
  const tones = ['success', 'danger', 'warning', 'info']
  for (const status of backend) {
    const label = certJobStatusLabel(status as CertJobStatus)
    assert.notEqual(label, '未知', `${status} 未补专属文案（空值兜底分支）`)
    assert.notEqual(label, status, `${status} 落入 unknown 分支（显示原始 token）`)
    assert.ok(label.length > 0)
    assert.ok(tones.includes(certJobStatusTone(status as CertJobStatus)), `${status} tone 非法`)
  }
})

test('重签禁用文案：不可重试且无冷却秒数时不得提示「等待 0 分钟」', () => {
  const page = code('src/views/settings/CertJobs.vue')
  const fn = section(page, 'const retryDisabledReason', '\n}')
  assert.match(fn, /if \(row\.retry_cooldown_seconds === null \|\| row\.retry_cooldown_seconds === undefined\) return '当前状态暂不可重签'/)
  assert.match(fn, /Math\.ceil\(row\.retry_cooldown_seconds \/ 60\)/, '有冷却值时不得再用 ?? 0 兜底物化 0 分钟')
  assert.doesNotMatch(fn, /retry_cooldown_seconds \?\? 0/)
})

// ── 续签语境状态口径（2026-10-30 裁定）：failed 按续签语境细分（失败/续签失败/
// 需人工），全部标签 ≤4 字；hover 为派生口径，CA 原文只在「日志」对话框。 ──

const CAP = 5

test('状态列标签全部 ≤4 字（26 态全表 + 细分标签）', () => {
  const go = repoCode('internal/db/db.go')
  const goBlock = section(go, 'var certJobStatuses = []string{', '\n}\n')
  for (const status of [...goBlock.matchAll(/"([a-z_]+)"/g)].map((m) => m[1])) {
    const label = certJobStatusLabel(status as CertJobStatus)
    assert.ok([...label].length <= 4, `${status} 标签「${label}」超 4 字`)
  }
  for (const label of ['需人工', '续签失败', '失败', '限流中', '已签发', '已禁用']) {
    assert.ok([...label].length <= 4, `细分标签「${label}」超 4 字`)
  }
})

test('需人工判据：failed 且无 CA 冷却且失败次数达上限（后端达上限必清 ca_available_after）', () => {
  assert.equal(certJobManualNeeded({ status: 'failed', renewal_attempts: 5 }, CAP), true, '达上限=需人工')
  assert.equal(certJobManualNeeded({ status: 'failed', renewal_attempts: 5, ca_available_after: '2026-10-30T01:13:00Z' }, CAP), false, '仍有冷却=还在自动重试节奏内')
  assert.equal(certJobManualNeeded({ status: 'failed', renewal_attempts: 4 }, CAP), false, '未达上限≠需人工')
  assert.equal(certJobManualNeeded({ status: 'failed' }, CAP), false, '缺 attempts 字段（omitempty）不算需人工')
  assert.equal(certJobManualNeeded({ status: 'waiting_ca', renewal_attempts: 5 }, CAP), false, '非终态失败不进需人工')
  assert.equal(CERT_JOB_RENEWAL_ATTEMPTS_FALLBACK, 5, '兜底上限=db.DefaultCertRenewalAttempts 同值')
})

test('状态列标签细分：failed → 需人工/续签失败/失败（旧证书在场判据=到期派生非空）', () => {
  assert.equal(certJobRowStatusLabel({ status: 'failed', renewal_attempts: 5 }, CAP), '需人工')
  assert.equal(certJobRowStatusLabel({ status: 'failed', renewal_attempts: 2, not_after: '2026-12-31T00:00:00Z' }, CAP), '续签失败')
  assert.equal(certJobRowStatusLabel({ status: 'failed', renewal_attempts: 2, expires_at: '2026-12-31T00:00:00Z' }, CAP), '续签失败', 'not_after 缺失时 expires_at 也是旧证书在场判据')
  assert.equal(certJobRowStatusLabel({ status: 'failed', renewal_attempts: 2 }, CAP), '失败', '首次签发失败（从未有证书）')
  assert.equal(certJobRowStatusLabel({ status: 'waiting_ca', renewal_attempts: 2 }, CAP), '限流中')
  assert.equal(certJobRowStatusLabel({ status: 'issued' }, CAP), '已签发', '非 failed 态沿用全表标签')
  assert.equal(certJobRowStatusLabel({ status: 'validating' }, CAP), '验证中')
})

test('状态 hover（派生口径）：续签失败/失败/需人工/限流中；CA 原文不进 hover', () => {
  // 测试注入的 HH:mm 时钟（实现侧由 CertJobs.vue 注入配置时区格式化）
  const clock = (iso: string): string => iso.slice(11, 16)
  const now = Date.parse('2026-10-30T00:26:00Z')
  assert.equal(
    certJobStatusHover({ status: 'failed', renewal_attempts: 2, days_remaining: 47, not_after: 'x', ca_available_after: '2026-10-30T01:13:00Z' }, CAP, now, clock),
    '旧证书剩 47 天 · 已失败 2 次（上限 5）· 下次自动重试 01:13（剩 47 分钟）',
  )
  assert.equal(
    certJobStatusHover({ status: 'failed', renewal_attempts: 1, ca_available_after: '2026-10-30T01:13:00Z' }, CAP, now, clock),
    '已失败 1 次（上限 5）· 下次自动重试 01:13（剩 47 分钟）',
    '失败=同续签失败去掉旧证书段',
  )
  assert.equal(
    certJobStatusHover({ status: 'failed', renewal_attempts: 5 }, CAP, now, clock),
    '自动重试已停止 · 查看日志 / 检查 DNS 或凭据 / 手动重签',
  )
  assert.equal(
    certJobStatusHover({ status: 'waiting_ca', renewal_attempts: 2, ca_available_after: '2026-10-30T01:13:00Z' }, CAP, now, clock),
    '已失败 2 次（上限 5）· 下次自动重试 01:13（剩 47 分钟）',
  )
  assert.equal(
    certJobStatusHover({ status: 'waiting_ca', renewal_attempts: 2 }, CAP, now, clock),
    '已失败 2 次（上限 5）',
    '无冷却时刻时省略下次重试段',
  )
  assert.equal(
    certJobStatusHover({ status: 'failed', renewal_attempts: 2, days_remaining: -3, not_after: 'x' }, CAP, now, clock),
    '旧证书已过期 3 天 · 已失败 2 次（上限 5）',
    '旧证书过期不得渲染裸负数（与有效期列同口径）',
  )
  assert.equal(certJobStatusHover({ status: 'validating' }, CAP, now, clock), '', '非四态返回空串（调用方回落在途说明）')
})

test('冷却时间列：终态失败显示档位·时刻（computeBackoff 同规则），429 实际间隔更短取实际', () => {
  assert.equal(certJobCooldownTierHours(1), 1)
  assert.equal(certJobCooldownTierHours(2), 2)
  assert.equal(certJobCooldownTierHours(3), 3)
  assert.equal(certJobCooldownTierHours(9), 3, '≥3 恒 3h（阶梯封顶）')
  assert.equal(certJobCooldownSpan(47 * 60_000), '47m')
  assert.equal(certJobCooldownSpan(90 * 60_000), '1h30m')
  assert.equal(certJobCooldownSpan(2 * 3_600_000), '2h')

  const clock = (iso: string): string => iso.slice(11, 16)
  // 档位 2h（attempts=2），429 实际间隔 43m 更短 → 显示实际间隔
  assert.equal(
    certJobCooldownCell({ status: 'failed', renewal_attempts: 2, updated_at: '2026-10-30T00:30:00Z', ca_available_after: '2026-10-30T01:13:00Z' }, clock),
    '43m · 01:13',
  )
  // 实际间隔 ≥ 档位 → 显示档位
  assert.equal(
    certJobCooldownCell({ status: 'failed', renewal_attempts: 1, updated_at: '2026-10-29T20:00:00Z', ca_available_after: '2026-10-30T01:13:00Z' }, clock),
    '1h · 01:13',
  )
  assert.equal(
    certJobCooldownCell({ status: 'failed', renewal_attempts: 2 }, clock),
    '',
    '无 ca_available_after 显示 -（空串）',
  )
  assert.equal(
    certJobCooldownCell({ status: 'waiting_ca', renewal_attempts: 2, ca_available_after: '2026-10-30T01:13:00Z' }, clock),
    '',
    'waiting_ca 仍由页面倒计时文案承载（不走档位形态）',
  )
})

test('需人工横幅指纹：行 id+updated_at；localStorage 记忆后新增/变化行重新出现', () => {
  const browser = installBrowserHost({ localStorage: new Map() })
  try {
    const fpA = certManualBannerFingerprint({ id: 3, updated_at: '2026-10-30T01:00:00Z' })
    assert.equal(fpA, '3:2026-10-30T01:00:00Z')
    // 同一行状态再变化（updated_at 变）→ 新指纹 → 横幅重现
    const fpA2 = certManualBannerFingerprint({ id: 3, updated_at: '2026-10-30T02:00:00Z' })
    assert.notEqual(fpA, fpA2)
    // updated_at 缺失（存量行瞬时形态）也要生成稳定指纹
    assert.equal(certManualBannerFingerprint({ id: 9, updated_at: null }), '9:')

    saveCertManualBannerDismissed([fpA])
    assert.ok(loadCertManualBannerDismissed().has(fpA), '已关闭指纹必须持久化')
    assert.equal(loadCertManualBannerDismissed().has(fpA2), false, '变化后的行不在关闭集（横幅重现）')
  } finally {
    browser.restore()
  }
})

test('CertJobs.vue 消费面接线：派生 hover/failed-only 重试列/冷却列档位/横幅指纹', () => {
  const page = code('src/views/settings/CertJobs.vue')
  // 状态列：标签与 hover 都走派生单源（SFC 侧薄包装与 renewalAt/statusType 同约定）
  const statusCol = section(page, 'label="状态"', '</el-table-column>')
  assert.match(statusCol, /rowStatusLabel\(row(?: as [A-Za-z]+)?\)/, '状态标签必须走细分单源包装')
  assert.match(page, /const rowStatusLabel[^\n]*certJobRowStatusLabel\(/, '包装必须委托细分单源')
  assert.match(statusCol, /:content="statusHover\(row(?: as [A-Za-z]+)?\)"/, '状态 hover 必须走派生单源')
  assert.doesNotMatch(statusCol, /row\.message/, '状态列模板不得直接消费 message（CA 原文）')
  // 重试次数列：仅终态失败显示 N
  const attemptsCol = section(page, 'label="重试次数"', '</el-table-column>')
  assert.match(attemptsCol, /attemptsCell\(row(?: as [A-Za-z]+)?\)/)
  const attemptsFn = member(code('src/views/settings/CertJobs.vue'), 'const attemptsCell')
  assert.match(attemptsFn, /row\.status === 'failed'/, '重试次数仅终态失败显示')
  // 冷却列：failed 档位形态
  const coolingCol = section(page, 'label="冷却时间"', '</el-table-column>')
  assert.match(coolingCol, /coolingCell\(row(?: as [A-Za-z]+)?\)/)
  const coolingFn = member(code('src/views/settings/CertJobs.vue'), 'const coolingCell')
  assert.match(coolingFn, /certJobCooldownCell\(/, 'failed 行冷却值必须走档位单源')
  // 横幅：指纹记忆 + 查看 + 关闭
  assert.match(page, /certManualBannerFingerprint/, '横幅指纹必须用单源')
  assert.match(page, /saveCertManualBannerDismissed/, '关闭必须持久化指纹')
  assert.match(page, /manualFilterActive/, '查看必须接筛选')
  // 续签重试上限：一次性 /config 拉取 + 兜底常量
  assert.match(page, /cert_renewal_attempts/, '上限必须读 /config')
  assert.match(page, /CERT_JOB_RENEWAL_ATTEMPTS_FALLBACK/, '读取失败时用兜底上限')
})
