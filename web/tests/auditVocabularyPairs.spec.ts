// 审计 Action/Resource 枚举钉（audit-i18n 方案 C · 第 1 步交付物）。
//
// 后端 audit_log 的 action/resource 是 zh 枚举库值（internal/db/audit.go 写点侧
// 口径），前端 utils/auditVocabulary.ts 以「库值 → 词条后缀」表承载 en 渲染映射
// （zh 母本与库值同文 ⇒ zh 原样）。本文件四件事：
//
//   1) 枚举集完整性（正钉）：全仓扫描 Go 写点（recordAudit / RecordAuditLog /
//      recordSystemAudit(Once) 的字面量 + FormatAuditAction 的返回字面量 +
//      audit_vocabulary_test.go 已核清动态装配族的取值），任一动作/对象未入
//      前端词条表即红——新增写点漏词条在门禁层暴露，不再静默渲染原样。
//   2) 词条双语言齐备（正钉）：表内每个词条后缀在 en/zh common.ts 双侧存在，
//      zh 值恒等于库值（「zh 原样」契约）；存量词（安全审计）在表内且当前代码
//      不产出（复活即红）。
//   3) 渲染接入钉：AuditLog.vue 的动作标签/对象列/两个筛选下拉全部经词条函数
//      渲染且筛选 value 保持库值原样（过滤参数不变）；列宽语言策略在位。
//   4) 行为钉：表外值与原型键（constructor/toString 等）回落原文；zh 原样、
//      en 翻译、空串保持空串。
//
// 运行：cd web && npm test
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { code } from './_helpers.ts'

import { AUDIT_ACTION_KEYS, AUDIT_RESOURCE_KEYS, auditActionLabel, auditResourceLabel } from '../src/utils/auditVocabulary.ts'
import zhCommon from '../src/locales/zh/common.ts'
import enCommon from '../src/locales/en/common.ts'
import { i18n } from '../src/i18n/index.ts'

const repoRoot = fileURLToPath(new URL('../../', import.meta.url))

// ── 1) Go 写点全仓扫描（与 internal/services/audit_vocabulary_test.go 同口径）──

interface LiteralPair { action: string; resource: string; file: string }

/** 括号平衡提取调用参数（首层逗号切分，字符串感知）；`open` 指向开括号。 */
function callArgs(src: string, open: number): { args: string[]; end: number } {
  const args: string[] = []
  let depth = 1
  let cur = ''
  let inStr = false
  let i = open + 1
  while (i < src.length && depth > 0) {
    const ch = src[i]
    if (inStr) {
      cur += ch
      if (ch === '\\') { cur += src[i + 1] ?? ''; i += 2; continue }
      if (ch === '"') inStr = false
    } else if (ch === '"') {
      inStr = true
      cur += ch
    } else if (ch === '(' || ch === '[' || ch === '{') {
      depth += 1
      cur += ch
    } else if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1
      if (depth === 0) { i += 1; break }
      cur += ch
    } else if (ch === ',' && depth === 1) {
      args.push(cur.trim())
      cur = ''
      if (args.length === 3) { i += 1; break }
    } else {
      cur += ch
    }
    i += 1
  }
  if (cur.trim() && args.length < 3) args.push(cur.trim())
  return { args, end: i }
}

const lit = (expr: string | undefined): string | null => {
  const s = (expr ?? '').trim()
  if (s.startsWith('"') && s.endsWith('"') && !s.includes('" "')) return s.slice(1, -1)
  return null
}

/** recordAudit(ctx, action, resource, …) / RecordAuditLog(user, action, resource, …)：首参非词条。 */
function extractLiteralPairs(goFiles: ReadonlyMap<string, string>): LiteralPair[] {
  const pairs: LiteralPair[] = []
  for (const [file, src] of goFiles) {
    for (const m of src.matchAll(/\b(?:recordAudit|RecordAuditLog|recordSystemAudit|recordSystemAuditOnce)\s*\(/g)) {
      const { args } = callArgs(src, m.index + m[0].length - 1)
      const isSystem = m[0].includes('SystemAudit')
      const action = lit(isSystem ? args[0] : args[1])
      const resource = lit(isSystem ? args[1] : args[2])
      if (action !== null && resource !== null) pairs.push({ action, resource, file })
    }
  }
  return pairs
}

// FormatAuditAction（中间件 Generic 三条：caddy start/stop/restart）
function extractFormatAuditActionPairs(src: string): LiteralPair[] {
  const pairs: LiteralPair[] = []
  for (const m of src.matchAll(/return\s+"([^"]+)",\s*"([^"]+)"/g)) {
    pairs.push({ action: m[1], resource: m[2], file: 'internal/services/auditlog.go#FormatAuditAction' })
  }
  return pairs
}

const goFiles = new Map<string, string>()
const walkGo = (dir: string): void => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = `${dir}/${entry.name}`
    if (entry.isDirectory()) {
      if (entry.name === 'waf-slave' || entry.name.startsWith('.')) continue
      walkGo(full)
    } else if (entry.name.endsWith('.go') && !entry.name.endsWith('_test.go')) {
      goFiles.set(full.replace(`${repoRoot}`, ''), readFileSync(full, 'utf-8'))
    }
  }
}
walkGo(`${repoRoot}internal`)

// 动态装配族取值：audit_vocabulary_test.go 头注 allowlist 已人工核清（变量词条
// 不出字面量扫描面）。族内取值变动时，Go 侧词数门/allowlist 注释与本表须同批更新。
const DYNAMIC_PAIRS: ReadonlyArray<readonly [string, string, string]> = [
  // cluster_registration.go clusterNodeAction：动作形参实参仅有 审批/拒绝/删除/更新地址
  ...(['审批', '拒绝', '删除', '更新地址'] as const).map((a) => [a, '集群节点', 'cluster_registration.go clusterNodeAction'] as const),
  // autobackup.go RunAutoBackupOnce（自动备份/手动备份）+ failAutoBackupAccess（verb+"失败"）
  ...(['自动备份', '手动备份', '还原失败', '下载失败', '删除失败'] as const).map((a) => [a, '配置备份', 'autobackup.go'] as const),
  // certificates.go renewExpiringCertificates：动作变量取值仅有 续签排队/重试排队
  ...(['续签排队', '重试排队'] as const).map((a) => [a, '证书任务', 'certificates.go renewExpiringCertificates'] as const),
  // services/task_trigger.go：动作 触发/触发失败，resource=任务引擎 Family id
  ...(['触发', '触发失败'] as const).flatMap((a) =>
    (['backup', 'cert-job', 'certificates', 'cluster', 'security', 'startup', 'system'] as const)
      .map((fam) => [a, fam, 'services/task_trigger.go actx.Family'] as const)),
  // services/downloadintegrity.go recordDownloadIntegrityAudits：调用方传字面量
  ...(['校验阻断', '下载校验'] as const).flatMap((a) =>
    (['CRS规则库', 'IP数据库', '完整性记录'] as const).map((r) => [a, r, 'services/downloadintegrity.go'] as const)),
  // services/autoban.go AutobanAuditAction 常量
  ['自动封禁', 'IP 地址列表', 'services/autoban.go AutobanAuditAction'] as const,
  // handlers/caddy.go UpdateConfig：对象变量取自 GetConfigSection/GetConfigSourceSection
  ...(['ACME配置', 'Caddy配置', '基础设置', '全局配置', '集群管理'] as const).map((r) => ['更新', r, 'caddy.go UpdateConfig'] as const),
  // handlers/securityiplists.go + handlers.go finishTxApply：f.AuditAction(+“失败”) 字面量字段族
  ...(['创建', '更新', '删除', '写入'] as const).flatMap((a) =>
    ['', '失败'].flatMap((suf) =>
      (['自定义规则', '拦截页面', '安全策略', 'IP 地址列表'] as const).map((r) => [`${a}${suf}`, r, 'handlers.go finishTxApply 族'] as const))),
  // handlers.go applyFailureSubject 常量（应用失败/保存失败/创建失败/清理失败）
  ...([['应用失败', 'Caddy配置'], ['保存失败', 'Caddy配置'], ['创建失败', '证书任务'], ['清理失败', '证书文件']] as const)
    .map(([a, r]) => [a, r, 'handlers.go applyFailureSubject'] as const),
  // handlers/config_backup.go + config_import_v1.go + coordinator abort：action/actionLabel 补集
  ...(['导入', '还原', '部分失败', '导入失败', '还原失败', '导入警告', '还原警告'] as const).map((a) => [a, '配置备份', 'config_backup.go 导入还原族'] as const),
] as ReadonlyArray<readonly [string, string, string]>

const scanned = [
  ...extractLiteralPairs(goFiles),
  ...extractFormatAuditActionPairs(goFiles.get('internal/services/auditlog.go') ?? ''),
]
const scannedActions = new Set<string>()
const scannedResources = new Set<string>()
for (const p of scanned) { scannedActions.add(p.action); scannedResources.add(p.resource) }
for (const [a, r] of DYNAMIC_PAIRS) { scannedActions.add(a); scannedResources.add(r) }

test('枚举正钉：Go 写点扫描非空（扫描器失效即红）', () => {
  assert.ok(scanned.length >= 180, `字面量写点过少（${scanned.length}）——扫描器失效`)
  assert.ok(goFiles.size >= 180, `Go 文件枚举过少（${goFiles.size}）——目录遍历失效`)
})

test('枚举正钉：每个可产出的动作/对象都在前端词条表', () => {
  const missA = [...scannedActions].filter((a) => !(a in AUDIT_ACTION_KEYS))
  assert.deepEqual(missA, [], `动作词条缺登记（新写点漏词条）：${missA.join('、')}`)
  const missR = [...scannedResources].filter((r) => !(r in AUDIT_RESOURCE_KEYS))
  assert.deepEqual(missR, [], `对象词条缺登记（新写点漏词条）：${missR.join('、')}`)
})

test('枚举正钉：动态装配族取值与 Go allowlist 同源（抽查锚点）', () => {
  const clusterReg = goFiles.get('internal/handlers/cluster_registration.go') ?? ''
  assert.match(clusterReg, /clusterNodeAction\(c, "审批"/, 'allowlist 注释中的取值漂移须同步 DYNAMIC_PAIRS')
  const autoban = goFiles.get('internal/services/autoban.go') ?? ''
  assert.match(autoban, /AutobanAuditAction = "自动封禁"/, '常量改名须同步词条表')
  const trigger = goFiles.get('internal/services/task_trigger.go') ?? ''
  assert.match(trigger, /"触发", actx\.Family/, '触发族 resource 口径漂移须同步 DYNAMIC_PAIRS')
})

// ── 2) 词条双语言齐备 + zh 原样契约 ──────────────────────────────────

const zhActions = zhCommon.app.auditActions as unknown as Record<string, string>
const zhResources = zhCommon.app.auditResources as unknown as Record<string, string>
const enActions = enCommon.app.auditActions as unknown as Record<string, string>
const enResources = enCommon.app.auditResources as unknown as Record<string, string>

test('词条正钉：表内每个后缀双语齐备', () => {
  // 契约升级(用户裁定「通俗直观」):auditActions 维持 zh=库值原样
  // (动作枚举库值本身即中文);auditResources 改 zh=本地化中文标签(原 family id
  // 直出如 backup/cert-job 不直观,与 en Task · X 同构)。筛选 value 仍库值原样。
  for (const [raw, key] of Object.entries(AUDIT_ACTION_KEYS)) {
    assert.ok(zhActions[key] !== undefined, `zh auditActions 缺 ${key}（库值 ${raw}）`)
    assert.equal(zhActions[key], raw, `zh auditActions.${key} 必须=库值原样（zh 原样契约）`)
    assert.ok(enActions[key] !== undefined && enActions[key] !== '', `en auditActions 缺 ${key}`)
  }
  for (const [raw, key] of Object.entries(AUDIT_RESOURCE_KEYS)) {
    assert.ok(zhResources[key] !== undefined && zhResources[key] !== '', `zh auditResources 缺 ${key}（库值 ${raw}）`)
    assert.ok(enResources[key] !== undefined && enResources[key] !== '', `en auditResources 缺 ${key}`)
    assert.notEqual(zhResources[key], enResources[key], `zh auditResources.${key} 与 en 同值=漏译`)
  }
})

test('存量词钉：安全审计在表内但当前代码不产出（复活即红）', () => {
  assert.ok('安全审计' in AUDIT_RESOURCE_KEYS, '存量词条目丢失——历史行将失去 en 渲染能力')
  assert.ok(!scannedResources.has('安全审计'), '「存量词」被当前代码重新产出——请移出存量段并核对其 en 译法')
})

test('词条表零重复：raw 与后缀键各自唯一', () => {
  assert.equal(new Set(Object.keys(AUDIT_ACTION_KEYS)).size, Object.keys(AUDIT_ACTION_KEYS).length)
  assert.equal(new Set(Object.values(AUDIT_ACTION_KEYS)).size, Object.keys(AUDIT_ACTION_KEYS).length)
  assert.equal(new Set(Object.keys(AUDIT_RESOURCE_KEYS)).size, Object.keys(AUDIT_RESOURCE_KEYS).length)
  assert.equal(new Set(Object.values(AUDIT_RESOURCE_KEYS)).size, Object.keys(AUDIT_RESOURCE_KEYS).length)
})

// ── 3) 渲染接入钉 ────────────────────────────────────────────────────

const vue = code('src/views/AuditLog.vue')

test('渲染钉：动作标签/对象列经词条函数渲染', () => {
  assert.match(vue, /\{\{ auditActionLabel\(row\.action\) \}\}/, '动作列标签必须过 auditActionLabel')
  assert.match(vue, /\{\{ auditResourceLabel\(row\.resource\) \}\}/, '对象列必须过 auditResourceLabel')
  assert.doesNotMatch(vue, /\{\{ row\.action \}\}/, '动作列不得回退渲染库值原样')
})

test('渲染钉：筛选下拉 label 词条化且 value 保持库值原样', () => {
  assert.match(vue, /:label="auditActionLabel\(o\)" :value="o"/, '动作下拉 label 词条化、value 原样')
  assert.match(vue, /:label="auditResourceLabel\(o\)" :value="o"/, '对象下拉 label 词条化、value 原样')
})

test('渲染钉：列宽语言策略在位（en 加宽防断词，zh 固定设计宽）', () => {
  assert.match(vue, /:width="isEn \? 170 : 90"/, '动作列 en 170/zh 90')
  assert.match(vue, /:width="isEn \? 190 : 160"/, '对象列 en 190/zh 160')
  assert.match(vue, /const isEn = computed\(\(\) => locale\.value === 'en'\)/)
})

test('渲染钉：色调函数仍吃库值原样（actionTagType 输入不词条化）', () => {
  assert.match(vue, /actionTagType\(row\.action\)/, '色调派生必须基于库值（词表键=库值）')
})

// ── 4) 行为钉 ────────────────────────────────────────────────────────

test('行为钉：zh 原样、en 翻译、表外值回落原文', () => {
  // 测试进程无 localStorage：detectLocale 回落 zh-CN
  assert.equal(auditActionLabel('创建'), '创建', 'zh 下枚举值原样')
  assert.equal(auditResourceLabel('负载规则'), '负载规则')
  const saved = i18n.global.locale.value
  try {
    i18n.global.locale.value = 'en'
    assert.equal(auditActionLabel('登录成功'), 'Signed in')
    assert.equal(auditResourceLabel('集群节点'), 'Cluster node')
    assert.equal(auditActionLabel('不存在的新词'), '不存在的新词', '表外动作回落原文')
    assert.equal(auditResourceLabel('backup'), 'Task · Backup', 'Family id 走 Task · 前缀词条')
  } finally {
    i18n.global.locale.value = saved
  }
})

test('行为钉：原型键与空值安全（hasOwn 守卫）', () => {
  for (const k of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
    assert.equal(auditActionLabel(k), k, `动作表原型键 ${k} 必须回落原文`)
    assert.equal(auditResourceLabel(k), k, `对象表原型键 ${k} 必须回落原文`)
  }
  assert.equal(auditActionLabel(''), '', '空串保持空串')
  assert.equal(auditResourceLabel(''), '', '空串保持空串')
  assert.equal(auditResourceLabel(null), '', 'null resource 渲染空串')
  assert.equal(auditResourceLabel(undefined), '')
})
