// 视图层边界态回归钉：一次性凭据关闭守卫、向导门控与预览完整性、文件读取
// 失败路径、空态与切窗三态、写侧值域控件、键盘/读屏残余、失败态恢复入口。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createOneTimeSecretCloseGuard } from '../src/utils/oneTimeSecretGuard.ts'
import { SECURITY_DESCRIPTION_MAX_RUNES, SECURITY_NAME_MAX_RUNES } from '../src/utils/securityLimits.ts'
import { code, openTags, repoCode, section } from './_helpers.ts'

// ── 一次性凭据关闭守卫（单源） ─────────────────────────────────
// 直接驱动守卫：确认框替身记录调用与文案，done 记录是否真正关闭弹框。
const recordingConfirmer = (outcome: 'confirm' | 'cancel') => {
  const calls: Array<{ message: string; title: string; options: Record<string, unknown> }> = []
  const confirmer = (message: string, title: string, options: Record<string, unknown>): Promise<unknown> => {
    calls.push({ message, title, options })
    return outcome === 'confirm' ? Promise.resolve('confirm') : Promise.reject(new Error('cancel'))
  }
  return { calls, confirmer }
}

// 确认框走 Promise 回调：done() 在 .then 的微任务里执行，断言前必须先让出
// 一拍（await Promise.resolve()）。只断言「确认框被调用」会让「确认后永不
// 关闭」的实现照样全绿——主契约是「点我已保存 → 弹框关闭」，必须钉 done
// 的调用次数。

test('一次性凭据守卫：确认后才关闭，取消则弹框保持打开', async () => {
  {
    const { calls, confirmer } = recordingConfirmer('confirm')
    let done = 0
    const close = createOneTimeSecretCloseGuard({ message: '仅此一次', title: '保存' }, confirmer)
    close(() => { done += 1 })
    assert.equal(calls.length, 1)
    assert.deepEqual(calls[0].options, { type: 'warning', confirmButtonText: '我已保存', cancelButtonText: '继续查看' })
    await Promise.resolve()
    assert.equal(done, 1, '用户确认已保存后必须关闭弹框（确认分支不得吞掉 done）')
    await Promise.resolve()
    assert.equal(done, 1, 'done 只能调用一次（重复关闭会二次触发 @closed 清理）')
  }
  {
    const { calls, confirmer } = recordingConfirmer('cancel')
    let done = 0
    const close = createOneTimeSecretCloseGuard({ message: '仅此一次', title: '保存' }, confirmer)
    close(() => { done += 1 })
    assert.equal(calls.length, 1)
    await Promise.resolve()
    assert.equal(done, 0, '取消关闭确认时不得关闭弹框（秘密仍在屏上）')
  }
})

test('一次性凭据守卫：blocked 静默拒绝、skip 直接关闭（均不弹确认）', () => {
  {
    const { calls, confirmer } = recordingConfirmer('confirm')
    let done = 0
    const close = createOneTimeSecretCloseGuard({ message: 'm', title: 't', blocked: () => true }, confirmer)
    close(() => { done += 1 })
    assert.equal(calls.length, 0, '提交在途时不得弹确认框')
    assert.equal(done, 0)
  }
  {
    const { calls, confirmer } = recordingConfirmer('confirm')
    let done = 0
    const close = createOneTimeSecretCloseGuard({ message: 'm', title: 't', skip: () => true }, confirmer)
    close(() => { done += 1 })
    assert.equal(calls.length, 0, '无秘密可丢时不得弹确认框')
    assert.equal(done, 1)
  }
  {
    // 提交在途且此刻无待保存秘密：拒绝必须优先——关闭动作落在提交中途会留下
    // 半提交状态；「跳过」只表达无需确认，不表达允许关闭。
    const { calls, confirmer } = recordingConfirmer('confirm')
    let done = 0
    const close = createOneTimeSecretCloseGuard(
      { message: 'm', title: 't', blocked: () => true, skip: () => true },
      confirmer,
    )
    close(() => { done += 1 })
    assert.equal(calls.length, 0, 'blocked 与 skip 同时成立时不得弹确认框')
    assert.equal(done, 0, 'blocked 必须优先于 skip（提交在途不得关闭）')
  }
})

test('三处一次性凭据弹框都经同一守卫（注册令牌/密钥明文/恢复码）', () => {
  const cluster = code('src/views/settings/ClusterSettings.vue')
  assert.match(cluster, /:before-close="closeTokenDialog"/, '注册令牌 ESC/X 必须走关闭守卫')
  assert.match(cluster, /@closed="registerToken = null"/, '关闭后清空内存中的令牌')
  assert.match(cluster, /const closeTokenDialog = createOneTimeSecretCloseGuard\(\{/)
  assert.match(cluster, /注册令牌仅此一次显示/)

  const keys = code('src/views/Keys.vue')
  assert.match(keys, /const closeCreatedKey = createOneTimeSecretCloseGuard\(\{/)

  const wizard = code('src/components/MfaBindingWizard.vue')
  assert.match(wizard, /const beforeClose = createOneTimeSecretCloseGuard\(\{/)
})

// ── 无障碍链接：按键自动重复 ───────────────────────────────────
test('AccessibleLink 经共享守卫过滤 event.repeat（长按不得反复激活）', () => {
  const wrapper = code('src/components/common/AccessibleLink.vue')
  const activate = section(wrapper, 'const activate = (event: KeyboardEvent): void => {', '\n}')
  assert.match(activate, /activateOnce\(event,/, '重复键过滤必须复用 keyboardActivate 单源')
  assert.match(code('src/utils/keyboardActivate.ts'), /if \(event\.repeat\) return/)
})

test('规则名入口复用 AccessibleLink（不再手写 <a role=button>）', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /<AccessibleLink class="rule-name-link"[^>]*@click="viewConfig\(row(?: as [A-Za-z]+)?\)">/)
  assert.doesNotMatch(rules, /<a class="rule-name-link"/, '手写可聚焦 <a> 已退役')
})

// ── 向导 TLS 门控 / 预览完整性 / 文件读取 ─────────────────────
test('证书详情失败只拦手动 TLS：改为 ACME 后可进下一步与保存', () => {
  const rules = code('src/views/Rules.vue')
  const nextTls = section(rules, "if (currentStep.value === WIZARD_STEP.TLS) {", 'if (wizardForm.tls_source === \'acme_dns\' && !wizardForm.acme_config_id) {')
  assert.match(nextTls, /if \(tlsDetailError\.value && wizardForm\.tls_source === 'manual'\)/, '步进门必须按证书来源收窄')
  assert.match(
    rules,
    /:disabled="tlsDetailError && wizardForm\.tls_source === 'manual'"/,
    '保存按钮同样按来源收窄（否则 ACME 路径被钉死）',
  )
  assert.match(rules, /v-if="tlsDetailError && wizardForm\.tls_source === 'manual'" class="info-note-bar"/, '横幅只作用于手动 TLS')
})

test('配置预览补齐「访问日志」与 HTTP 连接重试', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /<el-descriptions title="配置预览"/)
  const body = section(rules, '<el-descriptions title="配置预览"', '<el-descriptions-item label="上游服务器"')
  assert.match(body, /<el-descriptions-item label="连接重试" v-if="wizardForm\.protocol === 'http' \|\| wizardForm\.protocol === 'tcp'">/, 'HTTP 也必须展示重试窗口')
  assert.match(body, /默认 5s 窗口/, 'HTTP 未设置时必须点明默认窗口口径')
  assert.match(body, /禁用重试（NTLM 模式）/)
  assert.match(body, /<el-descriptions-item label="访问日志" v-if="wizardForm\.protocol === 'http'">/, '访问日志是高级步可编辑项，预览必须覆盖')
})

test('证书/私钥从文件读取：onerror 反馈 + 大小上限 + 不放开任意文件', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /const CERT_FILE_MAX_BYTES = 1024 \* 1024/, '证书文件必须有 1MiB 上限')
  const paste = section(rules, 'const pasteFromFile = ', '\n}\n')
  assert.match(paste, /if \(file\.size > CERT_FILE_MAX_BYTES\)/)
  assert.match(paste, /reader\.onerror = \(\) => \{/)
  assert.match(paste, /input\.accept = '\.pem,\.crt,\.key,\.txt'/, '不得带裸 `,*`（会选中二进制）')
  assert.doesNotMatch(paste, /catch \{/, '同步 catch 是死代码，已删除')
  assert.doesNotMatch(rules, /ElMessage\.error\('读取文件失败'\)/, '恒不可达的旧 catch 文案不得残留')
})

// ── API 密钥缺 key ───────────────────────────────────────────
test('创建密钥响应缺 key：先报错而非先报成功，且不关创建框', () => {
  const keys = code('src/views/Keys.vue')
  const errorAt = keys.indexOf("ElMessage.error('响应异常：密钥未返回")
  const successAt = keys.indexOf("mfaAwareSuccess('密钥创建成功')")
  const closeAt = keys.indexOf('createDialogVisible.value = false', successAt)
  assert.ok(errorAt > 0, '缺 key 必须显性报错')
  assert.ok(successAt > errorAt, '成功提示必须在 key 校验之后')
  assert.ok(closeAt > successAt, '只有拿到明文才关创建框')
})

// ── 大屏空态与切窗三态 ───────────────────────────────────────
test('大屏空态只用当前窗口的 stats 判定（旧帧不得宣称「无安全事件」）', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  const computed = section(screen, 'const showEmptyState = computed(() =>', '\n\n')
  assert.match(computed, /stats\.value\.hours === windowHours\.value/, '必须校验帧所属窗口')
  assert.match(computed, /!statsError\.value/)
})

// ── 自定义规则名称/描述值域 ──────────────────────────────────
test('自定义规则名称/描述上限与后端 rune 常量逐值对表（前端字面量回流即红）', () => {
  // 后端是唯一事实源：securityNameMaxRunes / securityDescriptionMaxRunes
  // 同时服务拦截页/自定义规则/策略三处写入口（含备份还原路径）。
  const backend = repoCode('internal/handlers/security.go')
  const nameMax = /securityNameMaxRunes\s*=\s*(\d+)/.exec(backend)
  const descriptionMax = /securityDescriptionMaxRunes\s*=\s*(\d+)/.exec(backend)
  assert.ok(nameMax && descriptionMax, '后端 rune 上限常量解析失败（改名即须同步本用例）')
  assert.equal(SECURITY_NAME_MAX_RUNES, Number(nameMax[1]), '名称上限与后端不同源')
  assert.equal(SECURITY_DESCRIPTION_MAX_RUNES, Number(descriptionMax[1]), '描述上限与后端不同源')

  for (const view of [
    'src/views/security/SecurityRules.vue',
    'src/views/security/SecurityPolicies.vue',
    'src/views/security/SecurityBlockPages.vue',
  ]) {
    const text = code(view)
    assert.match(text, /:maxlength="SECURITY_NAME_MAX_RUNES"/, `${view} 名称未绑定单源常量`)
    assert.match(text, /:maxlength="SECURITY_DESCRIPTION_MAX_RUNES"/, `${view} 描述未绑定单源常量`)
    assert.doesNotMatch(text, /v-model="(?:ruleForm\.name|ruleForm\.description|form\.name|form\.description)"[^>]*maxlength="\d+"/, `${view} 的名称/描述仍有写死的长度字面量（漂移时不会变红）`)
  }
  // 名称/描述输入框仍带字数提示（spell 字数可发现性）
  const rules = code('src/views/security/SecurityRules.vue')
  const form = section(rules, '<el-form-item label="名称" required>', '<el-form-item label="条件关系">')
  assert.match(form, /v-model="ruleForm\.name"[^>]*:maxlength="SECURITY_NAME_MAX_RUNES"[^>]*show-word-limit/)
  assert.match(form, /v-model="ruleForm\.description"[^>]*:maxlength="SECURITY_DESCRIPTION_MAX_RUNES"[^>]*show-word-limit/)
})


// ── 服务控制卡的选中态 ───────────────────────────────────────
test('服务控制四选一卡片暴露 radio 语义与选中态', () => {
  const cluster = code('src/views/settings/ClusterSettings.vue')
  assert.match(cluster, /class="service-control-grid" role="radiogroup" aria-label="服务控制操作"/)
  // 选中态必须落在同一个开标签上：距离窗口（`[\s\S]{0,120}`）在两属性之间插入
  // `v-if`/`v-else` 或调换书写顺序时假红，也可能跨到相邻分支的元素上。
  const radioCard = openTags(cluster, 'div').find((tag) => /\srole="radio"/.test(tag))
  assert.ok(radioCard !== undefined, '服务控制卡片必须暴露 role="radio"')
  assert.match(radioCard, /:aria-checked="serviceControlAction === item\.value"/, 'radio 语义必须带选中态（读屏听不到选中）')
})

// ── 无障碍族级残余 ──────────────────────────────────────────
test('TCP 锁图标有名称、规则开关有名称', () => {
  const rules = code('src/views/Rules.vue')
  // TCP 锁与 HTTP 同构（阶段 0/1 放开）：灰 placeholder 锁退役，
  // TCP 走同一 popover 锁（role=button + 流程弹框 aria 名称，键盘语义共享）
  assert.doesNotMatch(rules, /acl-lock-icon--tcp/)
  assert.doesNotMatch(rules, /TCP 规则不支持安全策略/)
  const reference = section(rules, '<template #reference>', '</template>')
  assert.match(reference, /role="button"/)
  assert.match(reference, /:aria-label="`查看「\$\{row\.name\}」的安全处理流程`"/)
  assert.match(rules, /:aria-label="`\$\{row\.name\} 的启用状态`"/)
})

test('CRS 源码折叠暴露展开态与焦点环', () => {
  const dialog = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(dialog, /class="crs-snippet-toggle" role="button" tabindex="0" :aria-expanded="crsSnippetExpanded"/)
  assert.match(dialog, /\.crs-snippet-toggle:focus-visible \{ outline: 2px solid var\(--el-color-primary\)/)
})

test('关联规则 drill-down 与触发明细 tooltip 键盘可达', () => {
  const policies = code('src/views/security/SecurityPolicies.vue')
  // 真按钮做 reference：原 role="button" 的 span 无任何激活行为（假按钮），
  // hover-only tooltip 的内容也从进不了焦点序。el-dropdown 的 click 触发 +
  // 菜单 roving focus + Esc 关闭给出可用键盘路径。
  assert.match(policies, /<el-dropdown\s+v-if="policyBoundRules\(row\.id\)\.length > 0"\s+trigger="click"/)
  assert.match(policies, /<button type="button" class="policy-rule-count" :aria-label="`关联规则/, 'reference 必须是真按钮')
  assert.match(policies, /<el-dropdown-item v-for="rule in policyBoundRules\(row\.id\)"/, '菜单项须逐条具名')
  assert.match(policies, /@command="openRuleInNewTab"/, '菜单命令必须接到跳转动作')
  assert.match(policies, /\.policy-rule-count:focus-visible/)
  assert.doesNotMatch(policies, /role="button" tabindex="0" :aria-label="`关联规则/, '不得回流无激活行为的假按钮')

  const events = code('src/views/security/SecurityEvents.vue')
  assert.match(events, /:content="row\.rule_msg" placement="top" :show-after="200" :trigger="\['hover', 'focus'\]"/)
  assert.match(events, /class="cell-tip" tabindex="0" :aria-label="row\.rule_msg"/)
  assert.match(events, /\.cell-tip:focus-visible/)
})

// ── 安全总览：失败态可重试 + 卡片不再伪装成功 ────────────────
test('安全总览六路数据失败后提供「立即重试」，且并发门防重复点击', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /const reloadAll = async \(\): Promise<void> => \{/)
  assert.match(page, /if \(reloading\.value\) return/, '重复点击不得叠发六组请求')
  assert.equal([...page.matchAll(/@click="reloadAll">立即重试<\/el-button>/g)].length, 3, '总览/最近拦截/限流三处失败态都要有重试入口')
  assert.match(page, /onMounted\(\(\) => \{ void reloadAll\(\) \}\)/)
})

test('安全总览威胁/爬虫卡失败时切危险底色并显示「—」', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /:class="threatError \? 'stat-box--danger' : 'stat-box--success'"/)
  assert.match(page, /:class="crawlerError \? 'stat-box--danger' : 'stat-box--success'"/)
  assert.match(page, /\{\{ threatError \? '—' : \(threatLatestVersion \|\| '未更新'\) \}\}/)
  assert.match(page, /\{\{ crawlerError \? '—' : \(crawlerLatestVersion \|\| '未更新'\) \}\}/)
})
