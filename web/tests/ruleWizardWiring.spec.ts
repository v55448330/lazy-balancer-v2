// 规则向导（Rules.vue 的向导部分）接线守卫。
//
// 行为断言在 ruleWizard.spec.ts 的纯函数用例里；这里只钉「视图把事件与失败分支
// 接到纯函数上」——纯函数全绿也拦不住视图绕过它另写一份、确认框取消后不回滚、
// 或校验失败仍只弹 toast 不切步。
//
// 运行：cd web && node --test tests/ruleWizardWiring.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, elementSlice, enclosingOpenTag, member, openTags, section } from './_helpers.ts'

const page = code('src/views/Rules.vue')
const zh = code('src/locales/zh/rules.ts')
const en = code('src/locales/en/rules.ts')

const count = (text: string, needle: string): number => text.split(needle).length - 1

/** 模板里包住 `probe` 的首个 `<tag>…</tag>` 元素（按标签配对取段，不靠定长窗口）。 */
const elementAround = (probe: string, tag: string): string => {
  const at = page.indexOf(probe)
  assert.ok(at >= 0, `模板缺少 ${probe}`)
  const openTag = enclosingOpenTag(page, tag, at)
  assert.ok(openTag !== null, `${probe} 必须位于 <${tag}> 内`)
  return elementSlice(page, page.lastIndexOf(openTag, at), tag)
}

/** zh/en 母本都必须有该键且值非空。 */
const assertKeyInBoth = (key: string): void => {
  for (const [label, lexicon] of [['zh', zh], ['en', en]] as const) {
    const line = lexicon.split('\n').find((text) => new RegExp(`^\\s+${key}: '`).test(text))
    assert.ok(line !== undefined, `${label} 词条缺 ${key}`)
    assert.match(line!, /:\s*'[^']/, `${label} ${key} 词条值不得为空`)
  }
}

// ── 协议切换：快照 / 清理 / 回填 ──

test('协议 watch：TCP 分支先拍快照再清理，回转分支按快照回填，各调用一次', () => {
  const watchBody = section(page, 'watch(() => wizardForm.protocol,', 'watch(() => wizardForm.enable_dns_server,')
  // 清理动作收在 enterTcpState 闭包里：确认后切换与无内容直接切换共用同一入口
  const enterBody = section(watchBody, 'const enterTcpState = (): void => {', "if (newVal === 'tcp') {")
  assert.equal(count(enterBody, 'snapshotHttpState(wizardForm)'), 1)
  assert.equal(count(enterBody, 'applyTcpState(wizardForm)'), 1)
  assert.ok(
    enterBody.indexOf('snapshotHttpState(wizardForm)') < enterBody.indexOf('applyTcpState(wizardForm)'),
    '快照必须先于清理（否则拍到的是已清空的 TCP 态）',
  )
  assert.match(
    enterBody,
    /if \(applyTcpState\(wizardForm\)\.portRelocated\) \{\s*ElMessage\.info\(t\('common\.app\.rules\.msgs\.switchedToTcpPort8080'\)\)/,
  )
  const tcpBranch = section(watchBody, "if (newVal === 'tcp') {", "} else if (newVal === 'http' && oldVal === 'tcp') {")
  // 两条路径各调一次进入函数：确认回调里一次、无待清内容时一次
  assert.equal(count(tcpBranch, 'enterTcpState()'), 2)
  assert.match(tcpBranch, /\)\.then\(\s*\(\) => enterTcpState\(\),/)
  // 取消 = 协议回滚、内容原样（回滚触发的回转分支因快照为空不回填）
  assert.match(tcpBranch, /wizardForm\.protocol = oldVal \?\? 'http'/)
  // 会被静默清空的内容必须先列清单确认
  assert.match(tcpBranch, /protocolSwitchImpact\(wizardForm, newVal\)/)
  assert.match(tcpBranch, /class: 'confirm-scope-list'/)
  const httpBranch = section(watchBody, "} else if (newVal === 'http' && oldVal === 'tcp') {", "}, { flush: 'sync' })")
  assert.equal(count(httpBranch, 'restoreHttpState(wizardForm, preTcpSnapshot)'), 1)
  assert.match(
    httpBranch,
    /restoringHttpState = true[\s\S]*\btry \{[\s\S]*restoreHttpState\(wizardForm, preTcpSnapshot\)[\s\S]*\} finally \{[\s\S]*restoringHttpState = false/,
    '回填期间必须置位守卫，并在 finally 复位',
  )
  assert.match(httpBranch, /if \(restored\) showTlsHint\(t\('common\.app\.rules\.msgs\.switchedHttpRestored'\)\)/)
  // 清理面与回填面都收进纯函数：视图里不再手写这些字段的赋值
  assert.doesNotMatch(
    watchBody,
    /wizardForm\.(?:path_rules|dynamic_dns|enable_dns_server|dns_server|health_check_host|custom_routes_enabled|forward_auth_enabled|forward_auth_upstream|upstream_force_http1|enable_tls|ntlm_compatible|strategy|listen_port) = /,
  )
  // NTLM 接管「恢复默认」的字段面与切 TCP 同源
  assert.match(member(page, 'const confirmNtlmToggle = '), /resetNtlmTakeover\(wizardForm\)/)
})

test('回填 TLS 时不触发「开启 TLS → 端口改 443」联动', () => {
  const tlsWatch = section(page, 'watch(() => wizardForm.enable_tls,', 'watch(() => wizardForm.protocol,')
  const guardAt = tlsWatch.indexOf('if (hydratingWizard || restoringHttpState) return')
  assert.ok(guardAt >= 0, 'enable_tls 联动 watcher 必须识别回填期')
  assert.ok(tlsWatch.indexOf('wizardForm.listen_port = 443') > guardAt)
})

// ── 关闭向导前的未保存检查 ──

test('向导关闭守卫：基线在 open 取、opened 定稿，脏了才确认，取消留在向导', () => {
  const dialogTag = openTags(page, 'el-dialog').find((tag) => tag.includes('v-model="wizardVisible"'))
  assert.ok(dialogTag !== undefined, '缺向导对话框（v-model="wizardVisible"）')
  assert.match(dialogTag, /@open="wizardDraft\.open"/)
  assert.match(dialogTag, /@opened="wizardDraft\.settle"/)
  const content = openTags(page, 'div').find((tag) => tag.includes('class="wizard-content"'))
  assert.ok(content !== undefined, '缺向导内容区')
  assert.match(content, /@pointerdown\.capture="wizardDraft\.touch"/)
  assert.match(content, /@keydown\.capture="wizardDraft\.touch"/)

  const close = member(page, 'const beforeWizardClose =')
  const savingAt = close.indexOf('if (saving.value) return')
  const dirtyAt = close.indexOf('if (!wizardDraft.isDirty())')
  const confirmAt = close.indexOf('ElMessageBox.confirm(')
  assert.ok(savingAt >= 0 && dirtyAt > savingAt, '保存中禁关必须先于未保存检查')
  assert.ok(confirmAt > dirtyAt, '未脏直接关闭之后才轮到确认框')
  assert.match(
    close,
    /ElMessageBox\.confirm\(t\('common\.app\.rules\.msgs\.unsavedConfirm'\), t\('common\.app\.rules\.msgs\.discard'\), \{\s*type: 'warning', confirmButtonText: t\('common\.app\.rules\.msgs\.discard'\), cancelButtonText: t\('common\.app\.rules\.msgs\.keepEditing'\),\s*\}\)/,
  )
  assert.match(close, /\.then\(\(\) => done\(\)\)/, '确认放弃才关闭')
  assert.doesNotMatch(close.slice(close.indexOf('.catch(')), /done\(\)/, '取消/ESC 必须留在向导，不得调用 done')
  assert.match(section(page, 'const resetWizard = ', 'const beforeWizardClose'), /wizardDraft\.clear\(\)/, '关闭必须清基线')
})

// ── 校验失败跳回出错步骤 ──

test('校验失败统一经 failStep：先切步骤再提示；nextStep 不再直弹 toast', () => {
  const failStep = member(page, 'const failStep = ')
  const switchAt = failStep.indexOf('currentStep.value = step')
  assert.ok(switchAt >= 0 && failStep.indexOf('ElMessage.') > switchAt, '必须先切到出错步骤再提示')
  const next = section(page, 'const nextStep = ', 'const prevStep = ')
  assert.doesNotMatch(next, /ElMessage\.(?:warning|error)\(/, '步进校验失败必须走 failStep')
  assert.equal(count(next, 'failStep('), 15, '步进门的 15 处失败出口全部经 failStep')
  assert.equal(count(next, 'failStep(WIZARD_STEP.ADVANCED, '), 1)
})

test('提交门：按出错字段所在步骤归位，每个失败出口都复位 saving 再 return', () => {
  const submit = section(page, 'const submitWizard = async', 'const data: UpdateRuleRequest')
  // 仅存的直弹 warning 是「策略绑定加载中」这类瞬时态——不是某一步的字段错误
  assert.deepEqual([...submit.matchAll(/ElMessage\.(warning|error)\(/g)].map((match) => match[0]), ['ElMessage.warning('])
  assert.match(
    submit,
    /ElMessage\.warning\(securityBindingsLoading\.value \? t\('common\.app\.rules\.msgs\.securityBindingsCopyWait'\) : t\('common\.app\.rules\.msgs\.securityBindingsCopyFailFirst'\)\)/,
  )
  assert.equal(count(submit, 'failStep(WIZARD_STEP.BASIC, '), 4, '名称/域名/端口/端口冲突 → 基本配置')
  assert.equal(count(submit, 'failStep(WIZARD_STEP.TLS, '), 2, 'DNS 配置/证书对 → TLS 配置')
  assert.equal(count(submit, 'failStep(WIZARD_STEP.CUSTOM_ROUTES, '), 2, '路径规则 → 自定义路由')
  assert.equal(count(page, 'failStep(upstreamError.step, upstreamError.message)'), 2, '启用上游门两处都按返回的步骤归位')
  assert.equal(count(submit, "'error')"), 2, '重复上游/健康检查路径保持 error 级')
  const gates = (submit.match(/^\s*failStep\(.*\)\n\s*saving\.value = false\n\s*return$/gm) ?? []).length
  assert.equal(gates, count(submit, 'failStep('), '提交门的每个 failStep 之后都必须复位 saving')
  assert.ok(gates >= 24)
  // 动态上游的协议栈在高级步选择：失败必须跳回改得了的那一步
  const upstreamGate = section(page, 'const validateEnabledUpstreams = ', 'const addUpstream = ')
  assert.match(upstreamGate, /t\('common\.app\.rules\.msgs\.duStackRequired'\), step: WIZARD_STEP\.ADVANCED \}/)
})

// ── 动态上游开关 ──

test('动态上游开关：会禁用多余上游时先列清单确认，取消回滚开关', () => {
  const toggle = member(page, 'const onDynamicDnsToggle = ')
  assert.match(toggle, /const surplus = dynamicUpstreamSurplus\(wizardForm\.upstreams\)/)
  assert.match(toggle, /if \(surplus\.length > 0 && !hydratingWizard\) \{/, '水合回填路径照旧静默归一')
  const confirmAt = toggle.indexOf('ElMessageBox.confirm(')
  const applyAt = toggle.indexOf('applyDynamicUpstreamLimit(wizardForm.upstreams)')
  assert.ok(confirmAt >= 0 && applyAt > confirmAt, '必须先确认后应用')
  assert.match(
    toggle,
    /ElMessageBox\.confirm\(\s*h\('div', \[\s*h\('div', t\('common\.app\.rules\.msgs\.dynamicUpstreamDisableLead'\)\),\s*h\('ul', \{ class: 'confirm-scope-list' \}, surplus\.map\(\(upstream\) => h\('li', hostPortKey\(upstream\.host, upstream\.port\)\)\)\),\s*\]\),\s*t\('common\.app\.rules\.msgs\.dynamicUpstreamConfirmTitle'\),/,
    '确认框必须逐行列出将被禁用的 host:port',
  )
  assert.match(
    toggle,
    /\.then\(\s*\(\) => applyDynamicUpstreamLimit\(wizardForm\.upstreams\),\s*\(\) => \{ wizardForm\.dynamic_dns = false \},?\s*\)/,
    '确认后才应用；取消必须回滚开关',
  )
  const switchTag = openTags(page, 'el-switch').find((tag) => tag.includes('v-model="wizardForm.dynamic_dns"'))
  assert.ok(switchTag !== undefined, '缺动态上游开关')
  assert.match(switchTag, /@change="onDynamicDnsToggle"/)
})

// ── 复制规则 ──

test('复制：入口不再先弹确认，副本域名留空并说明，预览状态行带提示', () => {
  const duplicate = member(page, 'const duplicateRule = ')
  assert.doesNotMatch(duplicate, /ElMessageBox\.confirm/, '保存路径已有确认，进入前不再弹第二次')
  assert.match(duplicate, /openCopyWizard\(rule\)/)
  const copy = section(page, 'const openCopyWizard = async', 'const viewConfig')
  assert.match(copy, /enabled: false,/, '副本默认禁用不得回退')
  assert.match(copy, /domain: copyRuleDomain\(fullRule\)/, 'HTTP 副本不继承源域名')
  assert.match(page, /t\('common\.app\.rules\.msgs\.copyConfirmTitle'\)/, '保存路径的复制确认仍在')

  const domainItem = elementAround('v-model="wizardForm.domain"', 'el-form-item')
  assert.match(
    domainItem,
    /<div v-if="isCopyMode" class="form-tip-line">\{\{ t\('common\.app\.rules\.wizard\.copyDomainTip'\) \}\}<\/div>/,
    'HTTP 副本的域名行必须说明默认禁用与改域名',
  )
  const portItem = elementAround('v-model="wizardForm.listen_port"', 'el-form-item')
  assert.match(
    portItem,
    /<div v-if="isCopyMode && wizardForm\.protocol !== 'http'" class="form-tip-line">\{\{ t\('common\.app\.rules\.wizard\.copyDisabledTip'\) \}\}<\/div>/,
    'TCP 副本无域名行，说明挂在端口行',
  )
  const statusItem = elementAround("t('common.app.rules.wizard.copyStatusTip')", 'el-descriptions-item')
  assert.match(statusItem, /:label="t\('common\.app\.rules\.common\.status'\)"/, '提示必须挂在预览的状态行')
  assert.match(statusItem, /<span v-if="isCopyMode" class="form-tip-inline">\{\{ t\('common\.app\.rules\.wizard\.copyStatusTip'\) \}\}<\/span>/)
})

// ── 预览与配置查看器的核对面 ──

test('预览与配置查看器覆盖认证网关 / NTLM / 路径规则 / 访问日志', () => {
  section(page, ":title=\"t('common.app.rules.cfg.previewTitle')\"", '</el-descriptions>')
  const faPreview = elementAround("{{ wizardForm.forward_auth_upstream || '-' }} · {{ wizardForm.forward_auth_uri }}", 'el-descriptions-item')
  assert.match(faPreview, /:label="t\('common\.app\.rules\.wizard\.forwardAuthLabel'\)" v-if="wizardForm\.protocol === 'http'"/)
  assert.match(faPreview, /<template v-if="forwardAuthOn">\{\{ t\('common\.app\.rules\.common\.on'\) \}\}/)
  assert.match(faPreview, /<template v-else>\{\{ t\('common\.app\.rules\.common\.off'\) \}\}<\/template>/, '关闭态也要成行，核对面才分得出「没配」和「关着」')

  const viewer = section(page, 'v-else-if="ruleConfig" class="config-view"', '</el-descriptions>')
  assert.ok(viewer.includes("ruleConfig.forward_auth_upstream || '-'"))
  const faRow = elementAround("{{ ruleConfig.forward_auth_upstream || '-' }} · {{ ruleConfig.forward_auth_uri }}", 'el-descriptions-item')
  assert.match(faRow, /:label="t\('common\.app\.rules\.wizard\.forwardAuthLabel'\)" v-if="ruleConfig\.protocol === 'http'"/)
  assert.match(faRow, /v-if="ruleConfig\.forward_auth_enabled === 1"/)
  const ntlmRow = elementAround('ruleConfig.ntlm_compatible === 1 ?', 'el-descriptions-item')
  assert.match(ntlmRow, /:label="t\('common\.app\.rules\.wizard\.ntlmCompat'\)" v-if="ruleConfig\.protocol === 'http'"/)
  const routesRow = elementAround("t('common.app.rules.cfg.pathRuleCount', { n: ruleConfig.path_rules.length })", 'el-descriptions-item')
  assert.match(routesRow, /:label="t\('common\.app\.rules\.common\.customRoutes'\)" v-if="ruleConfig\.protocol === 'http'"/)
  assert.match(routesRow, /v-if="ruleConfig\.custom_routes_enabled"/)
  const logRow = elementAround('{{ ruleConfig.log_enabled ?', 'el-descriptions-item')
  assert.match(logRow, /:label="t\('common\.app\.rules\.common\.accessLog'\)" v-if="ruleConfig\.protocol === 'http'"/)

  // 查看器的数据面必须带上这四组字段（缺一个模板就读到 undefined）
  const view = section(page, 'const buildRuleConfigView = (', 'const compressType = computed')
  for (const field of [
    'ntlm_compatible',
    'forward_auth_enabled',
    'forward_auth_upstream',
    'forward_auth_uri',
    'log_enabled',
    'custom_routes_enabled',
    'path_rules',
  ]) {
    assert.match(view, new RegExp(`\\b${field}: rule\\.`), `buildRuleConfigView 缺 ${field}`)
  }
})

// ── 词条 ──

test('新增词条 zh/en 成对；随改动退役的键两侧同步删除且页面不再引用', () => {
  for (const key of [
    'discard',
    'keepEditing',
    'unsavedConfirm',
    'dynamicUpstreamConfirmTitle',
    'dynamicUpstreamDisableLead',
    'switchedHttpRestored',
    'copyDomainTip',
    'copyDisabledTip',
    'copyStatusTip',
    'pathRuleCount',
  ]) {
    assertKeyInBoth(key)
  }
  // 调用点钉键之外再钉 zh 原文：文案被改成另一句话时本断言必红
  assert.ok(zh.includes("unsavedConfirm: '有未保存的修改，关闭将丢弃本次编辑。是否继续？'"))
  assert.ok(zh.includes("switchedHttpRestored: '已切换回 HTTP，并恢复切换前的配置'"))
  assert.ok(zh.includes("copyDomainTip: '副本默认禁用；请填写新的域名后再启用'"))
  for (const dead of ['ruleCopyConfirm', 'switchedHttp', 'listenPortAdjusted', 'tlsClosedInTcp']) {
    assert.doesNotMatch(zh, new RegExp(`\\b${dead}: `), `zh 死键 ${dead} 必须删除`)
    assert.doesNotMatch(en, new RegExp(`\\b${dead}: `), `en 死键 ${dead} 必须删除`)
    assert.doesNotMatch(page, new RegExp(`\\b${dead}\\b`), `页面不得再引用 ${dead}`)
  }
})
