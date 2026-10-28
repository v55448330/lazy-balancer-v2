// 规则向导提交/展示口径单源验收：
//   A. 策略卡片集与提交白名单同源派生（含 random/first，TCP 剔除 cookie）
//   B. 提交路径镜像步进 host 门（跳步直达预览不得静默剔除空 host 行）
//   C. 辅助端点（更新者/DNS 配置/CA 提供商）失败显性化并带重试
//   D. 数值控件边界与后端写侧门同源（不再写死并静默夹紧合法库值）
//   E. CA 选择器选项=启用 ∪ 当前值（已禁用项回显且不可新选）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, openTags, repoCode, section } from './_helpers.ts'
import { RULE_NUMERIC_LIMITS } from '../src/utils/ruleValidation.ts'
import { proxyTimeoutSummary } from '../src/utils/proxyTimeouts.ts'

const page = code('src/views/Rules.vue')

/**
 * 从 Go 写侧门提取界值（门缺失/形态漂移即硬失败——不得回退到 TS 字面量自证）。
 * `pattern` 第 1 组必须是界值数字。
 */
const gateBound = (text: string, pattern: RegExp, what: string): number => {
  const match = pattern.exec(text)
  assert.ok(match, `后端缺写侧门：${what}`)
  return Number(match[1])
}

// 策略枚举/卡片集的行为与跨栈对表归 strategyLabels.spec（键集由后端双 map 派生）；
// 本文件只钉「向导不另造第二份字面量」——同一不变量不重复断言。
test('A 向导不再自带第二份策略字面量，卡片与白名单均由共享常量派生', () => {
  assert.match(page, /strategyCardsForProtocol\(wizardForm\.protocol\)/)
  assert.match(page, /strategyValuesForProtocol\(wizardForm\.protocol\)/)
  assert.doesNotMatch(page, /'weighted_round_robin', 'ip_hash', 'least_conn'/, '白名单字面量数组不得回流')
  assert.doesNotMatch(page, /\{ value: 'least_conn', title:/, '卡片文案不得回流到视图')
})

test('B 提交路径镜像步进完整性门（跳步保存不得静默剔除空 host/port 行）', () => {
  const body = section(page, 'const submitWizard = async', 'const data: UpdateRuleRequest')
  assert.match(
    body,
    /upstreamTouched\.value = wizardForm\.upstreams\.map\(\(\) => true\)/,
    '提交门须与步进门同口径（先全量置 touched 再判定）',
  )
  assert.match(
    body,
    /if \(wizardForm\.upstreams\.some\(\(u, i\) => upstreamRowInvalid\(u, i\)\)\) \{\s*ElMessage\.warning\(upstreamFieldWarning\.value \|\| '请填写所有已启用上游服务器的主机地址与端口'\)/,
    '缺 host/port 门时空行会被载荷过滤静默剔除，保存「成功」但规则少了上游',
  )
  // 谓词两腿：host 与 port 缺一即无效（端口清空曾不报错也不进载荷）
  const predicates = section(page, 'const upstreamRowMissingHost', 'const upstreamFieldWarning')
  assert.match(predicates, /!u\.host && u\.enabled !== false && upstreamTouched\.value\[i\]/, 'host 腿缺失')
  assert.match(predicates, /!\(Number\(u\.port\) > 0\) && u\.enabled !== false && upstreamTouched\.value\[i\]/, 'port 腿缺失')
  assert.match(predicates, /upstreamRowMissingHost\(u, i\) \|\| upstreamRowMissingPort\(u, i\)/, '完整门须两腿并集')
  // 载荷侧过滤仍在（host+port 身份过滤），但门必须在其之前拦截
  const gateAt = body.indexOf('upstreamRowInvalid(u, i)')
  const filterAt = body.indexOf('filter(u => u.host && u.port)')
  assert.ok(gateAt >= 0 && filterAt > gateAt, '完整性门必须先于载荷过滤')
})

test('C 三个辅助端点失败有错误态 + 横幅重试（不再仅 console）', () => {
  for (const refName of ['usersLoadError', 'certConfigsLoadError', 'caProvidersLoadError']) {
    assert.match(page, new RegExp(`const ${refName} = ref\\(false\\)`), `${refName} 错误态缺失`)
  }
  assert.match(page, /const auxDataLoadFailed = computed\(/, '失败合入单条横幅')
  const alert = section(page, 'v-if="auxDataLoadFailed"', '</el-alert>')
  assert.match(alert, /retryAuxData/, '横幅必须带重试')
  // 字段级：ACME 步骤的 DNS 配置下拉失败与「未配置」区分。
  // ⚠ 与「提示条样式统一（info-note-bar）」联动：本行钉的是当前 form-tip-line
  // 形态；若该提示迁到 info-note-bar，须在同一提交里同步改这条断言（文案保留），
  // 否则纯样式改动会被误判成回归。
  assert.match(
    page,
    /v-if="certConfigsLoadError" class="form-tip-line port-warning">DNS 提供商配置加载失败/,
  )
  for (const fetchName of ['fetchUsers', 'fetchCertConfigs', 'fetchCAProviders']) {
    const fn = section(page, `const ${fetchName} = async`, '\n}\n')
    assert.match(fn, /LoadError\.value = true/, `${fetchName} 失败须置错误态`)
  }
})

test('D 数值控件边界与后端写侧门逐值对表（改门即红）', () => {
  // 这四条常量的唯一存在理由就是镜像后端写侧门；只钉 TS 字面量等于自证。
  // 界值从 Go 源码提取后逐值比较：后端收紧/放宽门时前端必须同批跟随。
  const handlers = repoCode('internal/handlers/handlers.go')
  const ruleFeatures = repoCode('internal/handlers/rule_features.go')

  const intervalMin = gateBound(handlers, /if data\.HealthCheckInterval < (\d+) \{/, '健康检查间隔下限')
  assert.equal(RULE_NUMERIC_LIMITS.healthCheckIntervalMin, intervalMin, '间隔下限与后端门漂移')
  const timeoutMin = gateBound(handlers, /if data\.HealthCheckTimeout < (\d+) \{/, '健康检查超时下限')
  assert.equal(RULE_NUMERIC_LIMITS.healthCheckTimeoutMin, timeoutMin, '超时下限与后端门漂移')
  // 上游最大连接数：`u.MaxConnections < N`（0=不限，负值 400）。
  const maxConnMin = gateBound(handlers, /if u\.MaxConnections < (\d+) \{/, '上游最大连接数下限')
  assert.equal(RULE_NUMERIC_LIMITS.maxConnectionsMin, maxConnMin, '最大连接下限与后端门漂移')

  // 重试间隔上界：http 分支 `interval < 0 || interval > N`，tcp 分支
  // `duration > N || interval > N`——两协议同值，且前端 :max 必须等于该值。
  const tcpTry = section(ruleFeatures, 'func validateTCPTryWindowBounds', 'func validateStoredRuleProtocolFields')
  const intervalMax = gateBound(tcpTry, /if interval < 0 \|\| interval > (\d+) \{/, 'tcp_try_interval 上界')
  assert.equal(RULE_NUMERIC_LIMITS.tcpTryIntervalMax, intervalMax, '重试间隔上界与后端门漂移')
  const bounds = [...tcpTry.matchAll(/interval > (\d+)/g)].map((m) => Number(m[1]))
  assert.deepEqual([...new Set(bounds)], [intervalMax], '两协议分支的上界必须同值')

  // 按 el-input-number 开标签取属性集判定：不依赖属性书写顺序。此前三条否定
  // 断言把 `:max="30"` 写在字段名之前，而模板恒为「字段名在前」——真回归（重新
  // 加 :max）时空转（死断言）。标签提取必须跳过引号内的 `>`（`:min="a > b ? …"`
  // 形态），否则会在属性值中途截断。
  const inputTags = openTags(page, 'el-input-number')
  const wizardTags = (field: string): string[] => {
    const matcher = new RegExp(`\\.${field}"`)
    return inputTags.filter((tag) => matcher.test(tag))
  }

  const timeoutTags = wizardTags('health_check_timeout')
  assert.equal(timeoutTags.length, 2, '超时输入框应有两处（HTTP 主动检查与 TCP 探测）')
  for (const tag of timeoutTags) {
    assert.match(tag, /:min="RULE_NUMERIC_LIMITS\.healthCheckTimeoutMin"/)
    // 与写侧无上限对齐：不得写死上限（否则合法库值被 spinner 静默夹回）
    assert.doesNotMatch(tag, /:max=/, '超时无后端上限')
  }

  const intervalTags = wizardTags('health_check_interval')
  assert.ok(intervalTags.length > 0)
  for (const tag of intervalTags) {
    assert.match(tag, /:min="RULE_NUMERIC_LIMITS\.healthCheckIntervalMin"/)
    assert.doesNotMatch(tag, /:min="5"/, '间隔下限不得写死 5')
  }

  const maxConnTags = wizardTags('max_connections')
  assert.ok(maxConnTags.length > 0)
  for (const tag of maxConnTags) {
    assert.match(tag, /:min="RULE_NUMERIC_LIMITS\.maxConnectionsMin"/)
    assert.doesNotMatch(tag, /:max=/, '最大连接无后端上限')
  }

  const tcpTryTags = wizardTags('tcp_try_interval')
  assert.ok(tcpTryTags.length > 0)
  for (const tag of tcpTryTags) {
    assert.match(tag, /:max="RULE_NUMERIC_LIMITS\.tcpTryIntervalMax"/)
    assert.doesNotMatch(tag, /:max="10000"/, '重试间隔上界不得写死 10000')
  }

  // 健康阈值与 upstream_keepalive_timeout：写侧只有下限（阈值 ≥1 / keepalive 拒负），
  // 前端不得写死上限——API/MCP 写入的合法值（20 / 7200）一旦触碰控件会被
  // el-input-number 静默夹到 10 / 3600 并随保存落库。
  for (const field of ['health_check_unhealthy_threshold', 'health_check_healthy_threshold', 'upstream_keepalive_timeout']) {
    const tags = wizardTags(field)
    assert.ok(tags.length > 0, `缺 ${field} 控件`)
    for (const tag of tags) assert.doesNotMatch(tag, /:max=/, `${field} 无后端上限`)
  }
})

test('E CA 选择器选项包含当前值（已禁用回显不可新选）', () => {
  // 选项构造函数与标签函数单源在 utils/caProviderOptions（selectableReferencedOptions /
  // referencedOptionLabel）：视图只做取值，不得内联过滤。
  assert.match(page, /const wizardCAProviderOptions = computed\(\(\) => selectableReferencedOptions\(/)
  assert.match(page, /v-for="p in wizardCAProviderOptions"/)
  assert.match(page, /:label="referencedOptionLabel\(p\)"/)
  assert.match(page, /:disabled="!p\.enabled"/)
  assert.doesNotMatch(page, /enabledCAProviders/, '裸 enabled 过滤会让已禁用引用显示成裸 id')
})

test('F 证书任务视图类型收敛共享定义（不再自带第二份字段清单）', () => {
  assert.match(page, /type CertJob = Pick<CertJobListItem,/)
  assert.doesNotMatch(page, /interface CertJob \{/, '字段清单不得回流视图')
})

test('G 自定义路由提交门镜像步进门（空清单不得落 custom_routes_enabled=1）', () => {
  const body = section(page, 'const submitWizard = async', 'const data: UpdateRuleRequest')
  const gate = section(body, "if (wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled) {", 'const pathRuleError = validatePathRules')
  assert.match(gate, /wizardForm\.path_rules\.length === 0/, '空清单必须先于形状校验被拦下')
  assert.match(gate, /请至少添加一条路径规则/, '与步进门同文案')
  const next = section(page, 'const nextStep = ', 'const prevStep = ')
  assert.match(next, /请至少添加一条路径规则/, '步进门仍在（两门同口径）')
})

test('H 规则名称与后端 100 字符门同源（不再过确认才 400）', () => {
  const body = section(page, "v-model=\"wizardForm.name\"", '/>')
  assert.match(body, /maxlength="100"/)
  assert.match(body, /show-word-limit/)
})

test('I 负载策略卡与流程入口键盘可达', () => {
  const cards = section(page, 'class="strategy-cards"', '</el-tooltip>')
  assert.match(cards, /role="radiogroup"/, '同组语义')
  assert.match(cards, /role="radio"/)
  assert.match(cards, /:aria-checked="wizardForm\.strategy === card\.value"/)
  assert.match(cards, /:aria-disabled="strategyLocked\(card\.value\)"/)
  // roving tabindex：整组只有一个 tab stop（锁定项与未选中项 -1），方向键移动
  assert.match(cards, /:tabindex="strategyTabindex\(card\.value\)"/)
  assert.match(cards, /@keydown="onStrategyKeydown\(\$event\)"/)
  assert.match(cards, /@keydown\.enter\.prevent="activateOnce\(\$event, \(\) => selectStrategy\(card\.value\)\)"/)
  assert.match(cards, /@keydown\.space\.prevent="activateOnce\(\$event, \(\) => selectStrategy\(card\.value\)\)"/)
  const roving = section(page, 'const strategyLocked = ', 'const selectStrategy = ')
  assert.match(roving, /rovingTabindex\(strategyCardOptions\.value\.map\(\(card\) => card\.value\), wizardForm\.strategy, strategyLocked, value\)/)
  assert.match(roving, /nextRadioValue\(/, '方向键必须落到组内移动')
  assert.match(roving, /strategyCardRefs\.get\(next\)\?\.focus\(\)/, '移动后必须跟进焦点')
  // 处理流程入口必须是真的可聚焦控件（el-link 无 href 渲染成不进 Tab 序的 <a>）
  assert.match(page, /<el-button link type="primary" @click="openFlowFromLock\(row(?: as [A-Za-z]+)?\)"/)
  assert.doesNotMatch(page, /<el-link type="primary"[^>]*openFlowFromLock/)
})

test('J 上游行内控件与图标按钮带可访问名（含行序）', () => {
  for (const label of ['主机地址', '端口', '协议', '回源域名', '权重（%）', '启用']) {
    assert.match(page, new RegExp(`上游第 \\$\\{\\$index \\+ 1\\} 行${label}`), `缺 ${label} 的 aria-label`)
  }
  // 最大连接/请求数按协议换词，仍是逐行名称
  assert.match(page, /上游第 \$\{\$index \+ 1\} 行\$\{wizardForm\.protocol === 'tcp' \? '最大连接' : '最大请求数'\}/)
  // 图标记删除按钮 N 行同名 → 必须带行序
  assert.match(page, /:aria-label="`删除上游第 \$\{\$index \+ 1\} 行`"/)
})

test('K TLS 证书详情重试成功后触发解析（验证块与预览不得留空）', () => {
  const retry = section(page, 'async function retryTlsDetail', 'const resetCertInfo')
  const assignKey = retry.indexOf('wizardForm.tlsKeySet = resp.data.tls_key_set === true')
  const validate = retry.indexOf('void validateCertificate()')
  assert.ok(assignKey > 0, '证书回填缺失')
  assert.ok(validate > assignKey, '回填后必须触发解析（derive 效果与正常加载路径一致）')
})

test('L 预览覆盖高级步全部可编辑项（请求体/Keepalive/代理超时/强制 HTTP1）', () => {
  const preview = section(page, 'title="配置预览"', '</el-descriptions>')
  assert.match(preview, /label="请求体大小"/, '请求体大小 0=全局默认的特殊语义必须可核')
  assert.match(preview, /label="Keepalive 超时"/)
  assert.match(preview, /label="代理超时"/)
  assert.match(preview, /label="强制 HTTP\/1\.1"/)
  // 代理超时七项不另造第二份清单：摘要取自字段单源
  assert.match(preview, /\{\{ proxyTimeoutSummary\(wizardForm\) \}\}/)

  // 摘要行为：0 继承全局、-1 立即透传、>0 秒值
  const base = {
    proxy_dial_timeout: 10,
    proxy_response_header_timeout: 0,
    proxy_read_timeout: 60,
    proxy_write_timeout: 0,
    proxy_stream_timeout: 0,
    proxy_flush_interval: -1,
    proxy_stream_close_delay: 5,
  }
  const summary = proxyTimeoutSummary(base)
  for (const clause of ['连接超时 10s', '响应头超时 全局', '读超时 60s', '流式超时 全局', '刷新间隔 立即透传', '流关闭延迟 5s']) {
    assert.ok(summary.includes(clause), `摘要缺 ${clause}：${summary}`)
  }
  // 七项全列（任一缺席都与「核对面」承诺矛盾）
  assert.equal(summary.split(' / ').length, 7)
})

test('M 「从文件读取」写入后重算证书校验（不得停留在上一份材料结论）', () => {
  const paste = section(page, 'const pasteFromFile = ', 'const openWizard = ')
  const certAssign = paste.indexOf('wizardForm.tls_cert = content')
  const keyAssign = paste.indexOf('wizardForm.tls_key = content')
  const revalidate = paste.indexOf('void validateCertificate()')
  assert.ok(certAssign > 0 && keyAssign > 0, '两路写入缺失')
  assert.ok(revalidate > keyAssign, '赋值之后必须重算（validateCertificate 自带会话/序号守卫）')
})

test('N 统计单飞锁在重试入口移交所有权（重试后不得永久冻结）', () => {
  const start = section(page, 'const startLogStats = async', 'const onRuleLogTabChange')
  const reset = start.indexOf('logStatsInFlight.value = false')
  const seq = start.indexOf('const requestSeq = ++ruleLogRequestSeq')
  assert.ok(reset > 0 && seq > reset, '重试先清锁再取新 seq（旧在途请求的 finally 因 seq 失配不会释放）')
})
