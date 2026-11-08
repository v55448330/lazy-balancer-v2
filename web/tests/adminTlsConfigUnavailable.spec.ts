// 管理面板 HTTPS 读路径的后端降级态（config_unavailable）必须被前端消费：
// DB 故障/迁移窗口下 /admin-tls 以 HTTP 200 返回降级后的「未启用/自签名」值，
// 若前端把它当真相展示，运维会看到「HTTPS 已关闭」的假象——开关显示为关闭且
// 没有任何提示，基于它做的判断与操作都发生在错误前提上。
//
// 契约：显式提示「配置读取失败，显示的开关不可信」+ 开关保持禁用（不把降级值
// 当成可用状态）+ 重试走同一读路径。降级态随设置草稿存活（切换设置分页重挂
// 后提示仍成立）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { repoCode, section, code } from './_helpers.ts'

test('/admin-tls 响应类型声明 config_unavailable（后端降级读标记）', () => {
  const api = code('src/utils/api.ts')
  const decl = section(api, "get(url: '/admin-tls'", '>')
  assert.match(decl, /config_unavailable\?: boolean/, '类型必须声明后端降级读标记')
})

test('后端契约：配置读取失败时置 config_unavailable=true 且仍返回 200', () => {
  const handler = repoCode('internal/handlers/admintls.go')
  const get = section(handler, 'func (h *Handlers) GetAdminTLS', 'c.JSON(http.StatusOK')
  assert.match(get, /"config_unavailable": cfgErr != nil/, '降级读必须在读路径显式申报')
})

test('设置页消费 config_unavailable：提示不可信、开关不得视为已加载', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const draft = code('src/composables/useSettingsDraft.ts')

  // 降级态属于服务端派生缓存：切分页重挂后提示继续成立
  assert.match(draft, /const adminTlsUnavailable = ref\(false\)/)
  assert.match(draft, /adminTlsUnavailable\.value = false/, '草稿复位必须清降级态')

  const load = section(page, 'const loadAdminTls = async () => {', 'const retryLoadAdminTls')
  assert.match(
    load,
    /adminTlsUnavailable\.value = res\.data\.config_unavailable === true/,
    '读取时必须从响应取值（不得以 enabled 推断）',
  )
  assert.match(
    load,
    /adminTlsLoaded\.value = !adminTlsUnavailable\.value/,
    '降级读不得视为加载成功——开关须保持禁用',
  )
})

test('降级态渲染：明确文案「显示的开关不可信」+ 重试入口', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const warn = section(page, 'v-if="adminTlsUnavailable"', '</template>')
  assert.match(warn, /app\.settings\.basic\.tls\.readFailUntrusted/, '不得以「已关闭」静默展示降级值')
  assert.match(warn, /retryLoadAdminTls/, '须给出重试入口')
})
