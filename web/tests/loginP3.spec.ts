import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, codeSection } from './_helpers.ts'

test('Login：OIDC 状态读取失败可见且可重试，403 才静默回退本地登录', () => {
  const login = code('src/views/Login.vue')
  const loader = codeSection(
    'src/views/Login.vue',
    'const loadOidcStatus = async ()',
    'const goOIDCLogin = () => {',
  )
  assert.match(loader, /caught:\s*unknown/, '失败分支必须读取真实错误')
  assert.match(loader, /caught instanceof ApiRequestError \? caught\.status : undefined/)
  assert.match(loader, /status === 403/, '仅明确禁止的状态可静默回退')
  assert.match(loader, /oidcStatusError\.value = '无法获取企业登录状态，请重试或使用本地账号登录'/)
  assert.match(login, /v-if="oidcStatusError"/)
  assert.match(login, /@click="loadOidcStatus"[^>]*>重试</)
})

test('Login：初始化探测期间卡片显示加载态而非空白', () => {
  const login = code('src/views/Login.vue')
  assert.match(login, /<el-card class="login-card" v-loading="checkingSetup"/)
  assert.match(login, /element-loading-text="正在检查登录状态/)
})

test('Login：OIDC 顶层跳转被中止后十秒解除按钮锁，卸载清理计时器', () => {
  const login = code('src/views/Login.vue')
  const redirect = codeSection(
    'src/views/Login.vue',
    'const goOIDCLogin = () => {',
    'const handleLogin = async () => {',
  )
  assert.match(redirect, /oidcRedirectTimer = setTimeout\(/)
  assert.match(redirect, /oidcRedirecting\.value = false/)
  assert.match(redirect, /10_000/)
  assert.match(login, /const clearOidcRedirectTimer = /)
  assert.match(login, /onUnmounted\(\(\) => \{\s*clearOidcRedirectTimer\(\)/)
})
