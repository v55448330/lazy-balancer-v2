// 登录页与首次初始化页（Login.vue 的 setupMode 形态）处于未登录态，没有主界面
// 顶栏——语言切换入口随之缺失，界面语言只能听凭浏览器语言，必须先登录才能切换。
// 本 spec 钉两件事：
//   1) 入口常驻：语言切换渲染在登录卡片之外、与卡片同级。卡片整体处在「初始化
//      状态探测」加载态里，内部再分 setup / MFA / 本地登录三形态；放在卡片之前的
//      同级节点在探测期与三种形态下都可见可用。
//   2) 单源：入口直接复用主界面的 LanguageSwitcher——同一存储键（lb_locale）、
//      同一 setLocale（先落盘再整页重载，切换即时生效）；登录页不得另写一套。
//
// 运行：cd web && node --test tests/loginLanguageSwitch.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, cssDeclarations, installBrowserHost, stripComments } from './_helpers.ts'
import { detectLocale, setLocale } from '../src/i18n/index.ts'

type Verdict = { readonly ok: true } | { readonly ok: false; readonly reason: string }

const SWITCH_TAG = /<LanguageSwitcher\s*\/>/g
const ANCHOR_OPEN = /<div class="login-locale"[^>]*>/

/** 从 openTagEnd（div 开标签之后）起按 div 标签配对找到块尾下标；不平衡返回 -1。 */
const divBlockEnd = (text: string, openTagEnd: number): number => {
  const token = /<div\b[^>]*>|<\/div>/g
  token.lastIndex = openTagEnd
  let depth = 1
  for (let hit = token.exec(text); hit; hit = token.exec(text)) {
    depth += hit[0].startsWith('</') ? -1 : 1
    if (depth === 0) return token.lastIndex
  }
  return -1
}

/**
 * 登录页语言切换入口的结构判定（纯函数，输入为剥注释后的 Login.vue 源码）。
 * 合格形态：`.login-locale` 是 `.login-container` 的直接子节点、紧邻登录卡片之前、
 * 自身与内部都没有条件/状态指令，内部恰有一个 <LanguageSwitcher />。
 */
const localeAnchorVerdict = (login: string): Verdict => {
  const template = login.slice(0, login.indexOf('<script'))
  const container = /<div class="login-container"[^>]*>/.exec(template)
  if (!container) return { ok: false, reason: '缺少 .login-container 根节点' }
  const headStart = container.index + container[0].length
  const card = /<el-card\b/.exec(template.slice(headStart))
  if (!card) return { ok: false, reason: '缺少登录卡片' }
  const head = template.slice(headStart, headStart + card.index)

  const anchor = ANCHOR_OPEN.exec(head)
  if (!anchor) return { ok: false, reason: '语言切换入口缺失，或不在登录卡片之前（卡片内受加载遮罩与形态分支约束）' }
  if (/\sv-[\w-]+/.test(anchor[0])) {
    return { ok: false, reason: `语言切换入口自身不得带指令（探测期与三种形态都必须可见）：${anchor[0]}` }
  }
  const anchorEnd = divBlockEnd(head, anchor.index + anchor[0].length)
  if (anchorEnd < 0) return { ok: false, reason: '语言切换入口标签不闭合' }
  const inner = head.slice(anchor.index + anchor[0].length, anchorEnd - '</div>'.length)
  const innerSwitches = [...inner.matchAll(SWITCH_TAG)]
  if (innerSwitches.length !== 1) {
    return { ok: false, reason: `语言切换入口内必须恰有一个 <LanguageSwitcher />（实际 ${innerSwitches.length}）` }
  }
  if (inner.replace(SWITCH_TAG, '').trim() !== '') {
    return { ok: false, reason: '语言切换入口内不得再包一层节点（条件包裹会让入口在部分形态下消失）' }
  }
  const around = `${head.slice(0, anchor.index)}${head.slice(anchorEnd)}`
  if (around.trim() !== '') {
    return { ok: false, reason: '语言切换入口必须是 .login-container 的直接子节点（不得被条件节点包裹）' }
  }
  const total = [...template.matchAll(SWITCH_TAG)].length
  if (total !== 1) return { ok: false, reason: `登录页只渲染一个语言切换入口（实际 ${total}）` }
  return { ok: true }
}

test('登录页 / 首次初始化页常驻语言切换入口：卡片之外、无条件渲染、复用主界面组件', () => {
  const login = code('src/views/Login.vue')
  assert.deepEqual(localeAnchorVerdict(login), { ok: true }, '语言切换入口结构不合格')
  assert.match(login, /import LanguageSwitcher from '@\/components\/LanguageSwitcher\.vue'/, '必须复用主界面的语言切换组件')
})

test('入口判定对已知劣化形态必须判不合格（判定空转即红）', () => {
  const live = code('src/views/Login.vue')
  assert.deepEqual(localeAnchorVerdict(live), { ok: true }, '变异基线本身必须合格')

  const block = /<div class="login-locale">[\s\S]*?<\/div>/.exec(live)
  if (!block) assert.fail('变异基线里找不到语言切换入口')
  const anchor = block[0]
  const rejected = (name: string, mutated: string, reasonHint: RegExp): void => {
    assert.notEqual(mutated, live, `${name}：变异未生效`)
    const verdict = localeAnchorVerdict(mutated)
    if (verdict.ok) assert.fail(`${name}：劣化形态被判定为合格`)
    assert.match(verdict.reason, reasonHint, `${name}：拒绝理由不对`)
  }

  rejected('入口被删除', live.replace(anchor, ''), /入口缺失/)
  rejected(
    '被形态条件包裹（只剩首次初始化页有入口）',
    live.replace(anchor, `<template v-if="setupMode">\n${anchor}\n</template>`),
    /直接子节点/,
  )
  rejected(
    '入口自身带探测期条件（探测期间不可用）',
    live.replace('<div class="login-locale">', '<div class="login-locale" v-if="!checkingSetup">'),
    /不得带指令/,
  )
  rejected(
    '入口移入登录卡片（被加载遮罩覆盖、随形态分支卸载）',
    live.replace(anchor, '').replace(/(<el-card class="login-card"[^>]*>)/, `$1${anchor}`),
    /入口缺失/,
  )
  rejected(
    '入口内部再包条件节点',
    live.replace(anchor, anchor.replace(SWITCH_TAG, '<template v-if="!checkingSetup"><LanguageSwitcher /></template>')),
    /不得再包一层/,
  )
  rejected('卡片之前并排两个入口', live.replace(anchor, `${anchor}${anchor}`), /直接子节点/)
  rejected(
    '首次初始化形态内另渲染一个入口',
    live.replace(/(<el-form v-if="setupMode"[^>]*>)/, `$1<LanguageSwitcher />`),
    /只渲染一个/,
  )
  rejected(
    '实现被注释掉（剥注释视图下等同删除）',
    stripComments(`<!-- ${anchor} -->${live.replace(anchor, '')}`),
    /入口缺失/,
  )
})

test('单源：登录页不另写语言切换，入口与主界面共用 LanguageSwitcher → setLocale', () => {
  const login = code('src/views/Login.vue')
  assert.doesNotMatch(login, /setLocale\(/, '页面不得直接调用 setLocale（走共享组件）')
  assert.doesNotMatch(login, /['"]lb_locale['"]/, '页面不得直接读写语言存储键')
  assert.doesNotMatch(login, /location\.reload\(/, '页面不得自管整页重载')
  assert.doesNotMatch(login, /\blocalStorage\b/, '页面不得自管语言偏好存储')

  const switcher = code('src/components/LanguageSwitcher.vue')
  assert.match(switcher, /import \{ setLocale, type Locale \} from '@\/i18n'/, '共享组件必须走 i18n 单源')
  assert.match(switcher, /if \(l !== locale\.value\) setLocale\(l\)/, '选择当前语言不得触发重载')

  // 「复用主界面的组件」这一事实本身：主界面顶栏与登录页渲染的是同一个组件。
  const layout = code('src/components/layout/AppLayout.vue')
  assert.match(layout, /import LanguageSwitcher from '@\/components\/LanguageSwitcher\.vue'/)
  assert.match(layout, /<LanguageSwitcher \/>/)
})

test('入口位于页面右上角：以页面容器为定位基准，贴上、右两条边', () => {
  const login = code('src/views/Login.vue')
  const anchor = cssDeclarations(login, '.login-locale')
  assert.equal(anchor.get('position'), 'absolute', '入口必须脱离卡片布局定位在角落')
  assert.ok(anchor.has('top'), '入口必须声明 top（贴上边）')
  assert.ok(anchor.has('right'), '入口必须声明 right（贴右边）')
  assert.ok(!anchor.has('left'), '入口不得同时声明 left（会被拉伸成整行）')
  const container = cssDeclarations(login, '.login-container')
  assert.equal(container.get('position'), 'relative', '页面容器必须是入口的定位基准')
  // 容器 min-height: 100vh 且带上下内边距：content-box 下高度=100vh+内边距，
  // 整页多出一截滚动、卡片随之下移（预留行把内边距加大后更明显）。
  assert.equal(container.get('box-sizing'), 'border-box', '页面容器必须按 border-box 计高，100vh 须含内边距')
})

test('切换即时生效：setLocale 先写 lb_locale 再整页重载，重载后按同一键恢复', () => {
  const storage = new Map<string, string>()
  const reloads: Array<string | undefined> = []
  const location = {
    href: 'https://panel.example/',
    reload: (): void => { reloads.push(storage.get('lb_locale')) },
  }
  const host = installBrowserHost({ localStorage: storage, navigator: { language: 'zh-CN' }, location })
  try {
    assert.equal(detectLocale(), 'zh-CN', '无已存偏好时按浏览器语言回落')

    setLocale('en')
    assert.deepEqual(reloads, ['en'], '必须先落盘再重载——重载发生时存储里已是新语言')
    assert.equal(storage.get('lb_locale'), 'en', '偏好必须落在共享存储键上')
    assert.equal(detectLocale(), 'en', '重载后的启动期必须按同一存储键取到新语言')

    setLocale('zh-CN')
    assert.deepEqual(reloads, ['en', 'zh-CN'], '每次切换都即时的整页重载')
    assert.equal(detectLocale(), 'zh-CN')
  } finally {
    host.restore()
  }
})

test('语言菜单可看出当前语言：当前项带选中态样式与 aria-current', () => {
  const switcher = code('src/components/LanguageSwitcher.vue')
  // 选项按当前语言打 active 类（无新增文案），样式按 popper-class 限定作用域
  assert.match(switcher, /:class="\{ active: current === 'zh-CN' \}"/, '中文项缺选中态类')
  assert.match(switcher, /:class="\{ active: current === 'en' \}"/, '英文项缺选中态类')
  assert.match(switcher, /popper-class="lang-switcher-menu"/, 'popper 必须带作用域类（下拉 teleport 到 body，scoped 样式够不到）')
  assert.match(
    switcher,
    /\.lang-switcher-menu \.el-dropdown-menu__item\.active\s*\{[^}]*color:/,
    '选中态必须有可见样式（此前的 active 类只有绑定、没有样式=看不出当前语言）',
  )
  assert.match(switcher, /:aria-current="current === 'zh-CN' \? 'true' : undefined"/, '读屏也需知道当前语言')
})
