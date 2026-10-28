// 构建戳：产物侧唯一能自证「这份 dist 来自哪个提交」的机制。镜像只 COPY
// 预构建的 web/dist，vite build 又不带任何标识，于是陈旧前端可以静默入镜像
// 而后端版本号照常显示新版本。本用例驱动插件的 generateBundle 本体（不是
// 文本钉配置行），缺失提交号/时刻/文件名任何一项都红。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { BUILD_INFO_FILE, buildInfo, buildStampPlugin } from '../build/buildStamp.ts'
import { code } from './_helpers.ts'

interface EmittedAsset {
  type: string
  fileName?: string
  source?: string
}

const emitThroughPlugin = (): EmittedAsset[] => {
  const emitted: EmittedAsset[] = []
  const plugin = buildStampPlugin()
  const generateBundle = plugin.generateBundle
  assert.equal(typeof generateBundle, 'function', '插件必须实现 generateBundle')
  // generateBundle 的 this 是 rollup 插件上下文，这里只用到 emitFile。
  const context = { emitFile: (asset: EmittedAsset): void => { emitted.push(asset) } }
  ;(generateBundle as unknown as (this: unknown, options: object, bundle: object) => void)
    .call(context, {}, {})
  return emitted
}

test('构建戳：产物根落一个 build-info.json，含提交号与构建时刻', () => {
  const emitted = emitThroughPlugin()
  assert.equal(emitted.length, 1, `必须且只发一个资产，实际 ${emitted.length}`)
  const asset = emitted[0]!
  assert.equal(asset.type, 'asset')
  assert.equal(asset.fileName, BUILD_INFO_FILE, '必须落在 dist 根（与 Dockerfile COPY 的目录同层）')
  const info = JSON.parse(asset.source ?? '') as { commit?: unknown; builtAt?: unknown }
  assert.deepEqual(Object.keys(info).sort(), ['builtAt', 'commit'], '戳内容刻意只含这两项（产物公开可读）')
  assert.match(String(info.commit), /^[0-9a-f]{7,40}$|^unknown$/, `提交号形态异常：${String(info.commit)}`)
  assert.ok(!Number.isNaN(Date.parse(String(info.builtAt))), `构建时刻必须是可解析时间：${String(info.builtAt)}`)
})

test('构建戳：时刻由调用方注入（避免用例依赖真实时钟）', () => {
  const fixed = new Date('2026-01-02T03:04:05.000Z')
  assert.equal(buildInfo(fixed).builtAt, '2026-01-02T03:04:05.000Z')
})

test('构建戳插件挂在 vite 插件链上（否则 vite build 不产戳）', () => {
  assert.match(code('vite.config.ts'), /buildStampPlugin\(\)/, 'vite 配置必须注册构建戳插件')
})
