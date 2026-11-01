// 版本比较纯函数（versionCheck.ts）全形状验收：官网 versions.json 的
// `vX.Y.Z` / `vX.Y.Z-beta` 解析、isNewer 语义（同版本号下 beta 是预发布——
// v2.4.0-beta 相对 v2.4.0 不是新版本）、畸形输入恒 false、远端目录拉取
// （5s 超时 / 失败一律 null 静默）与 channel 选取（数组序=新到旧，取首个）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  VERSIONS_URL,
  fetchRemoteVersions,
  isNewer,
  parseVersion,
  pickLatestChannel,
  type RemoteVersionEntry,
} from '../src/utils/versionCheck.ts'

const entry = (version: string, channel: string): RemoteVersionEntry => ({ version, channel })

test('parseVersion：v 前缀可有可无、预发布段按连字符后缀解析', () => {
  assert.deepEqual(parseVersion('v2.4.0'), { major: 2, minor: 4, patch: 0, prerelease: null })
  assert.deepEqual(parseVersion('2.4.0'), { major: 2, minor: 4, patch: 0, prerelease: null })
  assert.deepEqual(parseVersion('v2.4.0-beta'), { major: 2, minor: 4, patch: 0, prerelease: 'beta' })
  assert.deepEqual(parseVersion('2.10.3-beta.2'), { major: 2, minor: 10, patch: 3, prerelease: 'beta.2' })
  assert.deepEqual(parseVersion('  v2.4.0  '), { major: 2, minor: 4, patch: 0, prerelease: null }, '首尾空白容忍')
})

test('parseVersion：畸形输入一律 null', () => {
  for (const bad of ['', 'abc', 'v2.4', '2', 'v2.4.0.1', 'v2.4.0-', 'v2.4.0-', 'latest', 'v2.4.0.beta']) {
    assert.equal(parseVersion(bad), null, `畸形输入 ${JSON.stringify(bad)} 必须解析失败`)
  }
  assert.equal(parseVersion(undefined as unknown as string), null)
  assert.equal(parseVersion(null as unknown as string), null)
  assert.equal(parseVersion(2.4 as unknown as string), null)
})

test('isNewer：同版本（含 v 前缀差异）不是新版本', () => {
  assert.equal(isNewer('v2.4.0', '2.4.0'), false)
  assert.equal(isNewer('2.4.0', 'v2.4.0'), false)
  assert.equal(isNewer('v2.4.0-beta', 'v2.4.0-beta'), false)
})

test('isNewer：同版本号下 beta 是预发布——相对同号正式版不是新版本（钉测）', () => {
  assert.equal(isNewer('v2.4.0-beta', 'v2.4.0'), false)
  assert.equal(isNewer('2.4.0-beta', '2.4.0'), false)
  // 反向：同号正式版相对 beta 是新版本（beta 用户收到转正提示）
  assert.equal(isNewer('v2.4.0', 'v2.4.0-beta'), true)
})

test('isNewer：beta 预发布相对更旧的正式版是新版本', () => {
  assert.equal(isNewer('v2.4.0-beta', 'v2.3.9'), true)
  assert.equal(isNewer('v3.0.0-beta.1', 'v2.9.9'), true)
  assert.equal(isNewer('v2.3.9-beta', 'v2.3.9'), false, '同号 beta 相对同号正式仍不是新版本')
})

test('isNewer：跨 major/minor/patch 双向比较', () => {
  assert.equal(isNewer('v3.0.0', 'v2.9.9'), true)
  assert.equal(isNewer('v2.10.0', 'v2.9.9'), true, 'minor 按数值比较（10 > 9）')
  assert.equal(isNewer('v2.4.1', 'v2.4.0'), true)
  assert.equal(isNewer('v2.3.9', 'v2.4.0'), false)
  assert.equal(isNewer('v1.99.99', 'v2.0.0'), false)
})

test('isNewer：预发布段之间的先后（beta < beta.2 < rc）', () => {
  assert.equal(isNewer('v2.4.1-beta.2', 'v2.4.1-beta'), true)
  assert.equal(isNewer('v2.4.1-beta', 'v2.4.1-beta.2'), false)
  assert.equal(isNewer('v2.4.1-rc.1', 'v2.4.1-beta.9'), true, '字母标识符大于数字标识符（semver）')
  assert.equal(isNewer('v2.4.1-alpha', 'v2.4.1-beta'), false, '同长度字母段按字典序')
  assert.equal(isNewer('v2.4.1-beta.2', 'v2.4.1-beta.1'), true, '同位置数字段按数值比较')
  assert.equal(isNewer('v2.4.1-beta.2', 'v2.4.1-beta.rc'), false, '数字标识符小于字母标识符（semver）')
  assert.equal(isNewer('v2.4.1-beta.rc', 'v2.4.1-beta.2'), true, '字母标识符大于数字标识符（反向）')
  assert.equal(isNewer('v2.4.1-beta', 'v2.4.1-beta'), false, '预发布段逐字符相等（经比较器归零）')
})

test('isNewer：任一侧畸形返回 false', () => {
  assert.equal(isNewer('', 'v2.4.0'), false)
  assert.equal(isNewer('v2.5.0', ''), false)
  assert.equal(isNewer('not-a-version', 'v2.4.0'), false)
  assert.equal(isNewer('v2.5.0', 'nonsense'), false)
})

test('pickLatestChannel：数组序=新到旧，取首个匹配 channel；retired 不参与；缺失返回 null', () => {
  const versions = [
    entry('v2.4.0-beta', 'retired'),
    entry('v2.3.9', 'stable'),
    entry('v2.3.7', 'stable'),
    entry('v2.3.8-beta', 'beta'),
  ]
  assert.equal(pickLatestChannel(versions, 'stable')?.version, 'v2.3.9')
  assert.equal(pickLatestChannel(versions, 'beta')?.version, 'v2.3.8-beta')
  assert.equal(pickLatestChannel([entry('v2.3.9', 'stable')], 'beta'), null)
  assert.equal(pickLatestChannel([], 'stable'), null)
})

test('fetchRemoteVersions：请求官网 versions.json 且带超时 signal', async () => {
  const real = globalThis.fetch
  let seenUrl = ''
  let seenSignal: AbortSignal | null | undefined
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    seenUrl = String(url)
    seenSignal = init?.signal
    return { ok: true, json: async () => ({ updated_at: '2026-11-01', versions: [entry('v2.4.0', 'stable')] }) } as Response
  }) as typeof fetch
  try {
    const versions = await fetchRemoteVersions()
    assert.equal(seenUrl, VERSIONS_URL)
    assert.equal(VERSIONS_URL, 'https://www.lazybalancer.org/versions.json')
    assert.ok(seenSignal instanceof AbortSignal, '必须携带 AbortSignal.timeout 超时信号')
    assert.equal(versions?.length, 1)
    assert.equal(versions?.[0]?.version, 'v2.4.0')
  } finally {
    globalThis.fetch = real
  }
})

test('fetchRemoteVersions：形状异常的条目被剔除，合法条目保留', async () => {
  const real = globalThis.fetch
  globalThis.fetch = (async () => ({
    ok: true,
    json: async () => ({
      versions: [
        entry('v2.4.0', 'stable'),
        { channel: 'beta' },
        { version: 'v2.3.9' },
        null,
        'junk',
        { version: 1, channel: 'beta' },
      ],
    }),
  })) as unknown as typeof fetch
  try {
    const versions = await fetchRemoteVersions()
    assert.deepEqual(versions, [entry('v2.4.0', 'stable')])
  } finally {
    globalThis.fetch = real
  }
})

test('fetchRemoteVersions：HTTP 非 2xx / versions 非数组 / JSON 损坏 → 一律 null', async () => {
  const real = globalThis.fetch
  const respond = (body: unknown, ok = true): typeof fetch =>
    (async () => ({
      ok,
      json: async () => body,
    })) as unknown as typeof fetch
  try {
    globalThis.fetch = respond({}, false)
    assert.equal(await fetchRemoteVersions(), null, 'HTTP 失败静默')
    globalThis.fetch = respond({ versions: 'not-an-array' })
    assert.equal(await fetchRemoteVersions(), null, 'versions 非数组静默')
    globalThis.fetch = respond(undefined)
    assert.equal(await fetchRemoteVersions(), null, 'payload 空静默')
    globalThis.fetch = (async () => ({ ok: true, json: async () => { throw new SyntaxError('bad json') } })) as unknown as typeof fetch
    assert.equal(await fetchRemoteVersions(), null, 'JSON 解析失败静默')
  } finally {
    globalThis.fetch = real
  }
})

test('fetchRemoteVersions：网络层抛错（含超时 abort）→ null，不外泄异常', async () => {
  const real = globalThis.fetch
  try {
    globalThis.fetch = (async () => { throw new TypeError('fetch failed') }) as typeof fetch
    assert.equal(await fetchRemoteVersions(), null)
  } finally {
    globalThis.fetch = real
  }
})

test('fetchRemoteVersions：超时真正触发 abort 并归为静默失败', async () => {
  const real = globalThis.fetch
  let aborted = false
  const { promise, reject } = Promise.withResolvers<never>()
  globalThis.fetch = ((_url: string | URL, init?: RequestInit) => {
    init?.signal?.addEventListener('abort', () => {
      aborted = true
      reject(new DOMException('This operation was aborted', 'AbortError'))
    })
    return promise
  }) as typeof fetch
  try {
    assert.equal(await fetchRemoteVersions(5), null)
    assert.equal(aborted, true, '超时必须经由 signal abort 生效，而非仅靠返回值')
  } finally {
    globalThis.fetch = real
  }
})
