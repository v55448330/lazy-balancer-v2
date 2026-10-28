// 覆盖率阈值口径单源：阈值只在 web/package.json 的 test:coverage 参数里落地，
// 门禁说明（scripts/test-all.sh 的注释）不得持有第二份数值。
//
// 为什么单列一个 spec：断言对象是**说明文字**（注释），必须走 raw 视图——剥注释
// 后无法判定注释漂移。门禁脚本此前写着「阈值 89/92/95，留余量」，而实际参数已
// 随分母换成 src/**/*.ts 全量下调到 80/91/93（余量不足 1pp）：维护者据此误判
// 「还有余量」，排查方向被带偏。故此处按 raw 读取做双向对账。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, repoSource } from './_helpers.ts'

const THRESHOLD_FLAGS = ['lines', 'branches', 'functions'] as const

const coverageScript = (): string => {
  const pkg = JSON.parse(code('package.json')) as { scripts: Record<string, string> }
  return pkg.scripts['test:coverage'] ?? ''
}

test('test:coverage 带齐三项阈值，且分母是源码全量（tests 排除）', () => {
  const coverage = coverageScript()
  for (const metric of THRESHOLD_FLAGS) {
    assert.match(
      coverage,
      new RegExp(`--test-coverage-${metric}=\\d+`),
      `${metric} 阈值缺失：只开覆盖率不设门限等于放水: ${coverage}`,
    )
  }
  assert.ok(coverage.includes(`--test-coverage-include='src/**/*.ts'`), `分母必须是源码全量: ${coverage}`)
  assert.ok(coverage.includes(`--test-coverage-exclude='tests/**'`), `tests 不得计入分母: ${coverage}`)
})

test('门禁脚本的阈值说明与 package.json 逐值一致（不得持有第二份口径）', () => {
  const thresholds = THRESHOLD_FLAGS.map((metric) => {
    const matched = new RegExp(`--test-coverage-${metric}=(\\d+)`).exec(coverageScript())
    assert.ok(matched, `package.json 缺少 ${metric} 阈值`)
    return matched[1]!
  })
  const gateScript = repoSource('scripts/test-all.sh')
  const declared = [...gateScript.matchAll(/阈值 (\d+)\/(\d+)\/(\d+)/g)].map(
    (match) => `${match[1]}/${match[2]}/${match[3]}`,
  )
  assert.deepEqual(
    declared,
    [thresholds.join('/')],
    `scripts/test-all.sh 的阈值说明必须与 package.json 一致（实际 ${declared.join(' | ') || '缺失'}）——`
    + '换分母/调阈值时两处必须同改，否则读者按旧口径判断「还有余量」',
  )
})
