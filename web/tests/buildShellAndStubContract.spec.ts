// 构建壳与测试卫生（构建配置单源盘）：
//   - web/index.html 的挂载点/入口脚本/语言/首帧标题——被删时 vite build 仍产出
//     空壳，运行期整页空白，而全部行为用例照绿；
//   - 每个 spec 必须至少含 `test(` 与 `assert`（新增空 spec 文件不得静默混入）；
//   - `_stubs` 的两处 ElMessage 替身共用同一契约（可调用 + 同名记录）。

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { calls, resetCalls, EL_MESSAGE_METHODS, STUB_ELEMENT, STUB_SAVE_RESULT_DEPS, type StubCall } from './_stubs.ts'
import { code } from './_helpers.ts'

const webRoot = new URL('../', import.meta.url)

test('index.html 保留挂载点、入口脚本与首帧标题（否则运行期整页空白）', () => {
  const html = readFileSync(new URL('index.html', webRoot), 'utf8')
  assert.match(html, /<div id="app"><\/div>/, 'SFC 挂载点缺失（main.ts 挂到 #app）')
  assert.match(html, /<script type="module" src="\/src\/main\.ts"><\/script>/, '入口脚本缺失或路径漂移')
  assert.match(html, /<html lang="zh-CN">/, '语言声明漂移（字体/断行与读屏口径）')
  // 首帧标题与 branding 的品牌化口径一致：`${appName} V2`。
  assert.match(html, /<title>Lazy Balancer V2<\/title>/)
  const branding = code('src/utils/branding.ts')
  assert.match(branding, /export const appName = ref\('Lazy Balancer'\)/, '品牌默认名漂移（首帧标题与运行期标题会分叉）')
  assert.match(branding, /document\.title = `\$\{appName\.value\} V2`/, '运行期标题必须同形')
})

test('每个 spec 都含 test( 与 assert（防空用例文件混入，递归扫描子目录）', () => {
  const specDir = fileURLToPath(new URL('./', import.meta.url))
  // runner 的 glob 是 `tests/**/*.spec.ts`：单层 readdirSync 会让子目录里的新
  // spec 绕过本守卫（被 runner 执行但从未被检查）。
  const files = (readdirSync(specDir, { recursive: true }) as string[])
    .filter((name) => name.endsWith('.spec.ts'))
    .sort()
  assert.ok(files.length > 50, `递归扫描必须看到全部 spec（实际 ${files.length} 个）`)
  const offenders: string[] = []
  for (const name of files) {
    const text = readFileSync(`${specDir}${name}`, 'utf8')
    // 可量化口径：顶层用例数与断言数。注释里的 `test(` 不在行首、注释里的
    // `assert.` 仍会被计入（偏宽松）；断言数少于用例数则必然存在无用例。
    const testCount = (text.match(/^test\(/gm) ?? []).length
    const assertCount = (text.match(/\bassert\./g) ?? []).length
    if (testCount === 0 || assertCount < testCount) {
      offenders.push(`${name}（test=${testCount}，assert=${assertCount}）`)
    }
  }
  assert.deepEqual(offenders, [], '空 spec / 断言少于用例数的文件不得入库')
})

test('_stubs 两处 ElMessage 替身共用同一契约（可调用 + 方法集同源）', async () => {
  const g = globalThis as unknown as { __calls?: StubCall[] }
  const previous = g.__calls
  g.__calls = calls
  resetCalls()
  try {
    // 测试本身即在验证「data: 模块替身」的加载边界（静态 import 无法加载
    // 运行时拼接的 data: URL），故此处必须用动态 import。
    const saveDeps = (await import(STUB_SAVE_RESULT_DEPS)) as {
      ElMessage: ((arg: string) => void) & Record<string, unknown>
    }
    const element = (await import(STUB_ELEMENT)) as {
      ElMessage: ((arg: string) => void) & Record<string, unknown>
    }
    assert.equal(typeof saveDeps.ElMessage, 'function', 'saveResult 替身的 ElMessage 必须可调用（真实 API 同形）')
    assert.equal(typeof element.ElMessage, 'function', 'element 替身的 ElMessage 必须可调用')
    // 方法集必须逐项相同：两份替身各自漂移时（如只给一份加 warning）此前全绿。
    assert.deepEqual(
      Object.keys(saveDeps.ElMessage).sort(),
      Object.keys(element.ElMessage).sort(),
      '两处替身的 ElMessage 方法集必须一致',
    )
    assert.deepEqual(
      Object.keys(element.ElMessage).sort(),
      [...EL_MESSAGE_METHODS].sort(),
      '替身方法集必须来自单源清单（新增调用面只改 EL_MESSAGE_METHODS）',
    )
    saveDeps.ElMessage('a')
    element.ElMessage('b')
    for (const method of EL_MESSAGE_METHODS) {
      (element.ElMessage[method] as (arg: string) => void)('x')
      ;(saveDeps.ElMessage[method] as (arg: string) => void)('x')
    }
    const recorded = calls.map((call) => call.fn)
    for (const method of EL_MESSAGE_METHODS) {
      assert.ok(recorded.includes(`ElMessage.${method}`), `两处替身都必须记录 ElMessage.${method}`)
    }
    assert.equal(recorded.filter((fn) => fn === 'ElMessage').length, 2, '可调用形态各一次')
  } finally {
    g.__calls = previous
  }
})

test('src 里引用的 *.spec.ts 必须真实存在（文档指针不得悬空）', () => {
  // 单源注释常写「由 web/tests/xxx.spec.ts 对表」；指针指向不存在的文件时，
  // 维护者/审计者按注释去找门禁会扑空，误判「该不变量无覆盖」而重建第二处
  // 对表（单源退化为双源）。此处对 src 全量 *.spec.ts 引用逐个断言存在。
  const specDir = fileURLToPath(new URL('./', import.meta.url))
  const srcDir = fileURLToPath(new URL('../src/', import.meta.url))
  const referenced = new Set<string>()
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = `${dir}${entry.name}`
      if (entry.isDirectory()) {
        walk(`${full}/`)
        continue
      }
      if (!/\.(ts|vue)$/.test(entry.name)) continue
      for (const match of readFileSync(full, 'utf8').matchAll(/[A-Za-z0-9_-]+\.spec\.ts/g)) {
        referenced.add(match[0])
      }
    }
  }
  walk(srcDir)
  assert.ok(referenced.size >= 8, `src 中的 spec 指针扫描失效（仅 ${referenced.size} 个）`)
  const dangling = [...referenced].filter((name) => !existsSync(`${specDir}${name}`)).sort()
  assert.deepEqual(dangling, [], `注释里的 spec 指针指向不存在的文件：${dangling.join(', ')}`)
})
