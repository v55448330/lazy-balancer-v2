// _helpers.stripComments 自测：注释剥离必须保留字符串与正则字面量——
// 正则里的 `//`/`/*` 被误当注释会吞掉其后的真实引用（死代码扫描假绿/假红）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { code, member, section, stripComments, webFiles, webRelative } from './_helpers.ts'

test('section：缺 start / 缺 end / 顺序倒置一律抛错（边界不得空转）', () => {
  assert.throws(() => section('abc', 'x', 'c'), /missing start marker/)
  assert.throws(() => section('abc', 'a', 'x'), /missing end marker/)
  // end 只出现在 start 之前：不得返回倒置切片，必须抛错
  assert.throws(() => section('ba', 'a', 'b'), /missing end marker/)
  assert.equal(section('abc', 'a', 'c'), 'ab')
})

// member() 的**基础形状**自测单源在本文件（helper 自己的 spec）；其它 spec 只钉
// 自己依赖的增量形态（如 threatGlobe 的顶层 `;` 声明与声明头注释配对），避免同一
// 判据在两个文件各写一遍后口径漂移。
test('member：缺 marker / 无函数体 / 括号不平衡一律抛错', () => {
  assert.throws(() => member('const a = 1\n', 'const b'), /missing member/)
  assert.throws(() => member('const a = 1\n', 'const a'), /member has no body/)
  // 花括号未闭合：若 helper 改成「容错返回剩余文本」，数百条文本钉会同时空转，
  // 必须硬失败。
  assert.throws(() => member('function f() {\n  if (x) {\n', 'function f'), /unbalanced braces/)
})

test('member：单表达式箭头体不得顺延到下一个成员（越界切片）', () => {
  const src = 'const h = () => ({ a: 1 })\nconst k = () => {\n  return 9\n}\n'
  // 切片若顺延到 const k，match 可被邻接成员满足（假绿）、doesNotMatch 假红
  assert.throws(() => member(src, 'const h = '), /member has no block body/)
  // 块体成员仍正常切到自身收尾
  const k = member(src, 'const k = ')
  assert.match(k, /return 9/)
  assert.doesNotMatch(k, /const h/, '切片不得回吞前一个成员')
})

// 多行返回类型：`): {\n … } => {` 里首个 `{\n` 是类型注解。若把它当函数体，切片在
// 类型块收尾处结束，函数体整段不进切片——后续所有 doesNotMatch 恒真。
test('member：多行返回类型不得被当函数体（切片必须进入真实块体）', () => {
  const src = [
    'const f = (',
    '  x: number,',
    '): {',
    '  a: number',
    '} => {',
    '  return x',
    '}',
    'const g = () => {',
    '  return 2',
    '}',
    '',
  ].join('\n')
  const slice = member(src, 'const f = ')
  assert.match(slice, /return x/, '切片必须进入真实函数体')
  assert.doesNotMatch(slice, /return 2/, '切片不得吞下下一个成员')
  assert.doesNotMatch(slice, /const g/, '切片不得越界到下一个成员')
})

test('member：参数表内多行对象类型与函数声明返回类型同样跳过', () => {
  const paramType = 'function f(opts: {\n  a: number\n}): string {\n  return String(opts.a)\n}\n'
  assert.match(member(paramType, 'function f('), /return String/)
  const returnType = 'function g(): {\n  a: number\n} {\n  return 1\n}\nfunction h() {\n  return 2\n}\n'
  const slice = member(returnType, 'function g(')
  assert.match(slice, /return 1/)
  assert.doesNotMatch(slice, /function h/, '返回类型块后的函数体才算收尾')
})

test('section/member：注释里的同名 marker 不得命中（切片落进注释=假绿）', () => {
  const src = [
    'const k = 1',
    '// 说明：const k2 与 const k9 的旧形态如下，return 语义无关',
    'const k2 = (): string => {',
    "  return 'k'",
    '}',
    '',
  ].join('\n')
  // 注释里出现 marker：跳过注释，切到真实声明
  const seg = section(src, 'const k2', 'return')
  assert.doesNotMatch(seg, /说明/, 'section 起点不得落在注释中段')
  assert.match(seg, /const k2 = /)
  const slice = member(src, 'const k2')
  assert.match(slice, /return 'k'/)
  assert.doesNotMatch(slice, /说明/)
  // 只存在于注释里的 marker：代码里没有 → 硬失败（不得切到注释中段）
  assert.throws(() => section(src, 'const k9', 'x'), /missing start marker/)
  // 文档钉（断言对象本就是注释）仍按字面命中
  assert.match(section(src, '// 说明：', 'const k2'), /return 语义无关/)
})

test('member：模板量 ${} 内嵌对象既不提前收尾也不越界', () => {
  const src = 'const f = () => {\n  const s = `a${ { b: 1 } }c`\n  return s\n}\nconst g = () => {\n  return 2\n}\n'
  const slice = member(src, 'const f = ')
  assert.match(slice, /return s/)
  assert.doesNotMatch(slice, /return 2/, '切片不得吞下下一个成员')
})

test('行注释与块注释被剥离，字符串字面量保留', () => {
  const src = "const a = 1 // trailing\n/* block */ const b = '// not comment'\nconst c = `/* tpl */`"
  const out = stripComments(src)
  assert.doesNotMatch(out, /trailing|block/)
  assert.match(out, /'\/\/ not comment'/)
  assert.match(out, /`\/\* tpl \*\/`/)
})

test('正则字面量内的注释记号不触发剥离', () => {
  // 关键：代码与正则同行——`//`/`/*` 被误当注释会吞掉同行后续真实引用
  const src = "const re = /\\/\\//; afterCall(re)\nconst re2 = /\\/\\*/g; secondCall(re2)"
  const out = stripComments(src)
  assert.match(out, /\/\\\/\\\/\/; afterCall\(re\)/, '正则后的同行代码不得被当行注释吞掉')
  assert.match(out, /g; secondCall\(re2\)/, '正则内的 /* 不得吞掉同行后续代码')
})

test('关键字后的斜杠按正则处理（return/typeof/case）', () => {
  const src = 'function f() { return /a\\/\\/b/.test(x) }\nf()'
  const out = stripComments(src)
  assert.match(out, /f\(\)\s*$/, 'return 后的正则不得截断后续代码')
})

test('除法语义不误判为正则（操作数为标识符/数字/闭括号）', () => {
  const src = 'const q = a / b\nconst r = x / 2 // note\nconst s = (1 + 2) / 3'
  const out = stripComments(src)
  assert.match(out, /a \/ b/)
  assert.match(out, /x \/ 2/)
  assert.doesNotMatch(out, /note/)
  assert.match(out, /\(1 \+ 2\) \/ 3/)
})

test('Vue 模板注释剥离', () => {
  const out = stripComments('<div><!-- hidden --><span>ok</span></div>')
  assert.doesNotMatch(out, /hidden/)
  assert.match(out, /<span>ok<\/span>/)
})

test('同行模板注释：闭合/自闭合标签之后的 <!-- --> 同样剥离', () => {
  // 斜杠启发式若把 `</div>`、`<br />` 里的 `/` 当成正则起点，该行余下文本会被
  // 吞成「正则」，同行注释永不剥离——注释里复述代码即假绿，注释文字被当代码
  // 即误红（`section()` 可从注释中段起切）。
  const src = [
    '<div>x</div><!-- hidden-a -->',
    '<br /> <!-- hidden-b -->',
    '<span>y</span> <!-- hidden-c -->',
  ].join('\n')
  const out = stripComments(src)
  assert.doesNotMatch(out, /hidden-[abc]/)
  assert.match(out, /<div>x<\/div>/, '闭合标签本身不得被当正则吞掉')
  assert.match(out, /<br \/>/, '自闭合标签本身必须保留')
  assert.match(out, /<span>y<\/span>/)
})

test('同行注释里的代码形态不得被当成代码：section 必须抛错', () => {
  const src = 'const a = 1\n<div /> <!-- const target = 2 -->\nconst b = 3\n'
  assert.throws(() => section(src, 'const target', 'const b'), /missing start marker/)
  assert.doesNotMatch(stripComments(src), /const target/)
})

test('URL scheme 不构成行注释（`: //` 形态）', () => {
  const src = '<code>lazy-balancer://docs/setup</code>\nconst after = 1'
  const out = stripComments(src)
  assert.match(out, /lazy-balancer:\/\/docs\/setup/, 'URL 必须原样保留')
  assert.match(out, /const after = 1/, 'URL 之后的内容不得被当作注释剥掉')
})

test('全量 .vue 剥注释后不残留 <!--（潜在形态转为机检）', () => {
  const files = webFiles('src', ['.vue'])
  assert.ok(files.length >= 40, `扫描面过小（${files.length} 个 .vue）——目录枚举失效`)
  const dirty = files.filter((file) => code(file).includes('<!--'))
  assert.deepEqual(dirty, [], '模板注释未被剥离：code() 视图会咽下注释里的代码形态（断言被注释满足=假绿）')
})

test('脚本存在性断言文件禁止裸 source()/repoSource() 回流', () => {
  // 这些 spec 的断言对象是「脚本/Go 里某段实现仍在」：注释化实现是最常见的
  // 临时停用手段，raw 视图下注释里的代码仍满足断言（假绿）。已全量改走
  // code()/repoCode()，此门禁止把裸导入加回来（新增文件按同一判别表处理：
  // 模板文案/注释钉用 raw，代码存在性用 code）。
  const locked = [
    'viewsWiringGuards.spec.ts',
    'rulesUi.spec.ts',
    'securityBulk.spec.ts',
    'securityPoliciesWiring.spec.ts',
    'authRole.spec.ts',
    // 断言对象全是脚本/Go 实现（无模板文案钉），已全量改走 code()/repoCode()。
    'ingestionHealth.spec.ts',
    'autobanStatus.spec.ts',
    'certJobStatus.spec.ts',
    'countUpTween.spec.ts',
    'importFailure.spec.ts',
    'importPreview.spec.ts',
  ]
  // 只钉「裸调用」这一形态：裸**导入**已由下方递归扫描（offenders，未见
  // allowedRaw 即失败）严格蕴含——`locked` 里没有一个文件登记在 allowedRaw，
  // 在这里再写一遍导入断言是同一结论的第二份实现，删掉不会放宽守卫。
  for (const name of locked) {
    const text = readFileSync(new URL(`./${name}`, import.meta.url), 'utf8')
    assert.doesNotMatch(text, /(^|[^A-Za-z_.])(?:source|repoSource)\(/m, `${name} 仍有裸取源调用`)
  }

  // 扫描面改为递归枚举 tests/ 下全部 spec（单层 glob 会让子目录里的新 spec
  // 整体漏出守卫），只放行「raw 用于模板文案/注释文档钉」的文件清单。新增
  // 裸 source/repoSource 使用必须在清单里显式登记并确认其断言对象是文案/注释。
  const specFiles = (readdirSync(new URL('./', import.meta.url), { recursive: true }) as string[])
    .map((name) => name.replace(/\\/g, '/'))
    .filter((name) => name.endsWith('.spec.ts'))
    .sort()
  assert.ok(specFiles.length > 80, `扫描面过小（tests 下仅 ${specFiles.length} 个 spec）——递归枚举失效`)
  const rawImport = /import \{[^}]*\b(?:source|repoSource)\b[^}]*\} from '\.\/_helpers\.ts'/
  // 合成自检：判据必须能识别裸导入形态、且不误伤 code/repoCode 导入。
  assert.ok(rawImport.test("import { source } from './_helpers.ts'"), '判据抓不到裸 source 导入')
  assert.ok(rawImport.test("import { code, repoSource } from './_helpers.ts'"), '判据抓不到裸 repoSource 导入')
  assert.doesNotMatch("import { code, repoCode } from './_helpers.ts'", rawImport, '判据误伤剥注释视图导入')
  const readSpec = (name: string): string => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8')
  const allowedRaw = new Set([
    // 全体断言为模板文案/文档注释钉（用例名标注「文档钉」）；代码存在性断言
    // 一律走 code()/repoCode()，注释掉实现必须能红。
    'frontendWiringContracts.spec.ts',
    'infraWiring.spec.ts',
    'securityStagesPure.spec.ts',
    // 面板边界 marker 是 HTML 注释：先在 raw 上切片、再剥注释做代码断言。
    'panelUiWiring.spec.ts',
    // 注释文案钉（断言对象是过时注释本身，剥注释后无法判定）。
    'viewStateContracts.spec.ts',
    // 注释文案钉：断言对象是过时注释本身，剥注释后无法判定（用例名标注文档钉）。
    'feCoreContracts.spec.ts',
    'settingsWiringContracts.spec.ts',
    // 省界文件头注释与真实资源计数一致性钉。
    'admin1Provinces.spec.ts',
    // 覆盖率门槛说明（scripts/test-all.sh 的注释）与 package.json 数值的
    // 双向对账：断言对象是说明文字，剥注释后无法判定漂移。
    'coverageThresholdSource.spec.ts',
    // 模板类型门守卫：断言对象是模板里的诊断屏蔽注释（vue-ignore / ts-expect-error
    // 指令），剥注释后这些屏蔽手段不可见（用例名标注「不得…绕过」）。
    'templateTypeGate.spec.ts',
    // 注释文案钉：断言 allow 空名单的 fail-closed 说明，剥注释后无法判定。
    'securityStagesModel.spec.ts',
  ])
  // 本文件自身含判据的合成样本字符串（非真实导入），排除自扫描。
  const offenders = specFiles.filter((name) => name !== 'helpersStripComments.spec.ts' && rawImport.test(readSpec(name)) && !allowedRaw.has(name))
  assert.deepEqual(offenders, [], '新增裸 source/repoSource 使用：断言对象是代码存在性时改 code()/repoCode()；确属文案/文档钉才登记进 allowedRaw')
  const deadEntries = [...allowedRaw].filter((name) => !rawImport.test(readSpec(name)))
  assert.deepEqual(deadEntries, [], 'allowedRaw 存在不再使用 raw 的文件——删除死条目')
})

// webFiles 的键口径：相对 `web/` 的路径。旧实现按 `rel.indexOf(dir)` 取**首次**
// 出现位置切路径——检出路径本身含同名段时（CI 上 /home/ci/src/app/web/src/…）
// 键会错位成 src/app/web/src/utils/x.ts，所有「键与硬编码路径比较」的守卫集体
// 假红；取不到前缀时静默返回绝对路径则是 fail-open。此处钉锚定与硬失败。
test('webFiles 键锚定 web/ 根：路径含同名段不错位，根外路径硬失败', () => {
  const root = fileURLToPath(new URL('../', import.meta.url))
  assert.ok(root.endsWith('/'), '测试前提：web 根路径以分隔符结尾')
  assert.equal(webRelative(`${root}src/utils/api.ts`), 'src/utils/api.ts')
  assert.equal(webRelative(`${root}tests/_helpers.ts`), 'tests/_helpers.ts')
  // 同名段重复出现时按完整相对路径返回（不按首个 `src` 抢位）
  assert.equal(webRelative(`${root}src/src/x.ts`), 'src/src/x.ts')
  // 根外路径不得 fail-open 成绝对路径
  assert.throws(() => webRelative('/etc/passwd'), /不在/, 'web/ 之外的路径必须硬失败')
  assert.throws(() => webRelative(`${root}../outside.ts`), /不在/, '向上越界同样硬失败')
  assert.throws(() => webRelative(root.slice(0, -1)), /不在/, '根目录本身不是文件键')
  // 真实产出必须全部落在扫描目录下（键口径漂移会让所有目录扫描守卫假红）
  const files = webFiles('src', ['.ts'])
  assert.ok(files.length > 50, `扫描面过小（${files.length}）`)
  assert.deepEqual(files.filter((file) => !file.startsWith('src/')), [], 'webFiles 键必须锚定 web/ 根')
})
