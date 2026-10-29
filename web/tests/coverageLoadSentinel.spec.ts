// 覆盖率分母哨兵：`node --test` 的覆盖率只统计**运行期被装载过**的模块，
// `--test-coverage-include='src/**/*.ts'` 只是对已装载模块的过滤器。因此未被任何
// 行为用例 import 的源文件（当前 9 个：api.ts / highlight.ts / echarts.ts /
// restart.ts / chartTheme.ts / clusterSyncSwitches.ts / useCrsRuleIndex.ts /
// useDebouncedHighlight.ts / main.ts）完全不在分母里——新增一个零测试的源文件
// 不会拉低任何指标，门禁恒绿。
//
// 本 spec 把 `src/**/*.ts` 逐个装载：行为用例没覆盖到的模块以 0% 进入分母，
// 指标随新增未测文件立刻下降（阈值取实测值、不留静默余量，见 package.json）。
//
// 装载需要两类替身（只在测试进程里生效，不影响构建）：
//   - `.vue` / `.css`（含 vite 的无扩展名 `/css` 形态）→ 空模块：模板级行为
//     测试不在本 spec 范围（`.vue` 层因此不进分母，键判据仍由视图接线用例钉）；
//   - `prismjs/components/<lang>` 与相对路径无扩展名导入（浏览器侧由 vite 补
//     后缀）→ 补 `.ts`/`.js` 后再解析。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'

import { registerModuleHooks, webFiles } from './_helpers.ts'

const STUB_MODULE = 'data:text/javascript,export default {}'

// 解析顺序：本钩子先登记，负责字节级依赖（.vue/.css）与扩展名补齐；
// `@/…` 别名交给既有的 registerModuleHooks（同一实现，不另写一份）。
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (/\.(?:vue|css)$/.test(specifier) || /\/css$/.test(specifier)) {
      return { url: STUB_MODULE, shortCircuit: true }
    }
    if (specifier.startsWith('prismjs/components/')) return nextResolve(`${specifier}.js`, context)
    if (specifier.startsWith('.')) {
      try {
        return nextResolve(specifier, context)
      } catch {
        // vite 侧省略扩展名的相对导入（`./utils/branding`）：补 .ts 再解析一次。
        return nextResolve(`${specifier}.ts`, context)
      }
    }
    return nextResolve(specifier, context)
  },
})
registerModuleHooks()

test('src 下每个 .ts 模块都能被装载哨兵解析（解析失败的文件不会进入分母）', async () => {
  // 声明文件没有可执行语句，装载它们对分母无意义（也不保证能作为模块解析）。
  const files = webFiles('src', ['.ts']).filter((file) => !file.endsWith('.d.ts'))
  // 扫描面下限：目录枚举失效（路径/后缀漂移）时该守卫会静默归零。
  assert.ok(files.length > 100, `装载面异常偏少（${files.length} 个 .ts）——目录枚举已失效`)
  const unresolvable: string[] = []
  for (const file of files) {
    try {
      // 这里必须用动态 import：装载面是运行期枚举出来的，静态 import 无法表达
      // 「把 src 下的每个模块都装载一遍」。
      await import(new URL(`../${file}`, import.meta.url).href)
    } catch (error) {
      const message = (error as Error).message
      // 求值期错误（缺 DOM、第三方模块的副作用）不影响分母：模块已被编译并计入
      // 覆盖率分母。解析失败则相反——文件根本没进统计，必须判红。
      if (/Cannot find module|ERR_MODULE_NOT_FOUND|ERR_UNSUPPORTED_DIR_IMPORT|ERR_PACKAGE_PATH_NOT_EXPORTED/.test(message)) {
        unresolvable.push(`${file}: ${message.split('\n')[0]}`)
      }
    }
  }
  assert.deepEqual(unresolvable, [], '装载哨兵必须能解析 src/**/*.ts 的全部依赖')
})
