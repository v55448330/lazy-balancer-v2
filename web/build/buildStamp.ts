// 前端产物构建戳：把「这份 dist 是哪个提交、什么时候产出的」写进产物。
//
// 为什么需要：镜像只 COPY 预构建的 web/dist（Dockerfile 的 `COPY web/dist /app/ui`），
// 面板展示的版本号来自后端 `/api/v1/branding`，所以「新后端 + 陈旧前端」在界面
// 上完全看不出来——排障者会把「新功能没生效」归到后端。有了 build-info.json，
// 一条命令即可机械比对：
//     git rev-parse HEAD ; cat web/dist/build-info.json
//
// 内容只有提交号与构建时刻（不含配置、凭据、环境变量）：产物经 /ui 静态挂载，
// 任何人都能读到，故刻意保持这个信息量。

import { execFileSync } from 'node:child_process'
import type { Plugin } from 'vite'

/** 产物内的构建戳文件名（位于 dist 根，随镜像进 /app/ui）。 */
export const BUILD_INFO_FILE = 'build-info.json'

export interface BuildInfo {
  /** 构建时的提交号；拿不到 git（如打包出的源码树）时为 `unknown`。 */
  commit: string
  /** ISO-8601 构建时刻。 */
  builtAt: string
}

const readCommit = (): string => {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim() || 'unknown'
  } catch {
    return 'unknown'
  }
}

/** 构建戳内容（`now` 可注入，便于确定性验证）。 */
export const buildInfo = (now: Date = new Date()): BuildInfo => ({
  commit: readCommit(),
  builtAt: now.toISOString(),
})

/** 把 build-info.json 作为资产发进 bundle（随 `vite build` 落盘到 dist 根）。 */
export const buildStampPlugin = (): Plugin => ({
  name: 'lazy-balancer-build-stamp',
  generateBundle() {
    this.emitFile({
      type: 'asset',
      fileName: BUILD_INFO_FILE,
      source: `${JSON.stringify(buildInfo(), null, 2)}\n`,
    })
  },
})
