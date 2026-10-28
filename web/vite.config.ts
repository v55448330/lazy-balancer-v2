import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'
import { buildStampPlugin } from './build/buildStamp.ts'

// 面板默认 admin_tls_enabled=0；仅开发机明确启用 HTTPS 时设置
// VITE_DEV_BACKEND_HTTPS=1（secure:false 用于自签证书）。
const devBackendTarget = process.env.VITE_DEV_BACKEND_HTTPS === '1'
  ? 'https://localhost:8000'
  : 'http://localhost:8000'

export default defineConfig({
  plugins: [
    vue(),
    Components({
      // dts:false 只是不生成 components.d.ts（避免生成物入库）。**模板类型检查
      // 已开启**：tsconfig 的 vueCompilerOptions.strictTemplates + src/vite-env.d.ts
      // 的 `element-plus/global` 引用让 el-* 的 props/组件名/指令参与 vue-tsc，
      // 拼错属性（如 :datas）会在 typecheck 阶段报错；门禁口径与放宽理由见
      // src/types/vue-template.d.ts 与 tests/viewsWiringGuards.spec.ts。
      // 自动导入的本仓组件（DialogHeader/LogStorageBar 等）需在模板所在文件显式
      // import——否则类型检查看不到它们（运行时仍由本插件解析）。
      dts: false,
      resolvers: [ElementPlusResolver({ importStyle: 'css' })],
    }),
    // dist 无自证新鲜度的手段：陈旧预构建产物会被 Dockerfile 盲目 COPY 进镜像。
    // 戳把提交号写进 dist/build-info.json（详见 build/buildStamp.ts）。
    buildStampPlugin(),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: devBackendTarget,
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(moduleId) {
          if (moduleId.includes('/node_modules/echarts/') || moduleId.includes('/node_modules/zrender/')) return 'charts'
        },
      },
    },
  },
})
