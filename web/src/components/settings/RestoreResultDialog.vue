<template>
  <el-dialog
    :model-value="visible"
    width="min(680px, 96vw)"
    class="restore-result-dialog dialog-body-inset"
    top="8vh"
    :close-on-click-modal="false"
    :show-close="false"
    align-center
    @update:model-value="() => emit('close')"
  >
    <template #header>
      <DialogHeader
        :icon="hasIssues ? WarningFilled : CircleCheckFilled"
        :title="title"
        :subtitle="hasIssues ? t('app.settings.basic.restoreResult.doneWithIssues') : t('app.settings.basic.restoreResult.doneClean')"
      />
    </template>

    <div class="restore-result">
      <!-- 恢复统计:徽章网格(解析失败回退整段文本) -->
      <section v-if="stats.length > 0" class="rr-section">
        <div class="rr-section-title">{{ t('app.settings.basic.restoreResult.statsTitle') }}</div>
        <div class="rr-stats-grid">
          <div v-for="(s, i) in stats" :key="i" class="rr-stat-chip">
            <span class="rr-stat-num">{{ s.count }}</span>
            <span class="rr-stat-label">{{ s.label }}</span>
          </div>
        </div>
      </section>
      <div v-else class="rr-message-plain">{{ message }}</div>

      <!-- 重要提示:全局性变更(封禁/CRS 树/会话吊销/冲突计数) -->
      <section v-if="notices.length > 0" class="rr-section">
        <div class="rr-section-title">{{ t('app.settings.basic.restoreResult.noticesTitle') }}</div>
        <div class="rr-notices">
          <div v-for="(n, i) in notices" :key="i" class="rr-notice">
            <el-icon class="rr-notice-icon"><InfoFilled /></el-icon>
            <span>{{ n }}</span>
          </div>
        </div>
      </section>

      <!-- 规则级警告:逐条可滚动 -->
      <section v-if="ruleWarnings.length > 0" class="rr-section">
        <div class="rr-section-title">
          {{ t('app.settings.basic.restoreResult.ruleWarningsTitle', { count: ruleWarnings.length }) }}
        </div>
        <div class="rr-warnings">
          <div v-for="(w, i) in ruleWarnings" :key="i" class="rr-warning">
            <el-icon class="rr-warning-icon"><WarningFilled /></el-icon>
            <span class="rr-warning-text">{{ w }}</span>
          </div>
        </div>
      </section>
    </div>

    <template #footer>
      <el-button type="primary" size="large" class="rr-footer-btn" @click="emit('close')">
        {{ buttonText }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { CircleCheckFilled, InfoFilled, WarningFilled } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'

const props = withDefaults(defineProps<{
  kind?: 'restore' | 'import'
  visible: boolean
  /** 后端主统计文案:「配置还原成功：规则 15 条、上游 17 个、…」(en 侧同构英文) */
  message: string
  warnings: string[]
  /** 冲突自动禁用计数行(格式化后) */
  conflictsSummary?: string
  /** 冲突禁用明细(格式化后,规则级) */
  conflicts?: string[]
  /** 按钮文案:会话吊销场景=重新登录并刷新,常规=刷新页面 */
  buttonText?: string
}>(), { kind: 'restore' })

const emit = defineEmits<{ (e: 'close'): void }>()

const { t } = useI18n()

const title = computed(() =>
  props.kind === 'import' ? t('app.settings.basic.restoreResult.importTitle') : t('app.settings.basic.restoreResult.title'))
const hasIssues = computed(() => props.warnings.length > 0 || (props.conflictsSummary ?? '') !== '')

// 统计解析:主文案「…：规则 15 条、上游 17 个、…」→ {label,count} 徽章。
// 分隔符与量词走宽松双语解析(「、」/「,」;个/条/项/源/items);任何环节解析
// 失败返回空数组,展示层回退整段文本——后端文案变化时永不丢信息。
interface StatChip { label: string; count: string }
const stats = computed<StatChip[]>(() => {
  const m = props.message.match(/[:：]\s*(.+)$/s)
  if (!m) return []
  const items = m[1]!.split(/[、,]/).map((x) => x.trim()).filter(Boolean)
  const out: StatChip[] = []
  for (const item of items) {
    const sm = item.match(/^(.+?)\s*(\d+)\s*(个|条|项|源|resources|items|entries)?$/u)
    if (!sm) return []
    out.push({ label: sm[1]!.trim(), count: sm[2]! })
  }
  return out.length > 0 ? out : []
})

// warnings 二分:规则级(「规则 xxx：…」/「Rule xxx: …」开头)进滚动列表;
// 其余(封禁变更/CRS 树/会话吊销)为全局提示。冲突明细行并入规则警告区。
const RULE_WARNING_RE = /^(规则|Rule)\s/
const ruleWarnings = computed(() => [
  ...props.warnings.filter((w) => RULE_WARNING_RE.test(w.trim())),
  ...(props.conflicts ?? []),
])
const notices = computed(() => {
  const list = props.warnings.filter((w) => !RULE_WARNING_RE.test(w.trim()))
  if (props.conflictsSummary) list.push(props.conflictsSummary)
  return list
})
</script>

<style scoped>
.restore-result { display: flex; flex-direction: column; gap: 18px; }
.rr-section-title {
  font-size: 12px; font-weight: 600; color: var(--text-secondary);
  text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 8px;
}

.rr-stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.rr-stat-chip {
  display: flex; flex-direction: column; align-items: center; gap: 2px;
  background: var(--el-fill-color-light); border-radius: 8px; padding: 10px 4px 8px;
}
.rr-stat-num { font-size: 20px; font-weight: 700; color: var(--el-color-primary); line-height: 1.1; font-variant-numeric: tabular-nums; }
.rr-stat-label { font-size: 12px; color: var(--text-regular); }

.rr-message-plain { font-size: 13px; color: var(--text-regular); line-height: 1.6; }

.rr-notices { display: flex; flex-direction: column; gap: 8px; }
.rr-notice {
  display: flex; align-items: flex-start; gap: 8px; font-size: 13px; line-height: 1.55;
  color: var(--text-regular); background: var(--el-color-info-light-9);
  border-left: 3px solid var(--el-color-info-light-5); border-radius: 4px; padding: 8px 10px;
}
.rr-notice-icon { flex: none; margin-top: 3px; color: var(--el-color-info); font-size: 15px; }

.rr-warnings {
  display: flex; flex-direction: column; gap: 6px;
  max-height: 220px; overflow-y: auto; padding-right: 4px;
}
.rr-warning {
  display: flex; align-items: flex-start; gap: 8px; font-size: 13px; line-height: 1.5;
  color: var(--text-regular); background: var(--el-color-warning-light-9);
  border-left: 3px solid var(--el-color-warning-light-5); border-radius: 4px; padding: 7px 10px;
}
.rr-warning-icon { flex: none; margin-top: 2px; color: var(--el-color-warning); font-size: 15px; }
.rr-warning-text { word-break: break-word; }

.rr-footer-btn { width: 100%; }
</style>
