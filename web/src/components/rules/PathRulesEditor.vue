<template>
  <div class="path-rules-editor">
    <div class="editor-section-header">
      <div class="editor-heading-copy">
        <h3 class="editor-title">自定义路由</h3>
        <el-text type="info" size="small">按顺序匹配，先命中先生效；未命中走默认上游</el-text>
      </div>
      <el-button type="primary" :icon="Plus" @click="addRule">添加路径规则</el-button>
    </div>

    <div class="path-rules-list">
      <el-card
        v-for="(rule, index) in pathRules"
        :key="rule.id ?? `new-${index}`"
        shadow="never"
        class="path-rule-card"
      >
        <div class="path-rule-main-row">
          <span class="path-rule-order">规则 {{ index + 1 }}</span>

          <label class="rule-field match-type-field">
            <span class="rule-field-label">匹配方式</span>
            <el-select v-model="rule.match_type" aria-label="匹配方式">
              <el-option label="前缀匹配" value="prefix" />
              <el-option label="精确匹配" value="exact" />
            </el-select>
          </label>

          <label class="rule-field path-field">
            <span class="rule-field-label">路径</span>
            <el-input v-model="rule.path" :aria-label="`路径规则 ${index + 1} 的路径`" placeholder="例如：/api" />
          </label>

          <div class="path-rule-actions">
            <el-tooltip content="上移" placement="top">
              <el-button :icon="ArrowUp" size="small" plain :disabled="index === 0" aria-label="上移路径规则" @click="moveRule(index, -1)" />
            </el-tooltip>
            <el-tooltip content="下移" placement="top">
              <el-button :icon="ArrowDown" size="small" plain :disabled="index === pathRules.length - 1" aria-label="下移路径规则" @click="moveRule(index, 1)" />
            </el-tooltip>
            <el-tooltip content="删除" placement="top">
              <el-button :icon="Delete" size="small" type="danger" plain aria-label="删除路径规则" @click="removeRule(index)" />
            </el-tooltip>
          </div>
        </div>

        <div class="custom-upstream-section">
          <div class="custom-upstream-toggle">
            <el-switch :model-value="rule.upstreams !== null" @change="toggleCustomUpstreams(rule, $event)" />
            <div class="custom-upstream-copy">
              <span class="custom-upstream-title">使用自定义上游</span>
              <el-text type="info" size="small">关闭时使用规则的默认上游服务器</el-text>
            </div>
          </div>

          <div v-if="rule.upstreams !== null" class="custom-upstream-editor">
            <div class="upstream-grid upstream-grid-header" aria-hidden="true">
              <span>地址</span>
              <span>端口</span>
              <span>权重</span>
              <span>操作</span>
            </div>
            <div v-for="(upstream, upstreamIndex) in rule.upstreams" :key="upstreamIndex" class="upstream-grid upstream-row">
              <label class="upstream-field upstream-address-field">
                <span class="mobile-field-label">地址</span>
                <el-input v-model="upstream.address" :aria-label="`路径规则 ${index + 1} 自定义上游 ${upstreamIndex + 1} 地址`" placeholder="IP 或域名" />
              </label>
              <label class="upstream-field">
                <span class="mobile-field-label">端口</span>
                <el-input-number v-model="upstream.port" :min="1" :max="65535" aria-label="端口" controls-position="right" />
              </label>
              <label class="upstream-field">
                <span class="mobile-field-label">权重</span>
                <el-input-number v-model="upstream.weight" :min="1" :max="100" aria-label="权重" controls-position="right" />
              </label>
              <el-button :icon="Delete" type="danger" link aria-label="删除自定义上游" @click="removeUpstream(rule, upstreamIndex)" />
            </div>
            <el-button class="add-upstream-button" size="small" plain :icon="Plus" @click="addUpstream(rule)">添加上游</el-button>
          </div>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ArrowDown, ArrowUp, Delete, Plus } from '@element-plus/icons-vue'
import type { PathRule, PathRuleUpstream } from '@/types'

const pathRules = defineModel<PathRule[]>({ required: true })

const normalizeOrder = (): void => {
  pathRules.value.forEach((rule, index) => { rule.sort_order = index })
}

const addRule = (): void => {
  pathRules.value.push({ match_type: 'prefix', path: '/', sort_order: pathRules.value.length, upstreams: null })
}

const removeRule = (index: number): void => {
  pathRules.value.splice(index, 1)
  normalizeOrder()
}

const moveRule = (index: number, direction: -1 | 1): void => {
  const targetIndex = index + direction
  if (targetIndex < 0 || targetIndex >= pathRules.value.length) return
  const current = pathRules.value[index]
  const target = pathRules.value[targetIndex]
  if (!current || !target) return
  pathRules.value.splice(index, 1, target)
  pathRules.value.splice(targetIndex, 1, current)
  normalizeOrder()
}

const defaultUpstream = (): PathRuleUpstream => ({ address: '', port: 80, weight: 100 })

const toggleCustomUpstreams = (rule: PathRule, enabled: string | number | boolean): void => {
  rule.upstreams = Boolean(enabled) ? [defaultUpstream()] : null
}

const addUpstream = (rule: PathRule): void => {
  rule.upstreams?.push(defaultUpstream())
}

const removeUpstream = (rule: PathRule, index: number): void => {
  rule.upstreams?.splice(index, 1)
}
</script>

<style scoped>
.path-rules-editor { display: flex; flex-direction: column; gap: 16px; padding: 0 20px; }
.editor-section-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.editor-heading-copy { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.editor-title { margin: 0; color: var(--text-primary); font-size: 14px; font-weight: 600; }
.path-rules-list { display: flex; flex-direction: column; gap: 12px; }
.path-rule-card { border-color: var(--border); background: var(--bg-primary); }
.path-rule-card :deep(.el-card__body) { padding: 16px; }
.path-rule-main-row { display: grid; grid-template-columns: auto minmax(0, 0.7fr) minmax(0, 1.3fr) auto; align-items: end; gap: 12px; }
.path-rule-order { align-self: center; padding: 4px 8px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--bg-secondary); color: var(--text-secondary); font-size: 12px; font-weight: 600; white-space: nowrap; }
.rule-field { display: flex; min-width: 0; flex-direction: column; gap: 4px; }
.rule-field-label, .mobile-field-label { color: var(--text-regular); font-size: 13px; font-weight: 500; }
.path-rule-actions { display: flex; align-items: center; gap: 4px; }
.path-rule-actions :deep(.el-button + .el-button) { margin-left: 0; }
.custom-upstream-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border-lighter); }
.custom-upstream-toggle { display: flex; align-items: center; gap: 8px; }
.custom-upstream-copy { display: flex; min-width: 0; flex-direction: column; gap: 4px; }
.custom-upstream-title { color: var(--text-regular); font-size: 13px; font-weight: 500; }
.custom-upstream-editor { display: flex; flex-direction: column; gap: 8px; margin-top: 12px; padding: 12px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-secondary); }
.upstream-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 0.4fr) minmax(0, 0.4fr) auto; align-items: center; gap: 8px; }
.upstream-grid-header { color: var(--text-secondary); font-size: 12px; font-weight: 500; }
.upstream-field { display: flex; min-width: 0; flex-direction: column; gap: 4px; }
.upstream-field :deep(.el-input-number) { width: 100%; }
.mobile-field-label { display: none; }
.add-upstream-button { align-self: flex-start; }

@media (max-width: 767px) {
  .path-rules-editor { padding: 0; }
  .editor-section-header { align-items: flex-start; flex-direction: column; }
  .path-rule-main-row { grid-template-columns: 1fr; align-items: stretch; }
  .path-rule-order { justify-self: start; }
  .path-rule-actions { justify-content: flex-end; }
  .upstream-grid-header { display: none; }
  .upstream-row { grid-template-columns: 1fr 1fr; align-items: end; padding-top: 8px; border-top: 1px solid var(--border); }
  .upstream-row:first-of-type { padding-top: 0; border-top: 0; }
  .upstream-address-field { grid-column: 1 / -1; }
  .mobile-field-label { display: inline; }
  .upstream-row > .el-button { justify-self: end; }
}
</style>
