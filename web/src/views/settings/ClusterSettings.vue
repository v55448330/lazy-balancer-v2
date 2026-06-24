<template>
  <el-card class="settings-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Connection /></el-icon>
          <span>集群管理</span>
        </div>
      </div>
    </template>
    <el-form :model="settings" label-width="120px" class="settings-form">
      <el-form-item label="节点模式">
        <el-radio-group v-model="settings.is_master" :disabled="!isAdmin">
          <el-radio :true-value="true" :false-value="false">主节点</el-radio>
          <el-radio :true-value="false" :false-value="true">从节点</el-radio>
        </el-radio-group>
        <div class="form-tip">主节点管理负载均衡规则，从节点同步配置</div>
      </el-form-item>
      <el-form-item label="主节点地址" v-if="!settings.is_master">
        <el-input v-model="settings.master_url" placeholder="http://192.168.1.1:8000" />
        <div class="form-tip">从节点需要连接到主节点</div>
      </el-form-item>
      <el-form-item label="同步间隔">
        <el-input-number v-model="settings.sync_interval" :min="10" :max="3600" />
        <div class="form-tip">从节点同步配置的间隔（秒）</div>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { Connection } from '@element-plus/icons-vue'

const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

const settings = defineModel<any>('settings', { required: true })
</script>

<style scoped>
.card-header { display: flex; align-items: center; }
.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: #111827;
}
.settings-form { padding: 4px 0; }
.form-tip {
  font-size: 12px;
  color: #9ca3af;
  margin-top: 4px;
}
</style>
