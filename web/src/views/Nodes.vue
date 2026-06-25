<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Share /></el-icon>
          节点管理
        </h2>
        <p class="page-desc">管理集群节点和主从关系</p>
      </div>
    </div>

    <el-row :gutter="20">
      <el-col v-for="node in nodes" :key="node.id" :span="8" class="node-col">
        <el-card class="node-card" :class="{ 'node-online': node.online, 'node-offline': !node.online }">
          <div class="node-header">
            <div class="node-avatar" :class="{ 'online': node.online }">
              <el-icon><Monitor /></el-icon>
            </div>
            <div class="node-info">
              <div class="node-hostname">{{ node.hostname }}</div>
              <div class="node-tags">
                <el-tag :type="node.is_master ? 'danger' : 'warning'" size="small" effect="plain">
                  {{ node.is_master ? '主节点' : '从节点' }}
                </el-tag>
                <el-tag :type="node.online ? 'success' : 'danger'" size="small" effect="plain">
                  {{ node.online ? '在线' : '离线' }}
                </el-tag>
              </div>
            </div>
          </div>
          <el-divider />
          <div class="node-details">
            <div class="detail-row">
              <span class="detail-label">IP 地址</span>
              <span class="detail-value">{{ node.ip || '-' }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">最后心跳</span>
              <span class="detail-value">{{ formatDate(node.last_heartbeat) || '-' }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card v-if="nodes.length === 0" class="empty-card">
      <el-empty description="暂无节点信息" :image-size="80">
        <el-button type="primary">添加节点</el-button>
      </el-empty>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { Share, Monitor } from '@element-plus/icons-vue'

const nodes = ref<any[]>([])

const fetchNodes = async () => {
  const res = await request.get('/nodes')
  nodes.value = res.data || []
}

onMounted(() => {
  fetchNodes()
})
</script>

<style scoped>
.page { max-width: 1500px; margin: 0 auto; }

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.header-left { flex: 1; }

.page-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 18px;
  font-weight: 600;
  color: #111827;
  margin: 0;
}

.title-icon { color: #3b82f6; font-size: 20px; }

.page-desc {
  font-size: 13px;
  color: #6b7280;
  margin: 4px 0 0 28px;
}

.node-col { margin-bottom: 20px; }

.node-card {
  border-left: 3px solid #e5e7eb;
}

.node-card.node-online { border-left-color: #10b981; }
.node-card.node-offline { border-left-color: #ef4444; }

.node-header {
  display: flex;
  align-items: center;
  gap: 14px;
}

.node-avatar {
  width: 44px;
  height: 44px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f3f4f6;
  color: #6b7280;
  font-size: 20px;
}

.node-avatar.online {
  background: #ecfdf5;
  color: #10b981;
}

.node-info { flex: 1; }

.node-hostname {
  font-size: 15px;
  font-weight: 600;
  color: #111827;
  margin-bottom: 6px;
}

.node-tags { display: flex; gap: 6px; }

.node-details { padding: 4px 0; }

.detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
}

.detail-label { color: #6b7280; font-size: 13px; }
.detail-value { color: #111827; font-size: 13px; font-family: monospace; }

.empty-card { padding: 20px; }
</style>