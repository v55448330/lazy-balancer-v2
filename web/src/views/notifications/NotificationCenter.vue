<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Bell /></el-icon>
          {{ t('app.notification.pageTitle') }}
        </h2>
        <p class="page-desc">{{ t('app.notification.pageDesc') }}</p>
      </div>
    </div>

    <!-- 锚点导航 -->
    <div class="anchor-nav">
      <a v-for="sec in sections" :key="sec.id" :href="`#${sec.id}`"
        class="anchor-link" :class="{ active: activeSection === sec.id }"
        @click.prevent="scrollToSection(sec.id)">
        <el-icon :size="14"><component :is="sec.icon" /></el-icon>
        <span>{{ sec.label }}</span>
      </a>
    </div>

    <!-- 分区：我的通道 -->
    <section id="sec-channels" ref="secChannels" class="notify-section" data-section="channels">
      <ChannelCards />
    </section>

    <!-- 分区：事件订阅（含事件级消息模板） -->
    <section id="sec-subs" ref="secSubs" class="notify-section" data-section="subs">
      <SubscriptionMatrix />
    </section>

    <!-- 分区：日报（含投递目标透明） -->
    <section id="sec-daily" ref="secDaily" class="notify-section" data-section="daily">
      <DailyReport />
    </section>

    <!-- 分区：投递记录 -->
    <section id="sec-deliveries" ref="secDeliveries" class="notify-section" data-section="deliveries">
      <DeliveryLog />
    </section>

    <!-- 分区：邮件服务（管理员） -->
    <section v-if="isAdmin" id="sec-smtp" ref="secSmtp" class="notify-section" data-section="smtp">
      <SystemCredentials />
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Bell, ChatDotRound, Calendar, List, Message } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'
import ChannelCards from './ChannelCards.vue'
import SubscriptionMatrix from './SubscriptionMatrix.vue'
import DailyReport from './DailyReport.vue'
import DeliveryLog from './DeliveryLog.vue'
import SystemCredentials from './SystemCredentials.vue'

const { t } = useI18n()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

const sections = computed(() => {
  const list = [
    { id: 'channels', label: t('app.notification.tabs.channels'), icon: ChatDotRound },
    { id: 'subs', label: t('app.notification.tabs.subs'), icon: List },
    { id: 'daily', label: t('app.notification.tabs.daily'), icon: Calendar },
    { id: 'deliveries', label: t('app.notification.tabs.deliveries'), icon: Bell },
  ]
  if (isAdmin.value) {
    list.push({ id: 'smtp', label: t('app.notification.tabs.credentials'), icon: Message })
  }
  return list
})

const activeSection = ref('channels')
const secChannels = ref<HTMLElement>()
const secSubs = ref<HTMLElement>()
const secDaily = ref<HTMLElement>()
const secDeliveries = ref<HTMLElement>()
const secSmtp = ref<HTMLElement>()

const sectionRefs = () => ({
  channels: secChannels.value,
  subs: secSubs.value,
  daily: secDaily.value,
  deliveries: secDeliveries.value,
  smtp: secSmtp.value,
})

const scrollToSection = (id: string): void => {
  const refs = sectionRefs()
  const el = refs[id as keyof typeof refs]
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    activeSection.value = id
  }
}

let observer: IntersectionObserver | null = null

onMounted(() => {
  observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          const id = (entry.target as HTMLElement).dataset.section
          if (id) activeSection.value = id
        }
      }
    },
    { rootMargin: '-80px 0px -60% 0px' },
  )
  const refs = sectionRefs()
  for (const el of Object.values(refs)) {
    if (el && observer) observer.observe(el)
  }
})

onUnmounted(() => {
  if (observer) observer.disconnect()
})
</script>

<style scoped>
.anchor-nav {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-bottom: 16px;
  padding: 6px 12px;
  background: var(--el-fill-color-extra-light);
  border-radius: 8px;
  position: sticky;
  top: 8px;
  z-index: 10;
}
.anchor-link {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 6px 14px;
  border-radius: 6px;
  font-size: 13px;
  color: var(--text-secondary, #6b7280);
  text-decoration: none;
  transition: all 0.15s ease;
}
.anchor-link:hover {
  color: var(--el-color-primary);
  background: var(--el-fill-color);
}
.anchor-link.active {
  color: var(--el-color-primary);
  background: var(--el-color-primary-light-9);
  font-weight: 600;
}
.notify-section {
  margin-bottom: 24px;
  scroll-margin-top: 60px;
}
.notify-section + .notify-section {
  border-top: 1px solid var(--el-border-color-lighter);
  padding-top: 20px;
}
</style>
