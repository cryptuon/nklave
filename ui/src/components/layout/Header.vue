<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { useHealthStore } from '@/stores/health'

const route = useRoute()
const healthStore = useHealthStore()

const pageTitle = computed(() => {
  return (route.meta.title as string) || 'Nklave'
})

const statusColor = computed(() => {
  if (healthStore.isHealthy) return 'bg-green-500'
  if (healthStore.isDegraded) return 'bg-yellow-500'
  if (healthStore.isUnhealthy) return 'bg-red-500'
  return 'bg-gray-500'
})

const statusText = computed(() => {
  return healthStore.health?.status ?? 'Unknown'
})

const statusPulse = computed(() => {
  if (healthStore.isHealthy) return 'status-pulse-success'
  if (healthStore.isDegraded) return 'status-pulse-warning'
  if (healthStore.isUnhealthy) return 'status-pulse-danger'
  return ''
})

onMounted(() => {
  healthStore.startPolling()
})

onUnmounted(() => {
  healthStore.stopPolling()
})
</script>

<template>
  <header class="h-16 bg-gray-800 border-b border-gray-700 flex items-center justify-between px-6">
    <!-- Page title -->
    <h1 class="text-xl font-semibold text-white">{{ pageTitle }}</h1>

    <!-- Status indicator -->
    <div class="flex items-center space-x-4">
      <!-- Uptime -->
      <div class="text-sm text-gray-400">
        <span class="mr-1">Uptime:</span>
        <span class="text-gray-200">{{ healthStore.uptimeFormatted }}</span>
      </div>

      <!-- Divider -->
      <div class="h-6 w-px bg-gray-700"></div>

      <!-- Status badge -->
      <div class="flex items-center space-x-2">
        <div
          :class="[
            'w-2.5 h-2.5 rounded-full',
            statusColor,
            statusPulse
          ]"
        ></div>
        <span class="text-sm text-gray-300">{{ statusText }}</span>
      </div>
    </div>
  </header>
</template>
