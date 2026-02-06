import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { api, type HealthResponse, type MetricsSummary } from '@/api/client'

export const useHealthStore = defineStore('health', () => {
  const health = ref<HealthResponse | null>(null)
  const metrics = ref<MetricsSummary | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const lastUpdated = ref<Date | null>(null)

  let pollInterval: ReturnType<typeof setInterval> | null = null

  const isHealthy = computed(() => health.value?.status === 'Healthy')
  const isDegraded = computed(() => health.value?.status === 'Degraded')
  const isUnhealthy = computed(() => health.value?.status === 'Unhealthy')

  const uptimeFormatted = computed(() => {
    const seconds = metrics.value?.uptime_seconds ?? health.value?.uptime_seconds
    if (!seconds) return 'N/A'

    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    const secs = seconds % 60

    if (days > 0) return `${days}d ${hours}h ${mins}m`
    if (hours > 0) return `${hours}h ${mins}m ${secs}s`
    if (mins > 0) return `${mins}m ${secs}s`
    return `${secs}s`
  })

  async function fetchHealth() {
    try {
      loading.value = true
      const [healthRes, metricsRes] = await Promise.all([
        api.getHealth(),
        api.getMetricsSummary(),
      ])
      health.value = healthRes
      metrics.value = metricsRes
      error.value = null
      lastUpdated.value = new Date()
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Unknown error'
    } finally {
      loading.value = false
    }
  }

  function startPolling(intervalMs = 5000) {
    stopPolling()
    fetchHealth()
    pollInterval = setInterval(fetchHealth, intervalMs)
  }

  function stopPolling() {
    if (pollInterval) {
      clearInterval(pollInterval)
      pollInterval = null
    }
  }

  return {
    health,
    metrics,
    loading,
    error,
    lastUpdated,
    isHealthy,
    isDegraded,
    isUnhealthy,
    uptimeFormatted,
    fetchHealth,
    startPolling,
    stopPolling,
  }
})
