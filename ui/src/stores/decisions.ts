import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, type Decision, type DecisionsResponse } from '@/api/client'

export const useDecisionsStore = defineStore('decisions', () => {
  const decisions = ref<Decision[]>([])
  const total = ref(0)
  const page = ref(1)
  const pageSize = ref(50)
  const hasMore = ref(false)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const lastUpdated = ref<Date | null>(null)
  const filterValidator = ref<string | null>(null)

  let pollInterval: ReturnType<typeof setInterval> | null = null

  async function fetchDecisions(pageNum = 1) {
    try {
      loading.value = true
      const response: DecisionsResponse = await api.getDecisions(
        pageNum,
        pageSize.value,
        filterValidator.value ?? undefined
      )
      decisions.value = response.decisions
      total.value = response.total
      page.value = response.page
      hasMore.value = response.has_more
      error.value = null
      lastUpdated.value = new Date()
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Unknown error'
    } finally {
      loading.value = false
    }
  }

  function nextPage() {
    if (hasMore.value) {
      fetchDecisions(page.value + 1)
    }
  }

  function prevPage() {
    if (page.value > 1) {
      fetchDecisions(page.value - 1)
    }
  }

  function setFilter(validator: string | null) {
    filterValidator.value = validator
    fetchDecisions(1)
  }

  function startPolling(intervalMs = 10000) {
    stopPolling()
    fetchDecisions()
    pollInterval = setInterval(() => fetchDecisions(page.value), intervalMs)
  }

  function stopPolling() {
    if (pollInterval) {
      clearInterval(pollInterval)
      pollInterval = null
    }
  }

  // Format timestamp for display
  function formatTimestamp(timestamp: number): string {
    return new Date(timestamp * 1000).toLocaleString()
  }

  return {
    decisions,
    total,
    page,
    pageSize,
    hasMore,
    loading,
    error,
    lastUpdated,
    filterValidator,
    fetchDecisions,
    nextPage,
    prevPage,
    setFilter,
    startPolling,
    stopPolling,
    formatTimestamp,
  }
})
