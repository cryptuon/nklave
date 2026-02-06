import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { api, type ReloadResult } from '@/api/client'

export const useValidatorsStore = defineStore('validators', () => {
  const publicKeys = ref<string[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)
  const lastUpdated = ref<Date | null>(null)
  const reloadResult = ref<ReloadResult | null>(null)

  let pollInterval: ReturnType<typeof setInterval> | null = null

  const count = computed(() => publicKeys.value.length)

  // Truncate pubkey for display: 0x1234...5678
  function truncatePubkey(pubkey: string, chars = 8): string {
    if (pubkey.length <= chars * 2 + 3) return pubkey
    return `${pubkey.slice(0, chars + 2)}...${pubkey.slice(-chars)}`
  }

  async function fetchValidators() {
    try {
      loading.value = true
      publicKeys.value = await api.getPublicKeys()
      error.value = null
      lastUpdated.value = new Date()
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Unknown error'
    } finally {
      loading.value = false
    }
  }

  async function reloadKeys() {
    try {
      loading.value = true
      reloadResult.value = await api.reload()
      // Refresh the list after reload
      publicKeys.value = await api.getPublicKeys()
      error.value = null
      lastUpdated.value = new Date()
      return reloadResult.value
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Unknown error'
      throw e
    } finally {
      loading.value = false
    }
  }

  function startPolling(intervalMs = 30000) {
    stopPolling()
    fetchValidators()
    pollInterval = setInterval(fetchValidators, intervalMs)
  }

  function stopPolling() {
    if (pollInterval) {
      clearInterval(pollInterval)
      pollInterval = null
    }
  }

  return {
    publicKeys,
    loading,
    error,
    lastUpdated,
    reloadResult,
    count,
    truncatePubkey,
    fetchValidators,
    reloadKeys,
    startPolling,
    stopPolling,
  }
})
