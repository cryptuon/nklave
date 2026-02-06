<script setup lang="ts">
import { onMounted, onUnmounted, ref, computed } from 'vue'
import { useValidatorsStore } from '@/stores/validators'

const validatorsStore = useValidatorsStore()
const searchQuery = ref('')
const copiedPubkey = ref<string | null>(null)

const filteredValidators = computed(() => {
  if (!searchQuery.value) return validatorsStore.publicKeys
  const query = searchQuery.value.toLowerCase()
  return validatorsStore.publicKeys.filter(pk => pk.toLowerCase().includes(query))
})

onMounted(() => {
  validatorsStore.startPolling(30000)
})

onUnmounted(() => {
  validatorsStore.stopPolling()
})

async function copyToClipboard(pubkey: string) {
  try {
    await navigator.clipboard.writeText(pubkey)
    copiedPubkey.value = pubkey
    setTimeout(() => {
      copiedPubkey.value = null
    }, 2000)
  } catch (e) {
    console.error('Failed to copy:', e)
  }
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header with count and search -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold text-white">Validator Keys</h2>
        <p class="text-sm text-gray-400">
          {{ validatorsStore.count }} validator{{ validatorsStore.count === 1 ? '' : 's' }} loaded
        </p>
      </div>
      <div class="flex items-center gap-4">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search by public key..."
          class="input w-64"
        />
        <button
          @click="validatorsStore.reloadKeys"
          :disabled="validatorsStore.loading"
          class="btn btn-primary"
        >
          <svg class="w-4 h-4 mr-2" :class="{ 'animate-spin': validatorsStore.loading }" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Reload
        </button>
      </div>
    </div>

    <!-- Error message -->
    <div v-if="validatorsStore.error" class="bg-red-900/50 text-red-300 p-4 rounded-lg">
      {{ validatorsStore.error }}
    </div>

    <!-- Validators list -->
    <div class="card">
      <div v-if="validatorsStore.loading && validatorsStore.publicKeys.length === 0" class="p-8 text-center text-gray-400">
        Loading validators...
      </div>
      <div v-else-if="filteredValidators.length === 0" class="p-8 text-center text-gray-400">
        <svg class="w-12 h-12 mx-auto mb-4 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
        <p v-if="searchQuery">No validators match your search</p>
        <p v-else>No validators loaded</p>
        <p class="text-sm mt-2">Add keystores to the keys directory and click Reload</p>
      </div>
      <div v-else class="divide-y divide-gray-700">
        <div
          v-for="(pubkey, index) in filteredValidators"
          :key="pubkey"
          class="p-4 hover:bg-gray-750 transition-colors"
        >
          <div class="flex items-center justify-between">
            <div class="flex items-center space-x-4">
              <div class="w-8 h-8 rounded-full bg-nklave-900/50 flex items-center justify-center text-nklave-400 text-sm font-medium">
                {{ index + 1 }}
              </div>
              <div>
                <p class="pubkey">{{ validatorsStore.truncatePubkey(pubkey, 12) }}</p>
                <p class="text-xs text-gray-500 mt-1">Full: {{ pubkey.slice(0, 20) }}...</p>
              </div>
            </div>
            <button
              @click="copyToClipboard(pubkey)"
              class="btn btn-secondary text-sm py-1.5"
            >
              <svg v-if="copiedPubkey === pubkey" class="w-4 h-4 mr-1 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
              <svg v-else class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
              {{ copiedPubkey === pubkey ? 'Copied!' : 'Copy' }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Last updated -->
    <div v-if="validatorsStore.lastUpdated" class="text-sm text-gray-500 text-center">
      Last updated: {{ validatorsStore.lastUpdated.toLocaleTimeString() }}
    </div>
  </div>
</template>
