<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { useDecisionsStore } from '@/stores/decisions'
import { useValidatorsStore } from '@/stores/validators'

const decisionsStore = useDecisionsStore()
const validatorsStore = useValidatorsStore()

onMounted(() => {
  decisionsStore.startPolling(10000)
  validatorsStore.fetchValidators()
})

onUnmounted(() => {
  decisionsStore.stopPolling()
})

function truncatePubkey(pubkey: string): string {
  if (pubkey.length <= 20) return pubkey
  return `${pubkey.slice(0, 10)}...${pubkey.slice(-8)}`
}

function truncateHash(hash: string): string {
  if (hash.length <= 18) return hash
  return `${hash.slice(0, 10)}...${hash.slice(-6)}`
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold text-white">Signing History</h2>
        <p class="text-sm text-gray-400">
          {{ decisionsStore.total }} total decision{{ decisionsStore.total === 1 ? '' : 's' }}
        </p>
      </div>
      <div class="flex items-center gap-4">
        <select
          :value="decisionsStore.filterValidator ?? ''"
          @change="decisionsStore.setFilter(($event.target as HTMLSelectElement).value || null)"
          class="input w-64"
        >
          <option value="">All validators</option>
          <option v-for="pk in validatorsStore.publicKeys" :key="pk" :value="pk">
            {{ truncatePubkey(pk) }}
          </option>
        </select>
        <button
          @click="decisionsStore.fetchDecisions()"
          :disabled="decisionsStore.loading"
          class="btn btn-secondary"
        >
          <svg class="w-4 h-4" :class="{ 'animate-spin': decisionsStore.loading }" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>
    </div>

    <!-- Error message -->
    <div v-if="decisionsStore.error" class="bg-red-900/50 text-red-300 p-4 rounded-lg">
      {{ decisionsStore.error }}
    </div>

    <!-- Decisions table -->
    <div class="card overflow-hidden">
      <div v-if="decisionsStore.loading && decisionsStore.decisions.length === 0" class="p-8 text-center text-gray-400">
        Loading decisions...
      </div>
      <div v-else-if="decisionsStore.decisions.length === 0" class="p-8 text-center text-gray-400">
        <svg class="w-12 h-12 mx-auto mb-4 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p>No signing decisions recorded yet</p>
        <p class="text-sm mt-2">Decisions will appear here when validators sign messages</p>
      </div>
      <div v-else class="overflow-x-auto">
        <table class="table">
          <thead>
            <tr>
              <th>Seq</th>
              <th>Timestamp</th>
              <th>Validator</th>
              <th>Type</th>
              <th>Decision</th>
              <th>Signing Root</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="decision in decisionsStore.decisions" :key="decision.sequence">
              <td class="font-mono text-gray-300">{{ decision.sequence }}</td>
              <td class="text-gray-400">{{ decisionsStore.formatTimestamp(decision.timestamp) }}</td>
              <td class="pubkey">{{ truncatePubkey(decision.validator_pubkey) }}</td>
              <td>
                <span class="badge badge-info">{{ decision.request_type }}</span>
              </td>
              <td>
                <span :class="[
                  'badge',
                  decision.decision === 'Allow' ? 'badge-success' : 'badge-danger'
                ]">
                  {{ decision.decision }}
                </span>
              </td>
              <td class="font-mono text-xs text-gray-500">{{ truncateHash(decision.signing_root) }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div v-if="decisionsStore.total > 0" class="px-4 py-3 border-t border-gray-700 flex items-center justify-between">
        <div class="text-sm text-gray-400">
          Page {{ decisionsStore.page }} of {{ Math.ceil(decisionsStore.total / decisionsStore.pageSize) }}
        </div>
        <div class="flex gap-2">
          <button
            @click="decisionsStore.prevPage()"
            :disabled="decisionsStore.page <= 1"
            class="btn btn-secondary text-sm py-1.5"
          >
            Previous
          </button>
          <button
            @click="decisionsStore.nextPage()"
            :disabled="!decisionsStore.hasMore"
            class="btn btn-secondary text-sm py-1.5"
          >
            Next
          </button>
        </div>
      </div>
    </div>

    <!-- Last updated -->
    <div v-if="decisionsStore.lastUpdated" class="text-sm text-gray-500 text-center">
      Last updated: {{ decisionsStore.lastUpdated.toLocaleTimeString() }}
    </div>
  </div>
</template>
