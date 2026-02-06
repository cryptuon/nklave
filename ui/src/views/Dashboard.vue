<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useHealthStore } from '@/stores/health'
import { useValidatorsStore } from '@/stores/validators'
import { api } from '@/api/client'

const healthStore = useHealthStore()
const validatorsStore = useValidatorsStore()

const reloadLoading = ref(false)
const checkpointLoading = ref(false)
const actionMessage = ref<{ type: 'success' | 'error'; text: string } | null>(null)

onMounted(() => {
  healthStore.startPolling(5000)
  validatorsStore.fetchValidators()
})

onUnmounted(() => {
  healthStore.stopPolling()
})

async function handleReload() {
  reloadLoading.value = true
  actionMessage.value = null
  try {
    const result = await validatorsStore.reloadKeys()
    actionMessage.value = {
      type: 'success',
      text: `Reloaded ${result.loaded} keys (${result.new} new). Total: ${result.total}`
    }
  } catch (e) {
    actionMessage.value = {
      type: 'error',
      text: e instanceof Error ? e.message : 'Failed to reload keys'
    }
  } finally {
    reloadLoading.value = false
  }
}

async function handleCheckpoint() {
  checkpointLoading.value = true
  actionMessage.value = null
  try {
    const result = await api.createCheckpoint()
    actionMessage.value = {
      type: result.success ? 'success' : 'error',
      text: result.message
    }
  } catch (e) {
    actionMessage.value = {
      type: 'error',
      text: e instanceof Error ? e.message : 'Failed to create checkpoint'
    }
  } finally {
    checkpointLoading.value = false
  }
}

function getCheckResultClass(result: unknown): string {
  if (result === 'Pass') return 'text-green-400'
  if (typeof result === 'object' && result !== null) {
    if ('Warn' in result) return 'text-yellow-400'
    if ('Fail' in result) return 'text-red-400'
  }
  return 'text-gray-400'
}

function getCheckResultText(result: unknown): string {
  if (result === 'Pass') return 'Pass'
  if (typeof result === 'object' && result !== null) {
    if ('Warn' in result) return `Warning: ${(result as any).Warn.message}`
    if ('Fail' in result) return `Failed: ${(result as any).Fail.message}`
  }
  return 'Unknown'
}
</script>

<template>
  <div class="space-y-6">
    <!-- Action message -->
    <div
      v-if="actionMessage"
      :class="[
        'p-4 rounded-lg',
        actionMessage.type === 'success' ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'
      ]"
    >
      {{ actionMessage.text }}
    </div>

    <!-- Stats grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <!-- Health Status -->
      <div class="card">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-400">Status</p>
              <p :class="[
                'text-2xl font-bold',
                healthStore.isHealthy ? 'text-green-400' :
                healthStore.isDegraded ? 'text-yellow-400' :
                healthStore.isUnhealthy ? 'text-red-400' : 'text-gray-400'
              ]">
                {{ healthStore.health?.status ?? 'Unknown' }}
              </p>
            </div>
            <div :class="[
              'w-12 h-12 rounded-full flex items-center justify-center',
              healthStore.isHealthy ? 'bg-green-900/50' :
              healthStore.isDegraded ? 'bg-yellow-900/50' :
              healthStore.isUnhealthy ? 'bg-red-900/50' : 'bg-gray-700'
            ]">
              <svg class="w-6 h-6" :class="[
                healthStore.isHealthy ? 'text-green-400' :
                healthStore.isDegraded ? 'text-yellow-400' :
                healthStore.isUnhealthy ? 'text-red-400' : 'text-gray-400'
              ]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Validators Count -->
      <div class="card">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-400">Validators</p>
              <p class="text-2xl font-bold text-white">
                {{ healthStore.health?.validators ?? 0 }}
              </p>
            </div>
            <div class="w-12 h-12 rounded-full bg-nklave-900/50 flex items-center justify-center">
              <svg class="w-6 h-6 text-nklave-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Total Decisions -->
      <div class="card">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-400">Total Decisions</p>
              <p class="text-2xl font-bold text-white">
                {{ healthStore.metrics?.total_decisions ?? healthStore.health?.last_sequence ?? 0 }}
              </p>
            </div>
            <div class="w-12 h-12 rounded-full bg-purple-900/50 flex items-center justify-center">
              <svg class="w-6 h-6 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Uptime -->
      <div class="card">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-400">Uptime</p>
              <p class="text-2xl font-bold text-white">
                {{ healthStore.uptimeFormatted }}
              </p>
            </div>
            <div class="w-12 h-12 rounded-full bg-blue-900/50 flex items-center justify-center">
              <svg class="w-6 h-6 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Health Checks & Actions -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Health Checks -->
      <div class="card">
        <div class="card-header">Health Checks</div>
        <div class="card-body">
          <div v-if="healthStore.health?.checks" class="space-y-3">
            <div class="flex items-center justify-between py-2 border-b border-gray-700">
              <span class="text-gray-300">State Integrity</span>
              <span :class="getCheckResultClass(healthStore.health.checks.state_integrity)">
                {{ getCheckResultText(healthStore.health.checks.state_integrity) }}
              </span>
            </div>
            <div class="flex items-center justify-between py-2 border-b border-gray-700">
              <span class="text-gray-300">Keys Loaded</span>
              <span :class="getCheckResultClass(healthStore.health.checks.keys_loaded)">
                {{ getCheckResultText(healthStore.health.checks.keys_loaded) }}
              </span>
            </div>
            <div class="flex items-center justify-between py-2">
              <span class="text-gray-300">Decision Log</span>
              <span :class="getCheckResultClass(healthStore.health.checks.decision_log)">
                {{ getCheckResultText(healthStore.health.checks.decision_log) }}
              </span>
            </div>
          </div>
          <div v-else class="text-gray-500 text-center py-4">
            Loading health checks...
          </div>
        </div>
      </div>

      <!-- Quick Actions -->
      <div class="card">
        <div class="card-header">Quick Actions</div>
        <div class="card-body space-y-4">
          <div>
            <p class="text-sm text-gray-400 mb-2">Reload validator keys from disk</p>
            <button
              @click="handleReload"
              :disabled="reloadLoading"
              class="btn btn-primary w-full"
            >
              <span v-if="reloadLoading">Reloading...</span>
              <span v-else>Reload Keys</span>
            </button>
          </div>
          <div>
            <p class="text-sm text-gray-400 mb-2">Create manual checkpoint</p>
            <button
              @click="handleCheckpoint"
              :disabled="checkpointLoading"
              class="btn btn-secondary w-full"
            >
              <span v-if="checkpointLoading">Creating...</span>
              <span v-else>Create Checkpoint</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- System Info -->
    <div class="card">
      <div class="card-header">System Information</div>
      <div class="card-body">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <p class="text-gray-400">Last Sequence</p>
            <p class="text-white font-mono">{{ healthStore.health?.last_sequence ?? 'N/A' }}</p>
          </div>
          <div>
            <p class="text-gray-400">Genesis Root Set</p>
            <p class="text-white">{{ healthStore.metrics?.genesis_root_set ? 'Yes' : 'No' }}</p>
          </div>
          <div>
            <p class="text-gray-400">Since Checkpoint</p>
            <p class="text-white font-mono">{{ healthStore.metrics?.decisions_since_checkpoint ?? 'N/A' }}</p>
          </div>
          <div>
            <p class="text-gray-400">UI Embedded</p>
            <p class="text-white">{{ healthStore.metrics?.ui_available ? 'Yes' : 'No' }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
