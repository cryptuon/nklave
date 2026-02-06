<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useValidatorsStore } from '@/stores/validators'
import { api } from '@/api/client'

const validatorsStore = useValidatorsStore()

const selectedValidator = ref('')
const requestType = ref('RANDAO_REVEAL')
const signingRoot = ref('')
const epoch = ref('1')
const slot = ref('1')
const sourceEpoch = ref('0')
const targetEpoch = ref('1')

const loading = ref(false)
const result = ref<{ success: boolean; data: unknown } | null>(null)

const requestTypes = [
  'RANDAO_REVEAL',
  'ATTESTATION',
  'BLOCK_V2',
  'AGGREGATION_SLOT',
  'AGGREGATE_AND_PROOF',
  'VOLUNTARY_EXIT',
  'SYNC_COMMITTEE_MESSAGE',
  'SYNC_COMMITTEE_SELECTION_PROOF',
  'SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF',
  'VALIDATOR_REGISTRATION',
]

// Generate a random signing root
function generateSigningRoot() {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  signingRoot.value = '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// Build the request based on type
const requestBody = computed(() => {
  const base = {
    fork_info: {
      fork: {
        previous_version: '0x00000000',
        current_version: '0x00000000',
        epoch: '0',
      },
      genesis_validators_root: '0x0000000000000000000000000000000000000000000000000000000000000000',
    },
    signingRoot: signingRoot.value || '0x0000000000000000000000000000000000000000000000000000000000000001',
  }

  switch (requestType.value) {
    case 'RANDAO_REVEAL':
      return {
        type: 'RANDAO_REVEAL',
        ...base,
        randao_reveal: { epoch: epoch.value },
      }
    case 'ATTESTATION':
      return {
        type: 'ATTESTATION',
        ...base,
        attestation: {
          slot: slot.value,
          index: '0',
          beacon_block_root: '0x0000000000000000000000000000000000000000000000000000000000000000',
          source: {
            epoch: sourceEpoch.value,
            root: '0x0000000000000000000000000000000000000000000000000000000000000000',
          },
          target: {
            epoch: targetEpoch.value,
            root: '0x0000000000000000000000000000000000000000000000000000000000000000',
          },
        },
      }
    case 'BLOCK_V2':
      return {
        type: 'BLOCK_V2',
        ...base,
        beacon_block: {
          version: 'PHASE0',
          block_header: {
            slot: slot.value,
            proposer_index: '0',
            parent_root: '0x0000000000000000000000000000000000000000000000000000000000000000',
            state_root: '0x0000000000000000000000000000000000000000000000000000000000000000',
            body_root: '0x0000000000000000000000000000000000000000000000000000000000000000',
          },
        },
      }
    case 'AGGREGATION_SLOT':
      return {
        type: 'AGGREGATION_SLOT',
        ...base,
        aggregation_slot: { slot: slot.value },
      }
    case 'VOLUNTARY_EXIT':
      return {
        type: 'VOLUNTARY_EXIT',
        ...base,
        voluntary_exit: {
          epoch: epoch.value,
          validator_index: '0',
        },
      }
    default:
      return {
        type: requestType.value,
        ...base,
      }
  }
})

async function submitRequest() {
  if (!selectedValidator.value) {
    result.value = { success: false, data: { error: 'Please select a validator' } }
    return
  }

  loading.value = true
  result.value = null

  try {
    const response = await api.sign(selectedValidator.value, requestBody.value)
    result.value = { success: true, data: response }
  } catch (e) {
    result.value = { success: false, data: { error: e instanceof Error ? e.message : 'Unknown error' } }
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  validatorsStore.fetchValidators()
  generateSigningRoot()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div>
      <h2 class="text-lg font-semibold text-white">Signing Test</h2>
      <p class="text-sm text-gray-400">Test signing requests against the API</p>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Request Builder -->
      <div class="card">
        <div class="card-header">Request Builder</div>
        <div class="card-body space-y-4">
          <!-- Validator Selection -->
          <div>
            <label class="block text-sm font-medium text-gray-300 mb-2">Validator</label>
            <select v-model="selectedValidator" class="input">
              <option value="">Select a validator...</option>
              <option v-for="pk in validatorsStore.publicKeys" :key="pk" :value="pk">
                {{ validatorsStore.truncatePubkey(pk, 10) }}
              </option>
            </select>
          </div>

          <!-- Request Type -->
          <div>
            <label class="block text-sm font-medium text-gray-300 mb-2">Request Type</label>
            <select v-model="requestType" class="input">
              <option v-for="type in requestTypes" :key="type" :value="type">
                {{ type }}
              </option>
            </select>
          </div>

          <!-- Signing Root -->
          <div>
            <label class="block text-sm font-medium text-gray-300 mb-2">Signing Root</label>
            <div class="flex gap-2">
              <input v-model="signingRoot" class="input font-mono text-xs" placeholder="0x..." />
              <button @click="generateSigningRoot" class="btn btn-secondary text-sm">
                Random
              </button>
            </div>
          </div>

          <!-- Type-specific fields -->
          <div v-if="requestType === 'RANDAO_REVEAL' || requestType === 'VOLUNTARY_EXIT'">
            <label class="block text-sm font-medium text-gray-300 mb-2">Epoch</label>
            <input v-model="epoch" type="number" min="0" class="input" />
          </div>

          <div v-if="requestType === 'BLOCK_V2' || requestType === 'AGGREGATION_SLOT'">
            <label class="block text-sm font-medium text-gray-300 mb-2">Slot</label>
            <input v-model="slot" type="number" min="0" class="input" />
          </div>

          <div v-if="requestType === 'ATTESTATION'" class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-300 mb-2">Slot</label>
              <input v-model="slot" type="number" min="0" class="input" />
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">Source Epoch</label>
                <input v-model="sourceEpoch" type="number" min="0" class="input" />
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">Target Epoch</label>
                <input v-model="targetEpoch" type="number" min="0" class="input" />
              </div>
            </div>
          </div>

          <!-- Submit Button -->
          <button
            @click="submitRequest"
            :disabled="loading || !selectedValidator"
            class="btn btn-primary w-full"
          >
            <span v-if="loading">Signing...</span>
            <span v-else>Sign Request</span>
          </button>
        </div>
      </div>

      <!-- Request/Response Preview -->
      <div class="space-y-6">
        <!-- Request Preview -->
        <div class="card">
          <div class="card-header">Request Preview</div>
          <div class="card-body">
            <pre class="text-xs text-gray-300 bg-gray-900 p-4 rounded-lg overflow-x-auto font-mono">{{ JSON.stringify(requestBody, null, 2) }}</pre>
          </div>
        </div>

        <!-- Response -->
        <div class="card">
          <div class="card-header">Response</div>
          <div class="card-body">
            <div v-if="!result" class="text-gray-500 text-center py-4">
              Submit a request to see the response
            </div>
            <div v-else>
              <div :class="[
                'p-2 rounded-lg mb-4',
                result.success ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'
              ]">
                {{ result.success ? 'Success' : 'Error' }}
              </div>
              <pre class="text-xs text-gray-300 bg-gray-900 p-4 rounded-lg overflow-x-auto font-mono">{{ JSON.stringify(result.data, null, 2) }}</pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
