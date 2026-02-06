// API client for Nklave backend

const API_BASE = ''  // Same origin when embedded

// Types
export interface HealthCheck {
  state_integrity: CheckResult
  keys_loaded: CheckResult
  decision_log: CheckResult
}

export type CheckResult =
  | 'Pass'
  | { Warn: { message: string } }
  | { Fail: { message: string } }

export interface HealthResponse {
  status: 'Healthy' | 'Degraded' | 'Unhealthy'
  uptime_seconds: number | null
  checks: HealthCheck
  validators: number
  last_sequence: number
}

export interface StatusResponse {
  status: string
  validators: number
  last_sequence: number
  genesis_root_set: boolean
}

export interface MetricsSummary {
  uptime_seconds: number
  total_decisions: number
  validators_count: number
  last_sequence: number
  genesis_root_set: boolean
  decisions_since_checkpoint: number
  ui_available: boolean
}

export interface Decision {
  sequence: number
  timestamp: number
  validator_pubkey: string
  request_type: string
  decision: string
  signing_root: string
}

export interface DecisionsResponse {
  decisions: Decision[]
  total: number
  page: number
  page_size: number
  has_more: boolean
}

export interface ReloadResult {
  loaded: number
  new: number
  total: number
}

export interface CheckpointResult {
  success: boolean
  message: string
  sequence: number | null
}

export interface SignatureResponse {
  signature: string
}

export interface ApiError {
  error: string
}

// Helper to handle API responses
async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: response.statusText }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }
  return response.json()
}

// API functions
export const api = {
  // Health endpoints
  async getHealth(): Promise<HealthResponse> {
    const res = await fetch(`${API_BASE}/health`)
    return handleResponse(res)
  },

  async getStatus(): Promise<StatusResponse> {
    const res = await fetch(`${API_BASE}/status`)
    return handleResponse(res)
  },

  async getMetricsSummary(): Promise<MetricsSummary> {
    const res = await fetch(`${API_BASE}/api/v1/metrics/summary`)
    return handleResponse(res)
  },

  // Validator endpoints
  async getPublicKeys(): Promise<string[]> {
    const res = await fetch(`${API_BASE}/api/v1/eth2/publicKeys`)
    return handleResponse(res)
  },

  // Decision log endpoints
  async getDecisions(page = 1, pageSize = 50, validator?: string): Promise<DecisionsResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      size: pageSize.toString(),
    })
    if (validator) {
      params.set('validator', validator)
    }
    const res = await fetch(`${API_BASE}/api/v1/decisions?${params}`)
    return handleResponse(res)
  },

  // Admin endpoints
  async getAdminState(): Promise<unknown> {
    const res = await fetch(`${API_BASE}/admin/state`)
    return handleResponse(res)
  },

  async reload(): Promise<ReloadResult> {
    const res = await fetch(`${API_BASE}/reload`, { method: 'POST' })
    return handleResponse(res)
  },

  async createCheckpoint(): Promise<CheckpointResult> {
    const res = await fetch(`${API_BASE}/admin/checkpoint`, { method: 'POST' })
    return handleResponse(res)
  },

  // Signing endpoint
  async sign(pubkey: string, request: unknown): Promise<SignatureResponse> {
    const res = await fetch(`${API_BASE}/api/v1/eth2/sign/${pubkey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    })
    return handleResponse(res)
  },
}

// Export a simple upcheck function
export async function checkConnection(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/upcheck`)
    return res.ok
  } catch {
    return false
  }
}
