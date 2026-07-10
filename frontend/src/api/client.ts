import { ApiResponse, Target, Finding, Entity, Relationship, TimelineEvent, PluginMetadata, Provider, ChatRequest, SearchRequest } from '@/types/api'

const API_BASE = '/api'

// Helper for API fetching
async function apiFetch<T>(url: string, options: RequestInit = {}): Promise<T> {
  const resp = await fetch(url, options)
  if (!resp.ok) {
    let errorMsg = `HTTP Error ${resp.status}`
    try {
      const errData: ApiResponse<unknown> = await resp.json()
      if (errData.errors && errData.errors.length > 0) {
        errorMsg = errData.errors.join(', ')
      }
    } catch { /* ignore */ }
    throw new Error(errorMsg)
  }
  const data: ApiResponse<T> = await resp.json()
  if (data.success === false) {
    throw new Error(data.errors.join(', '))
  }
  return data.data
}

// Targets
export const getTargets = () => apiFetch<Target[]>(`${API_BASE}/targets`)

// Findings
export const getFindings = (targetId?: number) => 
  apiFetch<Finding[]>(`${API_BASE}/findings${targetId ? `?target_id=${targetId}` : ''}`)

// Entities
export const getEntities = (targetId: number) => 
  apiFetch<Entity[]>(`${API_BASE}/targets/${targetId}/entities`)

// Relationships
export const getRelationships = (targetId: number) => 
  apiFetch<Relationship[]>(`${API_BASE}/targets/${targetId}/relationships`)

// Timeline
export const getTimeline = (targetId: number) => 
  apiFetch<TimelineEvent[]>(`${API_BASE}/targets/${targetId}/timeline`)

// Search
export const search = (payload: SearchRequest) => 
  apiFetch<{ target_id: number; findings_count: number; findings: Finding[] }>(
    `${API_BASE}/search`, 
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }
  )

// Chat
export const chat = (payload: ChatRequest) => 
  apiFetch<{ response: string; provider: string; model: string }>(
    `${API_BASE}/chat`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }
  )

// Providers
export const getProviders = () => apiFetch<Provider[]>(`${API_BASE}/providers`)

export const configureProvider = (providerId: string, apiKey: string) =>
  apiFetch<{ message: string }>(`${API_BASE}/providers/${providerId}/configure`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ api_key: apiKey })
  })

export const testProvider = (providerId: string) =>
  apiFetch<{ message: string }>(`${API_BASE}/providers/${providerId}/test`, {
    method: 'POST'
  })

export const disconnectProvider = (providerId: string) =>
  apiFetch<{ message: string }>(`${API_BASE}/providers/${providerId}`, {
    method: 'DELETE'
  })

// Plugins
export const getPlugins = () => apiFetch<PluginMetadata[]>(`${API_BASE}/plugins`)