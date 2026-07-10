// API Types for Aegis OSINT AI

export interface Target {
  id: number
  query: string
  target_type: string
  status: string
  created_at: string
}

export interface Finding {
  id: number
  target_id: number
  source: string
  category: string
  severity: string
  confidence: number
  data: Record<string, unknown>
  created_at: string
}

export interface Entity {
  id?: number
  type: string
  value: string
  display_name?: string
  confidence: number
  metadata_json?: Record<string, unknown>
}

export interface Relationship {
  id?: number
  source_entity_id: number
  target_entity_id: number
  relationship_type: string
  confidence: number
  source_plugin: string
}

export interface TimelineEvent {
  id?: number
  target_id: number
  timestamp: string
  event_type: string
  severity: string
  description: string
}

export interface PluginMetadata {
  name: string
  description: string
  version: string
  supported_entity_types: string[]
  required_api_keys: string[]
  supported_authentication: string[]
  tags: string[]
  status: string
}

export interface Provider {
  id: string
  name: string
  description: string
  supported_authentication: string[]
  status: 'connected' | 'disconnected'
}

export interface ApiResponse<T> {
  success: boolean
  data: T
  errors: string[]
  metadata: Record<string, unknown>
}

export interface ChatResponse {
  response: string
  provider: string
  model: string
}

export interface ChatRequest {
  message: string
  provider?: string
  model?: string
}

export interface SearchRequest {
  query: string
  target_type?: string
}