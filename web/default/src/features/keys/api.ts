/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { api } from '@/lib/api'
import { ROLE } from '@/lib/roles'
import { useAuthStore } from '@/stores/auth-store'

import type {
  ApiKey,
  ApiResponse,
  GetApiKeysParams,
  GetApiKeysResponse,
  SearchApiKeysParams,
  ApiKeyFormData,
} from './types'

// ============================================================================
// API Key Management
// ============================================================================

function isAdminRequest(): boolean {
  return (useAuthStore.getState().auth.user?.role ?? 0) >= ROLE.ADMIN
}

// Get paginated API keys list
export async function getApiKeys(
  params: GetApiKeysParams = {}
): Promise<GetApiKeysResponse> {
  const { p = 1, size = 10 } = params
  const endpoint = isAdminRequest() ? '/api/token/admin' : '/api/token/'
  const res = await api.get(`${endpoint}?p=${p}&size=${size}`)
  return res.data
}

// Search API keys by keyword or token (with pagination)
export async function searchApiKeys(
  params: SearchApiKeysParams
): Promise<GetApiKeysResponse> {
  const { keyword = '', token = '', p, size } = params
  const queryParams = new URLSearchParams()
  if (keyword) queryParams.set('keyword', keyword)
  if (token) queryParams.set('token', token)
  if (p != null) queryParams.set('p', String(p))
  if (size != null) queryParams.set('size', String(size))
  const endpoint = isAdminRequest()
    ? '/api/token/admin/search'
    : '/api/token/search'
  const res = await api.get(`${endpoint}?${queryParams.toString()}`)
  return res.data
}

// Get single API key by ID
export async function getApiKey(id: number): Promise<ApiResponse<ApiKey>> {
  const endpoint = isAdminRequest()
    ? `/api/token/admin/${id}`
    : `/api/token/${id}`
  const res = await api.get(endpoint)
  return res.data
}

// Create a new API key
export async function createApiKey(
  data: ApiKeyFormData
): Promise<ApiResponse<ApiKey>> {
  const res = await api.post('/api/token/', data)
  return res.data
}

// Update an existing API key
export async function updateApiKey(
  data: ApiKeyFormData & { id: number }
): Promise<ApiResponse<ApiKey>> {
  const endpoint = isAdminRequest() ? '/api/token/admin/' : '/api/token/'
  const res = await api.put(endpoint, data)
  return res.data
}

// Delete a single API key
export async function deleteApiKey(id: number): Promise<ApiResponse> {
  const endpoint = isAdminRequest()
    ? `/api/token/admin/${id}`
    : `/api/token/${id}/`
  const res = await api.delete(endpoint)
  return res.data
}

// Batch delete multiple API keys
export async function batchDeleteApiKeys(
  ids: number[]
): Promise<ApiResponse<number>> {
  const endpoint = isAdminRequest()
    ? '/api/token/admin/batch'
    : '/api/token/batch'
  const res = await api.post(endpoint, { ids })
  return res.data
}

// Update API key status (enable/disable)
export async function updateApiKeyStatus(
  id: number,
  status: number
): Promise<ApiResponse<ApiKey>> {
  const endpoint = isAdminRequest()
    ? '/api/token/admin/?status_only=true'
    : '/api/token/?status_only=true'
  const res = await api.put(endpoint, { id, status })
  return res.data
}

// Fetch the real (unmasked) key for a token by ID
export async function fetchTokenKey(
  id: number
): Promise<{ success: boolean; message?: string; data?: { key: string } }> {
  const endpoint = isAdminRequest()
    ? `/api/token/admin/${id}/key`
    : `/api/token/${id}/key`
  const res = await api.post(endpoint)
  return res.data
}

// Batch fetch real (unmasked) keys for multiple tokens
export async function fetchTokenKeysBatch(ids: number[]): Promise<{
  success: boolean
  message?: string
  data?: { keys: Record<number, string> }
}> {
  const endpoint = isAdminRequest()
    ? '/api/token/admin/batch/keys'
    : '/api/token/batch/keys'
  const res = await api.post(endpoint, { ids })
  return res.data
}
