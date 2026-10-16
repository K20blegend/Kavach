// simple api helper for kavach backend
const API_BASE = 'http://127.0.0.1:8000/api/v1'

export async function auditUrl(url) {
  const res = await fetch(`${API_BASE}/audits/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url, save_history: false })
  })

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}))
    throw new Error(errData?.error?.message || `Scan failed with status ${res.status}`)
  }

  return await res.json()
}

export async function auditMessage(payload) {
  const res = await fetch(`${API_BASE}/audits/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text: payload.text,
      channel: payload.channel || 'email',
      raw_headers: payload.raw_headers || null,
      inspect_links: payload.inspect_links ?? false,
      save_history: false
    })
  })

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}))
    throw new Error(errData?.error?.message || `Message analysis failed with status ${res.status}`)
  }

  return await res.json()
}

export async function getScenarios(difficulty, channel) {
  const params = new URLSearchParams()
  if (difficulty) params.append('difficulty', difficulty)
  if (channel) params.append('channel', channel)
  const qs = params.toString() ? `?${params.toString()}` : ''

  const res = await fetch(`${API_BASE}/training/scenarios${qs}`)
  if (!res.ok) {
    throw new Error(`Failed to load scenarios (${res.status})`)
  }
  return await res.json()
}

export async function getScenario(scenarioId) {
  const res = await fetch(`${API_BASE}/training/scenarios/${scenarioId}`)
  if (!res.ok) {
    throw new Error(`Failed to load scenario details (${res.status})`)
  }
  return await res.json()
}

export async function evaluateScenario(scenarioId, selectedIndicatorIds) {
  const res = await fetch(`${API_BASE}/training/scenarios/${scenarioId}/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ selected_indicator_ids: selectedIndicatorIds })
  })

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}))
    throw new Error(errData?.detail || `Evaluation failed (${res.status})`)
  }

  return await res.json()
}
