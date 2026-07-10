import { useEffect, useState } from 'react'
import { getProviders, configureProvider, testProvider, disconnectProvider } from '@/api/client'
import type { Provider } from '@/types/api'
import { escapeHtml } from '@/lib/utils'

function SettingsPage() {
  const [providers, setProviders] = useState<Provider[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedProvider, setSelectedProvider] = useState<Provider | null>(null)
  const [apiKey, setApiKey] = useState('')
  const [feedback, setFeedback] = useState<{ message: string; type: 'success' | 'error' } | null>(null)

  useEffect(() => {
    getProviders()
      .then(setProviders)
      .finally(() => setLoading(false))
  }, [])

  const openModal = (p: Provider) => {
    setSelectedProvider(p)
    setApiKey('')
    setFeedback(null)
  }

  const closeModal = () => setSelectedProvider(null)

  const handleSave = async () => {
    if (!selectedProvider || !apiKey) return
    try {
      await configureProvider(selectedProvider.id, apiKey)
      setFeedback({ message: 'Saved successfully!', type: 'success' })
      getProviders().then(setProviders)
    } catch (e) {
      setFeedback({ message: (e as Error).message, type: 'error' })
    }
  }

  const handleTest = async () => {
    if (!selectedProvider) return
    try {
      const result = await testProvider(selectedProvider.id)
      setFeedback({ message: result.message, type: 'success' })
    } catch (e) {
      setFeedback({ message: (e as Error).message, type: 'error' })
    }
  }

  const handleDisconnect = async () => {
    if (!selectedProvider) return
    if (!confirm('Are you sure you want to disconnect this provider?')) return
    try {
      await disconnectProvider(selectedProvider.id)
      setFeedback({ message: 'Disconnected!', type: 'success' })
      getProviders().then(setProviders)
    } catch (e) {
      setFeedback({ message: (e as Error).message, type: 'error' })
    }
  }

  return (
    <div className="p-6">
      <header className="mb-6">
        <h2 className="text-2xl font-bold">Provider Manager</h2>
        <p className="text-muted-foreground">Configure plugins and AI models credentials</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {loading ? (
          <p className="text-muted-foreground">Loading providers...</p>
        ) : providers.length === 0 ? (
          <p className="text-muted-foreground">No providers configured</p>
        ) : (
          providers.map(p => (
            <div key={p.id} className="bg-card p-4 rounded-lg border border-border">
              <div className="flex justify-between items-start mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-lg">🔌</span>
                  <span className="font-medium">{escapeHtml(p.name)}</span>
                </div>
                <span className={`text-xs px-2 py-1 rounded ${
                  p.status === 'connected' ? 'bg-green-600/20' : 'bg-red-600/20'
                }`}>
                  {p.status.toUpperCase()}
                </span>
              </div>
              <div className="text-sm text-muted-foreground mb-3">
                {escapeHtml(p.description)}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => openModal(p)}
                  className="flex-1 px-3 py-1 text-sm bg-primary/20 rounded hover:bg-primary/30"
                >
                  Configure
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Modal */}
      {selectedProvider && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card p-6 rounded-lg border border-border w-full max-w-md">
            <h3 className="text-lg font-bold mb-1">{escapeHtml(selectedProvider.name)}</h3>
            <p className="text-sm text-muted-foreground mb-4">{escapeHtml(selectedProvider.description)}</p>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">API Key</label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Enter API Key"
                  className="w-full px-3 py-2 bg-background border border-border rounded-md"
                />
              </div>
              
              {feedback && (
                <div className={`text-sm ${feedback.type === 'success' ? 'text-green-400' : 'text-red-400'}`}>
                  {feedback.message}
                </div>
              )}
              
              <div className="flex gap-2">
                <button
                  onClick={handleSave}
                  className="flex-1 px-3 py-2 bg-primary text-primary-foreground rounded-md"
                >
                  Save
                </button>
                <button
                  onClick={handleTest}
                  className="flex-1 px-3 py-2 bg-secondary text-secondary-foreground rounded-md"
                >
                  Test
                </button>
              </div>
              
              <button
                onClick={handleDisconnect}
                className="w-full px-3 py-2 bg-destructive text-destructive-foreground rounded-md"
              >
                Disconnect
              </button>
              
              <button
                onClick={closeModal}
                className="w-full px-3 py-2 bg-secondary text-secondary-foreground rounded-md"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default SettingsPage