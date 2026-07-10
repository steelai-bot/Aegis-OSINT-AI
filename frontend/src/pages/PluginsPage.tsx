import { useEffect, useState } from 'react'
import { getPlugins } from '@/api/client'
import type { PluginMetadata } from '@/types/api'
import { escapeHtml } from '@/lib/utils'

function PluginsPage() {
  const [plugins, setPlugins] = useState<PluginMetadata[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getPlugins()
      .then(setPlugins)
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="p-6">
      <header className="mb-6">
        <h2 className="text-2xl font-bold">Plugins</h2>
        <p className="text-muted-foreground">Available OSINT data sources</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {loading ? (
          <p className="text-muted-foreground">Loading plugins...</p>
        ) : plugins.length === 0 ? (
          <p className="text-muted-foreground">No plugins installed</p>
        ) : (
          plugins.map(p => (
            <div key={p.name} className={`bg-card p-4 rounded-lg border border-border ${
              p.status === 'disabled' ? 'opacity-50' : ''
            }`}>
              <div className="font-medium">{escapeHtml(p.name)}</div>
              <div className="text-sm text-muted-foreground mt-1">
                {escapeHtml(p.description)}
              </div>
              <div className="flex gap-1 mt-2 flex-wrap">
                {(p.tags || []).map(tag => (
                  <span key={tag} className="text-xs bg-primary/20 px-2 py-1 rounded">
                    {escapeHtml(tag)}
                  </span>
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

export default PluginsPage