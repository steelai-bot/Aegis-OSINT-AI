import { useEffect, useState } from 'react'
import { getTargets, getPlugins } from '@/api/client'
import type { Target, PluginMetadata } from '@/types/api'
import { escapeHtml } from '@/lib/utils'

interface DashboardPageProps {
  onViewInvestigation: (id: number) => void
}

function DashboardPage({ onViewInvestigation }: DashboardPageProps) {
  const [targets, setTargets] = useState<Target[]>([])
  const [plugins, setPlugins] = useState<PluginMetadata[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([getTargets(), getPlugins()])
      .then(([t, p]) => {
        setTargets(t)
        setPlugins(p)
      })
      .catch(() => {
        /* ignore */
      })
      .finally(() => setLoading(false))
  }, [])

  const activePlugins = plugins.filter(p => p.status === 'enabled').length

  return (
    <div className="p-6">
      <header className="mb-6">
        <h2 className="text-2xl font-bold">Dashboard</h2>
        <p className="text-muted-foreground">Overview of your OSINT investigations</p>
      </header>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-card p-4 rounded-lg border border-border">
          <div className="text-3xl font-bold">{targets.length}</div>
          <div className="text-sm text-muted-foreground">Investigations</div>
        </div>
        <div className="bg-card p-4 rounded-lg border border-border">
          <div className="text-3xl font-bold">{targets.reduce((acc, t) => acc + 1, 0)}</div>
          <div className="text-sm text-muted-foreground">Findings</div>
        </div>
        <div className="bg-card p-4 rounded-lg border border-border">
          <div className="text-3xl font-bold">{targets.length}</div>
          <div className="text-sm text-muted-foreground">Entities</div>
        </div>
        <div className="bg-card p-4 rounded-lg border border-border">
          <div className="text-3xl font-bold">{activePlugins}</div>
          <div className="text-sm text-muted-foreground">Active Plugins</div>
        </div>
      </div>

      {/* Recent Investigations */}
      <div>
        <h3 className="text-lg font-semibold mb-3">Recent Investigations</h3>
        <div className="space-y-2">
          {loading ? (
            <div className="text-muted-foreground">Loading...</div>
          ) : targets.length === 0 ? (
            <p className="text-muted-foreground">No recent investigations</p>
          ) : (
            targets.slice(0, 5).map(t => (
              <div
                key={t.id}
                onClick={() => onViewInvestigation(t.id)}
                className="bg-card p-4 rounded-lg border border-border cursor-pointer hover:bg-card/80"
              >
                <div className="font-medium">{escapeHtml(t.query)}</div>
                <div className="text-sm text-muted-foreground">
                  {escapeHtml(t.target_type)} • {escapeHtml(t.status)} • {new Date(t.created_at).toLocaleDateString()}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

export default DashboardPage
