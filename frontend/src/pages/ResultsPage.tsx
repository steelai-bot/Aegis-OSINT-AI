import { useEffect, useState, useRef } from 'react'
import { DataSet } from 'vis-data'
import { Network } from 'vis-network'
import { getFindings, getEntities, getRelationships, getTimeline } from '@/api/client'
import type { Finding, Entity, Relationship, TimelineEvent } from '@/types/api'
import { escapeHtml } from '@/lib/utils'

interface ResultsPageProps {
  targetId: number
}

type Tab = 'findings' | 'entities' | 'timeline' | 'graph'

function ResultsPage({ targetId }: ResultsPageProps) {
  const [activeTab, setActiveTab] = useState<Tab>('findings')
  const [findings, setFindings] = useState<Finding[]>([])
  const [entities, setEntities] = useState<Entity[]>([])
  const [relationships, setRelationships] = useState<Relationship[]>([])
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [loading, setLoading] = useState(true)
  const networkRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setLoading(true)
    Promise.all([
      getFindings(targetId),
      getEntities(targetId),
      getRelationships(targetId),
      getTimeline(targetId)
    ])
      .then(([f, e, r, t]) => {
        setFindings(f)
        setEntities(e)
        setRelationships(r)
        setTimeline(t)
      })
      .finally(() => setLoading(false))
  }, [targetId])

  // Initialize vis-network when graph tab is active
  useEffect(() => {
    if (activeTab !== 'graph' || !networkRef.current || entities.length === 0) return

    const nodes = entities.map(e => ({
      id: e.id,
      label: e.value,
      group: e.type,
      title: e.type
    }))

    const edges = relationships.map(r => ({
      from: r.source_entity_id,
      to: r.target_entity_id,
      label: r.relationship_type,
      arrows: 'to'
    }))

    const data = { nodes: new DataSet(nodes), edges: new DataSet(edges) }
    const options = {
      nodes: {
        shape: 'dot',
        size: 16,
        font: { size: 12, color: '#e0e0e0' },
        borderWidth: 2
      },
      edges: {
        width: 2,
        font: { size: 10, align: 'middle', color: '#aaa' }
      },
      groups: {
        domain: { color: { background: '#4CAF50', border: '#388E3C' } },
        email: { color: { background: '#2196F3', border: '#1976D2' } },
        ip: { color: { background: '#F44336', border: '#D32F2F' } },
        company: { color: { background: '#FF9800', border: '#F57C00' } }
      },
      physics: {
        stabilization: false,
        barnesHut: { gravitationalConstant: -2000, springConstant: 0.04, springLength: 95 }
      }
    }

    const network = new Network(networkRef.current, data, options)
    return () => {
      // Cleanup on unmount
    }
  }, [activeTab, entities, relationships])

  return (
    <div className="p-6">
      <header className="mb-6">
        <h2 className="text-2xl font-bold">Results</h2>
        <p className="text-muted-foreground">Investigation findings, entities, and timeline</p>
      </header>

      {/* Tabs */}
      <div className="flex gap-2 mb-4 border-b border-border">
        {(['findings', 'entities', 'timeline', 'graph'] as Tab[]).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 capitalize ${
              activeTab === tab 
                ? 'border-b-2 border-primary text-primary' 
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="bg-card p-4 rounded-lg border border-border">
        {loading ? (
          <p className="text-muted-foreground">Loading...</p>
        ) : activeTab === 'findings' ? (
          <div className="space-y-3">
            {findings.length === 0 ? (
              <p className="text-muted-foreground">No findings found</p>
            ) : findings.map(f => (
              <div key={f.id} className="border border-border rounded p-3">
                <div className="flex justify-between items-start mb-2">
                  <span className="font-medium">{escapeHtml(f.source)}</span>
                  <span className="text-sm bg-primary/20 px-2 py-1 rounded">
                    {escapeHtml(f.severity)}
                  </span>
                </div>
                <pre className="text-xs text-muted-foreground whitespace-pre-wrap">
                  {escapeHtml(JSON.stringify(f.data, null, 2))}
                </pre>
              </div>
            ))}
          </div>
        ) : activeTab === 'entities' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {entities.length === 0 ? (
              <p className="text-muted-foreground">No entities found</p>
            ) : entities.map(e => (
              <div key={e.id} className="border border-border rounded p-3">
                <div className="text-xs uppercase text-primary mb-1">{escapeHtml(e.type)}</div>
                <div className="font-medium">{escapeHtml(e.value)}</div>
                {e.display_name && (
                  <div className="text-sm text-muted-foreground">{escapeHtml(e.display_name)}</div>
                )}
              </div>
            ))}
          </div>
        ) : activeTab === 'timeline' ? (
          <div className="space-y-3">
            {timeline.length === 0 ? (
              <p className="text-muted-foreground">No timeline events</p>
            ) : timeline.map(t => (
              <div key={t.id} className="border-l-2 border-primary pl-4 pb-2">
                <div className="text-sm text-muted-foreground">
                  {new Date(t.timestamp).toLocaleString()}
                </div>
                <div className={t.severity === 'error' ? 'text-destructive' : ''}>
                  {escapeHtml(t.description)}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div ref={networkRef} className="h-[500px] border border-border rounded">
            {entities.length === 0 && (
              <p className="text-muted-foreground p-4">No data for graph visualization</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default ResultsPage