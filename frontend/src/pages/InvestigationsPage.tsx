import { useState } from 'react'
import { search } from '@/api/client'
import type { Finding } from '@/types/api'
import { escapeHtml } from '@/lib/utils'

interface InvestigationsPageProps {
  onViewInvestigation: (id: number) => void
}

function InvestigationsPage({ onViewInvestigation }: InvestigationsPageProps) {
  const [query, setQuery] = useState('')
  const [targetType, setTargetType] = useState('auto')
  const [result, setResult] = useState<{ target_id: number; findings_count: number } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSearch = async () => {
    if (!query.trim()) return
    
    setLoading(true)
    setError(null)
    
    try {
      const r = await search({ query, target_type: targetType })
      setResult(r)
      onViewInvestigation(r.target_id)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6">
      <header className="mb-6">
        <h2 className="text-2xl font-bold">Investigations</h2>
        <p className="text-muted-foreground">Start a new OSINT investigation</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Search Form */}
        <div className="md:col-span-1">
          <div className="bg-card p-4 rounded-lg border border-border">
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Search Query</label>
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Enter domain, email, IP, company..."
                  className="w-full px-3 py-2 bg-background border border-border rounded-md"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1">Target Type</label>
                <select
                  value={targetType}
                  onChange={(e) => setTargetType(e.target.value)}
                  className="w-full px-3 py-2 bg-background border border-border rounded-md"
                >
                  <option value="auto">Auto-detect</option>
                  <option value="domain">Domain</option>
                  <option value="email">Email</option>
                  <option value="ip">IP Address</option>
                  <option value="company">Company</option>
                  <option value="abn">ABN</option>
                  <option value="nz_domain">NZ Domain</option>
                  <option value="nz_company">NZ Company</option>
                </select>
              </div>
              
              <button
                onClick={handleSearch}
                disabled={loading || !query.trim()}
                className="w-full px-4 py-2 bg-primary text-primary-foreground rounded-md disabled:opacity-50"
              >
                {loading ? 'Searching...' : 'Start Investigation'}
              </button>
              
              {error && (
                <div className="text-destructive text-sm">{escapeHtml(error)}</div>
              )}
              
              {result && (
                <div className="text-success">
                  ✓ Investigation complete: {result.findings_count} findings
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Results */}
        <div className="md:col-span-2">
          <div className="bg-card p-4 rounded-lg border border-border min-h-[200px]">
            {loading ? (
              <div className="text-muted-foreground">Running investigation...</div>
            ) : result ? (
              <div className="text-success">
                <div className="font-medium">Investigation Complete</div>
                <div>{result.findings_count} findings discovered</div>
              </div>
            ) : (
              <p className="text-muted-foreground">Enter a query to start searching</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default InvestigationsPage
