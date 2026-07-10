import { useState, useEffect } from 'react'
import { LayoutDashboard, Search, FileText, MessageSquare, Puzzle, Settings } from 'lucide-react'
import DashboardPage from './pages/DashboardPage'
import InvestigationsPage from './pages/InvestigationsPage'
import ResultsPage from './pages/ResultsPage'
import ChatPage from './pages/ChatPage'
import PluginsPage from './pages/PluginsPage'
import SettingsPage from './pages/SettingsPage'
import type { Finding, Entity, Relationship, TimelineEvent } from '@/types/api'

type Page = 'dashboard' | 'investigations' | 'results' | 'chat' | 'plugins' | 'settings'

function App() {
  const [currentPage, setCurrentPage] = useState<Page>('dashboard')
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null)

  const navItems = [
    { id: 'dashboard' as const, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'investigations' as const, label: 'Investigations', icon: Search },
    { id: 'results' as const, label: 'Results', icon: FileText },
    { id: 'chat' as const, label: 'AI Chat', icon: MessageSquare },
    { id: 'plugins' as const, label: 'Plugins', icon: Puzzle },
    { id: 'settings' as const, label: 'Settings', icon: Settings },
  ]

  useEffect(() => {
    // Load initial data
  }, [])

  return (
    <div className="flex h-screen bg-background text-foreground">
      {/* Sidebar */}
      <aside className="w-64 bg-sidebar border-r border-border flex flex-col">
        <div className="p-4 border-b border-border">
          <h1 className="text-xl font-bold">Aegis OSINT AI</h1>
          <p className="text-sm text-muted-foreground">OSINT Investigation Framework</p>
        </div>
        
        <nav className="flex-1 p-2">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setCurrentPage(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                currentPage === item.id
                  ? 'bg-primary/20 text-primary'
                  : 'text-muted-foreground hover:bg-card hover:text-foreground'
              }`}
            >
              <item.icon size={18} />
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
        
        <div className="p-4 border-t border-border">
          <div className="text-xs text-muted-foreground">v1.0.0</div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        {currentPage === 'dashboard' && <DashboardPage onViewInvestigation={setSelectedTargetId} />}
        {currentPage === 'investigations' && <InvestigationsPage onViewInvestigation={setSelectedTargetId} />}
        {currentPage === 'results' && selectedTargetId && <ResultsPage targetId={selectedTargetId} />}
        {currentPage === 'chat' && <ChatPage />}
        {currentPage === 'plugins' && <PluginsPage />}
        {currentPage === 'settings' && <SettingsPage />}
      </main>
    </div>
  )
}

export default App