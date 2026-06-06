import React, { useState } from 'react';
import { Shield, Activity, Search, AlertTriangle, Settings, RefreshCw } from 'lucide-react';
import { motion } from 'framer-motion';

function App() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!target) return;
    setLoading(true);
    setError(null);
    setResults(null);
    
    try {
      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, target_type: 'email' })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Scan failed');
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen bg-background text-white">
      {/* Sidebar */}
      <aside className="w-64 border-r border-[#303030] p-6 flex flex-col gap-8">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-accent" />
          <h1 className="text-xl font-bold tracking-wider">Aegis OSINT</h1>
        </div>
        
        <nav className="flex flex-col gap-4 text-[#a0a0a0]">
          <a href="#" className="flex items-center gap-3 text-white bg-card p-3 rounded-lg">
            <Activity className="w-5 h-5" /> Dashboard
          </a>
          <a href="#" className="flex items-center gap-3 p-3 hover:bg-[#1a1a1a] rounded-lg transition-colors">
            <Search className="w-5 h-5" /> Intelligence
          </a>
          <a href="#" className="flex items-center gap-3 p-3 hover:bg-[#1a1a1a] rounded-lg transition-colors">
            <AlertTriangle className="w-5 h-5" /> Exposures
          </a>
          <a href="#" className="flex items-center gap-3 p-3 hover:bg-[#1a1a1a] rounded-lg transition-colors">
            <Settings className="w-5 h-5" /> Settings
          </a>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-10 overflow-y-auto">
        <header className="mb-10">
          <h2 className="text-3xl font-semibold mb-2">Intelligence Center</h2>
          <p className="text-[#a0a0a0]">Scan targets across clear and dark web sources to uncover data exposures.</p>
        </header>

        <section className="bg-card p-8 rounded-2xl border border-[#303030] shadow-2xl">
          <form onSubmit={handleScan} className="flex gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-[#a0a0a0]" />
              <input 
                type="email" 
                placeholder="Enter email address (e.g., target@example.com)" 
                className="w-full bg-[#0d0d0d] border border-[#303030] rounded-xl py-4 pl-12 pr-4 focus:outline-none focus:border-accent transition-colors"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
            <button 
              type="submit" 
              disabled={loading}
              className="bg-accent text-[#0d0d0d] px-8 py-4 rounded-xl font-semibold hover:bg-opacity-90 transition-all flex items-center gap-2 disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-5 h-5 animate-spin" /> : 'Deep Search'}
            </button>
          </form>

          {error && (
            <div className="mt-6 p-4 bg-red-900/20 border border-red-500/50 rounded-xl text-red-200">
              {error}
            </div>
          )}

          {results && (
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-8"
            >
              <h3 className="text-xl font-medium mb-4 flex items-center gap-2">
                <AlertTriangle className={results.exposures.length > 0 ? "text-red-500" : "text-green-500"} />
                {results.exposures.length} Exposures Found
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {results.exposures.map((exposure, idx) => (
                  <div key={idx} className="p-4 bg-[#0d0d0d] border border-[#303030] rounded-xl flex items-center justify-between">
                    <span className="font-medium">{exposure}</span>
                    <span className="text-xs bg-red-500/20 text-red-400 px-2 py-1 rounded-full border border-red-500/30">Compromised</span>
                  </div>
                ))}
              </div>
              
              {results.exposures.length === 0 && (
                <div className="text-[#a0a0a0] p-4 bg-[#0d0d0d] rounded-xl border border-[#303030]">
                  No public exposures found for this target.
                </div>
              )}
            </motion.div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
