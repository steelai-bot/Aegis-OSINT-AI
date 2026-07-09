document.addEventListener('DOMContentLoaded', () => {
    // --- State Management ---
    const state = {
        currentPage: 'dashboard',
        investigations: [],
        findings: [],
        entities: [],
        relationships: [],
        timeline: [],
        plugins: [],
        settings: {},
        selectedInvestigationId: null
    };

    // --- DOM Elements ---
    const navItems = document.querySelectorAll('.nav-item');
    const pages = document.querySelectorAll('.page');
    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    const chatSend = document.getElementById('chat-send');
    const chatProvider = document.getElementById('chat-provider');
    const chatModel = document.getElementById('chat-model');
    const searchBtn = document.getElementById('search-btn');
    const searchQuery = document.getElementById('search-query');
    const searchType = document.getElementById('search-type');
    const searchResults = document.getElementById('search-results');
    const reportsList = document.getElementById('reports-list');
    const saveKeysBtn = document.getElementById('save-keys-btn');
    const pluginsGrid = document.getElementById('plugins-grid');
    const resultsContent = document.getElementById('results-content');
    const tabBtns = document.querySelectorAll('.tab-btn');

    // --- Navigation ---
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const pageId = item.getAttribute('data-page');
            navigateTo(pageId);
        });
    });

    function navigateTo(pageId) {
        state.currentPage = pageId;
        navItems.forEach(item => {
            item.classList.toggle('active', item.getAttribute('data-page') === pageId);
        });
        pages.forEach(page => {
            page.classList.toggle('active', page.id === `page-${pageId}`);
        });
        
        if (pageId === 'dashboard') updateDashboard();
        if (pageId === 'plugins') loadPlugins();
        if (pageId === 'settings') loadSettings();
    }

    // --- Dashboard ---
    async function updateDashboard() {
        try {
            const resp = await fetch('/api/targets');
            const targets = await resp.json();
            state.investigations = targets;
            
            document.getElementById('stat-investigations').textContent = targets.length;
            
            const recentList = document.getElementById('recent-investigations');
            if (targets.length === 0) {
                recentList.innerHTML = '<p class="empty-msg">No recent investigations</p>';
            } else {
                recentList.innerHTML = targets.slice(0, 5).map(t => `
                    <div class="recent-item" onclick="viewInvestigation(${t.id})">
                        <div class="recent-info">
                            <div class="recent-query">${t.query}</div>
                            <div class="recent-meta">${t.target_type} • ${t.status}</div>
                        </div>
                        <div class="recent-date">${new Date(t.created_at).toLocaleDateString()}</div>
                    </div>
                `).join('');
            }
        } catch (e) {
            console.error('Failed to update dashboard', e);
        }
    }

    // --- Search / Investigations ---
    searchBtn.addEventListener('click', async () => {
        const query = searchQuery.value.trim();
        const type = searchType.value;
        if (!query) return;

        searchBtn.disabled = true;
        searchBtn.textContent = 'Searching...';
        searchResults.innerHTML = '<div class="loading-spinner"></div>';

        try {
            const resp = await fetch('/api/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query, target_type: type })
            });
            const result = await resp.json();

            if (result.error) {
                throw new Error(result.error);
            }

            // Update local state
            state.selectedInvestigationId = result.target_id;
            state.findings = result.findings || [];
            state.entities = result.entities || [];
            state.relationships = result.relationships || [];
            state.timeline = result.timeline || [];

            searchResults.innerHTML = `
                <div class="search-success">
                    <div class="success-icon">✓</div>
                    <h3>Investigation Complete</h3>
                    <p>${result.findings_count} findings discovered</p>
                    <button class="btn btn-primary" onclick="viewResults(${result.target_id})">View Results</button>
                </div>
            `;
        } catch (e) {
            searchResults.innerHTML = `<div class="error-msg">Error: ${e.message}</div>`;
        } finally {
            searchBtn.disabled = false;
            searchBtn.textContent = 'Search';
        }
    });

    // --- Results ---
    window.viewResults = async (targetId) => {
        state.selectedInvestigationId = targetId;
        navigateTo('results');
        await loadResults(targetId);
    };

    async function loadResults(targetId) {
        resultsContent.innerHTML = '<div class="loading-spinner"></div>';
        try {
            // We already have some data from the search response, but let's refresh to be sure
            const [findingsResp, entitiesResp, relsResp, timelineResp] = await Promise.all([
                fetch(`/api/findings?target_id=${targetId}`).then(r => r.json()),
                fetch(`/api/targets/${targetId}/entities`).then(r => r.json()),
                fetch(`/api/targets/${target_id}/relationships`).then(r => r.json()),
                fetch(`/api/targets/${target_id}/timeline`).then(r => r.json())
            ]);

            state.findings = findingsResp;
            state.entities = entitiesResp;
            state.relationships = relsResp;
            state.timeline = timelineResp;

            renderFindings();
            renderEntities();
            renderTimeline();
            renderGraph();
        } catch (e) {
            resultsContent.innerHTML = `<div class="error-msg">Failed to load results: ${e.message}</div>`;
        }
    }

    function renderFindings() {
        const container = document.createElement('div');
        container.className = 'findings-list';
        
        if (state.findings.length === 0) {
            container.innerHTML = '<p class="empty-msg">No findings found for this investigation.</p>';
        } else {
            state.findings.forEach(f => {
                const div = document.createElement('div');
                div.className = `finding-card severity-${f.severity}`;
                div.innerHTML = `
                    <div class="finding-header">
                        <span class="finding-source">${f.source}</span>
                        <span class="finding-category">${f.category}</span>
                        <span class="finding-confidence">${(f.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <div class="finding-body">
                        <pre>${JSON.stringify(f.data, null, 2)}</pre>
                    </div>
                `;
                container.appendChild(div);
            });
        }
        resultsContent.innerHTML = '';
        resultsContent.appendChild(container);
    }

    function renderEntities() {
        const container = document.createElement('div');
        container.className = 'entities-grid';
        
        if (state.entities.length === 0) {
            container.innerHTML = '<p class="empty-msg">No entities discovered.</p>';
        } else {
            state.entities.forEach(e => {
                const div = document.createElement('div');
                div.className = 'entity-card';
                div.innerHTML = `
                    <div class="entity-type">${e.type.toUpperCase()}</div>
                    <div class="entity-value">${e.value}</div>
                    <div class="entity-meta">${e.display_name || ''}</div>
                `;
                container.appendChild(div);
            });
        }
        resultsContent.innerHTML = '';
        resultsContent.appendChild(container);
    }

    function renderTimeline() {
        const container = document.createElement('div');
        container.className = 'timeline-container';
        
        if (state.timeline.length === 0) {
            container.innerHTML = '<p class="empty-msg">No timeline events recorded.</p>';
        } else {
            state.timeline.forEach(t => {
                const div = document.createElement('div');
                div.className = 'timeline-item';
                div.innerHTML = `
                    <div class="timeline-marker"></div>
                    <div class="timeline-content">
                        <div class="timeline-time">${new Date(t.timestamp).toLocaleString()}</div>
                        <div class="timeline-desc">${t.description}</div>
                    </div>
                `;
                container.appendChild(div);
            });
        }
        resultsContent.innerHTML = '';
        resultsContent.appendChild(container);
    }

    function renderGraph() {
        resultsContent.innerHTML = `
            <div class="graph-placeholder">
                <p>Graph visualization is coming soon in the next update.</p>
                <div class="graph-mockup">
                    <div class="node" style="top: 50%; left: 50%;">Target</div>
                    ${state.entities.slice(0, 5).map((e, i) => `
                        <div class="node" style="top: ${20 + i*15}%; left: ${20 + i*10}%;">${e.value}</div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    // Tabs
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const tab = btn.getAttribute('data-tab');
            
            if (tab === 'findings') renderFindings();
            if (tab === 'entities') renderEntities();
            if (tab === 'timeline') renderTimeline();
            if (tab === 'graph') renderGraph();
        });
    });

    // --- Plugins ---
    async function loadPlugins() {
        try {
            const resp = await fetch('/api/plugins');
            const plugins = await resp.json();
            state.plugins = plugins;
            
            pluginsGrid.innerHTML = plugins.map(p => `
                <div class="plugin-card">
                    <div class="plugin-name">${p.name}</div>
                    <div class="plugin-desc">${p.description}</div>
                    <div class="plugin-tags">
                        ${p.tags.map(t => `<span class="tag">${t}</span>`).join('')}
                    </div>
                </div>
            `).join('');
        } catch (e) {
            pluginsGrid.innerHTML = '<p class="error-msg">Failed to load plugins.</p>';
        }
    }

    // --- Settings ---
    async function loadSettings() {
        try {
            const resp = await fetch('/api/settings');
            state.settings = await resp.json();
            
            // Map settings to inputs
            const mapping = {
                'openrouter': 'key-openrouter',
                'openai': 'key-openai',
                'anthropic': 'key-anthropic',
                'gemini': 'key-gemini',
                'nvidia': 'key-nvidia',
                'virustotal': 'key-virustotal',
                'shodan': 'key-shodan',
                'hunter': 'key-hunter',
                'intelx': 'key-intelx',
                'censys': 'key-censys',
                'abuseipdb': 'key-abuseipdb',
                'urlscan': 'key-urlscan',
                'googlesearch': 'key-googlesearch',
                'googlecx': 'key-googlecx',
                'github': 'key-github'
            };

            for (const [key, id] of Object.entries(mapping)) {
                const el = document.getElementById(id);
                if (el) el.value = state.settings[key.toUpperCase()] || '';
            }
        } catch (e) {
            console.error('Failed to load settings', e);
        }
    }

    saveKeysBtn.addEventListener('click', async () => {
        const payload = {};
        const mapping = {
            'openrouter': 'key-openrouter',
            'openai': 'key-openai',
            'anthropic': 'key-anthropic',
            'gemini': 'key-gemini',
            'nvidia': 'key-nvidia',
            'virustotal': 'key-virustotal',
            'shodan': 'key-shodan',
            'hunter': 'key-hunter',
            'intelx': 'key-intelx',
            'censys': 'key-censys',
            'abuseipdb': 'key-abuseipdb',
            'urlscan': 'key-urlscan',
            'googlesearch': 'key-googlesearch',
            'googlecx': 'key-googlecx',
            'github': 'key-github'
        };

        for (const [key, id] of Object.entries(mapping)) {
            const el = document.getElementById(id);
            if (el && el.value) {
                payload[key] = el.value;
            }
        }

        try {
            const resp = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const result = await resp.json();
            if (result.status === 'success') {
                alert('Settings saved successfully!');
            }
        } catch (e) {
            alert('Error saving settings: ' + e.message);
        }
    });

    // --- Chat ---
    chatSend.addEventListener('click', async () => {
        const message = chatInput.value.trim();
        if (!message) return;

        appendChatMessage('user', message);
        chatInput.value = '';

        try {
            const resp = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message,
                    provider: chatProvider.value,
                    model: chatModel.value
                })
            });
            const result = await resp.json();
            appendChatMessage('assistant', result.response);
        } catch (e) {
            appendChatMessage('assistant', 'Error: ' + e.message);
        }
    });

    function appendChatMessage(role, text) {
        const div = document.createElement('div');
        div.className = `message ${role}`;
        div.innerHTML = `
            <div class="message-avatar">${role === 'user' ? 'U' : 'AI'}</div>
            <div class="message-content"><p>${text}</p></div>
        `;
        chatMessages.appendChild(div);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // --- Initialization ---
    updateDashboard();
    loadPlugins();
    loadSettings();
});

// Global helper for dashboard clicks
window.viewInvestigation = async (id) => {
    // This is a bit hacky for a single-page app without a router, 
    // but works for our MVP structure.
    // We'll simulate a click on the 'Investigations' nav item and then the result.
    document.querySelector('[data-page="investigations"]').click();
    // In a real app, we'd have a dedicated view for a single investigation.
    // For now, we'll just show the results page.
    // We need to trigger the search results view.
    // This is a limitation of the current simple architecture.
    alert('Investigation details view coming soon. Use the Search page to start new ones.');
};

window.viewResults = async (id) => {
    document.querySelector('[data-page="results"]').click();
    // We'll rely on the state being updated by the search function.
};