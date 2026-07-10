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
        providers: [],
        selectedInvestigationId: null,
        currentProviderId: null
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
    const pluginsGrid = document.getElementById('plugins-grid');
    const providerGrid = document.getElementById('provider-grid');
    const resultsContent = document.getElementById('results-content');
    const tabBtns = document.querySelectorAll('.tab-btn');

    // Modal elements
    const providerModal = document.getElementById('provider-modal');
    const modalProviderName = document.getElementById('modal-provider-name');
    const modalProviderDesc = document.getElementById('modal-provider-desc');
    const modalAuthContainer = document.getElementById('modal-auth-container');
    const modalSaveBtn = document.getElementById('modal-save-btn');
    const modalTestBtn = document.getElementById('modal-test-btn');
    const modalDisconnectBtn = document.getElementById('modal-disconnect-btn');
    const modalCancelBtn = document.getElementById('modal-cancel-btn');
    const modalFeedback = document.getElementById('modal-feedback');

    // --- Helper for API Fetching ---
    async function apiFetch(url, options = {}) {
        const resp = await fetch(url, options);
        if (!resp.ok) {
            let errorMsg = `HTTP Error ${resp.status}`;
            try {
                const errData = await resp.json();
                if (errData.errors && errData.errors.length > 0) {
                    errorMsg = errData.errors.join(', ');
                }
            } catch(e) {}
            throw new Error(errorMsg);
        }
        const data = await resp.json();
        if (data.success === false) {
            throw new Error(data.errors.join(', '));
        }
        return data.data; // unwrap standardized response
    }

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
        if (pageId === 'settings') loadProviders();
        if (pageId === 'schedules') loadSchedules();
        if (pageId === 'chat') initChatPage();
    }

    // --- Dashboard ---
    async function updateDashboard() {
        try {
            const targets = await apiFetch('/api/targets');
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
            const result = await apiFetch('/api/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query, target_type: type })
            });

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
                    <button class="btn btn-primary" onclick="viewInvestigation(${result.target_id})">View Results</button>
                </div>
            `;
        } catch (e) {
            searchResults.innerHTML = `<div class="error-msg">Error: ${e.message}</div>`;
        } finally {
            searchBtn.disabled = false;
            searchBtn.textContent = 'Start Investigation';
        }
    });

    // --- Results ---
    window.viewInvestigation = async (targetId) => {
        state.selectedInvestigationId = targetId;
        navigateTo('results');
        await loadResults(targetId);
    };

    async function loadResults(targetId) {
        resultsContent.innerHTML = '<div class="loading-spinner"></div>';
        try {
            const [findings, entities, rels, timeline] = await Promise.all([
                apiFetch(`/api/findings?target_id=${targetId}`),
                apiFetch(`/api/targets/${targetId}/entities`),
                apiFetch(`/api/targets/${targetId}/relationships`),
                apiFetch(`/api/targets/${targetId}/timeline`)
            ]);

            state.findings = findings;
            state.entities = entities;
            state.relationships = rels;
            state.timeline = timeline;

            // Default to findings tab
            document.querySelector('.tab-btn[data-tab="findings"]').click();
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
                        <div class="timeline-desc ${t.severity === 'error' ? 'error-text' : ''}">${t.description}</div>
                    </div>
                `;
                container.appendChild(div);
            });
        }
        resultsContent.innerHTML = '';
        resultsContent.appendChild(container);
    }

    function renderGraph() {
        resultsContent.innerHTML = '<div id="vis-network" style="width: 100%; height: 500px; border: 1px solid #333; border-radius: 8px;"></div>';
        
        if (state.entities.length === 0) {
            resultsContent.innerHTML += '<p class="empty-msg">No data for graph visualization.</p>';
            return;
        }

        const nodes = state.entities.map(e => ({
            id: e.id,
            label: e.value,
            group: e.type,
            title: e.type
        }));

        const edges = state.relationships.map(r => ({
            from: r.source_entity_id,
            to: r.target_entity_id,
            label: r.relationship_type,
            arrows: 'to'
        }));

        const container = document.getElementById('vis-network');
        const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
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
        };

        new vis.Network(container, data, options);
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
            const plugins = await apiFetch('/api/plugins');
            state.plugins = plugins;
            
            pluginsGrid.innerHTML = plugins.map(p => `
                <div class="plugin-card ${p.status === 'disabled' ? 'disabled' : ''}">
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

    // --- Provider Management ---
    async function loadProviders() {
        try {
            const providers = await apiFetch('/api/providers');
            state.providers = providers;
            
        providerGrid.innerHTML = providers.map(p => `
            <div class="plugin-card provider-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span class="provider-icon">🔌</span>
                        <div class="plugin-name">${p.name}</div>
                    </div>
                    <span class="tag" style="background-color: ${p.status === 'connected' ? '#4CAF50' : '#f44336'};">${p.status.toUpperCase()}</span>
                </div>
                <div class="plugin-desc" style="margin-bottom: 0.5rem;">${p.description}</div>
                <div class="provider-meta" style="font-size: 0.8rem; color: #888; margin-bottom: 1rem;">
                    <div><strong>Auth:</strong> ${p.supported_authentication.join(', ')}</div>
                    <div><strong>Connection:</strong> ${p.status === 'connected' ? 'Active' : 'Disconnected'}</div>
                    <div><strong>Last Validation:</strong> ${new Date().toLocaleDateString()}</div>
                </div>
                <div class="provider-actions" style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                    <button class="btn btn-secondary" style="flex: 1;" onclick="openProviderModal('${p.id}')">Configure</button>
                    <button class="btn btn-primary" style="flex: 1;" onclick="testProvider('${p.id}')">Test</button>
                    <button class="btn btn-danger" style="flex: 1;" onclick="disconnectProvider('${p.id}')">Disconnect</button>
                    <a href="https://example.com/docs/${p.id}" target="_blank" class="btn btn-secondary" style="flex: 1; text-align: center; text-decoration: none;">Docs</a>
                </div>
            </div>
        `).join('');
        } catch (e) {
            providerGrid.innerHTML = `<p class="error-msg">Failed to load providers: ${e.message}</p>`;
        }
    }

    window.openProviderModal = (id) => {
        const p = state.providers.find(x => x.id === id);
        if (!p) return;

        state.currentProviderId = p.id;
        modalProviderName.textContent = p.name;
        modalProviderDesc.textContent = p.description;
        modalFeedback.innerHTML = '';
        modalFeedback.className = '';
        
        let html = '';
        if (p.supported_authentication.includes('api_key')) {
            html += `
                <label>API Key</label>
                <input type="password" id="modal-api-key" placeholder="Enter API Key" class="form-input">
            `;
        } else if (p.supported_authentication.includes('username_password')) {
            html += `
                <label>Username</label>
                <input type="text" id="modal-username" placeholder="Username" class="form-input" style="margin-bottom: 0.5rem;">
                <label>Password</label>
                <input type="password" id="modal-password" placeholder="Password" class="form-input">
            `;
        } else if (p.supported_authentication.includes('oauth')) {
            html += `<p>OAuth configuration requires backend redirect flow (Not Implemented in MVP).</p>`;
        } else {
            html += `<p>No configuration needed.</p>`;
        }
        
        modalAuthContainer.innerHTML = html;
        providerModal.style.display = 'flex';
    };

    modalCancelBtn.addEventListener('click', () => {
        providerModal.style.display = 'none';
    });

    modalSaveBtn.addEventListener('click', async () => {
        const id = state.currentProviderId;
        const p = state.providers.find(x => x.id === id);
        
        const payload = {};
        if (p.supported_authentication.includes('api_key')) {
            const val = document.getElementById('modal-api-key')?.value;
            if (val) payload['api_key'] = val;
        } else if (p.supported_authentication.includes('username_password')) {
            const username = document.getElementById('modal-username')?.value;
            const password = document.getElementById('modal-password')?.value;
            if (username) payload['username'] = username;
            if (password) payload['password'] = password;
        }

        try {
            const res = await apiFetch(`/api/providers/${id}/configure`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            showModalFeedback(res.message, 'success');
            await loadProviders(); // refresh
        } catch (e) {
            showModalFeedback(e.message, 'error');
        }
    });

    modalTestBtn.addEventListener('click', async () => {
        const id = state.currentProviderId;
        try {
            const res = await apiFetch(`/api/providers/${id}/test`, { method: 'POST' });
            showModalFeedback(res.message, 'success');
        } catch (e) {
            showModalFeedback(e.message, 'error');
        }
    });

    modalDisconnectBtn.addEventListener('click', async () => {
        const id = state.currentProviderId;
        try {
            const res = await apiFetch(`/api/providers/${id}`, { method: 'DELETE' });
            showModalFeedback(res.message, 'success');
            await loadProviders(); // refresh
        } catch (e) {
            showModalFeedback(e.message, 'error');
        }
    });

    window.testProvider = async (id) => {
        try {
            const res = await apiFetch(`/api/providers/${id}/test`, { method: 'POST' });
            alert(res.message || "Test successful!");
            await loadProviders();
        } catch (e) {
            alert(e.message || "Test failed.");
        }
    };

    window.disconnectProvider = async (id) => {
        if (!confirm('Are you sure you want to disconnect this provider?')) return;
        try {
            const res = await apiFetch(`/api/providers/${id}`, { method: 'DELETE' });
            alert(res.message || "Disconnected!");
            await loadProviders();
        } catch (e) {
            alert(e.message || "Failed to disconnect.");
        }
    };

    function showModalFeedback(msg, type) {
        modalFeedback.textContent = msg;
        modalFeedback.className = type === 'success' ? 'success-text' : 'error-text';
        if (type === 'success') modalFeedback.style.color = '#4CAF50';
        if (type === 'error') modalFeedback.style.color = '#F44336';
    }

    // --- Chat ---
    // (Optional for MVP, disabled if not implemented properly, but I'll update it to use apiFetch)
    if (chatSend) {
        chatSend.addEventListener('click', async () => {
            const message = chatInput.value.trim();
            if (!message) return;

            appendChatMessage('user', message);
            chatInput.value = '';

            try {
                const result = await apiFetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message,
                        provider: chatProvider.value,
                        model: chatModel.value
                    })
                });
                appendChatMessage('assistant', result.response);
            } catch (e) {
                appendChatMessage('assistant', 'Error: ' + e.message);
            }
        });
    }

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

    // --- Scheduled Scans (Phase 2) ---
    const scheduleCreateBtn = document.getElementById('schedule-create-btn');
    if (scheduleCreateBtn) {
        scheduleCreateBtn.addEventListener('click', async () => {
            const query = document.getElementById('schedule-query').value.trim();
            const type = document.getElementById('schedule-type').value;
            const cron = document.getElementById('schedule-cron').value.trim();
            if (!query || !cron) return alert('Query and cron are required');

            try {
                await apiFetch('/api/schedules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query, target_type: type, schedule: cron })
                });
                alert('Schedule created successfully!');
                loadSchedules();
            } catch (e) {
                alert('Error: ' + e.message);
            }
        });
    }

    window.deleteSchedule = async (id) => {
        if (!confirm('Delete this scheduled scan?')) return;
        try {
            await apiFetch(`/api/schedules/${id}`, { method: 'DELETE' });
            loadSchedules();
        } catch (e) {
            alert(e.message);
        }
    };

    async function loadSchedules() {
        const container = document.getElementById('schedules-list');
        if (!container) return;
        try {
            const schedules = await apiFetch('/api/schedules');
            if (schedules.length === 0) {
                container.innerHTML = '<p class="empty-msg">No scheduled scans yet.</p>';
                return;
            }
            container.innerHTML = schedules.map(s => `
                <div class="recent-item">
                    <div class="recent-info">
                        <div class="recent-query">${s.query}</div>
                        <div class="recent-meta">${s.schedule} • ${s.enabled ? 'Active' : 'Disabled'}</div>
                    </div>
                    <div>
                        <button class="btn btn-danger btn-sm" onclick="deleteSchedule(${s.id})">Delete</button>
                    </div>
                </div>
            `).join('');
        } catch (e) {
            container.innerHTML = `<p class="error-msg">Failed to load schedules: ${e.message}</p>`;
        }
    }

    // --- Chat Page (Local + Cloud) ---
    let chatInitialized = false;

    function initChatPage() {
        if (chatInitialized) return;
        chatInitialized = true;

        const chatSend = document.getElementById('chat-send');
        const chatInput = document.getElementById('chat-input');
        const chatMessages = document.getElementById('chat-messages');
        const chatProvider = document.getElementById('chat-provider');
        const chatModel = document.getElementById('chat-model');

        if (!chatSend || !chatInput) return;

        chatSend.addEventListener('click', sendChatMessage);
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendChatMessage();
        });

        function sendChatMessage() {
            const message = chatInput.value.trim();
            if (!message) return;

            appendChatMessage('user', message);
            chatInput.value = '';

            const provider = chatProvider.value;
            const model = chatModel.value || 'phi3:mini';

            apiFetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message, provider, model })
            })
            .then(result => {
                appendChatMessage('assistant', result.response || 'No response');
            })
            .catch(err => {
                appendChatMessage('assistant', 'Error: ' + err.message);
            });
        }

        function appendChatMessage(role, text) {
            const div = document.createElement('div');
            div.style.marginBottom = '12px';
            div.style.display = 'flex';
            div.style.gap = '8px';
            div.innerHTML = `
                <div style="width:28px;height:28px;border-radius:50%;background:${role === 'user' ? '#3b82f6' : '#22c55e'};display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:bold;flex-shrink:0;">
                    ${role === 'user' ? 'U' : 'AI'}
                </div>
                <div style="flex:1; background:#2a2a2a; padding:10px 14px; border-radius:8px; white-space:pre-wrap;">
                    ${text}
                </div>
            `;
            chatMessages.appendChild(div);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        // Welcome message
        if (chatMessages.children.length === 0) {
            appendChatMessage('assistant', 'Hello! I can help with OSINT questions or analyze investigation results. Using local model: phi3:mini (recommended).');
        }
    }

    // --- Initialization ---
    updateDashboard();
    loadPlugins();
});