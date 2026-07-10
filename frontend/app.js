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

    // --- XSS Prevention: Escape HTML in user-controlled data ---
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(String(str)));
        return div.innerHTML;
    }

    function escapeJson(obj) {
        return escapeHtml(JSON.stringify(obj, null, 2));
    }

    // --- Toast Notification System ---
    function showToast(message, type = 'info') {
        const existing = document.querySelector('.toast-container');
        let container = existing;
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => {
            toast.classList.add('toast-fade');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

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
            } catch (e) { }
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
        if (pageId === 'chat') { /* chat is always ready */ }
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
                            <div class="recent-query">${escapeHtml(t.query)}</div>
                            <div class="recent-meta">${escapeHtml(t.target_type)} • ${escapeHtml(t.status)}</div>
                        </div>
                        <div class="recent-date">${escapeHtml(new Date(t.created_at).toLocaleDateString())}</div>
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
                    <p>${escapeHtml(result.findings_count)} findings discovered</p>
                    <button class="btn btn-primary" onclick="viewInvestigation(${result.target_id})">View Results</button>
                </div>
            `;
        } catch (e) {
            searchResults.innerHTML = `<div class="error-msg">Error: ${escapeHtml(e.message)}</div>`;
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
            resultsContent.innerHTML = `<div class="error-msg">Failed to load results: ${escapeHtml(e.message)}</div>`;
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
                        <span class="finding-source">${escapeHtml(f.source)}</span>
                        <span class="finding-category">${escapeHtml(f.category)}</span>
                        <span class="finding-confidence">${escapeHtml((f.confidence * 100).toFixed(0))}%</span>
                    </div>
                    <div class="finding-body">
                        <pre>${escapeJson(f.data)}</pre>
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
                    <div class="entity-type">${escapeHtml(e.type.toUpperCase())}</div>
                    <div class="entity-value">${escapeHtml(e.value)}</div>
                    <div class="entity-meta">${escapeHtml(e.display_name || '')}</div>
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
                        <div class="timeline-time">${escapeHtml(new Date(t.timestamp).toLocaleString())}</div>
                        <div class="timeline-desc ${t.severity === 'error' ? 'error-text' : ''}">${escapeHtml(t.description)}</div>
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
        pluginsGrid.innerHTML = '<div class="loading-spinner"></div>';
        try {
            const plugins = await apiFetch('/api/plugins');
            state.plugins = plugins;

            if (plugins.length === 0) {
                pluginsGrid.innerHTML = '<p class="empty-msg">No plugins installed.</p>';
                return;
            }

            pluginsGrid.innerHTML = plugins.map(p => `
                <div class="plugin-card ${p.status === 'disabled' ? 'disabled' : ''}">
                    <div class="plugin-name">${escapeHtml(p.name)}</div>
                    <div class="plugin-desc">${escapeHtml(p.description)}</div>
                    <div class="plugin-tags">
                        ${(p.tags || []).map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('')}
                    </div>
                </div>
            `).join('');
        } catch (e) {
            pluginsGrid.innerHTML = '<p class="error-msg">Failed to load plugins.</p>';
        }
    }

    // --- Provider Management ---
    async function loadProviders() {
        providerGrid.innerHTML = '<div class="loading-spinner"></div>';
        try {
            const providers = await apiFetch('/api/providers');
            state.providers = providers;

            if (providers.length === 0) {
                providerGrid.innerHTML = '<p class="empty-msg">No providers configured.</p>';
                return;
            }

            providerGrid.innerHTML = providers.map(p => `
            <div class="plugin-card provider-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span class="provider-icon">🔌</span>
                        <div class="plugin-name">${escapeHtml(p.name)}</div>
                    </div>
                    <span class="tag" style="background-color: ${p.status === 'connected' ? '#4CAF50' : '#f44336'};">${escapeHtml(p.status.toUpperCase())}</span>
                </div>
                <div class="plugin-desc" style="margin-bottom: 0.5rem;">${escapeHtml(p.description)}</div>
                <div class="provider-meta" style="font-size: 0.8rem; color: #888; margin-bottom: 1rem;">
                    <div><strong>Auth:</strong> ${escapeHtml((p.supported_authentication || []).join(', '))}</div>
                    <div><strong>Connection:</strong> ${p.status === 'connected' ? 'Active' : 'Disconnected'}</div>
                    <div><strong>Last Validation:</strong> ${escapeHtml(new Date().toLocaleDateString())}</div>
                </div>
                <div class="provider-actions" style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                    <button class="btn btn-secondary" style="flex: 1;" onclick="openProviderModal('${escapeHtml(p.id)}')">Configure</button>
                    <button class="btn btn-primary" style="flex: 1;" onclick="testProvider('${escapeHtml(p.id)}')">Test</button>
                    <button class="btn btn-danger" style="flex: 1;" onclick="disconnectProvider('${escapeHtml(p.id)}')">Disconnect</button>
                    <a href="https://example.com/docs/${escapeHtml(p.id)}" target="_blank" class="btn btn-secondary" style="flex: 1; text-align: center; text-decoration: none;">Docs</a>
                </div>
            </div>
        `).join('');
        } catch (e) {
            providerGrid.innerHTML = `<p class="error-msg">Failed to load providers: ${escapeHtml(e.message)}</p>`;
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
            const val = document.getElementById('modal-api-key').value;
            if (val) payload['api_key'] = val;
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
            showToast(res.message || "Test successful!", 'success');
            await loadProviders();
        } catch (e) {
            showToast(e.message || "Test failed.", 'error');
        }
    };

    window.disconnectProvider = async (id) => {
        if (!confirm('Are you sure you want to disconnect this provider?')) return;
        try {
            const res = await apiFetch(`/api/providers/${id}`, { method: 'DELETE' });
            showToast(res.message || "Disconnected!", 'success');
            await loadProviders();
        } catch (e) {
            showToast(e.message || "Failed to disconnect.", 'error');
        }
    };

    function showModalFeedback(msg, type) {
        modalFeedback.textContent = msg;
        modalFeedback.className = type === 'success' ? 'success-text' : 'error-text';
        if (type === 'success') modalFeedback.style.color = '#4CAF50';
        if (type === 'error') modalFeedback.style.color = '#F44336';
    }

    // --- Chat ---
    if (chatSend) {
        chatSend.addEventListener('click', sendChatMessage);
    }

    if (chatInput) {
        chatInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendChatMessage();
            }
        });
    }

    async function sendChatMessage() {
        const message = chatInput.value.trim();
        if (!message) return;

        appendChatMessage('user', message);
        chatInput.value = '';

        // Show typing indicator
        const typingDiv = document.createElement('div');
        typingDiv.className = 'message assistant typing';
        typingDiv.innerHTML = '<div class="message-avatar">AI</div><div class="message-content"><div class="typing-indicator"><span></span><span></span><span></span></div></div>';
        chatMessages.appendChild(typingDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;

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
            // Remove typing indicator
            typingDiv.remove();
            appendChatMessage('assistant', result.response);
        } catch (e) {
            typingDiv.remove();
            appendChatMessage('assistant', 'Error: ' + e.message);
        }
    }

    function appendChatMessage(role, text) {
        const div = document.createElement('div');
        div.className = `message ${role}`;
        div.innerHTML = `
            <div class="message-avatar">${role === 'user' ? 'U' : 'AI'}</div>
            <div class="message-content"><p>${escapeHtml(text)}</p></div>
        `;
        chatMessages.appendChild(div);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // --- Initialization ---
    updateDashboard();
    loadPlugins();
});