// Aegis OSINT AI - Frontend Application

const API_BASE = 'http://localhost:8000';

// Page navigation
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', function(e) {
        e.preventDefault();
        
        // Update active state
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        this.classList.add('active');
        
        // Show corresponding page
        const pageId = this.getAttribute('data-page');
        document.querySelectorAll('.page').forEach(page => page.classList.remove('active'));
        document.getElementById(`page-${pageId}`).classList.add('active');
        
        // Load page-specific data
        if (pageId === 'reports') loadReports();
    });
});

// Chat functionality
document.getElementById('chat-send').addEventListener('click', async () => {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    if (!message) return;
    
    const provider = document.getElementById('chat-provider').value;
    
    // Add user message to chat
    addChatMessage(message, 'user');
    input.value = '';
    
    // Show typing indicator
    addChatMessage('...', 'assistant', true);
    
    try {
        const response = await fetch(`${API_BASE}/api/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, provider })
        });
        
        const data = await response.json();
        
        // Remove typing indicator and show response
        removeLastTypingIndicator();
        addChatMessage(data.response || 'No response received', 'assistant');
    } catch (error) {
        removeLastTypingIndicator();
        addChatMessage('Error: ' + error.message, 'assistant');
    }
});

function addChatMessage(content, sender, isTyping = false) {
    const messages = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${sender}`;
    
    if (isTyping) {
        messageDiv.id = 'typing-indicator';
    }
    
    messageDiv.innerHTML = `
        <div class="message-avatar">${sender === 'user' ? 'U' : 'AI'}</div>
        <div class="message-content"><p>${escapeHtml(content)}</p></div>
    `;
    
    messages.appendChild(messageDiv);
    messages.scrollTop = messages.scrollHeight;
}

function removeLastTypingIndicator() {
    const indicator = document.getElementById('typing-indicator');
    if (indicator) indicator.remove();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// OSINT Search functionality
document.getElementById('search-btn').addEventListener('click', async () => {
    const query = document.getElementById('search-query').value.trim();
    const targetType = document.getElementById('search-type').value;
    const customSearch = document.getElementById('search-type').value === 'custom' 
        ? document.getElementById('custom-search-engine').value 
        : null;
    
    if (!query) return;
    
    const resultsDiv = document.getElementById('search-results');
    resultsDiv.innerHTML = '<div class="loading">Searching...</div>';
    
    try {
        const response = await fetch(`${API_BASE}/api/search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query, target_type: targetType, custom_search: customSearch })
        });
        
        const data = await response.json();
        displaySearchResults(data);
    } catch (error) {
        resultsDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
});

function displaySearchResults(data) {
    const resultsDiv = document.getElementById('search-results');
    
    if (!data.findings || data.findings.length === 0) {
        resultsDiv.innerHTML = '<div class="results-placeholder"><p>No findings found.</p></div>';
        return;
    }
    
    let html = `
        <div class="results-header">
            <h3>Found ${data.findings.length} findings for "${data.query}"</h3>
            <p>Target type: ${data.target_type}</p>
        </div>
        <div class="findings-list">
    `;
    
    data.findings.forEach(finding => {
        html += `
            <div class="finding-item">
                <div class="finding-header">
                    <span class="finding-source">${finding.source}</span>
                    <span class="finding-severity ${finding.severity}">${finding.severity.toUpperCase()}</span>
                </div>
                <div class="finding-data">
                    <pre>${JSON.stringify(finding.data, null, 2)}</pre>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    resultsDiv.innerHTML = html;
}

// Reports functionality
document.getElementById('generate-report-btn').addEventListener('click', async () => {
    const format = document.getElementById('report-format').value;
    
    try {
        const response = await fetch(`${API_BASE}/api/reports`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_id: 1, format })
        });
        
        const data = await response.json();
        alert(`Report generated: ${data.report_id}`);
    } catch (error) {
        alert('Error: ' + error.message);
    }
});

async function loadReports() {
    const reportsList = document.getElementById('reports-list');
    
    try {
        const response = await fetch(`${API_BASE}/api/targets`);
        const targets = await response.json();
        
        if (targets.length === 0) {
            reportsList.innerHTML = `
                <div class="reports-placeholder">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                    </svg>
                    <p>No targets found. Run a search first.</p>
                </div>
            `;
            return;
        }
        
        let html = '<div class="reports-grid">';
        targets.forEach(target => {
            html += `
                <div class="report-card" data-target-id="${target.id}">
                    <h4>${escapeHtml(target.query)}</h4>
                    <p>Type: ${target.target_type}</p>
                    <p>Status: ${target.status}</p>
                    <button class="btn btn-primary" onclick="generateReport(${target.id})">Generate Report</button>
                </div>
            `;
        });
        html += '</div>';
        reportsList.innerHTML = html;
    } catch (error) {
        reportsList.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function generateReport(targetId) {
    const format = document.getElementById('report-format').value;
    
    fetch(`${API_BASE}/api/reports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_id: targetId, format })
    })
    .then(response => response.json())
    .then(data => {
        alert(`Report generated: ${data.report_id}`);
    })
    .catch(error => {
        alert('Error: ' + error.message);
    });
}

// Settings functionality
document.getElementById('save-keys-btn').addEventListener('click', () => {
    const keys = {
        openrouter: document.getElementById('key-openrouter').value,
        openai: document.getElementById('key-openai').value,
        anthropic: document.getElementById('key-anthropic').value,
        gemini: document.getElementById('key-gemini').value,
        nvidia: document.getElementById('key-nvidia').value
    };
    
    // Save to localStorage (in production, this would go to the backend)
    localStorage.setItem('api_keys', JSON.stringify(keys));
    alert('API keys saved locally. Note: These are not persisted across sessions in this demo.');
});

// Load saved settings
window.addEventListener('load', () => {
    const savedKeys = JSON.parse(localStorage.getItem('api_keys') || '{}');
    if (savedKeys.openrouter) document.getElementById('key-openrouter').value = savedKeys.openrouter;
    if (savedKeys.openai) document.getElementById('key-openai').value = savedKeys.openai;
    if (savedKeys.anthropic) document.getElementById('key-anthropic').value = savedKeys.anthropic;
    if (savedKeys.gemini) document.getElementById('key-gemini').value = savedKeys.gemini;
    if (savedKeys.nvidia) document.getElementById('key-nvidia').value = savedKeys.nvidia;
});

// Toggle custom search engine field
document.getElementById('search-type').addEventListener('change', function() {
    const customGroup = document.getElementById('custom-search-group');
    customGroup.style.display = this.value === 'custom' ? 'block' : 'none';
});