class GraphManager {
    constructor() {
        this.nodes = [];
        this.edges = [];
        this.filteredNodes = [];
        this.filteredEdges = [];
        this.currentLayout = 'force';
        this.filterText = '';
        this.activeGroup = 'all';
        this.filterTypes = [];
        this.graphInitialized = false;
    }

    async loadData(nodesData, edgesData) {
        this.nodes = nodesData.map(n => ({
            ...n,
            confidence: n.confidence <= 1 && n.confidence > 0 ? Math.round(n.confidence * 100) : (n.confidence || 100)
        }));
        this.edges = edgesData.map(e => ({
            ...e,
            confidence: e.confidence <= 1 && e.confidence > 0 ? Math.round(e.confidence * 100) : (e.confidence || 100)
        }));
        this.filteredNodes = [...this.nodes];
        this.filteredEdges = [...this.edges];
        this.filterTypes = [...new Set(this.nodes.map(n => n.type))];
        this.graphInitialized = true;
        this.applyFilter();
        this.renderGraph();
    }

    applyFilter() {
        const filter = this.filterText.toLowerCase();
        
        // Filter nodes by search term and active entity types
        this.filteredNodes = this.nodes.filter(node => {
            const matchesText = !filter || node.value.toLowerCase().includes(filter) || node.type.toLowerCase().includes(filter);
            const matchesType = this.filterTypes.length === 0 || this.filterTypes.includes(node.type);
            return matchesText && matchesType;
        });

        // Set of visible node IDs
        const nodeIds = new Set(this.filteredNodes.map(n => n.id));

        // Filter edges: BOTH 'from' and 'to' nodes must be in visible nodes set, and optional text filter
        this.filteredEdges = this.edges.filter(edge => {
            const matchesText = !filter || edge.type.toLowerCase().includes(filter) || (edge.source_plugin && edge.source_plugin.toLowerCase().includes(filter));
            const hasConnectedNodes = nodeIds.has(edge.from) && nodeIds.has(edge.to);
            return hasConnectedNodes && matchesText;
        });
    }

    toggleTypeFilter(type) {
        const idx = this.filterTypes.indexOf(type);
        if (idx > -1) {
            this.filterTypes.splice(idx, 1);
        } else {
            this.filterTypes.push(type);
        }
        this.applyFilter();
        this.renderGraph();
    }

    search(term) {
        this.filterText = term;
        this.applyFilter();
        this.renderGraph();
    }

    showNodeDetail(nodeId) {
        const node = this.nodes.find(n => n.id === nodeId);
        const sidebar = document.getElementById('detail-sidebar');
        if (!sidebar) return;

        if (node) {
            const conf = node.confidence <= 1 ? Math.round(node.confidence * 100) : node.confidence;
            const confColor = conf >= 80 ? 'text-emerald-400' : conf >= 50 ? 'text-amber-400' : 'text-red-400';
            sidebar.innerHTML = `
                <div class="flex justify-between items-center mb-3 border-b border-border pb-2">
                    <h4 class="font-semibold text-sm flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full" style="background:${this.getNodeColor(node.type)}"></span>
                        Entity Details
                    </h4>
                    <button onclick="graphManager.showNodeDetail(null)" class="text-muted hover:text-foreground text-lg">&times;</button>
                </div>
                <div class="space-y-3 text-sm">
                    <div>
                        <span class="text-xs text-muted block mb-1">Value</span>
                        <div class="font-mono text-xs bg-background p-2 rounded border border-border break-all text-foreground">${node.value}</div>
                    </div>
                    <div>
                        <span class="text-xs text-muted block mb-1">Type</span>
                        <span class="px-2 py-0.5 rounded-full text-xs font-medium uppercase tracking-wider" style="background:${this.getNodeColor(node.type)}20;color:${this.getNodeColor(node.type)}">${node.type}</span>
                    </div>
                    <div>
                        <span class="text-xs text-muted block mb-1">Confidence Score</span>
                        <div class="flex items-center gap-2">
                            <div class="flex-1 bg-background h-2 rounded-full overflow-hidden border border-border">
                                <div class="h-full bg-primary" style="width: ${conf}%"></div>
                            </div>
                            <span class="font-mono font-semibold text-xs ${confColor}">${conf}%</span>
                        </div>
                    </div>
                    ${node.first_seen ? `<div><span class="text-xs text-muted block mb-1">First Seen</span><span class="text-xs font-mono text-foreground">${node.first_seen}</span></div>` : ''}
                    ${node.metadata && Object.keys(node.metadata).length > 0 ? `<div><span class="text-xs text-muted block mb-1">Metadata</span><pre class="mt-1 p-2 bg-background rounded border border-border text-xs font-mono overflow-x-auto text-foreground">${JSON.stringify(node.metadata, null, 2)}</pre></div>` : ''}
                </div>
            `;
            sidebar.classList.add('active');
        } else if (nodeId === null) {
            sidebar.classList.remove('active');
        }
    }

    switchLayout(layout) {
        this.currentLayout = layout;
        this.renderGraph();
    }

    exportPNG() {
        const canvas = document.querySelector('#graph-container canvas');
        if (canvas) {
            const link = document.createElement('a');
            link.download = 'aegis-intelligence-graph.png';
            link.href = canvas.toDataURL();
            link.click();
        }
    }

    renderGraph() {
        if (!this.graphInitialized) return;
        
        const container = document.getElementById('graph-container');
        if (!container) return;
        
        const data = this.getNetworkData();
        const options = this.getNetworkOptions();
        
        if (!window.network) {
            window.network = new vis.Network(container, data, options);
            this.attachEvents(window.network);
        } else {
            window.network.setData(data);
            window.network.setOptions(options);
        }
    }

    attachEvents(network) {
        network.on('click', (params) => {
            if (params.nodes.length > 0) {
                this.showNodeDetail(params.nodes[0]);
            } else {
                this.showNodeDetail(null);
            }
        });
    }

    getNetworkData() {
        return {
            nodes: this.filteredNodes.map(node => {
                const conf = node.confidence <= 1 ? Math.round(node.confidence * 100) : (node.confidence || 100);
                return {
                    id: node.id,
                    label: node.value.length > 25 ? node.value.substring(0, 22) + '...' : node.value,
                    title: this.getNodeTitle(node),
                    color: {
                        background: this.getNodeColor(node.type),
                        border: '#ffffff',
                        highlight: { background: this.getNodeColor(node.type), border: '#06b6d4' }
                    },
                    font: { color: '#f1f5f9', size: 12, face: 'Inter, sans-serif' },
                    size: Math.max(16, Math.min(36, 16 + (conf / 5))),
                    borderWidth: 2,
                    borderWidthSelected: 3,
                    value: node.value,
                    type: node.type,
                    confidence: conf,
                    first_seen: node.first_seen,
                    metadata: node.metadata
                };
            }),
            edges: this.filteredEdges.map(edge => {
                const conf = edge.confidence <= 1 ? Math.round(edge.confidence * 100) : (edge.confidence || 100);
                return {
                    from: edge.from,
                    to: edge.to,
                    label: edge.type,
                    arrows: 'to',
                    color: { color: '#334155', highlight: '#06b6d4', opacity: 0.8 },
                    font: { color: '#94a3b8', size: 10, strokeWidth: 0, face: 'JetBrains Mono, monospace' },
                    width: Math.max(1, (conf / 100) * 3),
                    title: `Relationship: ${edge.type}<br>Confidence: ${conf}%<br>Plugin: ${edge.source_plugin || 'system'}`
                };
            })
        };
    }

    getNodeTitle(node) {
        const conf = node.confidence <= 1 ? Math.round(node.confidence * 100) : (node.confidence || 100);
        return `<div style="background:#111827;color:#f1f5f9;padding:8px 12px;border-radius:6px;border:1px solid #334155;font-family:Inter,sans-serif;">` +
               `<strong>${node.value}</strong><br>` +
               `<span style="color:#06b6d4;font-size:11px;text-transform:uppercase;">Type: ${node.type}</span><br>` +
               `<span style="color:#10b981;font-size:11px;">Confidence: ${conf}%</span>` +
               (node.first_seen ? `<br><span style="color:#64748b;font-size:10px;">First Seen: ${node.first_seen}</span>` : '') +
               `</div>`;
    }

    getNetworkOptions() {
        const isHierarchical = this.currentLayout === 'hierarchical';
        const isCircular = this.currentLayout === 'circular';
        
        const options = {
            nodes: {
                shape: 'dot',
                shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 5, x: 2, y: 2 }
            },
            edges: {
                smooth: { type: 'cubicBezier', roundness: 0.2 }
            },
            physics: {
                enabled: !isHierarchical && !isCircular,
                solver: 'barnesHut',
                barnesHut: {
                    gravitationalConstant: -6000,
                    centralGravity: 0.3,
                    springLength: 120,
                    springConstant: 0.04,
                    damping: 0.09
                },
                stabilization: { iterations: 100 }
            },
            interaction: {
                hover: true,
                tooltipDelay: 150,
                navigationButtons: true,
                keyboard: true,
                multiselect: true
            },
            layout: {}
        };

        if (isHierarchical) {
            options.layout.hierarchical = {
                enabled: true,
                direction: 'UD',
                sortMethod: 'directed',
                levelSeparation: 180,
                nodeSpacing: 140,
                treeSpacing: 200
            };
            options.physics = { enabled: false };
        }

        if (isCircular) {
            options.physics = { enabled: false };
        }

        return options;
    }

    getNodeColor(type) {
        const colors = {
            domain: '#3b82f6',
            subdomain: '#60a5fa',
            email: '#10b981',
            github: '#8b5cf6',
            phone: '#f59e0b',
            leak: '#ef4444',
            company: '#06b6d4',
            ip: '#a855f7',
            person: '#ec4899',
            unknown: '#64748b'
        };
        return colors[type.toLowerCase()] || '#64748b';
    }
}
