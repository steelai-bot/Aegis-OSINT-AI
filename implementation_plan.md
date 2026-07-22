# Implementation Plan

[Overview]
Improve the entity graph visualization on the investigation results page with better node grouping, filtering, search, and interactive features.

The current graph visualization in `backend/templates/results.html` uses vis-network to render a basic dot-and-line graph of entities and relationships. While functional, it lacks essential OSINT investigation features: there is no way to filter entities by type, no grouping of related nodes, no search/highlight capability, no node detail panel, no legend, and no statistics. The graph colors are hardcoded in a small JavaScript function and the node rendering is minimal (plain dots with text labels). This plan enhances the graph into a full-featured investigation visualization tool by adding a control panel with type-based filtering and grouping, a search bar with highlight, a clickable node detail sidebar, a legend, graph statistics, layout controls, and improved node styling with icons and size scaling. The backend needs a minor enhancement to return richer node data (display_name, metadata) for the detail panel.

[Types]
No new Pydantic models are needed; the existing Entity, Relationship, EntityType, and RelationshipType models already provide all required data.

The graph-data API endpoint currently returns a simplified JSON structure:
```json
{
  "nodes": [{"id": int, "value": str, "type": str}],
  "edges": [{"from": int, "to": int, "type": str}]
}
```

This will be enhanced to return richer node data:
```json
{
  "nodes": [
    {
      "id": int,
      "value": str,
      "type": str,
      "display_name": str | null,
      "confidence": float,
      "first_seen": str,
      "metadata": dict
    }
  ],
  "edges": [
    {
      "from": int,
      "to": int,
      "type": str,
      "confidence": float,
      "source_plugin": str
    }
  ],
  "stats": {
    "total_nodes": int,
    "total_edges": int,
    "types_breakdown": dict[str, int]
  }
}
```

No new enums or type definitions are required. The existing `EntityType` and `RelationshipType` enums already cover all needed type classifications.

[Files]
The implementation requires modifications to 4 existing files and creation of 1 new file.

**Modified files:**

1. `backend/main.py` - Modify the `/api/targets/{target_id}/graph-data` endpoint (line ~710-720) to return enriched node/edge data with metadata, confidence scores, and aggregated statistics.

2. `backend/templates/results.html` - Major overhaul of the Graph Tab section (lines ~84-96) and the graph JavaScript (lines ~100-156). Replace the minimal graph div with a full layout containing a control panel (filters, search, layout options), the graph canvas, a node detail sidebar, a legend, and statistics bar. Replace the basic `renderGraph()` function with a comprehensive graph manager.

3. `backend/static/css/components.css` - Add new CSS classes for the graph control panel, filter checkboxes, node detail sidebar, legend, search highlight, and statistics bar.

4. `backend/templates/components/investigation_result.html` - Read to check if any changes needed for graph integration (likely no changes needed, this is the search result partial).

**New files:**

5. `backend/static/js/graph.js` - New dedicated JavaScript module containing the `GraphManager` class with methods for rendering, filtering, grouping, searching, layout switching, node detail display, and export functionality.

[Functions]
The implementation adds new JavaScript functions/methods and modifies one Python endpoint function.

**New functions (in `backend/static/js/graph.js`):**

- `GraphManager` class constructor: `constructor(containerId, detailPanelId, options)` - Initializes the graph manager with vis-network instance, filter state, and event handlers.
- `GraphManager.loadData(jsonData)` - Parses enriched graph JSON, builds internal data structures, calculates node sizes based on connection count, assigns colors/icons by entity type, and renders the initial graph.
- `GraphManager.applyFilters()` - Reads the current filter checkbox state, filters the vis-network DataSet to show/hide nodes by entity type, and updates connected edges accordingly.
- `GraphManager.toggleGroup(entityType)` - Toggles clustering of nodes by entity type using vis-network's clustering API. When grouped, all nodes of that type collapse into a single cluster node showing the count.
- `GraphManager.search(query)` - Searches node labels/values for the query string, highlights matching nodes (increases size, adds glow border), dims non-matching nodes, and centers the view on matches.
- `GraphManager.clearSearch()` - Resets all nodes to their default visual state after a search.
- `GraphManager.showNodeDetail(nodeId)` - Populates the detail sidebar with the selected node's full information: type, value, display_name, confidence, first_seen, metadata, and connected edges.
- `GraphManager.hideNodeDetail()` - Closes/hides the detail sidebar panel.
- `GraphManager.switchLayout(layoutType)` - Switches between physics layouts: 'force' (barnesHut), 'hierarchical' (top-down), and 'circular' (custom positioning).
- `GraphManager.exportPNG()` - Exports the current graph view as a PNG image using the vis-network canvas.
- `GraphManager.getStats()` - Returns computed statistics object with node counts by type, edge counts by type, and density metrics.
- `GraphManager._getNodeColor(type)` - Returns the color configuration for a given entity type.
- `GraphManager._getNodeIcon(type)` - Returns the Lucide icon name for a given entity type.
- `GraphManager._calculateNodeSize(nodeId)` - Calculates node size based on number of connections (degree centrality).
- `GraphManager._buildLegend()` - Generates the legend HTML based on entity types present in the current data.
- `GraphManager._updateStats()` - Updates the statistics bar with current counts.
- `initGraphFromHTMX(response)` - Standalone function called from the HTMX afterRequest handler to initialize the GraphManager with the API response data.

**Modified functions:**

- `graph_data(target_id: int)` in `backend/main.py` (line ~710): Currently returns minimal node/edge data. Will be modified to return enriched data including display_name, confidence, first_seen, metadata for nodes; confidence and source_plugin for edges; and an aggregated stats object.

[Classes]
One new JavaScript class is introduced; no Python classes are modified.

**New classes:**

- `GraphManager` in `backend/static/js/graph.js`:
  - Purpose: Encapsulates all graph visualization logic, state management, and user interaction handling.
  - Key properties: `network` (vis.Network instance), `nodesDataSet` (vis.DataSet), `edgesDataSet` (vis.DataSet), `rawData` (original API data), `filters` (dict of entity type to boolean), `selectedNode` (currently selected node ID or null), `currentLayout` (string: 'force'|'hierarchical'|'circular').
  - Key methods: `loadData()`, `applyFilters()`, `toggleGroup()`, `search()`, `showNodeDetail()`, `switchLayout()`, `exportPNG()`, `getStats()`.
  - No inheritance. Standalone class instantiated in the results page.

**No Python classes are added or modified.**

[Dependencies]
No new Python or JavaScript dependencies are required.

The existing vis-network library (loaded from CDN at `https://unpkg.com/vis-network@9.1.9/dist/vis-network.min.js`) already supports all needed features: clustering, physics layouts, canvas export, DataSet filtering, and event handling. The existing Lucide icons library is used for entity type icons in the legend and detail panel. Alpine.js handles reactive UI state for the control panel. HTMX handles the data loading trigger. No additional npm packages, Python packages, or CDN scripts need to be added.

[Testing]
The graph visualization changes are primarily frontend (HTML/CSS/JS) so manual browser testing is the primary validation strategy.

**Manual test scenarios:**
1. Navigate to `/results/{target_id}` and click the Graph tab - verify the enhanced graph renders with proper node colors, sizes, and the control panel appears.
2. Test type filter checkboxes - uncheck "email" type, verify email nodes and their edges disappear; re-check, verify they reappear.
3. Test search - type a partial entity value in the search box, verify matching nodes are highlighted and non-matching are dimmed.
4. Test node click - click a node, verify the detail sidebar opens showing full entity information.
5. Test layout switching - switch between Force, Hierarchical, and Circular layouts, verify the graph re-renders appropriately.
6. Test grouping - click a "Group" button for a type, verify nodes of that type collapse into a cluster node.
7. Test export - click Export PNG, verify a PNG file downloads.
8. Test with no data - verify the graph shows a "No entities discovered" message when there are no nodes.

**Existing test modifications:**
- `tests/test_api.py` - No modifications needed; the graph-data endpoint test (if it exists) should still pass as the response is a superset of the original.

**No new automated test files are required** since graph rendering is purely client-side. The backend endpoint change is backward-compatible (adds fields, doesn't remove any).

[Implementation Order]
The implementation should proceed in this sequence to minimize conflicts and ensure each step can be independently verified.

1. **Modify the graph-data API endpoint** (`backend/main.py`): Enhance the `/api/targets/{target_id}/graph-data` endpoint to return enriched node data (display_name, confidence, first_seen, metadata), enriched edge data (confidence, source_plugin), and aggregated statistics. This is a backward-compatible change.

2. **Create the GraphManager JavaScript module** (`backend/static/js/graph.js`): Implement the full `GraphManager` class with all methods: loadData, applyFilters, toggleGroup, search, clearSearch, showNodeDetail, hideNodeDetail, switchLayout, exportPNG, getStats, and helper methods. Include the `initGraphFromHTMX` standalone function.

3. **Add graph-specific CSS styles** (`backend/static/css/components.css`): Append new CSS classes for the graph control panel layout, filter checkboxes with colored indicators, node detail sidebar (slide-in panel), legend component, search input with highlight state, statistics bar, and layout toggle buttons.

4. **Overhaul the results.html Graph Tab** (`backend/templates/results.html`): Replace the minimal graph div and inline JavaScript with the full layout: control panel (search bar, type filter checkboxes, layout selector, group/export buttons), resizable graph canvas container, node detail sidebar panel, legend component, and statistics summary bar. Load the new `graph.js` module. Wire up HTMX data loading to the `initGraphFromHTMX` function.

5. **Verify and test**: Run the application, create an investigation, navigate to results, test all graph features (filtering, searching, clicking nodes, switching layouts, grouping, exporting).
