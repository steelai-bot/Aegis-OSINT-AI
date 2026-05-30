#!/usr/bin/env python3
"""
au-osint-recon :: orchestrator.py
Main engine — coordinates all OSINT modules for Australian reconnaissance.
"""

import os
import sys
import json
import time
import argparse
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone

# Add scripts dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import logger, ResultStore, Finding, DataClassifier, ts_iso
from breach_search import BreachSearchEngine
from osint_australia import AustralianOSINT
from exploit_scanner import ExploitScanner
from darkweb_crawler import DarkWebCrawler
from telegram_monitor import TelegramMonitor
from paste_scraper import PasteScraper
from credential_parser import CredentialParser


class AUOSINTOrchestrator:
    """
    Master orchestrator for Australian OSINT reconnaissance.
    Coordinates all modules and produces unified reports.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.results = ResultStore()
        self.start_time = None
        self.end_time = None

        # Initialize modules
        self.breach_engine = BreachSearchEngine(self.config)
        self.au_osint = AustralianOSINT(self.config)
        self.exploit_scanner = ExploitScanner(self.config)
        self.darkweb = DarkWebCrawler(self.config)
        self.telegram = TelegramMonitor(self.config)
        self.paste_scraper = PasteScraper(self.config)
        self.cred_parser = CredentialParser()
        self.classifier = DataClassifier()

    def _merge_results(self, module_results: ResultStore) -> int:
        """Merge module results into main store."""
        return self.results.add_many(module_results.findings)

    # ── Scan Modes ───────────────────────────────────────────────────────

    def scan_email(self, email: str, modules: Optional[List[str]] = None) -> ResultStore:
        """Full scan on an email address."""
        active = modules or ['breach', 'paste', 'telegram', 'darkweb']
        domain = email.split('@')[1] if '@' in email else ''

        logger.info(f'═══ Email Scan: {email} ═══')
        logger.info(f'Active modules: {", ".join(active)}')

        if 'breach' in active:
            logger.info('━━━ BREACH SEARCH ━━━')
            breach_results = self.breach_engine.full_search(email)
            count = self._merge_results(breach_results)
            logger.info(f'  Merged: {count} new findings')

        if 'paste' in active:
            logger.info('━━━ PASTE SEARCH ━━━')
            paste_results = self.paste_scraper.full_search(email)
            count = self._merge_results(paste_results)
            logger.info(f'  Merged: {count} new findings')

        if 'osint' in active and domain:
            logger.info('━━━ AUSTRALIAN OSINT ━━━')
            osint_results = self.au_osint.full_recon(domain, 'domain')
            count = self._merge_results(osint_results)
            logger.info(f'  Merged: {count} new findings')

        if 'darkweb' in active:
            logger.info('━━━ DARK WEB SEARCH ━━━')
            dw_results = self.darkweb.full_search(email)
            count = self._merge_results(dw_results)
            logger.info(f'  Merged: {count} new findings')

        if 'telegram' in active:
            logger.info('━━━ TELEGRAM MONITORING ━━━')
            tg_results = self.telegram.full_search(email)
            count = self._merge_results(tg_results)
            logger.info(f'  Merged: {count} new findings')

        return self.results

    def scan_domain(self, domain: str, modules: Optional[List[str]] = None) -> ResultStore:
        """Full scan on a domain."""
        active = modules or ['breach', 'osint', 'paste', 'exploit', 'darkweb', 'telegram']

        logger.info(f'═══ Domain Scan: {domain} ═══')
        logger.info(f'Active modules: {", ".join(active)}')

        if 'osint' in active:
            logger.info('━━━ AUSTRALIAN OSINT ━━━')
            osint_results = self.au_osint.full_recon(domain, 'domain')
            count = self._merge_results(osint_results)
            logger.info(f'  Merged: {count} new findings')

        if 'breach' in active:
            logger.info('━━━ BREACH SEARCH ━━━')
            breach_results = self.breach_engine.full_search(domain, 'domain')
            count = self._merge_results(breach_results)
            logger.info(f'  Merged: {count} new findings')

        if 'paste' in active:
            logger.info('━━━ PASTE SEARCH ━━━')
            paste_results = self.paste_scraper.full_search(domain)
            count = self._merge_results(paste_results)
            logger.info(f'  Merged: {count} new findings')

        if 'exploit' in active:
            logger.info('━━━ EXPLOIT SCANNING ━━━')
            url = f'https://{domain}' if not domain.startswith('http') else domain
            exploit_results = self.exploit_scanner.full_scan(url)
            count = self._merge_results(exploit_results)
            logger.info(f'  Merged: {count} new findings')

        if 'darkweb' in active:
            logger.info('━━━ DARK WEB SEARCH ━━━')
            dw_results = self.darkweb.full_search(domain)
            count = self._merge_results(dw_results)
            logger.info(f'  Merged: {count} new findings')

        if 'telegram' in active:
            logger.info('━━━ TELEGRAM MONITORING ━━━')
            tg_results = self.telegram.full_search(domain)
            count = self._merge_results(tg_results)
            logger.info(f'  Merged: {count} new findings')

        return self.results

    def scan_company(self, company: str, modules: Optional[List[str]] = None) -> ResultStore:
        """Full scan on an Australian company."""
        active = modules or ['osint', 'breach', 'darkweb', 'paste', 'telegram']

        logger.info(f'═══ Company Scan: {company} ═══')
        logger.info(f'Active modules: {", ".join(active)}')

        if 'osint' in active:
            logger.info('━━━ AUSTRALIAN OSINT (Company) ━━━')
            osint_results = self.au_osint.full_recon(company, 'company')
            count = self._merge_results(osint_results)
            logger.info(f'  Merged: {count} new findings')

        if 'breach' in active:
            logger.info('━━━ BREACH SEARCH ━━━')
            breach_results = self.breach_engine.full_search(company, 'domain')
            count = self._merge_results(breach_results)
            logger.info(f'  Merged: {count} new findings')

            # Generate google dorks
            dorks = self.breach_engine.generate_google_dorks(company)
            self.results.add(Finding(
                source='GoogleDorks',
                category='search_queries',
                data={'target': company, 'dorks': dorks},
                confidence=1.0,
            ))

        if 'darkweb' in active:
            logger.info('━━━ DARK WEB SEARCH ━━━')
            dw_results = self.darkweb.full_search(company)
            count = self._merge_results(dw_results)
            logger.info(f'  Merged: {count} new findings')

        if 'paste' in active:
            logger.info('━━━ PASTE SEARCH ━━━')
            paste_results = self.paste_scraper.full_search(company)
            count = self._merge_results(paste_results)
            logger.info(f'  Merged: {count} new findings')

        if 'telegram' in active:
            logger.info('━━━ TELEGRAM MONITORING ━━━')
            tg_results = self.telegram.full_search(company)
            count = self._merge_results(tg_results)
            logger.info(f'  Merged: {count} new findings')

        return self.results

    def scan_url(self, url: str, modules: Optional[List[str]] = None) -> ResultStore:
        """Exploit scan on a URL."""
        active = modules or ['exploit', 'osint']

        logger.info(f'═══ URL Scan: {url} ═══')

        if 'exploit' in active:
            logger.info('━━━ EXPLOIT SCANNING ━━━')
            exploit_results = self.exploit_scanner.full_scan(url)
            count = self._merge_results(exploit_results)
            logger.info(f'  Merged: {count} new findings')

        if 'osint' in active:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            if domain:
                osint_results = self.au_osint.full_recon(domain, 'domain')
                count = self._merge_results(osint_results)

        return self.results

    def scan_phone(self, phone: str, modules: Optional[List[str]] = None) -> ResultStore:
        """Scan Australian phone number."""
        active = modules or ['osint', 'breach', 'telegram']

        logger.info(f'═══ Phone Scan: {phone} ═══')

        if 'osint' in active:
            logger.info('━━━ PHONE OSINT ━━━')
            osint_results = self.au_osint.full_recon(phone, 'phone')
            count = self._merge_results(osint_results)

        if 'breach' in active:
            logger.info('━━━ BREACH SEARCH ━━━')
            breach_results = self.breach_engine.full_search(phone, 'phone')
            count = self._merge_results(breach_results)

        if 'telegram' in active:
            logger.info('━━━ TELEGRAM ━━━')
            tg_results = self.telegram.full_search(phone)
            count = self._merge_results(tg_results)

        return self.results

    def scan_abn(self, abn: str) -> ResultStore:
        """Scan Australian Business Number."""
        logger.info(f'═══ ABN Scan: {abn} ═══')

        osint_results = self.au_osint.full_recon(abn, 'abn')
        self._merge_results(osint_results)

        return self.results

    # ── Full Recon ───────────────────────────────────────────────────────

    def full_recon(self, target: str, target_type: str = 'auto',
                   modules: Optional[List[str]] = None) -> ResultStore:
        """Auto-detect target type and run full reconnaissance."""
        self.start_time = time.time()

        import re
        # Auto-detect
        if target_type == 'auto':
            if '@' in target:
                target_type = 'email'
            elif target.startswith('http'):
                target_type = 'url'
            elif re.match(r'[\d\s\-+]+$', target) and len(target.replace(' ', '').replace('-', '').replace('+', '')) >= 8:
                target_type = 'phone'
            elif re.match(r'\d{11}$', target.replace(' ', '').replace('-', '')):
                target_type = 'abn'
            elif '.' in target and any(target.endswith(d) for d in ['.au', '.com', '.org', '.net', '.io']):
                target_type = 'domain'
            else:
                target_type = 'company'

        logger.info(f'Target type detected: {target_type}')

        if target_type == 'email':
            self.scan_email(target, modules)
        elif target_type == 'domain':
            self.scan_domain(target, modules)
        elif target_type == 'url':
            self.scan_url(target, modules)
        elif target_type == 'company':
            self.scan_company(target, modules)
        elif target_type == 'phone':
            self.scan_phone(target, modules)
        elif target_type == 'abn':
            self.scan_abn(target)

        self.end_time = time.time()
        elapsed = self.end_time - self.start_time

        logger.info(f'═══ SCAN COMPLETE ═══')
        logger.info(f'Target: {target} ({target_type})')
        logger.info(f'Duration: {elapsed:.1f}s')
        logger.info(f'Total findings: {len(self.results)}')

        summary = self.results.summary()
        logger.info(f'By category: {json.dumps(summary["by_category"], indent=2)}')
        logger.info(f'By source: {json.dumps(summary["by_source"], indent=2)}')

        return self.results

    # ── Report Generation ────────────────────────────────────────────────

    def generate_report(self, output_dir: str = '.', format: str = 'all') -> Dict[str, str]:
        """Generate reports in multiple formats."""
        os.makedirs(output_dir, exist_ok=True)
        files = {}

        elapsed = (self.end_time - self.start_time) if self.start_time and self.end_time else 0

        if format in ('json', 'all'):
            json_path = os.path.join(output_dir, 'au_osint_report.json')
            report = {
                'metadata': {
                    'generated_at': ts_iso(),
                    'duration_seconds': round(elapsed, 1),
                    'total_findings': len(self.results),
                },
                'summary': self.results.summary(),
                'findings': [f.to_dict() for f in self.results.findings],
            }
            with open(json_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            files['json'] = json_path

        if format in ('csv', 'all'):
            import csv as csv_mod
            csv_path = os.path.join(output_dir, 'au_osint_report.csv')
            with open(csv_path, 'w', newline='') as f:
                writer = csv_mod.writer(f)
                writer.writerow(['Source', 'Category', 'Confidence', 'Timestamp', 'Data'])
                for finding in self.results.findings:
                    writer.writerow([
                        finding.source,
                        finding.category,
                        f'{finding.confidence:.0%}',
                        finding.timestamp,
                        json.dumps(finding.data, default=str)[:500],
                    ])
            files['csv'] = csv_path

        if format in ('html', 'all'):
            html_path = os.path.join(output_dir, 'au_osint_report.html')
            files['html'] = html_path
            self._generate_html_report(html_path, elapsed)

        logger.info(f'Reports generated: {", ".join(f"{k}: {v}" for k, v in files.items())}')
        return files

    def _generate_html_report(self, filepath: str, elapsed: float) -> None:
        """Generate interactive HTML dashboard report."""
        summary = self.results.summary()
        findings_json = json.dumps([f.to_dict() for f in self.results.findings], default=str)

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AU-OSINT-RECON Report</title>
<style>
:root {{
    --bg: #0a0a0f;
    --surface: #12121a;
    --surface2: #1a1a25;
    --accent: #00ff88;
    --accent2: #00ccff;
    --danger: #ff4444;
    --warning: #ffaa00;
    --text: #e0e0e0;
    --text2: #888;
    --border: #2a2a35;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text); font-family:'Courier New',monospace; padding:20px; }}
.header {{ text-align:center; padding:30px 0; border-bottom:1px solid var(--accent); margin-bottom:30px; }}
.header h1 {{ color:var(--accent); font-size:2em; letter-spacing:3px; }}
.header .subtitle {{ color:var(--text2); margin-top:10px; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:15px; margin-bottom:30px; }}
.stat {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:20px; text-align:center; }}
.stat .value {{ font-size:2.5em; color:var(--accent); font-weight:bold; }}
.stat .label {{ color:var(--text2); margin-top:5px; font-size:0.9em; }}
.section {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:20px; margin-bottom:20px; }}
.section h2 {{ color:var(--accent2); margin-bottom:15px; font-size:1.3em; border-bottom:1px solid var(--border); padding-bottom:10px; }}
.finding {{ background:var(--surface2); border-left:3px solid var(--accent); padding:12px 15px; margin-bottom:10px; border-radius:0 5px 5px 0; }}
.finding .meta {{ display:flex; justify-content:space-between; margin-bottom:8px; }}
.finding .source {{ color:var(--accent); font-weight:bold; }}
.finding .category {{ color:var(--accent2); background:rgba(0,204,255,0.1); padding:2px 8px; border-radius:3px; }}
.finding .confidence {{ color:var(--warning); }}
.finding .data {{ color:var(--text2); font-size:0.85em; word-break:break-all; }}
.filters {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:20px; }}
.filters select, .filters input {{ background:var(--surface2); color:var(--text); border:1px solid var(--border); padding:8px 12px; border-radius:5px; font-family:inherit; }}
.severity-critical {{ border-left-color:var(--danger) !important; }}
.severity-high {{ border-left-color:var(--warning) !important; }}
.severity-medium {{ border-left-color:var(--accent2) !important; }}
.severity-low {{ border-left-color:var(--text2) !important; }}
.chart {{ display:flex; gap:5px; align-items:flex-end; height:150px; padding:10px 0; }}
.bar {{ background:var(--accent); min-width:30px; border-radius:3px 3px 0 0; position:relative; cursor:pointer; transition:opacity 0.2s; }}
.bar:hover {{ opacity:0.8; }}
.bar .tooltip {{ display:none; position:absolute; bottom:100%; left:50%; transform:translateX(-50%); background:var(--surface2); padding:5px 10px; border-radius:3px; white-space:nowrap; font-size:0.8em; }}
.bar:hover .tooltip {{ display:block; }}
table {{ width:100%; border-collapse:collapse; }}
th, td {{ padding:8px 12px; text-align:left; border-bottom:1px solid var(--border); }}
th {{ color:var(--accent); }}
tr:hover {{ background:var(--surface2); }}
.export-btn {{ background:var(--accent); color:var(--bg); border:none; padding:10px 20px; border-radius:5px; cursor:pointer; font-family:inherit; font-weight:bold; margin:5px; }}
.export-btn:hover {{ opacity:0.8; }}
.hidden {{ display:none; }}
</style>
</head>
<body>
<div class="header">
    <h1>🛡️ AU-OSINT-RECON</h1>
    <div class="subtitle">Australian Breach Intelligence Report</div>
    <div class="subtitle">Generated: {ts_iso()} | Duration: {elapsed:.1f}s</div>
</div>

<div class="stats">
    <div class="stat"><div class="value">{summary['total_findings']}</div><div class="label">Total Findings</div></div>
    <div class="stat"><div class="value">{len(summary.get('by_source', {}))}</div><div class="label">Data Sources</div></div>
    <div class="stat"><div class="value">{len(summary.get('by_category', {}))}</div><div class="label">Categories</div></div>
    <div class="stat"><div class="value">{elapsed:.1f}s</div><div class="label">Scan Duration</div></div>
</div>

<div class="section">
    <h2>📊 Findings by Category</h2>
    <div class="chart" id="categoryChart"></div>
</div>

<div class="section">
    <h2>📡 Findings by Source</h2>
    <div class="chart" id="sourceChart"></div>
</div>

<div class="section">
    <h2>🔍 Detailed Findings</h2>
    <div class="filters">
        <select id="filterSource"><option value="">All Sources</option></select>
        <select id="filterCategory"><option value="">All Categories</option></select>
        <select id="filterConfidence">
            <option value="0">All Confidence</option>
            <option value="0.9">90%+</option>
            <option value="0.7">70%+</option>
            <option value="0.5">50%+</option>
        </select>
        <input type="text" id="filterText" placeholder="Search findings...">
    </div>
    <div id="findingsList"></div>
</div>

<div class="section">
    <h2>📥 Export</h2>
    <button class="export-btn" onclick="exportJSON()">Export JSON</button>
    <button class="export-btn" onclick="exportCSV()">Export CSV</button>
</div>

<script>
const findings = {findings_json};
const summary = {json.dumps(summary, default=str)};

// Build charts
function buildChart(containerId, data) {{
    const container = document.getElementById(containerId);
    const max = Math.max(...Object.values(data));
    Object.entries(data).sort((a,b) => b[1]-a[1]).forEach(([key, val]) => {{
        const bar = document.createElement('div');
        bar.className = 'bar';
        bar.style.height = (val/max*100) + '%';
        bar.style.flex = '1';
        bar.innerHTML = `<span class="tooltip">${{key}}: ${{val}}</span>`;
        container.appendChild(bar);
    }});
}}
buildChart('categoryChart', summary.by_category || {{}});
buildChart('sourceChart', summary.by_source || {{}});

// Populate filters
const sources = [...new Set(findings.map(f => f.source))];
const categories = [...new Set(findings.map(f => f.category))];
sources.forEach(s => document.getElementById('filterSource').innerHTML += `<option value="${{s}}">${{s}}</option>`);
categories.forEach(c => document.getElementById('filterCategory').innerHTML += `<option value="${{c}}">${{c}}</option>`);

// Render findings
function renderFindings() {{
    const src = document.getElementById('filterSource').value;
    const cat = document.getElementById('filterCategory').value;
    const conf = parseFloat(document.getElementById('filterConfidence').value);
    const text = document.getElementById('filterText').value.toLowerCase();

    const filtered = findings.filter(f => {{
        if (src && f.source !== src) return false;
        if (cat && f.category !== cat) return false;
        if (f.confidence < conf) return false;
        if (text && !JSON.stringify(f).toLowerCase().includes(text)) return false;
        return true;
    }});

    const list = document.getElementById('findingsList');
    list.innerHTML = `<div style="color:var(--text2);margin-bottom:10px">Showing ${{filtered.length}} of ${{findings.length}} findings</div>`;

    filtered.slice(0, 200).forEach(f => {{
        const severity = f.data?.severity || (f.confidence >= 0.9 ? 'critical' : f.confidence >= 0.7 ? 'high' : f.confidence >= 0.5 ? 'medium' : 'low');
        const div = document.createElement('div');
        div.className = `finding severity-${{severity.toLowerCase()}}`;
        div.innerHTML = `
            <div class="meta">
                <span class="source">${{f.source}}</span>
                <span class="category">${{f.category}}</span>
                <span class="confidence">${{(f.confidence*100).toFixed(0)}}%</span>
            </div>
            <div class="data">${{JSON.stringify(f.data, null, 2).substring(0, 500)}}</div>
        `;
        list.appendChild(div);
    }});
}}
renderFindings();

document.getElementById('filterSource').onchange = renderFindings;
document.getElementById('filterCategory').onchange = renderFindings;
document.getElementById('filterConfidence').onchange = renderFindings;
document.getElementById('filterText').oninput = renderFindings;

function exportJSON() {{
    const blob = new Blob([JSON.stringify(findings, null, 2)], {{type: 'application/json'}});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'au_osint_findings.json';
    a.click();
}}

function exportCSV() {{
    let csv = 'Source,Category,Confidence,Timestamp,Data\\n';
    findings.forEach(f => {{
        csv += `"${{f.source}}","${{f.category}}",${{f.confidence}},"${{f.timestamp}}","${{JSON.stringify(f.data).replace(/"/g, '""').substring(0, 500)}}"\\n`;
    }});
    const blob = new Blob([csv], {{type: 'text/csv'}});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'au_osint_findings.csv';
    a.click();
}}
</script>
</body>
</html>'''
        with open(filepath, 'w') as f:
            f.write(html)


def main():
    parser = argparse.ArgumentParser(
        description='AU-OSINT-RECON — Australian OSINT Reconnaissance Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python orchestrator.py --target user@example.com.au --modules all
  python orchestrator.py --target example.com.au --modules osint,breach,exploit
  python orchestrator.py --company "Acme Corp" --country AU --modules osint,breach
  python orchestrator.py --url https://target.com.au --modules exploit
  python orchestrator.py --phone "+61412345678" --modules osint,breach
  python orchestrator.py --abn "12345678901" --modules osint
        ''',
    )
    parser.add_argument('--target', '-t', help='Target (email, domain, company, phone, IP)')
    parser.add_argument('--email', '-e', help='Target email')
    parser.add_argument('--domain', '-d', help='Target domain')
    parser.add_argument('--company', help='Target company name')
    parser.add_argument('--url', '-u', help='Target URL (for exploit scanning)')
    parser.add_argument('--phone', help='Target phone number')
    parser.add_argument('--abn', help='Australian Business Number')
    parser.add_argument('--modules', '-m', default='all',
                       help='Comma-separated modules: breach,osint,exploit,darkweb,telegram,paste,all')
    parser.add_argument('--output', '-o', default='./au_osint_output',
                       help='Output directory')
    parser.add_argument('--format', '-f', default='all',
                       choices=['json', 'csv', 'html', 'all'])
    parser.add_argument('--config', '-c', help='JSON config file with API keys')

    args = parser.parse_args()

    # Load config
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config) as f:
            config = json.load(f)

    # Parse modules
    modules = None if args.modules == 'all' else args.modules.split(',')

    # Initialize
    orch = AUOSINTOrchestrator(config)

    # Determine target
    if args.email:
        orch.full_recon(args.email, 'email', modules)
    elif args.domain:
        orch.full_recon(args.domain, 'domain', modules)
    elif args.company:
        orch.full_recon(args.company, 'company', modules)
    elif args.url:
        orch.full_recon(args.url, 'url', modules)
    elif args.phone:
        orch.full_recon(args.phone, 'phone', modules)
    elif args.abn:
        orch.full_recon(args.abn, 'abn', modules)
    elif args.target:
        orch.full_recon(args.target, 'auto', modules)
    else:
        parser.error('No target specified. Use --target, --email, --domain, --company, --url, --phone, or --abn')

    # Generate reports
    reports = orch.generate_report(args.output, args.format)
    print(f'\n═══ Reports generated ═══')
    for fmt, path in reports.items():
        print(f'  {fmt}: {path}')


if __name__ == '__main__':
    main()
