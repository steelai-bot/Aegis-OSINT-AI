"""au-osint-recon :: eni_signature.py
ENI's signature modules: Stealer Log Stream, Honey Account Generator,
Cred Stuff Reverse Engine, Passive WiFi BSSID Geo, AI Severity Re-Scorer,
Tarpit Detection, Breach Wave Predictor (handled in ai_modules.py).
"""
import os, re, json, time, hashlib, random, string
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone, timedelta

try:
    import requests
except ImportError:
    requests = None

from utils import logger, safe_request, Finding, ResultStore, DataClassifier


STEALER_KEYWORDS = ["stealer log", "redline log", "raccoon log", "vidar log",
                    "aurora stealer", "mars stealer", "meta stealer", "stealc log",
                    "risepro log", "cloud of logs", "fresh log", "private log",
                    "browser cookies", "autofill", "wallet seeds"]

AU_TARGETS_FOR_STEALER = [".com.au", ".gov.au", ".edu.au", "commbank", "westpac",
                          "anz.com", "nab.com.au", "optus.com.au", "telstra.com.au",
                          "medibank.com.au", "mygov.au", "ato.gov.au", "centrelink"]


class StealerLogStream:
    """Real-time pipeline for monitoring stealer log dumps in Telegram/forums."""

    def __init__(self, config=None):
        self.config = config or {}
        self.alert_keywords = []
        self.seen_hashes = set()

    def configure_alerts(self, keywords):
        self.alert_keywords = [k.lower() for k in keywords]

    def parse_redline_log(self, log_text):
        """Parse Redline stealer log format."""
        result = {
            "stealer_family": "Redline",
            "victim_data": {},
            "passwords": [],
            "cookies": [],
            "autofill": [],
            "credit_cards": [],
            "wallets": [],
            "system_info": {},
        }
        lines = log_text.splitlines()
        section = None
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("ip:"):
                result["system_info"]["ip"] = line.split(":",1)[1].strip()
            elif line.lower().startswith("hwid:"):
                result["system_info"]["hwid"] = line.split(":",1)[1].strip()
            elif line.lower().startswith("country:"):
                result["system_info"]["country"] = line.split(":",1)[1].strip()
            elif line.lower().startswith("os:"):
                result["system_info"]["os"] = line.split(":",1)[1].strip()
            elif "url:" in line.lower() and "password:" in line.lower():
                m = re.search(r"url:\s*(\S+).*login:\s*(\S+).*password:\s*(\S+)", line, re.IGNORECASE)
                if m:
                    result["passwords"].append({
                        "url": m.group(1),
                        "login": m.group(2),
                        "password": m.group(3),
                    })
        return result

    def stream_check(self, channels=None, forums=None):
        """Check configured channels/forums for new stealer log drops."""
        findings = []
        api_id = os.getenv("TELEGRAM_API_ID","")
        api_hash = os.getenv("TELEGRAM_API_HASH","")
        if api_id and api_hash:
            try:
                from telethon.sync import TelegramClient
                with TelegramClient("au_osint_stream", int(api_id), api_hash) as client:
                    for ch in (channels or []):
                        try:
                            messages = client.iter_messages(ch, limit=20)
                            for msg in messages:
                                if msg.file and msg.file.name:
                                    fname = msg.file.name.lower()
                                    is_stealer = any(kw in fname for kw in ["log","cookies","passwords","credentials","redline","raccoon","vidar"])
                                    text = (msg.message or "").lower()
                                    has_au = any(t in text for t in AU_TARGETS_FOR_STEALER)
                                    if is_stealer:
                                        findings.append(Finding(
                                            source="StealerLogStream",
                                            category="stealer_log_drop",
                                            data={
                                                "channel": ch,
                                                "file_name": msg.file.name,
                                                "file_size": msg.file.size,
                                                "date": str(msg.date),
                                                "message_preview": (msg.message or "")[:200],
                                                "has_au_keywords": has_au,
                                                "severity": "CRITICAL" if has_au else "HIGH",
                                            },
                                            confidence=0.9 if has_au else 0.6,
                                        ))
                        except Exception as e:
                            logger.warning(f"Channel {ch}: {e}")
            except ImportError:
                findings.append(Finding(
                    source="StealerLogStream", category="dependency_missing",
                    data={"message":"pip install telethon for live streaming"},
                    confidence=0.5,
                ))
        return findings


class HoneyAccountGenerator:
    """Generate fake AU personas as bait for tracking attackers."""

    def __init__(self, config=None):
        self.config = config or {}

    def generate_persona(self, count=1):
        first_names = ["James","Oliver","William","Jack","Noah","Charlotte","Olivia","Amelia","Isla","Mia"]
        last_names = ["Smith","Jones","Williams","Brown","Taylor","Wilson","Martin","Anderson","Thompson","Nguyen"]
        suburbs = ["Bondi","Surry Hills","Carlton","Fitzroy","South Yarra","Glebe","Newtown","St Kilda","Paddington","Manly"]
        states = [("NSW","2"),("VIC","3"),("QLD","4"),("WA","6"),("SA","5"),("TAS","7"),("NT","8"),("ACT","2")]

        personas = []
        for _ in range(count):
            first = random.choice(first_names)
            last = random.choice(last_names)
            suburb = random.choice(suburbs)
            state, sd = random.choice(states)
            year = random.randint(1970, 2000)
            number = random.randint(1, 999)
            street_types = ["St","Rd","Ave","Cres","Pde","Ct","Pl"]
            street_names = ["King","Queen","George","Park","Beach","Church","Bridge","Mountain","River","Forest"]

            persona = {
                "first_name": first,
                "last_name": last,
                "email": f"{first.lower()}.{last.lower()}{random.randint(10,99)}@gmail.com",
                "phone": f"+614{random.randint(10,99)}{random.randint(100,999)}{random.randint(100,999)}",
                "dob": f"{random.randint(1,28):02d}/{random.randint(1,12):02d}/{year}",
                "address": f"{number} {random.choice(street_names)} {random.choice(street_types)}, {suburb} {state} {sd}{random.randint(100,999)}",
                "occupation": random.choice(["Software Engineer","Accountant","Teacher","Nurse","Marketing Manager","Designer","Tradesperson"]),
                "honey_id": hashlib.sha256(f"{first}{last}{time.time()}".encode()).hexdigest()[:16],
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            personas.append(persona)

        return personas

    def generate_decoy_breach_entry(self, persona):
        """Create a fake breach entry to plant in dark web for tracking."""
        password = self._generate_realistic_password(persona)
        return {
            "email": persona["email"],
            "username": f"{persona['first_name'].lower()}{persona['last_name'].lower()}",
            "password": password,
            "honey_id": persona["honey_id"],
            "tracker_payload": "Place this on monitored honey infrastructure to track who uses it",
        }

    def _generate_realistic_password(self, persona):
        """Generate a plausible password using persona data."""
        base_options = [
            persona["first_name"], persona["last_name"],
            persona["address"].split()[1],
        ]
        base = random.choice(base_options)
        year = persona["dob"].split("/")[-1]
        suffix = random.choice([year, year[-2:], "123", "!", "@", year+"!"])
        return f"{base}{suffix}"


class CredStuffReverse:
    """Reverse engineering of credential stuffing campaigns."""

    def __init__(self, config=None):
        self.config = config or {}

    def detect_campaign(self, auth_log_entries):
        """Analyze auth logs to identify ongoing cred stuffing patterns."""
        if not auth_log_entries:
            return []
        findings = []
        ips_seen = {}
        passwords_tried = {}
        emails_targeted = {}
        for entry in auth_log_entries:
            ip = entry.get("ip","")
            email = entry.get("email","")
            password = entry.get("password","")
            success = entry.get("success", False)
            ts = entry.get("timestamp","")
            if ip:
                ips_seen.setdefault(ip, []).append(entry)
            if password:
                passwords_tried.setdefault(password, []).append(entry)
            if email:
                emails_targeted.setdefault(email, []).append(entry)

        for ip, entries in ips_seen.items():
            if len(entries) > 20:
                unique_users = len(set(e.get("email","") for e in entries))
                success_rate = sum(1 for e in entries if e.get("success",False)) / len(entries)
                findings.append(Finding(
                    source="CredStuffReverse", category="campaign_detected",
                    data={
                        "attacker_ip": ip,
                        "attempts": len(entries),
                        "unique_users_tried": unique_users,
                        "success_rate": round(success_rate*100,2),
                        "first_seen": entries[0].get("timestamp",""),
                        "last_seen": entries[-1].get("timestamp",""),
                        "severity": "CRITICAL" if success_rate > 0 else "HIGH",
                    },
                    confidence=0.85,
                ))

        for password, entries in passwords_tried.items():
            if len(entries) > 10:
                findings.append(Finding(
                    source="CredStuffReverse", category="spray_attack_password",
                    data={
                        "password_hash": hashlib.sha256(password.encode()).hexdigest()[:16],
                        "users_tried": len(set(e.get("email","") for e in entries)),
                        "total_attempts": len(entries),
                        "note": "Same password sprayed across many accounts - check leak corpus for source",
                    },
                    confidence=0.8,
                ))
        return findings


class PassiveWiFiBSSIDGeo:
    """Geolocate via leaked BSSID/MAC tables (wigle.net based)."""

    def __init__(self, config=None):
        self.config = config or {}
        self.wigle_key = self.config.get("WIGLE_API_KEY", os.getenv("WIGLE_API_KEY",""))

    def lookup_bssid(self, bssid):
        if not self.wigle_key:
            return [Finding(
                source="PassiveWiFiBSSID", category="dependency_missing",
                data={"message":"Set WIGLE_API_KEY for BSSID geolocation"},
                confidence=0.5,
            )]
        url = f"https://api.wigle.net/api/v2/network/search?netid={quote(bssid)}"
        resp = safe_request(url, headers={"Authorization":f"Basic {self.wigle_key}"}, timeout=15)
        findings = []
        if resp and resp.status_code == 200:
            data = resp.json()
            for r in data.get("results", []):
                findings.append(Finding(
                    source="PassiveWiFiBSSID", category="bssid_geolocated",
                    data={
                        "bssid": r.get("netid",""),
                        "ssid": r.get("ssid",""),
                        "lat": r.get("trilat",0),
                        "lon": r.get("trilong",0),
                        "country": r.get("country",""),
                        "city": r.get("city",""),
                        "first_seen": r.get("firsttime",""),
                        "last_seen": r.get("lasttime",""),
                        "encryption": r.get("encryption",""),
                    },
                    confidence=0.85,
                ))
        return findings

    def extract_bssids_from_text(self, text):
        bssid_pattern = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
        return list(set(bssid_pattern.findall(text)))


from urllib.parse import quote


if __name__ == "__main__":
    print("ENI Signature Modules loaded")
    gen = HoneyAccountGenerator()
    personas = gen.generate_persona(3)
    print(json.dumps(personas, indent=2))
