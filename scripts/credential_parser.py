"""
au-osint-recon :: credential_parser.py
Parse, normalize, deduplicate, and analyze leaked credential data.
Supports multiple formats: email:pass, user:pass, hash:pass, combo files, SQL dumps.
"""

import os
import re
import json
import csv
import hashlib
from typing import Optional, Dict, List, Any, Set, Tuple
from collections import Counter, defaultdict

from utils import (
    logger, Finding, ResultStore, DataClassifier,
    AU_PATTERNS, AU_EMAIL_DOMAINS, AU_MAJOR_BANKS, AU_TELCOS,
    identify_hash, fingerprint_data
)


class CredentialParser:
    """Parse and analyze leaked credentials with AU focus."""

    def __init__(self):
        self.results = ResultStore()
        self.classifier = DataClassifier()
        self.credentials: List[Dict] = []
        self._seen_hashes: Set[str] = set()

    # ── Format Detection ─────────────────────────────────────────────────

    @staticmethod
    def detect_format(line: str) -> Optional[str]:
        """Detect credential format from a line."""
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        patterns = [
            ('url:email:pass', re.compile(r'^https?://[^\s]+\s+[^:\s]+@[^:\s]+\.[^:\s]+:.+$')),
            ('email:pass:url', re.compile(r'^[^:\s]+@[^:\s]+\.[^:\s]+:.+:https?://.+$')),
            ('email:hash', re.compile(r'^[^:\s]+@[^:\s]+\.[^:\s]+:[a-fA-F0-9]{32,}$')),
            ('email:pass', re.compile(r'^[^:\s]+@[^:\s]+\.[^:\s]+:.+$')),
            ('user:hash', re.compile(r'^[^:\s@]+:[a-fA-F0-9]{32,}$')),
            ('user:pass', re.compile(r'^[^:\s@]+:.+$')),
            ('hash_only', re.compile(r'^[a-fA-F0-9]{32,128}$')),
            ('email_only', re.compile(r'^[^:\s]+@[^:\s]+\.[^:\s]+$')),
        ]

        for fmt, pattern in patterns:
            if pattern.match(line):
                return fmt

        return None

    # ── Line Parser ──────────────────────────────────────────────────────

    def parse_line(self, line: str, source: str = 'unknown') -> Optional[Dict]:
        """Parse a single credential line into structured data."""
        line = line.strip()
        if not line:
            return None

        fmt = self.detect_format(line)
        if not fmt:
            return None

        cred = {
            'raw': line,
            'format': fmt,
            'source': source,
            'email': '',
            'username': '',
            'password': '',
            'hash': '',
            'hash_type': [],
            'url': '',
            'domain': '',
            'is_australian': False,
        }

        if fmt == 'email:pass':
            parts = line.split(':', 1)
            cred['email'] = parts[0]
            cred['password'] = parts[1] if len(parts) > 1 else ''

        elif fmt == 'email:hash':
            parts = line.split(':', 1)
            cred['email'] = parts[0]
            cred['hash'] = parts[1]
            cred['hash_type'] = identify_hash(parts[1])

        elif fmt == 'user:pass':
            parts = line.split(':', 1)
            cred['username'] = parts[0]
            cred['password'] = parts[1] if len(parts) > 1 else ''

        elif fmt == 'user:hash':
            parts = line.split(':', 1)
            cred['username'] = parts[0]
            cred['hash'] = parts[1]
            cred['hash_type'] = identify_hash(parts[1])

        elif fmt == 'email:pass:url':
            parts = line.split(':')
            cred['email'] = parts[0]
            # Find where URL starts
            for i, p in enumerate(parts[1:], 1):
                if p.startswith('http') or p.startswith('//'):
                    cred['password'] = ':'.join(parts[1:i])
                    cred['url'] = ':'.join(parts[i:])
                    break
            else:
                cred['password'] = ':'.join(parts[1:])

        elif fmt == 'url:email:pass':
            # URL email:pass format
            match = re.match(r'(https?://\S+)\s+(\S+@\S+):(.+)', line)
            if match:
                cred['url'] = match.group(1)
                cred['email'] = match.group(2)
                cred['password'] = match.group(3)

        elif fmt == 'hash_only':
            cred['hash'] = line
            cred['hash_type'] = identify_hash(line)

        elif fmt == 'email_only':
            cred['email'] = line

        # Extract domain from email
        if cred['email'] and '@' in cred['email']:
            cred['domain'] = cred['email'].split('@')[1].lower()

        # Australian check
        cred['is_australian'] = any(
            cred.get('domain', '').endswith(d) for d in AU_EMAIL_DOMAINS
        ) or self.classifier.is_australian(line)

        return cred

    # ── File Parsers ─────────────────────────────────────────────────────

    def parse_combo_file(self, filepath: str, au_only: bool = True) -> List[Dict]:
        """Parse a combo list file."""
        creds = []
        line_count = 0
        au_count = 0

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_count += 1
                    cred = self.parse_line(line.strip(), source=os.path.basename(filepath))

                    if cred:
                        if au_only and not cred['is_australian']:
                            continue
                        au_count += 1
                        # Dedup
                        fp = fingerprint_data(cred['raw'])
                        if fp not in self._seen_hashes:
                            self._seen_hashes.add(fp)
                            creds.append(cred)

        except Exception as e:
            logger.error(f'Error parsing {filepath}: {e}')

        logger.info(f'Parsed {filepath}: {line_count} lines, {au_count} AU entries, {len(creds)} unique')
        return creds

    def parse_sql_dump(self, filepath: str, au_only: bool = True) -> List[Dict]:
        """Parse SQL dump file for credentials."""
        creds = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Find INSERT statements
            insert_pattern = re.compile(
                r"INSERT\s+INTO\s+[`'\"]?(\w+)[`'\"]?\s*"
                r"(?:\([^)]+\))?\s*VALUES\s*(.+?)(?:;|\n(?=INSERT|CREATE|DROP|ALTER))",
                re.IGNORECASE | re.DOTALL
            )

            for match in insert_pattern.finditer(content):
                table_name = match.group(1).lower()
                values_block = match.group(2)

                # Check if it's a user-related table
                user_tables = ['users', 'user', 'accounts', 'members', 'customers',
                              'clients', 'login', 'credentials', 'auth', 'admin',
                              'employees', 'staff', 'people', 'profiles']

                if not any(t in table_name for t in user_tables):
                    continue

                # Extract individual value tuples
                value_pattern = re.compile(r"\(([^)]+)\)")
                for val_match in value_pattern.finditer(values_block):
                    values = val_match.group(1)

                    # Find email and password
                    email_match = AU_PATTERNS['email_au'].search(values)
                    if not email_match and not au_only:
                        email_match = re.search(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.\w{2,}', values)

                    if email_match:
                        email = email_match.group()
                        # Look for password/hash in same row
                        parts = [p.strip().strip("'\"") for p in values.split(',')]

                        password = ''
                        hash_val = ''
                        for part in parts:
                            part_clean = part.strip()
                            hash_types = identify_hash(part_clean)
                            if hash_types:
                                hash_val = part_clean
                            elif len(part_clean) > 3 and part_clean != email and '@' not in part_clean:
                                if not re.match(r'^\d+$', part_clean) or len(part_clean) > 6:
                                    password = part_clean

                        cred = {
                            'raw': values[:200],
                            'format': 'sql_dump',
                            'source': f'{os.path.basename(filepath)}:{table_name}',
                            'email': email,
                            'username': '',
                            'password': password,
                            'hash': hash_val,
                            'hash_type': identify_hash(hash_val) if hash_val else [],
                            'url': '',
                            'domain': email.split('@')[1] if '@' in email else '',
                            'table': table_name,
                            'is_australian': any(email.endswith(d) for d in AU_EMAIL_DOMAINS),
                        }

                        fp = fingerprint_data(cred['email'] + cred['password'] + cred['hash'])
                        if fp not in self._seen_hashes:
                            self._seen_hashes.add(fp)
                            creds.append(cred)

        except Exception as e:
            logger.error(f'Error parsing SQL dump {filepath}: {e}')

        logger.info(f'Parsed SQL dump {filepath}: {len(creds)} credentials extracted')
        return creds

    def parse_csv_dump(self, filepath: str, au_only: bool = True) -> List[Dict]:
        """Parse CSV file for credentials."""
        creds = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                # Try to detect delimiter
                sample = f.read(4096)
                f.seek(0)

                dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
                reader = csv.DictReader(f, dialect=dialect)

                # Map column names
                email_cols = ['email', 'mail', 'e-mail', 'email_address', 'user_email']
                pass_cols = ['password', 'pass', 'pwd', 'passwd', 'user_password']
                user_cols = ['username', 'user', 'login', 'user_name', 'nickname']
                hash_cols = ['hash', 'password_hash', 'hashed_password', 'pass_hash']
                phone_cols = ['phone', 'mobile', 'tel', 'telephone', 'phone_number']

                if not reader.fieldnames:
                    return creds

                fields_lower = {f.lower(): f for f in reader.fieldnames}

                email_field = next((fields_lower[c] for c in email_cols if c in fields_lower), None)
                pass_field = next((fields_lower[c] for c in pass_cols if c in fields_lower), None)
                user_field = next((fields_lower[c] for c in user_cols if c in fields_lower), None)
                hash_field = next((fields_lower[c] for c in hash_cols if c in fields_lower), None)
                phone_field = next((fields_lower[c] for c in phone_cols if c in fields_lower), None)

                for row in reader:
                    email = row.get(email_field, '') if email_field else ''
                    password = row.get(pass_field, '') if pass_field else ''
                    username = row.get(user_field, '') if user_field else ''
                    hash_val = row.get(hash_field, '') if hash_field else ''
                    phone = row.get(phone_field, '') if phone_field else ''

                    if not (email or username):
                        continue

                    is_au = any(email.endswith(d) for d in AU_EMAIL_DOMAINS) if email else False
                    if au_only and not is_au:
                        # Check phone
                        if phone and (phone.startswith('+61') or phone.startswith('04')):
                            is_au = True
                        if not is_au:
                            continue

                    cred = {
                        'raw': json.dumps(row)[:200],
                        'format': 'csv',
                        'source': os.path.basename(filepath),
                        'email': email,
                        'username': username,
                        'password': password,
                        'hash': hash_val,
                        'hash_type': identify_hash(hash_val) if hash_val else [],
                        'phone': phone,
                        'domain': email.split('@')[1] if '@' in email else '',
                        'is_australian': is_au,
                        'extra': {k: v for k, v in row.items() if v and k not in [email_field, pass_field, user_field, hash_field]},
                    }

                    fp = fingerprint_data(email + username + password + hash_val)
                    if fp not in self._seen_hashes:
                        self._seen_hashes.add(fp)
                        creds.append(cred)

        except Exception as e:
            logger.error(f'Error parsing CSV {filepath}: {e}')

        logger.info(f'Parsed CSV {filepath}: {len(creds)} credentials')
        return creds

    # ── Analysis ─────────────────────────────────────────────────────────

    def analyze(self, creds: Optional[List[Dict]] = None) -> Dict:
        """Analyze credential set for patterns and statistics."""
        data = creds or self.credentials

        if not data:
            return {'error': 'No credentials to analyze'}

        stats = {
            'total': len(data),
            'with_password': sum(1 for c in data if c.get('password')),
            'with_hash': sum(1 for c in data if c.get('hash')),
            'with_email': sum(1 for c in data if c.get('email')),
            'australian': sum(1 for c in data if c.get('is_australian')),
        }

        # Domain breakdown
        domain_counter = Counter()
        for c in data:
            if c.get('domain'):
                domain_counter[c['domain']] += 1
        stats['top_domains'] = dict(domain_counter.most_common(30))

        # AU-specific domain breakdown
        au_domains = Counter()
        for c in data:
            domain = c.get('domain', '')
            if any(domain.endswith(d) for d in AU_EMAIL_DOMAINS):
                au_domains[domain] += 1
        stats['top_au_domains'] = dict(au_domains.most_common(30))

        # Password analysis
        passwords = [c['password'] for c in data if c.get('password')]
        if passwords:
            password_counter = Counter(passwords)
            stats['top_passwords'] = dict(password_counter.most_common(20))
            stats['password_stats'] = {
                'unique': len(set(passwords)),
                'reused': sum(1 for _, count in password_counter.items() if count > 1),
                'avg_length': round(sum(len(p) for p in passwords) / len(passwords), 1),
                'min_length': min(len(p) for p in passwords),
                'max_length': max(len(p) for p in passwords),
            }

            # Password complexity
            complexity = {
                'lowercase_only': sum(1 for p in passwords if p.islower()),
                'has_uppercase': sum(1 for p in passwords if any(c.isupper() for c in p)),
                'has_digits': sum(1 for p in passwords if any(c.isdigit() for c in p)),
                'has_special': sum(1 for p in passwords if re.search(r'[!@#$%^&*(),.?":{}|<>]', p)),
                'numeric_only': sum(1 for p in passwords if p.isdigit()),
            }
            stats['password_complexity'] = complexity

        # Hash type breakdown
        hash_types = Counter()
        for c in data:
            for ht in c.get('hash_type', []):
                hash_types[ht] += 1
        stats['hash_types'] = dict(hash_types.most_common())

        # Source breakdown
        source_counter = Counter(c.get('source', 'unknown') for c in data)
        stats['by_source'] = dict(source_counter.most_common())

        # AU bank/telco detection
        bank_hits = Counter()
        telco_hits = Counter()
        for c in data:
            domain = c.get('domain', '').lower()
            for bank in AU_MAJOR_BANKS:
                if bank in domain:
                    bank_hits[bank] += 1
            for telco in AU_TELCOS:
                if telco in domain:
                    telco_hits[telco] += 1

        stats['au_banks_detected'] = dict(bank_hits.most_common())
        stats['au_telcos_detected'] = dict(telco_hits.most_common())

        # Gov/edu detection
        gov_count = sum(1 for c in data if c.get('domain', '').endswith('.gov.au'))
        edu_count = sum(1 for c in data if c.get('domain', '').endswith('.edu.au'))
        stats['gov_au_count'] = gov_count
        stats['edu_au_count'] = edu_count

        return stats

    # ── Export ────────────────────────────────────────────────────────────

    def export_json(self, filepath: str, creds: Optional[List[Dict]] = None) -> None:
        """Export credentials to JSON."""
        data = creds or self.credentials
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f'Exported {len(data)} credentials to {filepath}')

    def export_csv(self, filepath: str, creds: Optional[List[Dict]] = None) -> None:
        """Export credentials to CSV."""
        data = creds or self.credentials
        if not data:
            return

        fields = ['email', 'username', 'password', 'hash', 'hash_type', 'domain',
                  'url', 'source', 'format', 'is_australian']

        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            for cred in data:
                row = {k: cred.get(k, '') for k in fields}
                row['hash_type'] = ','.join(cred.get('hash_type', []))
                writer.writerow(row)

        logger.info(f'Exported {len(data)} credentials to {filepath}')

    def export_combo(self, filepath: str, format: str = 'email:pass', creds: Optional[List[Dict]] = None) -> None:
        """Export as combo list in specified format."""
        data = creds or self.credentials

        with open(filepath, 'w') as f:
            for cred in data:
                if format == 'email:pass' and cred.get('email') and cred.get('password'):
                    f.write(f"{cred['email']}:{cred['password']}\n")
                elif format == 'user:pass' and cred.get('username') and cred.get('password'):
                    f.write(f"{cred['username']}:{cred['password']}\n")
                elif format == 'email:hash' and cred.get('email') and cred.get('hash'):
                    f.write(f"{cred['email']}:{cred['hash']}\n")

        logger.info(f'Exported combo list ({format}) to {filepath}')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Credential Parser Module')
    parser.add_argument('--input', '-i', required=True, help='Input file path')
    parser.add_argument('--format', '-f', default='auto', choices=['auto', 'combo', 'sql', 'csv'])
    parser.add_argument('--au-only', action='store_true', default=True)
    parser.add_argument('--output', '-o', default='parsed_creds.json')
    parser.add_argument('--analyze', action='store_true')
    args = parser.parse_args()

    parser_engine = CredentialParser()

    if args.format == 'auto':
        if args.input.endswith('.sql'):
            args.format = 'sql'
        elif args.input.endswith('.csv'):
            args.format = 'csv'
        else:
            args.format = 'combo'

    if args.format == 'combo':
        creds = parser_engine.parse_combo_file(args.input, au_only=args.au_only)
    elif args.format == 'sql':
        creds = parser_engine.parse_sql_dump(args.input, au_only=args.au_only)
    elif args.format == 'csv':
        creds = parser_engine.parse_csv_dump(args.input, au_only=args.au_only)

    parser_engine.credentials = creds
    parser_engine.export_json(args.output, creds)

    if args.analyze:
        stats = parser_engine.analyze(creds)
        print(json.dumps(stats, indent=2))
