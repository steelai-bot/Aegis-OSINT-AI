"""
au-osint-recon :: telegram_monitor.py
Telegram channel/group monitoring for Australian leak data.
Supports both MTProto API (Telethon) and Bot API approaches.
"""

import os
import re
import json
import time
from typing import Optional, Dict, List, Any
from urllib.parse import quote

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None

from utils import (
    logger, safe_request, Finding, ResultStore,
    DataClassifier, AU_PATTERNS, AU_EMAIL_DOMAINS
)


# Known Telegram channels/groups for leak data (public knowledge)
KNOWN_LEAK_CHANNELS = [
    # Generic leak channels (search terms for discovery)
    {'type': 'search_term', 'query': 'database leak'},
    {'type': 'search_term', 'query': 'combo list'},
    {'type': 'search_term', 'query': 'data breach'},
    {'type': 'search_term', 'query': 'leaked database'},
    {'type': 'search_term', 'query': 'stealer logs'},
    {'type': 'search_term', 'query': 'redline logs'},
    {'type': 'search_term', 'query': 'cloud of logs'},
    {'type': 'search_term', 'query': 'combolist fresh'},
    {'type': 'search_term', 'query': 'fullz cvv'},
    {'type': 'search_term', 'query': 'credit card dump'},
    # Australia-specific
    {'type': 'search_term', 'query': 'australia database'},
    {'type': 'search_term', 'query': 'aussie leak'},
    {'type': 'search_term', 'query': 'australian data'},
    {'type': 'search_term', 'query': 'com.au leak'},
    {'type': 'search_term', 'query': 'optus leak'},
    {'type': 'search_term', 'query': 'medibank data'},
]

AU_KEYWORDS = [
    'australia', 'australian', 'aussie', '.com.au', '.gov.au', '.edu.au',
    'sydney', 'melbourne', 'brisbane', 'perth', 'adelaide', 'canberra',
    'queensland', 'victoria', 'new south wales', 'tasmania',
    'commbank', 'westpac', 'anz', 'nab', 'commonwealth bank',
    'optus', 'telstra', 'vodafone au', 'medibank', 'medicare',
    'centrelink', 'mygov', 'service nsw', 'servicevic',
    'woolworths', 'coles', 'bunnings', 'qantas', 'jetstar',
    'abn', 'acn', 'tfn', 'bsb',
]


class TelegramMonitor:
    """Monitor Telegram for Australian data leaks."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.results = ResultStore()
        self.classifier = DataClassifier()

        # API credentials
        self.api_id = self.config.get('TELEGRAM_API_ID', os.getenv('TELEGRAM_API_ID', ''))
        self.api_hash = self.config.get('TELEGRAM_API_HASH', os.getenv('TELEGRAM_API_HASH', ''))
        self.bot_token = self.config.get('TELEGRAM_BOT_TOKEN', os.getenv('TELEGRAM_BOT_TOKEN', ''))

    # ── Telegram Search via t.me (public) ────────────────────────────────

    def search_telegram_public(self, query: str, max_results: int = 20) -> List[Finding]:
        """Search public Telegram channels/groups via web."""
        findings = []

        # Use Telegram's built-in search via clearnet
        search_engines = [
            f'https://tgstat.com/search?q={quote(query)}&type=channel',
            f'https://telemetr.io/en/search?q={quote(query)}',
            f'https://telegramchannels.me/search?q={quote(query)}',
        ]

        for engine_url in search_engines:
            resp = safe_request(engine_url, timeout=20)
            if not resp or resp.status_code != 200 or not BeautifulSoup:
                continue

            soup = BeautifulSoup(resp.text, 'html.parser')

            # Extract channel/group listings
            items = soup.find_all(['div', 'a', 'li'], class_=re.compile(
                r'channel|result|item|card', re.I
            ))

            for item in items[:max_results]:
                title_elem = item.find(['h3', 'h4', 'a', 'span'], class_=re.compile(r'title|name', re.I))
                desc_elem = item.find(['p', 'span', 'div'], class_=re.compile(r'desc|text|about', re.I))
                link_elem = item.find('a', href=re.compile(r't\.me/', re.I))

                if title_elem:
                    title = title_elem.get_text(strip=True)
                    desc = desc_elem.get_text(strip=True) if desc_elem else ''
                    link = link_elem.get('href', '') if link_elem else ''

                    combined = f'{title} {desc}'.lower()
                    is_au = any(kw in combined for kw in AU_KEYWORDS[:20])
                    is_leak = any(w in combined for w in [
                        'leak', 'dump', 'breach', 'combo', 'database',
                        'credential', 'stealer', 'logs', 'fullz', 'cvv',
                    ])

                    if is_au or is_leak:
                        findings.append(Finding(
                            source='Telegram-Search',
                            category='telegram_channel',
                            data={
                                'title': title[:200],
                                'description': desc[:500],
                                'telegram_link': link,
                                'search_query': query,
                                'is_australian': is_au,
                                'is_leak_related': is_leak,
                            },
                            confidence=0.5 if is_au else 0.3,
                        ))

            time.sleep(2)

        return findings

    # ── Telegram Bot API Search ──────────────────────────────────────────

    def search_via_bot(self, query: str, chat_id: str = '') -> List[Finding]:
        """Use Telegram Bot API to search within channels/groups."""
        findings = []

        if not self.bot_token:
            logger.warning('Telegram Bot token not configured')
            return findings

        base = f'https://api.telegram.org/bot{self.bot_token}'

        if chat_id:
            # Search messages in specific chat
            # Note: bots can only search in chats they're members of
            url = f'{base}/getUpdates'
            resp = safe_request(url, timeout=15)
            if resp and resp.status_code == 200:
                data = resp.json()
                messages = data.get('result', [])

                for msg in messages:
                    message = msg.get('message', {}) or msg.get('channel_post', {})
                    text = message.get('text', '') or message.get('caption', '')

                    if not text:
                        continue

                    text_lower = text.lower()
                    if query.lower() in text_lower or any(kw in text_lower for kw in AU_KEYWORDS[:10]):
                        # Classify data in message
                        classified = self.classifier.classify(text)

                        findings.append(Finding(
                            source='Telegram-Bot',
                            category='telegram_message',
                            data={
                                'chat_id': message.get('chat', {}).get('id', ''),
                                'chat_title': message.get('chat', {}).get('title', ''),
                                'message_id': message.get('message_id', ''),
                                'date': message.get('date', ''),
                                'text_preview': text[:500],
                                'detected_data': classified,
                                'has_file': bool(message.get('document')),
                                'file_name': message.get('document', {}).get('file_name', '') if message.get('document') else '',
                            },
                            confidence=0.7,
                        ))

        return findings

    # ── MTProto API (Telethon) ───────────────────────────────────────────

    def search_via_mtproto(self, query: str, channels: Optional[List[str]] = None) -> List[Finding]:
        """Full Telegram search using MTProto API (Telethon)."""
        findings = []

        if not (self.api_id and self.api_hash):
            logger.warning('Telegram API ID/Hash not configured for MTProto')
            return findings

        try:
            from telethon.sync import TelegramClient
            from telethon.tl.functions.messages import SearchGlobalRequest
            from telethon.tl.functions.contacts import SearchRequest
        except ImportError:
            logger.warning('Telethon not installed. Run: pip install telethon')
            return findings

        session_file = self.config.get('SESSION_FILE', 'au_osint_telegram')

        try:
            with TelegramClient(session_file, int(self.api_id), self.api_hash) as client:
                # Global search
                logger.info(f'  MTProto global search: {query}')
                result = client(SearchGlobalRequest(
                    q=query,
                    filter=None,
                    min_date=None,
                    max_date=None,
                    offset_rate=0,
                    offset_peer=None,
                    offset_id=0,
                    limit=100,
                ))

                for msg in result.messages:
                    text = msg.message or ''
                    text_lower = text.lower()

                    is_au = any(kw in text_lower for kw in AU_KEYWORDS[:15])

                    if is_au or query.lower() in text_lower:
                        classified = self.classifier.classify(text)

                        findings.append(Finding(
                            source='Telegram-MTProto',
                            category='telegram_message',
                            data={
                                'message_id': msg.id,
                                'date': str(msg.date),
                                'text_preview': text[:500],
                                'detected_data': classified,
                                'is_australian': is_au,
                                'peer_id': str(msg.peer_id),
                            },
                            confidence=0.7 if is_au else 0.4,
                        ))

                # Search specific channels
                if channels:
                    for channel_name in channels:
                        try:
                            entity = client.get_entity(channel_name)
                            messages = client.iter_messages(entity, search=query, limit=50)

                            for msg in messages:
                                text = msg.message or ''
                                text_lower = text.lower()
                                is_au = any(kw in text_lower for kw in AU_KEYWORDS[:15])

                                classified = self.classifier.classify(text)

                                findings.append(Finding(
                                    source='Telegram-Channel',
                                    category='telegram_message',
                                    data={
                                        'channel': channel_name,
                                        'message_id': msg.id,
                                        'date': str(msg.date),
                                        'text_preview': text[:500],
                                        'detected_data': classified,
                                        'is_australian': is_au,
                                        'has_file': bool(msg.file),
                                        'file_name': msg.file.name if msg.file else '',
                                    },
                                    confidence=0.7,
                                ))
                        except Exception as e:
                            logger.warning(f'Failed to search channel {channel_name}: {e}')

                # Discover AU-related channels/groups
                logger.info('  Discovering AU-related channels...')
                for kw in ['australia data', 'aussie leak', 'com.au database']:
                    try:
                        result = client(SearchRequest(
                            q=kw,
                            limit=20,
                        ))
                        for chat in result.chats:
                            findings.append(Finding(
                                source='Telegram-Discovery',
                                category='telegram_channel',
                                data={
                                    'channel_id': chat.id,
                                    'title': getattr(chat, 'title', ''),
                                    'username': getattr(chat, 'username', ''),
                                    'participants_count': getattr(chat, 'participants_count', 0),
                                    'search_keyword': kw,
                                },
                                confidence=0.5,
                            ))
                    except Exception as e:
                        logger.warning(f'Channel discovery failed for "{kw}": {e}')

        except Exception as e:
            logger.error(f'MTProto search failed: {e}')

        return findings

    # ── Telegram Leak Bot Interaction ────────────────────────────────────

    def generate_bot_queries(self, target: str) -> Dict[str, List[str]]:
        """Generate queries for common Telegram lookup bots."""
        return {
            'email_lookup_bots': [
                f'/search {target}',
                f'/lookup {target}',
                f'/check {target}',
                f'/find {target}',
            ],
            'phone_lookup_bots': [
                f'/phone {target}',
                f'/number {target}',
            ],
            'known_bots': [
                '@EmailSearchBot - email lookup',
                '@PhoneSearchBot - phone lookup',
                '@maaborosint_bot - OSINT aggregator',
                '@LeakCheckBot - breach check',
                '@IntelXBot - Intelligence X',
                '@GetContactBot - phone-to-name',
                '@eyeofgodbot - Russian OSINT (works for AU)',
                '@Quick_OSINT_bot - multi-lookup',
                '@himlookupchatbot - name/phone lookup',
            ],
            'note': 'Interact with these bots via Telegram client. Most require payment for detailed results.',
        }

    # ── Analyze Downloaded Telegram Data ─────────────────────────────────

    def analyze_telegram_export(self, filepath: str) -> List[Finding]:
        """Analyze exported Telegram chat data for AU leaks."""
        findings = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                if filepath.endswith('.json'):
                    data = json.load(f)
                    messages = data.get('messages', [])

                    for msg in messages:
                        text = ''
                        if isinstance(msg.get('text'), str):
                            text = msg['text']
                        elif isinstance(msg.get('text'), list):
                            text = ' '.join(str(t) for t in msg['text'])

                        if not text:
                            continue

                        text_lower = text.lower()
                        is_au = any(kw in text_lower for kw in AU_KEYWORDS[:15])

                        if is_au:
                            classified = self.classifier.classify(text)
                            if classified:
                                findings.append(Finding(
                                    source='Telegram-Export',
                                    category='telegram_leak',
                                    data={
                                        'message_id': msg.get('id', ''),
                                        'date': msg.get('date', ''),
                                        'text_preview': text[:500],
                                        'detected_data': classified,
                                        'is_australian': True,
                                    },
                                    confidence=0.7,
                                ))
                else:
                    # Plain text export
                    content = f.read()
                    chunks = content.split('\n\n')
                    for chunk in chunks:
                        if self.classifier.is_australian(chunk):
                            classified = self.classifier.classify(chunk)
                            if classified:
                                findings.append(Finding(
                                    source='Telegram-Export',
                                    category='telegram_leak',
                                    data={
                                        'text_preview': chunk[:500],
                                        'detected_data': classified,
                                    },
                                    confidence=0.6,
                                ))

        except Exception as e:
            logger.error(f'Failed to analyze Telegram export {filepath}: {e}')

        return findings

    # ── Full Telegram Search ─────────────────────────────────────────────

    def full_search(self, target: str, use_mtproto: bool = False, channels: Optional[List[str]] = None) -> ResultStore:
        """Full Telegram intelligence gathering."""
        logger.info(f'Starting Telegram monitoring for: {target}')

        # Public web search
        logger.info('[1] Public channel/group search...')
        for query in [f'{target} australia', f'{target} leak', f'{target} database']:
            public = self.search_telegram_public(query)
            self.results.add_many(public)
        logger.info(f'  → Public search: {len(self.results)} findings')

        # Bot API
        if self.bot_token:
            logger.info('[2] Bot API search...')
            bot = self.search_via_bot(target)
            self.results.add_many(bot)

        # MTProto
        if use_mtproto and self.api_id and self.api_hash:
            logger.info('[3] MTProto search...')
            mtproto = self.search_via_mtproto(target, channels)
            self.results.add_many(mtproto)

        # Bot queries
        logger.info('[4] Generating bot interaction queries...')
        bot_queries = self.generate_bot_queries(target)
        self.results.add(Finding(
            source='Telegram-BotQueries',
            category='search_queries',
            data=bot_queries,
            confidence=1.0,
        ))

        logger.info(f'Telegram search complete: {len(self.results)} findings')
        return self.results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Telegram Monitor Module')
    parser.add_argument('--target', '-t', required=True)
    parser.add_argument('--mtproto', action='store_true')
    parser.add_argument('--channels', nargs='+', default=None)
    parser.add_argument('--export', help='Path to Telegram export file')
    parser.add_argument('--output', '-o', default='telegram_results.json')
    args = parser.parse_args()

    monitor = TelegramMonitor()

    if args.export:
        results = monitor.analyze_telegram_export(args.export)
        store = ResultStore()
        store.add_many(results)
    else:
        store = monitor.full_search(args.target, use_mtproto=args.mtproto, channels=args.channels)

    with open(args.output, 'w') as f:
        f.write(store.to_json())
    print(json.dumps(store.summary(), indent=2))
