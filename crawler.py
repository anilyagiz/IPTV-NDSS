#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPTV Crawler - Professional Web Crawler for IPTV Research

This crawler performs query-based searches, forum-focused crawling,
APK link discovery, and exports results in multiple formats.

Features:
- Respects robots.txt (configurable)
- Domain-level polite rate limiting
- Asynchronous concurrent crawling
- Language detection and translation
- Theme-based content classification
- APK link discovery
- Multiple export formats (JSONL, CSV, TXT)

Ethics & Compliance:
- Uses compliant search APIs (Serper)
- Respects robots.txt and rate limits
- For research and educational purposes only

Author: Research Team
License: MIT
"""

import os
import re
import json
import csv
import time
import asyncio
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set, Any
from urllib.parse import urlparse, urljoin, urldefrag
import urllib.robotparser

import aiohttp
from aiohttp import ClientSession
from bs4 import BeautifulSoup
from langdetect import detect as lang_detect, DetectorFactory
from deep_translator import GoogleTranslator
from dateutil import tz

# Deterministic language detection
DetectorFactory.seed = 0

# -----------------------------
# Constants & Defaults
# -----------------------------

DEFAULT_QUERIES = [
    "iptv",
    "free iptv",
    "illicit IPTV sources",
    "illegal IPTV providers",
    "pirate IPTV streaming sites",
    "IPTV piracy networks",
    "underground IPTV sources",
    "IPTV hack providers",
    "illegal IPTV streaming platforms",
    "pirate IPTV reseller",
    "unauthorized IPTV services",
    "pirate IPTV subscriptions",
    "IPTV pirate content",
    "unlicensed IPTV streams",
    "iptv forum",
    "m3u8 iptv",
    "buy iptv subscription"
]

DEFAULT_FORUM_DOMAINS = [
    "reddit.com",
    "avsforum.com",
    "digitalspy.co.uk",
    "satelliteguys.us",
    "broadbandtvnews.com",
    "techsupportforum.com",
    "linuxquestions.org",
    "forum.kodi.tv",
    "forum.xda-developers.com"
]

DEFAULT_KEYWORDS = [
    "iptv", "ip tv", "free iptv",
    "pirate", "illicit", "illegal", "underground",
    "m3u", "m3u8", "xtream", "panel",
    "subscription", "reseller"
]

# Theme-based lexicon for content classification
THEME_LEXICON = {
    "infrastructure_distribution": [
        "cdn", "m3u", "m3u8", "xtream", "panel", "load balancer",
        "dns", "anonymizer", "cloudflare", "hosting", "server"
    ],
    "economics_marketing": [
        "reseller", "subscription", "trial", "panel price", "payment",
        "paypal", "crypto", "affiliate", "pricing", "revenue"
    ],
    "security_privacy_risks": [
        "malware", "phishing", "credential", "steal", "spyware",
        "leak", "privacy", "risk", "vulnerability", "exploit"
    ]
}

# -----------------------------
# Configuration
# -----------------------------

@dataclass
class CrawlerConfig:
    """Configuration for the IPTV Crawler"""

    # Search configuration
    queries: List[str] = field(default_factory=lambda: DEFAULT_QUERIES)
    keywords: List[str] = field(default_factory=lambda: DEFAULT_KEYWORDS)
    forum_domains: List[str] = field(default_factory=lambda: DEFAULT_FORUM_DOMAINS)

    # Crawling behavior
    site_specific_expansion: bool = True
    max_results_per_query: int = 30
    search_pages: int = 1
    max_pages_total: int = 1000
    max_pages_per_domain: int = 200
    follow_links_on_forums_only: bool = True
    max_depth_for_forums: int = 2

    # Performance & rate limiting
    concurrency: int = 20
    per_domain_min_interval_sec: float = 2.0
    request_timeout_sec: int = 15

    # Compliance
    respect_robots: bool = True
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) IPTVCrawler/2.0 (+research; contact@example.com)"

    # Translation
    translation_enabled: bool = True
    translate_to_lang: str = "en"

    # Output
    output_dir: str = "outputs"
    export_jsonl: str = "pages.jsonl"
    export_csv: str = "pages.csv"
    export_apk_list: str = "apk_links.txt"

    # Logging
    log_level: str = "INFO"

    # Search provider
    search_provider: str = "serper"
    serper_api_key_env: str = "SERPER_API_KEY"


# -----------------------------
# Utility Functions
# -----------------------------

def now_iso() -> str:
    """Returns current UTC timestamp in ISO format"""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def canonicalize_url(url: str) -> str:
    """Remove fragments and normalize URL"""
    url, _frag = urldefrag(url.strip())
    return url


def get_hostname(url: str) -> str:
    """Extract hostname from URL"""
    return urlparse(url).hostname or ""


def clean_text(text: str) -> str:
    """Clean and normalize text by collapsing whitespace"""
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def ensure_dir(path: str) -> None:
    """Create directory if it doesn't exist"""
    os.makedirs(path, exist_ok=True)


def snippet(text: str, length: int = 400) -> str:
    """Create a text snippet of specified length"""
    return (text[:length] + "…") if len(text) > length else text


# -----------------------------
# Search Provider
# -----------------------------

class SearchProvider:
    """Base class for search providers"""

    async def search(
        self,
        session: ClientSession,
        query: str,
        num: int,
        page: int
    ) -> List[Dict[str, str]]:
        """Execute a search query and return results"""
        raise NotImplementedError


class SerperSearchProvider(SearchProvider):
    """Google Serper API search provider"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.endpoint = "https://google.serper.dev/search"

    async def search(
        self,
        session: ClientSession,
        query: str,
        num: int,
        page: int
    ) -> List[Dict[str, str]]:
        """Search using Serper API"""
        if not self.api_key:
            return []

        payload = {"q": query, "num": num, "page": page}
        headers = {
            "X-API-KEY": self.api_key,
            "Content-Type": "application/json"
        }

        try:
            async with session.post(
                self.endpoint,
                headers=headers,
                json=payload,
                timeout=30
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()

                results = []
                for item in data.get("organic", []) or []:
                    link = item.get("link")
                    title = item.get("title")
                    if link:
                        results.append({"title": title or "", "link": link})

                return results

        except Exception as e:
            logging.warning(f"Search API error for query '{query}': {e}")
            return []


# -----------------------------
# Robots.txt & Rate Limiting
# -----------------------------

class RobotsCache:
    """Cache and check robots.txt permissions"""

    def __init__(self, respect_robots: bool, user_agent: str):
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self.cache: Dict[str, urllib.robotparser.RobotFileParser] = {}
        self.lock = asyncio.Lock()

    async def can_fetch(self, session: ClientSession, url: str) -> bool:
        """Check if URL is allowed by robots.txt"""
        if not self.respect_robots:
            return True

        host = get_hostname(url)
        if not host:
            return False

        robots_url = f"{urlparse(url).scheme}://{host}/robots.txt"

        async with self.lock:
            rp = self.cache.get(host)

            if rp is None:
                # Fetch and parse robots.txt
                rp = urllib.robotparser.RobotFileParser()
                try:
                    async with session.get(
                        robots_url,
                        headers={"User-Agent": self.user_agent},
                        timeout=10
                    ) as r:
                        if r.status == 200:
                            txt = await r.text()
                            rp.parse(txt.splitlines())
                        else:
                            # No robots.txt, allow by default
                            rp.allow_all = True

                except Exception as e:
                    logging.debug(f"Could not fetch robots.txt for {host}: {e}")
                    # On error, allow by default
                    rp.allow_all = True

                self.cache[host] = rp

        return rp.can_fetch(self.user_agent, url)


class DomainRateLimiter:
    """Per-domain rate limiting for polite crawling"""

    def __init__(self, min_interval_sec: float):
        self.min_interval = float(min_interval_sec)
        self._last: Dict[str, float] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def throttle(self, hostname: str) -> None:
        """Wait if necessary to respect rate limit for domain"""
        if self.min_interval <= 0:
            return

        async with await self._get_lock(hostname):
            now = time.monotonic()
            last = self._last.get(hostname, 0.0)
            to_wait = self.min_interval - (now - last)

            if to_wait > 0:
                await asyncio.sleep(to_wait)

            self._last[hostname] = time.monotonic()

    async def _get_lock(self, hostname: str) -> asyncio.Lock:
        """Get or create lock for specific hostname"""
        async with self._global_lock:
            if hostname not in self._locks:
                self._locks[hostname] = asyncio.Lock()
            return self._locks[hostname]


# -----------------------------
# Content Analysis
# -----------------------------

class KeywordMatcher:
    """Match and score text based on keywords"""

    def __init__(self, keywords: List[str]):
        self.keywords = keywords
        self.patterns = [
            re.compile(r"\b" + re.escape(k) + r"\b", flags=re.IGNORECASE)
            for k in keywords
        ]

    def score(self, text: str) -> Tuple[int, List[str]]:
        """Score text and return matched keywords"""
        matched = []
        score = 0

        for keyword, pattern in zip(self.keywords, self.patterns):
            hits = len(pattern.findall(text))
            if hits > 0:
                matched.append(keyword)
                score += hits

        return score, matched


def tag_themes(text_en: str) -> List[str]:
    """Tag text with relevant themes based on content"""
    tags = []
    text_lower = text_en.lower()

    for theme, terms in THEME_LEXICON.items():
        for term in terms:
            if term in text_lower:
                tags.append(theme)
                break

    return tags


# -----------------------------
# HTML Parsing
# -----------------------------

def extract_links(html: str, base_url: str) -> List[str]:
    """Extract all links from HTML"""
    try:
        soup = BeautifulSoup(html, "lxml")
        links = []

        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()

            # Skip anchors
            if href.startswith("#"):
                continue

            # Convert to absolute URL
            abs_url = urljoin(base_url, href)
            links.append(abs_url)

        return links

    except Exception as e:
        logging.debug(f"Error extracting links from {base_url}: {e}")
        return []


def extract_title_and_text(html: str) -> Tuple[str, str]:
    """Extract title and clean text from HTML"""
    try:
        soup = BeautifulSoup(html, "lxml")

        # Remove unwanted elements
        for tag in soup(["script", "style", "noscript", "header", "footer", "svg"]):
            tag.extract()

        # Extract title
        title = soup.title.get_text(strip=True) if soup.title else ""

        # Extract and clean text
        text = clean_text(soup.get_text(separator=" "))

        return title, text

    except Exception as e:
        logging.debug(f"Error parsing HTML: {e}")
        return "", ""


def detect_language_safe(text: str) -> str:
    """Detect language of text with error handling"""
    if not text or len(text) < 10:
        return "unknown"

    try:
        # Sample first 4000 chars for efficiency
        return lang_detect(text[:4000])
    except Exception as e:
        logging.debug(f"Language detection failed: {e}")
        return "unknown"


def translate_to(text: str, target_lang: str) -> str:
    """Translate text to target language"""
    if not text or len(text) < 10:
        return text

    try:
        translator = GoogleTranslator(source="auto", target=target_lang)
        return translator.translate(text)
    except Exception as e:
        logging.debug(f"Translation failed: {e}")
        return text  # Fallback to original


def is_forum_url(url: str, forum_domains: List[str]) -> bool:
    """Check if URL is likely a forum page"""
    host = get_hostname(url).lower()

    # Check against known forum domains
    if any(host.endswith(fd.lower()) for fd in forum_domains):
        return True

    # Check path for forum-like patterns
    path = urlparse(url).path.lower()
    forum_tokens = ["forum", "thread", "topic", "discussion", "board"]

    return any(token in path for token in forum_tokens)


# -----------------------------
# Data Models
# -----------------------------

@dataclass
class PageRecord:
    """Record for a crawled page"""
    url: str
    source: str  # "search" or "forum-crawl"
    depth: int
    hostname: str
    title: str
    language: str
    text_snippet: str
    matched_terms: List[str]
    keyword_score: int
    is_forum: bool
    themes_en: List[str]
    discovered_apk_urls: List[str]
    timestamp: str = field(default_factory=now_iso)


# -----------------------------
# Main Crawler
# -----------------------------

class IPTVCrawler:
    """Main crawler class for IPTV research"""

    def __init__(self, cfg: CrawlerConfig):
        self.cfg = cfg

        # Setup output directory
        ensure_dir(cfg.output_dir)

        # Setup logging
        logging.basicConfig(
            level=getattr(logging, cfg.log_level.upper(), logging.INFO),
            format="%(asctime)s [%(levelname)s] %(message)s"
        )
        self.log = logging.getLogger("IPTVCrawler")

        # Initialize components
        self.matcher = KeywordMatcher(cfg.keywords)
        self.robots = RobotsCache(cfg.respect_robots, cfg.user_agent)
        self.rate_limiter = DomainRateLimiter(cfg.per_domain_min_interval_sec)
        self.search_provider = self._make_search_provider(cfg.search_provider)

        # State tracking
        self.visited: Set[str] = set()
        self.domain_counts: Dict[str, int] = {}
        self.pages: List[PageRecord] = []
        self.apk_links: Set[str] = set()
        self.queue: asyncio.Queue = asyncio.Queue()

    def _make_search_provider(self, name: str) -> SearchProvider:
        """Create search provider instance"""
        if name == "serper":
            api_key = os.getenv(self.cfg.serper_api_key_env, "").strip()

            if not api_key:
                self.log.warning(
                    f"{self.cfg.serper_api_key_env} not found in environment. "
                    "Search functionality will be disabled."
                )

            return SerperSearchProvider(api_key=api_key)
        else:
            raise ValueError(f"Unknown search provider: {name}")

    async def run(self) -> None:
        """Main crawler execution"""
        self.log.info("Starting IPTV Crawler...")

        async with aiohttp.ClientSession(
            headers={"User-Agent": self.cfg.user_agent}
        ) as session:
            # Step 1: Gather seed URLs from search queries
            seeds = await self._gather_seeds(session)

            for url in seeds:
                await self._enqueue(url, source="search", depth=0)

            # Step 2: Forum-specific site expansion
            if self.cfg.site_specific_expansion:
                self.log.info("Performing site-specific forum expansion...")

                for domain in self.cfg.forum_domains:
                    query = f"site:{domain} iptv"
                    more_urls = await self._search_query(session, query)

                    for url in more_urls:
                        await self._enqueue(url, source="search", depth=0)

            # Step 3: Start worker pool
            self.log.info(f"Starting {self.cfg.concurrency} worker threads...")

            workers = [
                asyncio.create_task(self._worker(session))
                for _ in range(self.cfg.concurrency)
            ]

            # Wait for queue to be processed
            await self.queue.join()

            # Cancel workers
            for worker in workers:
                worker.cancel()

            # Step 4: Export results
            await self._export()

        self.log.info("Crawler finished successfully!")

    async def _gather_seeds(self, session: ClientSession) -> List[str]:
        """Gather seed URLs from search queries"""
        self.log.info(f"Executing {len(self.cfg.queries)} search queries...")

        tasks = [
            self._search_query(session, query)
            for query in self.cfg.queries
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect all URLs
        urls = []
        for result in results:
            if isinstance(result, list):
                urls.extend(result)
            elif isinstance(result, Exception):
                self.log.warning(f"Search query failed: {result}")

        # Canonicalize and deduplicate
        urls = [canonicalize_url(url) for url in urls]
        unique_urls = list(dict.fromkeys(urls))

        self.log.info(f"Gathered {len(unique_urls)} unique seed URLs")

        return unique_urls

    async def _search_query(self, session: ClientSession, query: str) -> List[str]:
        """Execute a single search query"""
        if not isinstance(self.search_provider, SerperSearchProvider):
            return []

        if not self.search_provider.api_key:
            self.log.debug(f"Skipping search (no API key): {query}")
            return []

        urls = []

        for page in range(1, self.cfg.search_pages + 1):
            try:
                results = await self.search_provider.search(
                    session, query, self.cfg.max_results_per_query, page
                )

                urls.extend([r["link"] for r in results if r.get("link")])

            except Exception as e:
                self.log.warning(
                    f"Search error for '{query}' page {page}: {e}"
                )

        return urls

    async def _enqueue(self, url: str, source: str, depth: int) -> None:
        """Add URL to crawl queue with checks"""
        url = canonicalize_url(url)

        # Skip if already visited
        if url in self.visited:
            return

        host = get_hostname(url)
        if not host:
            return

        # Check domain quota
        if self.domain_counts.get(host, 0) >= self.cfg.max_pages_per_domain:
            return

        # Check global quota
        if len(self.visited) >= self.cfg.max_pages_total:
            return

        await self.queue.put((url, source, depth))

    async def _worker(self, session: ClientSession) -> None:
        """Worker coroutine to process URLs from queue"""
        while True:
            try:
                url, source, depth = await self.queue.get()

                try:
                    await self._process_url(session, url, source, depth)
                except Exception as e:
                    self.log.debug(f"Error processing {url}: {e}")
                finally:
                    self.queue.task_done()

            except asyncio.CancelledError:
                break

    async def _process_url(
        self,
        session: ClientSession,
        url: str,
        source: str,
        depth: int
    ) -> None:
        """Process a single URL"""
        # Check if already visited
        if url in self.visited:
            return

        host = get_hostname(url)

        # Check quotas
        if self.domain_counts.get(host, 0) >= self.cfg.max_pages_per_domain:
            return

        if len(self.visited) >= self.cfg.max_pages_total:
            return

        # Check robots.txt
        allowed = await self.robots.can_fetch(session, url)
        if not allowed:
            self.log.debug(f"Blocked by robots.txt: {url}")
            return

        # Rate limiting
        await self.rate_limiter.throttle(host)

        # Fetch page
        try:
            async with session.get(
                url,
                timeout=self.cfg.request_timeout_sec
            ) as resp:
                # Only process HTML
                content_type = resp.headers.get("Content-Type", "")

                if resp.status != 200 or "text/html" not in content_type:
                    return

                html = await resp.text(errors="ignore")

        except asyncio.TimeoutError:
            self.log.debug(f"Timeout fetching {url}")
            return
        except Exception as e:
            self.log.debug(f"Error fetching {url}: {e}")
            return

        # Mark as visited
        self.visited.add(url)
        self.domain_counts[host] = self.domain_counts.get(host, 0) + 1

        # Extract content
        title, text = extract_title_and_text(html)

        if not text:
            return

        # Detect language
        lang = detect_language_safe(text)

        # Translate if needed
        text_en = text
        if (self.cfg.translation_enabled and
            lang != self.cfg.translate_to_lang and
            lang != "unknown"):
            text_en = translate_to(text, self.cfg.translate_to_lang)

        # Score and match keywords
        score, matched = self.matcher.score(text.lower())

        # Check if forum
        is_forum = is_forum_url(url, self.cfg.forum_domains)

        # Discover APK links
        apk_urls = []
        for link in extract_links(html, url):
            link_lower = link.lower()

            # Check for APK files
            if (link_lower.endswith(".apk") or
                ("apk" in link_lower and any(
                    s in link for s in [
                        "drive.google.com",
                        "mega.nz",
                        "mediafire.com"
                    ]
                ))):
                apk_urls.append(canonicalize_url(link))

        for apk_url in apk_urls:
            self.apk_links.add(apk_url)

        # Record page if relevant
        if score > 0 or is_forum:
            record = PageRecord(
                url=url,
                source=source,
                depth=depth,
                hostname=host,
                title=title or "",
                language=lang,
                text_snippet=snippet(text, 800),
                matched_terms=matched,
                keyword_score=score,
                is_forum=is_forum,
                themes_en=tag_themes(text_en),
                discovered_apk_urls=apk_urls
            )

            self.pages.append(record)

            # Log progress
            if len(self.pages) % 50 == 0:
                self.log.info(
                    f"Progress: {len(self.pages)} pages | "
                    f"{len(self.visited)} visited | "
                    f"{len(self.apk_links)} APKs"
                )

        # Follow links on forum pages
        if self.cfg.follow_links_on_forums_only:
            if is_forum and depth < self.cfg.max_depth_for_forums:
                links = extract_links(html, url)

                # Stay within same domain
                for link in links:
                    if get_hostname(link) == host:
                        await self._enqueue(link, source="forum-crawl", depth=depth + 1)

    async def _export(self) -> None:
        """Export results to multiple formats"""
        self.log.info("Exporting results...")

        # Export JSONL
        jsonl_path = os.path.join(self.cfg.output_dir, self.cfg.export_jsonl)
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for page in self.pages:
                f.write(json.dumps(asdict(page), ensure_ascii=False) + "\n")

        self.log.info(f"Exported JSONL: {jsonl_path}")

        # Export CSV
        csv_path = os.path.join(self.cfg.output_dir, self.cfg.export_csv)
        cols = [
            "url", "source", "depth", "hostname", "title", "language",
            "text_snippet", "matched_terms", "keyword_score", "is_forum",
            "themes_en", "discovered_apk_urls", "timestamp"
        ]

        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=cols)
            writer.writeheader()

            for page in self.pages:
                row = asdict(page)
                row["matched_terms"] = "|".join(page.matched_terms)
                row["themes_en"] = "|".join(page.themes_en)
                row["discovered_apk_urls"] = "|".join(page.discovered_apk_urls)

                writer.writerow({k: row.get(k, "") for k in cols})

        self.log.info(f"Exported CSV: {csv_path}")

        # Export APK links
        apk_path = os.path.join(self.cfg.output_dir, self.cfg.export_apk_list)
        with open(apk_path, "w", encoding="utf-8") as f:
            for apk_url in sorted(self.apk_links):
                f.write(apk_url + "\n")

        self.log.info(f"Exported APK links: {apk_path}")

        # Summary
        self.log.info("-" * 60)
        self.log.info(f"Total pages crawled: {len(self.pages)}")
        self.log.info(f"Total URLs visited: {len(self.visited)}")
        self.log.info(f"Total APK links found: {len(self.apk_links)}")
        self.log.info(f"Domains crawled: {len(self.domain_counts)}")
        self.log.info("-" * 60)


# -----------------------------
# CLI Entry Point
# -----------------------------

async def main() -> None:
    """Main entry point for the crawler"""

    # Create configuration
    config = CrawlerConfig(
        max_pages_total=1200,
        max_pages_per_domain=250,
        search_pages=1,
        max_results_per_query=30,
        concurrency=20,
        per_domain_min_interval_sec=2.0,
        follow_links_on_forums_only=True,
        max_depth_for_forums=2,
        translation_enabled=True,
        respect_robots=True,
        log_level="INFO",
        output_dir="outputs"
    )

    # Create and run crawler
    crawler = IPTVCrawler(config)
    await crawler.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nCrawler interrupted by user")
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        raise
