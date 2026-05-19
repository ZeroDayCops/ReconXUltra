#!/usr/bin/env python3
"""
ReconX Ultra — Intelligent Deduplication Engine
================================================
High-performance deduplication using:
  - SimHash for URL similarity detection
  - Response fingerprinting
  - Fuzzy hash clustering
  - Smart URL normalization
  - Parameter-aware dedup

Usage: dedup_engine.py <domain> [--urls] [--responses] [--all]
"""

import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else None
if not DOMAIN:
    print("Usage: dedup_engine.py <domain> [--urls|--responses|--all]", file=sys.stderr)
    sys.exit(1)

MODE = sys.argv[2] if len(sys.argv) > 2 else "--all"

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
OUT_URLS = OUTPUT_DIR / "urls"
OUT_JS = OUTPUT_DIR / "js"
OUT_INTEL = OUTPUT_DIR / "intelligence"
OUT_INTEL.mkdir(parents=True, exist_ok=True)


def read_lines(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


# ═══════════════════════════════════════════════════════════════════════════
# SimHash Implementation
# ═══════════════════════════════════════════════════════════════════════════

class SimHash:
    """64-bit SimHash for near-duplicate detection."""

    def __init__(self, tokens, bits=64):
        self.bits = bits
        self.hash = self._compute(tokens)

    def _compute(self, tokens):
        vector = [0] * self.bits
        for token in tokens:
            token_hash = int(hashlib.md5(token.encode('utf-8', errors='ignore')).hexdigest(), 16)
            for i in range(self.bits):
                if token_hash & (1 << i):
                    vector[i] += 1
                else:
                    vector[i] -= 1

        fingerprint = 0
        for i in range(self.bits):
            if vector[i] > 0:
                fingerprint |= (1 << i)
        return fingerprint

    def distance(self, other):
        """Hamming distance between two SimHashes."""
        x = self.hash ^ other.hash
        count = 0
        while x:
            count += 1
            x &= x - 1
        return count

    def is_similar(self, other, threshold=3):
        """Check if two SimHashes are similar (threshold = max hamming distance)."""
        return self.distance(other) <= threshold


# ═══════════════════════════════════════════════════════════════════════════
# URL Normalization & Dedup
# ═══════════════════════════════════════════════════════════════════════════

def normalize_url(url):
    """Normalize URL for deduplication."""
    try:
        parsed = urlparse(url)
        # Lowercase scheme and host
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower().rstrip('.')
        # Remove default ports
        netloc = re.sub(r':80$', '', netloc)
        netloc = re.sub(r':443$', '', netloc)
        # Normalize path
        path = parsed.path or '/'
        path = re.sub(r'/+', '/', path)
        path = path.rstrip('/') or '/'
        # Remove fragments
        # Sort query parameters
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(sorted(params.items()), doseq=True)
        else:
            sorted_query = ''

        return urlunparse((scheme, netloc, path, '', sorted_query, ''))
    except Exception:
        return url


def extract_url_pattern(url):
    """Extract structural pattern from URL for pattern-based dedup."""
    try:
        parsed = urlparse(url)
        path = parsed.path
        # Replace numeric segments with {N}
        path = re.sub(r'/\d+', '/{N}', path)
        # Replace UUIDs with {UUID}
        path = re.sub(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '/{UUID}', path)
        # Replace hex hashes with {HASH}
        path = re.sub(r'/[a-f0-9]{32,}', '/{HASH}', path)
        # Extract parameter names (not values)
        param_names = sorted(parse_qs(parsed.query, keep_blank_values=True).keys()) if parsed.query else []

        return f"{parsed.netloc}{path}?{'&'.join(param_names)}" if param_names else f"{parsed.netloc}{path}"
    except Exception:
        return url


def dedup_urls(urls):
    """Deduplicate URLs using multiple strategies."""
    if not urls:
        return [], {}

    # Stage 1: Exact dedup after normalization
    normalized = {}
    for url in urls:
        norm = normalize_url(url)
        if norm not in normalized:
            normalized[norm] = url

    stage1_count = len(normalized)

    # Stage 2: Pattern-based dedup (keep one per URL pattern)
    pattern_groups = defaultdict(list)
    for norm_url, orig_url in normalized.items():
        pattern = extract_url_pattern(norm_url)
        pattern_groups[pattern].append(orig_url)

    # Keep one URL per pattern, prefer URLs with more parameters
    unique_urls = []
    for pattern, group_urls in pattern_groups.items():
        # Sort by parameter count (descending), then by length
        group_urls.sort(key=lambda u: (-u.count('&'), -len(u)))
        unique_urls.append(group_urls[0])

    # Stage 3: SimHash-based similarity dedup for remaining URLs
    if len(unique_urls) > 100:
        simhash_groups = []
        for url in unique_urls:
            tokens = re.findall(r'\w+', url.lower())
            sh = SimHash(tokens)
            merged = False
            for group_hash, group_urls in simhash_groups:
                if sh.is_similar(group_hash, threshold=5):
                    group_urls.append(url)
                    merged = True
                    break
            if not merged:
                simhash_groups.append((sh, [url]))

        final_urls = []
        for _, group_urls in simhash_groups:
            # Keep the most parameter-rich URL from each group
            group_urls.sort(key=lambda u: (-u.count('?'), -u.count('&'), -len(u)))
            final_urls.append(group_urls[0])
        unique_urls = final_urls

    stats = {
        "original": len(urls),
        "after_normalization": stage1_count,
        "after_pattern_dedup": len(pattern_groups),
        "final": len(unique_urls),
        "reduction_pct": round((1 - len(unique_urls) / len(urls)) * 100, 1) if urls else 0
    }

    return sorted(unique_urls), stats


# ═══════════════════════════════════════════════════════════════════════════
# Response Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════

def fingerprint_response(body, status_code=200):
    """Generate a fingerprint for an HTTP response."""
    if not body:
        return None

    # Remove dynamic content
    cleaned = re.sub(r'\b\d{10,}\b', '{TIMESTAMP}', body)
    cleaned = re.sub(r'[a-f0-9]{32,}', '{TOKEN}', cleaned)
    cleaned = re.sub(r'"[^"]*\d{4}-\d{2}-\d{2}[^"]*"', '"{DATE}"', cleaned)

    # Extract structural features
    features = {
        "status": status_code,
        "length_bucket": len(body) // 100,  # Bucket by 100-byte increments
        "tag_count": len(re.findall(r'<[a-zA-Z]', body)),
        "has_form": 1 if '<form' in body.lower() else 0,
        "has_script": 1 if '<script' in body.lower() else 0,
        "title": re.search(r'<title>([^<]+)</title>', body, re.I),
    }

    if features["title"]:
        features["title"] = features["title"].group(1).strip()[:50]
    else:
        features["title"] = ""

    # Generate hash
    feature_str = json.dumps(features, sort_keys=True)
    return hashlib.sha256(feature_str.encode()).hexdigest()[:16]


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'='*60}")
    print(f"  Intelligent Deduplication Engine — {DOMAIN}")
    print(f"{'='*60}\n")

    if MODE in ("--urls", "--all"):
        # Dedup URLs
        all_urls = read_lines(OUT_URLS / "all_urls.txt")
        if all_urls:
            print(f"  [*] Deduplicating {len(all_urls)} URLs...")
            unique_urls, url_stats = dedup_urls(all_urls)

            # Write deduped URLs
            deduped_file = OUT_URLS / "all_urls_deduped.txt"
            with open(deduped_file, 'w') as f:
                f.write('\n'.join(unique_urls))

            print(f"  [+] URL dedup: {url_stats['original']} → {url_stats['final']} ({url_stats['reduction_pct']}% reduction)")
            print(f"      Stage 1 (normalize):  {url_stats['after_normalization']}")
            print(f"      Stage 2 (patterns):   {url_stats['after_pattern_dedup']}")
            print(f"      Stage 3 (simhash):    {url_stats['final']}")

        # Dedup JS URLs
        js_urls = read_lines(OUT_JS / "js_urls.txt")
        if js_urls:
            print(f"  [*] Deduplicating {len(js_urls)} JS URLs...")
            unique_js, js_stats = dedup_urls(js_urls)
            with open(OUT_JS / "js_urls_deduped.txt", 'w') as f:
                f.write('\n'.join(unique_js))
            print(f"  [+] JS dedup: {js_stats['original']} → {js_stats['final']} ({js_stats['reduction_pct']}% reduction)")

    # Save dedup statistics
    stats_file = OUT_INTEL / "dedup_stats.json"
    dedup_report = {
        "domain": DOMAIN,
        "urls": url_stats if 'url_stats' in dir() else {},
        "js": js_stats if 'js_stats' in dir() else {},
    }
    with open(stats_file, 'w') as f:
        json.dump(dedup_report, f, indent=2)

    print(f"\n{'─'*60}")
    print(f"  Deduplication complete")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
