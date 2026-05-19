#!/usr/bin/env python3
"""
ReconX Ultra — Response Similarity & Clustering Engine
=======================================================
Clusters duplicate endpoints, identifies framework-specific responses,
and reduces recon noise through response fingerprinting.

Outputs:
  - response_clusters.json
  - duplicate_endpoints.txt
  - unique_responses.txt
"""

import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else None
if not DOMAIN:
    print("Usage: response_cluster.py <domain>", file=sys.stderr)
    sys.exit(1)

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
OUT_LIVE = OUTPUT_DIR / "live"
OUT_URLS = OUTPUT_DIR / "urls"
OUT_INTEL = OUTPUT_DIR / "intelligence"
OUT_INTEL.mkdir(parents=True, exist_ok=True)

MAX_SAMPLE = 500


def read_lines(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def fetch_response(url):
    """Fetch URL and return status + body hash + features."""
    try:
        result = subprocess.run(
            ['curl', '-s', '-o', '-', '-w', '\n__META__%{http_code}|%{size_download}|%{content_type}',
             '--max-time', '8', '-L', url],
            capture_output=True, text=True, timeout=12
        )
        output = result.stdout
        meta_match = re.search(r'__META__(\d+)\|(\d+)\|(.*)$', output)
        if not meta_match:
            return None

        status = meta_match.group(1)
        size = int(meta_match.group(2))
        ctype = meta_match.group(3).strip()
        body = re.sub(r'__META__.*$', '', output)

        # Extract features for fingerprinting
        title = ""
        title_match = re.search(r'<title>([^<]+)</title>', body, re.I)
        if title_match:
            title = title_match.group(1).strip()[:100]

        # Remove dynamic content for hashing
        cleaned = re.sub(r'\b\d{10,}\b', '', body)
        cleaned = re.sub(r'[a-f0-9]{32,}', '', cleaned)
        cleaned = re.sub(r'nonce="[^"]*"', '', cleaned)
        cleaned = re.sub(r'csrf[^"]*"[^"]*"', '', cleaned)

        body_hash = hashlib.sha256(cleaned.encode('utf-8', errors='ignore')).hexdigest()[:16]
        size_bucket = size // 100

        fingerprint = f"{status}:{size_bucket}:{body_hash[:8]}"

        return {
            "url": url,
            "status": int(status),
            "size": size,
            "content_type": ctype,
            "title": title,
            "body_hash": body_hash,
            "fingerprint": fingerprint,
            "tag_count": len(re.findall(r'<[a-zA-Z]', body)),
            "has_form": '<form' in body.lower(),
            "has_login": bool(re.search(r'login|signin|password', body, re.I)),
        }
    except Exception:
        return None


def cluster_responses(responses):
    """Cluster responses by fingerprint similarity."""
    clusters = defaultdict(list)
    for resp in responses:
        clusters[resp["fingerprint"]].append(resp)

    # Identify significant clusters (duplicates)
    duplicate_clusters = {}
    unique_responses = []

    for fp, members in clusters.items():
        if len(members) > 1:
            duplicate_clusters[fp] = {
                "count": len(members),
                "status": members[0]["status"],
                "title": members[0]["title"],
                "urls": [m["url"] for m in members],
                "sample_size": members[0]["size"],
            }
        unique_responses.append(members[0])  # Keep one from each cluster

    return duplicate_clusters, unique_responses


def detect_framework_responses(responses):
    """Identify framework-specific default responses."""
    framework_patterns = {
        "WordPress": [r"wp-content", r"wordpress", r"wp-includes"],
        "Django": [r"csrfmiddlewaretoken", r"django", r"__debug__"],
        "Laravel": [r"laravel", r"csrf-token", r"app_name"],
        "Spring": [r"actuator", r"spring", r"whitelabel"],
        "Express": [r"express", r"X-Powered-By"],
        "React": [r"react-root", r"__NEXT_DATA__", r"_app"],
        "Angular": [r"ng-version", r"angular", r"ng-app"],
        "Vue": [r"v-app", r"vue", r"__vue__"],
        "Nginx Default": [r"Welcome to nginx"],
        "Apache Default": [r"Apache.*Server at"],
        "IIS Default": [r"IIS Windows Server"],
    }

    detected = defaultdict(list)
    for resp in responses:
        for framework, patterns in framework_patterns.items():
            if any(re.search(p, resp.get("title", ""), re.I) for p in patterns):
                detected[framework].append(resp["url"])

    return dict(detected)


def main():
    print(f"\n{'='*60}")
    print(f"  Response Similarity Engine — {DOMAIN}")
    print(f"{'='*60}\n")

    # Collect URLs to analyze
    urls = read_lines(OUT_LIVE / "live_hosts.txt")
    content_urls = read_lines(OUT_URLS / "all_urls.txt")

    # Sample for analysis
    sample_urls = urls[:MAX_SAMPLE]
    if content_urls:
        # Add some content URLs
        sample_urls.extend(content_urls[:MAX_SAMPLE - len(sample_urls)])
    sample_urls = list(set(sample_urls))[:MAX_SAMPLE]

    print(f"  [*] Analyzing {len(sample_urls)} URLs...")

    # Fetch responses in parallel
    responses = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(fetch_response, url): url for url in sample_urls}
        for future in as_completed(futures):
            result = future.result()
            if result:
                responses.append(result)

    print(f"  [+] {len(responses)} responses collected")

    if not responses:
        print("  [!] No responses — skipping clustering")
        return

    # Cluster responses
    print("  [*] Clustering by response similarity...")
    clusters, unique = cluster_responses(responses)
    print(f"  [+] {len(clusters)} duplicate clusters found")
    print(f"  [+] {len(unique)} unique response patterns")

    # Detect frameworks
    frameworks = detect_framework_responses(responses)
    if frameworks:
        print(f"  [+] Frameworks detected: {', '.join(frameworks.keys())}")

    # Save outputs
    with open(OUT_INTEL / "response_clusters.json", 'w') as f:
        json.dump({"clusters": clusters, "frameworks": frameworks}, f, indent=2)

    with open(OUT_INTEL / "duplicate_endpoints.txt", 'w') as f:
        for fp, data in sorted(clusters.items(), key=lambda x: -x[1]["count"]):
            f.write(f"\n# Cluster: {fp} ({data['count']} duplicates) | Status: {data['status']} | Title: {data['title']}\n")
            for url in data["urls"]:
                f.write(f"  {url}\n")

    with open(OUT_INTEL / "unique_responses.txt", 'w') as f:
        for resp in unique:
            f.write(f"[{resp['status']}] [{resp['size']}b] {resp['url']} | {resp['title']}\n")

    # Summary
    total_dupes = sum(c["count"] for c in clusters.values())
    reduction = round((total_dupes / len(responses)) * 100, 1) if responses else 0
    print(f"\n{'─'*60}")
    print(f"  Clustering Summary:")
    print(f"    Responses analyzed:   {len(responses)}")
    print(f"    Unique patterns:      {len(unique)}")
    print(f"    Duplicate clusters:   {len(clusters)}")
    print(f"    Noise reduction:      {reduction}%")
    print(f"    Frameworks detected:  {len(frameworks)}")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
