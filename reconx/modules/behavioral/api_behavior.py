#!/usr/bin/env python3
"""
ReconX Ultra X — API Behavior Intelligence Engine
===================================================
Understands API relationships, object patterns, auth requirements,
response structures, mutation behavior, and state transitions.
"""
import json, os, re, sys, subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: api_behavior.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
API_DIR = OUT / "behavioral"
API_DIR.mkdir(parents=True, exist_ok=True)

MAX_WORKERS = int(os.environ.get("RECONX_PROBE_WORKERS", "8"))


def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except:
        return []


def lj(f):
    try:
        return json.loads(Path(f).read_text())
    except:
        return None


class APIEndpoint:
    """Represents an observed API endpoint with behavioral data."""

    def __init__(self, url: str, method: str = "GET"):
        self.url = url
        self.method = method
        self.path = urlparse(url).path
        self.resource_type = ""
        self.auth_required = "unknown"
        self.response_type = ""
        self.response_size = 0
        self.has_pagination = False
        self.has_filtering = False
        self.has_relationships = False
        self.observations = []
        self.confidence = 0
        self.confidence_sources = []
        self.related_endpoints = []

    def observe(self, what: str, weight: int = 5):
        self.observations.append(what)
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {what}")

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "path": self.path,
            "resource_type": self.resource_type,
            "auth_required": self.auth_required,
            "response_type": self.response_type,
            "response_size": self.response_size,
            "has_pagination": self.has_pagination,
            "has_filtering": self.has_filtering,
            "observations": self.observations,
            "confidence": min(self.confidence, 100),
            "related_endpoints": self.related_endpoints[:5],
        }


def _probe_full(url: str) -> dict:
    """Probe and return status, headers, and body preview."""
    try:
        r = subprocess.run(
            ["curl", "-sk", "-D", "-", "-m", "5", url],
            capture_output=True, text=True, timeout=7)
        if r.returncode != 0:
            return {}

        raw = r.stdout
        header_section, _, body = raw.partition("\r\n\r\n")
        if not body:
            header_section, _, body = raw.partition("\n\n")

        status_match = re.search(r"HTTP/\S+\s+(\d+)", header_section)
        status = int(status_match.group(1)) if status_match else 0

        return {
            "status": status,
            "body_size": len(body),
            "is_json": body.strip()[:1] in ("{", "["),
            "is_xml": body.strip()[:1] == "<" and "xml" in body[:100].lower(),
            "body_preview": body[:500],
            "has_array": body.strip()[:1] == "[",
            "has_pagination": bool(re.search(r'"(page|limit|offset|cursor|next|prev)"', body[:1000])),
            "has_total": bool(re.search(r'"(total|count|total_count)"', body[:1000])),
        }
    except:
        return {}


class APIBehaviorEngine:
    """Understands API behavior patterns."""

    def __init__(self, domain: str):
        self.domain = domain
        self.endpoints = []
        self.api_groups = defaultdict(list)
        self.findings = []

    def discover_api_endpoints(self, urls: list):
        """Extract and classify API endpoints."""
        print("    🔌 Discovering API endpoints...")

        api_urls = [u for u in urls if re.search(
            r"/api/|/v\d+/|/rest/|/graphql|/gql", u, re.I)]

        for url in api_urls:
            parsed = urlparse(url)
            path = parsed.path

            ep = APIEndpoint(url)

            # Classify resource type
            resource_match = re.search(r"/(?:api|v\d+|rest)/(\w+)", path, re.I)
            if resource_match:
                ep.resource_type = resource_match.group(1).lower()

            # Detect query patterns
            params = parse_qs(parsed.query)
            if any(p in params for p in ["page", "limit", "offset", "per_page"]):
                ep.has_pagination = True
                ep.observe("Pagination parameters detected", 5)
            if any(p in params for p in ["filter", "search", "q", "sort", "order"]):
                ep.has_filtering = True
                ep.observe("Filtering/search parameters detected", 5)

            ep.observe(f"API endpoint: {ep.resource_type or path}", 5)
            self.endpoints.append(ep)

            # Group by resource
            if ep.resource_type:
                self.api_groups[ep.resource_type].append(ep)

    def probe_api_behavior(self):
        """Probe API endpoints for behavioral analysis."""
        print(f"    📡 Probing {min(len(self.endpoints), 25)} API endpoints...")

        def _probe_ep(ep):
            result = _probe_full(ep.url)
            if result:
                ep.response_size = result.get("body_size", 0)
                if result.get("is_json"):
                    ep.response_type = "json"
                    ep.observe("Returns JSON response", 5)
                elif result.get("is_xml"):
                    ep.response_type = "xml"
                    ep.observe("Returns XML response", 5)

                if result.get("status") == 200:
                    ep.auth_required = "no"
                    ep.observe("Accessible without authentication", 10)
                elif result.get("status") == 401:
                    ep.auth_required = "yes"
                    ep.observe("Requires authentication (401)", 3)
                elif result.get("status") == 403:
                    ep.auth_required = "yes"
                    ep.observe("Access forbidden (403)", 3)

                if result.get("has_array"):
                    ep.observe("Returns array — list endpoint", 5)
                if result.get("has_pagination"):
                    ep.has_pagination = True
                    ep.observe("Response contains pagination", 5)
                if result.get("has_total"):
                    ep.observe("Response includes total count", 8)

                # Check for sensitive data patterns
                body = result.get("body_preview", "")
                if re.search(r'"(email|password|ssn|credit_card|token)"', body, re.I):
                    ep.observe("Response contains sensitive field names", 20)
            return ep

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(_probe_ep, ep) for ep in self.endpoints[:25]]
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass

    def detect_crud_patterns(self):
        """Detect CRUD patterns (GET/POST/PUT/DELETE on same resource)."""
        print("    📝 Detecting CRUD patterns...")

        for resource, eps in self.api_groups.items():
            if len(eps) < 2:
                continue

            paths = set(ep.path for ep in eps)
            # Check if we have both list and detail endpoints
            has_list = any(ep.path.endswith(f"/{resource}") or
                          ep.path.endswith(f"/{resource}/")
                          for ep in eps)
            has_detail = any(re.search(rf"/{resource}/\d+", ep.path) for ep in eps)

            if has_list and has_detail:
                for ep in eps:
                    ep.observe(f"CRUD resource '{resource}' — list + detail endpoints", 10)
                    ep.related_endpoints = [e.url for e in eps if e.url != ep.url]

    def detect_relationship_patterns(self):
        """Detect nested/related API resources."""
        print("    🔗 Detecting API relationships...")

        for ep in self.endpoints:
            # Detect nested resources: /users/123/orders
            nested_match = re.search(r"/(\w+)/\d+/(\w+)", ep.path)
            if nested_match:
                parent = nested_match.group(1)
                child = nested_match.group(2)
                ep.observe(f"Nested resource: {parent} → {child}", 10)
                ep.has_relationships = True

                finding = {
                    "type": "nested_resource",
                    "parent": parent,
                    "child": child,
                    "url": ep.url,
                    "risk": "Test IDOR on parent ID to access child resources",
                }
                self.findings.append(finding)

    def run(self) -> list:
        urls = rl(OUT / "urls/all_urls.txt")
        if not urls:
            print("  ⚪ No URLs for API analysis")
            return []

        self.discover_api_endpoints(urls)
        self.probe_api_behavior()
        self.detect_crud_patterns()
        self.detect_relationship_patterns()

        self.endpoints.sort(key=lambda e: e.confidence, reverse=True)
        return self.endpoints

    def save(self):
        # Unauthed APIs
        unauthed = [e for e in self.endpoints if e.auth_required == "no" and e.response_size > 100]

        data = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "total_endpoints": len(self.endpoints),
            "unauthenticated_apis": len(unauthed),
            "resource_groups": {k: len(v) for k, v in self.api_groups.items()},
            "relationship_findings": self.findings,
            "endpoints": [e.to_dict() for e in self.endpoints[:100]],
        }
        (API_DIR / "api_behavior.json").write_text(json.dumps(data, indent=2))

        lines = [
            "═" * 64,
            f"  📡 API BEHAVIOR INTELLIGENCE — {self.domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 64, "",
            f"  Total API endpoints: {len(self.endpoints)}",
            f"  Unauthenticated: {len(unauthed)}",
            f"  Resource groups: {len(self.api_groups)}",
            "",
        ]

        if self.api_groups:
            lines.append("  ── API RESOURCES ──")
            for resource, eps in sorted(self.api_groups.items()):
                unauth = len([e for e in eps if e.auth_required == "no"])
                icon = "🔴" if unauth > 0 else "🟡"
                lines.append(f"    {icon} /{resource}: {len(eps)} endpoints ({unauth} unauthed)")

        if unauthed:
            lines.append("\n  ── UNAUTHENTICATED APIs (⚠ HIGH RISK) ──")
            for ep in unauthed[:10]:
                lines.append(f"    🔴 {ep.path} ({ep.response_size}B)")
                for o in ep.observations[:3]:
                    lines.append(f"       ✔ {o}")

        (API_DIR / "api_behavior.txt").write_text("\n".join(lines))


def main():
    print(f"\n  📡 API Behavior Intelligence — {DOMAIN}")
    print(f"  {'━' * 50}")

    engine = APIBehaviorEngine(DOMAIN)
    endpoints = engine.run()
    engine.save()

    unauthed = [e for e in endpoints if e.auth_required == "no" and e.response_size > 100]
    print(f"\n  📊 {len(endpoints)} API endpoints ({len(unauthed)} unauthenticated):")
    for resource, eps in sorted(engine.api_groups.items()):
        print(f"    📡 /{resource}: {len(eps)} endpoints")
    print(f"  💾 API Intel → {API_DIR}/")


if __name__ == "__main__":
    main()
