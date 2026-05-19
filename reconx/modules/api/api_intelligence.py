#!/usr/bin/env python3
"""
ReconX Ultra — Advanced API Intelligence Engine
=================================================
Detects REST APIs, GraphQL, Swagger/OpenAPI, mobile APIs, internal APIs.
Uses JS extraction + runtime patterns + custom api.txt wordlist.

Outputs:
  - api_inventory.json (comprehensive)
  - graphql_endpoints.txt
  - swagger_specs.txt
  - api_routes_discovered.txt
"""

import json
import re
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else None
if not DOMAIN:
    print("Usage: api_intelligence.py <domain>", file=sys.stderr)
    sys.exit(1)

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
OUT_LIVE = OUTPUT_DIR / "live"
OUT_URLS = OUTPUT_DIR / "urls"
OUT_JS = OUTPUT_DIR / "js"
OUT_INTEL = OUTPUT_DIR / "intelligence"
OUT_SCANS = OUTPUT_DIR / "scans"
WORDLISTS = RECONX_ROOT / "wordlists"
OUT_INTEL.mkdir(parents=True, exist_ok=True)


def read_lines(fp):
    try:
        with open(fp, 'r', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def load_json(fp):
    try:
        with open(fp) as f:
            return json.load(f)
    except:
        return None


def probe_url(url):
    """Probe a URL and return status + content-type."""
    try:
        result = subprocess.run(
            ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}|%{content_type}',
             '--max-time', '5', url],
            capture_output=True, text=True, timeout=8
        )
        parts = result.stdout.strip().split('|')
        if len(parts) >= 2:
            return int(parts[0]), parts[1]
    except:
        pass
    return 0, ""


# ═══════════════════════════════════════════════════════════════════════════
# API Discovery Functions
# ═══════════════════════════════════════════════════════════════════════════

def discover_graphql(live_hosts):
    """Detect GraphQL endpoints."""
    print("[*] Detecting GraphQL endpoints...")
    graphql_paths = [
        "/graphql", "/graphiql", "/playground", "/gql", "/api/graphql",
        "/v1/graphql", "/v2/graphql", "/_graphql", "/query",
        "/graphql/console", "/altair", "/voyager",
    ]
    found = []
    for host in live_hosts[:50]:
        host = host.rstrip('/')
        for path in graphql_paths:
            status, ctype = probe_url(f"{host}{path}")
            if status in (200, 301, 302, 401, 403):
                found.append({"url": f"{host}{path}", "status": status})
                # Test introspection
                if status == 200:
                    try:
                        intro_result = subprocess.run(
                            ['curl', '-s', '--max-time', '5', '-X', 'POST',
                             '-H', 'Content-Type: application/json',
                             '-d', '{"query":"{ __schema { types { name } } }"}',
                             f"{host}{path}"],
                            capture_output=True, text=True, timeout=8
                        )
                        if '__schema' in intro_result.stdout or 'types' in intro_result.stdout:
                            found[-1]["introspection"] = True
                    except:
                        pass
    return found


def discover_swagger(live_hosts):
    """Detect Swagger/OpenAPI specs."""
    print("[*] Detecting Swagger/OpenAPI endpoints...")
    swagger_paths = [
        "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
        "/api-docs", "/api-docs/swagger.json", "/openapi.json",
        "/openapi.yaml", "/v2/api-docs", "/v3/api-docs",
        "/swagger-resources", "/api/swagger.json", "/api/openapi.json",
        "/docs", "/redoc", "/api/docs", "/_catalog",
    ]
    found = []
    for host in live_hosts[:50]:
        host = host.rstrip('/')
        for path in swagger_paths:
            status, ctype = probe_url(f"{host}{path}")
            if status in (200, 301, 302):
                entry = {"url": f"{host}{path}", "status": status}
                if 'json' in ctype or 'yaml' in ctype:
                    entry["spec_found"] = True
                found.append(entry)
    return found


def discover_rest_apis(all_urls, live_hosts):
    """Identify REST API endpoints from URLs."""
    print("[*] Identifying REST API endpoints...")
    api_patterns = [
        (r'/api/v\d+/', "versioned_api"),
        (r'/api/', "api_root"),
        (r'/rest/', "rest_api"),
        (r'/v\d+/\w+', "versioned_endpoint"),
        (r'/api/\w+/\w+', "api_resource"),
    ]
    apis = defaultdict(set)
    for url in all_urls:
        for pattern, api_type in api_patterns:
            if re.search(pattern, url, re.I):
                apis[api_type].add(url)
    return {k: sorted(v)[:200] for k, v in apis.items()}


def discover_from_js(js_endpoints_file):
    """Extract API endpoints from JS analysis results."""
    print("[*] Extracting APIs from JS intelligence...")
    js_data = load_json(js_endpoints_file)
    if not js_data:
        return {}
    apis = {}
    for category, endpoints in js_data.items():
        if isinstance(endpoints, list):
            api_eps = [e for e in endpoints if re.search(r'/api|/v\d|graphql|rest', str(e), re.I)]
            if api_eps:
                apis[f"js_{category}"] = api_eps[:100]
    return apis


def discover_actuator(live_hosts):
    """Detect Spring Boot Actuator endpoints."""
    print("[*] Detecting Spring Boot Actuator...")
    actuator_paths = [
        "/actuator", "/actuator/health", "/actuator/info",
        "/actuator/env", "/actuator/beans", "/actuator/metrics",
        "/actuator/mappings", "/actuator/configprops",
        "/actuator/heapdump", "/actuator/threaddump",
    ]
    found = []
    for host in live_hosts[:30]:
        host = host.rstrip('/')
        for path in actuator_paths:
            status, ctype = probe_url(f"{host}{path}")
            if status == 200:
                found.append({"url": f"{host}{path}", "status": status})
    return found


def main():
    print(f"\n{'='*60}")
    print(f"  Advanced API Intelligence — {DOMAIN}")
    print(f"{'='*60}\n")

    live_hosts = read_lines(OUT_LIVE / "live_hosts.txt")
    all_urls = read_lines(OUT_URLS / "all_urls.txt")

    if not live_hosts:
        print("  [!] No live hosts — skipping API discovery")
        return

    inventory = {
        "domain": DOMAIN,
        "graphql_endpoints": [],
        "swagger_specs": [],
        "rest_apis": {},
        "js_extracted_apis": {},
        "actuator_endpoints": [],
        "websocket_endpoints": [],
        "mobile_api_hints": [],
    }

    # GraphQL
    graphql = discover_graphql(live_hosts)
    inventory["graphql_endpoints"] = graphql
    with open(OUT_INTEL / "graphql_endpoints.txt", 'w') as f:
        for ep in graphql:
            intro = " [INTROSPECTION]" if ep.get("introspection") else ""
            f.write(f"[{ep['status']}] {ep['url']}{intro}\n")

    # Swagger/OpenAPI
    swagger = discover_swagger(live_hosts)
    inventory["swagger_specs"] = swagger
    with open(OUT_INTEL / "swagger_specs.txt", 'w') as f:
        for ep in swagger:
            spec = " [SPEC]" if ep.get("spec_found") else ""
            f.write(f"[{ep['status']}] {ep['url']}{spec}\n")

    # REST APIs
    rest = discover_rest_apis(all_urls, live_hosts)
    inventory["rest_apis"] = rest

    # JS-extracted APIs
    js_apis = discover_from_js(OUT_INTEL / "js_endpoints.json")
    inventory["js_extracted_apis"] = js_apis

    # Actuator
    actuator = discover_actuator(live_hosts)
    inventory["actuator_endpoints"] = actuator

    # WebSocket detection
    ws_urls = [u for u in all_urls if re.search(r'wss?://', u, re.I)]
    inventory["websocket_endpoints"] = ws_urls[:50]

    # Mobile API hints
    mobile_hints = [u for u in all_urls if re.search(r'/mobile|/app/api|/m/api|/ios|/android', u, re.I)]
    inventory["mobile_api_hints"] = mobile_hints[:50]

    # Save
    with open(OUT_INTEL / "api_inventory.json", 'w') as f:
        json.dump(inventory, f, indent=2)

    # Combined route list
    with open(OUT_INTEL / "api_routes_discovered.txt", 'w') as f:
        for ep in graphql:
            f.write(f"[GRAPHQL] {ep['url']}\n")
        for ep in swagger:
            f.write(f"[SWAGGER] {ep['url']}\n")
        for api_type, urls in rest.items():
            for url in urls[:50]:
                f.write(f"[REST:{api_type}] {url}\n")
        for ep in actuator:
            f.write(f"[ACTUATOR] {ep['url']}\n")

    # Summary
    total = len(graphql) + len(swagger) + sum(len(v) for v in rest.values()) + len(actuator)
    print(f"\n{'─'*60}")
    print(f"  API Intelligence Summary:")
    print(f"    GraphQL endpoints:    {len(graphql)}")
    print(f"    Swagger/OpenAPI:      {len(swagger)}")
    print(f"    REST API patterns:    {sum(len(v) for v in rest.values())}")
    print(f"    JS-extracted APIs:    {sum(len(v) for v in js_apis.values())}")
    print(f"    Actuator endpoints:   {len(actuator)}")
    print(f"    WebSocket endpoints:  {len(ws_urls)}")
    print(f"    Mobile API hints:     {len(mobile_hints)}")
    print(f"    Total API surface:    {total}")
    if any(e.get("introspection") for e in graphql):
        print(f"    \033[1;31m⚠  GraphQL introspection ENABLED!\033[0m")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
