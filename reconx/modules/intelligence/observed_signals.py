#!/usr/bin/env python3
"""
ReconX Ultra X — Observed Signals Engine
==========================================
Tracks REAL observable evidence about target behavior.
Every signal is backed by actual HTTP response data.

NOT URL pattern matching.
REAL behavioral observation.
"""
import json, os, re, sys, subprocess, hashlib
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: observed_signals.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
SIG_DIR = OUT / "observed_signals"
SIG_DIR.mkdir(parents=True, exist_ok=True)

def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except: return []

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None


class ObservedSignal:
    """A single observed signal with evidence."""
    def __init__(self, signal_type: str, source: str, url: str = ""):
        self.signal_type = signal_type
        self.source = source
        self.url = url
        self.observations = []
        self.evidence = []
        self.timestamp = datetime.now().isoformat()

    def observe(self, what: str, detail: str = "", raw: str = ""):
        self.observations.append({
            "what": what,
            "detail": detail,
            "raw": raw[:200] if raw else "",
            "timestamp": datetime.now().isoformat(),
        })

    def add_evidence(self, evidence_type: str, value: str, weight: int = 10):
        self.evidence.append({
            "type": evidence_type,
            "value": value[:300],
            "weight": weight,
        })

    def confidence_score(self) -> int:
        return min(sum(e["weight"] for e in self.evidence), 100)

    def confidence_sources(self) -> list:
        return [f"+{e['weight']} {e['type']}" for e in self.evidence]

    def to_dict(self) -> dict:
        return {
            "signal_type": self.signal_type,
            "source": self.source,
            "url": self.url,
            "observations": self.observations,
            "evidence": self.evidence,
            "confidence": self.confidence_score(),
            "confidence_sources": self.confidence_sources(),
            "timestamp": self.timestamp,
        }


# Max concurrent HTTP probes (prevents overloading target)
MAX_WORKERS = int(os.environ.get("RECONX_PROBE_WORKERS", "8"))


class SignalCollector:
    """Collects observed signals from all intelligence sources."""
    def __init__(self, domain: str):
        self.domain = domain
        self.signals: list[ObservedSignal] = []
        self._probe_count = 0

    def _probe_url(self, url: str, timeout: int = 5) -> dict:
        """Lightweight HTTP probe — extract real response data."""
        self._probe_count += 1
        try:
            result = subprocess.run(
                ["curl", "-sk", "-o", "/dev/null", "-w",
                 '{"status":%{http_code},"size":%{size_download},'
                 '"redirect":"%{redirect_url}","content_type":"%{content_type}",'
                 '"time":%{time_total}}',
                 "-m", str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 2)
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout.strip())
        except: pass
        return {}

    def _probe_batch(self, urls: list, timeout: int = 5) -> dict:
        """Probe multiple URLs in parallel. Returns {url: response_dict}."""
        results = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(self._probe_url, url, timeout): url
                       for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    results[url] = future.result()
                except: results[url] = {}
        return results

    def _fetch_headers(self, url: str, timeout: int = 8) -> dict:
        """Fetch response headers."""
        try:
            result = subprocess.run(
                ["curl", "-skI", "-m", str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 2)
            headers = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
            return headers
        except: pass
        return {}

    # ── Status Code Behavior ──────────────────────────────────────────
    def observe_status_behavior(self, urls: list):
        """Observe status code patterns — detect auth, redirects, errors."""
        print("    📡 Observing status code behavior...")
        for url in urls[:50]:
            resp = self._probe_url(url)
            if not resp: continue
            status = resp.get("status", 0)
            size = resp.get("size", 0)
            redir = resp.get("redirect", "")

            sig = ObservedSignal("status_behavior", "http_probe", url)

            if status == 200 and size > 100:
                sig.observe("accessible", f"200 OK, {size} bytes")
                sig.add_evidence("accessible_endpoint", f"Status 200, {size}B", 5)
            elif status == 403:
                sig.observe("forbidden", "403 Forbidden — access control present")
                sig.add_evidence("access_control", "403 response", 8)
            elif status == 401:
                sig.observe("auth_required", "401 Unauthorized")
                sig.add_evidence("auth_enforcement", "401 response", 10)
            elif status in (301, 302) and redir:
                sig.observe("redirect", f"Redirects to: {redir[:100]}")
                if "login" in redir.lower() or "auth" in redir.lower():
                    sig.add_evidence("auth_redirect", f"Redirects to login: {redir[:80]}", 12)
                else:
                    sig.add_evidence("redirect_behavior", f"→ {redir[:80]}", 5)
            elif status == 500:
                sig.observe("server_error", "500 Internal Server Error")
                sig.add_evidence("error_leakage", "Server error exposed", 15)

            if sig.observations:
                self.signals.append(sig)

    # ── Response Length Analysis ───────────────────────────────────────
    def observe_response_deltas(self, urls: list):
        """Observe response length changes for IDOR/auth testing."""
        print("    📏 Observing response deltas...")
        # Group URLs by path pattern (different IDs)
        patterns = defaultdict(list)
        for url in urls[:200]:
            parsed = urlparse(url)
            # Normalize: replace digits in path with {id}
            norm_path = re.sub(r'/\d+', '/{id}', parsed.path)
            patterns[norm_path].append(url)

        for pattern, group_urls in patterns.items():
            if len(group_urls) < 2: continue
            sizes = []
            for url in group_urls[:5]:
                resp = self._probe_url(url)
                if resp and resp.get("status") == 200:
                    sizes.append((url, resp.get("size", 0)))

            if len(sizes) >= 2:
                sig = ObservedSignal("response_delta", "http_probe", pattern)
                lengths = [s[1] for s in sizes]
                if len(set(lengths)) > 1:
                    sig.observe("size_variation",
                                f"Responses differ: {lengths}")
                    sig.add_evidence("response_delta",
                                    f"Size varies across IDs: {lengths}", 15)
                    sig.add_evidence("potential_idor",
                                    f"Different content per object ID", 20)
                else:
                    sig.observe("uniform_response",
                                f"Same size across IDs: {lengths[0]}")
                self.signals.append(sig)

    # ── Header Intelligence ───────────────────────────────────────────
    def observe_security_headers(self, urls: list):
        """Observe CSP, CORS, auth, cache headers."""
        print("    🔒 Observing security headers...")
        for url in urls[:20]:
            headers = self._fetch_headers(url)
            if not headers: continue

            sig = ObservedSignal("security_headers", "header_analysis", url)

            # CSP
            csp = headers.get("content-security-policy", "")
            if not csp:
                sig.observe("no_csp", "No Content-Security-Policy header")
                sig.add_evidence("weak_csp", "CSP header missing", 15)
            elif "unsafe-inline" in csp:
                sig.observe("weak_csp", f"CSP allows unsafe-inline: {csp[:80]}")
                sig.add_evidence("unsafe_inline_csp", "CSP permits inline scripts", 20)
            elif "unsafe-eval" in csp:
                sig.observe("weak_csp_eval", f"CSP allows unsafe-eval")
                sig.add_evidence("unsafe_eval_csp", "CSP permits eval()", 18)

            # CORS
            acao = headers.get("access-control-allow-origin", "")
            if acao == "*":
                sig.observe("open_cors", "CORS: Access-Control-Allow-Origin: *")
                sig.add_evidence("open_cors", "Wildcard CORS policy", 20)
            elif acao and acao != "null":
                sig.observe("cors_configured", f"CORS origin: {acao}")

            # Server/tech leakage
            server = headers.get("server", "")
            powered = headers.get("x-powered-by", "")
            if server:
                sig.observe("server_header", f"Server: {server}")
                sig.add_evidence("tech_leakage", f"Server header: {server}", 5)
            if powered:
                sig.observe("powered_by", f"X-Powered-By: {powered}")
                sig.add_evidence("tech_leakage", f"X-Powered-By: {powered}", 8)

            # Cache
            cache = headers.get("cache-control", "")
            if "no-store" not in cache and "private" not in cache:
                sig.observe("cacheable", f"Cache-Control: {cache or 'not set'}")
                sig.add_evidence("cache_poisoning_surface", "Response may be cached", 5)

            # Auth headers
            if headers.get("www-authenticate"):
                sig.observe("auth_header", f"WWW-Authenticate: {headers['www-authenticate'][:60]}")
                sig.add_evidence("auth_mechanism", "Auth header present", 5)

            if sig.observations:
                self.signals.append(sig)

    # ── Error Leakage ─────────────────────────────────────────────────
    def observe_error_leakage(self, urls: list):
        """Probe for stack traces and verbose errors."""
        print("    💥 Observing error leakage...")
        error_probes = [
            ("'", "quote_injection"),
            ("{{7*7}}", "ssti_probe"),
            ("<script>", "xss_probe"),
            ("../../../etc/passwd", "lfi_probe"),
        ]
        for url in urls[:15]:
            if "?" not in url: continue
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params: continue
            first_param = list(params.keys())[0]

            for payload, probe_type in error_probes[:2]:
                test_url = re.sub(
                    f"{first_param}=[^&]*",
                    f"{first_param}={payload}",
                    url)
                try:
                    result = subprocess.run(
                        ["curl", "-sk", "-m", "5", test_url],
                        capture_output=True, text=True, timeout=7)
                    body = result.stdout[:2000].lower()

                    sig = ObservedSignal("error_leakage", probe_type, url)

                    # Check for error signatures
                    error_patterns = [
                        (r"stack\s*trace|traceback|exception", "stack_trace", 20),
                        (r"sql\s*(syntax|error)|mysql|postgresql|sqlite|ora-\d+", "sql_error", 25),
                        (r"warning.*\bon line\b|fatal error|parse error", "php_error", 15),
                        (r"<pre>.*error.*</pre>|internal server error", "verbose_error", 12),
                        (r"django|laravel|express|flask|spring|asp\.net", "framework_error", 10),
                    ]

                    for pattern, etype, weight in error_patterns:
                        if re.search(pattern, body):
                            sig.observe(etype, f"Error pattern detected with {probe_type}")
                            sig.add_evidence(etype, f"Triggered by: {payload}", weight)

                    # Reflection check
                    if payload in result.stdout:
                        sig.observe("reflection", f"Input reflected in response")
                        sig.add_evidence("input_reflection",
                                        f"Payload reflected: {payload}", 15)

                    if sig.observations:
                        self.signals.append(sig)
                except: pass

    # ── Upload Behavior ───────────────────────────────────────────────
    def observe_upload_behavior(self, urls: list):
        """Observe upload endpoint behavior."""
        print("    📤 Observing upload behavior...")
        upload_urls = [u for u in urls if re.search(
            r"upload|attach|import|media|avatar|file|image", u, re.I)]

        for url in upload_urls[:10]:
            sig = ObservedSignal("upload_behavior", "endpoint_analysis", url)
            sig.observe("upload_endpoint", f"Upload endpoint detected: {url[:100]}")
            sig.add_evidence("upload_surface", "Upload endpoint exists", 15)

            # Check if endpoint accepts requests
            resp = self._probe_url(url)
            if resp:
                status = resp.get("status", 0)
                if status in (200, 201, 204):
                    sig.observe("upload_accessible", f"Upload returns {status}")
                    sig.add_evidence("upload_accessible", f"Returns {status}", 10)
                elif status == 405:
                    sig.observe("method_restricted", "POST/PUT required")
                    sig.add_evidence("upload_requires_post", "GET not allowed", 5)

            self.signals.append(sig)

    # ── GraphQL Behavior ──────────────────────────────────────────────
    def observe_graphql_behavior(self, urls: list):
        """Observe GraphQL endpoint behavior."""
        print("    📊 Observing GraphQL behavior...")
        gql_urls = [u for u in urls if re.search(r"graphql|gql", u, re.I)]

        for url in gql_urls[:5]:
            sig = ObservedSignal("graphql_behavior", "graphql_probe", url)
            sig.observe("graphql_endpoint", f"GraphQL detected: {url[:100]}")
            sig.add_evidence("graphql_surface", "GraphQL endpoint exists", 15)

            # Test introspection
            try:
                introspection = '{"query":"{ __schema { types { name } } }"}'
                result = subprocess.run(
                    ["curl", "-sk", "-m", "5",
                     "-H", "Content-Type: application/json",
                     "-d", introspection, url],
                    capture_output=True, text=True, timeout=7)
                body = result.stdout[:3000]

                if "__schema" in body or '"types"' in body:
                    sig.observe("introspection_enabled",
                                "GraphQL introspection is enabled")
                    sig.add_evidence("introspection_enabled",
                                    "Full schema queryable", 25)
                elif "error" in body.lower() and "introspection" in body.lower():
                    sig.observe("introspection_disabled",
                                "Introspection explicitly disabled")
                    sig.add_evidence("introspection_blocked",
                                    "Some security awareness", -5)
            except: pass

            self.signals.append(sig)

    # ── JWT Behavior ──────────────────────────────────────────────────
    def observe_jwt_behavior(self, urls: list):
        """Look for JWT tokens in responses and JS."""
        print("    🔑 Observing JWT/token behavior...")
        for url in urls[:20]:
            try:
                result = subprocess.run(
                    ["curl", "-sk", "-m", "5", url],
                    capture_output=True, text=True, timeout=7)
                body = result.stdout[:5000]

                # JWT pattern
                jwt_matches = re.findall(
                    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                    body)
                if jwt_matches:
                    sig = ObservedSignal("jwt_exposure", "response_analysis", url)
                    sig.observe("jwt_in_response",
                                f"JWT token found in response ({len(jwt_matches)} tokens)")
                    sig.add_evidence("jwt_exposure",
                                    f"JWT leaked in response body", 20)

                    # Try to decode header (base64)
                    try:
                        import base64
                        header = jwt_matches[0].split(".")[0]
                        header += "=" * (4 - len(header) % 4)
                        decoded = base64.b64decode(header).decode()
                        if '"alg"' in decoded:
                            sig.observe("jwt_algorithm", f"Header: {decoded[:100]}")
                            if '"none"' in decoded.lower():
                                sig.add_evidence("jwt_alg_none",
                                                "Algorithm 'none' — critical", 30)
                            elif '"hs256"' in decoded.lower():
                                sig.add_evidence("jwt_hs256",
                                                "HS256 — test weak secret", 10)
                    except: pass

                    self.signals.append(sig)
            except: pass

    # ── Run All Observations ──────────────────────────────────────────
    def collect_all(self) -> list:
        """Run all signal collection with progress tracking."""
        urls = rl(OUT / "urls/all_urls.txt")
        live = rl(OUT / "live/live_hosts.txt")
        param_urls = [u for u in urls if "?" in u]

        if not urls:
            print("  ⚪ No URLs to observe")
            return []

        total_urls = len(urls)
        print(f"    📋 {total_urls} URLs, {len(param_urls)} parameterized, {len(live)} live hosts")

        self.observe_security_headers(live[:10])
        self.observe_status_behavior(param_urls[:20])
        self.observe_response_deltas(param_urls[:50])
        self.observe_error_leakage(param_urls[:8])
        self.observe_upload_behavior(urls[:100])
        self.observe_graphql_behavior(urls[:50])
        self.observe_jwt_behavior(urls[:10])

        print(f"    📡 Total HTTP probes: {self._probe_count}")
        return self.signals

    def save(self):
        """Save all signals."""
        data = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "total_signals": len(self.signals),
            "signals": [s.to_dict() for s in self.signals],
            "summary": self._summarize(),
        }
        (SIG_DIR / "observed_signals.json").write_text(
            json.dumps(data, indent=2))

        # Human-readable
        lines = [
            "═" * 60,
            f"  📡 OBSERVED SIGNALS — {self.domain}",
            f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 60, "",
        ]
        for sig in self.signals:
            if not sig.observations: continue
            lines.append(f"  [{sig.signal_type}] {sig.url[:80]}")
            for obs in sig.observations:
                lines.append(f"    ✔ {obs['what']}: {obs['detail'][:80]}")
            for ev in sig.evidence:
                lines.append(f"    +{ev['weight']} {ev['type']}")
            lines.append(f"    Confidence: {sig.confidence_score()}%")
            lines.append("")

        (SIG_DIR / "observed_signals.txt").write_text("\n".join(lines))

    def _summarize(self) -> dict:
        """Summarize signal types."""
        summary = defaultdict(int)
        for s in self.signals:
            summary[s.signal_type] += 1
        return dict(summary)


def main():
    print(f"\n  📡 Observed Signals Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    collector = SignalCollector(DOMAIN)
    signals = collector.collect_all()
    collector.save()

    print(f"\n  📊 {len(signals)} signals observed")
    for stype, count in collector._summarize().items():
        print(f"    📡 {stype}: {count}")
    print(f"  💾 Signals → {SIG_DIR}/")


if __name__ == "__main__":
    main()
