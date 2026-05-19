#!/usr/bin/env python3
"""
ReconX Ultra X — State Differential Engine
=============================================
Compares responses, DOM, auth state, API responses, and object visibility
across different conditions to detect hidden functionality,
role-based exposure, and auth bypass indicators.
"""
import json, os, re, sys, subprocess, hashlib
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: state_diff_engine.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
DIFF_DIR = OUT / "behavioral"
DIFF_DIR.mkdir(parents=True, exist_ok=True)

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


class StateDiff:
    """A state differential finding."""

    def __init__(self, diff_type: str, url: str = ""):
        self.diff_type = diff_type
        self.url = url
        self.state_a = {}
        self.state_b = {}
        self.delta = {}
        self.observations = []
        self.predictions = []
        self.confidence = 0
        self.confidence_sources = []
        self.risk = "MEDIUM"

    def observe(self, what: str, weight: int = 10):
        self.observations.append(what)
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {what}")

    def predict(self, what: str):
        self.predictions.append(what)

    def to_dict(self) -> dict:
        return {
            "diff_type": self.diff_type,
            "url": self.url,
            "delta": self.delta,
            "observations": self.observations,
            "predictions": self.predictions,
            "confidence": min(self.confidence, 100),
            "confidence_sources": self.confidence_sources,
            "risk": self.risk,
        }


def _probe_response(url: str) -> dict:
    """Get response fingerprint for comparison."""
    try:
        r = subprocess.run(
            ["curl", "-sk", "-D", "-", "-m", "5", url],
            capture_output=True, text=True, timeout=7)
        if r.returncode != 0:
            return {}

        raw = r.stdout
        header_sec, _, body = raw.partition("\r\n\r\n")
        if not body:
            header_sec, _, body = raw.partition("\n\n")

        status_match = re.search(r"HTTP/\S+\s+(\d+)", header_sec)
        status = int(status_match.group(1)) if status_match else 0

        headers = {}
        for line in header_sec.splitlines()[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        body_hash = hashlib.sha256(body[:5000].encode()).hexdigest()[:16]

        # Extract keywords
        keywords = set(re.findall(r'"(\w+)"', body[:2000]))

        return {
            "status": status,
            "size": len(body),
            "hash": body_hash,
            "headers": headers,
            "content_type": headers.get("content-type", ""),
            "keywords": list(keywords)[:20],
            "has_form": bool(re.search(r"<form|<input", body, re.I)),
            "has_json": body.strip()[:1] in ("{", "["),
            "links_count": len(re.findall(r'href="[^"]*"', body)),
        }
    except:
        return {}


class StateDiffEngine:
    """Compares states across different conditions."""

    def __init__(self, domain: str):
        self.domain = domain
        self.diffs = []

    def compare_method_responses(self, urls: list):
        """Compare GET vs POST vs other methods."""
        print("    🔄 Comparing HTTP method responses...")

        api_urls = [u for u in urls if re.search(r"/api/|/v\d+/|/rest/", u, re.I)][:15]

        for url in api_urls:
            get_resp = _probe_response(url)
            if not get_resp:
                continue

            # Try POST
            try:
                r = subprocess.run(
                    ["curl", "-sk", "-X", "POST", "-D", "-", "-m", "5", url],
                    capture_output=True, text=True, timeout=7)
                raw = r.stdout
                header_sec, _, body = raw.partition("\r\n\r\n")
                if not body:
                    header_sec, _, body = raw.partition("\n\n")
                status_match = re.search(r"HTTP/\S+\s+(\d+)", header_sec)
                post_status = int(status_match.group(1)) if status_match else 0
                post_size = len(body)
            except:
                continue

            if get_resp["status"] != post_status:
                diff = StateDiff("method_differential", url)
                diff.observe(f"GET returns {get_resp['status']}, POST returns {post_status}", 10)

                if get_resp["status"] == 200 and post_status == 200:
                    diff.observe("Both methods return 200 — mutation possible", 15)
                    diff.predict("POST may modify server state without CSRF protection")
                    diff.risk = "HIGH"
                elif get_resp["status"] in (401, 403) and post_status == 200:
                    diff.observe(f"GET blocked ({get_resp['status']}) but POST succeeds", 25)
                    diff.predict("Auth bypass via method switching")
                    diff.risk = "CRITICAL"

                if diff.confidence >= 10:
                    self.diffs.append(diff)

    def compare_response_headers(self, urls: list):
        """Detect header inconsistencies across endpoints."""
        print("    📋 Comparing response headers...")

        results = {}
        def _probe(url):
            return url, _probe_response(url)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(_probe, u): u for u in urls[:20]}
            for future in as_completed(futures):
                try:
                    url, result = future.result()
                    if result:
                        results[url] = result
                except:
                    pass

        # Compare security headers across endpoints
        csp_endpoints = defaultdict(list)
        cors_endpoints = defaultdict(list)

        for url, resp in results.items():
            csp = resp["headers"].get("content-security-policy", "none")
            cors = resp["headers"].get("access-control-allow-origin", "none")
            csp_endpoints[csp].append(url)
            cors_endpoints[cors].append(url)

        # Inconsistent CSP
        if len(csp_endpoints) > 1 and "none" in csp_endpoints:
            diff = StateDiff("header_inconsistency", "multiple")
            with_csp = sum(len(v) for k, v in csp_endpoints.items() if k != "none")
            without_csp = len(csp_endpoints.get("none", []))
            diff.observe(f"CSP inconsistent: {with_csp} with CSP, {without_csp} without", 15)
            diff.predict("CSP bypass via endpoints without CSP")
            diff.delta = {
                "with_csp": with_csp,
                "without_csp": without_csp,
                "sample_no_csp": csp_endpoints.get("none", [])[:3],
            }
            self.diffs.append(diff)

        # Wildcard CORS
        if "*" in cors_endpoints:
            diff = StateDiff("cors_differential", "multiple")
            diff.observe(f"CORS wildcard on {len(cors_endpoints['*'])} endpoints", 15)
            diff.predict("Cross-origin data theft possible")
            diff.risk = "HIGH"
            diff.delta = {"wildcard_endpoints": cors_endpoints["*"][:5]}
            self.diffs.append(diff)

    def compare_error_behavior(self, urls: list):
        """Compare normal vs error responses for info leakage."""
        print("    💥 Comparing error behavior...")

        param_urls = [u for u in urls if "?" in u][:10]

        for url in param_urls:
            normal = _probe_response(url)
            if not normal:
                continue

            # Trigger error with malformed input
            error_url = re.sub(r"=([^&]*)", "='OR+1=1--", url, count=1)
            error_resp = _probe_response(error_url)
            if not error_resp:
                continue

            if normal["hash"] != error_resp.get("hash"):
                diff = StateDiff("error_delta", url)
                size_delta = abs(normal["size"] - error_resp.get("size", 0))

                diff.observe(f"Response changes with error input (delta: {size_delta}B)", 15)
                diff.delta = {
                    "normal_size": normal["size"],
                    "error_size": error_resp.get("size", 0),
                    "normal_status": normal["status"],
                    "error_status": error_resp.get("status", 0),
                }

                if normal["status"] != error_resp.get("status", 0):
                    diff.observe(f"Status changes: {normal['status']} → {error_resp.get('status', 0)}", 15)

                if error_resp.get("size", 0) > normal["size"] + 200:
                    diff.observe("Error response larger than normal — possible stack trace", 20)
                    diff.predict("Verbose error messages may leak implementation details")
                    diff.risk = "HIGH"

                if diff.confidence >= 15:
                    self.diffs.append(diff)

    def run(self) -> list:
        urls = rl(OUT / "urls/all_urls.txt")
        if not urls:
            print("  ⚪ No URLs for state diff analysis")
            return []

        self.compare_method_responses(urls)
        self.compare_response_headers(urls)
        self.compare_error_behavior(urls)

        self.diffs.sort(key=lambda d: d.confidence, reverse=True)
        return self.diffs

    def save(self):
        data = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "total_diffs": len(self.diffs),
            "diffs": [d.to_dict() for d in self.diffs],
        }
        (DIFF_DIR / "state_diffs.json").write_text(json.dumps(data, indent=2))

        lines = [
            "═" * 64,
            f"  🔬 STATE DIFFERENTIAL ANALYSIS — {self.domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 64, "",
        ]
        for d in self.diffs:
            dd = d.to_dict()
            icon = "🔴" if dd["risk"] == "CRITICAL" else "🟠" if dd["risk"] == "HIGH" else "🟡"
            lines.append(f"  {icon} {dd['diff_type'].upper()}")
            lines.append(f"  URL: {dd['url'][:70]}")
            for o in dd["observations"]:
                lines.append(f"    ✔ {o}")
            for p in dd["predictions"]:
                lines.append(f"    ⚠ {p}")
            lines.append(f"  Confidence: {dd['confidence']}%")
            lines.append("")

        (DIFF_DIR / "state_diffs.txt").write_text("\n".join(lines))


def main():
    print(f"\n  🔬 State Differential Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    engine = StateDiffEngine(DOMAIN)
    diffs = engine.run()
    engine.save()

    print(f"\n  📊 {len(diffs)} state differentials detected:")
    for d in diffs[:8]:
        dd = d.to_dict()
        icon = "🔴" if dd["risk"] == "CRITICAL" else "🟠" if dd["risk"] == "HIGH" else "🟡"
        print(f"    {icon} {dd['diff_type']:25s} {dd['confidence']:3d}%")
    print(f"  💾 State Diffs → {DIFF_DIR}/")


if __name__ == "__main__":
    main()
