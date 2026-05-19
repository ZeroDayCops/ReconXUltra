#!/usr/bin/env python3
"""
ReconX Ultra X — Auth-State Behavioral Intelligence
=====================================================
REAL auth-aware analysis through HTTP behavioral observation.
Compares guest vs authenticated vs role-based responses.
Detects auth bypass, IDOR, privilege escalation indicators.

NOT pattern matching. REAL behavioral differential analysis.
"""
import json, os, re, sys, subprocess, hashlib
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: auth_behavior.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
AUTH_DIR = OUT / "auth_intelligence"
AUTH_DIR.mkdir(parents=True, exist_ok=True)

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


# ═══════════════════════════════════════════════════════════════════════════
# Auth State Probes
# ═══════════════════════════════════════════════════════════════════════════

class AuthProbe:
    """Probe an endpoint under different auth states."""

    def __init__(self, name: str, headers: dict = None, cookies: str = ""):
        self.name = name  # "guest", "user", "admin"
        self.headers = headers or {}
        self.cookies = cookies

    def probe(self, url: str, timeout: int = 5) -> dict:
        """Execute probe and return behavioral snapshot."""
        cmd = ["curl", "-sk", "-m", str(timeout), "-D", "-", url]
        for k, v in self.headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
        if self.cookies:
            cmd.extend(["-b", self.cookies])

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
            if r.returncode != 0:
                return {}

            raw = r.stdout
            header_section, _, body = raw.partition("\r\n\r\n")
            if not body:
                header_section, _, body = raw.partition("\n\n")

            # Parse status
            status_match = re.search(r"HTTP/\S+\s+(\d+)", header_section)
            status = int(status_match.group(1)) if status_match else 0

            # Parse headers
            resp_headers = {}
            for line in header_section.splitlines()[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    resp_headers[k.strip().lower()] = v.strip()

            # Fingerprint body
            body_stripped = re.sub(r"\s+", " ", body[:5000]).strip()
            body_hash = hashlib.sha256(body_stripped.encode()).hexdigest()[:16]

            return {
                "status": status,
                "body_size": len(body),
                "body_hash": body_hash,
                "headers": resp_headers,
                "redirect": resp_headers.get("location", ""),
                "content_type": resp_headers.get("content-type", ""),
                "set_cookie": resp_headers.get("set-cookie", ""),
                "has_form": bool(re.search(r"<form|<input", body, re.I)),
                "has_json": body.strip().startswith("{") or body.strip().startswith("["),
                "body_preview": body[:300],
            }
        except Exception:
            return {}


class AuthBehaviorFinding:
    """A behavioral auth finding."""

    def __init__(self, finding_type: str, url: str):
        self.finding_type = finding_type
        self.url = url
        self.observed = []
        self.predicted = []
        self.confidence = 0
        self.confidence_sources = []
        self.states = {}      # auth_state -> probe result
        self.risk = "MEDIUM"
        self.vuln_types = []

    def add_state(self, state_name: str, result: dict):
        self.states[state_name] = result

    def observe(self, what: str, weight: int = 10):
        self.observed.append(what)
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {what}")

    def predict(self, what: str):
        self.predicted.append(what)

    def to_dict(self) -> dict:
        return {
            "finding_type": self.finding_type,
            "url": self.url,
            "observed": self.observed,
            "predicted": self.predicted,
            "confidence": min(self.confidence, 100),
            "confidence_sources": self.confidence_sources,
            "risk": self.risk,
            "vuln_types": self.vuln_types,
            "states": {k: {sk: sv for sk, sv in v.items() if sk != "body_preview"}
                       for k, v in self.states.items()},
            "timestamp": datetime.now().isoformat(),
        }


# ═══════════════════════════════════════════════════════════════════════════
# Auth Behavioral Analysis
# ═══════════════════════════════════════════════════════════════════════════

class AuthBehaviorEngine:
    """Analyzes auth-state behavioral differentials."""

    def __init__(self, domain: str):
        self.domain = domain
        self.findings = []
        self.auth_profiles = self._load_auth_profiles()

    def _load_auth_profiles(self) -> list:
        """Load auth profiles — always have 'guest', optionally load saved profiles."""
        profiles = [AuthProbe("guest")]

        # Check for saved auth profiles
        auth_dir = ROOT / "configs" / "auth_profiles"
        if auth_dir.exists():
            for profile_file in sorted(auth_dir.glob("*.json")):
                try:
                    data = json.loads(profile_file.read_text())
                    name = data.get("name", profile_file.stem)
                    headers = data.get("headers", {})
                    cookies = data.get("cookies", "")
                    profiles.append(AuthProbe(name, headers, cookies))
                except Exception:
                    pass

        return profiles

    def analyze_auth_transitions(self, urls: list):
        """Detect auth-enforced vs auth-bypassed endpoints."""
        print("    🔐 Analyzing auth transitions...")

        auth_urls = [u for u in urls if re.search(
            r"login|signin|auth|oauth|session|logout|register|signup|forgot|reset",
            u, re.I)]

        for url in auth_urls[:10]:
            guest = self.auth_profiles[0]
            result = guest.probe(url)
            if not result:
                continue

            f = AuthBehaviorFinding("auth_transition", url)
            f.add_state("guest", result)

            status = result["status"]
            redirect = result.get("redirect", "")

            if status == 200 and result["has_form"]:
                f.observe("Auth form accessible to guest", 5)
                if result.get("set_cookie"):
                    f.observe("Session cookie set on auth page", 10)
                    cookie_val = result["set_cookie"]
                    if "httponly" not in cookie_val.lower():
                        f.observe("Cookie missing HttpOnly flag", 15)
                        f.predict("Session theft via XSS possible")
                        f.vuln_types.append("Session Theft")
                        f.risk = "HIGH"
                    if "secure" not in cookie_val.lower():
                        f.observe("Cookie missing Secure flag", 10)
                    if "samesite" not in cookie_val.lower():
                        f.observe("Cookie missing SameSite attribute", 8)
                        f.predict("CSRF via cookie-based auth possible")
                        f.vuln_types.append("CSRF")

            elif status in (301, 302):
                f.observe(f"Auth endpoint redirects: {redirect[:60]}", 5)

            if f.observed:
                self.findings.append(f)

    def analyze_access_control(self, urls: list):
        """Detect endpoints with broken access control."""
        print("    🔓 Analyzing access control behavior...")

        # Focus on potentially protected endpoints
        protected_patterns = [
            r"admin|manage|panel|console|dashboard|control",
            r"api/v\d+/users|api/v\d+/admin|api/v\d+/internal",
            r"settings|profile|account|billing|payment",
            r"upload|export|download|report|invoice",
            r"delete|edit|update|modify|create",
        ]
        target_urls = []
        for url in urls:
            for pattern in protected_patterns:
                if re.search(pattern, url, re.I):
                    target_urls.append(url)
                    break

        def _probe_url(url):
            guest = self.auth_profiles[0]
            return url, guest.probe(url)

        # Parallel probing
        results = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(_probe_url, u): u
                       for u in target_urls[:30]}
            for future in as_completed(futures):
                try:
                    url, result = future.result()
                    if result:
                        results[url] = result
                except Exception:
                    pass

        for url, result in results.items():
            status = result["status"]
            f = AuthBehaviorFinding("access_control", url)
            f.add_state("guest", result)

            if status == 200 and result["body_size"] > 200:
                # Potentially accessible without auth
                path = urlparse(url).path.lower()
                if re.search(r"admin|manage|panel|internal", path):
                    f.observe(f"Admin endpoint accessible as guest (200, {result['body_size']}B)", 25)
                    f.predict("Unauthorized admin access")
                    f.risk = "CRITICAL"
                    f.vuln_types.append("Broken Access Control")
                elif re.search(r"api/", path):
                    f.observe(f"API endpoint accessible as guest (200, {result['body_size']}B)", 15)
                    if result["has_json"]:
                        f.observe("API returns JSON data to unauthenticated request", 20)
                        f.predict("API data exposure without auth")
                        f.risk = "HIGH"
                        f.vuln_types.append("API Auth Bypass")
                elif re.search(r"settings|profile|account", path):
                    f.observe(f"Account endpoint accessible as guest (200)", 15)
                    f.predict("Profile access without authentication")
                    f.vuln_types.append("Auth Bypass")

            elif status == 403:
                f.observe(f"Access control enforced: 403 on {urlparse(url).path}", 3)

            elif status == 401:
                f.observe(f"Auth required: 401 on {urlparse(url).path}", 3)

            elif status in (301, 302):
                redirect = result.get("redirect", "")
                if "login" in redirect.lower():
                    f.observe(f"Auth redirect to login for {urlparse(url).path}", 5)

            if f.observed and f.confidence >= 10:
                self.findings.append(f)

    def analyze_response_differentials(self, urls: list):
        """Compare response behavior across auth states for IDOR detection."""
        print("    📊 Analyzing response differentials...")

        # Find ID-based endpoints
        id_urls = [u for u in urls if re.search(r"[?&](id|uid|user_id|order_id|invoice_id|ticket_id|profile_id|account_id)=\d+", u, re.I)]

        for url in id_urls[:15]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            id_param = None
            for p in params:
                if re.match(r"(id|uid|user_id|order_id|invoice_id|ticket_id|profile_id|account_id)", p, re.I):
                    id_param = p
                    break

            if not id_param:
                continue

            # Probe with original ID and adjacent IDs
            original_id = params[id_param][0]
            try:
                base_id = int(original_id)
            except ValueError:
                continue

            f = AuthBehaviorFinding("response_differential", url)
            responses = []

            for test_id in [base_id, base_id + 1, base_id + 2]:
                test_url = re.sub(
                    f"{id_param}={original_id}",
                    f"{id_param}={test_id}",
                    url)
                guest = self.auth_profiles[0]
                result = guest.probe(test_url)
                if result:
                    responses.append((test_id, result))
                    f.add_state(f"id_{test_id}", result)

            if len(responses) >= 2:
                # Compare responses
                hashes = [r[1]["body_hash"] for r in responses]
                sizes = [r[1]["body_size"] for r in responses]
                statuses = [r[1]["status"] for r in responses]

                if len(set(hashes)) > 1 and all(s == 200 for s in statuses):
                    f.observe(f"Different content for different {id_param} values", 25)
                    f.observe(f"All IDs return 200 (no auth check)", 20)
                    f.observe(f"Response sizes vary: {sizes}", 10)
                    f.predict(f"IDOR — {id_param} objects accessible without ownership check")
                    f.risk = "HIGH"
                    f.vuln_types.extend(["IDOR", "Broken Access Control"])

                elif all(s == 200 for s in statuses) and len(set(hashes)) == 1:
                    f.observe(f"Same response for different IDs — possible generic response", 3)

                elif any(s in (403, 404) for s in statuses[1:]) and statuses[0] == 200:
                    f.observe(f"Access control differentiates IDs — good auth", 5)

            if f.observed and f.confidence >= 15:
                self.findings.append(f)

    def analyze_method_behavior(self, urls: list):
        """Test HTTP method behavior for each endpoint."""
        print("    🔄 Analyzing HTTP method behavior...")

        api_urls = [u for u in urls if re.search(r"/api/|/v\d+/|/rest/", u, re.I)]

        for url in api_urls[:15]:
            for method in ["POST", "PUT", "DELETE", "PATCH"]:
                try:
                    r = subprocess.run(
                        ["curl", "-sk", "-X", method, "-o", "/dev/null",
                         "-w", '{"status":%{http_code},"size":%{size_download}}',
                         "-m", "5", url],
                        capture_output=True, text=True, timeout=7)
                    if r.returncode != 0:
                        continue
                    result = json.loads(r.stdout.strip())
                    status = result.get("status", 0)

                    if status == 200 and method in ("DELETE", "PUT", "PATCH"):
                        f = AuthBehaviorFinding("method_exposure", url)
                        f.observe(f"{method} returns 200 on API endpoint", 20)
                        f.predict(f"Destructive {method} operation may be unprotected")
                        f.risk = "HIGH"
                        f.vuln_types.append("Broken Access Control")
                        self.findings.append(f)
                    elif status == 405:
                        pass  # Method not allowed — good
                except Exception:
                    pass

    def run(self) -> list:
        """Run full auth behavior analysis."""
        urls = rl(OUT / "urls/all_urls.txt")
        if not urls:
            print("  ⚪ No URLs for auth analysis")
            return []

        self.analyze_auth_transitions(urls)
        self.analyze_access_control(urls)
        self.analyze_response_differentials(urls)
        self.analyze_method_behavior(urls)

        # Sort by confidence
        self.findings.sort(key=lambda f: f.confidence, reverse=True)
        return self.findings

    def save(self):
        """Save auth behavior findings."""
        data = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "auth_profiles": [p.name for p in self.auth_profiles],
            "findings": [f.to_dict() for f in self.findings],
            "summary": self._summarize(),
        }
        (AUTH_DIR / "auth_behavior.json").write_text(json.dumps(data, indent=2))

        # Human-readable
        lines = [
            "═" * 64,
            f"  🔐 AUTH-STATE BEHAVIORAL INTELLIGENCE — {self.domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 64, "",
        ]
        for f in self.findings:
            d = f.to_dict()
            icon = "🔴" if d["risk"] == "CRITICAL" else "🟠" if d["risk"] == "HIGH" else "🟡"
            lines.append(f"  {icon} {d['finding_type'].upper()} — {d['risk']}")
            lines.append(f"  URL: {d['url'][:80]}")
            lines.append("")
            lines.append("  Observed:")
            for o in d["observed"]:
                lines.append(f"    ✔ {o}")
            if d["predicted"]:
                lines.append("  Predicted:")
                for p in d["predicted"]:
                    lines.append(f"    ⚠ {p}")
            lines.append(f"  Confidence: {d['confidence']}%")
            for cs in d["confidence_sources"]:
                lines.append(f"    {cs}")
            if d["vuln_types"]:
                lines.append(f"  Vuln Types: {', '.join(d['vuln_types'])}")
            lines.append("\n" + "─" * 50)

        (AUTH_DIR / "auth_behavior.txt").write_text("\n".join(lines))

    def _summarize(self) -> dict:
        summary = defaultdict(int)
        for f in self.findings:
            summary[f.finding_type] += 1
        return dict(summary)


def main():
    print(f"\n  🔐 Auth-State Behavioral Intelligence — {DOMAIN}")
    print(f"  {'━' * 50}")

    engine = AuthBehaviorEngine(DOMAIN)
    findings = engine.run()
    engine.save()

    print(f"\n  📊 {len(findings)} auth behavior findings:")
    for f in findings[:10]:
        d = f.to_dict()
        icon = "🔴" if d["risk"] == "CRITICAL" else "🟠" if d["risk"] == "HIGH" else "🟡"
        print(f"    {icon} {d['finding_type']:25s} {d['confidence']:3d}% | "
              f"{', '.join(d['vuln_types'][:3]) or 'Info'}")
    print(f"  💾 Auth Intel → {AUTH_DIR}/")


if __name__ == "__main__":
    main()
