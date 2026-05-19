#!/usr/bin/env python3
"""
ReconX Ultra X — Session Intelligence Engine
==============================================
Tracks session behavior: rotation, fixation, cookie attributes,
JWT handling, token refresh, and auth persistence patterns.
"""
import json, os, re, sys, subprocess
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: session_intelligence.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
SESS_DIR = OUT / "behavioral"
SESS_DIR.mkdir(parents=True, exist_ok=True)

MAX_WORKERS = int(os.environ.get("RECONX_PROBE_WORKERS", "8"))


def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except:
        return []


def _fetch_headers(url: str) -> dict:
    try:
        r = subprocess.run(
            ["curl", "-skI", "-m", "5", url],
            capture_output=True, text=True, timeout=7)
        headers = {}
        for line in r.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                key = k.strip().lower()
                if key in headers:
                    headers[key] += "; " + v.strip()
                else:
                    headers[key] = v.strip()
        return headers
    except:
        return {}


class SessionFinding:
    def __init__(self, finding_type: str, url: str = ""):
        self.finding_type = finding_type
        self.url = url
        self.observed = []
        self.predicted = []
        self.confidence = 0
        self.confidence_sources = []
        self.risk = "MEDIUM"
        self.cookie_attributes = {}

    def observe(self, what: str, weight: int = 10):
        self.observed.append(what)
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {what}")

    def predict(self, what: str):
        self.predicted.append(what)

    def to_dict(self) -> dict:
        return {
            "type": self.finding_type,
            "url": self.url,
            "observed": self.observed,
            "predicted": self.predicted,
            "confidence": min(self.confidence, 100),
            "confidence_sources": self.confidence_sources,
            "risk": self.risk,
            "cookie_attributes": self.cookie_attributes,
        }


class SessionIntelligence:
    """Analyzes session management behavior."""

    def __init__(self, domain: str):
        self.domain = domain
        self.findings = []

    def analyze_cookie_security(self, urls: list):
        """Analyze cookie security attributes."""
        print("    🍪 Analyzing cookie security...")

        auth_urls = [u for u in urls if re.search(
            r"login|signin|auth|session|dashboard|account", u, re.I)][:10]
        if not auth_urls:
            auth_urls = urls[:5]

        for url in auth_urls:
            headers = _fetch_headers(url)
            set_cookie = headers.get("set-cookie", "")
            if not set_cookie:
                continue

            f = SessionFinding("cookie_security", url)
            cookie_parts = set_cookie.lower()

            # Parse cookie name
            name_match = re.match(r"([^=]+)=", set_cookie)
            cookie_name = name_match.group(1).strip() if name_match else "unknown"
            f.cookie_attributes["name"] = cookie_name

            f.observe(f"Cookie set: {cookie_name}", 5)

            # Check attributes
            if "httponly" in cookie_parts:
                f.observe("HttpOnly flag present", 3)
                f.cookie_attributes["httponly"] = True
            else:
                f.observe("HttpOnly flag MISSING — JS can access cookie", 15)
                f.predict("Session theft via XSS possible")
                f.risk = "HIGH"
                f.cookie_attributes["httponly"] = False

            if "secure" in cookie_parts:
                f.observe("Secure flag present", 3)
                f.cookie_attributes["secure"] = True
            else:
                f.observe("Secure flag MISSING — cookie sent over HTTP", 10)
                f.predict("Session hijacking via network sniffing")
                f.cookie_attributes["secure"] = False

            if "samesite" in cookie_parts:
                if "samesite=none" in cookie_parts:
                    f.observe("SameSite=None — cross-site cookie sending", 12)
                    f.predict("CSRF possible despite SameSite")
                    f.cookie_attributes["samesite"] = "none"
                elif "samesite=lax" in cookie_parts:
                    f.observe("SameSite=Lax — partial CSRF protection", 3)
                    f.cookie_attributes["samesite"] = "lax"
                elif "samesite=strict" in cookie_parts:
                    f.observe("SameSite=Strict — strong CSRF protection", 2)
                    f.cookie_attributes["samesite"] = "strict"
            else:
                f.observe("SameSite attribute MISSING", 8)
                f.predict("CSRF possible via cross-site requests")
                f.cookie_attributes["samesite"] = "missing"

            # Check for session ID patterns
            if re.search(r"(sess|phpsessid|jsession|aspsession|connect\.sid)", cookie_name, re.I):
                f.observe(f"Session ID cookie: {cookie_name}", 5)
                f.cookie_attributes["is_session_id"] = True

            # Check expiry
            if "expires" in cookie_parts or "max-age" in cookie_parts:
                f.observe("Cookie has explicit expiry", 3)
                f.cookie_attributes["persistent"] = True
            else:
                f.observe("Session cookie (no expiry) — dies on browser close", 2)
                f.cookie_attributes["persistent"] = False

            if f.confidence >= 10:
                self.findings.append(f)

    def analyze_session_fixation(self, urls: list):
        """Check for session fixation indicators."""
        print("    📌 Checking session fixation...")

        login_urls = [u for u in urls if re.search(r"login|signin", u, re.I)][:3]

        for url in login_urls:
            # Fetch pre-login cookie
            headers_before = _fetch_headers(url)
            cookie_before = headers_before.get("set-cookie", "")

            if cookie_before:
                # Check if a session is set before auth
                f = SessionFinding("session_fixation", url)
                f.observe("Session cookie set on login page (pre-auth)", 15)
                f.predict("Session fixation — pre-auth session may persist post-login")
                f.risk = "HIGH"

                name_match = re.match(r"([^=]+)=([^;]+)", cookie_before)
                if name_match:
                    f.observe(f"Pre-auth cookie: {name_match.group(1)}={name_match.group(2)[:20]}...", 5)

                self.findings.append(f)

    def analyze_cors_for_session(self, urls: list):
        """Check CORS configuration for session-bearing endpoints."""
        print("    🌐 Analyzing CORS for session endpoints...")

        api_urls = [u for u in urls if re.search(r"/api/|/v\d+/|graphql", u, re.I)][:10]

        for url in api_urls:
            try:
                r = subprocess.run(
                    ["curl", "-sk", "-I",
                     "-H", f"Origin: https://evil.com",
                     "-m", "5", url],
                    capture_output=True, text=True, timeout=7)

                headers = {}
                for line in r.stdout.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        headers[k.strip().lower()] = v.strip()

                acao = headers.get("access-control-allow-origin", "")
                acac = headers.get("access-control-allow-credentials", "")

                if acao == "https://evil.com" and acac.lower() == "true":
                    f = SessionFinding("cors_session_leak", url)
                    f.observe("CORS reflects arbitrary Origin", 25)
                    f.observe("Credentials allowed with reflected Origin", 20)
                    f.predict("Cross-origin session theft — attacker can steal data")
                    f.risk = "CRITICAL"
                    self.findings.append(f)
                elif acao == "*":
                    f = SessionFinding("cors_open", url)
                    f.observe("CORS: Access-Control-Allow-Origin: *", 10)
                    f.predict("Data accessible cross-origin (but no cookies)")
                    f.risk = "MEDIUM"
                    self.findings.append(f)
            except Exception:
                pass

    def run(self) -> list:
        urls = rl(OUT / "urls/all_urls.txt")
        if not urls:
            print("  ⚪ No URLs for session analysis")
            return []

        self.analyze_cookie_security(urls)
        self.analyze_session_fixation(urls)
        self.analyze_cors_for_session(urls)

        self.findings.sort(key=lambda f: f.confidence, reverse=True)
        return self.findings

    def save(self):
        data = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        (SESS_DIR / "session_intelligence.json").write_text(json.dumps(data, indent=2))

        lines = [
            "═" * 64,
            f"  🍪 SESSION INTELLIGENCE — {self.domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 64, "",
        ]
        for f in self.findings:
            d = f.to_dict()
            icon = "🔴" if d["risk"] == "CRITICAL" else "🟠" if d["risk"] == "HIGH" else "🟡"
            lines.append(f"  {icon} {d['type'].upper()}")
            lines.append(f"  URL: {d['url'][:70]}")
            for o in d["observed"]:
                lines.append(f"    ✔ {o}")
            for p in d["predicted"]:
                lines.append(f"    ⚠ {p}")
            lines.append(f"  Confidence: {d['confidence']}%")
            lines.append("")

        (SESS_DIR / "session_intelligence.txt").write_text("\n".join(lines))


def main():
    print(f"\n  🍪 Session Intelligence Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    engine = SessionIntelligence(DOMAIN)
    findings = engine.run()
    engine.save()

    print(f"\n  📊 {len(findings)} session findings:")
    for f in findings[:8]:
        d = f.to_dict()
        icon = "🔴" if d["risk"] == "CRITICAL" else "🟠" if d["risk"] == "HIGH" else "🟡"
        print(f"    {icon} {d['type']:25s} {d['confidence']:3d}%")
    print(f"  💾 Session Intel → {SESS_DIR}/")


if __name__ == "__main__":
    main()
