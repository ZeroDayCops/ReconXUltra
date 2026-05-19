#!/usr/bin/env python3
"""
ReconX Ultra X — DOM & SPA Intelligence Engine
================================================
Analyzes JavaScript for DOM manipulation patterns, SPA routes,
state management, API interactions, and client-side vulnerabilities.

L4 reasoning: browser-level observation via static JS analysis.
"""
import json, os, re, sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: dom_observer.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
DOM_DIR = OUT / "dom_intelligence"
DOM_DIR.mkdir(parents=True, exist_ok=True)


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
# DOM Pattern Definitions
# ═══════════════════════════════════════════════════════════════════════════

DOM_SINK_PATTERNS = {
    "innerHTML": {
        "pattern": r"\.innerHTML\s*[=+]",
        "severity": "CRITICAL",
        "risk": "XSS via innerHTML injection",
        "recommendation": "Test if user input reaches innerHTML assignment",
    },
    "outerHTML": {
        "pattern": r"\.outerHTML\s*[=+]",
        "severity": "CRITICAL",
        "risk": "XSS via outerHTML injection",
        "recommendation": "Test if user input reaches outerHTML",
    },
    "document.write": {
        "pattern": r"document\.write\s*\(",
        "severity": "CRITICAL",
        "risk": "XSS via document.write",
        "recommendation": "Test if user input flows into document.write",
    },
    "eval": {
        "pattern": r"\beval\s*\(",
        "severity": "CRITICAL",
        "risk": "Code injection via eval()",
        "recommendation": "Check if user data reaches eval()",
    },
    "postMessage": {
        "pattern": r"\.postMessage\s*\(",
        "severity": "HIGH",
        "risk": "Cross-origin message injection",
        "recommendation": "Check origin validation in message handler",
    },
    "addEventListener_message": {
        "pattern": r"addEventListener\s*\(\s*['\"]message['\"]",
        "severity": "HIGH",
        "risk": "postMessage handler may lack origin check",
        "recommendation": "Verify event.origin is validated",
    },
    "location_assign": {
        "pattern": r"(location\.(href|assign|replace)|window\.open)\s*[=(]",
        "severity": "HIGH",
        "risk": "Open redirect via DOM manipulation",
        "recommendation": "Test if user input controls redirect destination",
    },
    "jQuery_html": {
        "pattern": r"\$\([^)]+\)\.(html|append|prepend|after|before)\s*\(",
        "severity": "HIGH",
        "risk": "XSS via jQuery DOM manipulation",
        "recommendation": "Test if user input flows into jQuery DOM methods",
    },
    "dangerouslySetInnerHTML": {
        "pattern": r"dangerouslySetInnerHTML",
        "severity": "CRITICAL",
        "risk": "React XSS via dangerouslySetInnerHTML",
        "recommendation": "Check if user content reaches this prop",
    },
    "v_html": {
        "pattern": r"v-html\s*=",
        "severity": "HIGH",
        "risk": "Vue XSS via v-html directive",
        "recommendation": "Verify v-html does not render user input",
    },
    "bypassSecurityTrust": {
        "pattern": r"bypassSecurityTrust",
        "severity": "HIGH",
        "risk": "Angular sanitizer bypass",
        "recommendation": "Check if user input reaches trust bypass",
    },
}

SPA_ROUTE_PATTERNS = {
    "react_router": {
        "pattern": r"(Route|Switch|Router|BrowserRouter|HashRouter)\s*[({<]",
        "framework": "React",
    },
    "react_route_path": {
        "pattern": r"path\s*[:=]\s*['\"](/[^'\"]+)['\"]",
        "framework": "React/Generic",
    },
    "vue_router": {
        "pattern": r"(VueRouter|createRouter|router\.push|this\.\$router)",
        "framework": "Vue",
    },
    "angular_router": {
        "pattern": r"(RouterModule|routerLink|ActivatedRoute|NavigationEnd)",
        "framework": "Angular",
    },
    "next_router": {
        "pattern": r"(useRouter|router\.push|next\/router|next\/link)",
        "framework": "Next.js",
    },
}

API_INTERACTION_PATTERNS = {
    "fetch": r"fetch\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    "axios": r"axios\.(get|post|put|delete|patch)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    "xhr_open": r"\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH)['\"]\s*,\s*['\"`]([^'\"`]+)['\"`]",
    "ajax": r"\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['\"`]([^'\"`]+)['\"`]",
    "graphql_query": r"(query|mutation)\s+\w+\s*[({]",
}

STATE_PATTERNS = {
    "localStorage_set": r"localStorage\.setItem\s*\(\s*['\"]([^'\"]+)['\"]",
    "localStorage_get": r"localStorage\.getItem\s*\(\s*['\"]([^'\"]+)['\"]",
    "sessionStorage_set": r"sessionStorage\.setItem\s*\(\s*['\"]([^'\"]+)['\"]",
    "cookie_set": r"document\.cookie\s*=",
    "redux_store": r"(createStore|configureStore|useSelector|useDispatch)",
    "vuex_store": r"(Vuex\.Store|mapState|mapGetters|commit\s*\()",
}


class DOMFinding:
    """A DOM intelligence finding."""

    def __init__(self, category: str, finding_type: str):
        self.category = category    # "sink", "route", "api", "state"
        self.finding_type = finding_type
        self.file = ""
        self.line = 0
        self.context = ""
        self.severity = "MEDIUM"
        self.risk = ""
        self.recommendation = ""
        self.value = ""
        self.confidence = 0
        self.confidence_sources = []

    def observe(self, what: str, weight: int = 10):
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {what}")

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "type": self.finding_type,
            "file": self.file,
            "line": self.line,
            "context": self.context[:200],
            "severity": self.severity,
            "risk": self.risk,
            "recommendation": self.recommendation,
            "value": self.value[:200],
            "confidence": min(self.confidence, 100),
            "confidence_sources": self.confidence_sources,
        }


class DOMObserver:
    """Analyzes JS files for DOM patterns, SPA routes, and state management."""

    def __init__(self, domain: str):
        self.domain = domain
        self.findings = []
        self.routes = []
        self.apis = []
        self.state_keys = []
        self.framework = "unknown"

    def _load_js_content(self) -> dict:
        """Load JS file contents from downloaded files."""
        js_content = {}
        js_dir = OUT / "js"

        # Check for downloaded JS files
        for pattern in ["*.js", "js_downloads/*.js", "downloaded/*.js"]:
            for js_file in sorted(js_dir.glob(pattern)):
                if js_file.stat().st_size > 0:
                    try:
                        content = js_file.read_text(errors="ignore")
                        js_content[str(js_file)] = content
                    except Exception:
                        pass

        # Also check intelligence for extracted JS data
        js_deep = lj(OUT / "intelligence/js_analysis_deep.json")
        if isinstance(js_deep, dict):
            for url, data in js_deep.items():
                if isinstance(data, dict) and data.get("content"):
                    js_content[url] = data["content"]

        return js_content

    def analyze_dom_sinks(self, js_content: dict):
        """Find dangerous DOM sinks."""
        print("    🔍 Analyzing DOM sinks...")

        for filepath, content in js_content.items():
            lines = content.split("\n")
            for sink_name, config in DOM_SINK_PATTERNS.items():
                for i, line in enumerate(lines):
                    if re.search(config["pattern"], line):
                        f = DOMFinding("sink", sink_name)
                        f.file = os.path.basename(filepath)
                        f.line = i + 1
                        f.context = line.strip()[:200]
                        f.severity = config["severity"]
                        f.risk = config["risk"]
                        f.recommendation = config["recommendation"]
                        f.observe(f"DOM sink '{sink_name}' in {f.file}:{f.line}", 15)

                        # Check if user-controlled sources flow in
                        source_context = "\n".join(lines[max(0, i-3):i+3])
                        user_sources = [
                            r"location\.(hash|search|href|pathname)",
                            r"document\.(URL|referrer|cookie)",
                            r"window\.name",
                            r"\.getParameter|\.searchParams",
                            r"decodeURI(Component)?",
                        ]
                        for source in user_sources:
                            if re.search(source, source_context):
                                f.observe(f"User-controlled source near sink", 20)
                                f.severity = "CRITICAL"
                                break

                        self.findings.append(f)

    def analyze_spa_routes(self, js_content: dict):
        """Detect SPA routes and framework."""
        print("    🛤️  Analyzing SPA routes...")

        all_routes = set()
        framework_votes = defaultdict(int)

        for filepath, content in js_content.items():
            # Detect framework
            for pattern_name, config in SPA_ROUTE_PATTERNS.items():
                matches = re.findall(config["pattern"], content)
                if matches:
                    framework_votes[config["framework"]] += len(matches)

            # Extract route paths
            route_matches = re.findall(
                r"""(?:path|route|to)\s*[:=]\s*['\"](/[a-zA-Z0-9/_\-:*{}]+)['\"]""",
                content)
            for route in route_matches:
                all_routes.add(route)

            # Next.js / file-based routing
            if "pages/" in filepath or "app/" in filepath:
                path_match = re.search(r"(pages|app)/(.+?)(?:\.tsx?|\.jsx?|/index)", filepath)
                if path_match:
                    route = "/" + path_match.group(2).replace("[", ":").replace("]", "")
                    all_routes.add(route)

        if framework_votes:
            self.framework = max(framework_votes, key=framework_votes.get)

        for route in sorted(all_routes):
            f = DOMFinding("route", "spa_route")
            f.value = route
            f.observe(f"SPA route detected: {route}", 5)

            # Check for sensitive routes
            if re.search(r"admin|manage|settings|dashboard|internal", route, re.I):
                f.observe("Sensitive SPA route", 15)
                f.severity = "HIGH"
                f.risk = "Hidden admin route may be accessible"
            elif re.search(r"api|graphql|webhook", route, re.I):
                f.observe("API route in SPA", 10)
                f.risk = "Client-side API route exposure"
            elif ":" in route or "{" in route:
                f.observe("Dynamic route parameter", 5)
                f.risk = "IDOR via route parameter"

            self.routes.append(f)
            self.findings.append(f)

    def analyze_api_interactions(self, js_content: dict):
        """Extract API endpoints from JS code."""
        print("    📡 Analyzing API interactions...")

        all_apis = set()
        for filepath, content in js_content.items():
            for api_type, pattern in API_INTERACTION_PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        url = match[-1]  # Last group is usually the URL
                    else:
                        url = match
                    if url and not url.startswith("data:") and len(url) > 3:
                        all_apis.add((api_type, url))

        for api_type, url in sorted(all_apis):
            f = DOMFinding("api", api_type)
            f.value = url
            f.observe(f"API endpoint: {url[:60]}", 8)

            if re.search(r"admin|internal|private|secret", url, re.I):
                f.observe("Sensitive API endpoint", 15)
                f.severity = "HIGH"
                f.risk = "Internal API exposed in client-side code"
            elif re.search(r"password|token|key|secret|auth", url, re.I):
                f.observe("Auth-related API endpoint", 12)
                f.severity = "HIGH"

            self.apis.append(f)
            self.findings.append(f)

    def analyze_state_management(self, js_content: dict):
        """Detect client-side state management patterns."""
        print("    💾 Analyzing state management...")

        for filepath, content in js_content.items():
            for state_type, pattern in STATE_PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]

                    f = DOMFinding("state", state_type)
                    f.file = os.path.basename(filepath)
                    f.value = match[:100] if match else ""

                    if "localStorage" in state_type or "sessionStorage" in state_type:
                        f.observe(f"Client storage key: {match}", 10)
                        if re.search(r"token|jwt|auth|session|key", match, re.I):
                            f.observe("Sensitive data in client storage", 20)
                            f.severity = "HIGH"
                            f.risk = "Token/secret in localStorage — XSS leads to theft"
                        self.state_keys.append(match)
                    elif "cookie" in state_type:
                        f.observe("Client-side cookie manipulation", 8)
                        f.risk = "Cookie set via JavaScript (not HttpOnly)"
                        f.severity = "MEDIUM"
                    else:
                        f.observe(f"State management: {state_type}", 5)

                    if f.confidence >= 8:
                        self.findings.append(f)

    def run(self) -> list:
        js_content = self._load_js_content()
        if not js_content:
            print("  ⚪ No JS content available for DOM analysis")
            # Try to use existing intelligence data
            existing = lj(OUT / "intelligence/dom_sinks.json")
            if isinstance(existing, list):
                for item in existing:
                    if isinstance(item, dict):
                        f = DOMFinding("sink", item.get("sink", "unknown"))
                        f.file = item.get("file", "")
                        f.severity = item.get("severity", "MEDIUM")
                        f.risk = item.get("risk", "")
                        f.observe(f"DOM sink from prior analysis: {f.file}", 10)
                        self.findings.append(f)
            return self.findings

        print(f"    📄 Analyzing {len(js_content)} JS files...")

        self.analyze_dom_sinks(js_content)
        self.analyze_spa_routes(js_content)
        self.analyze_api_interactions(js_content)
        self.analyze_state_management(js_content)

        self.findings.sort(key=lambda f: f.confidence, reverse=True)
        return self.findings

    def save(self):
        sinks = [f for f in self.findings if f.category == "sink"]
        routes = [f for f in self.findings if f.category == "route"]
        apis = [f for f in self.findings if f.category == "api"]
        states = [f for f in self.findings if f.category == "state"]

        data = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "framework": self.framework,
            "total_findings": len(self.findings),
            "dom_sinks": len(sinks),
            "spa_routes": len(routes),
            "api_endpoints": len(apis),
            "state_keys": len(states),
            "critical_sinks": len([f for f in sinks if f.severity == "CRITICAL"]),
            "findings": [f.to_dict() for f in self.findings[:200]],
        }
        (DOM_DIR / "dom_intelligence.json").write_text(json.dumps(data, indent=2))

        # Human-readable
        lines = [
            "═" * 64,
            f"  🔍 DOM & SPA INTELLIGENCE — {self.domain}",
            f"  Framework: {self.framework}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 64, "",
            f"  DOM Sinks: {len(sinks)} ({len([f for f in sinks if f.severity == 'CRITICAL'])} critical)",
            f"  SPA Routes: {len(routes)}",
            f"  API Endpoints: {len(apis)}",
            f"  State Keys: {len(states)}",
            "",
        ]

        if sinks:
            lines.append("  ── DOM SINKS ──")
            for f in sinks[:15]:
                d = f.to_dict()
                icon = "🔴" if d["severity"] == "CRITICAL" else "🟠"
                lines.append(f"    {icon} {d['type']} in {d['file']}:{d.get('line', 0)}")
                lines.append(f"       {d['risk']}")
                lines.append(f"       → {d['recommendation']}")
                lines.append("")

        if routes:
            lines.append("  ── SPA ROUTES ──")
            for f in routes[:20]:
                d = f.to_dict()
                icon = "🟠" if d["severity"] == "HIGH" else "🟡"
                lines.append(f"    {icon} {d['value']}")

        if apis:
            lines.append("\n  ── API ENDPOINTS ──")
            for f in apis[:15]:
                d = f.to_dict()
                icon = "🟠" if d["severity"] == "HIGH" else "🟡"
                lines.append(f"    {icon} [{d['type']}] {d['value'][:60]}")

        (DOM_DIR / "dom_intelligence.txt").write_text("\n".join(lines))


def main():
    print(f"\n  🔍 DOM & SPA Intelligence Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    observer = DOMObserver(DOMAIN)
    findings = observer.run()
    observer.save()

    sinks = [f for f in findings if f.category == "sink"]
    routes = [f for f in findings if f.category == "route"]
    apis = [f for f in findings if f.category == "api"]

    print(f"\n  📊 {len(findings)} DOM findings:")
    print(f"    🔍 {len(sinks)} sinks ({len([f for f in sinks if f.severity == 'CRITICAL'])} critical)")
    print(f"    🛤️  {len(routes)} SPA routes")
    print(f"    📡 {len(apis)} API endpoints")
    print(f"    🔧 Framework: {observer.framework}")
    print(f"  💾 DOM Intel → {DOM_DIR}/")


if __name__ == "__main__":
    main()
