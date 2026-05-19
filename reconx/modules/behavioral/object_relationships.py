#!/usr/bin/env python3
"""
ReconX Ultra X — Object Relationship Intelligence
====================================================
Understands objects within the target application:
invoices, orders, tickets, profiles, payments, etc.

Maps object exposure, ownership, and access patterns.
NOT just "id=123" — understands "invoice object exposed through API".
"""
import json, os, re, sys, subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: object_relationships.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
OBJ_DIR = OUT / "object_relationships"
OBJ_DIR.mkdir(parents=True, exist_ok=True)

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
# Object Type Definitions
# ═══════════════════════════════════════════════════════════════════════════

OBJECT_TYPES = {
    "user": {
        "url_patterns": [r"/users?/", r"/profile", r"/account", r"/member"],
        "param_patterns": [r"user_?id", r"uid", r"profile_?id", r"account_?id"],
        "risk": "HIGH",
        "impact": "PII exposure, account takeover",
    },
    "invoice": {
        "url_patterns": [r"/invoices?/", r"/billing", r"/receipt"],
        "param_patterns": [r"invoice_?id", r"receipt_?id", r"billing_?id"],
        "risk": "HIGH",
        "impact": "Financial data exposure, invoice fraud",
    },
    "order": {
        "url_patterns": [r"/orders?/", r"/checkout", r"/purchase"],
        "param_patterns": [r"order_?id", r"purchase_?id", r"transaction_?id"],
        "risk": "HIGH",
        "impact": "Order data exposure, price manipulation",
    },
    "ticket": {
        "url_patterns": [r"/tickets?/", r"/support", r"/issues?/", r"/bugs?/"],
        "param_patterns": [r"ticket_?id", r"issue_?id", r"case_?id"],
        "risk": "MEDIUM",
        "impact": "Support ticket data exposure",
    },
    "payment": {
        "url_patterns": [r"/payment", r"/card", r"/subscribe", r"/plan"],
        "param_patterns": [r"payment_?id", r"card_?id", r"subscription_?id"],
        "risk": "CRITICAL",
        "impact": "Payment data exposure, financial fraud",
    },
    "document": {
        "url_patterns": [r"/documents?/", r"/files?/", r"/attachments?/", r"/uploads?/"],
        "param_patterns": [r"doc_?id", r"file_?id", r"attachment_?id"],
        "risk": "HIGH",
        "impact": "Document exposure, data leak",
    },
    "message": {
        "url_patterns": [r"/messages?/", r"/chat", r"/inbox", r"/conversations?/"],
        "param_patterns": [r"message_?id", r"chat_?id", r"conversation_?id"],
        "risk": "HIGH",
        "impact": "Private message exposure",
    },
    "admin": {
        "url_patterns": [r"/admin/", r"/manage/", r"/panel/", r"/console/"],
        "param_patterns": [r"admin_?id", r"role_?id"],
        "risk": "CRITICAL",
        "impact": "Admin function exposure, privilege escalation",
    },
    "api_resource": {
        "url_patterns": [r"/api/v\d+/\w+/\d+", r"/rest/\w+/\d+"],
        "param_patterns": [r"resource_?id", r"item_?id"],
        "risk": "HIGH",
        "impact": "API object exposure, mass data access",
    },
    "media": {
        "url_patterns": [r"/media/", r"/images?/", r"/photos?/", r"/avatar"],
        "param_patterns": [r"media_?id", r"image_?id", r"photo_?id"],
        "risk": "MEDIUM",
        "impact": "Private media exposure",
    },
}


class ObjectInstance:
    """A detected object instance."""

    def __init__(self, obj_type: str, url: str, identifier: str = ""):
        self.obj_type = obj_type
        self.url = url
        self.identifier = identifier
        self.access_status = 0
        self.response_size = 0
        self.has_data = False
        self.exposed = False
        self.observations = []
        self.confidence = 0
        self.confidence_sources = []
        self.relationships = []  # Related objects

    def observe(self, what: str, weight: int = 5):
        self.observations.append(what)
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {what}")

    def to_dict(self) -> dict:
        return {
            "type": self.obj_type,
            "url": self.url,
            "identifier": self.identifier,
            "access_status": self.access_status,
            "response_size": self.response_size,
            "has_data": self.has_data,
            "exposed": self.exposed,
            "observations": self.observations,
            "confidence": min(self.confidence, 100),
            "confidence_sources": self.confidence_sources,
            "relationships": self.relationships,
            "impact": OBJECT_TYPES.get(self.obj_type, {}).get("impact", ""),
            "risk": OBJECT_TYPES.get(self.obj_type, {}).get("risk", "MEDIUM"),
        }


def _probe(url: str) -> dict:
    try:
        r = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w",
             '{"status":%{http_code},"size":%{size_download}}',
             "-m", "5", url],
            capture_output=True, text=True, timeout=7)
        return json.loads(r.stdout.strip()) if r.returncode == 0 else {}
    except:
        return {}


class ObjectRelationshipEngine:
    """Maps object relationships across the target."""

    def __init__(self, domain: str):
        self.domain = domain
        self.objects = []
        self.relationship_graph = defaultdict(list)

    def detect_objects(self, urls: list):
        """Detect objects from URLs and parameters."""
        print("    🔍 Detecting application objects...")

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            params = parse_qs(parsed.query)

            for obj_type, config in OBJECT_TYPES.items():
                matched = False

                # URL path match
                for pattern in config["url_patterns"]:
                    if re.search(pattern, path, re.I):
                        # Extract ID from path
                        id_match = re.search(r"/(\d+)(?:/|$|\?)", parsed.path)
                        identifier = id_match.group(1) if id_match else ""
                        obj = ObjectInstance(obj_type, url, identifier)
                        obj.observe(f"URL path matches {obj_type} pattern", 10)
                        self.objects.append(obj)
                        matched = True
                        break

                if matched:
                    continue

                # Parameter match
                for param_pattern in config["param_patterns"]:
                    for param_name in params:
                        if re.match(param_pattern, param_name, re.I):
                            identifier = params[param_name][0]
                            obj = ObjectInstance(obj_type, url, identifier)
                            obj.observe(f"Parameter {param_name}={identifier} indicates {obj_type}", 10)
                            self.objects.append(obj)
                            break

    def probe_object_access(self):
        """Probe objects to understand access behavior."""
        print(f"    📡 Probing {min(len(self.objects), 40)} objects...")

        def _probe_obj(obj):
            result = _probe(obj.url)
            if result:
                obj.access_status = result.get("status", 0)
                obj.response_size = result.get("size", 0)
                if obj.access_status == 200 and obj.response_size > 100:
                    obj.exposed = True
                    obj.has_data = True
                    obj.observe(f"Object accessible: {obj.access_status}, {obj.response_size}B", 15)
                elif obj.access_status == 403:
                    obj.observe("Object protected: 403", 3)
                elif obj.access_status == 401:
                    obj.observe("Object requires auth: 401", 5)
            return obj

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(_probe_obj, obj)
                       for obj in self.objects[:40]]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def detect_relationships(self):
        """Detect relationships between objects."""
        print("    🔗 Mapping object relationships...")

        # Group by type
        by_type = defaultdict(list)
        for obj in self.objects:
            by_type[obj.obj_type].append(obj)

        # Detect cross-object relationships
        relationship_rules = [
            ("user", "order", "User has orders"),
            ("user", "invoice", "User has invoices"),
            ("user", "ticket", "User has tickets"),
            ("user", "document", "User has documents"),
            ("user", "message", "User has messages"),
            ("order", "payment", "Order has payment"),
            ("order", "invoice", "Order generates invoice"),
            ("ticket", "message", "Ticket has messages"),
            ("admin", "user", "Admin manages users"),
        ]

        for obj_a_type, obj_b_type, relationship in relationship_rules:
            if by_type[obj_a_type] and by_type[obj_b_type]:
                for obj_a in by_type[obj_a_type][:5]:
                    for obj_b in by_type[obj_b_type][:5]:
                        obj_a.relationships.append({
                            "type": relationship,
                            "target_type": obj_b_type,
                            "target_url": obj_b.url[:80],
                        })
                        self.relationship_graph[obj_a_type].append(obj_b_type)

        # Detect IDOR patterns
        for obj_type, objs in by_type.items():
            exposed = [o for o in objs if o.exposed]
            if len(exposed) >= 2:
                ids = [o.identifier for o in exposed if o.identifier]
                try:
                    int_ids = sorted([int(i) for i in ids if i.isdigit()])
                    if len(int_ids) >= 2:
                        # Check for sequential
                        diffs = [int_ids[i+1] - int_ids[i] for i in range(len(int_ids)-1)]
                        if any(d <= 5 for d in diffs):
                            for obj in exposed:
                                obj.observe(f"Sequential {obj_type} IDs detected — IDOR risk", 20)

                except ValueError:
                    pass

    def run(self) -> list:
        urls = rl(OUT / "urls/all_urls.txt")
        if not urls:
            print("  ⚪ No URLs for object analysis")
            return []

        self.detect_objects(urls)
        self.probe_object_access()
        self.detect_relationships()

        # Sort by confidence
        self.objects.sort(key=lambda o: o.confidence, reverse=True)
        return self.objects

    def save(self):
        exposed = [o for o in self.objects if o.exposed]
        protected = [o for o in self.objects if not o.exposed and o.access_status > 0]
        by_type = defaultdict(int)
        for o in self.objects:
            by_type[o.obj_type] += 1

        data = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "total_objects": len(self.objects),
            "exposed_objects": len(exposed),
            "protected_objects": len(protected),
            "by_type": dict(by_type),
            "relationship_graph": {k: list(set(v)) for k, v in self.relationship_graph.items()},
            "objects": [o.to_dict() for o in self.objects[:100]],
        }
        (OBJ_DIR / "object_relationships.json").write_text(json.dumps(data, indent=2))

        # Human-readable
        lines = [
            "═" * 64,
            f"  🔗 OBJECT RELATIONSHIP INTELLIGENCE — {self.domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 64, "",
            f"  Total: {len(self.objects)} | Exposed: {len(exposed)} | Protected: {len(protected)}",
            "",
        ]
        for obj_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            exposed_count = len([o for o in self.objects if o.obj_type == obj_type and o.exposed])
            risk = OBJECT_TYPES.get(obj_type, {}).get("risk", "MEDIUM")
            icon = "🔴" if risk == "CRITICAL" else "🟠" if risk == "HIGH" else "🟡"
            lines.append(f"  {icon} {obj_type:20s} {count:3d} objects ({exposed_count} exposed)")

        lines.append("")
        for obj in self.objects[:20]:
            if not obj.observations:
                continue
            d = obj.to_dict()
            lines.append(f"  [{d['type']}] {d['url'][:70]}")
            for o in d["observations"][:3]:
                lines.append(f"    ✔ {o}")
            if d["relationships"]:
                lines.append(f"    Relationships: {len(d['relationships'])}")
            lines.append("")

        (OBJ_DIR / "object_relationships.txt").write_text("\n".join(lines))


def main():
    print(f"\n  🔗 Object Relationship Intelligence — {DOMAIN}")
    print(f"  {'━' * 50}")

    engine = ObjectRelationshipEngine(DOMAIN)
    objects = engine.run()
    engine.save()

    exposed = [o for o in objects if o.exposed]
    by_type = defaultdict(int)
    for o in objects:
        by_type[o.obj_type] += 1

    print(f"\n  📊 {len(objects)} objects detected ({len(exposed)} exposed):")
    for obj_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
        e = len([o for o in objects if o.obj_type == obj_type and o.exposed])
        risk = OBJECT_TYPES.get(obj_type, {}).get("risk", "MEDIUM")
        icon = "🔴" if risk == "CRITICAL" else "🟠" if risk == "HIGH" else "🟡"
        print(f"    {icon} {obj_type:15s} {count:3d} ({e} exposed)")
    print(f"  💾 Objects → {OBJ_DIR}/")


if __name__ == "__main__":
    main()
