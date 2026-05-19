#!/usr/bin/env python3
"""
ReconX Ultra X — Confidence-Driven Reasoning Engine
====================================================
Implements the KNOW → THINK → TEST → VALIDATE reasoning loop
inspired by XBOW / Cyber-AutoAgent architecture.

Every action in the framework follows this cycle:
  1. KNOW  — confirmed evidence, technologies, attack surface, workflows
  2. THINK — vulnerability probability, attack-path prediction, risk scoring
  3. TEST  — lightweight validation, maximum signal extraction
  4. VALIDATE — evidence confirmation, confidence updates, strategy adaptation

Confidence Levels:
  VERIFIED  (90-100) — Tool-confirmed, multi-source validated
  HIGH      (70-89)  — Strong evidence, single-tool confirmed
  MEDIUM    (40-69)  — Pattern match, heuristic signal
  LOW       (1-39)   — Weak signal, needs investigation
"""
import json
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════
# Confidence Levels
# ═══════════════════════════════════════════════════════════════════════════
CONFIDENCE_LEVELS = {
    "VERIFIED": (90, 100),
    "HIGH":     (70, 89),
    "MEDIUM":   (40, 69),
    "LOW":      (1, 39),
}

CONFIDENCE_ICONS = {
    "VERIFIED": "🟢",
    "HIGH":     "🔵",
    "MEDIUM":   "🟡",
    "LOW":      "⚪",
}


def confidence_label(score: int) -> str:
    """Map numeric score to confidence label."""
    for label, (lo, hi) in CONFIDENCE_LEVELS.items():
        if lo <= score <= hi:
            return label
    return "LOW"


def confidence_icon(score: int) -> str:
    """Get icon for confidence score."""
    return CONFIDENCE_ICONS.get(confidence_label(score), "⚪")


# ═══════════════════════════════════════════════════════════════════════════
# Evidence & Knowledge Base
# ═══════════════════════════════════════════════════════════════════════════
class Evidence:
    """A single piece of evidence about a target."""
    def __init__(self, source: str, category: str, data: Any,
                 confidence: int = 30, timestamp: str = None):
        self.source = source        # e.g. "httpx", "nuclei", "js_analysis"
        self.category = category    # e.g. "technology", "endpoint", "secret"
        self.data = data
        self.confidence = min(max(confidence, 0), 100)
        self.timestamp = timestamp or datetime.now().isoformat()
        self.validations = []       # List of validation attempts

    def validate(self, validator: str, result: bool, boost: int = 15):
        """Record a validation attempt and adjust confidence."""
        self.validations.append({
            "validator": validator,
            "result": result,
            "timestamp": datetime.now().isoformat(),
        })
        if result:
            self.confidence = min(self.confidence + boost, 100)
        else:
            self.confidence = max(self.confidence - 5, 1)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "category": self.category,
            "data": self.data,
            "confidence": self.confidence,
            "confidence_label": confidence_label(self.confidence),
            "timestamp": self.timestamp,
            "validations": self.validations,
        }


class KnowledgeBase:
    """Accumulated knowledge about a target — the KNOW state."""
    def __init__(self, domain: str):
        self.domain = domain
        self.evidence: list[Evidence] = []
        self.technologies: dict[str, int] = {}     # tech → confidence
        self.attack_surface: dict[str, list] = defaultdict(list)
        self.workflows: dict[str, dict] = {}
        self.secrets: list[dict] = []
        self.apis: dict[str, list] = defaultdict(list)
        self.auth_mechanisms: list[str] = []
        self.cloud_providers: list[str] = []
        self.reasoning_log: list[dict] = []

    def add_evidence(self, evidence: Evidence):
        """Add evidence to knowledge base."""
        self.evidence.append(evidence)

    def add_technology(self, tech: str, confidence: int = 50):
        """Register a detected technology."""
        existing = self.technologies.get(tech, 0)
        self.technologies[tech] = min(max(existing, confidence), 100)

    def add_attack_surface(self, vuln_type: str, endpoint: str,
                           confidence: int = 30, reason: str = ""):
        """Register an attack surface entry."""
        self.attack_surface[vuln_type].append({
            "endpoint": endpoint,
            "confidence": confidence,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        })

    def add_reasoning(self, phase: str, action: str, result: str,
                      confidence_delta: int = 0):
        """Log a reasoning step."""
        self.reasoning_log.append({
            "phase": phase,
            "action": action,
            "result": result,
            "confidence_delta": confidence_delta,
            "timestamp": datetime.now().isoformat(),
        })

    def get_high_confidence_surface(self, min_confidence: int = 50) -> dict:
        """Get attack surfaces above a confidence threshold."""
        result = {}
        for vuln_type, entries in self.attack_surface.items():
            high = [e for e in entries if e["confidence"] >= min_confidence]
            if high:
                result[vuln_type] = sorted(high,
                    key=lambda x: x["confidence"], reverse=True)
        return result

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "evidence_count": len(self.evidence),
            "technologies": self.technologies,
            "attack_surface": {k: v[:50] for k, v in self.attack_surface.items()},
            "workflows": self.workflows,
            "secrets_count": len(self.secrets),
            "apis": {k: v[:50] for k, v in self.apis.items()},
            "auth_mechanisms": self.auth_mechanisms,
            "cloud_providers": self.cloud_providers,
            "reasoning_log": self.reasoning_log[-50:],
        }

    def save(self, output_dir: Path):
        """Persist knowledge base to disk."""
        kb_dir = output_dir / "knowledge_base"
        kb_dir.mkdir(parents=True, exist_ok=True)
        (kb_dir / "knowledge_base.json").write_text(
            json.dumps(self.to_dict(), indent=2))
        # Save evidence separately (can be large)
        (kb_dir / "evidence.json").write_text(
            json.dumps([e.to_dict() for e in self.evidence[:500]], indent=2))


# ═══════════════════════════════════════════════════════════════════════════
# Reasoning Engine — KNOW → THINK → TEST → VALIDATE
# ═══════════════════════════════════════════════════════════════════════════
class ReasoningEngine:
    """
    The core reasoning loop. Each cycle:
      KNOW   — gather confirmed evidence
      THINK  — predict vulnerabilities, rank attack paths
      TEST   — select lightweight tests for maximum signal
      VALIDATE — confirm or reject, update confidence
    """
    def __init__(self, domain: str, output_dir: Path = None):
        self.domain = domain
        self.kb = KnowledgeBase(domain)
        self.output_dir = output_dir or Path(f"output/{domain}")
        self.cycle_count = 0
        self.strategy_history: list[dict] = []

    # ── Phase 1: KNOW ──────────────────────────────────────────────────────
    def know(self, data_sources: dict) -> dict:
        """
        KNOW phase: ingest all available data into knowledge base.
        data_sources: dict of source_name → data (list/dict)
        """
        self.kb.add_reasoning("KNOW", "ingest_data",
            f"Processing {len(data_sources)} data sources")

        summary = {"sources_processed": 0, "evidence_added": 0}

        for source, data in data_sources.items():
            if isinstance(data, list):
                for item in data:
                    ev = Evidence(source=source, category=_categorize(item),
                                 data=item, confidence=30)
                    self.kb.add_evidence(ev)
                    summary["evidence_added"] += 1
            elif isinstance(data, dict):
                for key, values in data.items():
                    if isinstance(values, list):
                        for v in values[:100]:
                            ev = Evidence(source=source, category=key,
                                         data=v, confidence=30)
                            self.kb.add_evidence(ev)
                            summary["evidence_added"] += 1
            summary["sources_processed"] += 1

        self.kb.add_reasoning("KNOW", "ingest_complete",
            f"Added {summary['evidence_added']} evidence items")
        return summary

    # ── Phase 2: THINK ─────────────────────────────────────────────────────
    def think(self) -> dict:
        """
        THINK phase: analyze evidence, predict vulnerabilities,
        build attack-path hypotheses, rank targets.
        """
        self.kb.add_reasoning("THINK", "analysis_start",
            f"Analyzing {len(self.kb.evidence)} evidence items")

        predictions = defaultdict(list)
        attack_paths = []

        # Analyze each evidence item for vulnerability signals
        for ev in self.kb.evidence:
            signals = _extract_vuln_signals(ev)
            for signal in signals:
                vuln_type = signal["vuln_type"]
                probability = signal["probability"]
                self.kb.add_attack_surface(
                    vuln_type, str(ev.data),
                    confidence=probability, reason=signal["reason"])
                predictions[vuln_type].append({
                    "target": str(ev.data)[:200],
                    "probability": probability,
                    "reason": signal["reason"],
                })

        # Build attack paths from correlated evidence
        attack_paths = self._build_attack_paths()

        # Generate strategy
        strategy = self._generate_strategy(predictions, attack_paths)

        self.kb.add_reasoning("THINK", "analysis_complete",
            f"Predicted {len(predictions)} vuln types, "
            f"{len(attack_paths)} attack paths")

        return {
            "predictions": {k: sorted(v, key=lambda x: x["probability"],
                                       reverse=True)[:20]
                           for k, v in predictions.items()},
            "attack_paths": attack_paths[:10],
            "strategy": strategy,
        }

    # ── Phase 3: TEST ──────────────────────────────────────────────────────
    def test(self, think_results: dict) -> dict:
        """
        TEST phase: select highest-signal tests to run.
        Returns test plan (actual execution is done by modules).
        """
        self.kb.add_reasoning("TEST", "plan_start",
            "Generating test plan from THINK results")

        test_plan = {
            "priority_tests": [],
            "recommended_tools": [],
            "estimated_duration": "unknown",
        }

        # Rank by prediction probability
        for vuln_type, preds in think_results.get("predictions", {}).items():
            if preds and preds[0]["probability"] >= 40:
                test_plan["priority_tests"].append({
                    "vuln_type": vuln_type,
                    "targets": [p["target"] for p in preds[:5]],
                    "confidence": preds[0]["probability"],
                    "recommended_tool": _recommend_tool(vuln_type),
                })

        # Sort by confidence
        test_plan["priority_tests"].sort(
            key=lambda x: x["confidence"], reverse=True)

        self.kb.add_reasoning("TEST", "plan_complete",
            f"Generated {len(test_plan['priority_tests'])} priority tests")

        return test_plan

    # ── Phase 4: VALIDATE ──────────────────────────────────────────────────
    def validate(self, test_results: list[dict]) -> dict:
        """
        VALIDATE phase: process test results, update confidence,
        adapt strategy based on outcomes.
        """
        self.kb.add_reasoning("VALIDATE", "validation_start",
            f"Processing {len(test_results)} test results")

        validated = []
        strategy_adjustments = []

        for result in test_results:
            vuln_type = result.get("type", "unknown")
            confirmed = result.get("confirmed", False)
            score = result.get("score", 0)

            # Update evidence confidence
            for ev in self.kb.evidence:
                if str(ev.data) == result.get("target", ""):
                    ev.validate(result.get("tool", "unknown"), confirmed)

            if confirmed and score >= 50:
                validated.append({
                    **result,
                    "confidence": confidence_label(score),
                    "icon": confidence_icon(score),
                })
                # Adapt strategy: if one vuln found, look for related
                related = _get_related_vulns(vuln_type)
                for rv in related:
                    strategy_adjustments.append({
                        "action": "investigate_related",
                        "vuln_type": rv,
                        "reason": f"Found {vuln_type}, {rv} likely related",
                    })

        self.cycle_count += 1
        self.kb.add_reasoning("VALIDATE", "validation_complete",
            f"Validated {len(validated)} findings, "
            f"{len(strategy_adjustments)} strategy adjustments")

        return {
            "validated_findings": validated,
            "strategy_adjustments": strategy_adjustments,
            "cycle": self.cycle_count,
        }

    # ── Full Reasoning Cycle ───────────────────────────────────────────────
    def run_cycle(self, data_sources: dict,
                  test_results: list[dict] = None) -> dict:
        """Run a complete KNOW → THINK → TEST → VALIDATE cycle."""
        know_result = self.know(data_sources)
        think_result = self.think()
        test_plan = self.test(think_result)
        validate_result = self.validate(test_results or [])

        # Save knowledge base
        self.kb.save(self.output_dir)

        return {
            "cycle": self.cycle_count,
            "know": know_result,
            "think": think_result,
            "test_plan": test_plan,
            "validate": validate_result,
            "timestamp": datetime.now().isoformat(),
        }

    # ── Internal Helpers ───────────────────────────────────────────────────
    def _build_attack_paths(self) -> list:
        """Build attack paths from correlated attack surface entries."""
        paths = []
        surface = self.kb.attack_surface

        # XSS + JWT → Account Takeover
        if surface.get("xss") and surface.get("jwt_issue"):
            paths.append({
                "name": "XSS → JWT Theft → Account Takeover",
                "severity": "CRITICAL",
                "confidence": max(
                    (e["confidence"] for e in surface["xss"]), default=0),
                "steps": ["XSS injection", "JWT extraction",
                          "Session hijack", "Account takeover"],
            })

        # SSRF + Cloud → Infrastructure Compromise
        if surface.get("ssrf") and surface.get("cloud_exposure"):
            paths.append({
                "name": "SSRF → Cloud Metadata → IAM Credentials",
                "severity": "CRITICAL",
                "confidence": max(
                    (e["confidence"] for e in surface["ssrf"]), default=0),
                "steps": ["SSRF exploitation", "Metadata access",
                          "Credential extraction", "Infrastructure pivot"],
            })

        # Upload + XSS → Stored XSS
        if surface.get("upload_vuln") and surface.get("xss"):
            paths.append({
                "name": "File Upload → Stored XSS → Mass Compromise",
                "severity": "CRITICAL",
                "confidence": 60,
                "steps": ["Upload malicious file", "Content served to users",
                          "Stored XSS execution"],
            })

        # IDOR + Auth → Data Exfiltration
        if surface.get("idor") and surface.get("auth_bypass"):
            paths.append({
                "name": "IDOR + Auth Bypass → Mass Data Access",
                "severity": "CRITICAL",
                "confidence": 55,
                "steps": ["Enumerate object IDs", "Bypass auth checks",
                          "Access other users' data"],
            })

        # OAuth + Redirect → Token Theft
        if surface.get("oauth_misconfig") and surface.get("open_redirect"):
            paths.append({
                "name": "OAuth + Open Redirect → Token Theft",
                "severity": "HIGH",
                "confidence": 50,
                "steps": ["Open redirect in redirect_uri",
                          "OAuth token leaks to attacker"],
            })

        # GraphQL + Auth → Data Leak
        if surface.get("graphql_abuse"):
            paths.append({
                "name": "GraphQL Introspection → Field-Level Auth Bypass",
                "severity": "HIGH",
                "confidence": 45,
                "steps": ["Introspection query", "Discover hidden mutations",
                          "Bypass field-level auth"],
            })

        return sorted(paths, key=lambda x: x["confidence"], reverse=True)

    def _generate_strategy(self, predictions: dict,
                           attack_paths: list) -> dict:
        """Generate a hunter testing strategy."""
        priority_order = []

        # Rank vuln types by total prediction strength
        type_scores = {}
        for vtype, preds in predictions.items():
            if preds:
                type_scores[vtype] = sum(p["probability"] for p in preds[:10])

        for vtype in sorted(type_scores, key=type_scores.get, reverse=True):
            priority_order.append({
                "vuln_type": vtype,
                "total_signal": type_scores[vtype],
                "target_count": len(predictions[vtype]),
                "recommended_action": _recommend_action(vtype),
            })

        return {
            "priority_order": priority_order[:15],
            "attack_paths": len(attack_paths),
            "top_path": attack_paths[0]["name"] if attack_paths else "None",
            "cycle": self.cycle_count,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════
import re

_VULN_PATTERNS = {
    "xss": [
        (r"search|query|q=|keyword|callback|preview|render|template|comment",
         20, "Search/render parameter"),
        (r"innerHTML|outerHTML|document\.write|eval\(|dangerouslySetInnerHTML",
         40, "DOM sink detected"),
    ],
    "sqli": [
        (r"id=|user=|cat=|page=|item=|order=|sort=|filter=|where=",
         20, "Database parameter"),
        (r"\.php\?|\.asp\?|action=|report|export",
         15, "Server-side processing"),
    ],
    "ssrf": [
        (r"url=|endpoint=|dest=|redirect=|uri=|proxy=|fetch=|webhook=",
         25, "URL parameter"),
        (r"image=|avatar=|screenshot|pdf|export|import",
         20, "Media/export endpoint"),
    ],
    "idor": [
        (r"id=\d|uid=|user_id=|account_id=|order_id=|invoice_id=",
         25, "Sequential ID parameter"),
        (r"/api/v\d+/user|/profile|/account|/order",
         20, "Resource endpoint"),
    ],
    "upload_vuln": [
        (r"upload|attach|import|media|avatar|file|document",
         25, "Upload endpoint"),
    ],
    "graphql_abuse": [
        (r"graphql|gql|playground|graphiql|mutation",
         35, "GraphQL endpoint"),
    ],
    "oauth_misconfig": [
        (r"oauth|callback|redirect_uri|authorize|client_id|response_type",
         30, "OAuth parameter"),
    ],
    "ssti": [
        (r"template|render|preview|content|email|generate|invoice",
         25, "Template rendering"),
    ],
    "open_redirect": [
        (r"redirect=|return=|next=|goto=|dest=|rurl=|forward=",
         25, "Redirect parameter"),
    ],
    "lfi": [
        (r"file=|path=|include=|template=|page=|doc=|dir=|load=",
         25, "File parameter"),
    ],
    "jwt_issue": [
        (r"jwt|bearer|token|authorization|session",
         20, "Token handling"),
    ],
    "cloud_exposure": [
        (r"s3\.amazonaws|storage\.googleapis|blob\.core\.windows|firebase",
         30, "Cloud storage reference"),
    ],
    "admin_exposure": [
        (r"admin|manage|dashboard|control|panel|console|backoffice",
         30, "Admin panel"),
    ],
    "api_exposure": [
        (r"api/v\d|rest/|internal|private|swagger|openapi|api-docs",
         25, "API endpoint"),
    ],
    "info_disclosure": [
        (r"\.env|\.git|config|debug|trace|phpinfo|actuator|server-status",
         35, "Config exposure"),
    ],
    "websocket_abuse": [
        (r"ws://|wss://|socket\.io|websocket",
         20, "WebSocket endpoint"),
    ],
    "cors_misconfig": [
        (r"access-control-allow-origin|cors",
         15, "CORS related"),
    ],
    "business_logic": [
        (r"payment|checkout|cart|billing|invoice|order|coupon|discount",
         25, "Business/payment flow"),
    ],
    "prototype_pollution": [
        (r"__proto__|constructor\.prototype|Object\.assign",
         30, "Prototype pollution vector"),
    ],
    "race_condition": [
        (r"coupon|discount|vote|like|follow|transfer|withdraw",
         20, "Race-prone operation"),
    ],
    "cache_poisoning": [
        (r"X-Forwarded|X-Original-URL|X-Rewrite-URL|cache",
         20, "Cache/header injection"),
    ],
    "host_header_injection": [
        (r"Host:|X-Forwarded-Host|reset|forgot|password",
         20, "Host header vector"),
    ],
}


def _extract_vuln_signals(evidence: Evidence) -> list:
    """Extract vulnerability signals from an evidence item."""
    signals = []
    data_str = str(evidence.data).lower()

    for vuln_type, patterns in _VULN_PATTERNS.items():
        for pattern, base_prob, reason in patterns:
            if re.search(pattern, data_str, re.IGNORECASE):
                signals.append({
                    "vuln_type": vuln_type,
                    "probability": base_prob,
                    "reason": reason,
                })
                break  # One signal per vuln type per evidence

    return signals


def _categorize(item: Any) -> str:
    """Auto-categorize an evidence item."""
    s = str(item).lower()
    if any(kw in s for kw in ["api", "endpoint", "graphql", "rest"]):
        return "api"
    if any(kw in s for kw in ["secret", "key", "token", "password"]):
        return "secret"
    if any(kw in s for kw in [".js", "webpack", "chunk", "bundle"]):
        return "javascript"
    if any(kw in s for kw in ["upload", "file", "media"]):
        return "upload"
    if any(kw in s for kw in ["auth", "login", "oauth", "jwt"]):
        return "auth"
    return "endpoint"


def _recommend_tool(vuln_type: str) -> str:
    """Recommend the best tool for a vulnerability type."""
    tools = {
        "xss": "dalfox + XSStrike + manual",
        "sqli": "sqlmap + manual",
        "ssrf": "httpx + collaborator",
        "idor": "manual + autorize",
        "upload_vuln": "manual + custom payloads",
        "graphql_abuse": "graphql-cop + introspection",
        "oauth_misconfig": "manual + burp",
        "ssti": "tplmap + manual",
        "open_redirect": "httpx + manual",
        "lfi": "ffuf + manual",
        "jwt_issue": "jwt_tool + manual",
        "cors_misconfig": "cors-scanner",
        "cloud_exposure": "cloud_enum + manual",
    }
    return tools.get(vuln_type, "manual investigation")


def _recommend_action(vuln_type: str) -> str:
    """Recommend testing action for a vulnerability type."""
    actions = {
        "xss": "Test reflection + DOM sinks with context-aware payloads",
        "sqli": "Test error-based + time-based injection",
        "ssrf": "Test URL params with internal IP + cloud metadata",
        "idor": "Enumerate IDs and test authorization boundaries",
        "upload_vuln": "Test file type bypass + path traversal",
        "graphql_abuse": "Run introspection, test mutations, check auth",
        "oauth_misconfig": "Test redirect_uri manipulation + state bypass",
        "ssti": "Test template syntax: {{7*7}}, ${7*7}, #{7*7}",
        "open_redirect": "Test common redirect payloads",
        "lfi": "Test path traversal + null byte + encoding bypass",
        "admin_exposure": "Check auth bypass + default credentials",
        "info_disclosure": "Verify exposed configs + secrets",
        "business_logic": "Test price manipulation + race conditions",
    }
    return actions.get(vuln_type, "Manual investigation required")


def _get_related_vulns(vuln_type: str) -> list:
    """Get vulnerabilities commonly related to a given type."""
    relations = {
        "xss": ["csrf", "session_theft", "phishing"],
        "sqli": ["data_exfiltration", "auth_bypass", "rce"],
        "ssrf": ["cloud_exposure", "internal_access", "port_scan"],
        "idor": ["data_leak", "privilege_escalation"],
        "upload_vuln": ["rce", "xss", "path_traversal"],
        "oauth_misconfig": ["account_takeover", "token_theft"],
        "open_redirect": ["oauth_misconfig", "phishing"],
        "ssti": ["rce", "info_disclosure"],
        "lfi": ["rce", "info_disclosure"],
    }
    return relations.get(vuln_type, [])
