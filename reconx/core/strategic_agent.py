#!/usr/bin/env python3
"""
ReconX Ultra X — Strategic Agent (XBOW-Style Meta-Architecture)
================================================================
ONE PRIMARY STRATEGIC AGENT that orchestrates all helper agents,
plugin execution, and dynamic workflow selection.

Inspired by XBOW / Cyber-AutoAgent / Claude-Bug-Bounty architecture.
"""
import json, os, sys, time
from pathlib import Path
from datetime import datetime
from collections import defaultdict

RECONX_ROOT = Path(os.environ.get("RECONX_ROOT",
    Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(RECONX_ROOT / "core"))

from confidence_engine import (ReasoningEngine, KnowledgeBase, Evidence,
                                confidence_label, confidence_icon)

# ═══════════════════════════════════════════════════════════════════════════
# Helper Agent Definitions
# ═══════════════════════════════════════════════════════════════════════════
HELPER_AGENTS = {
    "recon-agent": {
        "name": "Recon Agent",
        "icon": "🌐",
        "description": "Subdomain enumeration, live host detection, URL gathering",
        "modules": ["subdomains", "live", "urls", "dedup"],
        "priority": 1,
    },
    "js-agent": {
        "name": "JS Intelligence Agent",
        "icon": "📜",
        "description": "JavaScript analysis, secret extraction, DOM sink detection",
        "modules": ["js"],
        "scripts": ["modules/intelligence/js_deep_analysis.py"],
        "priority": 2,
    },
    "api-agent": {
        "name": "API Discovery Agent",
        "icon": "🔌",
        "description": "GraphQL, Swagger, REST API discovery and analysis",
        "modules": ["api"],
        "scripts": ["modules/api/api_intelligence.py"],
        "priority": 3,
    },
    "auth-agent": {
        "name": "Auth Intelligence Agent",
        "icon": "🔐",
        "description": "OAuth, JWT, session, auth flow mapping",
        "scripts": ["modules/intelligence/workflow_intel.py"],
        "priority": 4,
    },
    "workflow-agent": {
        "name": "Workflow Mapper Agent",
        "icon": "🗺️",
        "description": "Critical workflow detection, attack surface mapping",
        "scripts": ["modules/intelligence/workflow_intel.py",
                     "modules/intelligence/bug_signal.py"],
        "priority": 5,
    },
    "cloud-agent": {
        "name": "Cloud Exposure Agent",
        "icon": "☁️",
        "description": "Cloud storage, Firebase, AWS exposure detection",
        "scripts": ["modules/intelligence/cloud_exposure.py"],
        "priority": 6,
    },
    "chain-builder": {
        "name": "Attack Chain Builder",
        "icon": "🔗",
        "description": "Correlate findings into exploit chains",
        "scripts": ["modules/intelligence/attack_chain.py",
                     "modules/intelligence/chain_builder.py"],
        "priority": 7,
    },
    "report-agent": {
        "name": "Report Generator Agent",
        "icon": "📊",
        "description": "Dashboard, reports, visualizations",
        "modules": ["reporting"],
        "priority": 8,
    },
}


class StrategicAgent:
    """
    Primary Strategic Agent — the brain of BitexRecon Ultra X.
    Controls all helper agents, adapts strategy based on findings.
    """

    def __init__(self, domain: str, hunt_mode: str = "full",
                 output_dir: Path = None):
        self.domain = domain
        self.hunt_mode = hunt_mode
        self.output_dir = output_dir or RECONX_ROOT / "output" / domain
        self.reasoning = ReasoningEngine(domain, self.output_dir)
        self.state = "INITIALIZING"
        self.active_agents: list[str] = []
        self.completed_agents: list[str] = []
        self.findings: list[dict] = []
        self.strategy: dict = {}
        self.start_time = time.time()
        self.log: list[dict] = []

        # Ensure output directories
        for d in ["knowledge_base", "strategy", "agent_logs"]:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)

    def _log(self, phase: str, message: str, data: dict = None):
        """Log strategic decision."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "message": message,
            "data": data or {},
        }
        self.log.append(entry)

    # ── Strategy Generation ────────────────────────────────────────────────
    def generate_strategy(self) -> dict:
        """Generate hunting strategy based on hunt mode and knowledge."""
        self._log("STRATEGY", f"Generating strategy for mode: {self.hunt_mode}")

        # Mode-specific agent selection
        mode_agents = self._select_agents_for_mode()

        # Build execution plan
        plan = {
            "domain": self.domain,
            "hunt_mode": self.hunt_mode,
            "timestamp": datetime.now().isoformat(),
            "phases": [
                {
                    "name": "RECONNAISSANCE",
                    "agents": ["recon-agent"],
                    "description": "Gather attack surface data",
                },
                {
                    "name": "INTELLIGENCE",
                    "agents": ["js-agent", "api-agent", "auth-agent",
                               "workflow-agent", "cloud-agent"],
                    "description": "Analyze and classify findings",
                },
                {
                    "name": "REASONING",
                    "agents": [],
                    "description": "KNOW→THINK→TEST→VALIDATE cycle",
                },
                {
                    "name": "CORRELATION",
                    "agents": ["chain-builder"],
                    "description": "Build attack chains and predictions",
                },
                {
                    "name": "REPORTING",
                    "agents": ["report-agent"],
                    "description": "Generate intelligence products",
                },
            ],
            "selected_agents": mode_agents,
            "confidence_threshold": 40,
            "max_depth": 3,
        }

        self.strategy = plan
        self._save_strategy(plan)
        return plan

    def _select_agents_for_mode(self) -> list:
        """Select which helper agents to activate based on hunt mode."""
        mode_map = {
            "xss-hunt": ["recon-agent", "js-agent", "workflow-agent",
                         "chain-builder", "report-agent"],
            "sqli-hunt": ["recon-agent", "api-agent", "workflow-agent",
                          "chain-builder", "report-agent"],
            "ssrf-hunt": ["recon-agent", "api-agent", "cloud-agent",
                          "chain-builder", "report-agent"],
            "idor-hunt": ["recon-agent", "api-agent", "auth-agent",
                          "chain-builder", "report-agent"],
            "graphql-hunt": ["recon-agent", "api-agent", "auth-agent",
                             "chain-builder", "report-agent"],
            "api-hunt": ["recon-agent", "api-agent", "auth-agent",
                         "js-agent", "chain-builder", "report-agent"],
            "auth-hunt": ["recon-agent", "auth-agent", "js-agent",
                          "workflow-agent", "chain-builder", "report-agent"],
            "upload-hunt": ["recon-agent", "workflow-agent", "js-agent",
                            "chain-builder", "report-agent"],
            "cloud-hunt": ["recon-agent", "cloud-agent", "js-agent",
                           "chain-builder", "report-agent"],
            "secrets-hunt": ["recon-agent", "js-agent", "cloud-agent",
                             "report-agent"],
            "js-hunt": ["recon-agent", "js-agent", "api-agent",
                        "chain-builder", "report-agent"],
            "chain-hunt": list(HELPER_AGENTS.keys()),
            "stealth-hunt": ["recon-agent", "js-agent", "report-agent"],
            "aggressive-hunt": list(HELPER_AGENTS.keys()),
            "full": list(HELPER_AGENTS.keys()),
        }
        return mode_map.get(self.hunt_mode, list(HELPER_AGENTS.keys()))

    # ── Reasoning Cycle Integration ────────────────────────────────────────
    def run_reasoning_cycle(self) -> dict:
        """Run the KNOW→THINK→TEST→VALIDATE reasoning cycle."""
        self._log("REASONING", "Starting reasoning cycle")
        self.state = "REASONING"

        # KNOW — load all collected intelligence
        data_sources = self._load_intelligence_data()

        # Run full cycle
        cycle_result = self.reasoning.run_cycle(data_sources)

        # Extract strategy
        think = cycle_result.get("think", {})
        strategy = think.get("strategy", {})

        # Generate hunter strategy document
        self._generate_hunter_strategy(think)

        self._log("REASONING", "Cycle complete",
                  {"cycle": cycle_result["cycle"]})
        return cycle_result

    def _load_intelligence_data(self) -> dict:
        """Load all intelligence outputs as data sources for reasoning."""
        sources = {}
        intel_dir = self.output_dir / "intelligence"

        # Load various intelligence files
        file_map = {
            "urls": self.output_dir / "urls" / "all_urls.txt",
            "live_hosts": self.output_dir / "live" / "live_hosts.txt",
            "js_urls": self.output_dir / "js" / "js_urls.txt",
            "xss_candidates": intel_dir / "xss_candidates.txt",
            "sqli_candidates": intel_dir / "sqli_candidates.txt",
            "ssrf_candidates": intel_dir / "ssrf_candidates.txt",
            "idor_candidates": intel_dir / "idor_candidates.txt",
        }

        for name, path in file_map.items():
            if path.exists():
                lines = [l.strip() for l in path.read_text().splitlines()
                         if l.strip()]
                sources[name] = lines

        # Load JSON intelligence
        json_files = {
            "api_inventory": intel_dir / "api_inventory.json",
            "workflows": intel_dir / "critical_workflows.json",
            "secrets": intel_dir / "js_secrets_deep.json",
            "dom_sinks": intel_dir / "dom_sinks.json",
            "attack_surface": intel_dir / "attack_surface_summary.json",
        }

        for name, path in json_files.items():
            if path.exists():
                try:
                    data = json.loads(path.read_text())
                    sources[name] = data
                except (json.JSONDecodeError, Exception):
                    pass

        return sources

    def _generate_hunter_strategy(self, think_result: dict):
        """Generate the hunter strategy document."""
        strategy_dir = self.output_dir / "strategy"
        strategy_dir.mkdir(parents=True, exist_ok=True)

        predictions = think_result.get("predictions", {})
        attack_paths = think_result.get("attack_paths", [])
        strategy = think_result.get("strategy", {})

        lines = [
            "═" * 60,
            "  🔥 HUNTER STRATEGY — BitexRecon Ultra X",
            "  Autonomous Hunter Intelligence OS",
            "═" * 60,
            "",
            f"  Target: {self.domain}",
            f"  Mode: {self.hunt_mode}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "  ═══ MOST LIKELY VULNERABLE FLOWS ═══",
            "",
        ]

        for i, item in enumerate(strategy.get("priority_order", [])[:10], 1):
            icon = "🔴" if item["total_signal"] > 100 else "🟠" if item["total_signal"] > 50 else "🟡"
            lines.append(f"  {icon} {i}. {item['vuln_type']}")
            lines.append(f"     Targets: {item['target_count']} | Signal: {item['total_signal']}")
            lines.append(f"     Action: {item['recommended_action']}")
            lines.append("")

        if attack_paths:
            lines.extend(["  ═══ ATTACK CHAINS ═══", ""])
            for path in attack_paths[:5]:
                lines.append(f"  🔗 {path['name']} [{path['severity']}]")
                lines.append(f"     Confidence: {path['confidence']}%")
                lines.append(f"     Steps: {' → '.join(path['steps'])}")
                lines.append("")

        lines.extend([
            "  ═══ RECOMMENDED TESTING ORDER ═══",
            "",
        ])
        for i, item in enumerate(strategy.get("priority_order", [])[:5], 1):
            lines.append(f"  {i}. {item['recommended_action']}")
        lines.append("")

        (strategy_dir / "hunter_strategy.txt").write_text("\n".join(lines))

        # JSON version
        (strategy_dir / "strategy.json").write_text(json.dumps({
            "domain": self.domain,
            "hunt_mode": self.hunt_mode,
            "timestamp": datetime.now().isoformat(),
            "predictions": {k: v[:10] for k, v in predictions.items()},
            "attack_paths": attack_paths[:10],
            "strategy": strategy,
        }, indent=2))

    # ── Save/Load ──────────────────────────────────────────────────────────
    def _save_strategy(self, plan: dict):
        """Save execution plan to disk."""
        path = self.output_dir / "strategy" / "execution_plan.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(plan, indent=2))

    def save_state(self):
        """Save agent state to disk."""
        state = {
            "domain": self.domain,
            "hunt_mode": self.hunt_mode,
            "state": self.state,
            "active_agents": self.active_agents,
            "completed_agents": self.completed_agents,
            "findings_count": len(self.findings),
            "elapsed": round(time.time() - self.start_time, 1),
            "log": self.log[-100:],
            "timestamp": datetime.now().isoformat(),
        }
        path = self.output_dir / "agent_logs" / "agent_state.json"
        path.write_text(json.dumps(state, indent=2))

    def get_status(self) -> dict:
        """Get current agent status summary."""
        return {
            "domain": self.domain,
            "state": self.state,
            "hunt_mode": self.hunt_mode,
            "elapsed": round(time.time() - self.start_time, 1),
            "active_agents": self.active_agents,
            "completed_agents": self.completed_agents,
            "findings": len(self.findings),
            "reasoning_cycles": self.reasoning.cycle_count,
        }


# ═══════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else ""
    mode = sys.argv[2] if len(sys.argv) > 2 else "full"

    if not domain:
        print("Usage: strategic_agent.py <domain> [hunt_mode]")
        sys.exit(1)

    agent = StrategicAgent(domain, mode)
    print(f"\n  ⚡ Strategic Agent — {domain}")
    print(f"  {'━' * 50}")
    print(f"  Mode: {mode}")

    # Generate strategy
    plan = agent.generate_strategy()
    print(f"  📋 Strategy generated: {len(plan['selected_agents'])} agents")

    # Run reasoning cycle
    result = agent.run_reasoning_cycle()
    cycle = result.get("think", {}).get("strategy", {})
    priorities = cycle.get("priority_order", [])

    if priorities:
        print(f"\n  🔥 TOP VULNERABILITY PREDICTIONS:")
        for i, p in enumerate(priorities[:5], 1):
            print(f"    {i}. {p['vuln_type']} "
                  f"({p['target_count']} targets, signal: {p['total_signal']})")

    paths = result.get("think", {}).get("attack_paths", [])
    if paths:
        print(f"\n  🔗 ATTACK PATHS: {len(paths)}")
        for p in paths[:3]:
            print(f"    ⚡ {p['name']} [{p['severity']}] ({p['confidence']}%)")

    agent.save_state()
    print(f"\n  💾 Strategy saved → {agent.output_dir}/strategy/")
