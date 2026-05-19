#!/usr/bin/env python3
"""
ReconX Ultra X — Autonomous Command Router
=============================================
Dispatches /commands to the appropriate agents and modules.

Commands:
  /recon, /hunt, /validate, /report, /autopilot, /intel,
  /surface, /chain, /triage, /auth-session, /graphql-hunt,
  /js-hunt, /cloud-hunt, /upload-hunt, /monitor, /dna, /status
"""
import json, os, sys, subprocess
from pathlib import Path
from datetime import datetime

RECONX_ROOT = Path(os.environ.get("RECONX_ROOT",
    Path(__file__).resolve().parent.parent))


COMMANDS = {
    "/recon": {
        "description": "Run full reconnaissance pipeline",
        "modules": "subdomains,live,urls,dedup,js",
        "agent": "recon-agent",
    },
    "/hunt": {
        "description": "Run hunt mode with specified type",
        "usage": "/hunt <type> — xss|sqli|ssrf|idor|graphql|api|auth|upload|cloud|secrets|js|chain|stealth|aggressive",
    },
    "/validate": {
        "description": "Run validation engine on candidates",
        "modules": "validation",
        "agent": "validation",
    },
    "/report": {
        "description": "Generate reports and dashboard",
        "modules": "reporting",
        "agent": "report-agent",
    },
    "/autopilot": {
        "description": "Full autonomous recon → intelligence → validation → report",
        "modules": "all",
    },
    "/intel": {
        "description": "Run intelligence analysis on collected data",
        "modules": "intelligence",
        "agent": "workflow-agent",
    },
    "/surface": {
        "description": "Generate attack surface ranking",
        "script": "modules/intelligence/surface_ranker.py",
    },
    "/chain": {
        "description": "Run attack chain builder",
        "script": "modules/intelligence/chain_builder.py",
    },
    "/triage": {
        "description": "Run AI hunter prioritizer",
        "script": "modules/intelligence/ai_hunter.py",
    },
    "/auth-session": {
        "description": "Manage auth profiles",
        "script": "core/auth_manager.py",
    },
    "/dna": {
        "description": "Generate target DNA fingerprint",
        "script": "modules/intelligence/target_dna.py",
    },
    "/js-hunt": {
        "description": "Deep JavaScript intelligence analysis",
        "modules": "subdomains,live,urls,js,intelligence,reporting",
        "hunt_mode": "js-hunt",
    },
    "/graphql-hunt": {
        "description": "GraphQL-focused hunting",
        "modules": "subdomains,live,urls,api,intelligence,reporting",
        "hunt_mode": "graphql-hunt",
    },
    "/cloud-hunt": {
        "description": "Cloud exposure hunting",
        "modules": "subdomains,live,urls,js,intelligence,reporting",
        "hunt_mode": "cloud-hunt",
    },
    "/upload-hunt": {
        "description": "Upload vulnerability hunting",
        "modules": "subdomains,live,urls,content,intelligence,reporting",
        "hunt_mode": "upload-hunt",
    },
    "/monitor": {
        "description": "Continuous monitoring mode",
        "script": "core/monitor_engine.py",
    },
    "/status": {
        "description": "Show current scan status",
    },
    "/strategy": {
        "description": "Generate hunter strategy",
        "script": "core/strategic_agent.py",
    },
    "/plugins": {
        "description": "List available plugins",
        "script": "core/plugin_loader.py",
    },
}


def route_command(command: str, domain: str, args: list = None) -> dict:
    """Route a command to the appropriate handler."""
    args = args or []
    cmd_config = COMMANDS.get(command)

    if not cmd_config:
        return {"error": f"Unknown command: {command}",
                "available": list(COMMANDS.keys())}

    result = {
        "command": command,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "status": "dispatched",
    }

    # Script-based commands
    if "script" in cmd_config:
        script = RECONX_ROOT / cmd_config["script"]
        if script.exists():
            try:
                cmd_args = ["python3", str(script), domain] + args
                proc = subprocess.run(cmd_args, capture_output=True, text=True,
                                      timeout=600,
                                      env={**os.environ,
                                           "RECONX_ROOT": str(RECONX_ROOT)})
                result["output"] = proc.stdout
                result["status"] = "completed" if proc.returncode == 0 else "error"
                if proc.stderr:
                    result["stderr"] = proc.stderr[-500:]
            except subprocess.TimeoutExpired:
                result["status"] = "timeout"
            except Exception as e:
                result["status"] = "error"
                result["error"] = str(e)
        else:
            result["status"] = "error"
            result["error"] = f"Script not found: {cmd_config['script']}"

    # Module-based commands
    elif "modules" in cmd_config:
        modules = cmd_config["modules"]
        hunt_mode = cmd_config.get("hunt_mode", "full")

        if modules == "all":
            # Autopilot — run everything
            result["action"] = "autopilot"
            result["command_line"] = (
                f"bash {RECONX_ROOT}/reconx.sh -d {domain} "
                f"--hunt {hunt_mode}")
        else:
            result["action"] = "run_modules"
            result["command_line"] = (
                f"bash {RECONX_ROOT}/reconx.sh -d {domain} "
                f"--modules {modules} --hunt {hunt_mode}")

    # Hunt mode commands
    elif command == "/hunt":
        if args:
            hunt_type = args[0]
            result["action"] = "hunt"
            result["hunt_mode"] = hunt_type
            result["command_line"] = (
                f"bash {RECONX_ROOT}/reconx.sh -d {domain} "
                f"--hunt {hunt_type}")
        else:
            result["error"] = "Specify hunt type: /hunt <type>"
            result["available_types"] = [
                "xss-hunt", "sqli-hunt", "ssrf-hunt", "idor-hunt",
                "graphql-hunt", "api-hunt", "auth-hunt", "upload-hunt",
                "cloud-hunt", "secrets-hunt", "js-hunt", "chain-hunt",
                "stealth-hunt", "aggressive-hunt"
            ]

    # Status command
    elif command == "/status":
        result["action"] = "status"
        out_dir = RECONX_ROOT / "output" / domain
        if out_dir.exists():
            from pathlib import Path
            stats = {}
            for name, path in {
                "subdomains": "subs/all_subdomains.txt",
                "live_hosts": "live/live_hosts.txt",
                "urls": "urls/all_urls.txt",
                "js_files": "js/js_urls.txt",
            }.items():
                p = out_dir / path
                if p.exists():
                    stats[name] = sum(1 for l in p.read_text().splitlines() if l.strip())
            result["stats"] = stats
        else:
            result["stats"] = "No data collected yet"

    return result


def print_commands():
    """Print available commands."""
    print("\n  ⚡ BitexRecon Ultra X — Command System")
    print(f"  {'━' * 50}")
    for cmd, config in COMMANDS.items():
        print(f"  {cmd:20s} {config['description']}")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_commands()
        sys.exit(0)

    command = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 else ""
    args = sys.argv[3:]

    if command == "--help" or command == "-h":
        print_commands()
    elif not domain:
        print(f"Usage: command_router.py <command> <domain> [args...]")
    else:
        result = route_command(command, domain, args)
        if result.get("command_line"):
            print(f"  → {result['command_line']}")
        if result.get("output"):
            print(result["output"])
        if result.get("error"):
            print(f"  ❌ {result['error']}")
        if result.get("stats"):
            print(json.dumps(result["stats"], indent=2))
