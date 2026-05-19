#!/usr/bin/env python3
"""
ReconX Ultra X — Tool Auto-Discovery & Health Check Engine
Discovers, validates, and registers all security tools.
"""
import json, os, shutil, subprocess, sys
from pathlib import Path

RECONX_ROOT = Path(__file__).resolve().parent.parent  # core/ → reconx/
TOOLS_DIR = RECONX_ROOT / "tools"
REGISTRY_FILE = RECONX_ROOT / "core" / "tools_registry.json"

# ═══════════════════════════════════════════════════════════════════════════
# Tool Definitions — name, search paths, test command
# ═══════════════════════════════════════════════════════════════════════════
TOOL_DEFS = {
    # System PATH tools
    "dalfox":     {"type": "binary", "test": "dalfox version",    "required": False},
    "nuclei":     {"type": "binary", "test": "nuclei -version",   "required": True},
    "httpx":      {"type": "binary", "test": "httpx -version",    "required": True},
    "subfinder":  {"type": "binary", "test": "subfinder -version","required": True},
    "katana":     {"type": "binary", "test": "katana -version",   "required": False},
    "naabu":      {"type": "binary", "test": "naabu -version",    "required": False},
    "ffuf":       {"type": "binary", "test": "ffuf -V",           "required": False},
    "sqlmap":     {"type": "binary", "test": "sqlmap --version",  "required": False},
    "gf":         {"type": "binary", "test": "gf -h",             "required": False},
    "qsreplace":  {"type": "binary", "test": "echo ok | qsreplace test", "required": False},
    # Local Python tools
    "loxs":       {"type": "python_local", "path": "tools/loxs/loxs.py",
                   "venv": "tools/loxs/venv", "test": "python3 -c 'import sys'", "required": False},
    "xsstrike":   {"type": "python_local", "path": "tools/XSStrike/xsstrike.py",
                   "test": "python3 -c 'import sys'", "required": False},
}


def find_tool(name, tdef):
    """Find a tool — check PATH, then local tools dir."""
    result = {"name": name, "found": False, "path": "", "version": "", "type": tdef["type"],
              "health": "missing", "required": tdef.get("required", False)}

    if tdef["type"] == "binary":
        path = shutil.which(name)
        if path:
            result["found"] = True
            result["path"] = path
            result["health"] = "ok"
            # Get version
            try:
                out = subprocess.run(tdef["test"].split(), capture_output=True, text=True, timeout=5)
                result["version"] = out.stdout.strip().split("\n")[0][:80]
            except:
                result["version"] = "unknown"

    elif tdef["type"] == "python_local":
        local_path = RECONX_ROOT / tdef["path"]
        if local_path.exists():
            result["found"] = True
            result["path"] = str(local_path)
            result["health"] = "ok"
            # Check venv
            venv = tdef.get("venv")
            if venv:
                venv_path = RECONX_ROOT / venv
                if venv_path.exists():
                    result["venv"] = str(venv_path)
                    result["exec"] = f"{venv_path}/bin/python3 {local_path}"
                else:
                    result["exec"] = f"python3 {local_path}"
                    result["health"] = "no_venv"
            else:
                result["exec"] = f"python3 {local_path}"

    return result


def discover_all():
    """Discover all tools and build registry."""
    registry = {}
    print("\n  🔍 Tool Auto-Discovery Engine")
    print("  " + "─" * 50)

    found = 0
    missing = 0
    for name, tdef in TOOL_DEFS.items():
        r = find_tool(name, tdef)
        registry[name] = r
        if r["found"]:
            found += 1
            icon = "✅"
            detail = r.get("version") or r.get("path", "")
            if r["health"] == "no_venv":
                icon = "⚠️"
                detail += " (no venv)"
        else:
            missing += 1
            icon = "❌" if r["required"] else "⚪"
            detail = "not found"

        print(f"    {icon} {name:15s} {detail[:60]}")

    print(f"\n    📊 {found} found | {missing} missing")

    # Save registry
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(REGISTRY_FILE, "w") as f:
        json.dump(registry, f, indent=2)
    print(f"    💾 Saved → {REGISTRY_FILE}")

    return registry


def get_tool_cmd(name):
    """Get the correct command to execute a tool."""
    if REGISTRY_FILE.exists():
        reg = json.loads(REGISTRY_FILE.read_text())
        if name in reg and reg[name].get("found"):
            return reg[name].get("exec", reg[name].get("path", name))
    # Fallback: check common paths
    if name == "loxs":
        p = TOOLS_DIR / "loxs" / "loxs.py"
        v = TOOLS_DIR / "loxs" / "venv" / "bin" / "python3"
        if p.exists():
            return f"{v} {p}" if v.exists() else f"python3 {p}"
    if name == "xsstrike":
        p = TOOLS_DIR / "XSStrike" / "xsstrike.py"
        if p.exists():
            return f"python3 {p}"
    return shutil.which(name) or name


if __name__ == "__main__":
    discover_all()
