#!/usr/bin/env python3
"""
ReconX Ultra X — Plugin Ecosystem Loader
==========================================
Dynamic plugin system with YAML manifests, isolated execution,
and dependency management.

Plugin structure:
  plugins/<plugin_name>/
    plugin.yaml       — manifest (name, version, deps, hooks)
    execution.py      — main plugin logic
    payloads/          — custom payloads
    prompts/           — AI prompt templates
"""
import json, os, sys, importlib.util, subprocess
from pathlib import Path
from datetime import datetime

RECONX_ROOT = Path(os.environ.get("RECONX_ROOT",
    Path(__file__).resolve().parent.parent))
PLUGINS_DIR = RECONX_ROOT / "plugins"
PLUGINS_DIR.mkdir(exist_ok=True)


def _load_yaml_simple(path: Path) -> dict:
    """Load YAML without pyyaml dependency (simple key: value parser)."""
    result = {}
    if not path.exists():
        return result
    current_key = None
    current_list = None
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current_key and current_list is not None:
                current_list.append(stripped[2:].strip().strip('"').strip("'"))
            continue
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if val:
                if current_key and current_list is not None:
                    result[current_key] = current_list
                result[key] = val
                current_key = None
                current_list = None
            else:
                if current_key and current_list is not None:
                    result[current_key] = current_list
                current_key = key
                current_list = []
    if current_key and current_list is not None:
        result[current_key] = current_list
    return result


class Plugin:
    """Represents a loaded plugin."""
    def __init__(self, name: str, path: Path, manifest: dict):
        self.name = name
        self.path = path
        self.manifest = manifest
        self.version = manifest.get("version", "0.1.0")
        self.description = manifest.get("description", "")
        self.author = manifest.get("author", "unknown")
        self.enabled = manifest.get("enabled", "true").lower() == "true"
        self.hooks = manifest.get("hooks", [])
        self.dependencies = manifest.get("dependencies", [])
        self.module = None

    def load(self) -> bool:
        """Load the plugin's execution module."""
        exec_path = self.path / "execution.py"
        if not exec_path.exists():
            return False
        try:
            spec = importlib.util.spec_from_file_location(
                f"plugin_{self.name}", str(exec_path))
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
            return True
        except Exception as e:
            print(f"  ⚠️  Plugin load error [{self.name}]: {e}")
            return False

    def execute(self, domain: str, context: dict = None) -> dict:
        """Execute the plugin's main function."""
        if not self.module:
            if not self.load():
                return {"error": f"Failed to load plugin {self.name}"}
        try:
            if hasattr(self.module, "run"):
                return self.module.run(domain, context or {})
            elif hasattr(self.module, "main"):
                return self.module.main(domain, context or {})
            return {"error": "No run() or main() function found"}
        except Exception as e:
            return {"error": str(e)}


class PluginLoader:
    """Manages the plugin ecosystem."""
    def __init__(self):
        self.plugins: dict[str, Plugin] = {}
        self.hooks: dict[str, list[Plugin]] = {}

    def discover(self) -> int:
        """Discover all plugins in the plugins directory."""
        count = 0
        if not PLUGINS_DIR.exists():
            return 0

        for plugin_dir in sorted(PLUGINS_DIR.iterdir()):
            if not plugin_dir.is_dir():
                continue
            manifest_path = plugin_dir / "plugin.yaml"
            if not manifest_path.exists():
                continue

            manifest = _load_yaml_simple(manifest_path)
            name = manifest.get("name", plugin_dir.name)
            plugin = Plugin(name, plugin_dir, manifest)

            if plugin.enabled:
                self.plugins[name] = plugin
                # Register hooks
                for hook in plugin.hooks:
                    if hook not in self.hooks:
                        self.hooks[hook] = []
                    self.hooks[hook].append(plugin)
                count += 1

        return count

    def get_plugin(self, name: str) -> Plugin:
        return self.plugins.get(name)

    def list_plugins(self) -> list:
        return [{"name": p.name, "version": p.version,
                 "description": p.description, "enabled": p.enabled,
                 "hooks": p.hooks}
                for p in self.plugins.values()]

    def execute_hook(self, hook: str, domain: str,
                     context: dict = None) -> list:
        """Execute all plugins registered for a hook."""
        results = []
        for plugin in self.hooks.get(hook, []):
            result = plugin.execute(domain, context)
            results.append({"plugin": plugin.name, "result": result})
        return results

    def execute_plugin(self, name: str, domain: str,
                       context: dict = None) -> dict:
        """Execute a specific plugin by name."""
        plugin = self.plugins.get(name)
        if not plugin:
            return {"error": f"Plugin not found: {name}"}
        return plugin.execute(domain, context)


def create_plugin_template(name: str):
    """Create a new plugin from template."""
    plugin_dir = PLUGINS_DIR / name
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "payloads").mkdir(exist_ok=True)
    (plugin_dir / "prompts").mkdir(exist_ok=True)

    # plugin.yaml
    (plugin_dir / "plugin.yaml").write_text(f"""# ReconX Ultra X Plugin Manifest
name: {name}
version: 0.1.0
description: Custom {name} plugin
author: hunter
enabled: true

# Hooks: pre_recon, post_recon, pre_intelligence, post_intelligence,
#         pre_validation, post_validation, pre_report, post_report
hooks:
  - post_intelligence

dependencies:
  - httpx
""")

    # execution.py
    (plugin_dir / "execution.py").write_text(f'''#!/usr/bin/env python3
"""ReconX Ultra X Plugin: {name}"""
import json
from pathlib import Path

def run(domain: str, context: dict) -> dict:
    """Main plugin entry point.
    Args:
        domain: Target domain
        context: Execution context with output_dir, config, etc.
    Returns:
        dict with plugin results
    """
    print(f"  🔌 Plugin [{name}] running for {{domain}}")

    results = {{
        "plugin": "{name}",
        "domain": domain,
        "findings": [],
        "status": "completed",
    }}

    # Your plugin logic here
    # output_dir = Path(context.get("output_dir", f"output/{{domain}}"))

    return results
''')
    print(f"  ✅ Plugin template created: {plugin_dir}")


# ═══════════════════════════════════════════════════════════════════════════
# Global singleton
# ═══════════════════════════════════════════════════════════════════════════
_loader = None

def get_plugin_loader() -> PluginLoader:
    global _loader
    if _loader is None:
        _loader = PluginLoader()
        _loader.discover()
    return _loader

# Aliases for API compatibility
PluginManager = PluginLoader
load_plugins = get_plugin_loader


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "create":
        name = sys.argv[2] if len(sys.argv) > 2 else "my_plugin"
        create_plugin_template(name)
    else:
        loader = get_plugin_loader()
        plugins = loader.list_plugins()
        print(f"\n  🔌 Plugin Ecosystem — {len(plugins)} plugins loaded")
        for p in plugins:
            print(f"    {'✅' if p['enabled'] else '⚪'} {p['name']} "
                  f"v{p['version']} — {p['description']}")
            if p['hooks']:
                print(f"       Hooks: {', '.join(p['hooks'])}")
