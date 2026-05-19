#!/usr/bin/env python3
"""
ReconX Ultra X — Real-Time Performance Metrics Engine
======================================================
Tracks all recon operations in real-time:
  - requests/sec, URLs processed, JS analyzed
  - APIs discovered, secrets found, vuln signals
  - active workers, CPU/RAM, ETA
  - per-module timing and throughput

Writes: output/<domain>/intelligence/performance_metrics.json (updated every 2s)
"""

import json
import os
import sys
import time
import threading
from pathlib import Path
from datetime import datetime

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent


class MetricsEngine:
    """Thread-safe real-time metrics tracker."""

    def __init__(self, domain):
        self.domain = domain
        self.output_dir = RECONX_ROOT / "output" / domain / "intelligence"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_file = self.output_dir / "performance_metrics.json"
        self.lock = threading.Lock()
        self.start_time = time.time()
        self._running = False
        self._writer_thread = None

        self.counters = {
            "subdomains_discovered": 0,
            "live_hosts_found": 0,
            "urls_processed": 0,
            "urls_parameterized": 0,
            "js_files_analyzed": 0,
            "apis_discovered": 0,
            "secrets_detected": 0,
            "vuln_signals": 0,
            "endpoints_scored": 0,
            "requests_total": 0,
            "requests_failed": 0,
            "bytes_downloaded": 0,
            "nuclei_findings": 0,
            "takeover_candidates": 0,
            "bypass_403_found": 0,
            "hidden_params_found": 0,
            "xss_candidates": 0,
            "sqli_candidates": 0,
            "ssrf_candidates": 0,
            "lfi_candidates": 0,
            "ssti_candidates": 0,
        }

        self.rates = {
            "requests_per_sec": 0.0,
            "urls_per_sec": 0.0,
            "js_per_min": 0.0,
        }

        self.workers = {
            "active": 0,
            "total": 0,
            "idle": 0,
        }

        self.modules = {}  # module_name -> {start, end, status, results}
        self.current_module = ""
        self._last_req_count = 0
        self._last_rate_time = time.time()

    def increment(self, key, value=1):
        """Thread-safe counter increment."""
        with self.lock:
            if key in self.counters:
                self.counters[key] += value

    def set_counter(self, key, value):
        """Set a counter to a specific value."""
        with self.lock:
            self.counters[key] = value

    def set_workers(self, active, total=0):
        """Update worker stats."""
        with self.lock:
            self.workers["active"] = active
            self.workers["total"] = total or active
            self.workers["idle"] = max(0, (total or active) - active)

    def module_start(self, name):
        """Record module start."""
        with self.lock:
            self.current_module = name
            self.modules[name] = {
                "start": time.time(),
                "end": None,
                "status": "running",
                "results": 0,
                "duration_sec": 0,
            }

    def module_end(self, name, results=0, status="completed"):
        """Record module completion."""
        with self.lock:
            if name in self.modules:
                self.modules[name]["end"] = time.time()
                self.modules[name]["status"] = status
                self.modules[name]["results"] = results
                self.modules[name]["duration_sec"] = round(
                    self.modules[name]["end"] - self.modules[name]["start"], 1
                )

    def _calculate_rates(self):
        """Calculate throughput rates."""
        now = time.time()
        elapsed = now - self._last_rate_time
        if elapsed >= 1.0:
            req_delta = self.counters["requests_total"] - self._last_req_count
            self.rates["requests_per_sec"] = round(req_delta / elapsed, 1)
            self._last_req_count = self.counters["requests_total"]
            self._last_rate_time = now

        total_elapsed = now - self.start_time
        if total_elapsed > 0:
            self.rates["urls_per_sec"] = round(
                self.counters["urls_processed"] / total_elapsed, 1
            )
            self.rates["js_per_min"] = round(
                self.counters["js_files_analyzed"] / (total_elapsed / 60), 1
            )

    def _estimate_eta(self):
        """Estimate remaining time based on current progress."""
        elapsed = time.time() - self.start_time
        # Simple heuristic: estimate based on module completion
        completed = sum(1 for m in self.modules.values() if m["status"] == "completed")
        total = max(len(self.modules), 16)  # 16 modules in pipeline
        if completed > 0:
            avg_time = elapsed / completed
            remaining = (total - completed) * avg_time
            mins = int(remaining // 60)
            secs = int(remaining % 60)
            return f"{mins:02d}m {secs:02d}s"
        return "calculating..."

    def get_snapshot(self):
        """Get current metrics snapshot."""
        with self.lock:
            self._calculate_rates()
            elapsed = time.time() - self.start_time

            return {
                "domain": self.domain,
                "timestamp": datetime.now().isoformat(),
                "uptime_sec": round(elapsed, 1),
                "uptime_human": f"{int(elapsed//3600):02d}h {int((elapsed%3600)//60):02d}m {int(elapsed%60):02d}s",
                "eta": self._estimate_eta(),
                "current_module": self.current_module,
                "counters": dict(self.counters),
                "rates": dict(self.rates),
                "workers": dict(self.workers),
                "modules": {
                    k: {**v, "start": None, "end": None}
                    for k, v in self.modules.items()
                },
                "system": self._get_system_stats(),
            }

    def _get_system_stats(self):
        """Get CPU/RAM usage."""
        stats = {"cpu_percent": 0, "ram_used_mb": 0, "ram_total_mb": 0}
        try:
            with open("/proc/loadavg") as f:
                load = f.read().split()
                stats["cpu_load_1m"] = float(load[0])
            with open("/proc/meminfo") as f:
                mem = {}
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        mem[parts[0].rstrip(":")] = int(parts[1])
                stats["ram_total_mb"] = mem.get("MemTotal", 0) // 1024
                stats["ram_used_mb"] = (
                    mem.get("MemTotal", 0) - mem.get("MemAvailable", 0)
                ) // 1024
        except Exception:
            pass
        return stats

    def write_metrics(self):
        """Write current metrics to JSON file."""
        snapshot = self.get_snapshot()
        try:
            with open(self.metrics_file, "w") as f:
                json.dump(snapshot, f, indent=2)
        except Exception:
            pass

    def print_status_line(self):
        """Print a compact status line to stderr."""
        s = self.get_snapshot()
        c = s["counters"]
        r = s["rates"]
        line = (
            f"\r\033[36m[METRICS]\033[0m "
            f"URLs:{c['urls_processed']:,} | "
            f"JS:{c['js_files_analyzed']:,} | "
            f"APIs:{c['apis_discovered']:,} | "
            f"Vulns:{c['vuln_signals']} | "
            f"Speed:{r['requests_per_sec']} req/s | "
            f"Workers:{s['workers']['active']} | "
            f"ETA:{s['eta']}"
        )
        print(line, end="", file=sys.stderr, flush=True)

    def start_background_writer(self, interval=2):
        """Start a background thread that writes metrics periodically."""
        self._running = True

        def _writer():
            while self._running:
                self.write_metrics()
                time.sleep(interval)

        self._writer_thread = threading.Thread(target=_writer, daemon=True)
        self._writer_thread.start()

    def stop(self):
        """Stop the background writer."""
        self._running = False
        self.write_metrics()  # Final write


# Singleton for use across modules
_engine = None


def get_metrics(domain=None):
    """Get or create the global metrics engine."""
    global _engine
    if _engine is None:
        if domain is None:
            domain = os.environ.get("RECONX_DOMAIN", "unknown")
        _engine = MetricsEngine(domain)
    return _engine


def init_metrics(domain):
    """Initialize metrics for a new scan."""
    global _engine
    _engine = MetricsEngine(domain)
    _engine.start_background_writer()
    return _engine


# CLI usage: python3 metrics_engine.py <domain> --status
if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else None
    if not domain:
        print("Usage: metrics_engine.py <domain> [--status]")
        sys.exit(1)

    metrics_file = RECONX_ROOT / "output" / domain / "intelligence" / "performance_metrics.json"
    if metrics_file.exists():
        with open(metrics_file) as f:
            data = json.load(f)
        c = data.get("counters", {})
        r = data.get("rates", {})
        w = data.get("workers", {})
        s = data.get("system", {})

        print(f"\n{'='*60}")
        print(f"  ReconX Ultra X — Performance Metrics")
        print(f"  Domain: {data.get('domain', '?')}")
        print(f"  Uptime: {data.get('uptime_human', '?')} | ETA: {data.get('eta', '?')}")
        print(f"{'='*60}")
        print(f"  URLs Processed:     {c.get('urls_processed', 0):>10,}")
        print(f"  JS Analyzed:        {c.get('js_files_analyzed', 0):>10,}")
        print(f"  APIs Discovered:    {c.get('apis_discovered', 0):>10,}")
        print(f"  Secrets Detected:   {c.get('secrets_detected', 0):>10,}")
        print(f"  Vuln Signals:       {c.get('vuln_signals', 0):>10,}")
        print(f"  Speed:              {r.get('requests_per_sec', 0):>10} req/s")
        print(f"  Workers:            {w.get('active', 0):>10} active")
        print(f"  RAM:                {s.get('ram_used_mb', 0):>10} MB")
        print(f"{'='*60}\n")
    else:
        print(f"No metrics found for {domain}")
