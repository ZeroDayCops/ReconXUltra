<p align="center">
  <img src="https://img.shields.io/badge/⚡-ReconX_Ultra_X-7c5bf5?style=for-the-badge&labelColor=0a0a0f" alt="ReconX Ultra X" height="40">
</p>

<h1 align="center">⚡ ReconX Ultra X</h1>

<p align="center">
  <b>Behavior-Aware Autonomous Hunter Intelligence Platform</b><br>
  <i>Evidence-backed reasoning • Behavioral intelligence • Workflow-aware attack-path generation • Explainable AI-driven bug bounty intelligence</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-7c5bf5?style=flat-square&labelColor=0a0a0f" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-34d399?style=flat-square&labelColor=0a0a0f" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux-5bc0f5?style=flat-square&labelColor=0a0a0f" alt="Platform">
  <img src="https://img.shields.io/badge/python-3.8+-f59e0b?style=flat-square&labelColor=0a0a0f" alt="Python">
  <img src="https://img.shields.io/badge/bash-5.0+-ec4899?style=flat-square&labelColor=0a0a0f" alt="Bash">
  <img src="https://img.shields.io/badge/go-1.20+-06b6d4?style=flat-square&labelColor=0a0a0f" alt="Go">
  <img src="https://img.shields.io/badge/modules-82+-ef4444?style=flat-square&labelColor=0a0a0f" alt="Modules">
  <img src="https://img.shields.io/badge/wordlists-68-a78bfa?style=flat-square&labelColor=0a0a0f" alt="Wordlists">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/EBRE-Evidence_Based_Reasoning-34d399?style=flat-square" alt="EBRE">
  <img src="https://img.shields.io/badge/Behavioral-L5_Intelligence-7c5bf5?style=flat-square" alt="Behavioral">
  <img src="https://img.shields.io/badge/Reasoning-L1→L5-f59e0b?style=flat-square" alt="Reasoning">
  <img src="https://img.shields.io/badge/Modes-18_Hunt_Modes-ef4444?style=flat-square" alt="Modes">
</p>

---

## 🧬 What is ReconX Ultra X?

ReconX Ultra X is **not a recon tool**. It's an **Autonomous Hunter Intelligence Operating System** — a behavior-aware, evidence-backed attack surface intelligence platform that **thinks like a bug bounty hunter**.

> 🧠 **It doesn't just find endpoints. It understands applications — their auth flows, object relationships, workflow transitions, DOM behavior, API patterns, and session management — then generates evidence-backed attack paths with explainable confidence scores.**

### The Evolution

```
ReconX v1.0         → Passive recon framework
ReconX Ultra v2.0   → Attack surface intelligence + AI prioritization
ReconX Ultra X v3.0 → Behavior-aware autonomous hunter intelligence
```

---

## 🔥 Why ReconX Ultra X?

<table>
<tr><th>Capability</th><th>Traditional Recon</th><th>ReconX Ultra X</th></tr>
<tr><td><b>Reasoning</b></td><td>URL pattern matching</td><td><b>5-level behavioral reasoning engine</b></td></tr>
<tr><td><b>Evidence</b></td><td>None — guesswork</td><td><b>Every finding has OBSERVED vs PREDICTED evidence</b></td></tr>
<tr><td><b>Auth</b></td><td>Ignores auth state</td><td><b>Guest/user/admin differential analysis</b></td></tr>
<tr><td><b>Objects</b></td><td>Sees <code>id=123</code></td><td><b>Understands "invoice object exposed via API"</b></td></tr>
<tr><td><b>Workflows</b></td><td>Scans URLs</td><td><b>Maps login→dashboard, checkout→payment state machines</b></td></tr>
<tr><td><b>Attack Paths</b></td><td>Static signatures</td><td><b>Multi-evidence behavioral chain reasoning</b></td></tr>
<tr><td><b>Guidance</b></td><td>Dump findings</td><td><b>Live hunter guidance: "JWT in localStorage → XSS → admin takeover"</b></td></tr>
<tr><td><b>Visualization</b></td><td>Text reports</td><td><b>Interactive Cytoscape.js behavior graph + Chart.js dashboard</b></td></tr>
<tr><td><b>Intelligence</b></td><td>~5 modules</td><td><b>82+ modules across 12 module groups</b></td></tr>
<tr><td><b>Wordlists</b></td><td>Manual selection</td><td><b>68 wordlists auto-classified by tech fingerprint</b></td></tr>
</table>

---

## 🧠 Intelligence Architecture

```
┌──────────────────── RECONX ULTRA X ────────────────────┐
│                                                        │
│  Phase 1: RECON                                        │
│  ├── Subdomains (10+ sources)                          │
│  ├── Live Hosts (httpx full probe)                     │
│  ├── URL Intelligence (5 crawlers)                     │
│  ├── JS Deep Analysis (secrets, sinks, APIs)           │
│  └── API Discovery (GraphQL, Swagger, REST)            │
│                                                        │
│  Phase 2: INTELLIGENCE                                 │
│  ├── Target DNA (tech fingerprint → wordlist mapping)  │
│  ├── AI Risk Prioritizer (12 category scoring)         │
│  ├── Surface Ranker (attack surface scoring)           │
│  └── 68 Wordlists (auto-classified)                    │
│                                                        │
│  Phase 3: EBRE (Evidence-Based Reasoning Engine)       │
│  ├── Observed Signals (parallel HTTP probing)          │
│  ├── Micro-Validation (lightweight vuln probes)        │
│  ├── Workflow Evidence (business logic mapping)        │
│  ├── Reasoning Engine (multi-source correlation)       │
│  ├── Attack Paths (≥2 evidence threshold)              │
│  ├── Reasoning Trace (explainability layer)            │
│  └── Strategy Engine (hunter strategy generation)      │
│                                                        │
│  Phase 4: BEHAVIORAL INTELLIGENCE          ← NEW ✨    │
│  ├── Auth-State Analysis (guest/user/admin diffs)      │
│  ├── Object Relationships (IDOR + ownership mapping)   │
│  ├── Workflow Transitions (7 state machines)           │
│  ├── DOM Observer (14 sink types + SPA routes)         │
│  ├── Session Intelligence (cookie/CORS/fixation)       │
│  ├── API Behavior (CRUD patterns + relationships)      │
│  ├── State Diff Engine (method/header/error diffs)     │
│  └── Target Understanding (unified brain + guidance)   │
│                                                        │
│  Phase 5-8: EXPLOIT → CHAINS → REPORT → VISUALIZE     │
│  ├── XSS/SQLi/SSRF/LFI/SSTI validation               │
│  ├── Attack chain correlation                          │
│  ├── Interactive dashboard (Chart.js + D3.js)          │
│  └── Behavior graph (Cytoscape.js)                     │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

## 🔬 Five Reasoning Levels

ReconX Ultra X reasons at **5 progressive depth levels**:

| Level | Name | What It Does | Example |
|:-----:|------|-------------|---------|
| **L1** | URL Heuristics | Pattern matching on endpoints | `/admin/` → admin panel |
| **L2** | Response Intelligence | HTTP probe + response analysis | `200 OK + 3KB JSON` → data exposure |
| **L3** | Workflow Understanding | State machines + object mapping | `checkout→payment bypass risk` |
| **L4** | Browser Observation | DOM sinks + SPA routes + JS APIs | `innerHTML + location.hash` → DOM XSS |
| **L5** | Behavioral Reasoning | Unified understanding + attack guidance | `JWT in localStorage + XSS → admin takeover` |

---

## ⚡ Core Engines

### 🔐 Auth-State Behavioral Intelligence
Real HTTP-based auth differential analysis:
- Probes endpoints as guest / user / admin
- Detects broken access control on admin endpoints
- Compares sequential object IDs for IDOR
- Tests destructive HTTP methods (DELETE, PUT)
- Analyzes cookie attributes (HttpOnly, Secure, SameSite)

### 🔗 Object Relationship Intelligence
Understands 10 object types: users, invoices, orders, tickets, payments, documents, messages, admin resources, API resources, media — maps exposure, ownership, and cross-object relationships.

### 🔄 Workflow Transition Engine
Maps 7 workflow state machines with bypass detection:
- **Authentication**: login → submit → auth → dashboard
- **Registration**: signup → verify → account created
- **File Upload**: form → validate → store → access
- **Checkout**: cart → checkout → payment → confirm
- **Password Reset**: forgot → token → new password
- **Export/Report**: config → generate → download
- **OAuth**: authorize → consent → callback → exchange

### 🔍 DOM & SPA Intelligence
Static JS analysis detecting 14 DOM sink types (innerHTML, eval, document.write, postMessage, jQuery .html(), React dangerouslySetInnerHTML, Vue v-html, Angular bypassSecurityTrust), SPA route extraction, and API endpoint mapping.

### 🧠 Evidence-Based Reasoning Engine (EBRE)
Every finding carries evidence:
```
Observed:
  ✔ SVG upload accepted (200 OK)
  ✔ File rendered inline (Content-Type: image/svg+xml)
  ✔ JWT stored in localStorage
  ✔ Upload visible cross-user (sequential ID)

Predicted:
  ⚠ SVG upload → stored XSS → JWT theft → admin API access

Confidence: 81%
  +25 Upload accepted
  +20 Inline rendering
  +20 JWT in localStorage
  +16 Cross-user visibility
```

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/yourusername/BitexReconTool.git
cd BitexReconTool/reconx

# Run the installer
chmod +x install/installer.sh
./install/installer.sh

source ~/.bashrc
```

### Configuration

```bash
# Set API keys and preferences
nano configs/default.yaml
```

### Usage

```bash
# 🤖 AUTOPILOT: Full autonomous hunt (all 8 phases)
./reconx.sh -d target.com --autopilot

# ⚡ Quick recon
./reconx.sh -d target.com

# 🎯 Hunt mode (XSS focus)
./reconx.sh -d target.com --hunt xss

# 🔬 Behavioral intelligence only
./reconx.sh -d target.com -m behavioral

# 🧠 EBRE reasoning only
./reconx.sh -d target.com -m reasoning

# 🔥 Aggressive mode with parallel pipeline
./reconx.sh -d target.com --mode aggressive --parallel

# 💀 Nuclear mode (max speed, own infrastructure)
./reconx.sh -d target.com --mode nuclear --parallel

# 📋 Multiple targets
./reconx.sh -l domains.txt --autopilot

# ▶️ Resume interrupted scan
./reconx.sh -d target.com --resume

# 📊 List all modules
./reconx.sh --list-modules

# ✅ Check dependencies
./reconx.sh --check
```

### Performance Modes

| Mode | Threads | Rate | Use Case |
|:----:|:-------:|:----:|----------|
| `safe` | 10 | 50 | Stealthy, rate-limited targets |
| `balanced` | 50 | 150 | Default — good for most targets |
| `aggressive` | 100 | 300 | Bug bounty programs |
| `ultra` | 200 | 500 | Large scope, fast infrastructure |
| `nuclear` | 500 | 1000 | Maximum speed, own infrastructure |

---

## 📁 Project Structure

```
reconx/
├── reconx.sh                           # Main CLI entry point
│
├── core/                               # Framework core
│   ├── module_runner.sh                # Pipeline orchestrator
│   ├── async_runner.sh                 # Parallel execution engine
│   ├── telegram.sh                     # 17 Telegram alert functions
│   ├── strategic_agent.py              # Autonomous strategic agent
│   ├── plugin_loader.py               # Plugin system
│   └── ...                            # Config, logging, state, dedup
│
├── modules/
│   ├── subdomains/                     # 10+ passive + active sources
│   ├── live/                           # httpx full probing
│   ├── urls/                           # 5 crawlers + SimHash dedup
│   ├── js/                             # Deep JS intelligence
│   ├── content/                        # Fuzzing + 403 bypass
│   ├── api/                            # GraphQL + Swagger + REST
│   ├── ports/                          # naabu + nmap
│   ├── nuclei/                         # Template scanning
│   ├── takeover/                       # Subdomain takeover
│   ├── cors/                           # CORS misconfiguration
│   ├── wordpress/                      # WP scanning
│   │
│   ├── intelligence/                   # 23 intelligence modules
│   │   ├── observed_signals.py         # Parallel HTTP evidence collection
│   │   ├── reasoning_engine.py         # Multi-source correlation
│   │   ├── attack_paths.py             # Evidence-backed attack chains
│   │   ├── strategy_engine.py          # Hunter strategy generation
│   │   ├── target_dna.py              # Technology fingerprinting
│   │   ├── ai_prioritizer.py          # AI risk scoring
│   │   ├── js_deep_analysis.py        # JS secrets + sinks
│   │   └── ...                        # 16 more intelligence modules
│   │
│   ├── behavioral/                     # 9 behavioral modules ✨ NEW
│   │   ├── auth_behavior.py           # Auth-state differential analysis
│   │   ├── object_relationships.py    # Object mapping + IDOR detection
│   │   ├── workflow_transitions.py    # State machine + bypass detection
│   │   ├── dom_observer.py            # DOM sinks + SPA routes
│   │   ├── session_intelligence.py    # Cookie/CORS/session analysis
│   │   ├── api_behavior.py            # CRUD patterns + auth reqs
│   │   ├── state_diff_engine.py       # Response differential analysis
│   │   ├── target_understanding.py    # Unified brain + hunter guidance
│   │   └── target_behavior_graph.py   # Cytoscape.js visualization
│   │
│   ├── exploit/                        # XSS, SQLi, payload fuzzing
│   ├── validation/                     # Browser + PoC validation
│   └── reporting/                      # Dashboard + summary + reports
│
├── configs/                            # YAML configuration
├── wordlists/                          # 68 classified wordlists
└── templates/                          # Custom nuclei templates
```

---

## 📊 Output Structure

```
output/<target>/
├── subs/                    # Subdomains
├── live/                    # Live hosts
├── urls/                    # All URLs
├── js/                      # JS analysis
├── intelligence/            # AI intelligence
├── observed_signals/        # HTTP evidence
├── reasoning/               # Reasoned findings
├── attack_paths/            # Justified attack chains
├── auth_intelligence/       # Auth behavior findings
├── object_relationships/    # Object maps
├── workflow_transitions/    # State machines
├── dom_intelligence/        # DOM sinks + routes
├── behavioral/              # Session + API + state diffs
├── target_understanding/    # Unified understanding
├── live_guidance/           # Hunter guidance markdown
├── hunter_strategy/         # Strategy playbooks
├── target_dna/             # Technology fingerprint
└── reports/
    ├── dashboard.html       # Interactive Chart.js dashboard
    └── behavior_graph.html  # Cytoscape.js behavior visualization
```

---

## 🧠 Evidence vs Hallucination

ReconX Ultra X enforces a strict **anti-hallucination policy**:

| Principle | Implementation |
|-----------|---------------|
| **Minimum Evidence** | Attack paths require ≥2 observed signals |
| **Observed vs Predicted** | Every finding separates OBSERVED evidence from PREDICTED impact |
| **Confidence Scoring** | Weighted scores with per-source breakdown |
| **Reasoning Trace** | Full explainability: why each finding exists |
| **Behavioral Correlation** | Multiple engines cross-validate findings |

---

## 📡 Real-Time Telegram Alerts

17 alert functions delivering live intelligence:

```
🔐 AUTH BEHAVIORAL DIFFERENTIAL
🎯 Target: app.example.com
🔓 Finding: Admin panel accessible without auth
⚠ Risk: CRITICAL
📊 Confidence: 85%

🔗 OBJECT EXPOSURE DETECTED
🎯 Target: api.example.com
📦 Object: invoice
📊 Total: 12 | Exposed: 8
⚠ Risk: IDOR / Broken Access Control

🎯 HUNTER GUIDANCE
💡 Insight: JWT stored in localStorage
🔴 Priority: CRITICAL
🎯 Action: Find XSS → steal JWT → impersonate admin
```

---

## 🔧 Required Tools

### Go Tools (21)
subfinder, dnsx, httpx, nuclei, katana, naabu, gau, waybackurls, ffuf, hakrawler, alterx, subzy, gf, qsreplace, unfurl, anew, assetfinder, uncover, chaos, notify, interactsh-client

### Python Tools (7)
arjun, uro, trufflehog, xnLinkFinder, dirsearch, Corsy, CORScanner

### System Tools
curl, wget, jq, python3, go, git, nmap, dig, whois, openssl, chromium

---

## 🔄 Full Pipeline Flow

```
                    ┌─────────────┐
                    │  SUBDOMAINS  │
                    │  10+ sources │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  LIVE HOSTS  │
                    │  httpx probe │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──┐   ┌────▼────┐  ┌───▼────┐
       │  URLs   │   │  JS     │  │  APIs  │
       │ 5 tools │   │ secrets │  │ GQL+SW │
       └────┬────┘   └────┬────┘  └───┬────┘
            │              │           │
            └──────────────┼───────────┘
                           │
                ┌──────────▼──────────┐
                │   INTELLIGENCE      │
                │ DNA + AI + Surface  │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │   EBRE REASONING    │
                │ Signals → Evidence  │
                │ → Reasoning → Paths │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │  BEHAVIORAL INTEL   │ ✨
                │ Auth + Objects +    │
                │ Workflows + DOM +   │
                │ Sessions + APIs     │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │   EXPLOIT + CHAIN   │
                │ XSS/SQLi/SSRF/LFI  │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │  📊 REPORTS + VIZ   │
                │ Dashboard + Graph   │
                │ + Hunter Guidance   │
                └─────────────────────┘
```

---

## 📜 License

MIT License — For authorized security testing only.

---

## ⚠️ Legal Disclaimer

This tool is designed for **authorized security testing and bug bounty hunting only**. Always obtain proper written authorization before scanning any target. Unauthorized access to computer systems is illegal. The developers assume no liability for misuse.

---

<p align="center">
  <br>
  <b>Built for hunters, by hunters ⚡</b><br>
  <i>ReconX Ultra X — Understand targets. Reason about attacks. Hunt with evidence.</i><br>
  <br>
  <img src="https://img.shields.io/badge/Made_with-❤️-ef4444?style=flat-square&labelColor=0a0a0f" alt="Made with love">
  <img src="https://img.shields.io/badge/For-Offensive_Security-7c5bf5?style=flat-square&labelColor=0a0a0f" alt="For offensive security">
</p>
