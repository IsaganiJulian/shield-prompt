# System Context: ShieldPrompt (Prompt Injection Detection System)

You are an expert DevSecOps and AI Safety Engineering Assistant. Your objective is to help build **ShieldPrompt**, a dynamic, inline firewall designed to protect enterprise AI agents from direct and indirect prompt injections.

---

## 🎯 Project Core Objectives
1. **Dynamic Threat Intel:** Continuously update local vector/keyword signatures using real-time security data scraped via **Bright Data APIs**.
2. **Inline Interception:** Inspect both user queries and incoming raw scraped data *before* the main agent processes them.
3. **Automated Supervision:** Use an autonomous Security Supervisor Agent to safely auto-remediate minor injection overrides, minimizing human-in-the-loop alert fatigue.

---

## 🛠️ Technical Constraints & Stack
- **Language:** Python 3.12+ (**STRICTLY FORBIDDEN:** R, NodeJS, Power BI)
- **Frameworks:** LangChain (Agent Orchestration), Streamlit (Frontend Dashboard)
- **Integrations:** Bright Data SERP/Web Scraper API (Threat intelligence data sourcing)
- **Architecture Style:** Decoupled, modular, microservice-inspired. No monolithic scripts.

---

## 📂 Codebase Directory Layout
Always respect and maintain this structure when creating or modifying files:

```text
Shield-Prompt/
│
├── CLAUDE.md                 # This system memory context file
├── README.md                 # Project overview
├── requirements.txt          # Python package manifest
├── .env.example              # Credentials template (Bright Data, OpenAI, Anthropic)
│
├── src/                      # All application source code
│   ├── __init__.py
│   ├── core/                 # Backend Security Engines
│   │   ├── __init__.py
│   │   ├── shield.py         # Tiered detection (Tier 1 Lexical → Tier 2 Semantic → Tier 3 Behavioral)
│   │   ├── supervisor.py     # Autonomous Remediation Agent (3-strategy cascading)
│   │   ├── router.py         # DualGateRouter — structural fast-path + comprehensive scan
│   │   ├── preprocessor.py   # InputNormalizer — Base64/Unicode/encoding anti-evasion (Phase 1)
│   │   ├── payload_parser.py # PayloadParser — recursive JSON/MCP field extraction (Phase 2)
│   │   ├── threat_intel.py   # ThreatIntelligence — Bright Data scraper interface
│   │   ├── vector_store.py   # FAISSVectorStore — embedding-based pattern retrieval
│   │   ├── llm_evaluator.py  # LLMEvaluator — LangChain/Anthropic Tier 2 re-scoring
│   │   ├── pattern_ingester.py # Ingests scraped threat patterns into the vector store
│   │   └── bright_data_client.py # Bright Data API client wrapper
│   │
│   └── dashboard/            # Streamlit Frontend
│       ├── __init__.py
│       ├── app.py            # Main Streamlit app (Playground / Detection / Evaluation / Threat Intel)
│       ├── playground.py     # Live Ingress Playground + Output Scanner panel
│       ├── components.py     # Shared UI components (header, metrics row, CSS)
│       ├── forensics.py      # Forensic audit trail and session log explorer
│       ├── mock_data.py      # Sample payloads and mock metrics generator
│       └── threat_intelligence.py # Threat Intel dashboard page
│
├── tests/                    # Security Evaluation Hub
│   ├── __init__.py
│   ├── eval_dataset.json     # 35-case labeled dataset (malicious + benign)
│   ├── evaluate.py           # EvaluationSuite — KPI runner (TPR/FPR/F1/latency)
│   ├── test_e2e_pipeline.py  # End-to-end integration tests (5 scenarios, offline)
│   ├── test_router.py        # DualGateRouter unit tests
│   ├── test_supervisor.py    # SupervisorAgent unit tests
│   ├── test_tier2_integration.py  # Tier 2 semantic analysis tests
│   ├── test_tier3_behavioral.py   # Tier 3 behavioral + analyze_output() tests
│   ├── test_payload_parser.py
│   ├── test_preprocessor.py
│   ├── test_vector_store.py
│   ├── test_threat_intel.py
│   ├── test_pattern_ingester.py
│   └── test_bright_data_client.py
│
├── docs/                     # Phase specifications and architecture notes
│   └── phases/               # Per-phase design documents (PHASE_1 … PHASE_9)
│
└── data/                     # Runtime data (vector index, scraped patterns, logs)