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
shieldprompt-hackathon/
│
├── .env.example              # Credentials template (Bright Data, OpenAI)
├── .gitignore                # Target folder exclusions
├── requirements.txt          # Python package manifest
├── claude.md                 # This system memory context file
│
├── core/                     # Backend Security Engines
│   ├── __init__.py
│   ├── shield.py             # Tiered Inspections (Regex -> Vector -> LLM Eval)
│   ├── supervisor.py         # Autonomous Remediation Agent
│   └── threat_intel.py       # Bright Data Interface Script
│
├── tests/                    # Security Evaluation Hub
│   ├── __init__.py
│   ├── eval_dataset.json     # Matrix of attacks and safe queries
│   └── evaluate.py           # Programmatic KPI runner script
│
└── app.py                    # Streamlit Dashboard (Side-by-side Exploit UI)