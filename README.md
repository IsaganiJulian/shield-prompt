# ShieldPrompt - Multi-Tiered Prompt Injection Detection System

A dynamic, production-grade security system for detecting and auto-remediating prompt injection threats in real-time.

## Architecture Overview

```
User Input / Web Payloads
         ↓
    SHIELD.PY (Multi-Tiered Detection)
    ├─ Tier 1: Lexical Analysis (Pattern Matching)
    ├─ Tier 2: Semantic Analysis (LLM Context)
    └─ Tier 3: Behavioral Analysis (Model Anomalies)
         ↓
    [Malicious Detected?]
         ├─ YES → SUPERVISOR.PY (Auto-Remediation)
         │         ├─ Attempt Remediation
         │         ├─ Resolve / Escalate
         │         └─ Log to Human-in-Loop
         │
         └─ NO → Downstream Consumer Agent

```

## Tech Stack

- **Python 3.12+** - Core runtime
- **Streamlit** - Real-time web UI
- **LangChain** - Agent orchestration
- **Claude (Anthropic)** - Semantic analysis & reasoning
- **Bright Data APIs** - Live threat intelligence scraping
- **Pydantic** - Data validation
- **Pytest** - Testing framework

## Features

✅ **Multi-Tier Detection**
- Tier 1: Regex/lexical pattern matching
- Tier 2: LLM-based semantic understanding
- Tier 3: Behavioral anomaly detection

✅ **Auto-Remediation**
- Instruction sanitization
- Semantic rewriting
- Context isolation
- Human escalation for critical threats

✅ **Live Threat Intelligence**
- CVE/NVD feed integration
- GitHub exploit repository scraping
- Security research publication tracking
- Pattern auto-update every hour

✅ **Evaluation Suite**
- TPR, FPR, precision, recall metrics
- Detection latency benchmarking
- Remediation success tracking

## Quick Start

### 1. Clone & Setup

```bash
git clone <repo>
cd ShieldPrompt
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your API keys:
# - ANTHROPIC_API_KEY
# - BRIGHT_DATA_API_KEY
```

### 3. Run UI

```bash
streamlit run app.py
```

Access at: `http://localhost:8501`

### 4. Run Tests

```bash
pytest tests/ -v
```

## Project Structure

```
ShieldPrompt/
├── core/
│   ├── __init__.py
│   ├── shield.py            # Multi-tiered detection engine
│   ├── supervisor.py        # Auto-remediation agent
│   └── threat_intel.py      # Live threat intelligence
├── tests/
│   ├── __init__.py
│   └── evaluate.py          # Evaluation suite
├── logs/                    # Escalation & incident logs
├── data/
│   ├── threats/             # Threat patterns
│   └── remediation_history/ # Remediation audit trail
├── app.py                   # Streamlit UI entry point
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## API Reference

### ShieldDetector

```python
from core.shield import ShieldDetector

detector = ShieldDetector(config={"detection_threshold": 0.85})
result = detector.detect("User input to analyze")
print(result.threat_level, result.confidence)
```

### SupervisorAgent

```python
from core.supervisor import SupervisorAgent

supervisor = SupervisorAgent(config={"auto_remediation_enabled": True})
remediation = supervisor.remediate(threat_input, threat_analysis)
```

### ThreatIntelligence

```python
from core.threat_intel import ThreatIntelligence

threat_intel = ThreatIntelligence()
patterns = threat_intel.fetch_latest_threats()
threat_intel.update_patterns()
```

## Configuration

All settings in `.env`:

```env
ANTHROPIC_API_KEY=sk-...
BRIGHT_DATA_API_KEY=...
DETECTION_THRESHOLD=0.85
AUTO_REMEDIATION_ENABLED=true
ESCALATION_THRESHOLD=0.95
LOG_LEVEL=INFO
```

## Logs & Escalation

- **Detection logs**: `logs/shield_*.log`
- **Escalations**: `logs/escalations_*.log`
- **Remediation history**: `data/remediation_history/`

## Evaluation Metrics

Run full evaluation:

```python
python -m tests.evaluate
```

Generates:
- **TPR/FPR curves**
- **Confusion matrix**
- **Detection latency (p50, p95, p99)**
- **Remediation success rate**
- **Tier effectiveness breakdown**

## Contributing

1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes
3. Run tests: `pytest tests/ -v`
4. Submit PR

## License

Proprietary - All rights reserved

## Support

For issues or questions, contact: [support@shieldprompt.io](mailto:support@shieldprompt.io)

---

**Built with 🛡️ Security First**
