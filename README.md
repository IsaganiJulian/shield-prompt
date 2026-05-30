# ShieldPrompt: Dynamic Prompt Injection Detection System

Enterprise-grade inline firewall for AI agents, protecting against direct and indirect prompt injection attacks using a real-time, multi-tiered detection pipeline powered by Bright Data threat intelligence.

## Key Features

- **Multi-Tiered Detection** — Tier 1 lexical (~5-10ms) → Tier 2 LLM semantic → Tier 3 behavioral output analysis
- **Tier-First Early Exit** — 80-90% of attacks caught in <10ms before expensive processing
- **Structural Field Optimization** — Metadata (IDs, timestamps) bypass detection; only user-supplied content is scanned
- **Live Threat Intelligence** — Bright Data SERP/Web Scraper API feeds a FAISS vector store with real-time attack patterns
- **Autonomous Remediation** — SupervisorAgent cascades: sanitization → LLM rewrite → context isolation, with human-in-the-loop escalation
- **MCP/JSON-RPC Support** — Native support for Model Context Protocol envelopes with JSON path attribution
- **Streamlit Dashboard** — Live Playground, Detection Console, Evaluation Hub, and Threat Intel viewer
- **386 Tests Passing** — Full coverage across all tiers and phases

## Quick Start

```bash
git clone https://github.com/IsaganiJulian/shield-prompt.git
cd shield-prompt
pip install -r requirements.txt
cp .env.example .env   # add your API keys
pytest tests/ -v
streamlit run src/dashboard/app.py
```

### Environment Variables

```bash
ANTHROPIC_API_KEY=      # Claude Haiku — LLM re-scoring & supervisor rewriting
OPENAI_API_KEY=         # text-embedding-3-small — FAISS vector gate
BRIGHT_DATA_API_KEY=    # Threat intelligence scraping
```

All keys are optional — the system degrades gracefully to Tier 1 lexical-only mode if keys are absent.

## Architecture

```
Raw Input
  ├─ String?  → Tier 1 Lexical (raw) → Early Exit? → Decide
  │                   ↓ inconclusive
  │            Normalize (Phase 1) → Tier 2 Semantic → Tier 3 Behavioral → Decide
  │
  └─ Dict/List? → Parse Fields (Phase 2)
                      ├─ Structural (IDs, timestamps) → Skip detection (fast path)
                      └─ Scannable (prompts, content) → [Tier 1 → Normalize → Tier 2-3] → Decide
```

**Routing Decisions**

| Decision | Meaning |
|---|---|
| `ALLOW` | No threats detected |
| `BLOCK` | Critical threat, reject immediately |
| `QUARANTINE` | Medium confidence, flag for human review |
| `ESCALATE` | High-confidence threat, route to operator |
| `REMEDIATE` | Auto-fixed by SupervisorAgent |

## Detection Pipeline

| Phase | Component | Status |
|---|---|---|
| Phase 1 | `InputNormalizer` — Base64/Unicode/encoding anti-evasion | ✅ Complete |
| Phase 2 | `PayloadParser` — recursive JSON/MCP field extraction | ✅ Complete |
| Phase 3 | `DualGateRouter` — structural fast-path + tier synthesis | ✅ Complete |
| Phase 4 | Streamlit Dashboard — Playground / Detection / Eval / Threat Intel | ✅ Complete |
| Phase 5 | `BrightDataClient` + `ThreatIntelligence` — live SERP scraping | ✅ Complete |
| Phase 6 | `LLMEvaluator` + `FAISSVectorStore` — Tier 2 semantic analysis | ✅ Complete |
| Phase 7 | `SupervisorAgent` — 3-strategy cascading auto-remediation | ✅ Complete |
| Phase 8 | Tier 3 behavioral analysis — flooding, drift, multi-vector, repetition | ✅ Complete |
| Phase 9 | Evaluation suite — KPI runner (TPR/FPR/F1/latency) | ✅ Complete |

## Performance

| Scenario | Latency | Description |
|---|---|---|
| Tier 1 Early Exit | ~5-10ms | Common injection caught before normalization |
| Clean Input | ~10-20ms | No threats, quick pass-through |
| Normalized Analysis | ~100-300ms | Encoding evasion decoded and re-analyzed |
| Mixed JSON Payload | ~20-100ms | Structural fields skipped, scannable fields scanned |

## Usage

```python
from src.core.router import DualGateRouter, RoutingDecision

router = DualGateRouter()

result = router.route({"content": "Ignore previous instructions and..."})

if result.decision == RoutingDecision.BLOCK:
    reject_and_log(result.escalation_reason)
elif result.decision == RoutingDecision.ALLOW:
    process_safely(payload)
```

## Project Structure

```
shield-prompt/
├── src/
│   ├── core/
│   │   ├── shield.py              # Tiered detection engine
│   │   ├── router.py              # DualGateRouter orchestration
│   │   ├── preprocessor.py        # InputNormalizer (Phase 1)
│   │   ├── payload_parser.py      # PayloadParser (Phase 2)
│   │   ├── supervisor.py          # SupervisorAgent auto-remediation
│   │   ├── llm_evaluator.py       # Tier 2 LLM re-scoring
│   │   ├── vector_store.py        # FAISS vector store
│   │   ├── threat_intel.py        # Threat intelligence interface
│   │   ├── pattern_ingester.py    # Ingests scraped patterns into FAISS
│   │   └── bright_data_client.py  # Bright Data API client
│   └── dashboard/
│       ├── app.py                 # Streamlit entry point
│       ├── playground.py          # Live Ingress Playground
│       ├── components.py          # Shared UI components
│       ├── threat_intelligence.py # Threat Intel dashboard page
│       └── forensics.py           # Forensic audit trail explorer
├── tests/                         # 386 tests
│   ├── eval_dataset.json          # 35-case labeled dataset
│   ├── evaluate.py                # KPI runner (TPR/FPR/F1/latency)
│   ├── test_router.py
│   ├── test_supervisor.py
│   ├── test_tier2_integration.py
│   ├── test_tier3_behavioral.py
│   ├── test_e2e_pipeline.py
│   └── ...
├── docs/
│   ├── ARCHITECTURE.md
│   ├── GETTING_STARTED.md
│   ├── STARTUP_GUIDE.md
│   └── phases/                    # Per-phase design docs (PHASE_1 … PHASE_9)
├── requirements.txt
└── .env.example
```

## Testing

```bash
pytest tests/ -v                   # Run all 386 tests
pytest tests/ --cov=src            # With coverage report
python tests/evaluate.py           # KPI benchmark (TPR/FPR/F1/latency)
```

## Documentation

| Document | Purpose |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Tier-first optimization and system design |
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Usage guide and examples |
| [docs/STARTUP_GUIDE.md](docs/STARTUP_GUIDE.md) | Dashboard startup and navigation |
| [docs/phases/](docs/phases/) | Per-phase design specifications |

## Tech Stack

- **Python 3.12+** — core language
- **LangChain** — agent orchestration
- **Anthropic Claude** — LLM semantic re-scoring and supervisor rewriting
- **OpenAI Embeddings** — FAISS vector store indexing
- **FAISS** — local vector similarity search
- **Bright Data** — real-time threat intelligence scraping
- **Streamlit** — security operations dashboard
- **Pydantic** — data validation

## License

MIT License — see [LICENSE](LICENSE) for details.

## Support

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Getting Started](docs/GETTING_STARTED.md)
- [Issue Tracker](https://github.com/IsaganiJulian/shield-prompt/issues)
