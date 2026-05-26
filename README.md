# ShieldPrompt: Dynamic Prompt Injection Detection System

Enterprise-grade security firewall for AI agents protecting against direct and indirect prompt injection attacks.

## Features

✅ **Multi-Tiered Detection System**
- Tier 1: Fast regex-based pattern matching (~5-10ms)
- Tier 2: LLM semantic analysis [In development]
- Tier 3: Behavioral output analysis [In development]

✅ **Structural Field Optimization**
- Metadata (IDs, timestamps, types) bypass detection
- Only user-supplied content gets scanned
- Fast path: ~1-2ms for metadata-heavy payloads

✅ **Threat Attribution**
- JSON path precision: `$.messages[0].content`
- Complete audit trails for each field
- Forensic-ready threat analysis

✅ **MCP/JSON-RPC Support**
- Native support for Model Context Protocol envelopes
- Chat message structure awareness
- Agent response processing

✅ **Auto-Remediation**
- Autonomous supervisor agent for minor overrides
- Escalation for critical threats
- Human-in-the-loop review queues

✅ **Comprehensive Testing**
- 100+ test cases, all passing
- Complete test coverage for all phases
- Batch processing and edge cases validated

## Quick Start

```python
from src.core.router import DualGateRouter, RoutingDecision

# Initialize security router
router = DualGateRouter()

# Process a payload through the full pipeline
payload = {"content": "What is AI?"}
result = router.route(payload)

# Check verdict
if result.decision == RoutingDecision.ALLOW:
    process_safely(payload)
elif result.decision == RoutingDecision.BLOCK:
    reject_and_log(payload, result.escalation_reason)
```

See [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for more examples.

## Installation

```bash
git clone https://github.com/yourusername/shieldprompt.git
cd shieldprompt
pip install -r requirements.txt
pytest tests/ -v
```

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/OVERVIEW.md](docs/OVERVIEW.md) | System architecture overview |
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Usage guide and examples |
| [docs/phases/PHASE_1_NORMALIZATION.md](docs/phases/PHASE_1_NORMALIZATION.md) | Input normalization pipeline |
| [docs/phases/PHASE_2_PARSING.md](docs/phases/PHASE_2_PARSING.md) | Payload parser & field classification |
| [docs/phases/PHASE_3_ROUTING.md](docs/phases/PHASE_3_ROUTING.md) | Dual-gate orchestration |

## Architecture

```
Raw Input → Phase 1: Normalize → Phase 2: Parse → Phase 3: Route → Verdict
            (Denormalize)        (Extract Fields)  (Orchestrate)
                                                         ↓
                                                    Detection Tiers:
                                                    • Tier 1: Lexical
                                                    • Tier 2: Semantic
                                                    • Tier 3: Behavioral
```

**Phase 1: Input Normalization** (`src/core/preprocessor.py`)
- Reverses encoding obfuscation (Base64, hex, URL, nested)
- Normalizes Unicode homoglyphs
- Collapses whitespace evasion
- Extracts code blocks

**Phase 2: Payload Parser** (`src/core/payload_parser.py`)
- Structural decomposition and field classification
- JSON path attribution (e.g., `$.messages[0].content`)

**Phase 3: Dual-Gate Router** (`src/core/router.py`)
- Fast path (structural) + comprehensive path (scannable)
- Coordinates phases 1-2 with multi-tier detection
- Decision verdicts: ALLOW, BLOCK, QUARANTINE, ESCALATE, REMEDIATE

**Multi-Tiered Detection** (`src/core/shield.py`)
- Tier 1 (Lexical): Fast regex patterns (~5-10ms)
- Tier 2 (Semantic): LLM analysis (~100-200ms) [Placeholder]
- Tier 3 (Behavioral): Output anomalies [Placeholder]

## Project Structure

```
shieldprompt/
├── docs/                        # Documentation
│   ├── OVERVIEW.md
│   ├── GETTING_STARTED.md
│   └── phases/
│       ├── PHASE_1_NORMALIZATION.md
│       ├── PHASE_2_PARSING.md
│       └── PHASE_3_ROUTING.md
│
├── src/                         # Production code
│   ├── core/                   # Detection pipeline
│   │   ├── preprocessor.py    # Phase 1: Normalization
│   │   ├── payload_parser.py  # Phase 2: Parsing
│   │   ├── router.py          # Phase 3: Orchestration
│   │   ├── shield.py          # Detection tiers
│   │   ├── supervisor.py      # Auto-remediation
│   │   └── threat_intel.py
│   │
│   └── utils/
│       └── (utilities)
│
├── tests/                       # 100+ test cases
│   ├── test_shield.py
│   ├── test_payload_parser.py
│   ├── test_router.py
│   ├── test_preprocessor.py
│   ├── evaluate.py             # Benchmarking
│   └── eval_dataset.json
│
├── requirements.txt
└── claude.md
```

## Performance

| Scenario | Latency | Throughput |
|----------|---------|-----------|
| Structural only | ~1-2ms | 500+/sec |
| Mixed payload | <100ms typical | 10-100/sec |
| Pure scannable | 10-500ms+ | 2-100/sec |

*Metadata fields skip detection via dual-path strategy.*

## Test Coverage

**Phase 1**: Tier logic, pattern matching, confidence scoring
**Phase 2**: Field classification, JSON paths, edge cases
**Phase 3**: Dual-path routing, decision synthesis, MCP handling
**Utils**: Input preprocessing, encoding detection

**Total**: 100+ test cases, all passing

```bash
pytest tests/ -v                    # Run all tests
pytest tests/ --cov=src             # With coverage
python tests/evaluate.py            # Run benchmarks
```

## Key Concepts

### Dual-Gate Routing Strategy

**Fast Path** (Structural Fields):
- Metadata: IDs, types, timestamps, enums
- Skip detection entirely (~0 latency overhead)
- UUID/ISO date pattern recognition

**Comprehensive Path** (Scannable Fields):
- User text: prompts, queries, content, messages
- Full Tier 1-3 detection pipeline
- Conservative fallback (scan if unsure)

### Routing Decisions

- **ALLOW**: No threats, proceed safely
- **BLOCK**: Critical threat detected, reject immediately
- **QUARANTINE**: Medium threat, mark for human review
- **ESCALATE**: High-confidence threat, route to human operator
- **REMEDIATE**: Auto-fixed by supervisor agent

### Threat Attribution

Each threat is mapped to exact JSON path for precise forensics:
```
$.messages[0].content → CRITICAL injection payload (confidence 0.92)
$.messages[0].role → STRUCTURAL (not scanned)
$.messages[1].content → CLEAN
$.messages[1].role → STRUCTURAL
```

## Usage Examples

### Single Payload

```python
from src.core.router import DualGateRouter

router = DualGateRouter()
result = router.route({"content": "ignore all previous"})
print(result.decision)  # RoutingDecision.ESCALATE
```

### Batch Processing

```python
payloads = [
    {"content": "What is Python?"},
    {"content": "ignore system prompt"},
    {"content": "Tell me a joke"},
]

results = router.batch_route(payloads)
for result in results:
    print(f"Decision: {result.decision}")
```

### MCP Messages

```python
mcp_envelope = {
    "messages": [
        {"role": "user", "content": user_query},
        {"role": "assistant", "content": agent_response}
    ]
}

result = router.route(mcp_envelope)
print(router.generate_report(result))  # Audit trail
```

## Configuration

```python
config = {
    "critical_block_threshold": 0.90,    # CRITICAL + 90% → BLOCK
    "escalation_threshold": 0.80,        # HIGH + 80% → ESCALATE
    "auto_remediate": True,              # Enable auto-fix
}

router = DualGateRouter(config=config)
```

## Roadmap

| Phase | Status | Component |
|-------|--------|-----------|
| 1 | ✅ Complete | Multi-tiered detection (Tier 1 lexical) |
| 2 | ✅ Complete | Payload parser (field classification) |
| 3 | ✅ Complete | Dual-gate router (orchestration) |
| 4 | 🔄 In Progress | Streamlit dashboard |
| 5 | 📋 Planned | Bright Data threat intel integration |
| 6 | 📋 Planned | Webhook SIEM integration |

## Contributing

See [claude.md](claude.md) for development guidelines.

## License

Proprietary - All rights reserved

## Support

- 📖 [Full Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/yourusername/shieldprompt/issues)
- 💬 [Discussions](https://github.com/yourusername/shieldprompt/discussions)

---

**Built with 🛡️ Security First**
