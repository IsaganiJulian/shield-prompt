# ShieldPrompt: Dynamic Prompt Injection Defense System

## System Architecture

ShieldPrompt is built as a three-phase security pipeline followed by multi-tiered threat detection:

```
Raw Input → Phase 1: Normalize → Phase 2: Parse → Phase 3: Route → Verdict
            (Denormalize)        (Extract Fields)  (Orchestrate)
                                                         ↓
                                                    Detection Tiers:
                                                    • Tier 1: Lexical
                                                    • Tier 2: Semantic
                                                    • Tier 3: Behavioral
```

### Phase 1: Input Normalization Pipeline
**File**: `src/core/preprocessor.py`

Anti-semantic-drift layer that reverses evasion techniques:
- Decodes layered encodings (Base64, hex, URL, nested combinations)
- Normalizes Unicode homoglyphs to canonical form
- Collapses whitespace obfuscation
- Extracts code blocks for separate analysis
- Deterministic, reproducible, auditable preprocessing

**Key Features**:
- Max recursion depth: 3 layers (prevents DoS)
- Timeout: 100ms per input
- Returns normalized text + transformation metadata

### Phase 2: Payload Parser
**File**: `src/core/payload_parser.py`

Structural decomposition and field classification:
- Extracts string values from nested JSON/MCP/API structures
- Classifies each field: STRUCTURAL (metadata) or SCANNABLE (user text)
- Returns JSON paths for precise threat attribution (e.g., `$.messages[0].content`)
- Enables efficient dual-path processing in Phase 3

### Phase 3: Dual-Gate Router
**File**: `src/core/router.py`

Central orchestration layer coordinating phases 1-2 with multi-tier detection:
- **FAST PATH**: Structural metadata bypasses detection (no latency)
- **COMPREHENSIVE PATH**: Scannable fields through full Tier 1-3 analysis
- Orchestrates: normalize → parse → detect → remediate → decide
- Decision verdicts: ALLOW, BLOCK, QUARANTINE, ESCALATE, REMEDIATE
- Complete audit trails with JSON path attribution

### Multi-Tiered Detection System
**File**: `src/core/shield.py`

Three-tier threat detection engine (used within Phase 3):
- **Tier 1 (Lexical)**: Fast regex-based pattern matching (~5-10ms)
- **Tier 2 (Semantic)**: LLM-based contextual analysis (~100-200ms) [Placeholder]
- **Tier 3 (Behavioral)**: Output anomaly detection [Placeholder]

**Threat Levels**: CLEAN, LOW, MEDIUM, HIGH, CRITICAL
**Confidence**: 0.0-1.0 scoring with short-circuit optimization

## Directory Structure

```
shieldprompt/
├── README.md                    # Main entry point
├── requirements.txt
├── .env.example
├── claude.md                    # Project instructions
│
├── docs/
│   ├── OVERVIEW.md             # This file
│   ├── GETTING_STARTED.md
│   └── phases/
│       ├── PHASE_1_NORMALIZATION.md
│       ├── PHASE_2_PARSING.md
│       └── PHASE_3_ROUTING.md
│
├── src/
│   ├── core/                    # Detection pipeline
│   │   ├── shield.py           # Phase 1: Tier 1-3 detection
│   │   ├── payload_parser.py   # Phase 2: Field extraction
│   │   ├── router.py           # Phase 3: Orchestration
│   │   ├── supervisor.py       # Auto-remediation agent
│   │   └── threat_intel.py     # Threat intelligence management
│   │
│   ├── utils/
│   │   └── preprocessor.py     # Input normalization
│   │
│   └── app.py                   # Streamlit dashboard [Phase 4]
│
├── tests/
│   ├── test_shield.py
│   ├── test_payload_parser.py
│   ├── test_router.py
│   ├── test_preprocessor.py
│   ├── evaluate.py             # Benchmark suite
│   └── eval_dataset.json
│
└── data/
    └── threat_intel/           # Cached threat patterns
```

## Quick Start

```python
from src.core.router import DualGateRouter

# Initialize router (coordinates all phases)
router = DualGateRouter()

# Route a payload through the full pipeline
payload = {"content": "What is AI?"}
result = router.route(payload)

# Check verdict
if result.decision == RoutingDecision.ALLOW:
    process_safely()
elif result.decision == RoutingDecision.BLOCK:
    reject_request()

# Access threat details
for threat in result.critical_threats:
    print(f"Location: {threat.parsed_field.json_path}")
    print(f"Confidence: {threat.detection_result.confidence:.2f}")
```

## Test Coverage

- **Phase 1**: ShieldDetector tier logic, pattern matching
- **Phase 2**: PayloadParser field classification, JSON paths
- **Phase 3**: DualGateRouter dual-path, decision synthesis, MCP handling
- **Utilities**: Input preprocessing, encoding detection
- **Total**: 100+ test cases, all passing

Run: `pytest tests/ -v`

## Performance Profile

| Scenario | Latency | Throughput |
|----------|---------|-----------|
| Structural only | ~1-2ms | 500+/sec |
| Mixed payload | <100ms typical | 10-100/sec |
| Pure scannable | 10-500ms+ | 2-100/sec |

Structural fields skip expensive detection via Phase 3's dual-path strategy.

## Integration

**Upstream** (data sources):
- Web API payloads
- MCP/JSON-RPC envelopes
- User chat queries
- Agent responses

**Downstream** (decision handlers):
- Safe processing pipeline
- Human escalation queue
- Audit logging
- Threat dashboard
- Auto-remediation

## Configuration

See individual phase documentation:
- Phase 1: `docs/phases/PHASE_1_DETECTION.md`
- Phase 2: `docs/phases/PHASE_2_PARSING.md`
- Phase 3: `docs/phases/PHASE_3_ROUTING.md`

## Next Steps

- **Phase 4**: Streamlit dashboard for real-time monitoring
- **Phase 5**: Webhook integration for external SIEM systems
- **Phase 6**: Adaptive thresholds via threat intelligence
