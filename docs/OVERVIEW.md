# ShieldPrompt: Dynamic Prompt Injection Defense System

## System Architecture

ShieldPrompt uses a **Tier-First with Early-Exit** pipeline optimized for both speed and robustness:

```
Raw Input
  ├─ String? → Tier 1 (Raw) → Early Exit? → Decide
  │                 ↓
  │              Inconclusive?
  │                 ↓
  │         Normalize → Tier 2-3 → Decide
  │
  └─ Dict/List? → Parse Fields → Structural/Scannable
                      ├─ Structural → Skip detection
                      └─ Scannable → [Tier 1 → Normalize → Tier 2-3] → Decide
```

**Key Insight**: Run Tier 1 (fast lexical) on raw input FIRST. Only if inconclusive, then normalize and run expensive semantic analysis.

## Multi-Tiered Detection System

### Tier 1: Lexical Analysis (Raw Input)
- **Speed**: ~5-10ms per input
- **Method**: Regex pattern matching against ~7 core injection signatures
- **Examples Caught**: "ignore all previous", "jailbreak mode", "bypass restrictions"
- **Early Exit**: HIGH/CRITICAL threats with high confidence skip downstream analysis

### Tier 2: Semantic Analysis (Normalized Input)
- **Speed**: ~100-200ms per input (on-demand)
- **Method**: LLM-based contextual understanding
- **Status**: Placeholder, integrated with LangChain + Bright Data vectors
- **When**: Only runs if Tier 1 is inconclusive

### Tier 3: Behavioral Analysis (Output Anomaly)
- **Speed**: ~50-100ms per input (on-demand)
- **Method**: Pattern analysis of model responses
- **Status**: Placeholder for future development
- **When**: Only runs if Tiers 1-2 are inconclusive

## Input Processing Phases

### Phase 1: Normalization (Anti-Evasion)
**When**: Only if Tier 1 is inconclusive

Reverses obfuscation techniques:
- Decodes layered encodings (Base64, hex, URL, nested combinations)
- Normalizes Unicode homoglyphs to canonical form
- Collapses whitespace evasion
- Removes zero-width characters

**Key Features**:
- Max recursion depth: 3 layers (prevents DoS)
- Timeout: 100ms per input
- Only runs when necessary

### Phase 2: Payload Parser
**When**: Complex payloads (JSON/MCP structures)

Structural decomposition and field classification:
- Extracts string values from nested structures
- Classifies each field: STRUCTURAL (metadata) or SCANNABLE (user text)
- Returns JSON paths for precise threat attribution (e.g., `$.messages[0].content`)
- Enables dual-path processing: structural fields skip detection

### Phase 3: Dual-Gate Router
**When**: Always (orchestration layer)

Central orchestration coordinating all phases and tiers:
- Routes structural metadata through fast path (no detection)
- Routes scannable user text through full Tier 1-3 pipeline
- Coordinates normalization only when needed
- Orchestrates remediation for detected threats
- Synthesizes final decision verdict

## Routing Decisions

- **ALLOW**: No threats detected, safe to proceed
- **BLOCK**: Critical threat with high confidence, immediate rejection
- **QUARANTINE**: Medium threat flagged, awaiting remediation
- **ESCALATE**: High threat requiring human operator review
- **REMEDIATE**: Threat auto-fixed by supervisor agent

## Directory Structure

```
shieldprompt/
├── README.md                    # Main entry point
├── requirements.txt
├── .env.example
│
├── docs/
│   ├── OVERVIEW.md             # This file
│   ├── ARCHITECTURE.md         # Tier-first optimization details
│   ├── GETTING_STARTED.md
│   └── phases/
│       ├── PHASE_1_NORMALIZATION.md
│       ├── PHASE_2_PARSING.md
│       └── PHASE_3_ROUTING.md
│
├── src/
│   ├── core/                    # Detection pipeline
│   │   ├── shield.py           # Multi-tiered detection engine
│   │   ├── payload_parser.py   # Field classification
│   │   ├── router.py           # Dual-gate orchestration
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

# Initialize router (coordinates all phases and tiers)
router = DualGateRouter()

# Route a payload through the optimized pipeline
payload = {"content": "What is AI?"}
result = router.route(payload)

# Check verdict
if result.decision == RoutingDecision.ALLOW:
    process_safely(payload)
elif result.decision == RoutingDecision.BLOCK:
    reject_request(payload)

# Access threat details with JSON path attribution
for threat in result.critical_threats:
    print(f"Location: {threat.parsed_field.json_path}")
    print(f"Confidence: {threat.detection_result.confidence:.2f}")
```

## Performance Profile

| Scenario | Latency | Throughput | Description |
|----------|---------|-----------|-------------|
| Tier 1 Early Exit | ~5-10ms | 100-200/sec | Simple injection caught immediately |
| Clean Input | ~10-20ms | 50-100/sec | No threats, quick semantic check |
| Normalized Analysis | ~100-300ms | 3-10/sec | Evasion decoded and analyzed |
| Mixed Payload | ~20-100ms | 10-50/sec | Structural fields skipped, scannable analyzed |

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

## Test Coverage

- **Tier 1**: Lexical detection, pattern matching, early-exit validation
- **Phases**: Normalization, parsing, routing, decision synthesis
- **Tiers 2-3**: Placeholder validation, structural vs. scannable
- **Total**: 100+ test cases, all passing

Run: `pytest tests/ -v`

## Configuration

See detailed configuration in:
- [ARCHITECTURE.md](ARCHITECTURE.md) — Pipeline configuration
- [docs/phases/](docs/phases/) — Phase-specific details

## Next Steps

- **Phase 4**: Streamlit dashboard for real-time monitoring
- **Phase 5**: Webhook integration for external SIEM systems
- **Phase 6**: Adaptive thresholds via threat intelligence


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
